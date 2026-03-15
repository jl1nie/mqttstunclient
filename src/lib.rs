use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit};
use log::info;
use std::convert::TryInto;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};

/// Return value of get_client_addr / get_server_addr
pub struct ConnectionResult {
    pub peer_addr: SocketAddr,
}

pub struct MQTTStunClient {
    server_name: String,
    key: [u8; 32],
    stun_server_addr: SocketAddr,
    mqtt_broker_url: String,
}

impl MQTTStunClient {
    const STUN_BINDING_REQUEST_MSG_TYPE: u16 = 0x0001;
    const STUN_MAGIC_COOKIE: u32 = 0x2112A442;
    const STUN_ATTR_MAPPED_ADDRESS: u16 = 0x0001;
    const STUN_ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

    pub fn new(
        server_name: String,
        key: &str,
        stun_server: Option<&str>,
        mqtt_broker_url: Option<&str>,
    ) -> Self {
        let key_bytes = key.as_bytes();
        let mut key = [0u8; 32];
        let len_to_copy = std::cmp::min(key_bytes.len(), key.len());
        key[..len_to_copy].copy_from_slice(&key_bytes[..len_to_copy]);

        let stun_server_addr = stun_server
            .unwrap_or("stun.l.google.com:19302")
            .to_socket_addrs()
            .ok()
            .and_then(|iter| iter.filter(|addr| addr.is_ipv4()).next())
            .expect("Can not find IPv4 address of stun server.");

        let mqtt_broker_url = mqtt_broker_url
            .unwrap_or("mqtt://broker.emqx.io:1883")
            .to_string();

        info!(
            "STUN Sever: {} MQTT Topic: {} Broker: {}",
            stun_server_addr, server_name, mqtt_broker_url
        );

        Self {
            server_name,
            key,
            stun_server_addr,
            mqtt_broker_url,
        }
    }

    pub fn sanity_check(&self) {
        if self.key.len() != 32 {
            panic!("Key length must be 32 bytes");
        }
        if self.server_name.is_empty() {
            panic!("Server name cannot be empty");
        }
        let check_message = "Sanity check passed!";
        let encrypted_message = self.encrypt_message(check_message.as_bytes());
        let decrypted_message = self.decrypt_message(&encrypted_message);
        if decrypted_message.is_none() {
            panic!("Decryption failed after encryption");
        }
        let decrypted_message = decrypted_message.unwrap();
        if decrypted_message != check_message {
            panic!("Decrypted message does not match original");
        }
        info!("Sanity check passed!");
    }

    fn encrypt_message(&self, plaintext: &[u8]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new(&self.key.into());
        let mut iv = [0u8; 12];
        rand::fill(&mut iv);
        let ciphertext = cipher
            .encrypt(&iv.into(), plaintext)
            .expect("encryption failed");
        [iv.to_vec(), ciphertext].concat()
    }

    fn decrypt_message(&self, encrypted_payload: &[u8]) -> Option<String> {
        if encrypted_payload.len() < 12 {
            return None;
        }
        let iv = &encrypted_payload[..12];
        let ciphertext = &encrypted_payload[12..];
        let cipher = ChaCha20Poly1305::new(&self.key.into());
        cipher
            .decrypt(iv.into(), ciphertext)
            .ok()
            .map(|bytes| String::from_utf8_lossy(&bytes).to_string())
    }

    fn generate_stun_binding_request() -> (Vec<u8>, [u8; 12]) {
        let mut transaction_id = [0u8; 12];
        rand::fill(&mut transaction_id);

        let mut request = Vec::with_capacity(20);
        request.extend_from_slice(&MQTTStunClient::STUN_BINDING_REQUEST_MSG_TYPE.to_be_bytes());
        request.extend_from_slice(&0u16.to_be_bytes());
        request.extend_from_slice(&MQTTStunClient::STUN_MAGIC_COOKIE.to_be_bytes());
        request.extend_from_slice(&transaction_id);

        (request, transaction_id)
    }

    fn parse_stun_binding_response(
        response: &[u8],
        expected_transaction_id: &[u8; 12],
    ) -> Option<SocketAddr> {
        if response.len() < 20 {
            info!("STUN: response too short ({} bytes)", response.len());
            return None;
        }

        let msg_type = u16::from_be_bytes(response[0..2].try_into().ok()?);
        let msg_len = u16::from_be_bytes(response[2..4].try_into().ok()?);
        let magic_cookie = u32::from_be_bytes(response[4..8].try_into().ok()?);
        let transaction_id: [u8; 12] = response[8..20].try_into().ok()?;

        if magic_cookie != MQTTStunClient::STUN_MAGIC_COOKIE {
            info!("STUN: magic cookie mismatch: {:x}", magic_cookie);
            return None;
        }
        if &transaction_id != expected_transaction_id {
            info!("STUN: transaction ID mismatch");
            return None;
        }

        if msg_type != 0x0101 {
            info!("STUN: unexpected message type: {:x}", msg_type);
            return None;
        }

        let mut current_offset = 20;
        while current_offset < (20 + msg_len as usize) && current_offset + 4 <= response.len() {
            let attr_type = u16::from_be_bytes(
                response[current_offset..current_offset + 2]
                    .try_into()
                    .ok()?,
            );
            let attr_len = u16::from_be_bytes(
                response[current_offset + 2..current_offset + 4]
                    .try_into()
                    .ok()?,
            );
            current_offset += 4;

            if current_offset + attr_len as usize > response.len() {
                info!("STUN: attribute length out of bounds");
                return None;
            }
            let attr_value = &response[current_offset..current_offset + attr_len as usize];

            if attr_type == MQTTStunClient::STUN_ATTR_MAPPED_ADDRESS {
                if attr_len >= 8 && attr_value[0] == 0x00 && attr_value[1] == 0x01 {
                    let port = u16::from_be_bytes(attr_value[2..4].try_into().ok()?);
                    let ip_bytes: [u8; 4] = attr_value[4..8].try_into().ok()?;
                    let ip = IpAddr::from(ip_bytes);
                    info!("STUN: MAPPED-ADDRESS {}:{}", ip, port);
                    return Some(SocketAddr::new(ip, port));
                }
            } else if attr_type == MQTTStunClient::STUN_ATTR_XOR_MAPPED_ADDRESS {
                if attr_len >= 8 && attr_value[0] == 0x00 && attr_value[1] == 0x01 {
                    let xor_port_bytes: [u8; 2] = attr_value[2..4].try_into().ok()?;
                    let xor_ip_bytes: [u8; 4] = attr_value[4..8].try_into().ok()?;

                    let magic_cookie_high_bytes: [u8; 2] = MQTTStunClient::STUN_MAGIC_COOKIE
                        .to_be_bytes()[0..2]
                        .try_into()
                        .ok()?;
                    let port = u16::from_be_bytes(xor_port_bytes)
                        ^ u16::from_be_bytes(magic_cookie_high_bytes);

                    let mut ip_bytes = [0u8; 4];
                    let magic_cookie_all_bytes = MQTTStunClient::STUN_MAGIC_COOKIE.to_be_bytes();
                    for i in 0..4 {
                        ip_bytes[i] = xor_ip_bytes[i] ^ magic_cookie_all_bytes[i];
                    }
                    let ip = IpAddr::from(ip_bytes);
                    info!("STUN: XOR-MAPPED-ADDRESS {}:{}", ip, port);
                    return Some(SocketAddr::new(ip, port));
                }
            }
            current_offset += attr_len as usize;
            if (attr_len % 4) != 0 {
                current_offset += 4 - (attr_len % 4) as usize;
            }
        }
        info!("STUN: no address attribute found");
        None
    }

    fn get_stun_addr(&mut self, socket: &UdpSocket) -> Option<SocketAddr> {
        let (request_payload, transaction_id) = MQTTStunClient::generate_stun_binding_request();
        let original_timeout = socket.read_timeout().unwrap_or(None);
        if let Err(e) = socket.set_read_timeout(Some(std::time::Duration::from_secs(3))) {
            info!("STUN: failed to set socket timeout: {}", e);
        }

        const MAX_RETRIES: usize = 3;
        for attempt in 0..MAX_RETRIES {
            info!("STUN: attempt {}/{}", attempt + 1, MAX_RETRIES);
            if let Err(e) = socket.send_to(&request_payload, self.stun_server_addr) {
                info!("STUN: send failed: {:?}", e);
                if attempt == MAX_RETRIES - 1 {
                    socket
                        .set_read_timeout(original_timeout)
                        .unwrap_or_else(|e| info!("STUN: failed to restore timeout: {}", e));
                    return None;
                }
                std::thread::sleep(std::time::Duration::from_millis(200 * (attempt as u64 + 1)));
                continue;
            }
            info!(
                "STUN: sent binding request ({} bytes) to {}",
                request_payload.len(),
                self.stun_server_addr
            );

            let mut buf = [0u8; 512];
            match socket.recv_from(&mut buf) {
                Ok((amt, src)) => {
                    info!("STUN: received {} bytes from {}", amt, src);
                    socket
                        .set_read_timeout(original_timeout)
                        .unwrap_or_else(|e| info!("STUN: failed to restore timeout: {}", e));

                    let response_data = &buf[..amt];
                    if let Some(mapped_addr) =
                        MQTTStunClient::parse_stun_binding_response(response_data, &transaction_id)
                    {
                        info!("STUN: my public address is {}", mapped_addr);
                        return Some(mapped_addr);
                    } else {
                        info!("STUN: failed to parse response");
                        return None;
                    }
                }
                Err(e) => {
                    info!("STUN: recv timeout/error ({:?} {})", e.kind(), e);
                    if attempt == MAX_RETRIES - 1 {
                        socket
                            .set_read_timeout(original_timeout)
                            .unwrap_or_else(|e| info!("STUN: failed to restore timeout: {}", e));
                        return None;
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(300 * (attempt as u64 + 1)));
        }

        socket
            .set_read_timeout(original_timeout)
            .unwrap_or_else(|e| info!("STUN: failed to restore timeout: {}", e));
        info!("STUN: all attempts failed");
        None
    }

    /// Returns a routable (non-link-local, non-loopback, non-unspecified) IPv6 address if available.
    pub fn try_get_routable_ipv6() -> Option<IpAddr> {
        let s = match UdpSocket::bind("[::]:0") {
            Ok(s) => s,
            Err(e) => {
                info!("try_get_routable_ipv6: bind [::]:0 failed: {}", e);
                return None;
            }
        };
        if let Err(e) = s.connect("2001:4860:4860::8888:53") {
            info!("try_get_routable_ipv6: connect to Google IPv6 DNS failed (no IPv6?): {}", e);
            return None;
        }
        let addr = match s.local_addr() {
            Ok(a) => a,
            Err(e) => {
                info!("try_get_routable_ipv6: local_addr failed: {}", e);
                return None;
            }
        };
        if let IpAddr::V6(ip6) = addr.ip() {
            if !ip6.is_loopback()
                && !ip6.is_unspecified()
                && (ip6.segments()[0] & 0xffc0) != 0xfe80
            {
                info!("try_get_routable_ipv6: global IPv6 address: {}", ip6);
                return Some(IpAddr::V6(ip6));
            }
            info!("try_get_routable_ipv6: {} is not global (loopback/link-local/unspecified)", ip6);
        } else {
            info!("try_get_routable_ipv6: local addr {} is not IPv6", addr.ip());
        }
        None
    }

    /// Selects the best address from a newline-separated address list.
    /// Prefers IPv6 when has_v6=true, falls back to IPv4 otherwise.
    fn select_best_addr(s: &str, has_v6: bool) -> Option<SocketAddr> {
        let mut ipv4 = None;
        for part in s.split('\n') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if let Ok(addr) = part.parse::<SocketAddr>() {
                match addr.ip() {
                    IpAddr::V6(_) if has_v6 => return Some(addr),
                    IpAddr::V4(_) => ipv4 = Some(addr),
                    _ => {}
                }
            }
        }
        ipv4
    }

    fn get_global_ip(&mut self, socket: &UdpSocket) -> Vec<u8> {
        let port = socket.local_addr().map(|a| a.port()).unwrap_or(0);
        let mut addrs = Vec::<String>::new();

        if let Some(ip6) = Self::try_get_routable_ipv6() {
            let addr = SocketAddr::new(ip6, port);
            info!("Advertising IPv6: {}", addr);
            addrs.push(addr.to_string());
        }

        if let Some(ipv4_addr) = self.get_stun_addr(socket) {
            info!("Advertising IPv4 (via STUN): {}", ipv4_addr);
            addrs.push(ipv4_addr.to_string());
        }

        if addrs.is_empty() {
            panic!("Failed to get any IP address");
        }
        self.encrypt_message(addrs.join("\n").as_bytes())
    }

    #[cfg(feature = "rumqttc")]
    pub fn get_server_addr(&mut self, socket: &UdpSocket, has_v6: bool) -> Option<SocketAddr> {
        use rumqttc::{Client, Event, MqttOptions, Packet, QoS};
        let host = self
            .mqtt_broker_url
            .split("://")
            .nth(1)
            .unwrap()
            .split(':')
            .next()
            .unwrap();

        let port = self
            .mqtt_broker_url
            .split("://")
            .nth(1)
            .unwrap()
            .split(':')
            .nth(1)
            .unwrap()
            .parse::<u16>()
            .unwrap_or(1883);

        let mqttoptions = MqttOptions::new("wifikey-client", host, port);
        let (client, mut connection) = Client::new(mqttoptions, 10);

        let client_addr = self.get_global_ip(socket);
        let ctopic = format!("{}{}", self.server_name, "/client");
        client
            .publish(ctopic.clone(), QoS::AtLeastOnce, true, client_addr)
            .unwrap();

        let topic = format!("{}{}", self.server_name, "/server");
        client.subscribe(topic.clone(), QoS::AtLeastOnce).unwrap();

        loop {
            let notification = connection.iter().next();
            if let Some(Ok(Event::Incoming(Packet::Publish(p)))) = notification {
                if p.topic == topic {
                    if let Some(peer_addr_str) = self.decrypt_message(&p.payload) {
                        match Self::select_best_addr(&peer_addr_str, has_v6) {
                            Some(peer_socket_addr) => {
                                info!("Server address: {}", peer_socket_addr);
                                for _ in 0..10 {
                                    socket.send_to(b"PU", peer_socket_addr).unwrap();
                                    std::thread::sleep(std::time::Duration::from_millis(100));
                                }
                                socket
                                    .set_read_timeout(Some(std::time::Duration::from_millis(500)))
                                    .unwrap();
                                let mut buf = [0; 10];
                                for _ in 0..10 {
                                    match socket.recv_from(&mut buf) {
                                        Ok((amt, src)) => {
                                            if &buf[..amt] == b"PU" {
                                                info!("Received punching packet from {}", src);
                                            } else {
                                                info!(
                                                    "Received unexpected packet from {}: {:?}",
                                                    src,
                                                    &buf[..amt]
                                                );
                                            }
                                        }
                                        Err(ref e)
                                            if e.kind() == std::io::ErrorKind::WouldBlock
                                                || e.kind() == std::io::ErrorKind::TimedOut =>
                                        {
                                            break;
                                        }
                                        Err(e) => {
                                            info!("Error receiving punching packet: {:?}", e);
                                            break;
                                        }
                                    }
                                }
                                client
                                    .publish(ctopic.clone(), QoS::AtLeastOnce, true, Vec::new())
                                    .unwrap();
                                return Some(peer_socket_addr);
                            }
                            None => {
                                info!("Failed to find usable address in payload");
                            }
                        }
                    }
                }
            } else {
                info!("Error: {:?}", notification);
            }
        }
    }

    #[cfg(feature = "rumqttc")]
    pub fn get_client_addr(&mut self, socket: &UdpSocket, has_v6: bool) -> Option<ConnectionResult> {
        use rumqttc::{Client, Event, MqttOptions, Packet, QoS};
        let host = self
            .mqtt_broker_url
            .split("://")
            .nth(1)
            .unwrap()
            .split(':')
            .next()
            .unwrap();

        let port = self
            .mqtt_broker_url
            .split("://")
            .nth(1)
            .unwrap()
            .split(':')
            .nth(1)
            .unwrap()
            .parse::<u16>()
            .unwrap_or(1883);

        let mqttoptions = MqttOptions::new("wifikey-server", host, port);
        let (client, mut connection) = Client::new(mqttoptions, 10);

        let server_addr = self.get_global_ip(socket);
        let topic = format!("{}{}", self.server_name, "/server");
        client
            .publish(topic.clone(), QoS::AtLeastOnce, true, server_addr)
            .unwrap();

        let topic = format!("{}{}", self.server_name, "/client");
        // Do not publish empty retain to /client: keep the client's retained address intact.
        // (Overwriting causes a race condition where the client address is lost → timeout)
        client.subscribe(topic.clone(), QoS::AtLeastOnce).unwrap();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            if std::time::Instant::now() >= deadline {
                info!("get_client_addr: timeout waiting for client");
                return None;
            }
            let notification = connection.iter().next();
            match notification {
                Some(Ok(Event::Incoming(Packet::Publish(p)))) => {
                    if p.topic == topic {
                        if p.payload.is_empty() {
                            info!("get_client_addr: empty payload, skipping");
                            continue;
                        }
                        if let Some(peer_addr_str) = self.decrypt_message(&p.payload) {
                            match Self::select_best_addr(&peer_addr_str, has_v6) {
                                Some(peer_socket_addr) => {
                                    info!("Client address: {}", peer_socket_addr);
                                    for _ in 0..10 {
                                        socket.send_to(b"PU", peer_socket_addr).unwrap();
                                        std::thread::sleep(std::time::Duration::from_millis(100));
                                    }
                                    socket
                                        .set_read_timeout(Some(std::time::Duration::from_millis(
                                            500,
                                        )))
                                        .unwrap();
                                    let mut buf = [0; 10];
                                    for _ in 0..10 {
                                        match socket.recv_from(&mut buf) {
                                            Ok((amt, src)) => {
                                                if &buf[..amt] == b"PU" {
                                                    info!("Received punching packet from {}", src);
                                                } else {
                                                    info!(
                                                        "Received unexpected packet from {}: {:?}",
                                                        src,
                                                        &buf[..amt]
                                                    );
                                                }
                                            }
                                            Err(ref e)
                                                if e.kind() == std::io::ErrorKind::WouldBlock
                                                    || e.kind() == std::io::ErrorKind::TimedOut =>
                                            {
                                                break;
                                            }
                                            Err(e) => {
                                                info!("Error receiving punching packet: {:?}", e);
                                                break;
                                            }
                                        }
                                    }
                                    return Some(ConnectionResult {
                                        peer_addr: peer_socket_addr,
                                    });
                                }
                                None => {
                                    info!("Failed to find usable address in payload");
                                    return None;
                                }
                            }
                        }
                    } else {
                        info!("Invalid topic: {} != {}", p.topic, topic);
                    }
                }
                Some(Ok(Event::Incoming(Packet::Disconnect))) | None => {
                    info!("get_client_addr: MQTT disconnected, giving up");
                    return None;
                }
                Some(Err(e)) => {
                    info!("get_client_addr: MQTT error: {:?}, giving up", e);
                    return None;
                }
                _ => {}
            }
        }
    }

    #[cfg(feature = "esp-idf-mqtt")]
    pub fn get_server_addr(&mut self, socket: &UdpSocket, has_v6: bool) -> Option<SocketAddr> {
        use esp_idf_svc::mqtt::client::{EspMqttClient, MqttClientConfiguration, QoS};
        use std::sync::mpsc;
        use std::thread;

        let client_addr_payload = self.get_global_ip(socket);
        let ctopic_base = format!("{}{}", self.server_name, "/client");
        let topic_to_subscribe_base = format!("{}{}", self.server_name, "/server");

        let broker_url = self.mqtt_broker_url.as_str();
        let mqtt_config = MqttClientConfiguration::default();

        let (mut client, mut connection) = match EspMqttClient::new(broker_url, &mqtt_config) {
            Ok(c) => c,
            Err(e) => {
                info!("get_server_addr: failed to create MQTT client: {:?}", e);
                return None;
            }
        };
        info!("get_server_addr: MQTT client created");

        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        let topic_to_subscribe_for_thread = topic_to_subscribe_base.clone();
        let ctopic_for_empty_publish = ctopic_base.clone();

        thread::spawn(move || {
            info!("get_server_addr: MQTT event loop thread started");
            loop {
                let event_result = connection.next();
                match event_result {
                    Ok(event) => {
                        match event.payload() {
                            esp_idf_svc::mqtt::client::EventPayload::Received {
                                id: _,
                                topic: Some(recv_topic),
                                data,
                                details: _,
                            } if recv_topic == topic_to_subscribe_for_thread => {
                                if data.is_empty() {
                                    info!("get_server_addr: empty payload received, skipping");
                                    continue;
                                }
                                info!("get_server_addr: received encrypted data ({} bytes)", data.len());
                                if let Err(e) = tx.send(data.to_vec()) {
                                    info!("get_server_addr: channel send failed: {}", e);
                                    return;
                                }
                                info!("get_server_addr: data forwarded to main thread");
                            }
                            esp_idf_svc::mqtt::client::EventPayload::Connected(_) => {
                                info!("get_server_addr: MQTT connected");
                            }
                            esp_idf_svc::mqtt::client::EventPayload::Disconnected => {
                                info!("get_server_addr: MQTT disconnected, exiting event loop");
                                return;
                            }
                            _ => {
                                info!("get_server_addr: other MQTT event: {:?}", event.payload())
                            }
                        }
                    }
                    Err(e) => {
                        info!("get_server_addr: MQTT error in event loop: {:?}", e);
                        return;
                    }
                }
            }
        });

        info!("get_server_addr: publishing client address to {}", ctopic_base);
        match client.publish(&ctopic_base, QoS::AtLeastOnce, true, &client_addr_payload) {
            Ok(_) => info!("get_server_addr: published client address to {}", ctopic_base),
            Err(e) => {
                info!("get_server_addr: failed to publish client address: {:?}", e);
                return None;
            }
        }

        match client.subscribe(&topic_to_subscribe_base, QoS::AtLeastOnce) {
            Ok(_) => info!("get_server_addr: subscribed to {}", topic_to_subscribe_base),
            Err(e) => {
                info!("get_server_addr: failed to subscribe: {:?}", e);
                return None;
            }
        }
        info!("get_server_addr: waiting for server address (60s timeout)");

        let peer_addr_option = match rx.recv_timeout(std::time::Duration::from_secs(60)) {
            Ok(encrypted_data) => {
                info!("get_server_addr: received encrypted data ({} bytes)", encrypted_data.len());
                if let Some(peer_addr_str) = self.decrypt_message(&encrypted_data) {
                    info!("get_server_addr: decrypted address: {:?} (has_v6={})", peer_addr_str, has_v6);
                    match Self::select_best_addr(&peer_addr_str, has_v6) {
                        Some(peer_addr) => {
                            info!("get_server_addr: selected peer address: {}", peer_addr);
                            match client.publish(
                                &ctopic_for_empty_publish,
                                QoS::AtLeastOnce,
                                true,
                                &[],
                            ) {
                                Ok(_) => {
                                    info!("get_server_addr: published empty retain to {}", ctopic_for_empty_publish)
                                }
                                Err(e) => info!("get_server_addr: failed to publish empty retain: {:?}", e),
                            }
                            Some(peer_addr)
                        }
                        None => {
                            info!("get_server_addr: failed to parse peer address");
                            None
                        }
                    }
                } else {
                    info!("get_server_addr: decryption failed");
                    None
                }
            }
            Err(e) => {
                info!("get_server_addr: timeout waiting for server address: {}", e);
                None
            }
        };

        if let Some(peer_addr) = peer_addr_option {
            for _ in 0..10 {
                if let Err(e) = socket.send_to(b"PU", peer_addr) {
                    info!("get_server_addr: failed to send punching packet: {}", e);
                    return None;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            socket
                .set_read_timeout(Some(std::time::Duration::from_millis(500)))
                .unwrap_or_else(|e| info!("get_server_addr: failed to set punch recv timeout: {}", e));
            let mut buf = [0; 10];
            for _ in 0..10 {
                match socket.recv_from(&mut buf) {
                    Ok((amt, src)) => {
                        if &buf[..amt] == b"PU" {
                            info!("get_server_addr: received punching packet from {}", src);
                        } else {
                            info!("get_server_addr: unexpected packet from {}: {:?}", src, &buf[..amt]);
                        }
                    }
                    Err(ref e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        break;
                    }
                    Err(e) => {
                        info!("get_server_addr: punch recv error: {:?}", e);
                        break;
                    }
                }
            }
            return Some(peer_addr);
        }

        None
    }

    #[cfg(feature = "esp-idf-mqtt")]
    pub fn get_client_addr(&mut self, socket: &UdpSocket, has_v6: bool) -> Option<ConnectionResult> {
        use esp_idf_svc::mqtt::client::{EspMqttClient, MqttClientConfiguration, QoS};
        use std::sync::mpsc;
        use std::thread;

        let server_addr_payload = self.get_global_ip(socket);
        let server_topic_base = format!("{}{}", self.server_name, "/server");
        let client_topic_to_subscribe_base = format!("{}{}", self.server_name, "/client");

        let broker_url = self.mqtt_broker_url.as_str();
        let mqtt_config = MqttClientConfiguration {
            client_id: Some("wifikey-server"),
            ..Default::default()
        };

        let (mut client, mut connection) = match EspMqttClient::new(broker_url, &mqtt_config) {
            Ok(c) => c,
            Err(e) => {
                info!("get_client_addr: failed to create MQTT client: {:?}", e);
                return None;
            }
        };
        info!("get_client_addr: MQTT client created");

        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        let client_topic_to_subscribe_for_thread = client_topic_to_subscribe_base.clone();

        thread::spawn(move || {
            info!("get_client_addr: MQTT event loop thread started");
            loop {
                let event_result = connection.next();
                match event_result {
                    Ok(event) => {
                        match event.payload() {
                            esp_idf_svc::mqtt::client::EventPayload::Received {
                                id: _,
                                topic: Some(recv_topic),
                                data,
                                details: _,
                            } if recv_topic == client_topic_to_subscribe_for_thread => {
                                if data.is_empty() {
                                    info!("get_client_addr: empty payload received, skipping");
                                    continue;
                                }
                                info!("get_client_addr: received encrypted data ({} bytes)", data.len());
                                if let Err(e) = tx.send(data.to_vec()) {
                                    info!("get_client_addr: channel send failed: {}", e);
                                    return;
                                }
                                info!("get_client_addr: data forwarded to main thread");
                            }
                            esp_idf_svc::mqtt::client::EventPayload::Connected(_) => {
                                info!("get_client_addr: MQTT connected");
                            }
                            esp_idf_svc::mqtt::client::EventPayload::Disconnected => {
                                info!("get_client_addr: MQTT disconnected, exiting event loop");
                                return;
                            }
                            _ => {}
                        }
                    }
                    Err(e) => {
                        info!("get_client_addr: MQTT error in event loop: {:?}", e);
                        return;
                    }
                }
            }
        });

        info!("get_client_addr: publishing server address to {}", server_topic_base);
        match client.publish(
            &server_topic_base,
            QoS::AtLeastOnce,
            true,
            &server_addr_payload,
        ) {
            Ok(_) => info!("get_client_addr: published server address to {}", server_topic_base),
            Err(e) => {
                info!("get_client_addr: failed to publish server address: {:?}", e);
                return None;
            }
        }

        // Do not publish empty retain to /client: keep the client's retained address intact.
        // (Overwriting causes a race condition where the client address is lost → timeout)

        match client.subscribe(&client_topic_to_subscribe_base, QoS::AtLeastOnce) {
            Ok(_) => info!("get_client_addr: subscribed to {}", client_topic_to_subscribe_base),
            Err(e) => {
                info!("get_client_addr: failed to subscribe: {:?}", e);
                return None;
            }
        }
        info!("get_client_addr: waiting for client address (30s timeout)");

        let client_addr_option = match rx.recv_timeout(std::time::Duration::from_secs(30)) {
            Ok(encrypted_data) => {
                info!("get_client_addr: received encrypted data ({} bytes)", encrypted_data.len());
                if let Some(client_addr_str) = self.decrypt_message(&encrypted_data) {
                    match Self::select_best_addr(&client_addr_str, has_v6) {
                        Some(client_addr) => {
                            info!("get_client_addr: client address: {}", client_addr);
                            Some(client_addr)
                        }
                        None => {
                            info!("get_client_addr: failed to parse client address");
                            None
                        }
                    }
                } else {
                    info!("get_client_addr: decryption failed");
                    None
                }
            }
            Err(e) => {
                info!("get_client_addr: timeout waiting for client address: {}", e);
                None
            }
        };

        if let Some(client_addr) = client_addr_option {
            return Some(ConnectionResult {
                peer_addr: client_addr,
            });
        }

        None
    }
}
