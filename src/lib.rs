use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit};
use log::info;
use std::convert::TryInto;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};

/// ICE-like address candidates for NAT traversal
/// Contains both local (host) and STUN-acquired (server reflexive) addresses
#[derive(Debug, Clone)]
pub struct AddressCandidates {
    /// Local/private IP address (host candidate)
    pub local: Option<SocketAddr>,
    /// STUN-acquired public IP address (server reflexive candidate)
    pub stun: Option<SocketAddr>,
}

impl AddressCandidates {
    /// Create new candidates with both addresses
    pub fn new(local: Option<SocketAddr>, stun: Option<SocketAddr>) -> Self {
        Self { local, stun }
    }

    /// Serialize to MQTT payload format: "stun_addr,local_addr" or "stun_addr" or "local_addr"
    pub fn to_payload(&self) -> String {
        match (&self.stun, &self.local) {
            (Some(stun), Some(local)) => format!("{},{}", stun, local),
            (Some(stun), None) => format!("{}", stun),
            (None, Some(local)) => format!("{}", local),
            (None, None) => String::new(),
        }
    }

    /// Parse from MQTT payload format
    pub fn from_payload(payload: &str) -> Self {
        let parts: Vec<&str> = payload.split(',').collect();
        match parts.as_slice() {
            [stun, local] => Self {
                stun: stun.parse().ok(),
                local: local.parse().ok(),
            },
            [single] => {
                // Try to determine if it's local or STUN based on IP range
                if let Ok(addr) = single.parse::<SocketAddr>() {
                    if Self::is_private_ip(&addr) {
                        Self {
                            local: Some(addr),
                            stun: None,
                        }
                    } else {
                        Self {
                            stun: Some(addr),
                            local: None,
                        }
                    }
                } else {
                    Self {
                        local: None,
                        stun: None,
                    }
                }
            }
            _ => Self {
                local: None,
                stun: None,
            },
        }
    }

    /// Check if an address is in private IP range
    fn is_private_ip(addr: &SocketAddr) -> bool {
        match addr.ip() {
            IpAddr::V4(ip) => ip.is_private() || ip.is_loopback() || ip.is_link_local(),
            IpAddr::V6(ip) => {
                ip.is_loopback() // IPv6 private detection is more complex
            }
        }
    }

    /// Get all valid addresses as a vector, prioritizing local for same-LAN
    pub fn to_vec(&self) -> Vec<SocketAddr> {
        let mut addrs = Vec::new();
        // Try local first (faster if on same LAN)
        if let Some(local) = self.local {
            addrs.push(local);
        }
        // Then STUN address
        if let Some(stun) = self.stun {
            addrs.push(stun);
        }
        addrs
    }
}

pub struct MQTTStunClient {
    server_name: String,
    key: [u8; 32],
    stun_server_addr: SocketAddr,
    mqtt_broker_url: String,
}

impl MQTTStunClient {
    const STUN_BINDING_REQUEST_MSG_TYPE: u16 = 0x0001; // 「教えてー！」っていうメッセージの種類
    const STUN_MAGIC_COOKIE: u32 = 0x2112A442; // STUNメッセージのおまじないみたいなやつ
    const STUN_ATTR_MAPPED_ADDRESS: u16 = 0x0001; // 「これが住所だよ」っていう属性の種類
    const STUN_ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020; // ちょっと暗号化された「これが住所だよ」

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

        //stun_server_addrを指定しない場合は、GoogleのSTUNサーバーを使用
        let stun_server_addr = stun_server
            .unwrap_or("stun.l.google.com:19302")
            .to_socket_addrs()
            .ok()
            .and_then(|mut iter| iter.find(|addr| addr.is_ipv4())) // IPv4アドレスだけフィルタリング！
            .expect("STUN server IPv4 address not found."); // 見つからなかったらパニック！

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
        // ここで sanity check を行う
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
            return None; // IV（Nonce）が不足している場合はエラー
        }
        let iv = &encrypted_payload[..12]; // 先頭12バイトがIV
        let ciphertext = &encrypted_payload[12..]; // 残りが暗号化データ
        let cipher = ChaCha20Poly1305::new(&self.key.into());
        cipher
            .decrypt(iv.into(), ciphertext)
            .ok()
            .map(|bytes| String::from_utf8_lossy(&bytes).to_string())
    }

    // 「教えてー！」メッセージを作る関数
    fn generate_stun_binding_request() -> (Vec<u8>, [u8; 12]) {
        let mut transaction_id = [0u8; 12];
        rand::fill(&mut transaction_id); // テキトーなIDを生成（既存のrand::fillを使うよん）

        let mut request = Vec::with_capacity(20); // ヘッダは20バイト
        request.extend_from_slice(&MQTTStunClient::STUN_BINDING_REQUEST_MSG_TYPE.to_be_bytes()); // メッセージの種類
        request.extend_from_slice(&0u16.to_be_bytes()); // メッセージの長さ（今回は属性なしだから0）
        request.extend_from_slice(&MQTTStunClient::STUN_MAGIC_COOKIE.to_be_bytes()); // おまじない
        request.extend_from_slice(&transaction_id); // さっき作ったID

        (request, transaction_id)
    }

    // STUNサーバーからの返事を解析する関数
    fn parse_stun_binding_response(
        response: &[u8],
        expected_transaction_id: &[u8; 12],
    ) -> Option<SocketAddr> {
        if response.len() < 20 {
            // ヘッダ分もないのは論外！
            info!("STUN: 返事短すぎ！ {} bytes", response.len());
            return None;
        }

        // 返事のヘッダを分解！
        let msg_type = u16::from_be_bytes(response[0..2].try_into().ok()?);
        let msg_len = u16::from_be_bytes(response[2..4].try_into().ok()?);
        let magic_cookie = u32::from_be_bytes(response[4..8].try_into().ok()?);
        let transaction_id: [u8; 12] = response[8..20].try_into().ok()?;

        if magic_cookie != MQTTStunClient::STUN_MAGIC_COOKIE {
            // おまじないが違う！ニセモノかも？
            info!("STUN: おまじないが違うよ！ {:x}", magic_cookie);
            return None;
        }
        if &transaction_id != expected_transaction_id {
            // 送ったIDと違う！誰の返事これ？
            info!("STUN: トランザクションIDが違うじゃん！");
            return None;
        }

        // 0x0101 は「成功したよ！」って意味
        if msg_type != 0x0101 {
            info!("STUN: 成功じゃなかったみたい… {:x}", msg_type);
            return None;
        }

        // ここから属性を見ていくよ！
        let mut current_offset = 20; // ヘッダの次から
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
                info!("STUN: 属性の長さが変だよ！");
                return None;
            }
            let attr_value = &response[current_offset..current_offset + attr_len as usize];

            if attr_type == MQTTStunClient::STUN_ATTR_MAPPED_ADDRESS {
                // そのままの住所！
                if attr_len >= 8 && attr_value[0] == 0x00 && attr_value[1] == 0x01 {
                    // IPv4の場合ね
                    let port = u16::from_be_bytes(attr_value[2..4].try_into().ok()?);
                    let ip_bytes: [u8; 4] = attr_value[4..8].try_into().ok()?;
                    let ip = IpAddr::from(ip_bytes);
                    info!("STUN: MAPPED-ADDRESSゲット！ {}:{}", ip, port);
                    return Some(SocketAddr::new(ip, port));
                }
            } else if attr_type == MQTTStunClient::STUN_ATTR_XOR_MAPPED_ADDRESS {
                // ちょっと暗号化された住所！
                if attr_len >= 8 && attr_value[0] == 0x00 && attr_value[1] == 0x01 {
                    // IPv4の場合
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
                    info!("STUN: XOR-MAPPED-ADDRESSゲット！ {}:{}", ip, port);
                    return Some(SocketAddr::new(ip, port));
                }
            }
            current_offset += attr_len as usize;
            // 属性は4バイト区切りだから、余りがあったら調整
            if (attr_len % 4) != 0 {
                current_offset += 4 - (attr_len % 4) as usize;
            }
        }
        info!("STUN: 住所情報が見つかんなかった～");
        None
    }

    fn get_stun_addr(&mut self, socket: &UdpSocket) -> Option<SocketAddr> {
        let (request_payload, transaction_id) = MQTTStunClient::generate_stun_binding_request(); // さっき作った関数で「教えてー！」メッセージ作成
        // UDPソケットの読み取りタイムアウトを一時的に設定 (例: 3秒)
        // このソケット、他でも使ってるから元の設定に戻すの忘れないでね！
        let original_timeout = socket.read_timeout().unwrap_or(None);
        if let Err(e) = socket.set_read_timeout(Some(std::time::Duration::from_secs(3))) {
            info!("STUN: ソケットのタイムアウト設定失敗… {}", e);
            // ま、いっか、とりあえず進も！
        }

        const MAX_RETRIES: usize = 3; // 3回までトライ！
        for attempt in 0..MAX_RETRIES {
            info!("STUN: トライ {}回目！", attempt + 1);
            if let Err(e) = socket.send_to(&request_payload, self.stun_server_addr) {
                info!("STUN: 「教えてー！」って送るの失敗した… {:?}", e);
                if attempt == MAX_RETRIES - 1 {
                    // もう後がない！
                    socket
                        .set_read_timeout(original_timeout)
                        .unwrap_or_else(|e| info!("STUN: タイムアウト戻すのも失敗した… {}", e));
                    return None;
                }
                std::thread::sleep(std::time::Duration::from_millis(200 * (attempt as u64 + 1))); // ちょっと待ってリトライ
                continue;
            }
            info!(
                "STUN: 「教えてー！」送信完了！ ({} bytes) to {}",
                request_payload.len(),
                self.stun_server_addr
            );

            let mut buf = [0u8; 512]; // 返事はこのくらいあれば足りるっしょ
            match socket.recv_from(&mut buf) {
                Ok((amt, src)) => {
                    info!("STUN: 返事キタ！ {} bytes from {}", amt, src);
                    socket
                        .set_read_timeout(original_timeout)
                        .unwrap_or_else(|e| info!("STUN: タイムアウト戻すの失敗… {}", e)); // とりあえずタイムアウト設定戻しとこ

                    // if src != stun_server_addr { // 違うとこから返事きたら…まぁいっか今回は！
                    //     info!("STUN: あれ、違う人から返事きた？ {}", src);
                    // }
                    let response_data = &buf[..amt];
                    if let Some(mapped_addr) =
                        MQTTStunClient::parse_stun_binding_response(response_data, &transaction_id)
                    {
                        info!("STUN: やった！自分の住所わかった！ {}", mapped_addr);
                        return Some(mapped_addr);
                    } else {
                        info!("STUN: 返事きたけど、よくわかんなかった…");
                        // 解析失敗なら、リトライしても意味ないかもだから今回はここで諦める
                        return None;
                    }
                }
                Err(e) => {
                    info!("STUN: 返事待ってたけど来なかった… ({:?} {})", e.kind(), e);
                    if attempt == MAX_RETRIES - 1 {
                        // これでダメなら諦めよ…
                        socket
                            .set_read_timeout(original_timeout)
                            .unwrap_or_else(|e| info!("STUN: タイムアウト戻すの失敗… {}", e));
                        return None;
                    }
                    // タイムアウトならリトライ
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(300 * (attempt as u64 + 1))); // リトライ間隔をちょっとずつ長くする
        }

        // ここまで来ちゃったらダメだったってこと
        socket
            .set_read_timeout(original_timeout)
            .unwrap_or_else(|e| info!("STUN: 最後にタイムアウト戻すのも失敗… {}", e));
        info!("STUN: 何回やってもダメだったわ…");
        None
    }

    /// Get local IP address by connecting to an external address (doesn't actually send data)
    fn get_local_addr(socket: &UdpSocket) -> Option<SocketAddr> {
        // Get the local address bound to this socket
        match socket.local_addr() {
            Ok(addr) => {
                // If bound to 0.0.0.0, try to find the actual local IP
                if addr.ip().is_unspecified() {
                    // Create a temporary socket to determine the local IP
                    // by "connecting" to an external address (no actual data sent)
                    if let Ok(temp_socket) = UdpSocket::bind("0.0.0.0:0") {
                        // Connect to Google's DNS - this doesn't send data, just sets the route
                        if temp_socket.connect("8.8.8.8:53").is_ok()
                            && let Ok(local) = temp_socket.local_addr()
                        {
                            let local_with_port = SocketAddr::new(local.ip(), addr.port());
                            info!("Local IP Address (detected): {}", local_with_port);
                            return Some(local_with_port);
                        }
                    }
                    None
                } else {
                    info!("Local IP Address (bound): {}", addr);
                    Some(addr)
                }
            }
            Err(e) => {
                info!("Failed to get local address: {}", e);
                None
            }
        }
    }

    /// Get both local and STUN addresses as candidates
    fn get_address_candidates(&mut self, socket: &UdpSocket) -> AddressCandidates {
        let local_addr = Self::get_local_addr(socket);
        let stun_addr = self.get_stun_addr(socket);

        info!(
            "Address Candidates - Local: {:?}, STUN: {:?}",
            local_addr, stun_addr
        );

        AddressCandidates::new(local_addr, stun_addr)
    }

    /// Get encrypted payload containing address candidates
    fn get_address_payload(&mut self, socket: &UdpSocket) -> Vec<u8> {
        let candidates = self.get_address_candidates(socket);
        let message = candidates.to_payload();

        if message.is_empty() {
            panic!("Failed to get any IP address (both local and STUN failed)");
        }

        info!("Address payload: {}", message);
        self.encrypt_message(message.as_bytes())
    }

    /// Try UDP hole punching to multiple candidate addresses and return the first one that responds
    fn try_punch_candidates(
        socket: &UdpSocket,
        candidates: &AddressCandidates,
    ) -> Option<SocketAddr> {
        let addrs = candidates.to_vec();
        if addrs.is_empty() {
            info!("No candidate addresses to punch");
            return None;
        }

        info!(
            "Trying UDP hole punching to {} candidates: {:?}",
            addrs.len(),
            addrs
        );

        // Send punching packets to all candidates
        for _ in 0..5 {
            for addr in &addrs {
                if let Err(e) = socket.send_to(b"PU", addr) {
                    info!("Failed to send punch to {}: {}", addr, e);
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        // Wait for response from any candidate
        socket
            .set_read_timeout(Some(std::time::Duration::from_millis(500)))
            .unwrap_or_else(|e| info!("Failed to set read timeout: {}", e));

        let mut buf = [0; 10];
        let mut connected_addr: Option<SocketAddr> = None;

        for _ in 0..10 {
            match socket.recv_from(&mut buf) {
                Ok((amt, src)) => {
                    if &buf[..amt] == b"PU" {
                        info!("Received punch response from {}", src);
                        // Check if the source is one of our candidates
                        if addrs.iter().any(|a| a.ip() == src.ip()) {
                            connected_addr = Some(src);
                            // Continue to drain remaining packets
                            socket
                                .set_read_timeout(Some(std::time::Duration::from_millis(50)))
                                .unwrap_or_default();
                        }
                    } else {
                        info!("Received unexpected packet from {}: {:?}", src, &buf[..amt]);
                    }
                }
                Err(ref e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    break;
                }
                Err(e) => {
                    info!("Error receiving punch response: {:?}", e);
                    break;
                }
            }
        }

        if let Some(addr) = connected_addr {
            info!("Successfully connected to {}", addr);
        } else {
            info!("No punch response received from any candidate");
        }

        connected_addr
    }

    #[cfg(feature = "rumqttc")]
    pub fn get_server_addr(&mut self, socket: &UdpSocket) -> Option<SocketAddr> {
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

        // Send our address candidates (both local and STUN)
        let client_addr_payload = self.get_address_payload(socket);
        let ctopic = format!("{}{}", self.server_name, "/client");
        client
            .publish(ctopic.clone(), QoS::AtLeastOnce, true, client_addr_payload)
            .unwrap();

        let topic = format!("{}{}", self.server_name, "/server");
        client.subscribe(topic.clone(), QoS::AtLeastOnce).unwrap();

        loop {
            let notification = connection.iter().next();
            if let Some(Ok(Event::Incoming(Packet::Publish(p)))) = notification {
                if p.topic == topic
                    && let Some(peer_addr_str) = self.decrypt_message(&p.payload)
                {
                    // Parse as address candidates
                    let candidates = AddressCandidates::from_payload(&peer_addr_str);
                    info!("Received server candidates: {:?}", candidates);

                    if let Some(connected_addr) = Self::try_punch_candidates(socket, &candidates) {
                        client
                            .publish(ctopic.clone(), QoS::AtLeastOnce, true, Vec::new())
                            .unwrap();
                        return Some(connected_addr);
                    } else {
                        info!("Failed to connect to any server candidate");
                    }
                }
            } else {
                info!("MQTT event: {:?}", notification);
            }
        }
    }

    #[cfg(feature = "rumqttc")]
    pub fn get_client_addr(&mut self, socket: &UdpSocket) -> Option<SocketAddr> {
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

        // Send our address candidates (both local and STUN)
        let server_addr_payload = self.get_address_payload(socket);
        let stopic = format!("{}{}", self.server_name, "/server");
        client
            .publish(stopic.clone(), QoS::AtLeastOnce, true, server_addr_payload)
            .unwrap();

        let topic = format!("{}{}", self.server_name, "/client");
        client
            .publish(topic.clone(), QoS::AtLeastOnce, true, Vec::new())
            .unwrap();
        client.subscribe(topic.clone(), QoS::AtLeastOnce).unwrap();

        loop {
            let notification = connection.iter().next();
            if let Some(Ok(Event::Incoming(Packet::Publish(p)))) = notification {
                if p.topic == topic
                    && !p.payload.is_empty()
                    && let Some(peer_addr_str) = self.decrypt_message(&p.payload)
                {
                    // Parse as address candidates
                    let candidates = AddressCandidates::from_payload(&peer_addr_str);
                    info!("Received client candidates: {:?}", candidates);

                    if let Some(connected_addr) = Self::try_punch_candidates(socket, &candidates) {
                        return Some(connected_addr);
                    } else {
                        info!("Failed to connect to any client candidate");
                        return None;
                    }
                }
            } else if let Some(Ok(Event::Incoming(Packet::Publish(p)))) = &notification {
                if p.topic != topic {
                    info!("Invalid topic: {} != {}", p.topic, topic);
                }
            } else {
                info!("MQTT event: {:?}", notification);
            }
        }
    }

    #[cfg(feature = "esp-idf-mqtt")]
    pub fn get_server_addr(&mut self, socket: &UdpSocket) -> Option<SocketAddr> {
        use esp_idf_svc::mqtt::client::{EspMqttClient, MqttClientConfiguration, QoS};
        use std::sync::mpsc;
        use std::thread;

        // Get both local and STUN addresses
        let client_addr_payload = self.get_address_payload(socket);
        let ctopic_base = format!("{}{}", self.server_name, "/client");
        let topic_to_subscribe_base = format!("{}{}", self.server_name, "/server");

        let broker_url = self.mqtt_broker_url.as_str();
        let mqtt_config = MqttClientConfiguration::default();

        let (mut client, mut connection) = match EspMqttClient::new(broker_url, &mqtt_config) {
            Ok(c) => c,
            Err(e) => {
                info!("メインスレッドでMQTTクライアント作成失敗: {:?}", e);
                return None;
            }
        };
        info!("メインスレッドでMQTTクライアント作成成功！");

        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        let topic_to_subscribe_for_thread = topic_to_subscribe_base.clone();
        let ctopic_for_empty_publish = ctopic_base.clone();

        thread::spawn(move || {
            info!("MQTTイベントループスレッド開始！");
            // connection は Iterator<Item = Result<Event<'a, Message>>> を実装してるはずだから、
            // for event_result in connection.iter() って書ける！
            loop {
                let event_result = connection.next();
                // iter() を使ってループ！
                info!("MQTTイベントループスレッドでイベント待ち中…");
                match event_result {
                    Ok(event) => {
                        // Result を剥がす！
                        match event.payload() {
                            esp_idf_svc::mqtt::client::EventPayload::Received {
                                id: _,
                                topic: Some(recv_topic),
                                data,
                                details: _,
                            } if recv_topic == topic_to_subscribe_for_thread => {
                                info!("暗号化されたデータ受信！ ({} bytes)", data.len());
                                if let Err(e) = tx.send(data.to_vec()) {
                                    info!("チャネルに暗号化データ送るの失敗した… {}", e);
                                    return; // 送信失敗ならスレッド終了
                                }
                                info!("暗号化データ送信完了、スレッドの役目は一旦終わり！");
                            }
                            esp_idf_svc::mqtt::client::EventPayload::Connected(_) => {
                                info!("MQTT Connected in thread!");
                            }
                            esp_idf_svc::mqtt::client::EventPayload::Disconnected => {
                                info!("MQTT Disconnected in thread, exiting loop.");
                                return; // 切断されたらスレッド終了
                            }
                            // 他のイベントも必要ならここで処理してね！
                            _ => {
                                info!("Received other MQTT event: {:?}", event.payload())
                            }
                        }
                    }
                    Err(e) => {
                        info!("MQTT Error in thread's event loop: {:?}", e);
                        return; // エラーならスレッド終了
                    }
                }
                info!("MQTT event loop finished in thread."); // iter() が終わったらここに来る (普通は来ないはずだけど)
            }
        });

        info!("メインスレッド: publish開始！");
        match client.publish(&ctopic_base, QoS::AtLeastOnce, true, &client_addr_payload) {
            Ok(_) => info!("Published client address to {}", ctopic_base),
            Err(e) => {
                info!("Failed to publish client address: {:?}", e);
                return None;
            }
        }
        info!("メインスレッド: publish完了！ subscribe開始！");

        match client.subscribe(&topic_to_subscribe_base, QoS::AtLeastOnce) {
            Ok(_) => info!("Subscribed to {}", topic_to_subscribe_base),
            Err(e) => {
                info!("Failed to subscribe to topic: {:?}", e);
                return None;
            }
        }
        info!("メインスレッド: subscribe完了！ チャネルからの受信待ち…");

        let candidates_option = match rx.recv_timeout(std::time::Duration::from_secs(300)) {
            Ok(encrypted_data) => {
                info!(
                    "メインスレッドで暗号化データゲットだぜ！ ({} bytes)",
                    encrypted_data.len()
                );
                if let Some(peer_addr_str) = self.decrypt_message(&encrypted_data) {
                    // Parse as address candidates
                    let candidates = AddressCandidates::from_payload(&peer_addr_str);
                    info!("サーバーアドレス候補の復号成功！ {:?}", candidates);
                    match client.publish(&ctopic_for_empty_publish, QoS::AtLeastOnce, true, &[]) {
                        Ok(_) => {
                            info!("Published empty message to {}", ctopic_for_empty_publish)
                        }
                        Err(e) => info!("Failed to publish empty message: {:?}", e),
                    }
                    Some(candidates)
                } else {
                    info!("メッセージの復号失敗…");
                    None
                }
            }
            Err(e) => {
                info!(
                    "チャネルから暗号化データ受け取るの失敗した… (タイムアウトかも？) {}",
                    e
                );
                None
            }
        };

        if let Some(candidates) = candidates_option {
            // Try punching to all candidate addresses
            if let Some(connected_addr) = Self::try_punch_candidates(socket, &candidates) {
                info!("パンチング成功！接続先: {}", connected_addr);
                return Some(connected_addr);
            } else {
                info!("全候補へのパンチング失敗…");
                return None;
            }
        }
        None
    }

    #[cfg(feature = "esp-idf-mqtt")]
    pub fn get_client_addr(&mut self, socket: &UdpSocket) -> Option<SocketAddr> {
        use esp_idf_svc::mqtt::client::{EspMqttClient, MqttClientConfiguration, QoS};
        use std::sync::mpsc;
        use std::thread;

        // Get both local and STUN addresses
        let server_addr_payload = self.get_address_payload(socket);
        let server_topic_base = format!("{}{}", self.server_name, "/server");
        let client_topic_to_subscribe_base = format!("{}{}", self.server_name, "/client");

        let broker_url = self.mqtt_broker_url.as_str();
        let mqtt_config = MqttClientConfiguration {
            client_id: Some("wifikey-server"), // client_id は get_server_addr と被らないようにね！
            ..Default::default()
        };

        let (mut client, mut connection) = match EspMqttClient::new(broker_url, &mqtt_config) {
            Ok(c) => c,
            Err(e) => {
                info!(
                    "メインスレッドでMQTTクライアント作成失敗 (get_client_addr): {:?}",
                    e
                );
                return None;
            }
        };
        info!("メインスレッドでMQTTクライアント作成成功！ (get_client_addr)");

        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        let client_topic_to_subscribe_for_thread = client_topic_to_subscribe_base.clone();

        thread::spawn(move || {
            info!("MQTTイベントループスレッド開始！ (get_client_addr)");
            loop {
                let event_result = connection.next();
                // iter() を使ってループ！
                match event_result {
                    Ok(event) => {
                        // Result を剥がす！
                        match event.payload() {
                            esp_idf_svc::mqtt::client::EventPayload::Received {
                                id: _,
                                topic: Some(recv_topic),
                                data,
                                details: _,
                            } if recv_topic == client_topic_to_subscribe_for_thread => {
                                if data.is_empty() {
                                    info!("空メッセージ受信 (get_client_addr), スキップするね！");
                                    continue;
                                }
                                info!(
                                    "暗号化されたデータ受信！ ({} bytes) (get_client_addr)",
                                    data.len()
                                );
                                if let Err(e) = tx.send(data.to_vec()) {
                                    info!(
                                        "チャネルに暗号化データ送るの失敗した… {}(get_client_addr)",
                                        e
                                    );
                                    return;
                                }
                                info!(
                                    "暗号化データ送信完了、スレッドの役目は一旦終わり！ (get_client_addr)"
                                );
                            }
                            esp_idf_svc::mqtt::client::EventPayload::Connected(_) => {
                                info!("MQTT Connected in thread! (get_client_addr)");
                            }
                            esp_idf_svc::mqtt::client::EventPayload::Disconnected => {
                                info!(
                                    "MQTT Disconnected in thread, exiting loop. (get_client_addr)"
                                );
                                return;
                            }
                            _ => { /* info!("Received other MQTT event: {:?} (get_client_addr)", event.payload()) */
                            }
                        }
                    }
                    Err(e) => {
                        info!(
                            "MQTT Error in thread's event loop: {:?} (get_client_addr)",
                            e
                        );
                        return;
                    }
                }
            }
            info!("MQTT event loop finished in thread. (get_client_addr)");
        });

        info!("メインスレッド: publish開始！ (get_client_addr)");
        match client.publish(
            &server_topic_base,
            QoS::AtLeastOnce,
            true,
            &server_addr_payload,
        ) {
            Ok(_) => info!(
                "Published server address to {} (get_client_addr)",
                server_topic_base
            ),
            Err(e) => {
                info!(
                    "Failed to publish server address: {:?} (get_client_addr)",
                    e
                );
                return None;
            }
        }

        match client.publish(&client_topic_to_subscribe_base, QoS::AtLeastOnce, true, &[]) {
            Ok(_) => info!(
                "Published empty message to {} (get_client_addr)",
                client_topic_to_subscribe_base
            ),
            Err(e) => {
                info!(
                    "Failed to publish empty message to client topic: {:?} (get_client_addr)",
                    e
                );
            }
        }
        info!("メインスレッド: publish完了！ subscribe開始！ (get_client_addr)");

        match client.subscribe(&client_topic_to_subscribe_base, QoS::AtLeastOnce) {
            Ok(_) => info!(
                "Subscribed to {} (get_client_addr)",
                client_topic_to_subscribe_base
            ),
            Err(e) => {
                info!("Failed to subscribe to topic: {:?} (get_client_addr)", e);
                return None;
            }
        }
        info!("メインスレッド: subscribe完了！ チャネルからの受信待ち… (get_client_addr)");

        let candidates_option = match rx.recv_timeout(std::time::Duration::from_secs(30)) {
            Ok(encrypted_data) => {
                info!(
                    "メインスレッドで暗号化データゲットだぜ！ ({} bytes) (get_client_addr)",
                    encrypted_data.len()
                );
                if let Some(client_addr_str) = self.decrypt_message(&encrypted_data) {
                    // Parse as address candidates
                    let candidates = AddressCandidates::from_payload(&client_addr_str);
                    info!(
                        "クライアントアドレス候補の復号成功！ {:?} (get_client_addr)",
                        candidates
                    );
                    Some(candidates)
                } else {
                    info!("メッセージの復号失敗… (get_client_addr)");
                    None
                }
            }
            Err(e) => {
                info!(
                    "チャネルから暗号化データ受け取るの失敗した… (タイムアウトかも？) {} (get_client_addr)",
                    e
                );
                None
            }
        };

        if let Some(candidates) = candidates_option {
            // Try punching to all candidate addresses
            if let Some(connected_addr) = Self::try_punch_candidates(socket, &candidates) {
                info!(
                    "クライアントへのパンチング成功！接続先: {} (get_client_addr)",
                    connected_addr
                );
                return Some(connected_addr);
            } else {
                info!("全候補へのパンチング失敗… (get_client_addr)");
                return None;
            }
        }
        None
    }
}
