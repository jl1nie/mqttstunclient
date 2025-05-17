use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit};
use log::info;
use std::convert::TryInto;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};

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
            .unwrap()
            .next()
            .unwrap();

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

    fn get_global_ip(&mut self, socket: &UdpSocket) -> Vec<u8> {
        // グローバルIPアドレスを取得
        let global_ip = self
            .get_stun_addr(socket)
            .expect("Failed to get global IP address");

        info!("Global IP Address: {}", global_ip);

        // メッセージを暗号化
        let message = format!("{}", global_ip);
        self.encrypt_message(message.as_bytes())
    }

    #[cfg(feature = "rumqttc")]
    pub fn get_server_addr(&mut self, socket: &UdpSocket) -> Option<SocketAddr> {
        use rumqttc::{Client, Event, MqttOptions, Packet, QoS};
        //self.mqtt_borker_urlからhost/portを取得
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

        let client_addr = self.get_global_ip(socket); //self.get_my_mqtt_payload(socket).unwrap();
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
                        match peer_addr_str.parse::<SocketAddr>() {
                            Ok(peer_socket_addr) => {
                                info!("Server Address: {}", peer_socket_addr);
                                // UDPでピアにメッセージを送信
                                for _ in 0..5 {
                                    socket.send_to(b"PU", peer_socket_addr).unwrap();
                                    std::thread::sleep(std::time::Duration::from_millis(100));
                                }
                                // パンチングパケットの受信と破棄
                                socket
                                    .set_read_timeout(Some(std::time::Duration::from_millis(200)))
                                    .unwrap();
                                let mut buf = [0; 10]; // 受信バッファ
                                for _ in 0..5 {
                                    // 念のため複数回試行
                                    match socket.recv_from(&mut buf) {
                                        Ok((amt, src)) => {
                                            if &buf[..amt] == b"PU" {
                                                info!("Received punching packet from {}", src);
                                            } else {
                                                // パンチングパケット以外はとりあえずログだけ
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
                                            // タイムアウトならOK、ループを抜ける
                                            break;
                                        }
                                        Err(e) => {
                                            info!("Error receiving punching packet: {:?}", e);
                                            break; // その他のエラー
                                        }
                                    }
                                }
                                client
                                    .publish(ctopic.clone(), QoS::AtLeastOnce, true, Vec::new()) // 空メッセージで上書き！
                                    .unwrap();
                                return Some(peer_socket_addr);
                            }
                            Err(e) => {
                                info!("Failed to parse peer address '{}': {}", peer_addr_str, e);
                                // パースに失敗した場合はループを続けるか、エラーを返すなど適宜処理
                                // ここでは None を返さずに次のメッセージを待つ
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
    pub fn get_client_addr(&mut self, socket: &UdpSocket) -> Option<SocketAddr> {
        use rumqttc::{Client, Event, MqttOptions, Packet, QoS};
        //self.mqtt_borker_urlからhost/portを取得
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

        let server_addr = self.get_global_ip(socket); //self.get_my_mqtt_payload(socket).unwrap();
        let topic = format!("{}{}", self.server_name, "/server");
        client
            .publish(topic.clone(), QoS::AtLeastOnce, true, server_addr)
            .unwrap();

        let topic = format!("{}{}", self.server_name, "/client");
        client
            .publish(topic.clone(), QoS::AtLeastOnce, true, Vec::new()) // 空メッセージで上書き！
            .unwrap();
        client.subscribe(topic.clone(), QoS::AtLeastOnce).unwrap();

        loop {
            let notification = connection.iter().next();
            if let Some(Ok(Event::Incoming(Packet::Publish(p)))) = notification {
                if p.topic == topic {
                    if let Some(peer_addr_str) = self.decrypt_message(&p.payload) {
                        match peer_addr_str.parse::<SocketAddr>() {
                            Ok(peer_socket_addr) => {
                                info!("Client Address: {}", peer_socket_addr);
                                // UDPでピアにメッセージを送信
                                for _ in 0..5 {
                                    socket.send_to(b"PU", peer_socket_addr).unwrap();
                                    std::thread::sleep(std::time::Duration::from_millis(100));
                                }
                                // パンチングパケットの受信と破棄
                                socket
                                    .set_read_timeout(Some(std::time::Duration::from_millis(200)))
                                    .unwrap();
                                let mut buf = [0; 10]; // 受信バッファ
                                for _ in 0..5 {
                                    // 念のため複数回試行
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
                                return Some(peer_socket_addr);
                            }
                            Err(e) => {
                                info!("Failed to parse peer address '{}': {}", peer_addr_str, e);
                                return None;
                            }
                        }
                    }
                } else {
                    info!("Invalid topic: {} != {}", p.topic, topic);
                }
            } else {
                info!("Other: {:?}", notification);
            }
        }
    }

    #[cfg(feature = "esp-idf-mqtt")]
    pub fn get_server_addr(&mut self, socket: &UdpSocket) -> Option<SocketAddr> {
        use esp_idf_svc::mqtt::client::{EspMqttClient, MqttClientConfiguration, QoS};

        let broker_url = self.mqtt_broker_url.as_str();
        let mqtt_config = MqttClientConfiguration::default();
        // mqtt_config.client_id = Some("wifikey-client"); // 必要に応じてクライアントIDを設定

        let (mut client, mut connection) = match EspMqttClient::new(broker_url, &mqtt_config) {
            Ok(c) => c,
            Err(e) => {
                info!("Failed to create MQTT client: {:?}", e);
                return None;
            }
        };

        let client_addr = self.get_global_ip(socket);
        let ctopic = format!("{}{}", self.server_name, "/client");
        match client.publish(&ctopic, QoS::AtLeastOnce, true, &client_addr) {
            Ok(_) => info!("Published client address to {}", ctopic),
            Err(e) => {
                info!("Failed to publish client address: {:?}", e);
                return None;
            }
        }

        let topic = format!("{}{}", self.server_name, "/server");
        match client.subscribe(&topic, QoS::AtLeastOnce) {
            Ok(_) => info!("Subscribed to {}", topic),
            Err(e) => {
                info!("Failed to subscribe to topic: {:?}", e);
                return None;
            }
        }

        loop {
            match connection.next() {
                Ok(event) => {
                    match event.payload() {
                        esp_idf_svc::mqtt::client::EventPayload::Received {
                            id: _,
                            topic: Some(recv_topic),
                            data,
                            details: _,
                        } if recv_topic == topic => {
                            if let Some(peer_addr_str) = self.decrypt_message(data) {
                                match peer_addr_str.parse::<SocketAddr>() {
                                    Ok(peer_socket_addr) => {
                                        info!("Server Address: {}", peer_socket_addr);
                                        for _ in 0..5 {
                                            socket.send_to(b"PU", peer_socket_addr).unwrap();
                                            std::thread::sleep(std::time::Duration::from_millis(
                                                100,
                                            ));
                                        }
                                        // パンチングパケットの受信と破棄
                                        socket
                                            .set_read_timeout(Some(
                                                std::time::Duration::from_millis(200),
                                            ))
                                            .unwrap();
                                        let mut buf = [0; 5]; // 受信バッファ
                                        for _ in 0..10 {
                                            // 念のため複数回試行
                                            match socket.recv_from(&mut buf) {
                                                Ok((amt, src)) => {
                                                    if &buf[..amt] == b"PU" {
                                                        info!(
                                                            "Received punching packet from {}",
                                                            src
                                                        );
                                                    } else {
                                                        info!(
                                                            "Received unexpected packet from {}: {:?}",
                                                            src,
                                                            &buf[..amt]
                                                        );
                                                    }
                                                }
                                                Err(ref e)
                                                    if e.kind()
                                                        == std::io::ErrorKind::WouldBlock
                                                        || e.kind()
                                                            == std::io::ErrorKind::TimedOut =>
                                                {
                                                    break;
                                                }
                                                Err(e) => {
                                                    info!(
                                                        "Error receiving punching packet: {:?}",
                                                        e
                                                    );
                                                    break;
                                                }
                                            }
                                        }
                                        match client.publish(&ctopic, QoS::AtLeastOnce, true, &[]) {
                                            // 空メッセージで上書き！
                                            Ok(_) => {
                                                info!("Published empty message to {}", ctopic)
                                            }
                                            Err(e) => {
                                                info!("Failed to publish empty message: {:?}", e)
                                            }
                                        }
                                        return Some(peer_socket_addr);
                                    }
                                    Err(e) => {
                                        info!(
                                            "Failed to parse peer address '{}': {}",
                                            peer_addr_str, e
                                        );
                                    }
                                }
                            }
                        }
                        _ => info!("Received other MQTT event: {:?}", event.payload()),
                    }
                }
                Err(e) => {
                    info!("MQTT Error: {:?}", e);
                    return None;
                }
            }
        }
    }

    #[cfg(feature = "esp-idf-mqtt")]
    pub fn get_client_addr(&mut self, socket: &UdpSocket) -> Option<SocketAddr> {
        use esp_idf_svc::mqtt::client::{EspMqttClient, MqttClientConfiguration, QoS}; // QoS をインポート

        let broker_url = self.mqtt_broker_url.as_str();
        let mqtt_config = MqttClientConfiguration {
            client_id: Some("wifikey-server"),
            ..Default::default()
        };

        let (mut client, mut connection) = match EspMqttClient::new(broker_url, &mqtt_config) {
            Ok(c) => c,
            Err(e) => {
                info!("Failed to create MQTT client: {:?}", e);
                return None;
            }
        };

        let server_addr = self.get_global_ip(socket);
        let server_topic = format!("{}{}", self.server_name, "/server");
        match client.publish(&server_topic, QoS::AtLeastOnce, true, &server_addr) {
            Ok(_) => info!("Published server address to {}", server_topic),
            Err(e) => {
                info!("Failed to publish server address: {:?}", e);
                return None;
            }
        }

        let client_topic = format!("{}{}", self.server_name, "/client");
        // クライアントトピックを空メッセージで上書き
        match client.publish(&client_topic, QoS::AtLeastOnce, true, &[]) {
            Ok(_) => info!("Published empty message to {}", client_topic),
            Err(e) => {
                info!("Failed to publish empty message to client topic: {:?}", e);
                // ここでリターンするかどうかは要件次第だけど、とりあえずログだけ出す
            }
        }

        match client.subscribe(&client_topic, QoS::AtLeastOnce) {
            Ok(_) => info!("Subscribed to {}", client_topic),
            Err(e) => {
                info!("Failed to subscribe to topic: {:?}", e);
                return None;
            }
        }

        loop {
            match connection.next() {
                Ok(event) => {
                    match event.payload() {
                        esp_idf_svc::mqtt::client::EventPayload::Received {
                            id: _,
                            topic: Some(recv_topic),
                            data,
                            details: _,
                        } if recv_topic == client_topic => {
                            if data.is_empty() {
                                // 空のメッセージは無視する（自分のpublishかもしれないし）
                                info!("Received empty message on client topic, skipping.");
                                continue;
                            }
                            if let Some(peer_addr_str) = self.decrypt_message(data) {
                                match peer_addr_str.parse::<SocketAddr>() {
                                    Ok(peer_socket_addr) => {
                                        info!("Client Address: {}", peer_socket_addr);
                                        for _ in 0..5 {
                                            socket.send_to(b"PU", peer_socket_addr).unwrap();
                                            std::thread::sleep(std::time::Duration::from_millis(
                                                100,
                                            ));
                                        }
                                        // パンチングパケットの受信と破棄
                                        socket
                                            .set_read_timeout(Some(
                                                std::time::Duration::from_millis(200),
                                            ))
                                            .unwrap();
                                        let mut buf = [0; 10]; // 受信バッファ
                                        for _ in 0..5 {
                                            // 念のため複数回試行
                                            match socket.recv_from(&mut buf) {
                                                Ok((amt, src)) => {
                                                    if &buf[..amt] == b"PU" {
                                                        info!(
                                                            "Received punching packet from {}",
                                                            src
                                                        );
                                                    } else {
                                                        info!(
                                                            "Received unexpected packet from {}: {:?}",
                                                            src,
                                                            &buf[..amt]
                                                        );
                                                    }
                                                }
                                                Err(ref e)
                                                    if e.kind()
                                                        == std::io::ErrorKind::WouldBlock
                                                        || e.kind()
                                                            == std::io::ErrorKind::TimedOut =>
                                                {
                                                    break;
                                                }
                                                Err(e) => {
                                                    info!(
                                                        "Error receiving punching packet: {:?}",
                                                        e
                                                    );
                                                    break;
                                                }
                                            }
                                        }
                                        return Some(peer_socket_addr);
                                    }
                                    Err(e) => {
                                        info!(
                                            "Failed to parse peer address '{}': {}",
                                            peer_addr_str, e
                                        );
                                        // パース失敗時はループを継続
                                    }
                                }
                            }
                        }
                        _ => info!("Received other MQTT event: {:?}", event.payload()),
                    }
                }
                Err(e) => {
                    info!("MQTT Error: {:?}", e);
                    return None;
                }
            }
        }
    }
}
