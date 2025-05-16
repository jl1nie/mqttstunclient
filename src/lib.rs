use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit};
use log::trace;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use stunclient::StunClient;

pub struct MQTTStunClient {
    mqtt_topic: String,
    key: [u8; 32],
    stun_addr: Option<SocketAddr>,
    peer_addr: Option<SocketAddr>,
}

impl MQTTStunClient {
    pub fn new(mqtt_topic: String, key: &str) -> Self {
        let key_bytes = key.as_bytes();
        let mut key = [0u8; 32];
        let len_to_copy = std::cmp::min(key_bytes.len(), key.len());
        key[..len_to_copy].copy_from_slice(&key_bytes[..len_to_copy]);

        Self {
            mqtt_topic,
            key,
            stun_addr: None,
            peer_addr: None,
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

    fn get_stun_addr(&mut self, socket: &UdpSocket) -> Option<SocketAddr> {
        let stun_server = "stun.l.google.com:19302"
            .to_socket_addrs()
            .unwrap()
            .find(|x| x.is_ipv4())
            .unwrap();

        let client = StunClient::new(stun_server);

        if let Ok(stun_addr) = client.query_external_address(socket) {
            self.stun_addr = Some(stun_addr);
            return Some(stun_addr);
        }
        None
    }

    fn get_global_ip(&mut self, socket: &UdpSocket) -> Vec<u8> {
        // グローバルIPアドレスを取得
        let global_ip = self
            .get_stun_addr(socket)
            .expect("Failed to get global IP address");

        trace!("Global IP Address: {}", global_ip);

        // メッセージを暗号化
        let message = format!("{}", global_ip);
        self.encrypt_message(message.as_bytes())
    }

    #[cfg(feature = "rumqttc")]
    pub fn get_server_addr(&mut self, socket: &UdpSocket) -> Option<SocketAddr> {
        use rumqttc::{Client, Event, MqttOptions, Packet, QoS};

        let mqttoptions = MqttOptions::new("wifikey-client", "broker.emqx.io", 1883);
        let (client, mut connection) = Client::new(mqttoptions, 10);

        let client_addr = self.get_global_ip(socket); //self.get_my_mqtt_payload(socket).unwrap();
        let ctopic = format!("{}{}", self.mqtt_topic, "/client");
        client
            .publish(ctopic.clone(), QoS::AtLeastOnce, true, client_addr)
            .unwrap();

        let topic = format!("{}{}", self.mqtt_topic, "/server");
        client.subscribe(topic.clone(), QoS::AtLeastOnce).unwrap();

        loop {
            let notification = connection.iter().next();
            if let Some(Ok(Event::Incoming(Packet::Publish(p)))) = notification {
                if p.topic == topic {
                    if let Some(peer_addr_str) = self.decrypt_message(&p.payload) {
                        match peer_addr_str.parse::<SocketAddr>() {
                            Ok(peer_socket_addr) => {
                                trace!("Server Address: {}", peer_socket_addr);
                                // UDPでピアにメッセージを送信
                                for _ in 0..5 {
                                    socket.send_to(b"PU", peer_socket_addr).unwrap();
                                    std::thread::sleep(std::time::Duration::from_millis(100));
                                }
                                client
                                    .publish(ctopic.clone(), QoS::AtLeastOnce, true, Vec::new()) // 空メッセージで上書き！
                                    .unwrap();
                                self.peer_addr = Some(peer_socket_addr);
                                return self.peer_addr;
                            }
                            Err(e) => {
                                trace!("Failed to parse peer address '{}': {}", peer_addr_str, e);
                                // パースに失敗した場合はループを続けるか、エラーを返すなど適宜処理
                                // ここでは None を返さずに次のメッセージを待つ
                            }
                        }
                    }
                }
            } else {
                trace!("Error: {:?}", notification);
            }
        }
    }
    #[cfg(feature = "rumqttc")]
    pub fn get_client_addr(&mut self, socket: &UdpSocket) -> Option<SocketAddr> {
        use rumqttc::{Client, Event, MqttOptions, Packet, QoS};
        let mqttoptions = MqttOptions::new("wifikey-server", "broker.emqx.io", 1883);
        let (client, mut connection) = Client::new(mqttoptions, 10);

        let server_addr = self.get_global_ip(socket); //self.get_my_mqtt_payload(socket).unwrap();
        let topic = format!("{}{}", self.mqtt_topic, "/server");
        client
            .publish(topic.clone(), QoS::AtLeastOnce, true, server_addr)
            .unwrap();

        let topic = format!("{}{}", self.mqtt_topic, "/client");
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
                                trace!("Client Address: {}", peer_socket_addr);
                                // UDPでピアにメッセージを送信
                                for _ in 0..5 {
                                    socket.send_to(b"PU", peer_socket_addr).unwrap();
                                    std::thread::sleep(std::time::Duration::from_millis(100));
                                }
                                self.peer_addr = Some(peer_socket_addr);
                                return self.peer_addr;
                            }
                            Err(e) => {
                                trace!("Failed to parse peer address '{}': {}", peer_addr_str, e);
                                return None;
                            }
                        }
                    }
                } else {
                    trace!("Invalid topic: {} != {}", p.topic, topic);
                }
            } else {
                trace!("Error: {:?}", notification);
            }
        }
    }

    #[cfg(feature = "esp-idf-mqtt")]
    pub fn get_server_addr(&mut self, socket: &UdpSocket) -> Option<SocketAddr> {
        use esp_idf_svc::mqtt::client::{EspMqttClient, MqttClientConfiguration, QoS};

        let broker_url = "mqtt://broker.emqx.io:1883";
        let mqtt_config = MqttClientConfiguration::default();
        // mqtt_config.client_id = Some("wifikey-client"); // 必要に応じてクライアントIDを設定

        let (mut client, mut connection) = match EspMqttClient::new(broker_url, &mqtt_config) {
            Ok(c) => c,
            Err(e) => {
                trace!("Failed to create MQTT client: {:?}", e);
                return None;
            }
        };

        let client_addr = self.get_global_ip(socket);
        let ctopic = format!("{}{}", self.mqtt_topic, "/client");
        match client.publish(&ctopic, QoS::AtLeastOnce, true, &client_addr) {
            Ok(_) => trace!("Published client address to {}", ctopic),
            Err(e) => {
                trace!("Failed to publish client address: {:?}", e);
                return None;
            }
        }

        let topic = format!("{}{}", self.mqtt_topic, "/server");
        match client.subscribe(&topic, QoS::AtLeastOnce) {
            Ok(_) => trace!("Subscribed to {}", topic),
            Err(e) => {
                trace!("Failed to subscribe to topic: {:?}", e);
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
                                        trace!("Server Address: {}", peer_socket_addr);
                                        for _ in 0..5 {
                                            socket.send_to(b"PU", peer_socket_addr).unwrap();
                                            std::thread::sleep(std::time::Duration::from_millis(
                                                100,
                                            ));
                                        }
                                        match client.publish(&ctopic, QoS::AtLeastOnce, true, &[]) {
                                            // 空メッセージで上書き！
                                            Ok(_) => {
                                                trace!("Published empty message to {}", ctopic)
                                            }
                                            Err(e) => {
                                                trace!("Failed to publish empty message: {:?}", e)
                                            }
                                        }
                                        self.peer_addr = Some(peer_socket_addr);
                                        return self.peer_addr;
                                    }
                                    Err(e) => {
                                        trace!(
                                            "Failed to parse peer address '{}': {}",
                                            peer_addr_str, e
                                        );
                                    }
                                }
                            }
                        }
                        _ => trace!("Received other MQTT event: {:?}", event.payload()),
                    }
                }
                Err(e) => {
                    trace!("MQTT Error: {:?}", e);
                    return None;
                }
            }
        }
    }

    #[cfg(feature = "esp-idf-mqtt")]
    pub fn get_client_addr(&mut self, socket: &UdpSocket) -> Option<SocketAddr> {
        use esp_idf_svc::mqtt::client::{EspMqttClient, MqttClientConfiguration, QoS}; // QoS をインポート

        let broker_url = "mqtt://broker.emqx.io:1883";
        let mqtt_config = MqttClientConfiguration {
            client_id: Some("wifikey-server"),
            ..Default::default()
        };

        let (mut client, mut connection) = match EspMqttClient::new(broker_url, &mqtt_config) {
            Ok(c) => c,
            Err(e) => {
                trace!("Failed to create MQTT client: {:?}", e);
                return None;
            }
        };

        let server_addr = self.get_global_ip(socket);
        let server_topic = format!("{}{}", self.mqtt_topic, "/server");
        match client.publish(&server_topic, QoS::AtLeastOnce, true, &server_addr) {
            Ok(_) => trace!("Published server address to {}", server_topic),
            Err(e) => {
                trace!("Failed to publish server address: {:?}", e);
                return None;
            }
        }

        let client_topic = format!("{}{}", self.mqtt_topic, "/client");
        // クライアントトピックを空メッセージで上書き
        match client.publish(&client_topic, QoS::AtLeastOnce, true, &[]) {
            Ok(_) => trace!("Published empty message to {}", client_topic),
            Err(e) => {
                trace!("Failed to publish empty message to client topic: {:?}", e);
                // ここでリターンするかどうかは要件次第だけど、とりあえずログだけ出す
            }
        }

        match client.subscribe(&client_topic, QoS::AtLeastOnce) {
            Ok(_) => trace!("Subscribed to {}", client_topic),
            Err(e) => {
                trace!("Failed to subscribe to topic: {:?}", e);
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
                                trace!("Received empty message on client topic, skipping.");
                                continue;
                            }
                            if let Some(peer_addr_str) = self.decrypt_message(data) {
                                match peer_addr_str.parse::<SocketAddr>() {
                                    Ok(peer_socket_addr) => {
                                        trace!("Client Address: {}", peer_socket_addr);
                                        for _ in 0..5 {
                                            socket.send_to(b"PU", peer_socket_addr).unwrap();
                                            std::thread::sleep(std::time::Duration::from_millis(
                                                100,
                                            ));
                                        }
                                        self.peer_addr = Some(peer_socket_addr);
                                        return self.peer_addr;
                                    }
                                    Err(e) => {
                                        trace!(
                                            "Failed to parse peer address '{}': {}",
                                            peer_addr_str, e
                                        );
                                        // パース失敗時はループを継続
                                    }
                                }
                            }
                        }
                        _ => trace!("Received other MQTT event: {:?}", event.payload()),
                    }
                }
                Err(e) => {
                    trace!("MQTT Error: {:?}", e);
                    return None;
                }
            }
        }
    }
}
