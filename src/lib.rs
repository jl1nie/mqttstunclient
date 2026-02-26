use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit};
use log::info;
use std::convert::TryInto;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};

#[cfg(feature = "ru-mqtt")]
mod turn;
#[cfg(feature = "ru-mqtt")]
mod turnproxy;
#[cfg(feature = "ru-mqtt")]
pub use turnproxy::TurnProxy;

/// ICE-like address candidates for NAT traversal.
///
/// Candidates are ordered by priority in `to_vec()`:
/// `local_v6` → `local` → `stun` → `turn`
#[derive(Debug, Clone)]
pub struct AddressCandidates {
    /// Local/private IPv4 address (host candidate)
    pub local: Option<SocketAddr>,
    /// STUN-acquired public IPv4 address (server-reflexive candidate)
    pub stun: Option<SocketAddr>,
    /// TURN relay address (relayed candidate — lowest priority, fallback)
    pub turn: Option<SocketAddr>,
    /// Local IPv6 global-unicast address (host candidate, NATless)
    pub local_v6: Option<SocketAddr>,
}

impl AddressCandidates {
    /// Create candidates with local and STUN addresses (turn/local_v6 default to None).
    pub fn new(local: Option<SocketAddr>, stun: Option<SocketAddr>) -> Self {
        Self {
            local,
            stun,
            turn: None,
            local_v6: None,
        }
    }

    /// Serialize to MQTT payload in key=value format.
    ///
    /// Example: `"local=192.168.1.10:5000,stun=1.2.3.4:5000,turn=relay:49152,v6=[::1]:5000"`
    pub fn to_payload(&self) -> String {
        let mut parts = Vec::new();
        if let Some(local) = self.local {
            parts.push(format!("local={local}"));
        }
        if let Some(stun) = self.stun {
            parts.push(format!("stun={stun}"));
        }
        if let Some(turn) = self.turn {
            parts.push(format!("turn={turn}"));
        }
        if let Some(v6) = self.local_v6 {
            parts.push(format!("v6={v6}"));
        }
        parts.join(",")
    }

    /// Parse from MQTT payload.
    ///
    /// Handles both the new key=value format and the legacy `"stun_addr,local_addr"` format
    /// for backward compatibility with older firmware.
    pub fn from_payload(payload: &str) -> Self {
        if payload.is_empty() {
            return Self::new(None, None);
        }

        // Detect format: new format contains '=' in the first field
        if payload.contains('=') {
            Self::parse_kv_format(payload)
        } else {
            Self::parse_legacy_format(payload)
        }
    }

    /// Parse the new key=value format.
    fn parse_kv_format(payload: &str) -> Self {
        let mut local = None;
        let mut stun = None;
        let mut turn = None;
        let mut local_v6 = None;

        // Split on ',' but be careful about IPv6 addresses like "[::1]:5000"
        // Since IPv6 addresses use brackets, a simple comma-split is safe
        // (brackets don't contain commas).
        for part in payload.split(',') {
            let part = part.trim();
            if let Some((key, val)) = part.split_once('=') {
                match key {
                    "local" => local = val.parse().ok(),
                    "stun" => stun = val.parse().ok(),
                    "turn" => turn = val.parse().ok(),
                    "v6" => local_v6 = val.parse().ok(),
                    _ => {}
                }
            }
        }
        Self {
            local,
            stun,
            turn,
            local_v6,
        }
    }

    /// Parse the legacy `"stun_addr,local_addr"` format for backward compatibility.
    fn parse_legacy_format(payload: &str) -> Self {
        let parts: Vec<&str> = payload.split(',').collect();
        match parts.as_slice() {
            [first, second] => Self {
                stun: first.parse().ok(),
                local: second.parse().ok(),
                turn: None,
                local_v6: None,
            },
            [single] => {
                if let Ok(addr) = single.parse::<SocketAddr>() {
                    if Self::is_private_ip(&addr) {
                        Self {
                            local: Some(addr),
                            stun: None,
                            turn: None,
                            local_v6: None,
                        }
                    } else {
                        Self {
                            stun: Some(addr),
                            local: None,
                            turn: None,
                            local_v6: None,
                        }
                    }
                } else {
                    Self::new(None, None)
                }
            }
            _ => Self::new(None, None),
        }
    }

    /// Check if an address is in a private/non-routable IP range.
    pub(crate) fn is_private_ip(addr: &SocketAddr) -> bool {
        match addr.ip() {
            IpAddr::V4(ip) => ip.is_private() || ip.is_loopback() || ip.is_link_local(),
            IpAddr::V6(ip) => ip.is_loopback(),
        }
    }

    /// Return all valid candidates as a vector in priority order:
    /// `local_v6` → `local` → `stun` → `turn`
    ///
    /// The TURN relay candidate is last (lowest priority / fallback).
    pub fn to_vec(&self) -> Vec<SocketAddr> {
        let mut addrs = Vec::new();
        if let Some(v6) = self.local_v6 {
            addrs.push(v6);
        }
        if let Some(local) = self.local {
            addrs.push(local);
        }
        if let Some(stun) = self.stun {
            addrs.push(stun);
        }
        if let Some(turn) = self.turn {
            addrs.push(turn);
        }
        addrs
    }
}

/// TURN server configuration (optional).
///
/// When set on [`MQTTStunClient`], a TURN relay will be allocated and its
/// address included as a fallback candidate.  If unset, only STUN+hole-punch
/// is used (the existing behaviour).
#[cfg(feature = "ru-mqtt")]
#[derive(Clone)]
pub struct TurnConfig {
    /// TURN server address, e.g. `"turn.example.com:3478".parse().unwrap()`
    pub server: SocketAddr,
    /// TURN username
    pub username: String,
    /// TURN password
    pub password: String,
}

/// Result returned by [`MQTTStunClient::get_client_addr`].
pub struct ConnectionResult {
    /// The effective peer address (hole-punched or TURN relay address).
    pub peer_addr: SocketAddr,
    /// TURN proxy, present only when the relay path is being used.
    /// Must be kept alive as long as the session is active.
    #[cfg(feature = "ru-mqtt")]
    pub turn_proxy: Option<TurnProxy>,
}

pub struct MQTTStunClient {
    server_name: String,
    key: [u8; 32],
    stun_server_addr: SocketAddr,
    mqtt_broker_url: String,
    /// TURN server configuration (optional, `ru-mqtt` feature only).
    #[cfg(feature = "ru-mqtt")]
    turn_config: Option<TurnConfig>,
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
        #[cfg(feature = "ru-mqtt")] turn_config: Option<TurnConfig>,
    ) -> Self {
        let key_bytes = key.as_bytes();
        let mut key = [0u8; 32];
        let len_to_copy = std::cmp::min(key_bytes.len(), key.len());
        key[..len_to_copy].copy_from_slice(&key_bytes[..len_to_copy]);

        // Default STUN server: Google's public STUN
        let stun_server_addr = stun_server
            .unwrap_or("stun.l.google.com:19302")
            .to_socket_addrs()
            .ok()
            .and_then(|mut iter| iter.find(|addr| addr.is_ipv4()))
            .expect("STUN server IPv4 address not found.");

        let mqtt_broker_url = mqtt_broker_url
            .unwrap_or("mqtt://broker.emqx.io:1883")
            .to_string();

        info!(
            "STUN Server: {stun_server_addr} MQTT Topic: {server_name} Broker: {mqtt_broker_url}"
        );

        Self {
            server_name,
            key,
            stun_server_addr,
            mqtt_broker_url,
            #[cfg(feature = "ru-mqtt")]
            turn_config,
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
            info!("STUN: おまじないが違うよ！ {magic_cookie:x}");
            return None;
        }
        if &transaction_id != expected_transaction_id {
            // 送ったIDと違う！誰の返事これ？
            info!("STUN: トランザクションIDが違うじゃん！");
            return None;
        }

        // 0x0101 は「成功したよ！」って意味
        if msg_type != 0x0101 {
            info!("STUN: 成功じゃなかったみたい… {msg_type:x}");
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
                    info!("STUN: MAPPED-ADDRESSゲット！ {ip}:{port}");
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
                    info!("STUN: XOR-MAPPED-ADDRESSゲット！ {ip}:{port}");
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
            info!("STUN: ソケットのタイムアウト設定失敗… {e}");
            // ま、いっか、とりあえず進も！
        }

        const MAX_RETRIES: usize = 3; // 3回までトライ！
        for attempt in 0..MAX_RETRIES {
            info!("STUN: トライ {}回目！", attempt + 1);
            if let Err(e) = socket.send_to(&request_payload, self.stun_server_addr) {
                info!("STUN: 「教えてー！」って送るの失敗した… {e:?}");
                if attempt == MAX_RETRIES - 1 {
                    // もう後がない！
                    socket
                        .set_read_timeout(original_timeout)
                        .unwrap_or_else(|e| info!("STUN: タイムアウト戻すのも失敗した… {e}"));
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
                    info!("STUN: 返事キタ！ {amt} bytes from {src}");
                    socket
                        .set_read_timeout(original_timeout)
                        .unwrap_or_else(|e| info!("STUN: タイムアウト戻すの失敗… {e}")); // とりあえずタイムアウト設定戻しとこ

                    // if src != stun_server_addr { // 違うとこから返事きたら…まぁいっか今回は！
                    //     info!("STUN: あれ、違う人から返事きた？ {}", src);
                    // }
                    let response_data = &buf[..amt];
                    if let Some(mapped_addr) =
                        MQTTStunClient::parse_stun_binding_response(response_data, &transaction_id)
                    {
                        info!("STUN: やった！自分の住所わかった！ {mapped_addr}");
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
                            .unwrap_or_else(|e| info!("STUN: タイムアウト戻すの失敗… {e}"));
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
            .unwrap_or_else(|e| info!("STUN: 最後にタイムアウト戻すのも失敗… {e}"));
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
                            info!("Local IP Address (detected): {local_with_port}");
                            return Some(local_with_port);
                        }
                    }
                    None
                } else {
                    info!("Local IP Address (bound): {addr}");
                    Some(addr)
                }
            }
            Err(e) => {
                info!("Failed to get local address: {e}");
                None
            }
        }
    }

    /// Get the first global-unicast IPv6 address of the local machine.
    ///
    /// Excludes loopback, link-local (fe80::/10), ULA (fc00::/7), and multicast.
    /// Returns `None` if no global IPv6 address is found or IPv6 is unavailable.
    ///
    /// `ru-mqtt` build: enumerates interfaces with `if_addrs` to find all addresses.
    /// `esp-idf-mqtt` build: uses the "connect trick" (route lookup, no packet sent)
    ///   which also works on ESP32/lwIP.
    #[cfg(feature = "ru-mqtt")]
    fn get_local_v6_addr(port: u16) -> Option<SocketAddr> {
        use if_addrs::get_if_addrs;
        match get_if_addrs() {
            Ok(addrs) => {
                for iface in addrs {
                    if let IpAddr::V6(v6) = iface.ip()
                        && !v6.is_loopback()
                        && !v6.is_multicast()
                        && !v6.is_unspecified()
                        && (v6.segments()[0] & 0xfe00) != 0xfc00 // not ULA
                        && (v6.segments()[0] & 0xffc0) != 0xfe80
                    // not link-local
                    {
                        let addr = SocketAddr::new(IpAddr::V6(v6), port);
                        info!("Local IPv6 Address: {addr}");
                        return Some(addr);
                    }
                }
                info!("No global IPv6 address found");
                None
            }
            Err(e) => {
                info!("Failed to enumerate network interfaces: {e}");
                None
            }
        }
    }

    /// IPv6 address discovery for ESP32 (esp-idf-mqtt).
    ///
    /// Uses UDP "connect" trick: set the routing destination without sending data,
    /// then read back the local address that lwIP selected.  Works even if Google
    /// DNS is not reachable because no packet is actually sent.
    #[cfg(all(feature = "esp-idf-mqtt", not(feature = "ru-mqtt")))]
    fn get_local_v6_addr(port: u16) -> Option<SocketAddr> {
        // Google Public DNS (IPv6) — used only as a routing target, no packet sent.
        let temp = UdpSocket::bind("[::]:0").ok()?;
        temp.connect("[2001:4860:4860::8888]:53").ok()?;
        let local = temp.local_addr().ok()?;
        if let IpAddr::V6(v6) = local.ip() {
            if !v6.is_loopback()
                && !v6.is_multicast()
                && !v6.is_unspecified()
                && (v6.segments()[0] & 0xfe00) != 0xfc00 // not ULA
                && (v6.segments()[0] & 0xffc0) != 0xfe80
            // not link-local
            {
                let addr = SocketAddr::new(IpAddr::V6(v6), port);
                info!("Local IPv6 Address (ESP32): {addr}");
                return Some(addr);
            }
        }
        info!("No global IPv6 address on ESP32");
        None
    }

    /// Get address candidates: local IPv4, STUN server-reflexive, and local IPv6.
    fn get_address_candidates(&mut self, socket: &UdpSocket) -> AddressCandidates {
        let local_addr = Self::get_local_addr(socket);
        let stun_addr = self.get_stun_addr(socket);

        // IPv6 discovery is available for both ru-mqtt and esp-idf-mqtt builds.
        #[cfg(any(feature = "ru-mqtt", feature = "esp-idf-mqtt"))]
        let local_v6 = {
            let port = socket.local_addr().ok().map(|a| a.port()).unwrap_or(0);
            Self::get_local_v6_addr(port)
        };
        #[cfg(not(any(feature = "ru-mqtt", feature = "esp-idf-mqtt")))]
        let local_v6: Option<SocketAddr> = None;

        info!(
            "Address Candidates - Local: {local_addr:?}, STUN: {stun_addr:?}, IPv6: {local_v6:?}"
        );

        AddressCandidates {
            local: local_addr,
            stun: stun_addr,
            local_v6,
            turn: None,
        }
    }

    /// Get encrypted payload containing address candidates
    fn get_address_payload(&mut self, socket: &UdpSocket) -> Vec<u8> {
        let candidates = self.get_address_candidates(socket);
        let message = candidates.to_payload();

        if message.is_empty() {
            panic!("Failed to get any IP address (both local and STUN failed)");
        }

        info!("Address payload: {message}");
        self.encrypt_message(message.as_bytes())
    }

    /// Normalize IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) to pure IPv4.
    ///
    /// Dual-stack sockets on Linux return IPv4 connections as IPv4-mapped IPv6
    /// addresses.  This helper converts them back so that address comparisons
    /// with plain IPv4 candidates work correctly.
    fn normalize_addr(addr: SocketAddr) -> SocketAddr {
        if let SocketAddr::V6(v6) = addr
            && let Some(v4) = v6.ip().to_ipv4_mapped()
        {
            return SocketAddr::new(IpAddr::V4(v4), v6.port());
        }
        addr
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
                    info!("Failed to send punch to {addr}: {e}");
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        // Wait for response from any candidate
        socket
            .set_read_timeout(Some(std::time::Duration::from_millis(500)))
            .unwrap_or_else(|e| info!("Failed to set read timeout: {e}"));

        let mut buf = [0; 10];
        let mut connected_addr: Option<SocketAddr> = None;

        for _ in 0..10 {
            match socket.recv_from(&mut buf) {
                Ok((amt, src)) => {
                    // Normalize IPv4-mapped IPv6 (::ffff:x.x.x.x) from dual-stack sockets.
                    let src = Self::normalize_addr(src);
                    if &buf[..amt] == b"PU" {
                        info!("Received punch response from {src}");
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
                    info!("Error receiving punch response: {e:?}");
                    break;
                }
            }
        }

        if let Some(addr) = connected_addr {
            info!("Successfully connected to {addr}");
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
    pub fn get_client_addr(&mut self, socket: &UdpSocket) -> Option<ConnectionResult> {
        use crate::turnproxy::TurnProxy;
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

        // Build enhanced address candidates: local IPv4 + STUN + IPv6 + TURN relay
        let local_addr = Self::get_local_addr(socket);
        let stun_addr = self.get_stun_addr(socket);
        let udp_port = socket.local_addr().ok().map(|a| a.port()).unwrap_or(0);
        let v6_addr = Self::get_local_v6_addr(udp_port);

        // Allocate TURN relay if configured (relay address is published as a candidate)
        let mut turn_proxy_opt: Option<TurnProxy> = None;
        if let Some(ref tc) = self.turn_config {
            match TurnProxy::allocate(tc.server, &tc.username, &tc.password) {
                Ok(proxy) => {
                    info!("TURN relay allocated: {}", proxy.relayed_addr);
                    turn_proxy_opt = Some(proxy);
                }
                Err(e) => info!("TURN allocation failed: {e} (continuing without TURN)"),
            }
        }

        let candidates = AddressCandidates {
            local: local_addr,
            stun: stun_addr,
            turn: turn_proxy_opt.as_ref().map(|p| p.relayed_addr),
            local_v6: v6_addr,
        };

        let message = candidates.to_payload();
        if message.is_empty() {
            info!("No address candidates available");
            return None;
        }
        info!("Server address candidates: {message}");
        let server_addr_payload = self.encrypt_message(message.as_bytes());

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
                    // Parse client's address candidates
                    let client_candidates = AddressCandidates::from_payload(&peer_addr_str);
                    info!("Received client candidates: {:?}", client_candidates);

                    // Create TURN permission for the client's public IP before punching.
                    // We use the STUN address (NAT-mapped) as the permitted peer IP.
                    if let Some(ref proxy) = turn_proxy_opt {
                        let client_ip = client_candidates
                            .stun
                            .or(client_candidates.local)
                            .map(|a| a.ip());
                        if let Some(ip) = client_ip {
                            use std::net::SocketAddr;
                            // TURN permission only cares about the IP; port is ignored.
                            let peer_for_perm = SocketAddr::new(ip, 3478);
                            if let Err(e) = proxy.create_permission(peer_for_perm) {
                                info!("TURN CreatePermission failed: {e} (continuing)");
                            }
                        }
                    }

                    // Try direct hole punch (exclude TURN relay from punch targets)
                    let direct = AddressCandidates {
                        local: client_candidates.local,
                        stun: client_candidates.stun,
                        local_v6: client_candidates.local_v6,
                        turn: None,
                    };

                    if let Some(connected_addr) = Self::try_punch_candidates(socket, &direct) {
                        info!("Direct connection established: {connected_addr}");
                        // TurnProxy (if any) is dropped here — relay threads are stopped.
                        return Some(ConnectionResult {
                            peer_addr: connected_addr,
                            turn_proxy: None,
                        });
                    }

                    // Direct punch failed — fall back to TURN relay if available
                    if let Some(mut proxy) = turn_proxy_opt {
                        info!("Direct punch failed, switching to TURN relay");
                        proxy.start_threads();
                        let relay_addr = proxy.relayed_addr;
                        return Some(ConnectionResult {
                            peer_addr: relay_addr,
                            turn_proxy: Some(proxy),
                        });
                    }

                    info!("Failed to connect to any client candidate");
                    return None;
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
                info!("メインスレッドでMQTTクライアント作成失敗: {e:?}");
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
                                    info!("チャネルに暗号化データ送るの失敗した… {e}");
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
                        info!("MQTT Error in thread's event loop: {e:?}");
                        return; // エラーならスレッド終了
                    }
                }
                info!("MQTT event loop finished in thread."); // iter() が終わったらここに来る (普通は来ないはずだけど)
            }
        });

        info!("メインスレッド: publish開始！");
        match client.publish(&ctopic_base, QoS::AtLeastOnce, true, &client_addr_payload) {
            Ok(_) => info!("Published client address to {ctopic_base}"),
            Err(e) => {
                info!("Failed to publish client address: {e:?}");
                return None;
            }
        }
        info!("メインスレッド: publish完了！ subscribe開始！");

        match client.subscribe(&topic_to_subscribe_base, QoS::AtLeastOnce) {
            Ok(_) => info!("Subscribed to {topic_to_subscribe_base}"),
            Err(e) => {
                info!("Failed to subscribe to topic: {e:?}");
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
                    info!("サーバーアドレス候補の復号成功！ {candidates:?}");
                    match client.publish(&ctopic_for_empty_publish, QoS::AtLeastOnce, true, &[]) {
                        Ok(_) => {
                            info!("Published empty message to {ctopic_for_empty_publish}")
                        }
                        Err(e) => info!("Failed to publish empty message: {e:?}"),
                    }
                    Some(candidates)
                } else {
                    info!("メッセージの復号失敗…");
                    None
                }
            }
            Err(e) => {
                info!("チャネルから暗号化データ受け取るの失敗した… (タイムアウトかも？) {e}");
                None
            }
        };

        if let Some(candidates) = candidates_option {
            // Try punching to all candidate addresses
            if let Some(connected_addr) = Self::try_punch_candidates(socket, &candidates) {
                info!("パンチング成功！接続先: {connected_addr}");
                return Some(connected_addr);
            } else {
                info!("全候補へのパンチング失敗…");
                return None;
            }
        }
        None
    }
    #[cfg(feature = "esp-idf-mqtt")]
    pub fn get_client_addr(&mut self, socket: &UdpSocket) -> Option<ConnectionResult> {
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
                info!("メインスレッドでMQTTクライアント作成失敗 (get_client_addr): {e:?}");
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
                                        "チャネルに暗号化データ送るの失敗した… {e}(get_client_addr)"
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
                        info!("MQTT Error in thread's event loop: {e:?} (get_client_addr)");
                        return;
                    }
                }
            }
        });

        info!("メインスレッド: publish開始！ (get_client_addr)");
        match client.publish(
            &server_topic_base,
            QoS::AtLeastOnce,
            true,
            &server_addr_payload,
        ) {
            Ok(_) => info!("Published server address to {server_topic_base} (get_client_addr)"),
            Err(e) => {
                info!("Failed to publish server address: {e:?} (get_client_addr)");
                return None;
            }
        }

        match client.publish(&client_topic_to_subscribe_base, QoS::AtLeastOnce, true, &[]) {
            Ok(_) => info!(
                "Published empty message to {client_topic_to_subscribe_base} (get_client_addr)"
            ),
            Err(e) => {
                info!("Failed to publish empty message to client topic: {e:?} (get_client_addr)");
            }
        }
        info!("メインスレッド: publish完了！ subscribe開始！ (get_client_addr)");

        match client.subscribe(&client_topic_to_subscribe_base, QoS::AtLeastOnce) {
            Ok(_) => info!("Subscribed to {client_topic_to_subscribe_base} (get_client_addr)"),
            Err(e) => {
                info!("Failed to subscribe to topic: {e:?} (get_client_addr)");
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
                    info!("クライアントアドレス候補の復号成功！ {candidates:?} (get_client_addr)");
                    Some(candidates)
                } else {
                    info!("メッセージの復号失敗… (get_client_addr)");
                    None
                }
            }
            Err(e) => {
                info!(
                    "チャネルから暗号化データ受け取るの失敗した… (タイムアウトかも？) {e} (get_client_addr)"
                );
                None
            }
        };

        if let Some(candidates) = candidates_option {
            // Try punching to all candidate addresses
            if let Some(connected_addr) = Self::try_punch_candidates(socket, &candidates) {
                info!("クライアントへのパンチング成功！接続先: {connected_addr} (get_client_addr)");
                return Some(ConnectionResult {
                    peer_addr: connected_addr,
                    #[cfg(feature = "ru-mqtt")]
                    turn_proxy: None,
                });
            } else {
                info!("全候補へのパンチング失敗… (get_client_addr)");
                return None;
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===================
    // AddressCandidates tests
    // ===================

    #[test]
    fn test_address_candidates_to_payload_both() {
        let candidates = AddressCandidates {
            local: Some("192.168.1.100:5000".parse().unwrap()),
            stun: Some("203.0.113.50:5000".parse().unwrap()),
            turn: None,
            local_v6: None,
        };
        let payload = candidates.to_payload();
        assert_eq!(payload, "local=192.168.1.100:5000,stun=203.0.113.50:5000");
    }

    #[test]
    fn test_address_candidates_to_payload_stun_only() {
        let candidates = AddressCandidates {
            local: None,
            stun: Some("203.0.113.50:5000".parse().unwrap()),
            turn: None,
            local_v6: None,
        };
        let payload = candidates.to_payload();
        assert_eq!(payload, "stun=203.0.113.50:5000");
    }

    #[test]
    fn test_address_candidates_to_payload_local_only() {
        let candidates = AddressCandidates {
            local: Some("192.168.1.100:5000".parse().unwrap()),
            stun: None,
            turn: None,
            local_v6: None,
        };
        let payload = candidates.to_payload();
        assert_eq!(payload, "local=192.168.1.100:5000");
    }

    #[test]
    fn test_address_candidates_to_payload_empty() {
        let candidates = AddressCandidates {
            local: None,
            stun: None,
            turn: None,
            local_v6: None,
        };
        let payload = candidates.to_payload();
        assert_eq!(payload, "");
    }

    #[test]
    fn test_address_candidates_to_payload_all() {
        let candidates = AddressCandidates {
            local: Some("192.168.1.10:5000".parse().unwrap()),
            stun: Some("1.2.3.4:5000".parse().unwrap()),
            turn: Some(
                "relay.example.com:49152"
                    .parse::<SocketAddr>()
                    .unwrap_or_else(|_| "5.6.7.8:49152".parse().unwrap()),
            ),
            local_v6: None,
        };
        let payload = candidates.to_payload();
        assert!(payload.contains("local=192.168.1.10:5000"));
        assert!(payload.contains("stun=1.2.3.4:5000"));
        assert!(payload.contains("turn="));
    }

    #[test]
    fn test_address_candidates_from_payload_legacy_both() {
        // Legacy format: "stun_addr,local_addr"
        let candidates = AddressCandidates::from_payload("203.0.113.50:5000,192.168.1.100:5000");
        assert_eq!(candidates.stun, Some("203.0.113.50:5000".parse().unwrap()));
        assert_eq!(
            candidates.local,
            Some("192.168.1.100:5000".parse().unwrap())
        );
        assert_eq!(candidates.turn, None);
        assert_eq!(candidates.local_v6, None);
    }

    #[test]
    fn test_address_candidates_from_payload_kv_both() {
        // New key=value format
        let candidates =
            AddressCandidates::from_payload("local=192.168.1.100:5000,stun=203.0.113.50:5000");
        assert_eq!(candidates.stun, Some("203.0.113.50:5000".parse().unwrap()));
        assert_eq!(
            candidates.local,
            Some("192.168.1.100:5000".parse().unwrap())
        );
        assert_eq!(candidates.turn, None);
    }

    #[test]
    fn test_address_candidates_from_payload_kv_with_turn() {
        let candidates = AddressCandidates::from_payload(
            "local=192.168.1.10:5000,stun=1.2.3.4:5000,turn=5.6.7.8:49152",
        );
        assert_eq!(candidates.local, Some("192.168.1.10:5000".parse().unwrap()));
        assert_eq!(candidates.stun, Some("1.2.3.4:5000".parse().unwrap()));
        assert_eq!(candidates.turn, Some("5.6.7.8:49152".parse().unwrap()));
        assert_eq!(candidates.local_v6, None);
    }

    #[test]
    fn test_address_candidates_from_payload_public_only() {
        // Public IP is detected as STUN in legacy format
        let candidates = AddressCandidates::from_payload("203.0.113.50:5000");
        assert_eq!(candidates.stun, Some("203.0.113.50:5000".parse().unwrap()));
        assert_eq!(candidates.local, None);
    }

    #[test]
    fn test_address_candidates_from_payload_private_only() {
        // Private IP is detected as local in legacy format
        let candidates = AddressCandidates::from_payload("192.168.1.100:5000");
        assert_eq!(candidates.stun, None);
        assert_eq!(
            candidates.local,
            Some("192.168.1.100:5000".parse().unwrap())
        );
    }

    #[test]
    fn test_address_candidates_from_payload_empty() {
        let candidates = AddressCandidates::from_payload("");
        assert_eq!(candidates.stun, None);
        assert_eq!(candidates.local, None);
    }

    #[test]
    fn test_address_candidates_roundtrip_new_format() {
        let original = AddressCandidates {
            local: Some("10.0.0.5:12345".parse().unwrap()),
            stun: Some("198.51.100.1:54321".parse().unwrap()),
            turn: Some("5.6.7.8:49152".parse().unwrap()),
            local_v6: None,
        };
        let payload = original.to_payload();
        let parsed = AddressCandidates::from_payload(&payload);
        assert_eq!(original.local, parsed.local);
        assert_eq!(original.stun, parsed.stun);
        assert_eq!(original.turn, parsed.turn);
    }

    #[test]
    fn test_address_candidates_to_vec() {
        let candidates = AddressCandidates {
            local: Some("192.168.1.100:5000".parse().unwrap()),
            stun: Some("203.0.113.50:5000".parse().unwrap()),
            turn: None,
            local_v6: None,
        };
        let vec = candidates.to_vec();
        assert_eq!(vec.len(), 2);
        // Local should come first (same-LAN priority)
        assert_eq!(vec[0], "192.168.1.100:5000".parse().unwrap());
        assert_eq!(vec[1], "203.0.113.50:5000".parse().unwrap());
    }

    #[test]
    fn test_address_candidates_is_private_ip() {
        // Private ranges
        assert!(AddressCandidates::is_private_ip(
            &"192.168.1.1:1234".parse().unwrap()
        ));
        assert!(AddressCandidates::is_private_ip(
            &"10.0.0.1:1234".parse().unwrap()
        ));
        assert!(AddressCandidates::is_private_ip(
            &"172.16.0.1:1234".parse().unwrap()
        ));
        assert!(AddressCandidates::is_private_ip(
            &"127.0.0.1:1234".parse().unwrap()
        ));
        // Link-local
        assert!(AddressCandidates::is_private_ip(
            &"169.254.1.1:1234".parse().unwrap()
        ));
        // Public
        assert!(!AddressCandidates::is_private_ip(
            &"8.8.8.8:1234".parse().unwrap()
        ));
        assert!(!AddressCandidates::is_private_ip(
            &"203.0.113.1:1234".parse().unwrap()
        ));
    }

    // ===================
    // Encryption tests
    // ===================

    /// Helper to create a key from password (same logic as MQTTStunClient::new)
    fn make_key(password: &str) -> [u8; 32] {
        let key_bytes = password.as_bytes();
        let mut key = [0u8; 32];
        let len_to_copy = std::cmp::min(key_bytes.len(), key.len());
        key[..len_to_copy].copy_from_slice(&key_bytes[..len_to_copy]);
        key
    }

    /// Encrypt test helper
    fn encrypt_with_key(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};
        let cipher = ChaCha20Poly1305::new(key.into());
        let mut iv = [0u8; 12];
        rand::fill(&mut iv);
        let ciphertext = cipher
            .encrypt(&iv.into(), plaintext)
            .expect("encryption failed");
        [iv.to_vec(), ciphertext].concat()
    }

    /// Decrypt test helper
    fn decrypt_with_key(key: &[u8; 32], encrypted: &[u8]) -> Option<String> {
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};
        if encrypted.len() < 12 {
            return None;
        }
        let (iv, ciphertext) = encrypted.split_at(12);
        let cipher = ChaCha20Poly1305::new(key.into());
        let iv_array: [u8; 12] = iv.try_into().ok()?;
        let decrypted = cipher.decrypt(&iv_array.into(), ciphertext).ok()?;
        String::from_utf8(decrypted).ok()
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = make_key("test_password");

        let plaintext = "Hello, World!";
        let encrypted = encrypt_with_key(&key, plaintext.as_bytes());
        let decrypted = decrypt_with_key(&key, &encrypted);

        assert!(decrypted.is_some());
        assert_eq!(decrypted.unwrap(), plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_empty() {
        let key = make_key("test_password");

        let plaintext = "";
        let encrypted = encrypt_with_key(&key, plaintext.as_bytes());
        let decrypted = decrypt_with_key(&key, &encrypted);

        assert!(decrypted.is_some());
        assert_eq!(decrypted.unwrap(), plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_binary_data() {
        let key = make_key("secret123");

        // Binary data that's valid UTF-8 when decrypted
        let plaintext = "192.168.1.100:5000,10.0.0.1:6000";
        let encrypted = encrypt_with_key(&key, plaintext.as_bytes());
        let decrypted = decrypt_with_key(&key, &encrypted);

        assert!(decrypted.is_some());
        assert_eq!(decrypted.unwrap(), plaintext);
    }

    #[test]
    fn test_decrypt_invalid_data() {
        let key = make_key("test_password");

        // Random garbage that's not valid encrypted data
        let garbage = vec![0u8, 1, 2, 3, 4, 5];
        let decrypted = decrypt_with_key(&key, &garbage);

        // Should fail to decrypt invalid data (too short for IV)
        assert!(decrypted.is_none());
    }

    #[test]
    fn test_decrypt_tampered_data() {
        let key = make_key("test_password");

        let plaintext = "secret message";
        let mut encrypted = encrypt_with_key(&key, plaintext.as_bytes());
        // Tamper with the ciphertext
        if encrypted.len() > 15 {
            encrypted[15] ^= 0xFF;
        }
        let decrypted = decrypt_with_key(&key, &encrypted);

        // Should fail to decrypt tampered data
        assert!(decrypted.is_none());
    }

    #[test]
    fn test_different_passwords_cannot_decrypt() {
        let key1 = make_key("password1");
        let key2 = make_key("password2");

        let plaintext = "secret message";
        let encrypted = encrypt_with_key(&key1, plaintext.as_bytes());
        let decrypted = decrypt_with_key(&key2, &encrypted);

        // Different password should fail to decrypt
        assert!(decrypted.is_none());
    }

    #[test]
    fn test_same_password_can_decrypt() {
        let key = make_key("shared_password");

        let plaintext = "shared secret";
        let encrypted = encrypt_with_key(&key, plaintext.as_bytes());
        let decrypted = decrypt_with_key(&key, &encrypted);

        // Same password should allow decryption
        assert!(decrypted.is_some());
        assert_eq!(decrypted.unwrap(), plaintext);
    }

    #[test]
    fn test_long_password_truncated() {
        // Password longer than 32 bytes should be truncated
        let long_password = "this_is_a_very_long_password_that_exceeds_32_bytes";
        let key = make_key(long_password);

        // Only first 32 bytes should be used
        assert_eq!(&key[..32], &long_password.as_bytes()[..32]);

        // Encryption should still work
        let plaintext = "test";
        let encrypted = encrypt_with_key(&key, plaintext.as_bytes());
        let decrypted = decrypt_with_key(&key, &encrypted);
        assert_eq!(decrypted.unwrap(), plaintext);
    }
}
