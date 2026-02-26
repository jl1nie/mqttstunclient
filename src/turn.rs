//! TURN protocol implementation (RFC 5766)
//!
//! Implements TURN message encoding/decoding for:
//! - Allocate request/response (with long-term credential auth)
//! - CreatePermission request/response
//! - Send Indication (client → peer via relay)
//! - Data Indication (peer → client via relay)
//! - Refresh request/response (keepalive)

use log::info;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

// STUN magic cookie (RFC 5389)
const STUN_MAGIC_COOKIE: u32 = 0x2112A442;

// TURN message types (RFC 5766)
pub(crate) const TURN_ALLOCATE_REQUEST: u16 = 0x0003;
pub(crate) const TURN_ALLOCATE_SUCCESS: u16 = 0x0103;
pub(crate) const TURN_ALLOCATE_ERROR: u16 = 0x0113;
pub(crate) const TURN_REFRESH_REQUEST: u16 = 0x0004;
#[allow(dead_code)]
pub(crate) const TURN_REFRESH_SUCCESS: u16 = 0x0104;
pub(crate) const TURN_CREATE_PERMISSION_REQUEST: u16 = 0x0008;
pub(crate) const TURN_CREATE_PERMISSION_SUCCESS: u16 = 0x0108;
pub(crate) const TURN_SEND_INDICATION: u16 = 0x0016;
pub(crate) const TURN_DATA_INDICATION: u16 = 0x0017;

// STUN/TURN attribute types
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_USERNAME: u16 = 0x0006;
pub(crate) const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
const ATTR_ERROR_CODE: u16 = 0x0009;
pub(crate) const ATTR_DATA: u16 = 0x000C;
const ATTR_LIFETIME: u16 = 0x000D;
#[allow(dead_code)]
pub(crate) const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
pub(crate) const ATTR_XOR_PEER_ADDRESS: u16 = 0x0012;
pub(crate) const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;
const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;
const ATTR_REALM: u16 = 0x0014;
const ATTR_NONCE: u16 = 0x0015;

/// Long-term credential authentication information (RFC 5389 Section 10.2)
#[derive(Clone)]
pub struct AuthInfo {
    pub username: String,
    pub realm: String,
    pub nonce: String,
    /// Key = MD5(username:realm:password)
    pub key: Vec<u8>,
}

/// Result of a successful TURN Allocate
#[derive(Debug)]
pub struct AllocateResult {
    pub relayed_addr: SocketAddr,
    pub mapped_addr: Option<SocketAddr>,
    pub lifetime: u32,
}

/// TURN protocol error
#[derive(Debug)]
pub enum TurnError {
    /// 401 Unauthorized — contains realm and nonce for the retry
    Unauthorized { realm: String, nonce: String },
    /// Other STUN/TURN error response
    ErrorCode(u16, String),
    /// Protocol parse failure
    ParseError(String),
    /// Underlying I/O error
    Io(std::io::Error),
}

impl std::fmt::Display for TurnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TurnError::Unauthorized { realm, nonce } => {
                write!(f, "TURN 401 Unauthorized (realm={realm}, nonce={nonce})")
            }
            TurnError::ErrorCode(code, reason) => write!(f, "TURN error {code}: {reason}"),
            TurnError::ParseError(msg) => write!(f, "TURN parse error: {msg}"),
            TurnError::Io(e) => write!(f, "TURN I/O error: {e}"),
        }
    }
}

impl From<std::io::Error> for TurnError {
    fn from(e: std::io::Error) -> Self {
        TurnError::Io(e)
    }
}

// ---------------------------------------------------------------------------
// Attribute helpers
// ---------------------------------------------------------------------------

/// Append a STUN/TURN attribute (TLV, value padded to 4-byte boundary).
pub fn add_attr(buf: &mut Vec<u8>, attr_type: u16, value: &[u8]) {
    buf.extend_from_slice(&attr_type.to_be_bytes());
    buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
    buf.extend_from_slice(value);
    let pad = (4 - (value.len() % 4)) % 4;
    buf.extend(std::iter::repeat(0u8).take(pad));
}

/// Encode an IPv4 SocketAddr as an XOR-encoded address attribute value (8 bytes).
pub fn encode_xor_addr_v4(addr: SocketAddr) -> Vec<u8> {
    match addr {
        SocketAddr::V4(v4) => {
            let mut val = vec![0x00u8, 0x01]; // reserved=0, family=IPv4
            let xport = v4.port() ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
            val.extend_from_slice(&xport.to_be_bytes());
            let octets = v4.ip().octets();
            let magic = STUN_MAGIC_COOKIE.to_be_bytes();
            for i in 0..4 {
                val.push(octets[i] ^ magic[i]);
            }
            val
        }
        SocketAddr::V6(_) => vec![], // IPv6 not supported
    }
}

/// Decode an XOR-encoded address attribute value.
pub fn decode_xor_addr(buf: &[u8]) -> Option<SocketAddr> {
    if buf.len() < 4 {
        return None;
    }
    let family = buf[1];
    let xport = u16::from_be_bytes([buf[2], buf[3]]);
    let port = xport ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
    if family == 0x01 {
        // IPv4
        if buf.len() < 8 {
            return None;
        }
        let magic = STUN_MAGIC_COOKIE.to_be_bytes();
        let ip = Ipv4Addr::new(
            buf[4] ^ magic[0],
            buf[5] ^ magic[1],
            buf[6] ^ magic[2],
            buf[7] ^ magic[3],
        );
        Some(SocketAddr::new(IpAddr::V4(ip), port))
    } else {
        None // IPv6 not supported
    }
}

/// Decode a raw (non-XOR) IPv4 address attribute value.
fn decode_raw_addr_v4(buf: &[u8]) -> Option<SocketAddr> {
    if buf.len() < 8 || buf[1] != 0x01 {
        return None;
    }
    let port = u16::from_be_bytes([buf[2], buf[3]]);
    let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
    Some(SocketAddr::new(IpAddr::V4(ip), port))
}

// ---------------------------------------------------------------------------
// Message parsing
// ---------------------------------------------------------------------------

/// Parse a STUN/TURN message header.
/// Returns `(msg_type, body_len, transaction_id)` or `None` if invalid.
pub fn parse_header(buf: &[u8]) -> Option<(u16, usize, [u8; 12])> {
    if buf.len() < 20 {
        return None;
    }
    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    let body_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let magic = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if magic != STUN_MAGIC_COOKIE {
        return None;
    }
    let mut txid = [0u8; 12];
    txid.copy_from_slice(&buf[8..20]);
    Some((msg_type, body_len, txid))
}

/// Parse attribute TLV list from a message body slice.
pub fn parse_attrs(body: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut result = Vec::new();
    let mut offset = 0;
    while offset + 4 <= body.len() {
        let attr_type = u16::from_be_bytes([body[offset], body[offset + 1]]);
        let attr_len = u16::from_be_bytes([body[offset + 2], body[offset + 3]]) as usize;
        offset += 4;
        if offset + attr_len > body.len() {
            break;
        }
        result.push((attr_type, body[offset..offset + attr_len].to_vec()));
        // Advance past value + padding
        let padded = (attr_len + 3) & !3;
        offset += padded;
    }
    result
}

// ---------------------------------------------------------------------------
// Cryptographic helpers
// ---------------------------------------------------------------------------

/// Compute HMAC-SHA1 of `msg` under `key`.
pub fn compute_hmac_sha1(key: &[u8], msg: &[u8]) -> [u8; 20] {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;
    type HmacSha1 = Hmac<Sha1>;
    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    let result = mac.finalize();
    result.into_bytes().into()
}

/// Compute the TURN long-term credential key: MD5(username:realm:password).
pub fn compute_long_term_key(username: &str, realm: &str, password: &str) -> Vec<u8> {
    use md5::{Digest, Md5};
    let mut hasher = Md5::new();
    hasher.update(format!("{username}:{realm}:{password}").as_bytes());
    hasher.finalize().to_vec()
}

// ---------------------------------------------------------------------------
// Message building
// ---------------------------------------------------------------------------

/// Build a 20-byte STUN/TURN message header.
fn build_header(msg_type: u16, body_len: u16, txid: &[u8; 12]) -> Vec<u8> {
    let mut h = Vec::with_capacity(20);
    h.extend_from_slice(&msg_type.to_be_bytes());
    h.extend_from_slice(&body_len.to_be_bytes());
    h.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    h.extend_from_slice(txid);
    h
}

/// Build a complete STUN/TURN message with a MESSAGE-INTEGRITY attribute.
///
/// Per RFC 5389 §15.4:
/// - The length field is set to include the MESSAGE-INTEGRITY attribute size.
/// - The HMAC-SHA1 is computed over [header-with-updated-length + attrs-before-MI].
fn build_with_integrity(msg_type: u16, txid: &[u8; 12], attrs: Vec<u8>, key: &[u8]) -> Vec<u8> {
    // Body length = all attrs + MESSAGE-INTEGRITY (4-byte TLV header + 20-byte HMAC)
    let body_len = (attrs.len() + 24) as u16;
    let mut msg = build_header(msg_type, body_len, txid);
    msg.extend_from_slice(&attrs);
    // HMAC is computed over [header-with-MI-included-length + attrs]
    let hmac = compute_hmac_sha1(key, &msg);
    add_attr(&mut msg, ATTR_MESSAGE_INTEGRITY, &hmac);
    msg
}

/// Build an unauthenticated Allocate Request (initial probe to get 401+REALM+NONCE).
pub fn build_allocate_request(txid: &[u8; 12]) -> Vec<u8> {
    let mut attrs = Vec::new();
    // REQUESTED-TRANSPORT = 17 (UDP)
    add_attr(&mut attrs, ATTR_REQUESTED_TRANSPORT, &[0x11, 0x00, 0x00, 0x00]);
    let body_len = attrs.len() as u16;
    let mut msg = build_header(TURN_ALLOCATE_REQUEST, body_len, txid);
    msg.extend_from_slice(&attrs);
    msg
}

/// Build an authenticated Allocate Request.
pub fn build_allocate_request_auth(txid: &[u8; 12], auth: &AuthInfo) -> Vec<u8> {
    let mut attrs = Vec::new();
    add_attr(&mut attrs, ATTR_REQUESTED_TRANSPORT, &[0x11, 0x00, 0x00, 0x00]);
    add_attr(&mut attrs, ATTR_USERNAME, auth.username.as_bytes());
    add_attr(&mut attrs, ATTR_REALM, auth.realm.as_bytes());
    add_attr(&mut attrs, ATTR_NONCE, auth.nonce.as_bytes());
    build_with_integrity(TURN_ALLOCATE_REQUEST, txid, attrs, &auth.key)
}

/// Parse an Allocate response.
/// Returns `AllocateResult` on success or `TurnError` on failure.
pub fn parse_allocate_response(buf: &[u8]) -> Result<AllocateResult, TurnError> {
    let (msg_type, body_len, _txid) = parse_header(buf)
        .ok_or_else(|| TurnError::ParseError("Invalid STUN header".to_string()))?;
    let body = buf
        .get(20..20 + body_len)
        .ok_or_else(|| TurnError::ParseError("Truncated body".to_string()))?;
    let attrs = parse_attrs(body);

    if msg_type == TURN_ALLOCATE_ERROR {
        let mut error_code = 0u16;
        let mut error_reason = String::new();
        let mut realm = String::new();
        let mut nonce = String::new();
        for (attr_type, value) in &attrs {
            match *attr_type {
                ATTR_ERROR_CODE if value.len() >= 4 => {
                    let class = (value[2] & 0x07) as u16;
                    let num = value[3] as u16;
                    error_code = class * 100 + num;
                    error_reason = String::from_utf8_lossy(&value[4..]).to_string();
                }
                ATTR_REALM => realm = String::from_utf8_lossy(value).to_string(),
                ATTR_NONCE => nonce = String::from_utf8_lossy(value).to_string(),
                _ => {}
            }
        }
        if error_code == 401 {
            return Err(TurnError::Unauthorized { realm, nonce });
        }
        return Err(TurnError::ErrorCode(error_code, error_reason));
    }

    if msg_type != TURN_ALLOCATE_SUCCESS {
        return Err(TurnError::ParseError(format!(
            "Unexpected message type: 0x{msg_type:04x}"
        )));
    }

    let mut relayed_addr = None;
    let mut mapped_addr = None;
    let mut lifetime = 600u32;
    for (attr_type, value) in &attrs {
        match *attr_type {
            ATTR_XOR_RELAYED_ADDRESS => relayed_addr = decode_xor_addr(value),
            ATTR_XOR_MAPPED_ADDRESS => mapped_addr = decode_xor_addr(value),
            ATTR_MAPPED_ADDRESS if mapped_addr.is_none() => {
                mapped_addr = decode_raw_addr_v4(value)
            }
            ATTR_LIFETIME if value.len() >= 4 => {
                lifetime = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
            }
            _ => {}
        }
    }

    let relayed = relayed_addr.ok_or_else(|| {
        TurnError::ParseError("Missing XOR-RELAYED-ADDRESS in Allocate response".to_string())
    })?;
    info!("TURN: relay={relayed}, mapped={mapped_addr:?}, lifetime={lifetime}s");

    Ok(AllocateResult {
        relayed_addr: relayed,
        mapped_addr,
        lifetime,
    })
}

/// Build a CreatePermission Request (authenticated).
pub fn build_create_permission_request(
    txid: &[u8; 12],
    peer: SocketAddr,
    auth: &AuthInfo,
) -> Vec<u8> {
    let mut attrs = Vec::new();
    let xor_val = encode_xor_addr_v4(peer);
    add_attr(&mut attrs, ATTR_XOR_PEER_ADDRESS, &xor_val);
    add_attr(&mut attrs, ATTR_USERNAME, auth.username.as_bytes());
    add_attr(&mut attrs, ATTR_REALM, auth.realm.as_bytes());
    add_attr(&mut attrs, ATTR_NONCE, auth.nonce.as_bytes());
    build_with_integrity(TURN_CREATE_PERMISSION_REQUEST, txid, attrs, &auth.key)
}

/// Build a Send Indication (no authentication required for indications).
pub fn build_send_indication(peer: SocketAddr, data: &[u8]) -> Vec<u8> {
    let mut txid = [0u8; 12];
    rand::fill(&mut txid);
    let mut attrs = Vec::new();
    add_attr(&mut attrs, ATTR_XOR_PEER_ADDRESS, &encode_xor_addr_v4(peer));
    add_attr(&mut attrs, ATTR_DATA, data);
    let body_len = attrs.len() as u16;
    let mut msg = build_header(TURN_SEND_INDICATION, body_len, &txid);
    msg.extend_from_slice(&attrs);
    msg
}

/// Parse a Data Indication and return `(peer_addr, data)`.
pub fn parse_data_indication(buf: &[u8]) -> Option<(SocketAddr, Vec<u8>)> {
    let (msg_type, body_len, _txid) = parse_header(buf)?;
    if msg_type != TURN_DATA_INDICATION {
        return None;
    }
    let body = buf.get(20..20 + body_len)?;
    let attrs = parse_attrs(body);
    let mut peer_addr = None;
    let mut data = None;
    for (attr_type, value) in attrs {
        match attr_type {
            ATTR_XOR_PEER_ADDRESS => peer_addr = decode_xor_addr(&value),
            ATTR_DATA => data = Some(value),
            _ => {}
        }
    }
    match (peer_addr, data) {
        (Some(addr), Some(d)) => Some((addr, d)),
        _ => None,
    }
}

/// Build a Refresh Request (authenticated, used for allocation keepalive).
pub fn build_refresh_request(txid: &[u8; 12], lifetime: u32, auth: &AuthInfo) -> Vec<u8> {
    let mut attrs = Vec::new();
    add_attr(&mut attrs, ATTR_LIFETIME, &lifetime.to_be_bytes());
    add_attr(&mut attrs, ATTR_USERNAME, auth.username.as_bytes());
    add_attr(&mut attrs, ATTR_REALM, auth.realm.as_bytes());
    add_attr(&mut attrs, ATTR_NONCE, auth.nonce.as_bytes());
    build_with_integrity(TURN_REFRESH_REQUEST, txid, attrs, &auth.key)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_attr_aligned() {
        let mut buf = Vec::new();
        add_attr(&mut buf, 0x0001, &[1, 2, 3, 4]); // 4 bytes — no padding needed
        assert_eq!(buf.len(), 8);
        assert_eq!(&buf[0..2], &[0x00, 0x01]);
        assert_eq!(&buf[2..4], &[0x00, 0x04]);
        assert_eq!(&buf[4..8], &[1, 2, 3, 4]);
    }

    #[test]
    fn test_add_attr_unaligned() {
        let mut buf = Vec::new();
        add_attr(&mut buf, 0x0006, b"alice"); // 5 bytes → 3 bytes padding
        assert_eq!(buf.len(), 12); // 4 TLV + 5 value + 3 pad
        assert_eq!(&buf[2..4], &[0x00, 0x05]); // length = actual 5 bytes
        assert_eq!(&buf[4..9], b"alice");
        assert_eq!(&buf[9..12], &[0, 0, 0]);
    }

    #[test]
    fn test_encode_decode_xor_addr_roundtrip() {
        let original: SocketAddr = "203.0.113.50:12345".parse().unwrap();
        let encoded = encode_xor_addr_v4(original);
        let decoded = decode_xor_addr(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_encode_decode_xor_addr_boundaries() {
        let lo: SocketAddr = "1.2.3.4:1".parse().unwrap();
        let hi: SocketAddr = "255.255.255.255:65535".parse().unwrap();
        assert_eq!(decode_xor_addr(&encode_xor_addr_v4(lo)).unwrap(), lo);
        assert_eq!(decode_xor_addr(&encode_xor_addr_v4(hi)).unwrap(), hi);
    }

    #[test]
    fn test_parse_header_valid() {
        let txid = [0xABu8; 12];
        let msg = build_header(0x0003, 0x0010, &txid);
        let (msg_type, body_len, parsed_txid) = parse_header(&msg).unwrap();
        assert_eq!(msg_type, 0x0003);
        assert_eq!(body_len, 0x0010);
        assert_eq!(parsed_txid, txid);
    }

    #[test]
    fn test_parse_header_wrong_magic() {
        let mut msg = build_header(0x0003, 0, &[0u8; 12]);
        msg[4] = 0xFF; // corrupt magic cookie
        assert!(parse_header(&msg).is_none());
    }

    #[test]
    fn test_parse_header_too_short() {
        assert!(parse_header(&[0u8; 10]).is_none());
    }

    #[test]
    fn test_parse_attrs_multiple() {
        let mut buf = Vec::new();
        add_attr(&mut buf, 0x0001, b"hello");
        add_attr(&mut buf, 0x0002, b"world!!");
        let attrs = parse_attrs(&buf);
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[0].0, 0x0001);
        assert_eq!(attrs[0].1, b"hello");
        assert_eq!(attrs[1].0, 0x0002);
        assert_eq!(attrs[1].1, b"world!!");
    }

    #[test]
    fn test_build_allocate_request_structure() {
        let txid = [0xFFu8; 12];
        let pkt = build_allocate_request(&txid);
        assert!(pkt.len() >= 20);
        let (msg_type, _, parsed_txid) = parse_header(&pkt).unwrap();
        assert_eq!(msg_type, TURN_ALLOCATE_REQUEST);
        assert_eq!(parsed_txid, txid);
    }

    #[test]
    fn test_build_send_indication_structure() {
        let peer: SocketAddr = "203.0.113.50:5000".parse().unwrap();
        let data = b"hello world";
        let pkt = build_send_indication(peer, data);
        let (msg_type, body_len, _) = parse_header(&pkt).unwrap();
        assert_eq!(msg_type, TURN_SEND_INDICATION);
        let body = &pkt[20..20 + body_len];
        let attrs = parse_attrs(body);
        // Find XOR-PEER-ADDRESS
        let xpa = attrs
            .iter()
            .find(|(t, _)| *t == ATTR_XOR_PEER_ADDRESS)
            .unwrap();
        assert_eq!(decode_xor_addr(&xpa.1).unwrap(), peer);
        // Find DATA
        let d = attrs.iter().find(|(t, _)| *t == ATTR_DATA).unwrap();
        assert_eq!(d.1, data);
    }

    #[test]
    fn test_parse_data_indication() {
        let peer: SocketAddr = "1.2.3.4:5000".parse().unwrap();
        let data = b"test payload";
        let txid = [0x42u8; 12];
        let mut attrs = Vec::new();
        add_attr(&mut attrs, ATTR_XOR_PEER_ADDRESS, &encode_xor_addr_v4(peer));
        add_attr(&mut attrs, ATTR_DATA, data);
        let body_len = attrs.len() as u16;
        let mut pkt = build_header(TURN_DATA_INDICATION, body_len, &txid);
        pkt.extend_from_slice(&attrs);
        let (addr, payload) = parse_data_indication(&pkt).unwrap();
        assert_eq!(addr, peer);
        assert_eq!(payload, data);
    }

    #[test]
    fn test_parse_data_indication_wrong_type() {
        let txid = [0u8; 12];
        let pkt = build_header(TURN_SEND_INDICATION, 0, &txid);
        assert!(parse_data_indication(&pkt).is_none());
    }

    #[test]
    fn test_compute_long_term_key_length() {
        let key = compute_long_term_key("user", "example.org", "password");
        assert_eq!(key.len(), 16); // MD5 produces 16 bytes
    }

    #[test]
    fn test_build_with_integrity_has_mi_attribute() {
        let key = compute_long_term_key("user", "realm", "password");
        let auth = AuthInfo {
            username: "user".to_string(),
            realm: "realm".to_string(),
            nonce: "nonce".to_string(),
            key,
        };
        let txid = [1u8; 12];
        let pkt = build_allocate_request_auth(&txid, &auth);
        let (_, body_len, _) = parse_header(&pkt).unwrap();
        let body = &pkt[20..20 + body_len];
        let attrs = parse_attrs(body);
        let has_mi = attrs.iter().any(|(t, _)| *t == ATTR_MESSAGE_INTEGRITY);
        assert!(has_mi, "MESSAGE-INTEGRITY attribute must be present");
        // The MI value should be 20 bytes (SHA1 HMAC)
        let mi = attrs
            .iter()
            .find(|(t, _)| *t == ATTR_MESSAGE_INTEGRITY)
            .unwrap();
        assert_eq!(mi.1.len(), 20);
    }

    #[test]
    fn test_build_refresh_request_structure() {
        let key = compute_long_term_key("u", "r", "p");
        let auth = AuthInfo {
            username: "u".to_string(),
            realm: "r".to_string(),
            nonce: "n".to_string(),
            key,
        };
        let txid = [7u8; 12];
        let pkt = build_refresh_request(&txid, 600, &auth);
        let (msg_type, _, parsed_txid) = parse_header(&pkt).unwrap();
        assert_eq!(msg_type, TURN_REFRESH_REQUEST);
        assert_eq!(parsed_txid, txid);
    }
}
