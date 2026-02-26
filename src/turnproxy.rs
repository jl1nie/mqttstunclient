//! TURN relay proxy (RFC 5766).
//!
//! Transparently bridges between a local [`WkListener`] socket and a TURN relay
//! server so that the WkListener does not need to know about TURN at all.
//!
//! ## Architecture
//!
//! ```text
//! [WkListener] ←→ app_socket (127.0.0.1:APP_PORT)
//!      ↕ UDP localhost (via vcs)
//! [TurnProxy threads]
//!      ↕ TURN protocol (Send/Data Indications)
//! [TURN Server]
//!      ↕ plain UDP
//! [ESP32]
//! ```
//!
//! - **Thread A** (`turn_socket` → `vcs` → `app_socket`): receives Data
//!   Indications from the TURN server, extracts the actual ESP32 source address,
//!   and forwards the payload to the WkListener via the local VCS socket.
//! - **Thread B** (`vcs` ← `app_socket` → `turn_socket`): receives data sent
//!   by WkListener/WkSession toward the VCS address and wraps it in a TURN
//!   Send Indication before forwarding to the TURN server.
//! - **Thread C**: sends a TURN Refresh every 30 s to keep the allocation alive.

use crate::turn::{
    build_allocate_request, build_allocate_request_auth, build_create_permission_request,
    build_refresh_request, build_send_indication, compute_long_term_key, parse_allocate_response,
    parse_data_indication, parse_header, AuthInfo, TurnError, TURN_CREATE_PERMISSION_SUCCESS,
};
use log::info;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// TURN relay proxy.
///
/// ## Usage
///
/// ```no_run
/// # use mqttstunclient::TurnProxy;
/// # let turn_server: std::net::SocketAddr = "203.0.113.1:3478".parse().unwrap();
/// # let esp32_addr: std::net::SocketAddr = "198.51.100.1:54321".parse().unwrap();
/// let mut proxy = TurnProxy::allocate(turn_server, "user", "pass").unwrap();
/// proxy.create_permission(esp32_addr).unwrap();
/// let app_socket = proxy.take_app_socket().unwrap();
/// proxy.start_threads();
/// // Hand app_socket to WkListener::bind()
/// // Keep proxy alive until the session ends (Drop stops the threads)
/// ```
pub struct TurnProxy {
    turn_socket: Arc<UdpSocket>,
    turn_server: SocketAddr,
    auth: AuthInfo,
    /// The TURN-allocated relay address (publish this in AddressCandidates).
    pub relayed_addr: SocketAddr,
    /// VCS socket bound to 127.0.0.1:VCP_PORT — used by Thread A and Thread B.
    vcs: Arc<UdpSocket>,
    /// Address of app_socket (127.0.0.1:APP_PORT) — Thread A sends data here.
    app_addr: SocketAddr,
    /// Most recent ESP32 source address (populated from the first Data Indication).
    actual_client: Arc<Mutex<Option<SocketAddr>>>,
    /// The WkListener socket (consumed by `take_app_socket()`).
    app_socket: Option<UdpSocket>,
    /// Tells background threads to exit.
    stop: Arc<AtomicBool>,
    /// Background thread handles (kept alive until TurnProxy is dropped).
    _threads: Vec<JoinHandle<()>>,
}

impl TurnProxy {
    /// Perform TURN allocation using the long-term credential mechanism (RFC 5766).
    ///
    /// Connects to `turn_server`, performs the two-step authentication dance
    /// (unauthenticated probe → 401 with REALM/NONCE → authenticated Allocate),
    /// and returns a `TurnProxy` ready to use.
    pub fn allocate(
        turn_server: SocketAddr,
        username: &str,
        password: &str,
    ) -> anyhow::Result<Self> {
        let turn_socket = UdpSocket::bind("0.0.0.0:0")?;
        turn_socket.set_read_timeout(Some(Duration::from_secs(5)))?;

        // --- Phase 1: unauthenticated probe to get 401 + REALM + NONCE ---
        let mut txid = [0u8; 12];
        rand::fill(&mut txid);
        let req = build_allocate_request(&txid);
        info!("TURN: sending unauthenticated Allocate to {turn_server}");
        turn_socket.send_to(&req, turn_server)?;

        let mut buf = [0u8; 1024];
        let (amt, _) = turn_socket.recv_from(&mut buf)?;

        let auth = match parse_allocate_response(&buf[..amt]) {
            Err(TurnError::Unauthorized { realm, nonce }) => {
                info!("TURN: 401 received, building auth (realm={realm})");
                let key = compute_long_term_key(username, &realm, password);
                AuthInfo {
                    username: username.to_string(),
                    realm,
                    nonce,
                    key,
                }
            }
            Ok(r) => {
                // Some servers skip the 401 challenge (rare but allowed)
                info!(
                    "TURN: allocated without auth challenge (relay={})",
                    r.relayed_addr
                );
                return Self::finish(
                    turn_socket,
                    turn_server,
                    AuthInfo {
                        username: username.to_string(),
                        realm: String::new(),
                        nonce: String::new(),
                        key: vec![],
                    },
                    r.relayed_addr,
                );
            }
            Err(e) => anyhow::bail!("TURN unauthenticated Allocate failed: {e}"),
        };

        // --- Phase 2: authenticated Allocate ---
        rand::fill(&mut txid);
        let req = build_allocate_request_auth(&txid, &auth);
        info!("TURN: sending authenticated Allocate");
        turn_socket.send_to(&req, turn_server)?;

        let (amt, _) = turn_socket.recv_from(&mut buf)?;
        let result = parse_allocate_response(&buf[..amt])
            .map_err(|e| anyhow::anyhow!("TURN authenticated Allocate failed: {e}"))?;

        Self::finish(turn_socket, turn_server, auth, result.relayed_addr)
    }

    fn finish(
        turn_socket: UdpSocket,
        turn_server: SocketAddr,
        auth: AuthInfo,
        relayed_addr: SocketAddr,
    ) -> anyhow::Result<Self> {
        // VCS (virtual client socket) — Thread A sends here to reach WkListener.
        let vcs = UdpSocket::bind("127.0.0.1:0")?;
        let vcs_addr = vcs.local_addr()?;

        // app_socket — WkListener will bind to this.
        let app_socket = UdpSocket::bind("127.0.0.1:0")?;
        let app_addr = app_socket.local_addr()?;

        info!(
            "TURN: proxy ready — relay={relayed_addr}, app={app_addr}, vcs={vcs_addr}"
        );

        Ok(TurnProxy {
            turn_socket: Arc::new(turn_socket),
            turn_server,
            auth,
            relayed_addr,
            vcs: Arc::new(vcs),
            app_addr,
            actual_client: Arc::new(Mutex::new(None)),
            app_socket: Some(app_socket),
            stop: Arc::new(AtomicBool::new(false)),
            _threads: Vec::new(),
        })
    }

    /// Create a TURN permission that allows the given peer IP to send data to
    /// the relay allocation.
    ///
    /// Must be called **before** `start_threads()` (both use `turn_socket`).
    pub fn create_permission(&self, peer: SocketAddr) -> anyhow::Result<()> {
        info!("TURN: creating permission for {}", peer.ip());
        let mut txid = [0u8; 12];
        rand::fill(&mut txid);
        let pkt = build_create_permission_request(&txid, peer, &self.auth);
        self.turn_socket.send_to(&pkt, self.turn_server)?;

        // Wait for response (best-effort — we continue even on timeout)
        let mut buf = [0u8; 512];
        match self.turn_socket.recv_from(&mut buf) {
            Ok((amt, _)) => {
                if let Some((msg_type, _, _)) = parse_header(&buf[..amt]) {
                    if msg_type == TURN_CREATE_PERMISSION_SUCCESS {
                        info!("TURN: CreatePermission OK for {}", peer.ip());
                    } else {
                        info!(
                            "TURN: CreatePermission response type=0x{msg_type:04x} (may be OK)"
                        );
                    }
                }
            }
            Err(e) => {
                info!("TURN: CreatePermission response timeout/error: {e} (continuing)");
            }
        }
        Ok(())
    }

    /// Take the `app_socket` intended for `WkListener::bind()`.
    ///
    /// This must be called **before** `start_threads()`.
    pub fn take_app_socket(&mut self) -> anyhow::Result<UdpSocket> {
        self.app_socket
            .take()
            .ok_or_else(|| anyhow::anyhow!("app_socket already taken"))
    }

    /// Start the three background proxy threads.
    ///
    /// Call after `create_permission()` and before passing `app_socket` to
    /// `WkListener`.
    pub fn start_threads(&mut self) {
        // Set short read timeouts so threads can check the stop flag.
        self.turn_socket
            .set_read_timeout(Some(Duration::from_millis(500)))
            .ok();
        self.vcs
            .set_read_timeout(Some(Duration::from_millis(500)))
            .ok();

        // ---- Thread A: TURN server → WkListener ----
        let ts_a = self.turn_socket.clone();
        let vcs_a = self.vcs.clone();
        let app_addr = self.app_addr;
        let actual_a = self.actual_client.clone();
        let stop_a = self.stop.clone();

        let thread_a = thread::spawn(move || {
            let mut buf = vec![0u8; 65535];
            info!("TURN proxy Thread A started");
            loop {
                if stop_a.load(Ordering::Relaxed) {
                    break;
                }
                match ts_a.recv_from(&mut buf) {
                    Ok((amt, _)) => {
                        if let Some((peer_addr, data)) = parse_data_indication(&buf[..amt]) {
                            {
                                let mut ac = actual_a.lock().unwrap();
                                if ac.is_none() {
                                    info!("TURN proxy: first contact from ESP32 at {peer_addr}");
                                    *ac = Some(peer_addr);
                                }
                            }
                            if let Err(e) = vcs_a.send_to(&data, app_addr) {
                                info!("TURN Thread A → app_socket failed: {e}");
                            }
                        }
                        // Non-Data-Indication messages (e.g., Refresh responses) are ignored.
                    }
                    Err(ref e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        continue;
                    }
                    Err(e) => {
                        info!("TURN Thread A recv error: {e}");
                        break;
                    }
                }
            }
            info!("TURN proxy Thread A stopped");
        });

        // ---- Thread B: WkListener → TURN server ----
        let ts_b = self.turn_socket.clone();
        let vcs_b = self.vcs.clone();
        let turn_server_b = self.turn_server;
        let actual_b = self.actual_client.clone();
        let stop_b = self.stop.clone();

        let thread_b = thread::spawn(move || {
            let mut buf = vec![0u8; 65535];
            info!("TURN proxy Thread B started");
            loop {
                if stop_b.load(Ordering::Relaxed) {
                    break;
                }
                match vcs_b.recv_from(&mut buf) {
                    Ok((amt, _from)) => {
                        let actual = { *actual_b.lock().unwrap() };
                        if let Some(peer_addr) = actual {
                            let ind = build_send_indication(peer_addr, &buf[..amt]);
                            if let Err(e) = ts_b.send_to(&ind, turn_server_b) {
                                info!("TURN Thread B → send_indication failed: {e}");
                            }
                        } else {
                            info!("TURN Thread B: no ESP32 connected yet, dropping packet");
                        }
                    }
                    Err(ref e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        continue;
                    }
                    Err(e) => {
                        info!("TURN Thread B recv error: {e}");
                        break;
                    }
                }
            }
            info!("TURN proxy Thread B stopped");
        });

        // ---- Thread C: Refresh keepalive ----
        let ts_c = self.turn_socket.clone();
        let turn_server_c = self.turn_server;
        let auth_c = self.auth.clone();
        let stop_c = self.stop.clone();

        let thread_c = thread::spawn(move || {
            info!("TURN proxy Thread C (keepalive) started");
            let mut counter = 0u32;
            loop {
                // Sleep in 1-second increments so we can check the stop flag promptly.
                for _ in 0..30 {
                    if stop_c.load(Ordering::Relaxed) {
                        info!("TURN proxy Thread C stopped");
                        return;
                    }
                    std::thread::sleep(Duration::from_secs(1));
                }
                counter += 1;
                info!("TURN proxy: keepalive Refresh #{counter}");
                let mut txid = [0u8; 12];
                rand::fill(&mut txid);
                let pkt = build_refresh_request(&txid, 600, &auth_c);
                if let Err(e) = ts_c.send_to(&pkt, turn_server_c) {
                    info!("TURN Thread C: Refresh send failed: {e}");
                }
            }
        });

        self._threads.push(thread_a);
        self._threads.push(thread_b);
        self._threads.push(thread_c);
    }
}

impl Drop for TurnProxy {
    fn drop(&mut self) {
        info!("TurnProxy: stopping background threads");
        self.stop.store(true, Ordering::Relaxed);
        // Threads will exit on the next iteration (they poll `stop` with a
        // 500 ms socket timeout, so they stop within ~1 s).
    }
}
