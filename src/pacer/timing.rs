//! AirPlay 2 UDP Timing Server, Control Client, and NTP conversion utilities.
//!
//! Handles microsecond-accurate clock synchronization between Linux audio pipelines
//! and Apple audioOS hardware (HomePod mini) over UDP.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::error::SonusError;

/// Number of seconds between the NTP epoch (1900-01-01 00:00:00 UTC)
/// and the Unix epoch (1970-01-01 00:00:00 UTC).
pub const UNIX_NTP_DELTA: u64 = 0x83AA7E80; // 2_208_988_800 seconds

/// Ring buffer capacity for packet retransmission backlog (1024 packets ~ 8.17s).
pub const RETRANSMIT_BUFFER_SIZE: usize = 1024;

/// Returns current 64-bit NTP timestamp: `(secs << 32) | frac`.
pub fn ntp_now() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let sec = now.as_secs() + UNIX_NTP_DELTA;
    // Fractional second represented as 2^32 fractions of a second (32-bit fraction)
    let frac = ((now.subsec_nanos() as u128 * (1u128 << 32)) / 1_000_000_000u128) as u64;
    (sec << 32) | (frac & 0xFFFF_FFFF)
}

/// Unpacks a 64-bit NTP timestamp into `(sec, frac)` tuple.
pub fn ntp2parts(ntp: u64) -> (u32, u32) {
    let sec = (ntp >> 32) as u32;
    let frac = (ntp & 0xFFFF_FFFF) as u32;
    (sec, frac)
}

/// Converts a 64-bit NTP timestamp to a 32-bit RTP timestamp for a given sample rate:
/// `(((ntp >> 16) * (sample_rate as u64)) >> 16) as u32`.
pub fn ntp2ts(ntp: u64, sample_rate: u32) -> u32 {
    let scaled = ((ntp >> 16) as u128) * (sample_rate as u128);
    ((scaled >> 16) & 0xFFFF_FFFF) as u32
}

/// Converts a 64-bit NTP timestamp to a full 64-bit sample count (`start_ts` / `head_ts` in `pyatv`):
/// `(((ntp >> 16) * (sample_rate as u128)) >> 16) as u64`.
pub fn ntp2ts64(ntp: u64, sample_rate: u32) -> u64 {
    let scaled = ((ntp >> 16) as u128) * (sample_rate as u128);
    (scaled >> 16) as u64
}

/// Converts a full 64-bit sample count (`head_ts`) back into a 64-bit NTP timestamp (`ts2ntp` in `pyatv`):
/// `((((timestamp as u128) << 16) / (sample_rate as u128)) << 16) as u64`.
pub fn ts2ntp64(timestamp: u64, sample_rate: u32) -> u64 {
    if sample_rate == 0 {
        return 0;
    }
    let div = ((timestamp as u128) << 16) / (sample_rate as u128);
    (div << 16) as u64
}

/// Encodes a 20-byte RAOP SyncPacket.
///
/// Layout:
/// - Byte 0: `0x90` if `first_packet` else `0x80`
/// - Byte 1: `0xD4` (Sync packet type)
/// - Bytes 2..4: `0x00, 0x07`
/// - Bytes 4..8: `(current_rtptime - latency_frames)` (rendered presentation time)
/// - Bytes 8..12: `ntp_sec`
/// - Bytes 12..16: `ntp_frac`
/// - Bytes 16..20: `current_rtptime`
pub fn encode_sync_packet(
    first_packet: bool,
    current_rtptime: u32,
    latency_frames: u32,
    ntp: u64,
) -> [u8; 20] {
    let mut packet = [0u8; 20];
    packet[0] = if first_packet { 0x90 } else { 0x80 };
    packet[1] = 0xD4;
    packet[2] = 0x00;
    packet[3] = 0x07;

    let rtp_latency = current_rtptime.wrapping_sub(latency_frames);
    packet[4..8].copy_from_slice(&rtp_latency.to_be_bytes());

    let (sec, frac) = ntp2parts(ntp);
    packet[8..12].copy_from_slice(&sec.to_be_bytes());
    packet[12..16].copy_from_slice(&frac.to_be_bytes());
    packet[16..20].copy_from_slice(&current_rtptime.to_be_bytes());

    packet
}

/// RAOP UDP Timing Server responding to HomePod clock sync requests.
pub struct TimingServer {
    local_port: u16,
    handle: JoinHandle<()>,
}

impl TimingServer {
    /// Binds an ephemeral local UDP port (`0.0.0.0:0`) and spawns the timing responder task.
    pub async fn bind() -> Result<Self, SonusError> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        Self::from_socket(socket)
    }

    /// Convenience alias for `bind()`.
    pub async fn new() -> Result<Self, SonusError> {
        Self::bind().await
    }

    /// Binds to a specific address.
    pub async fn bind_addr<A: tokio::net::ToSocketAddrs>(addr: A) -> Result<Self, SonusError> {
        let socket = UdpSocket::bind(addr).await?;
        Self::from_socket(socket)
    }

    /// Spawns the timing server listener loop around an existing `UdpSocket`.
    pub fn from_socket(socket: UdpSocket) -> Result<Self, SonusError> {
        let local_port = socket.local_addr()?.port();

        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 128];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((n, peer_addr)) => {
                        // 32-byte Timing Request: buf[0] == 0x80 && (buf[1] == 0x52 || buf[1] == 0xD2)
                        if n >= 32 && buf[0] == 0x80 && (buf[1] == 0x52 || buf[1] == 0xD2) {
                            let mut res = [0u8; 32];
                            res[0] = 0x80;
                            res[1] = 0xD3;
                            res[2] = 0x00;
                            res[3] = 0x07;
                            res[4..8].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
                            // Copy client's send_time [24..32] into reference_time [8..16]
                            res[8..16].copy_from_slice(&buf[24..32]);

                            let rec_time = ntp_now().to_be_bytes();
                            res[16..24].copy_from_slice(&rec_time);

                            let send_time = ntp_now().to_be_bytes();
                            res[24..32].copy_from_slice(&send_time);

                            if let Err(e) = socket.send_to(&res, peer_addr).await {
                                warn!("TimingServer send_to error: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        debug!("TimingServer receive loop terminated: {}", e);
                        break;
                    }
                }
            }
        });

        Ok(Self { local_port, handle })
    }

    /// Returns the local port the Timing Server is bound to.
    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    /// Terminate the timing server background listener.
    pub fn shutdown(&self) {
        self.handle.abort();
    }
}

impl Drop for TimingServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Thread-safe circular buffer storing the last 1024 encrypted RTP packets for retransmission.
pub type RetransmitBacklog = Arc<Mutex<Vec<Option<(u16, Vec<u8>)>>>>;

/// Convenience wrapper around `RetransmitBacklog`.
#[derive(Clone)]
pub struct RetransmitBuffer {
    buffer: RetransmitBacklog,
}

impl RetransmitBuffer {
    pub fn new() -> Self {
        Self {
            buffer: Arc::new(Mutex::new(vec![None; RETRANSMIT_BUFFER_SIZE])),
        }
    }

    pub fn insert(&self, seqno: u16, packet: Vec<u8>) {
        let idx = (seqno as usize) % RETRANSMIT_BUFFER_SIZE;
        let mut guard = self.buffer.lock().unwrap();
        guard[idx] = Some((seqno, packet));
    }

    pub fn get(&self, seqno: u16) -> Option<Vec<u8>> {
        let guard = self.buffer.lock().unwrap();
        let idx = (seqno as usize) % RETRANSMIT_BUFFER_SIZE;
        match &guard[idx] {
            Some((s, data)) if *s == seqno => Some(data.clone()),
            _ => None,
        }
    }

    pub fn inner(&self) -> RetransmitBacklog {
        Arc::clone(&self.buffer)
    }
}

impl Default for RetransmitBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// AirPlay 2 UDP Control Client managing periodic clock sync and handling retransmit requests.
pub struct ControlClient {
    local_port: u16,
    socket: Arc<UdpSocket>,
    backlog: RetransmitBacklog,
    remote_ip: Arc<RwLock<String>>,
    target_addr: Arc<RwLock<Option<SocketAddr>>>,
    current_rtptime: Arc<AtomicU32>,
    initial_rtptime: Arc<AtomicU32>,
    start_ts: Arc<AtomicU64>,
    latency_frames: Arc<AtomicU32>,
    is_syncing: Arc<AtomicBool>,
    retransmit_handle: JoinHandle<()>,
    sync_handle: JoinHandle<()>,
}

impl ControlClient {
    /// Binds an ephemeral local UDP port and sets up background tasks for retransmit and 1s sync.
    pub async fn bind(homepod_ip: &str, server_control_port: u16) -> Result<Self, SonusError> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        Self::from_socket(socket, homepod_ip, server_control_port)
    }

    /// Convenience constructor matching `bind`.
    pub async fn new(homepod_ip: &str, server_control_port: u16) -> Result<Self, SonusError> {
        Self::bind(homepod_ip, server_control_port).await
    }

    /// Construct `ControlClient` from an already bound socket.
    pub fn from_socket(
        socket: UdpSocket,
        homepod_ip: &str,
        server_control_port: u16,
    ) -> Result<Self, SonusError> {
        let local_port = socket.local_addr()?.port();
        let socket = Arc::new(socket);

        let initial_target = if server_control_port > 0 && !homepod_ip.is_empty() {
            let addr_str = format!("{homepod_ip}:{server_control_port}");
            addr_str
                .parse::<SocketAddr>()
                .ok()
                .or_else(|| addr_str.to_socket_addrs().ok()?.next())
        } else {
            None
        };

        let remote_ip = Arc::new(RwLock::new(homepod_ip.to_string()));
        let target_addr = Arc::new(RwLock::new(initial_target));
        let backlog: RetransmitBacklog = Arc::new(Mutex::new(vec![None; RETRANSMIT_BUFFER_SIZE]));
        let current_rtptime = Arc::new(AtomicU32::new(0));
        let initial_rtptime = Arc::new(AtomicU32::new(0));
        let start_ts = Arc::new(AtomicU64::new(0));
        let latency_frames = Arc::new(AtomicU32::new(crate::config::TARGET_LATENCY_FRAMES));
        let is_syncing = Arc::new(AtomicBool::new(false));

        // 1. Retransmit request listener task
        let rx_socket = Arc::clone(&socket);
        let rx_backlog = Arc::clone(&backlog);
        let retransmit_handle = tokio::spawn(async move {
            let mut buf = [0u8; 128];
            loop {
                match rx_socket.recv_from(&mut buf).await {
                    Ok((n, peer_addr)) => {
                        // RetransmitRequest packet: buf[1] == 0x55 || buf[1] == 0xD5
                        if n >= 8 && (buf[1] == 0x55 || buf[1] == 0xD5) {
                            let lost_seqno = u16::from_be_bytes([buf[4], buf[5]]);
                            let count = u16::from_be_bytes([buf[6], buf[7]]);
                            let count = count.clamp(1, 1024);

                            for i in 0..count {
                                let target_seq = lost_seqno.wrapping_add(i);
                                let idx = (target_seq as usize) % RETRANSMIT_BUFFER_SIZE;
                                let found = {
                                    let guard = rx_backlog.lock().unwrap();
                                    match &guard[idx] {
                                        Some((s, data)) if *s == target_seq => Some(data.clone()),
                                        _ => None,
                                    }
                                };

                                if let Some(pkt) = found {
                                    let [seq_hi, seq_lo] = target_seq.to_be_bytes();
                                    let mut retransmit_pkt = Vec::with_capacity(4 + pkt.len());
                                    // 4-byte retransmit header: [0x80, 0xD6, seq_hi, seq_lo]
                                    retransmit_pkt.extend_from_slice(&[0x80, 0xD6, seq_hi, seq_lo]);
                                    retransmit_pkt.extend_from_slice(&pkt);

                                    if let Err(e) =
                                        rx_socket.send_to(&retransmit_pkt, peer_addr).await
                                    {
                                        warn!(
                                            "Failed to send retransmitted packet seq {}: {}",
                                            target_seq, e
                                        );
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        debug!("ControlClient retransmit listener terminated: {}", e);
                        break;
                    }
                }
            }
        });

        // 2. Periodic 1-second sync packet sender task
        let sync_socket = Arc::clone(&socket);
        let sync_target = Arc::clone(&target_addr);
        let sync_rtptime = Arc::clone(&current_rtptime);
        let sync_init_rtptime = Arc::clone(&initial_rtptime);
        let sync_start_ts = Arc::clone(&start_ts);
        let sync_latency = Arc::clone(&latency_frames);
        let sync_flag = Arc::clone(&is_syncing);

        let sync_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;

                if sync_flag.load(Ordering::Relaxed) {
                    let target = *sync_target.read().unwrap();
                    if let Some(addr) = target {
                        let rtptime = sync_rtptime.load(Ordering::Relaxed);
                        let init_rtp = sync_init_rtptime.load(Ordering::Relaxed);
                        let s_ts = sync_start_ts.load(Ordering::Relaxed);
                        let latency = sync_latency.load(Ordering::Relaxed);
                        // Lock NTP timestamp in SyncPacket to exact frame count (`ts2ntp(head_ts)`)
                        let ntp = if s_ts > 0 {
                            let frames_sent = rtptime.wrapping_sub(init_rtp) as u64;
                            ts2ntp64(s_ts + frames_sent, crate::config::SAMPLE_RATE)
                        } else {
                            ntp_now()
                        };
                        let sync_pkt = encode_sync_packet(false, rtptime, latency, ntp);

                        if let Err(e) = sync_socket.send_to(&sync_pkt, addr).await {
                            warn!("Periodic sync packet send error: {}", e);
                        }
                    }
                }
            }
        });

        Ok(Self {
            local_port,
            socket,
            backlog,
            remote_ip,
            target_addr,
            current_rtptime,
            initial_rtptime,
            start_ts,
            latency_frames,
            is_syncing,
            retransmit_handle,
            sync_handle,
        })
    }

    /// Local port this control socket is bound to (sent in RTSP SETUP).
    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    /// Sets or updates the remote server control port received from HomePod RTSP SETUP response.
    pub fn set_server_control_port(&self, port: u16) {
        let mut lock = self.target_addr.write().unwrap();
        if let Some(addr) = *lock {
            *lock = Some(SocketAddr::new(addr.ip(), port));
        } else {
            let ip_str = self.remote_ip.read().unwrap();
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                *lock = Some(SocketAddr::new(ip, port));
            } else {
                let candidate = format!("{ip_str}:{port}");
                if let Ok(mut addrs) = candidate.to_socket_addrs() {
                    if let Some(addr) = addrs.next() {
                        *lock = Some(addr);
                    }
                }
            }
        }
    }

    /// Sets or updates the target address for sync packets.
    pub fn set_target(&self, ip: &str, port: u16) -> Result<(), SonusError> {
        let addr: SocketAddr = format!("{ip}:{port}").parse().or_else(|_| {
            format!("{ip}:{port}")
                .to_socket_addrs()
                .map_err(|e| {
                    SonusError::Config(format!("Failed to resolve target {ip}:{port}: {e}"))
                })?
                .next()
                .ok_or_else(|| SonusError::Config(format!("No address found for {ip}:{port}")))
        })?;
        *self.remote_ip.write().unwrap() = ip.to_string();
        *self.target_addr.write().unwrap() = Some(addr);
        Ok(())
    }

    /// Stores an encrypted packet into the circular retransmission backlog.
    pub fn store_packet(&self, seqno: u16, packet: Vec<u8>) {
        let idx = (seqno as usize) % RETRANSMIT_BUFFER_SIZE;
        let mut guard = self.backlog.lock().unwrap();
        guard[idx] = Some((seqno, packet));
    }

    /// Stores an encrypted packet slice into the circular retransmission backlog.
    pub fn store_packet_slice(&self, seqno: u16, packet: &[u8]) {
        self.store_packet(seqno, packet.to_vec());
    }

    /// Returns direct reference to the retransmit backlog ring buffer.
    pub fn backlog(&self) -> RetransmitBacklog {
        Arc::clone(&self.backlog)
    }

    /// Updates the current RTP timestamp tracked for periodic sync packets.
    pub fn update_rtptime(&self, rtptime: u32) {
        self.current_rtptime.store(rtptime, Ordering::Relaxed);
    }

    /// Sets the presentation latency frames.
    pub fn set_latency_frames(&self, latency: u32) {
        self.latency_frames.store(latency, Ordering::Relaxed);
    }

    /// Sends the immediate 0x90 SyncPacket when audio streaming starts and enables the 1s sync loop.
    pub async fn send_initial_sync(
        &self,
        current_rtptime: u32,
        latency_frames: u32,
    ) -> Result<(), SonusError> {
        let ntp = ntp_now();
        let s_ts = ntp2ts64(ntp, crate::config::SAMPLE_RATE);
        self.current_rtptime
            .store(current_rtptime, Ordering::SeqCst);
        self.initial_rtptime
            .store(current_rtptime, Ordering::SeqCst);
        self.start_ts.store(s_ts, Ordering::SeqCst);
        self.latency_frames.store(latency_frames, Ordering::SeqCst);
        self.is_syncing.store(true, Ordering::SeqCst);

        let target = *self.target_addr.read().unwrap();
        let target = target.ok_or_else(|| {
            SonusError::Pacer("Server control address not configured".to_string())
        })?;

        let sync_ntp = ts2ntp64(s_ts, crate::config::SAMPLE_RATE);
        let initial_pkt = encode_sync_packet(true, current_rtptime, latency_frames, sync_ntp);
        self.socket.send_to(&initial_pkt, target).await?;
        Ok(())
    }

    /// Shuts down background tasks.
    pub fn shutdown(&self) {
        self.is_syncing.store(false, Ordering::SeqCst);
        self.retransmit_handle.abort();
        self.sync_handle.abort();
    }
}

impl Drop for ControlClient {
    fn drop(&mut self) {
        self.retransmit_handle.abort();
        self.sync_handle.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntp_math_and_conversions() {
        assert_eq!(UNIX_NTP_DELTA, 0x83AA7E80);

        // 1.0 second in NTP format: sec = 1, frac = 0
        let ntp_one_sec: u64 = 1 << 32;
        let (sec, frac) = ntp2parts(ntp_one_sec);
        assert_eq!(sec, 1);
        assert_eq!(frac, 0);

        // ntp2ts at 44.1kHz for 1 second should yield exactly 44,100 samples
        let ts_one_sec = ntp2ts(ntp_one_sec, 44_100);
        assert_eq!(ts_one_sec, 44_100);

        // 0.5 second in NTP format: sec = 0, frac = 0x80000000
        let ntp_half_sec: u64 = 1 << 31;
        let (sec2, frac2) = ntp2parts(ntp_half_sec);
        assert_eq!(sec2, 0);
        assert_eq!(frac2, 0x8000_0000);

        let ts_half_sec = ntp2ts(ntp_half_sec, 44_100);
        assert_eq!(ts_half_sec, 22_050);

        // ntp_now produces sensible values (> UNIX_NTP_DELTA)
        let now = ntp_now();
        let (now_sec, _) = ntp2parts(now);
        assert!(now_sec as u64 > UNIX_NTP_DELTA);
    }

    #[test]
    fn test_encode_sync_packet() {
        let ntp: u64 = (100u64 << 32) | 500u64;
        let current_rtp = 50_000u32;
        let latency = 11_025u32;

        // First packet: Marker bit set (0x90)
        let pkt_first = encode_sync_packet(true, current_rtp, latency, ntp);
        assert_eq!(pkt_first[0], 0x90);
        assert_eq!(pkt_first[1], 0xD4);
        assert_eq!(pkt_first[2], 0x00);
        assert_eq!(pkt_first[3], 0x07);

        let expected_latency_rtp = current_rtp - latency;
        assert_eq!(&pkt_first[4..8], &expected_latency_rtp.to_be_bytes());
        assert_eq!(&pkt_first[8..12], &100u32.to_be_bytes());
        assert_eq!(&pkt_first[12..16], &500u32.to_be_bytes());
        assert_eq!(&pkt_first[16..20], &current_rtp.to_be_bytes());

        // Subsequent packet: Marker bit cleared (0x80)
        let pkt_subsequent = encode_sync_packet(false, current_rtp, latency, ntp);
        assert_eq!(pkt_subsequent[0], 0x80);
        assert_eq!(pkt_subsequent[1], 0xD4);
    }

    #[tokio::test]
    async fn test_timing_server_request_response_roundtrip() {
        let server = TimingServer::bind().await.unwrap();
        let port = server.local_port();
        assert!(port > 0);

        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

        // 32-byte Timing Request
        let mut req = [0u8; 32];
        req[0] = 0x80;
        req[1] = 0x52; // Timing Request
        req[2] = 0x00;
        req[3] = 0x07;
        let client_send_time = 0x1122_3344_5566_7788u64;
        req[24..32].copy_from_slice(&client_send_time.to_be_bytes());

        client_socket.send_to(&req, target).await.unwrap();

        let mut resp = [0u8; 64];
        let (n, _) = client_socket.recv_from(&mut resp).await.unwrap();
        assert_eq!(n, 32);

        assert_eq!(resp[0], 0x80);
        assert_eq!(resp[1], 0xD3); // Timing Response
        assert_eq!(resp[2], 0x00);
        assert_eq!(resp[3], 0x07);
        assert_eq!(&resp[4..8], &[0, 0, 0, 0]);

        // Server must copy client send_time into reference_time [8..16]
        let echoed_ref = u64::from_be_bytes(resp[8..16].try_into().unwrap());
        assert_eq!(echoed_ref, client_send_time);

        // receive_time and send_time must be non-zero
        let rec_time = u64::from_be_bytes(resp[16..24].try_into().unwrap());
        let send_time = u64::from_be_bytes(resp[24..32].try_into().unwrap());
        assert!(rec_time > 0);
        assert!(send_time > 0);
    }

    #[tokio::test]
    async fn test_control_client_retransmit_request() {
        let homepod_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let homepod_port = homepod_socket.local_addr().unwrap().port();

        let client = ControlClient::bind("127.0.0.1", homepod_port)
            .await
            .unwrap();
        let client_port = client.local_port();
        let target: SocketAddr = format!("127.0.0.1:{client_port}").parse().unwrap();

        // Populate backlog with packet sequence 100
        let fake_payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
        client.store_packet(100, fake_payload.clone());

        // Send RetransmitRequest from HomePod for seq 100, count 1
        let mut req = [0u8; 8];
        req[0] = 0x80;
        req[1] = 0x55; // Retransmit request
        req[4..6].copy_from_slice(&100u16.to_be_bytes()); // lost_seqno
        req[6..8].copy_from_slice(&1u16.to_be_bytes()); // count

        homepod_socket.send_to(&req, target).await.unwrap();

        let mut resp = [0u8; 64];
        let (n, _) = homepod_socket.recv_from(&mut resp).await.unwrap();
        // 4 bytes header + 4 bytes payload = 8 bytes
        assert_eq!(n, 8);
        assert_eq!(resp[0], 0x80);
        assert_eq!(resp[1], 0xD6); // Retransmit reply
        assert_eq!(&resp[2..4], &100u16.to_be_bytes());
        assert_eq!(&resp[4..8], &fake_payload[..]);
    }

    #[tokio::test]
    async fn test_control_client_initial_sync() {
        let homepod_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let homepod_port = homepod_socket.local_addr().unwrap().port();

        let client = ControlClient::bind("127.0.0.1", homepod_port)
            .await
            .unwrap();

        client.send_initial_sync(88_200, 11_025).await.unwrap();

        let mut buf = [0u8; 64];
        let (n, _) = homepod_socket.recv_from(&mut buf).await.unwrap();
        assert_eq!(n, 20);
        assert_eq!(buf[0], 0x90); // First packet marker
        assert_eq!(buf[1], 0xD4);
        let expected_latency = 88_200u32 - 11_025u32;
        assert_eq!(&buf[4..8], &expected_latency.to_be_bytes());
        assert_eq!(&buf[16..20], &88_200u32.to_be_bytes());
    }

    #[tokio::test]
    async fn test_control_client_periodic_sync() {
        let homepod_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let homepod_port = homepod_socket.local_addr().unwrap().port();

        let client = ControlClient::bind("127.0.0.1", homepod_port)
            .await
            .unwrap();
        client.send_initial_sync(44_100, 11_025).await.unwrap();

        // 1. Initial sync packet received
        let mut buf = [0u8; 64];
        let (n, _) = homepod_socket.recv_from(&mut buf).await.unwrap();
        assert_eq!(n, 20);
        assert_eq!(buf[0], 0x90);

        // Update rtptime to 88_200
        client.update_rtptime(88_200);

        // 2. Wait for next periodic sync packet (interval is 1 second)
        let res = tokio::time::timeout(
            Duration::from_millis(1500),
            homepod_socket.recv_from(&mut buf),
        )
        .await;

        assert!(res.is_ok());
        let (n, _) = res.unwrap().unwrap();
        assert_eq!(n, 20);
        assert_eq!(buf[0], 0x80); // Marker bit NOT set for periodic sync
        assert_eq!(buf[1], 0xD4);
        assert_eq!(&buf[16..20], &88_200u32.to_be_bytes());
    }
}
