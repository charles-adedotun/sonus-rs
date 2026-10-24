//! RTSP 1.0 client state machine for Apple AirPlay 2 / RAOP sessions.
//!
//! Supports:
//! - HAP Transient Pairing (`POST /pair-pin-start`, `POST /pair-setup` M1-M4) via SRP-6a 3072-bit.
//! - Transparent 1024-byte framed ChaCha20-Poly1305 session encryption (`HapSession`).
//! - Interleaved peer-initiated incoming requests (`POST /command`, `SET_PARAMETER`) during read loop.
//! - Stage 1 base SETUP (`timingPort`, `eventPort`) and Stage 2 stream SETUP (`streamType: 2`).
//! - Real-time playback controls: `RECORD`, `FLUSH`, `SET_PARAMETER volume`, `POST /feedback`.
//! - MediaRemote supported commands and now-playing metadata synchronization.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info};

use crate::dacp::dmap::{container_tag, string_tag};
use crate::error::SonusError;
use crate::raop::hap::{decode_tlv8, encode_tlv8, hkdf_sha512, HapSession, HapSrpClient, TlvTag};
use crate::raop::plist::{
    build_base_setup_plist, build_homepod_stream_setup_plist, parse_base_setup_response,
    parse_stream_setup_response, SetupStreamResponse,
};

/// Parsed RTSP Response.
#[derive(Debug, Clone)]
pub struct RtspResponse {
    pub status_code: u16,
    pub status_line: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

/// Asynchronous RTSP Client for interacting with HomePod mini.
pub struct RtspClient {
    stream: TcpStream,
    local_ip: String,
    cseq: u32,
    session_id: u64,
    pub active_session_header: Option<String>,
    pub hap_session: Option<HapSession>,
    read_buf: Vec<u8>,
}

impl RtspClient {
    /// Connect to HomePod RTSP server on target IP and port (default 7000).
    pub async fn connect(host: &str, port: u16) -> Result<Self, SonusError> {
        let addr = format!("{host}:{port}");
        info!("Connecting to HomePod RTSP endpoint at {}", addr);
        let stream = TcpStream::connect(&addr).await.map_err(|e| {
            SonusError::Rtsp(format!("Failed to connect to HomePod at {addr}: {e}"))
        })?;

        let local_ip = stream
            .local_addr()
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|_| "127.0.0.1".to_string());

        // Generate a 32-bit session ID matching pyatv's randrange(2**32)
        let session_id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| ((d.as_nanos() as u32).max(1)) as u64)
            .unwrap_or(0x484F4D45);

        Ok(Self {
            stream,
            local_ip,
            cseq: 1,
            session_id,
            active_session_header: None,
            hap_session: None,
            read_buf: Vec::new(),
        })
    }

    /// Return the canonical RTSP session URI (`rtsp://<local_ip>/<session_id>`).
    pub fn session_uri(&self) -> String {
        format!("rtsp://{}/{}", self.local_ip, self.session_id)
    }

    /// Return the local IP bound by this TCP connection.
    pub fn local_ip(&self) -> &str {
        &self.local_ip
    }

    /// Transmit an RTSP/1.0 request and await the corresponding response.
    pub async fn exchange(
        &mut self,
        method: &str,
        path: &str,
        extra_headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<RtspResponse, SonusError> {
        self.exchange_with_protocol("RTSP/1.0", method, path, extra_headers, body)
            .await
    }

    /// Transmit an HTTP/1.1 or RTSP/1.0 request and await the corresponding response.
    ///
    /// Once HAP encryption is enabled, all requests are encrypted and responses
    /// are decrypted through `HapSession`.
    pub async fn exchange_with_protocol(
        &mut self,
        protocol: &str,
        method: &str,
        path: &str,
        extra_headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<RtspResponse, SonusError> {
        let current_cseq = self.cseq;
        self.cseq += 1;

        let path_str = if path.is_empty() { "/" } else { path };

        let mut req = format!(
            "{method} {path_str} {protocol}\r\n\
             CSeq: {current_cseq}\r\n\
             User-Agent: AirPlay/550.10\r\n\
             Client-Instance: 484F4D454C414231\r\n\
             DACP-ID: 484F4D454C414231\r\n\
             Active-Remote: 1986535575\r\n"
        );

        if let Some(ref session) = self.active_session_header {
            req.push_str(&format!("Session: {session}\r\n"));
        }

        for (k, v) in extra_headers {
            req.push_str(&format!("{k}: {v}\r\n"));
        }

        let full_req = if let Some(b) = body {
            req.push_str(&format!("Content-Length: {}\r\n\r\n", b.len()));
            let mut v = req.into_bytes();
            v.extend_from_slice(b);
            v
        } else {
            req.push_str("Content-Length: 0\r\n\r\n");
            req.into_bytes()
        };

        if let Some(ref mut hap) = self.hap_session {
            let enc = hap.encrypt(&full_req)?;
            self.stream.write_all(&enc).await?;
        } else {
            self.stream.write_all(&full_req).await?;
        }
        self.stream.flush().await?;

        // Read and parse RTSP response
        let resp = self.read_response().await?;
        debug!("RTSP {} {} -> Status {}", method, path, resp.status_code);

        if let Some(sess) = resp.headers.get("session") {
            self.active_session_header = Some(sess.clone());
        }

        if resp.status_code >= 400 {
            return Err(SonusError::RtspStatus {
                code: resp.status_code,
                message: resp.status_line,
            });
        }

        Ok(resp)
    }

    /// Read raw RTSP response from socket, decrypting HAP frames when active
    /// and transparently handling interleaved peer requests.
    async fn read_response(&mut self) -> Result<RtspResponse, SonusError> {
        let mut raw_buf = vec![0u8; 8192];

        loop {
            // Check if read_buf contains a complete HTTP / RTSP header
            if let Some(pos) = self.read_buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let header_str = String::from_utf8_lossy(&self.read_buf[..pos]);
                let first_line = header_str.lines().next().unwrap_or("").to_string();

                // Interleaved peer requests: POST /command, SET_PARAMETER, GET, etc.
                let is_peer_request = first_line.starts_with("POST ")
                    || first_line.starts_with("SET_PARAMETER ")
                    || first_line.starts_with("GET ");

                let mut content_length = 0usize;
                let mut cseq = 0u32;
                for line in header_str.lines().skip(1) {
                    if let Some((k, v)) = line.split_once(':') {
                        let k = k.trim().to_ascii_lowercase();
                        let v = v.trim();
                        if k == "content-length" {
                            content_length = v.parse().unwrap_or(0);
                        } else if k == "cseq" {
                            cseq = v.parse().unwrap_or(0);
                        }
                    }
                }

                let total_len = pos + 4 + content_length;
                if self.read_buf.len() >= total_len {
                    if is_peer_request {
                        debug!(
                            "Handling interleaved peer request on RTSP socket: {}",
                            first_line
                        );
                        self.read_buf.drain(0..total_len);

                        // Respond 200 OK to satisfy HomePod peer
                        let reply = format!(
                            "RTSP/1.0 200 OK\r\n\
                             CSeq: {cseq}\r\n\
                             Content-Length: 0\r\n\
                             Audio-Latency: 0\r\n\
                             \r\n"
                        );

                        if let Some(ref mut hap) = self.hap_session {
                            let enc = hap.encrypt(reply.as_bytes())?;
                            self.stream.write_all(&enc).await?;
                        } else {
                            self.stream.write_all(reply.as_bytes()).await?;
                        }
                        self.stream.flush().await?;

                        // Continue awaiting our response
                        continue;
                    } else {
                        // Consumed RTSP response
                        let resp_bytes = self.read_buf.drain(0..total_len).collect::<Vec<u8>>();
                        return Self::parse_rtsp_response(&resp_bytes, pos);
                    }
                }
            }

            // Need more data from TCP socket
            let n = self.stream.read(&mut raw_buf).await?;
            if n == 0 {
                return Err(SonusError::Rtsp(
                    "Remote closed RTSP connection".to_string(),
                ));
            }

            if let Some(ref mut hap) = self.hap_session {
                let decrypted = hap.decrypt(&raw_buf[..n])?;
                self.read_buf.extend_from_slice(&decrypted);
            } else {
                self.read_buf.extend_from_slice(&raw_buf[..n]);
            }
        }
    }

    /// Parses raw status line, headers, and binary body from a complete response slice.
    fn parse_rtsp_response(
        resp_bytes: &[u8],
        header_end_pos: usize,
    ) -> Result<RtspResponse, SonusError> {
        let header_str = String::from_utf8_lossy(&resp_bytes[..header_end_pos]);
        let mut lines = header_str.lines();
        let status_line = lines
            .next()
            .ok_or_else(|| SonusError::Rtsp("Empty RTSP response".to_string()))?
            .to_string();

        let status_code: u16 = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(500);

        let mut headers = HashMap::new();
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
            }
        }

        let body = resp_bytes[header_end_pos + 4..].to_vec();

        Ok(RtspResponse {
            status_code,
            status_line,
            headers,
            body,
        })
    }

    /// Performs HAP Transient Pairing (`POST /pair-pin-start` and SRP-6a M1-M4 handshake).
    ///
    /// Upon success, activates `HapSession` on `self` for all subsequent RTSP communication
    /// and returns `(audio_shk, event_read_key, event_write_key)` for stream setup and EventChannel.
    pub async fn pair_verify_transient(
        &mut self,
    ) -> Result<([u8; 32], [u8; 32], [u8; 32]), SonusError> {
        info!("Initiating AirPlay 2 HAP Transient Pairing");

        let auth_headers = [
            ("User-Agent", "AirPlay/320.20"),
            ("Connection", "keep-alive"),
            ("X-Apple-HKP", "4"),
            ("Content-Type", "application/octet-stream"),
        ];

        // 1. POST /pair-pin-start
        self.exchange_with_protocol("HTTP/1.1", "POST", "/pair-pin-start", &auth_headers, None)
            .await?;

        // 2. POST /pair-setup (M1)
        let srp_client = HapSrpClient::new();
        let m1_tlv = encode_tlv8(&[
            (TlvTag::Method as u8, &[0x00]),
            (TlvTag::SeqNo as u8, &[0x01]),
            (TlvTag::Flags as u8, &[0x10]), // TransientPairing flag
        ]);

        let m2_resp = self
            .exchange_with_protocol(
                "HTTP/1.1",
                "POST",
                "/pair-setup",
                &auth_headers,
                Some(&m1_tlv),
            )
            .await?;
        let m2_tags = decode_tlv8(&m2_resp.body);

        let salt = m2_tags
            .get(&(TlvTag::Salt as u8))
            .ok_or_else(|| SonusError::Crypto("Pair-setup M2 missing Salt TLV".to_string()))?;
        let atv_pub_key = m2_tags
            .get(&(TlvTag::PublicKey as u8))
            .ok_or_else(|| SonusError::Crypto("Pair-setup M2 missing PublicKey TLV".to_string()))?;

        // 3. Compute client proof M1 and expected server proof M2
        let srp_result = srp_client.process_server_response(atv_pub_key, salt)?;

        let m3_tlv = encode_tlv8(&[
            (TlvTag::SeqNo as u8, &[0x03]),
            (TlvTag::PublicKey as u8, srp_client.public_key_bytes()),
            (TlvTag::Proof as u8, &srp_result.client_proof_m1),
        ]);

        let _m4_resp = self
            .exchange_with_protocol(
                "HTTP/1.1",
                "POST",
                "/pair-setup",
                &auth_headers,
                Some(&m3_tlv),
            )
            .await?;

        // 4. Derive RTSP control keys and EventChannel / stream keys
        let srp_shared_key = srp_result.shared_key;

        let ctrl_write_key = hkdf_sha512(
            b"Control-Salt",
            b"Control-Write-Encryption-Key",
            &srp_shared_key,
        );
        let ctrl_read_key = hkdf_sha512(
            b"Control-Salt",
            b"Control-Read-Encryption-Key",
            &srp_shared_key,
        );

        // Enable HAP framing cipher on control RTSP socket
        self.hap_session = Some(HapSession::new(&ctrl_write_key, &ctrl_read_key));

        // For EventChannel (reverse channel initiated by HomePod):
        // - HomePod encrypts outbound events with "Events-Write-Encryption-Key" (so client reads with it)
        // - Client encrypts 200 OK replies with "Events-Read-Encryption-Key" (so client writes with it)
        // - Audio stream shared secret (shk) is derived from "Events-Write-Encryption-Key"
        let hp_events_write_key = hkdf_sha512(
            b"Events-Salt",
            b"Events-Write-Encryption-Key",
            &srp_shared_key,
        );
        let hp_events_read_key = hkdf_sha512(
            b"Events-Salt",
            b"Events-Read-Encryption-Key",
            &srp_shared_key,
        );
        let audio_shk = hp_events_write_key;
        let event_client_read_key = hp_events_write_key;
        let event_client_write_key = hp_events_read_key;

        info!("HAP Transient Pairing established successfully; session encryption enabled");
        Ok((audio_shk, event_client_read_key, event_client_write_key))
    }

    /// Performs Stage 1 AirPlay 2 Base SETUP negotiating NTP timing and speaker event channel.
    ///
    /// Returns the negotiated `eventPort` on the HomePod.
    pub async fn setup_base(&mut self, timing_port: u16) -> Result<u16, SonusError> {
        let session_uuid = format!(
            "{:08X}-484F-4D45-8C41-{:012X}",
            self.session_id as u32, self.session_id
        );
        let bplist_payload = build_base_setup_plist(timing_port, &session_uuid)?;

        let extra_headers = [
            ("Content-Type", "application/x-apple-binary-plist"),
            ("X-Apple-ProtocolVersion", "1"),
        ];

        let uri = self.session_uri();
        let resp = self
            .exchange("SETUP", &uri, &extra_headers, Some(&bplist_payload))
            .await?;

        parse_base_setup_response(&resp.body)
    }

    /// Query HomePod RTSP server capabilities via OPTIONS.
    pub async fn options(&mut self) -> Result<RtspResponse, SonusError> {
        self.exchange("OPTIONS", "*", &[], None).await
    }

    /// Query HomePod `/info` endpoint.
    pub async fn info(&mut self) -> Result<RtspResponse, SonusError> {
        self.exchange("GET", "/info", &[], None).await
    }

    /// Perform Stage 2 AirPlay 2 setup for real-time interactive stream (250ms).
    pub async fn setup_stream(
        &mut self,
        control_client_port: u16,
        shared_secret: &[u8],
    ) -> Result<SetupStreamResponse, SonusError> {
        let bplist_payload =
            build_homepod_stream_setup_plist(self.session_id, control_client_port, shared_secret)?;

        let extra_headers = [
            ("Content-Type", "application/x-apple-binary-plist"),
            ("X-Apple-ProtocolVersion", "1"),
        ];

        let uri = self.session_uri();
        let resp = self
            .exchange("SETUP", &uri, &extra_headers, Some(&bplist_payload))
            .await?;

        parse_stream_setup_response(&resp.body)
    }

    /// Start audio playback with RECORD.
    pub async fn record(&mut self) -> Result<RtspResponse, SonusError> {
        let uri = self.session_uri();
        self.exchange("RECORD", &uri, &[], None).await
    }

    /// Flushes audio buffers up to specified RTP sequence number and timestamp.
    pub async fn flush(&mut self, seq: u16, rtptime: u32) -> Result<RtspResponse, SonusError> {
        let uri = self.session_uri();
        let rtp_info = format!("seq={seq};rtptime={rtptime}");
        let extra_headers = [("Range", "npt=0-"), ("RTP-Info", rtp_info.as_str())];
        self.exchange("FLUSH", &uri, &extra_headers, None).await
    }

    /// Sends `POST /feedback` keepalive packet.
    pub async fn feedback(&mut self) -> Result<RtspResponse, SonusError> {
        self.exchange("POST", "/feedback", &[], None).await
    }

    /// Sends DMAP `mlit` track metadata (`minm`, `asar`, `asal`) via `SET_PARAMETER`.
    pub async fn set_metadata(
        &mut self,
        seq: u16,
        rtptime: u32,
        title: &str,
        artist: &str,
        album: &str,
    ) -> Result<RtspResponse, SonusError> {
        let mut inner = Vec::new();
        if !title.is_empty() {
            inner.extend_from_slice(&string_tag(b"minm", title));
        }
        if !album.is_empty() {
            inner.extend_from_slice(&string_tag(b"asal", album));
        }
        if !artist.is_empty() {
            inner.extend_from_slice(&string_tag(b"asar", artist));
        }
        let body = container_tag(b"mlit", &inner);
        let uri = self.session_uri();
        let rtp_info = format!("seq={seq};rtptime={rtptime}");
        let extra_headers = [
            ("Content-Type", "application/x-dmap-tagged"),
            ("RTP-Info", rtp_info.as_str()),
        ];
        self.exchange("SET_PARAMETER", &uri, &extra_headers, Some(&body))
            .await
    }

    /// Sends active media title, artist, and album to the HomePod via RAOP DMAP SET_PARAMETER.
    pub async fn send_mr_now_playing(
        &mut self,
        title: &str,
        artist: &str,
        album: &str,
        _rate: f64,
    ) -> Result<RtspResponse, SonusError> {
        self.set_metadata(0, 0, title, artist, album).await
    }

    /// Adjust volume on HomePod via SET_PARAMETER.
    pub async fn set_volume(&mut self, volume_dbfs: f32) -> Result<RtspResponse, SonusError> {
        let uri = self.session_uri();
        let body = format!("volume: {volume_dbfs:.6}\r\n");
        let extra_headers = [("Content-Type", "text/parameters")];
        self.exchange("SET_PARAMETER", &uri, &extra_headers, Some(body.as_bytes()))
            .await
    }

    /// Tear down the RTSP audio streaming session.
    pub async fn teardown(&mut self) -> Result<RtspResponse, SonusError> {
        let uri = self.session_uri();
        self.exchange("TEARDOWN", &uri, &[], None).await
    }

    pub fn session_id(&self) -> u64 {
        self.session_id
    }
}
