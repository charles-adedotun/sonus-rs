//! Encrypted AirPlay 2 EventChannel for HomePod touch surface, volume, and playback commands.
//!
//! Connects to the HomePod's negotiated `eventPort` using ChaCha20-Poly1305 `HapSession`
//! framing derived from `Events-Salt`. Listens for peer-initiated `POST /command` binary plists,
//! translates hardware touch events, and replies with encrypted `200 OK` responses.

use plist::Value;
use std::io::Cursor;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::error::SonusError;
use crate::raop::hap::HapSession;
use crate::raop::plist::dbfs_to_pct;

/// High-level events emitted by the HomePod mini touch surface and MediaRemote stack.
#[derive(Debug, Clone, PartialEq)]
pub enum HomePodEvent {
    Play,
    Pause,
    PlayPause,
    Stop,
    Next,
    Previous,
    SeekTo(f64),
    VolumePercent(u8),
    InitialVolumeDbfs(f32),
}

/// Parses HomePod `POST /command` binary property lists into strongly typed `HomePodEvent`s.
///
/// Ensures strict type validation:
/// - `dvlc` / volume events always yield `VolumePercent(pct)`.
/// - `type == "updateInfo"` never misclassifies as `PlayPause` and extracts `initialVolume`.
/// - `mrCommand` / `kMRMediaRemoteCommand` are mapped to transport controls.
pub fn parse_command_bplist(body: &[u8]) -> Option<HomePodEvent> {
    let cursor = Cursor::new(body);
    let val = Value::from_reader(cursor).ok()?;
    let root = val.as_dictionary()?;

    let type_str = root.get("type").and_then(|v| v.as_string());
    let command_str = root.get("command").and_then(|v| v.as_string());
    let value_str = root.get("value").and_then(|v| v.as_string());

    // 1. Check for `updateInfo` (speaker initialization / state announcement)
    if type_str == Some("updateInfo") || command_str == Some("updateInfo") {
        if let Some(val_dict) = root.get("value").and_then(|v| v.as_dictionary()) {
            if let Some(init_vol) = val_dict.get("initialVolume") {
                let dbfs = init_vol
                    .as_real()
                    .or_else(|| init_vol.as_signed_integer().map(|i| i as f64))?
                    as f32;
                return Some(HomePodEvent::InitialVolumeDbfs(dbfs));
            }
            if let Some(vol_val) = val_dict.get("volume") {
                return parse_volume_value(vol_val);
            }
        }
        // `updateInfo` with no volume must NEVER be misclassified as PlayPause!
        return None;
    }

    // 2. Check for `dvlc` (Delta Volume Level Change) or explicit volume notifications
    let is_dvlc = value_str == Some("dvlc")
        || type_str == Some("dvlc")
        || command_str == Some("dvlc")
        || type_str == Some("volume")
        || command_str == Some("volume");

    // Check volume in root
    if let Some(v) = root.get("volume") {
        return parse_volume_value(v);
    }

    // Check volume in params dictionary
    if let Some(params) = root.get("params").and_then(|p| p.as_dictionary()) {
        if let Some(v) = params.get("volume") {
            return parse_volume_value(v);
        }
    }

    // Check volume in value dictionary
    if let Some(val_dict) = root.get("value").and_then(|v| v.as_dictionary()) {
        if let Some(v) = val_dict.get("volume") {
            return parse_volume_value(v);
        }
    }

    if is_dvlc {
        // If message is marked dvlc without numeric volume, do not misclassify as PlayPause
        return None;
    }

    // 3. Check MediaRemote numerical command codes (mrCommand / kMRMediaRemoteCommand / command)
    let cmd_code = extract_command_code(root);
    if let Some(code) = cmd_code {
        match code {
            0 => return Some(HomePodEvent::Play),
            1 => return Some(HomePodEvent::Pause),
            2 => return Some(HomePodEvent::PlayPause),
            3 => return Some(HomePodEvent::Stop),
            4 => return Some(HomePodEvent::Next),
            5 => return Some(HomePodEvent::Previous),
            45 => {
                let pos = extract_seek_position(root).unwrap_or(0.0);
                return Some(HomePodEvent::SeekTo(pos));
            }
            _ => return None,
        }
    }

    // 4. Check string command representations
    let action_str = command_str.or(type_str).or(value_str)?;
    match action_str.to_ascii_lowercase().as_str() {
        "play" => Some(HomePodEvent::Play),
        "pause" => Some(HomePodEvent::Pause),
        "playpause" | "toggle" => Some(HomePodEvent::PlayPause),
        "stop" => Some(HomePodEvent::Stop),
        "next" | "nexttrack" => Some(HomePodEvent::Next),
        "previous" | "prevtrack" => Some(HomePodEvent::Previous),
        _ => None,
    }
}

/// Helper extracting float/int volume values into `HomePodEvent::VolumePercent(0..=100)`.
fn parse_volume_value(val: &Value) -> Option<HomePodEvent> {
    let vol_f = val
        .as_real()
        .or_else(|| val.as_signed_integer().map(|i| i as f64))?;

    let pct = if vol_f < 0.0 {
        // Decibel Full Scale (dBFS), e.g. -30.0..0.0 dBFS
        dbfs_to_pct(vol_f as f32).round() as u8
    } else if vol_f <= 1.0 {
        // Normalized ratio 0.0..1.0
        (vol_f * 100.0).round() as u8
    } else {
        // Direct percentage 1..100
        vol_f.clamp(0.0, 100.0).round() as u8
    };

    Some(HomePodEvent::VolumePercent(pct))
}

/// Helper extracting MediaRemote integer command IDs from nested plist structures.
fn extract_command_code(root: &plist::Dictionary) -> Option<u32> {
    for key in &["mrCommand", "kMRMediaRemoteCommand", "command"] {
        if let Some(v) = root.get(key).and_then(|v| v.as_unsigned_integer()) {
            return Some(v as u32);
        }
    }

    if let Some(params) = root.get("params").and_then(|v| v.as_dictionary()) {
        for key in &["mrCommand", "kMRMediaRemoteCommand", "command"] {
            if let Some(v) = params.get(key).and_then(|v| v.as_unsigned_integer()) {
                return Some(v as u32);
            }
        }
    }

    if let Some(val_dict) = root.get("value").and_then(|v| v.as_dictionary()) {
        for key in &["mrCommand", "kMRMediaRemoteCommand", "command"] {
            if let Some(v) = val_dict.get(key).and_then(|v| v.as_unsigned_integer()) {
                return Some(v as u32);
            }
        }
    }

    None
}

/// Helper extracting seek position in seconds from command parameters.
fn extract_seek_position(root: &plist::Dictionary) -> Option<f64> {
    let find_real = |d: &plist::Dictionary, k: &str| {
        d.get(k).and_then(|v| {
            v.as_real()
                .or_else(|| v.as_signed_integer().map(|i| i as f64))
        })
    };

    for k in &["playbackPosition", "position", "seekTime"] {
        if let Some(pos) = find_real(root, k) {
            return Some(pos);
        }
    }

    if let Some(params) = root.get("params").and_then(|v| v.as_dictionary()) {
        for k in &["playbackPosition", "position", "seekTime"] {
            if let Some(pos) = find_real(params, k) {
                return Some(pos);
            }
        }
    }

    None
}

/// Asynchronous AirPlay 2 EventChannel client running on background Tokio task.
pub struct EventChannelClient;

impl EventChannelClient {
    /// Connects to the HomePod's negotiated event port with derived HAP encryption keys.
    ///
    /// Decrypts incoming frames, dispatches parsed `HomePodEvent`s over `event_tx`,
    /// and acknowledges peer commands with encrypted `RTSP/1.0 200 OK` frames.
    pub async fn connect(
        host: &str,
        event_port: u16,
        read_key: [u8; 32],
        write_key: [u8; 32],
        event_tx: mpsc::Sender<HomePodEvent>,
    ) -> Result<tokio::task::JoinHandle<()>, SonusError> {
        let addr = format!("{host}:{event_port}");
        info!("Connecting to HomePod EventChannel endpoint at {}", addr);

        // Retry connection up to 5 times (200ms sleep) to allow HomePod socket to bind
        let mut stream = None;
        for attempt in 1..=5 {
            match TcpStream::connect(&addr).await {
                Ok(s) => {
                    stream = Some(s);
                    break;
                }
                Err(e) => {
                    if attempt == 5 {
                        return Err(SonusError::Rtsp(format!(
                            "Failed to connect to EventChannel at {addr}: {e}"
                        )));
                    }
                    debug!(
                        "EventChannel connect attempt {} failed: {}, retrying...",
                        attempt, e
                    );
                    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
                }
            }
        }

        let mut stream = stream.unwrap();

        let handle = tokio::spawn(async move {
            let mut hap_session = HapSession::new(&write_key, &read_key);
            let mut raw_buf = vec![0u8; 4096];
            let mut channel_buf = Vec::new();

            loop {
                let n = match stream.read(&mut raw_buf).await {
                    Ok(0) => {
                        info!("HomePod EventChannel remote closed connection");
                        break;
                    }
                    Ok(n) => n,
                    Err(e) => {
                        warn!("HomePod EventChannel TCP read error: {}", e);
                        break;
                    }
                };

                let decrypted = match hap_session.decrypt(&raw_buf[..n]) {
                    Ok(d) => d,
                    Err(e) => {
                        warn!("HomePod EventChannel decryption error: {}", e);
                        continue;
                    }
                };

                channel_buf.extend_from_slice(&decrypted);

                // Process complete HTTP / RTSP requests in channel_buf
                while let Some(header_end) = channel_buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let header_str = String::from_utf8_lossy(&channel_buf[..header_end]);
                    let mut lines = header_str.lines();
                    let first_line = lines.next().unwrap_or("").to_string();

                    let mut cseq = 0u32;
                    let mut content_length = 0usize;

                    for line in lines {
                        if let Some((k, v)) = line.split_once(':') {
                            let k = k.trim().to_ascii_lowercase();
                            let v = v.trim();
                            if k == "cseq" {
                                cseq = v.parse().unwrap_or(0);
                            } else if k == "content-length" {
                                content_length = v.parse().unwrap_or(0);
                            }
                        }
                    }

                    let total_msg_len = header_end + 4 + content_length;
                    if channel_buf.len() < total_msg_len {
                        // Wait for complete message payload
                        break;
                    }

                    let body = &channel_buf[header_end + 4..total_msg_len];

                    // Parse event if body is present
                    if !body.is_empty() {
                        if let Some(event) = parse_command_bplist(body) {
                            debug!("EventChannel received HomePod event: {:?}", event);
                            let _ = event_tx.send(event).await;
                        }
                    }

                    // Acknowledge peer request with encrypted 200 OK
                    let ack = format!(
                        "RTSP/1.0 200 OK\r\n\
                         CSeq: {cseq}\r\n\
                         Content-Length: 0\r\n\
                         Audio-Latency: 0\r\n\
                         \r\n"
                    );

                    let encrypted_ack = match hap_session.encrypt(ack.as_bytes()) {
                        Ok(enc) => enc,
                        Err(e) => {
                            warn!("Failed to encrypt EventChannel ACK: {}", e);
                            break;
                        }
                    };

                    if let Err(e) = stream.write_all(&encrypted_ack).await {
                        warn!("Failed to write EventChannel ACK to TCP stream: {}", e);
                        break;
                    }
                    let _ = stream.flush().await;

                    channel_buf.drain(0..total_msg_len);
                    debug!("Handled EventChannel request: {}", first_line);
                }
            }
        });

        Ok(handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plist::Dictionary;

    #[test]
    fn test_parse_dvlc_volume() {
        let mut params = Dictionary::new();
        params.insert("volume".to_string(), Value::Real(0.75));

        let mut root = Dictionary::new();
        root.insert("value".to_string(), Value::String("dvlc".to_string()));
        root.insert("params".to_string(), Value::Dictionary(params));

        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &Value::Dictionary(root)).unwrap();

        let event = parse_command_bplist(&body).unwrap();
        assert_eq!(event, HomePodEvent::VolumePercent(75));
    }

    #[test]
    fn test_parse_dvlc_dbfs_volume() {
        let mut params = Dictionary::new();
        params.insert("volume".to_string(), Value::Real(-15.0));

        let mut root = Dictionary::new();
        root.insert("value".to_string(), Value::String("dvlc".to_string()));
        root.insert("params".to_string(), Value::Dictionary(params));

        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &Value::Dictionary(root)).unwrap();

        let event = parse_command_bplist(&body).unwrap();
        assert_eq!(event, HomePodEvent::VolumePercent(50));
    }

    #[test]
    fn test_parse_update_info_initial_volume() {
        let mut val_dict = Dictionary::new();
        val_dict.insert("initialVolume".to_string(), Value::Real(-27.0));

        let mut root = Dictionary::new();
        root.insert("type".to_string(), Value::String("updateInfo".to_string()));
        root.insert("value".to_string(), Value::Dictionary(val_dict));

        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &Value::Dictionary(root)).unwrap();

        let event = parse_command_bplist(&body).unwrap();
        assert_eq!(event, HomePodEvent::InitialVolumeDbfs(-27.0));
    }

    #[test]
    fn test_update_info_never_playpause() {
        let mut val_dict = Dictionary::new();
        val_dict.insert(
            "someField".to_string(),
            Value::String("arbitrary".to_string()),
        );

        let mut root = Dictionary::new();
        root.insert("type".to_string(), Value::String("updateInfo".to_string()));
        root.insert("value".to_string(), Value::Dictionary(val_dict));

        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &Value::Dictionary(root)).unwrap();

        let event = parse_command_bplist(&body);
        assert_eq!(event, None);
    }

    #[test]
    fn test_parse_mr_commands() {
        let test_cases = [
            (0, HomePodEvent::Play),
            (1, HomePodEvent::Pause),
            (2, HomePodEvent::PlayPause),
            (3, HomePodEvent::Stop),
            (4, HomePodEvent::Next),
            (5, HomePodEvent::Previous),
        ];

        for (code, expected) in test_cases {
            let mut root = Dictionary::new();
            root.insert("mrCommand".to_string(), Value::Integer(code.into()));
            let mut body = Vec::new();
            plist::to_writer_binary(&mut body, &Value::Dictionary(root)).unwrap();

            let event = parse_command_bplist(&body).unwrap();
            assert_eq!(event, expected);
        }
    }

    #[test]
    fn test_parse_mr_seek_to() {
        let mut params = Dictionary::new();
        params.insert("playbackPosition".to_string(), Value::Real(123.45));

        let mut root = Dictionary::new();
        root.insert("mrCommand".to_string(), Value::Integer(45.into()));
        root.insert("params".to_string(), Value::Dictionary(params));

        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &Value::Dictionary(root)).unwrap();

        let event = parse_command_bplist(&body).unwrap();
        assert_eq!(event, HomePodEvent::SeekTo(123.45));
    }
}
