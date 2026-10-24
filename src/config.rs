//! Configuration constants, device profiles, and environment settings.

use crate::error::SonusError;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::Path;

/// Audio format constants matching Apple RAOP hardware requirements.
pub const SAMPLE_RATE: u32 = 44_100;
pub const CHANNELS: u16 = 2;
pub const BITS_PER_SAMPLE: u16 = 16;
pub const BYTES_PER_FRAME: usize = 4; // 2 channels * 2 bytes (s16le)
pub const SAMPLES_PER_FRAME: usize = 352;
pub const PCM_PACKET_BYTES: usize = SAMPLES_PER_FRAME * BYTES_PER_FRAME; // 1,408 bytes

/// Latency constants.
/// Clamping min and max latency to 11,025 frames forces exactly 250.0ms interactive presentation.
pub const TARGET_LATENCY_FRAMES: u32 = 11_025;
pub const MIN_LATENCY_FRAMES: u32 = 11_025;
pub const MAX_LATENCY_FRAMES: u32 = 11_025;
pub const STANDARD_AIRPLAY_LATENCY_FRAMES: u32 = 88_200; // 2,000ms delay default

/// Packet wire layout sizes.
pub const RTP_HEADER_BYTES: usize = 12;
pub const POLY1305_TAG_BYTES: usize = 16;
pub const NONCE_SUFFIX_BYTES: usize = 8;
pub const ENCRYPTED_RTP_PACKET_BYTES: usize =
    RTP_HEADER_BYTES + PCM_PACKET_BYTES + POLY1305_TAG_BYTES + NONCE_SUFFIX_BYTES; // 1,444 bytes

/// Network defaults.
pub const DEFAULT_HOMEPOD_IP: &str = "192.168.1.100";
pub const DEFAULT_RTSP_PORT: u16 = 7000;
pub const DEFAULT_DACP_PORT: u16 = 3689;
pub const DEFAULT_DACP_ID: &str = "484F4D454C414231"; // ASCII "HOMELAB1"
pub const DEFAULT_ACTIVE_REMOTE: u32 = 1_986_535_575;
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 60;
pub const DEFAULT_SINK_NAME: &str = "HomePod";

/// Configuration profile for `sonus-rs`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SonusConfig {
    pub homepod_ip: String,
    pub homepod_port: u16,
    pub homepod_name: String,
    pub homepod_id: String,
    pub sink_name: String,
    pub dacp_id: String,
    pub dacp_port: u16,
    pub active_remote: u32,
    pub latency_frames: u32,
    pub idle_timeout_secs: u64,
}

impl Default for SonusConfig {
    fn default() -> Self {
        Self {
            homepod_ip: DEFAULT_HOMEPOD_IP.to_string(),
            homepod_port: DEFAULT_RTSP_PORT,
            homepod_name: "Office".to_string(),
            homepod_id: "AA:BB:CC:DD:EE:FF".to_string(),
            sink_name: DEFAULT_SINK_NAME.to_string(),
            dacp_id: DEFAULT_DACP_ID.to_string(),
            dacp_port: DEFAULT_DACP_PORT,
            active_remote: DEFAULT_ACTIVE_REMOTE,
            latency_frames: TARGET_LATENCY_FRAMES,
            idle_timeout_secs: DEFAULT_IDLE_TIMEOUT_SECS,
        }
    }
}

impl SonusConfig {
    /// Load configuration by merging environment variables over defaults.
    pub fn from_env() -> Self {
        let mut conf = Self::default();

        if let Ok(ip) = std::env::var("HOMEPOD_IP") {
            conf.homepod_ip = ip;
        }
        if let Ok(port) = std::env::var("HOMEPOD_PORT") {
            if let Ok(p) = port.parse() {
                conf.homepod_port = p;
            }
        }
        if let Ok(name) = std::env::var("HOMEPOD_NAME") {
            conf.homepod_name = name;
        }
        if let Ok(id) = std::env::var("HOMEPOD_ID") {
            conf.homepod_id = id;
        }
        if let Ok(sink) = std::env::var("HOMEPOD_SINK_NAME") {
            conf.sink_name = sink;
        }
        if let Ok(dacp_port) = std::env::var("HOMEPOD_DACP_PORT") {
            if let Ok(p) = dacp_port.parse() {
                conf.dacp_port = p;
            }
        }
        if let Ok(dacp_id) = std::env::var("HOMEPOD_DACP_ID") {
            conf.dacp_id = dacp_id;
        }

        conf
    }

    /// Load configuration from a JSON file.
    pub fn load_file<P: AsRef<Path>>(path: P) -> Result<Self, SonusError> {
        let data = std::fs::read_to_string(path)?;
        let conf: Self = serde_json::from_str(&data)?;
        Ok(conf)
    }

    /// Persist configuration to a JSON file.
    pub fn save_file<P: AsRef<Path>>(&self, path: P) -> Result<(), SonusError> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_string_pretty(self)?;
        std::fs::write(path, data)?;
        Ok(())
    }

    /// Calculate presentation latency in milliseconds.
    pub fn presentation_latency_ms(&self) -> f32 {
        (self.latency_frames as f32 / SAMPLE_RATE as f32) * 1000.0
    }

    /// Validate the IP address format.
    pub fn parsed_ip(&self) -> Result<IpAddr, SonusError> {
        self.homepod_ip.parse::<IpAddr>().map_err(|e| {
            SonusError::Config(format!("Invalid HomePod IP '{}': {}", self.homepod_ip, e))
        })
    }
}
