//! Domain errors for the `sonus-rs` audio engine and DACP service.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum SonusError {
    #[error("RTSP protocol error: {0}")]
    Rtsp(String),

    #[error("RTSP status code error: status {code}, message: {message}")]
    RtspStatus { code: u16, message: String },

    #[error("AirPlay cryptography error: {0}")]
    Crypto(String),

    #[error("Property list serialization/deserialization error: {0}")]
    Plist(#[from] plist::Error),

    #[error("DMAP binary tag error: {0}")]
    Dmap(String),

    #[error("RTP pacer error: {0}")]
    Pacer(String),

    #[error("PipeWire audio pipeline error: {0}")]
    PipeWire(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Json(#[from] serde_json::Error),
}
