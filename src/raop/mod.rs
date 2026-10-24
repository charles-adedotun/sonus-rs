//! Apple AirPlay 2 / RAOP audio protocol implementation.

pub mod crypto;
pub mod event_channel;
pub mod hap;
pub mod plist;
pub mod rtsp;

pub use crypto::AirPlayAudioCipher;
pub use event_channel::{parse_command_bplist, EventChannelClient, HomePodEvent};
pub use hap::{
    decode_tlv8, encode_tlv8, hkdf_sha512, HapSession, HapSrpClient, SrpExchangeResult, TlvTag,
};
pub use plist::{
    build_base_setup_plist, build_mr_now_playing_plist, build_mr_supported_commands_plist,
    build_stream_setup_plist, dbfs_to_pct, parse_base_setup_response, parse_stream_setup_response,
    pct_to_dbfs, SetupStreamResponse,
};
pub use rtsp::{RtspClient, RtspResponse};
