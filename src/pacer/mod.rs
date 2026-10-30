//! Audio pacing, 352-sample packetization, 60-second silence maintenance,
//! PipeWire Delay-Locked Loop (SpaDll), and AirPlay 2 UDP timing/control synchronization.

pub mod dll;
pub mod packetizer;
pub mod silence;
pub mod timing;

pub use dll::{SpaDll, DEFAULT_DLL_BW, DEFAULT_DLL_PERIOD, DEFAULT_DLL_RATE};
pub use packetizer::{Packetizer, RtpAudioPacket};
pub use silence::SilencePacer;
pub use timing::{
    encode_sync_packet, ntp2parts, ntp2ts, ntp_now, ControlClient, RetransmitBacklog,
    RetransmitBuffer, TimingServer, RETRANSMIT_BUFFER_SIZE, UNIX_NTP_DELTA,
};
