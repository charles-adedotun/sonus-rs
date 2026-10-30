//! 352-sample RTP audio packetizer for Apple RAOP streaming.
//!
//! Encapsulates 1,408 bytes of stereo 16-bit PCM audio (352 samples @ 44.1kHz)
//! into standard 12-byte RTP headers with monotonic timestamp and sequence increments.

use crate::config::{PCM_PACKET_BYTES, SAMPLES_PER_FRAME, SAMPLE_RATE};
use crate::error::SonusError;
use std::time::Duration;

/// Individual RTP Audio Packet containing the 12-byte header and PCM payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpAudioPacket {
    pub header: [u8; 12],
    pub payload: Vec<u8>,
}

impl RtpAudioPacket {
    /// Return the 12-byte RTP header slice.
    pub fn header(&self) -> &[u8; 12] {
        &self.header
    }

    /// Return the audio payload slice (1,408 bytes).
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Extract the 16-bit sequence number from the header.
    pub fn sequence_number(&self) -> u16 {
        u16::from_be_bytes([self.header[2], self.header[3]])
    }

    /// Extract the 32-bit timestamp from the header.
    pub fn timestamp(&self) -> u32 {
        u32::from_be_bytes([
            self.header[4],
            self.header[5],
            self.header[6],
            self.header[7],
        ])
    }

    /// Assemble full unencrypted packet bytes (header + payload).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(12 + self.payload.len());
        bytes.extend_from_slice(&self.header);
        bytes.extend_from_slice(&self.payload);
        bytes
    }
}

/// RTP Packetizer tracking sequence numbers and RTP timestamps.
pub struct Packetizer {
    session_id: u32,
    current_seq: u16,
    current_timestamp: u32,
    is_first_packet: bool,
}

impl Packetizer {
    /// Initialize a new packetizer with the session ID / SSRC.
    pub fn new(session_id: u32) -> Self {
        Self {
            session_id,
            current_seq: 0,
            current_timestamp: 0,
            is_first_packet: true,
        }
    }

    /// Set initial sequence number (useful for testing or reconnect).
    pub fn with_initial_seq(mut self, seq: u16) -> Self {
        self.current_seq = seq;
        self
    }

    /// Exact duration of each 352-sample audio packet (~7.981859 ms).
    pub fn packet_duration() -> Duration {
        Duration::from_nanos((SAMPLES_PER_FRAME as u64 * 1_000_000_000) / SAMPLE_RATE as u64)
    }

    /// Packetize a chunk of raw stereo 16-bit PCM bytes into an RTP packet.
    ///
    /// If the chunk is less than 1,408 bytes, it is zero-padded to maintain
    /// timing and audioOS decoder alignment.
    pub fn packetize(&mut self, pcm_chunk: &[u8]) -> Result<RtpAudioPacket, SonusError> {
        let mut payload = Vec::with_capacity(PCM_PACKET_BYTES);
        payload.extend_from_slice(pcm_chunk);

        // Pad with zeros if necessary
        if payload.len() < PCM_PACKET_BYTES {
            payload.resize(PCM_PACKET_BYTES, 0);
        } else if payload.len() > PCM_PACKET_BYTES {
            payload.truncate(PCM_PACKET_BYTES);
        }

        let mut header = [0u8; 12];
        header[0] = 0x80; // RTP v2, no padding, no extension, CC=0

        // Payload Type 96 (0x60). First packet sets Marker bit (0x80 | 0x60 = 0xE0).
        if self.is_first_packet {
            header[1] = 0xE0;
            self.is_first_packet = false;
        } else {
            header[1] = 0x60;
        }

        // Sequence Number (big-endian)
        header[2..4].copy_from_slice(&self.current_seq.to_be_bytes());
        self.current_seq = self.current_seq.wrapping_add(1);

        // Timestamp (big-endian)
        header[4..8].copy_from_slice(&self.current_timestamp.to_be_bytes());
        self.current_timestamp = self
            .current_timestamp
            .wrapping_add(SAMPLES_PER_FRAME as u32);

        // SSRC / Session ID (big-endian)
        header[8..12].copy_from_slice(&self.session_id.to_be_bytes());

        Ok(RtpAudioPacket { header, payload })
    }

    pub fn current_seq(&self) -> u16 {
        self.current_seq
    }

    pub fn current_timestamp(&self) -> u32 {
        self.current_timestamp
    }

    /// Re-anchor the RTP timestamp baseline (e.g. to `ntp2ts(ntp_now(), 44100)` after RECORD/FLUSH).
    pub fn reanchor_timestamp(&mut self, rtptime: u32) {
        self.current_timestamp = rtptime;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packetizer_timing_and_cadence() {
        let dur = Packetizer::packet_duration();
        // 352 / 44100 = 7.9818594 ms = 7,981,859 ns
        assert_eq!(dur.as_nanos(), 7_981_859);
    }

    #[test]
    fn test_packetizer_rollover_and_padding() {
        let mut p = Packetizer::new(0x12345678).with_initial_seq(65535);

        // First packet should have marker bit (0xE0) and seq 65535
        let short_pcm = vec![0x55u8; 100];
        let pkt1 = p.packetize(&short_pcm).unwrap();

        assert_eq!(pkt1.header[1], 0xE0);
        assert_eq!(pkt1.sequence_number(), 65535);
        assert_eq!(pkt1.timestamp(), 0);
        assert_eq!(pkt1.payload.len(), 1408);
        assert_eq!(&pkt1.payload[..100], &short_pcm[..]);
        assert_eq!(pkt1.payload[100], 0x00); // padded with zero

        // Second packet rolls over to 0, marker bit cleared (0x60), timestamp advanced by 352
        let pkt2 = p.packetize(&[]).unwrap();
        assert_eq!(pkt2.header[1], 0x60);
        assert_eq!(pkt2.sequence_number(), 0);
        assert_eq!(pkt2.timestamp(), 352);
        assert_eq!(pkt2.payload.len(), 1408);
    }

    #[test]
    fn test_reanchor_timestamp() {
        let mut p = Packetizer::new(0x1234);
        assert_eq!(p.current_timestamp(), 0);
        let _ = p.packetize(&[]).unwrap();
        assert_eq!(p.current_timestamp(), 352);

        // Re-anchor to arbitrary baseline (e.g. from ntp2ts)
        p.reanchor_timestamp(1_234_567);
        assert_eq!(p.current_timestamp(), 1_234_567);

        let pkt = p.packetize(&[]).unwrap();
        assert_eq!(pkt.timestamp(), 1_234_567);
        assert_eq!(p.current_timestamp(), 1_234_567 + 352);
    }
}
