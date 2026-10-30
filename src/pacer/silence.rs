//! 60-second RTP silence pacer maintaining NTP/RTP sync across pause/resume.
//!
//! Apple HomePod mini's audioOS hardware DAC will power down or disconnect the
//! session if RTP audio frames cease for more than ~2.5 seconds.
//!
//! When system audio is paused (e.g. YouTube or Spotify paused on Linux desktop),
//! `SilencePacer` injects 1,408 bytes of zeroed PCM frames (`0x00`) at exact 7.98ms
//! intervals. This:
//! 1. Preserves RTP sequence continuity.
//! 2. Keeps presentation time aligned with NTP clock.
//! 3. Prevents speaker popping or clicking when playback resumes.
//! 4. Holds the session hot for up to 60 seconds before clean RTSP teardown.

use crate::config::{DEFAULT_IDLE_TIMEOUT_SECS, PCM_PACKET_BYTES};
use crate::error::SonusError;
use crate::pacer::packetizer::{Packetizer, RtpAudioPacket};
use std::time::{Duration, Instant};

/// Pre-allocated buffer of 1,408 zeroed PCM bytes for zero-allocation silence generation.
const SILENCE_FRAME: [u8; PCM_PACKET_BYTES] = [0u8; PCM_PACKET_BYTES];

/// Tracks silence pacing lifecycle and idle timeout.
pub struct SilencePacer {
    idle_timeout: Duration,
    silence_start: Option<Instant>,
    silence_packets_sent: u64,
}

impl SilencePacer {
    /// Initialize with a custom idle timeout (default 60 seconds).
    pub fn new(idle_timeout_secs: u64) -> Self {
        Self {
            idle_timeout: Duration::from_secs(idle_timeout_secs),
            silence_start: None,
            silence_packets_sent: 0,
        }
    }

    /// Reset silence tracking when real audio playback resumes.
    pub fn reset_active(&mut self) {
        self.silence_start = None;
        self.silence_packets_sent = 0;
    }

    /// Check if the silence timeout has expired (> 60 seconds).
    pub fn is_timed_out(&self) -> bool {
        if let Some(start) = self.silence_start {
            start.elapsed() >= self.idle_timeout
        } else {
            false
        }
    }

    /// Generate the next silence packet if within the idle window.
    /// Returns `Ok(Some(packet))` during the 60s idle window, or `Ok(None)` once timed out.
    pub fn generate_silence_packet(
        &mut self,
        packetizer: &mut Packetizer,
    ) -> Result<Option<RtpAudioPacket>, SonusError> {
        let now = Instant::now();
        if self.silence_start.is_none() {
            self.silence_start = Some(now);
        }

        if self.is_timed_out() {
            return Ok(None);
        }

        self.silence_packets_sent += 1;
        let pkt = packetizer.packetize(&SILENCE_FRAME)?;
        Ok(Some(pkt))
    }

    /// Duration elapsed since silence started.
    pub fn elapsed_silence(&self) -> Duration {
        self.silence_start
            .map(|s| s.elapsed())
            .unwrap_or(Duration::ZERO)
    }

    pub fn silence_packets_count(&self) -> u64 {
        self.silence_packets_sent
    }
}

impl Default for SilencePacer {
    fn default() -> Self {
        Self::new(DEFAULT_IDLE_TIMEOUT_SECS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_silence_pacer_lifecycle() {
        let mut pacer = SilencePacer::new(1); // 1 second timeout for test
        let mut pktzr = Packetizer::new(0x42);

        // Before ticking, not timed out
        assert!(!pacer.is_timed_out());

        // First silence packet
        let p1 = pacer.generate_silence_packet(&mut pktzr).unwrap().unwrap();
        assert_eq!(p1.payload().len(), PCM_PACKET_BYTES);
        assert!(p1.payload().iter().all(|&b| b == 0));
        assert_eq!(pacer.silence_packets_count(), 1);

        // Reset on audio active
        pacer.reset_active();
        assert_eq!(pacer.silence_packets_count(), 0);
    }
}
