//! PipeWire 2nd-order discrete-time Delay-Locked Loop (`SpaDll`).
//!
//! Provides clock tracking and dynamic resampling / packet pacing adjustments
//! based on PipeWire's `<spa/utils/dll.h>`. Clamps clock drift compensation
//! within +/- 200 ppm (`[0.9998, 1.0002]`).

use crate::config::BYTES_PER_FRAME;
use std::time::Duration;

/// Default bandwidth setting for the 2nd-order DLL.
pub const DEFAULT_DLL_BW: f64 = 0.04;

/// Default period (samples per packet).
pub const DEFAULT_DLL_PERIOD: u32 = 352;

/// Default audio sample rate (Hz).
pub const DEFAULT_DLL_RATE: u32 = 44_100;

/// Discrete-time 2nd-order Delay-Locked Loop matching PipeWire's `<spa/utils/dll.h>`.
#[derive(Debug, Clone, PartialEq)]
pub struct SpaDll {
    pub bw: f64,
    pub period: u32,
    pub rate: u32,
    pub z1: f64,
    pub z2: f64,
    pub z3: f64,
    pub w0: f64,
    pub w1: f64,
    pub w2: f64,
}

impl SpaDll {
    /// Initialize a new Delay-Locked Loop with specified bandwidth, period, and sample rate.
    pub fn new(bw: f64, period: u32, rate: u32) -> Self {
        let w = 2.0 * std::f64::consts::PI * bw * (period as f64) / (rate as f64);
        let w0 = 1.0 - (-20.0 * w).exp();
        let w1 = w * 1.5 / (period as f64);
        let w2 = w / 1.5;

        Self {
            bw,
            period,
            rate,
            z1: 0.0,
            z2: 0.0,
            z3: 0.0,
            w0,
            w1,
            w2,
        }
    }

    /// Reset internal filter state registers (z1, z2, z3) to zero.
    pub fn reset(&mut self) {
        self.z1 = 0.0;
        self.z2 = 0.0;
        self.z3 = 0.0;
    }

    /// Recompute coefficients with a new loop bandwidth.
    pub fn set_bw(&mut self, bw: f64) {
        let w = 2.0 * std::f64::consts::PI * bw * (self.period as f64) / (self.rate as f64);
        self.w0 = 1.0 - (-20.0 * w).exp();
        self.w1 = w * 1.5 / (self.period as f64);
        self.w2 = w / 1.5;
        self.bw = bw;
    }

    /// Update DLL filter state with buffer delay/lead error in frames.
    ///
    /// Returns rate multiplier clamped to `[0.9998, 1.0002]` (+/- 200 ppm).
    pub fn update(&mut self, buffer_error_frames: f64) -> f64 {
        self.z1 += self.w0 * (self.w1 * buffer_error_frames - self.z1);
        self.z2 += self.w0 * (self.z1 - self.z2);
        self.z3 += self.w2 * self.z2;

        let raw_rate = 1.0 - (self.z2 + self.z3);
        raw_rate.clamp(0.9998, 1.0002)
    }

    /// Compute dynamic packet duration adjusted by buffer error relative to target.
    ///
    /// If `current_buffered_bytes > target_buffered_bytes`, `buffer_error_frames > 0`,
    /// causing the returned interval to shorten slightly (packets sent faster) to drain the buffer.
    /// If `current_buffered_bytes < target_buffered_bytes`, `buffer_error_frames < 0`,
    /// causing the returned interval to lengthen slightly (packets sent slower) to accumulate buffer.
    pub fn adjusted_packet_duration(
        &mut self,
        current_buffered_bytes: usize,
        target_buffered_bytes: usize,
    ) -> Duration {
        let buffer_error_bytes = (current_buffered_bytes as f64) - (target_buffered_bytes as f64);
        let buffer_error_frames = buffer_error_bytes / (BYTES_PER_FRAME as f64);
        let rate_mult = self.update(buffer_error_frames);

        let nominal_nanos = (self.period as f64 * 1_000_000_000.0) / (self.rate as f64);
        let adjusted_nanos = (nominal_nanos * rate_mult).round();
        Duration::from_nanos(adjusted_nanos as u64)
    }
}

impl Default for SpaDll {
    fn default() -> Self {
        Self::new(DEFAULT_DLL_BW, DEFAULT_DLL_PERIOD, DEFAULT_DLL_RATE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spa_dll_initialization() {
        let mut dll = SpaDll::default();
        assert_eq!(dll.bw, 0.04);
        assert_eq!(dll.period, 352);
        assert_eq!(dll.rate, 44_100);
        assert_eq!(dll.z1, 0.0);
        assert_eq!(dll.z2, 0.0);
        assert_eq!(dll.z3, 0.0);

        // At zero error, rate multiplier is exactly 1.0
        let rate = dll.update(0.0);
        assert_eq!(rate, 1.0);
    }

    #[test]
    fn test_spa_dll_rate_clamping() {
        let mut dll = SpaDll::default();

        // Repeated large positive errors -> clamp to 0.9998
        for _ in 0..500 {
            dll.update(100_000.0);
        }
        let rate = dll.update(100_000.0);
        assert_eq!(rate, 0.9998);

        // Reset and apply repeated large negative errors -> clamp to 1.0002
        dll.reset();
        assert_eq!(dll.z1, 0.0);
        assert_eq!(dll.z2, 0.0);
        assert_eq!(dll.z3, 0.0);

        for _ in 0..500 {
            dll.update(-100_000.0);
        }
        let rate_neg = dll.update(-100_000.0);
        assert_eq!(rate_neg, 1.0002);
    }

    #[test]
    fn test_spa_dll_adjusted_packet_duration() {
        let mut dll = SpaDll::default();

        // At zero error: duration matches nominal ~7,981,859 ns
        let d_nom = dll.adjusted_packet_duration(10_000, 10_000);
        assert_eq!(d_nom.as_nanos(), 7_981_859);

        // Current > target (too full): interval shortens (< 7,981,859 ns)
        let mut dll_drain = SpaDll::default();
        for _ in 0..200 {
            dll_drain.adjusted_packet_duration(20_000, 10_000);
        }
        let d_drain = dll_drain.adjusted_packet_duration(20_000, 10_000);
        assert!(d_drain < d_nom);
        assert_eq!(d_drain.as_nanos(), 7_980_263); // 7_981_859 * 0.9998

        // Current < target (too empty): interval lengthens (> 7,981,859 ns)
        let mut dll_fill = SpaDll::default();
        for _ in 0..200 {
            dll_fill.adjusted_packet_duration(5_000, 10_000);
        }
        let d_fill = dll_fill.adjusted_packet_duration(5_000, 10_000);
        assert!(d_fill > d_nom);
        assert_eq!(d_fill.as_nanos(), 7_983_456); // 7_981_859.4 * 1.0002
    }

    #[test]
    fn test_spa_dll_reset() {
        let mut dll = SpaDll::default();
        dll.update(50.0);
        assert!(dll.z1 != 0.0 || dll.z2 != 0.0 || dll.z3 != 0.0);

        dll.reset();
        assert_eq!(dll.z1, 0.0);
        assert_eq!(dll.z2, 0.0);
        assert_eq!(dll.z3, 0.0);
        assert_eq!(dll.update(0.0), 1.0);
    }
}
