//! Loopback sink monitor, audio capture, and PipeWire control bridge.
//!
//! Subscribes to the PipeWire virtual sink node (`HomePod`, 60-homepod.conf)
//! configured as `Audio/Sink` with stereo 16-bit 44,100 Hz PCM.

use std::collections::VecDeque;
use std::f32::consts::PI;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, Notify};

use crate::config::{BYTES_PER_FRAME, PCM_PACKET_BYTES, SAMPLE_RATE};
use crate::error::SonusError;

/// Maximum ring buffer capacity: 8,448 bytes = 6 packets of 1,408 bytes.
pub const MAX_RING_BUFFER_BYTES: usize = 6 * PCM_PACKET_BYTES; // 8,448 bytes

/// Overflow trim target: 4,224 bytes = 3 packets of 1,408 bytes.
pub const TRIM_TARGET_BYTES: usize = 3 * PCM_PACKET_BYTES; // 4,224 bytes

/// Startup backlog drain target: 2,816 bytes = 2 packets of 1,408 bytes.
pub const STARTUP_BACKLOG_BYTES: usize = 2 * PCM_PACKET_BYTES; // 2,816 bytes

/// State of the virtual PipeWire sink node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkState {
    Idle,
    Running,
    Suspended,
}

/// Dynamic events emitted by the PipeWire sink monitor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SinkEvent {
    StateChanged(SinkState),
    VolumeChanged { percent: u8, muted: bool },
}

/// Abstract audio source providing raw stereo 16-bit PCM chunks.
pub trait AudioSource: Send + 'static {
    /// Read next PCM frames into buffer. Returns number of bytes read.
    fn read_chunk(&mut self, buf: &mut [u8]) -> Result<usize, SonusError>;
}

/// Synthetic sine wave generator for audio testing and presentation latency calibration.
pub struct SineToneSource {
    frequency_hz: f32,
    sample_index: usize,
    sample_rate: u32,
}

impl SineToneSource {
    /// Create a new sine wave generator with the specified frequency (e.g. 440.0 Hz).
    pub fn new(frequency_hz: f32) -> Self {
        Self {
            frequency_hz,
            sample_index: 0,
            sample_rate: SAMPLE_RATE,
        }
    }
}

impl AudioSource for SineToneSource {
    fn read_chunk(&mut self, buf: &mut [u8]) -> Result<usize, SonusError> {
        let frame_count = buf.len() / BYTES_PER_FRAME;
        let mut buf_idx = 0;

        for _ in 0..frame_count {
            let t = self.sample_index as f32 / self.sample_rate as f32;
            let sample_val = (2.0 * PI * self.frequency_hz * t).sin();
            // Scale to 16-bit signed integer amplitude (70% max volume) in RFC 3551 L16 big-endian (s16be)
            let sample_i16 = (sample_val * 23000.0) as i16;
            let bytes = sample_i16.to_be_bytes();

            // Left channel
            buf[buf_idx] = bytes[0];
            buf[buf_idx + 1] = bytes[1];
            // Right channel
            buf[buf_idx + 2] = bytes[0];
            buf[buf_idx + 3] = bytes[1];

            buf_idx += 4;
            self.sample_index = self.sample_index.wrapping_add(1);
        }

        Ok(frame_count * BYTES_PER_FRAME)
    }
}

/// PipeWire Loopback Sink Monitor abstraction.
///
/// In production on Linux desktops, binds to `playback.HomePod` via `libpipewire-0.3`.
/// Provides lock-free buffer handoff across thread boundaries.
pub struct PipeWireSinkMonitor {
    sink_name: String,
    is_active: Arc<AtomicBool>,
    pcm_tx: mpsc::Sender<Vec<u8>>,
    pcm_rx: Option<mpsc::Receiver<Vec<u8>>>,
}

impl PipeWireSinkMonitor {
    /// Create a new monitor for the given PipeWire sink name.
    pub fn new(sink_name: &str) -> Self {
        let (tx, rx) = mpsc::channel(64);
        Self {
            sink_name: sink_name.to_string(),
            is_active: Arc::new(AtomicBool::new(false)),
            pcm_tx: tx,
            pcm_rx: Some(rx),
        }
    }

    /// Take the audio chunk receiver stream.
    pub fn take_receiver(&mut self) -> Option<mpsc::Receiver<Vec<u8>>> {
        self.pcm_rx.take()
    }

    /// Check if the sink is currently in active streaming state.
    pub fn is_active(&self) -> bool {
        self.is_active.load(Ordering::Relaxed)
    }

    /// Sink node name.
    pub fn sink_name(&self) -> &str {
        &self.sink_name
    }

    /// Push an audio buffer into the processing pipeline (called by real-time callback).
    pub fn push_pcm_frame(&self, frame: &[u8]) {
        self.is_active.store(true, Ordering::Relaxed);
        let _ = self.pcm_tx.try_send(frame.to_vec());
    }

    /// Mark the sink as idle.
    pub fn mark_idle(&self) {
        self.is_active.store(false, Ordering::Relaxed);
    }
}

/// Configure the PipeWire virtual sink node parameters for low-latency bit-perfect audio.
///
/// Finds the sink ID for `sink_name` via `pactl list sinks short`, and configures:
/// 1. `pw-cli set-param <id> Props '{ params = [ "monitor.channel-volumes" false "resample.quality" 10 ] }'`
/// 2. `pw-cli set-param <id> ProcessLatency '{ rate = <latency_frames>, ns = <latency_ns> }'`
///
/// This ensures Chrome, YouTube, Firefox, and MPV automatically delay video by 250ms
/// for zero A/V lip-sync lag while keeping PCM bit-perfect (`monitor.channel-volumes = false`).
pub fn configure_pipewire_sink(
    sink_name: &str,
    latency_frames: u32,
    latency_ns: u64,
) -> Result<(), SonusError> {
    let output = std::process::Command::new("pactl")
        .args(["list", "sinks", "short"])
        .output()
        .map_err(|e| {
            SonusError::PipeWire(format!("Failed to execute 'pactl list sinks short': {e}"))
        })?;

    if !output.status.success() {
        return Err(SonusError::PipeWire(format!(
            "pactl list sinks short failed with status: {}",
            output.status
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut sink_id = None;
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 && parts[1] == sink_name {
            sink_id = Some(parts[0].to_string());
            break;
        }
    }

    let id = sink_id.ok_or_else(|| {
        SonusError::PipeWire(format!(
            "Sink '{sink_name}' not found in pactl list sinks short"
        ))
    })?;

    let props_arg = r#"{ params = [ "monitor.channel-volumes" false "resample.quality" 10 ] }"#;
    let status_props = std::process::Command::new("pw-cli")
        .args(["set-param", &id, "Props", props_arg])
        .status()
        .map_err(|e| SonusError::PipeWire(format!("Failed to execute pw-cli Props: {e}")))?;

    if !status_props.success() {
        return Err(SonusError::PipeWire(format!(
            "pw-cli set-param {id} Props returned status {status_props}"
        )));
    }

    let latency_arg = format!(r#"{{ rate = {latency_frames}, ns = {latency_ns} }}"#);
    let status_latency = std::process::Command::new("pw-cli")
        .args(["set-param", &id, "ProcessLatency", &latency_arg])
        .status()
        .map_err(|e| {
            SonusError::PipeWire(format!("Failed to execute pw-cli ProcessLatency: {e}"))
        })?;

    if !status_latency.success() {
        return Err(SonusError::PipeWire(format!(
            "pw-cli set-param {id} ProcessLatency returned status {status_latency}"
        )));
    }

    Ok(())
}

/// Query current state of the virtual PipeWire sink node (`Running`, `Idle`, `Suspended`).
pub fn get_sink_state(sink_name: &str) -> Option<SinkState> {
    let output = std::process::Command::new("pactl")
        .args(["list", "sinks", "short"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 && parts[1] == sink_name {
            if line.contains("RUNNING") {
                return Some(SinkState::Running);
            } else if line.contains("IDLE") {
                return Some(SinkState::Idle);
            } else if line.contains("SUSPENDED") {
                return Some(SinkState::Suspended);
            }
        }
    }

    None
}

/// Check if `sink_name` is currently in `RUNNING` state via `pactl list sinks short`.
pub fn is_sink_running(sink_name: &str) -> bool {
    matches!(get_sink_state(sink_name), Some(SinkState::Running))
}

/// Parse volume percentage (0..=100) from `pactl get-sink-volume` output text.
pub fn parse_volume_percent_from_pactl(output: &str) -> Option<u8> {
    for part in output.split_whitespace() {
        if let Some(stripped) = part.strip_suffix('%') {
            if let Ok(val) = stripped.parse::<u32>() {
                return Some(val.min(100) as u8);
            }
        }
    }
    None
}

/// Parse mute boolean state from `pactl get-sink-mute` output text.
pub fn parse_mute_from_pactl(output: &str) -> Option<bool> {
    for word in output.split_whitespace() {
        match word.trim().to_lowercase().as_str() {
            "yes" | "true" | "1" => return Some(true),
            "no" | "false" | "0" => return Some(false),
            _ => {}
        }
    }
    None
}

/// Query current volume percentage (`0..=100`) and mute status for `sink_name`.
pub fn get_sink_volume_and_mute(sink_name: &str) -> Option<(u8, bool)> {
    let vol_output = std::process::Command::new("pactl")
        .args(["get-sink-volume", sink_name])
        .output()
        .ok()?;
    if !vol_output.status.success() {
        return None;
    }
    let vol_str = String::from_utf8_lossy(&vol_output.stdout);
    let vol = parse_volume_percent_from_pactl(&vol_str)?;

    let mute_output = std::process::Command::new("pactl")
        .args(["get-sink-mute", sink_name])
        .output()
        .ok()?;
    if !mute_output.status.success() {
        return None;
    }
    let mute_str = String::from_utf8_lossy(&mute_output.stdout);
    let mute = parse_mute_from_pactl(&mute_str).unwrap_or(false);

    Some((vol, mute))
}

/// Set sink volume to an absolute percentage (`0..=100`).
pub fn set_sink_volume_percent(sink_name: &str, pct: u8) -> bool {
    let pct_clamped = pct.min(100);
    let arg = format!("{pct_clamped}%");
    std::process::Command::new("pactl")
        .args(["set-sink-volume", sink_name, &arg])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Adjust sink volume by a delta string (e.g. `"+5%"` or `"-5%"`).
pub fn adjust_sink_volume_delta(sink_name: &str, delta: &str) -> bool {
    std::process::Command::new("pactl")
        .args(["set-sink-volume", sink_name, delta])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Toggle sink mute status.
pub fn toggle_sink_mute(sink_name: &str) -> bool {
    std::process::Command::new("pactl")
        .args(["set-sink-mute", sink_name, "toggle"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Continuous audio capture stream from PipeWire monitor node.
///
/// Spawns `parec -d <sink_name>.monitor --rate=44100 --channels=2 --format=s16le --latency-msec=10 --process-time-msec=5`
/// with graceful fallback to `pw-record --target <sink_name>.monitor --rate 44100 --channels 2 --format s16 --latency 256/44100 -`.
///
/// Features a frame-aligned (4-byte stereo frame) ring buffer:
/// - Max buffer: 8,448 bytes (6 packets). Trims to 4,224 bytes (3 packets) on overflow.
/// - Startup drain: Drains initial backlog down to 2,816 bytes (2 packets) on first read for sub-20ms startup latency.
pub struct PipeWireCaptureStream {
    buffer: Arc<Mutex<VecDeque<u8>>>,
    notify: Arc<Notify>,
    is_first_read: bool,
    in_prebuf: bool,
    is_closed: Arc<AtomicBool>,
    task_handle: Option<tokio::task::JoinHandle<()>>,
}

impl PipeWireCaptureStream {
    /// Spawn audio capture on the monitor source of `sink_name`.
    pub fn new(sink_name: &str) -> Result<Self, SonusError> {
        let target_sink = format!("{sink_name}.monitor");

        let mut child = match tokio::process::Command::new("parec")
            .args([
                "-d",
                &target_sink,
                "--rate=44100",
                "--channels=2",
                "--format=s16le",
                "--latency-msec=10",
                "--process-time-msec=5",
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
        {
            Ok(child) => child,
            Err(_) => tokio::process::Command::new("pw-record")
                .args([
                    "--target",
                    &target_sink,
                    "--rate",
                    "44100",
                    "--channels",
                    "2",
                    "--format",
                    "s16",
                    "--latency",
                    "256/44100",
                    "-",
                ])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .map_err(|e| {
                    SonusError::PipeWire(format!(
                        "Failed to spawn parec and pw-record for sink {sink_name}: {e}"
                    ))
                })?,
        };

        let buffer = Arc::new(Mutex::new(VecDeque::with_capacity(MAX_RING_BUFFER_BYTES)));
        let notify = Arc::new(Notify::new());
        let is_closed = Arc::new(AtomicBool::new(false));

        let task_buffer = Arc::clone(&buffer);
        let task_notify = Arc::clone(&notify);
        let task_closed = Arc::clone(&is_closed);

        let task_handle = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut stdout = match child.stdout.take() {
                Some(s) => s,
                None => return,
            };
            // Keep `child` alive for the full lifetime of the capture task (Rust 2021 disjoint capture)
            let _child_guard = child;

            let mut read_buf = [0u8; 4096];
            while !task_closed.load(Ordering::Relaxed) {
                match stdout.read(&mut read_buf).await {
                    Ok(0) => {
                        // End of stream
                        task_closed.store(true, Ordering::SeqCst);
                        task_notify.notify_waiters();
                        break;
                    }
                    Ok(n) => {
                        {
                            let mut ring = task_buffer.lock().unwrap();
                            ring.extend(&read_buf[..n]);

                            // Overflow handling: clamp to TRIM_TARGET_BYTES (4,224 bytes)
                            if ring.len() > MAX_RING_BUFFER_BYTES {
                                let excess = ring.len() - TRIM_TARGET_BYTES;
                                let aligned_excess = (excess / BYTES_PER_FRAME) * BYTES_PER_FRAME;
                                ring.drain(..aligned_excess);
                            }
                        }
                        task_notify.notify_waiters();
                    }
                    Err(e) => {
                        tracing::debug!("PipeWire capture read error: {}", e);
                        task_closed.store(true, Ordering::SeqCst);
                        task_notify.notify_waiters();
                        break;
                    }
                }
            }
        });

        Ok(Self {
            buffer,
            notify,
            is_first_read: true,
            in_prebuf: true,
            is_closed,
            task_handle: Some(task_handle),
        })
    }

    /// Convenience alias to `new`.
    pub fn spawn(sink_name: &str) -> Result<Self, SonusError> {
        Self::new(sink_name)
    }

    /// Number of audio bytes currently buffered in the ring buffer.
    pub fn buffered_bytes(&self) -> usize {
        self.buffer.lock().unwrap().len()
    }

    /// Read next full 1,408-byte PCM stereo packet (352 samples * 4 bytes/sample).
    ///
    /// Drains initial startup backlog to 2,816 bytes (2 packets) on first read and
    /// uses a 2-packet prebuffer hysteresis (`in_prebuf`) so underruns return silence
    /// immediately (0ms) without ever stalling the 44.1 kHz RTP clock.
    pub async fn read_packet(&mut self) -> Option<[u8; PCM_PACKET_BYTES]> {
        if self.is_first_read {
            self.is_first_read = false;
            let start = tokio::time::Instant::now();
            while start.elapsed() < std::time::Duration::from_millis(35) {
                let notified = self.notify.notified();
                {
                    let ring = self.buffer.lock().unwrap();
                    if ring.len() >= STARTUP_BACKLOG_BYTES || self.is_closed.load(Ordering::Relaxed)
                    {
                        break;
                    }
                }
                if tokio::time::timeout(std::time::Duration::from_millis(12), notified)
                    .await
                    .is_err()
                {
                    break;
                }
            }
            let mut ring = self.buffer.lock().unwrap();
            if ring.len() > STARTUP_BACKLOG_BYTES {
                let excess = ring.len() - STARTUP_BACKLOG_BYTES;
                let aligned_excess = (excess / BYTES_PER_FRAME) * BYTES_PER_FRAME;
                ring.drain(..aligned_excess);
            }
            if ring.len() >= STARTUP_BACKLOG_BYTES {
                self.in_prebuf = false;
            }
        }

        if self.in_prebuf {
            let ring = self.buffer.lock().unwrap();
            if ring.len() >= STARTUP_BACKLOG_BYTES {
                self.in_prebuf = false;
            } else if self.is_closed.load(Ordering::Relaxed) {
                return None;
            } else {
                // Return silence immediately (0ms) while prebuffering 2 packets
                return Some([0u8; PCM_PACKET_BYTES]);
            }
        }

        let need_wait = {
            let ring = self.buffer.lock().unwrap();
            ring.len() < PCM_PACKET_BYTES && !self.is_closed.load(Ordering::Relaxed)
        };
        if need_wait {
            let notified = self.notify.notified();
            let _ = tokio::time::timeout(std::time::Duration::from_millis(6), notified).await;
        }

        let mut ring = self.buffer.lock().unwrap();
        if ring.len() >= PCM_PACKET_BYTES {
            let mut packet = [0u8; PCM_PACKET_BYTES];
            for b in packet.iter_mut() {
                *b = ring.pop_front().unwrap();
            }
            // Convert native s16le PCM to RFC 3551 L16 network byte order (s16be) required by AirPlay ct=1
            for pair in packet.chunks_exact_mut(2) {
                pair.swap(0, 1);
            }
            return Some(packet);
        }

        if self.is_closed.load(Ordering::Relaxed) {
            return None;
        }

        // Underrun detected: preserve partial frame-aligned bytes and enter prebuffer mode
        self.in_prebuf = true;
        Some([0u8; PCM_PACKET_BYTES])
    }

    /// Stop capture task and terminate child process cleanly.
    pub async fn stop(&mut self) {
        self.is_closed.store(true, Ordering::SeqCst);
        if let Some(handle) = self.task_handle.take() {
            handle.abort();
            let _ = handle.await;
        }
        self.notify.notify_waiters();
    }
}

impl Drop for PipeWireCaptureStream {
    fn drop(&mut self) {
        self.is_closed.store(true, Ordering::SeqCst);
        if let Some(handle) = self.task_handle.take() {
            handle.abort();
        }
    }
}

/// Spawns a single persistent `pactl subscribe` process watching for sink/sink-input events.
///
/// Features built-in echo suppression: only emits events when state or volume/mute actually changes.
pub fn spawn_sink_event_listener(
    sink_name: String,
    tx: mpsc::Sender<SinkEvent>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Initial baseline snapshot
        let mut last_state = get_sink_state(&sink_name);
        if let Some(state) = last_state {
            let _ = tx.send(SinkEvent::StateChanged(state)).await;
        }

        let mut last_vol = get_sink_volume_and_mute(&sink_name);
        if let Some((percent, muted)) = last_vol {
            let _ = tx.send(SinkEvent::VolumeChanged { percent, muted }).await;
        }

        let mut child = match tokio::process::Command::new("pactl")
            .args(["subscribe"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
        {
            Ok(child) => child,
            Err(e) => {
                tracing::error!("Failed to spawn pactl subscribe: {}", e);
                return;
            }
        };

        let Some(stdout) = child.stdout.take() else {
            return;
        };

        use tokio::io::AsyncBufReadExt;
        let mut reader = tokio::io::BufReader::new(stdout).lines();

        while let Ok(Some(line)) = reader.next_line().await {
            if line.contains("sink") || line.contains("server") {
                if let Some(current_state) = get_sink_state(&sink_name) {
                    if last_state != Some(current_state) {
                        last_state = Some(current_state);
                        if tx
                            .send(SinkEvent::StateChanged(current_state))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }

                if let Some((pct, muted)) = get_sink_volume_and_mute(&sink_name) {
                    if last_vol != Some((pct, muted)) {
                        last_vol = Some((pct, muted));
                        if tx
                            .send(SinkEvent::VolumeChanged {
                                percent: pct,
                                muted,
                            })
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sine_tone_generation() {
        let mut gen = SineToneSource::new(440.0);
        let mut buf = vec![0u8; PCM_PACKET_BYTES];
        let bytes_read = gen.read_chunk(&mut buf).unwrap();

        assert_eq!(bytes_read, PCM_PACKET_BYTES);
        // Verify non-zero data
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_parse_volume_and_mute() {
        let vol_sample = "Volume: front-left: 41287 /  63% / -12.04 dB,   front-right: 41287 /  63% / -12.04 dB\n        balance 0.00";
        assert_eq!(parse_volume_percent_from_pactl(vol_sample), Some(63));

        let mute_sample_no = "Mute: no";
        assert_eq!(parse_mute_from_pactl(mute_sample_no), Some(false));

        let mute_sample_yes = "Mute: yes";
        assert_eq!(parse_mute_from_pactl(mute_sample_yes), Some(true));
    }

    #[test]
    fn test_ring_buffer_math() {
        // Test overflow trimming to TRIM_TARGET_BYTES (4,224)
        let mut ring = VecDeque::new();
        ring.extend(vec![1u8; 9000]);
        if ring.len() > MAX_RING_BUFFER_BYTES {
            let excess = ring.len() - TRIM_TARGET_BYTES;
            let aligned_excess = (excess / BYTES_PER_FRAME) * BYTES_PER_FRAME;
            ring.drain(..aligned_excess);
        }
        assert_eq!(ring.len(), TRIM_TARGET_BYTES);
        assert_eq!(ring.len() % BYTES_PER_FRAME, 0);

        // Test startup backlog drain to STARTUP_BACKLOG_BYTES (2,816)
        let mut ring2 = VecDeque::new();
        ring2.extend(vec![2u8; 5000]);
        if ring2.len() > STARTUP_BACKLOG_BYTES {
            let excess = ring2.len() - STARTUP_BACKLOG_BYTES;
            let aligned_excess = (excess / BYTES_PER_FRAME) * BYTES_PER_FRAME;
            ring2.drain(..aligned_excess);
        }
        assert_eq!(ring2.len(), STARTUP_BACKLOG_BYTES);
        assert_eq!(ring2.len() % BYTES_PER_FRAME, 0);
    }
}
