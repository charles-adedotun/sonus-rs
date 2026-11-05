//! CLI entry point and real-time AirPlay 2 / PipeWire / MPRIS orchestrator for `sonus-rs`.
#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use tokio::net::UdpSocket;
use tokio::signal;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use sonus_rs::config::{SonusConfig, PCM_PACKET_BYTES, SAMPLES_PER_FRAME, SAMPLE_RATE};
use sonus_rs::dacp::{DacpCommand, DacpServer, PlaybackState};
use sonus_rs::discovery::{discover_homepods, run_environment_doctor, MdnsDacpAdvertiser};
use sonus_rs::error::SonusError;
use sonus_rs::mpris::{
    dispatch_mpris_command, dispatch_mpris_seek_seconds, get_active_player_metadata,
};
use sonus_rs::pacer::{ntp2ts, ntp_now, ControlClient, Packetizer, SilencePacer, TimingServer};
use sonus_rs::pipewire::{
    adjust_sink_volume_delta, configure_pipewire_sink, get_sink_volume_and_mute, is_sink_running,
    set_sink_volume_percent, spawn_sink_event_listener, toggle_sink_mute, AudioSource,
    PipeWireCaptureStream, SineToneSource, SinkEvent, SinkState,
};
use sonus_rs::raop::{
    dbfs_to_pct, pct_to_dbfs, AirPlayAudioCipher, EventChannelClient, HomePodEvent, RtspClient,
};

#[derive(Parser, Debug)]
#[command(name = "sonus")]
#[command(author = "Charles Adedotun <charles.adedotun8@gmail.com>")]
#[command(version = "0.1.0")]
#[command(
    about = "Sub-250ms Safe Rust PipeWire to Apple AirPlay 2 / RAOP audio engine & DACP touch daemon"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run production background daemon (PipeWire sink monitor + DACP/EventChannel touch server + AirPlay 2 pacer)
    #[command(visible_alias = "run")]
    Daemon {
        /// Optional path to configuration file (e.g. ~/.config/sonus/profile.json)
        #[arg(short, long)]
        config: Option<String>,
    },

    /// Discover AirPlay 2 / HomePod devices on the local network via mDNS
    Discover {
        /// Scan timeout in seconds
        #[arg(short, long, default_value_t = 3)]
        timeout: u64,
    },

    /// Run environmental diagnostics (PipeWire sink, 250ms ProcessLatency, MPRIS2, DACP port, HomePod reachability)
    Doctor {
        /// Optional path to configuration file
        #[arg(short, long)]
        config: Option<String>,
    },

    /// Display current PipeWire sink state, volume, and active MPRIS media player status
    Status {
        /// Optional path to configuration file
        #[arg(short, long)]
        config: Option<String>,
    },

    /// Stream a synthetic stereo sine tone to HomePod using full HAP transient pairing to measure presentation latency
    StreamTone {
        /// Target HomePod IP address
        #[arg(short = 'H', long, default_value = "192.168.1.100")]
        host: String,

        /// Target HomePod RTSP port
        #[arg(short, long, default_value_t = 7000)]
        port: u16,

        /// Sine tone frequency in Hertz
        #[arg(short, long, default_value_t = 440.0)]
        freq: f32,

        /// Playback duration in seconds (0 = infinite)
        #[arg(short, long, default_value_t = 5)]
        duration: u64,
    },

    /// Probe HomePod mini RTSP endpoint, verify `/info`, and test HAP transient SRP-6a handshake
    Probe {
        /// Target HomePod IP address
        #[arg(short = 'H', long, default_value = "192.168.1.100")]
        host: String,

        /// Target HomePod RTSP port
        #[arg(short, long, default_value_t = 7000)]
        port: u16,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,sonus=info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Daemon { config } => {
            let conf = load_config(config)?;
            run_daemon(conf).await?;
        }

        Commands::Discover { timeout } => {
            run_discover(timeout).await?;
        }

        Commands::Doctor { config } => {
            let conf = load_config(config)?;
            run_doctor(&conf).await;
        }

        Commands::Status { config } => {
            let conf = load_config(config)?;
            run_status(&conf).await;
        }

        Commands::StreamTone {
            host,
            port,
            freq,
            duration,
        } => {
            run_stream_tone(&host, port, freq, duration).await?;
        }

        Commands::Probe { host, port } => {
            run_probe(&host, port).await?;
        }
    }

    Ok(())
}

fn load_config(path: Option<String>) -> Result<SonusConfig, SonusError> {
    if let Some(p) = path {
        SonusConfig::load_file(p)
    } else {
        Ok(SonusConfig::from_env())
    }
}

/// Discover HomePod / AirPlay 2 receivers on the LAN.
async fn run_discover(timeout_secs: u64) -> Result<(), SonusError> {
    println!("Scanning local network for AirPlay 2 / HomePod devices ({timeout_secs}s)...");
    let devices = discover_homepods(timeout_secs).await?;
    if devices.is_empty() {
        println!("No AirPlay 2 devices found on the local network.");
        return Ok(());
    }

    println!(
        "{:<22} {:<16} {:<6} {:<20} {:<18} {:<10}",
        "NAME", "IP", "PORT", "MODEL", "DEVICE ID", "OS"
    );
    println!("{}", "-".repeat(96));
    for d in devices {
        println!(
            "{:<22} {:<16} {:<6} {:<20} {:<18} {:<10}",
            d.name, d.ip, d.port, d.model, d.device_id, d.os_version
        );
    }
    Ok(())
}

/// Run environmental doctor checks.
async fn run_doctor(conf: &SonusConfig) {
    println!(
        "Running sonus-rs Environment Doctor (Sink: '{}', Target: {}:{})...\n",
        conf.sink_name, conf.homepod_ip, conf.homepod_port
    );
    let checks = run_environment_doctor(conf).await;
    let mut all_passed = true;
    for check in &checks {
        let badge = if check.passed { "[PASS]" } else { "[WARN]" };
        if !check.passed {
            all_passed = false;
        }
        println!("  {} {:<28} — {}", badge, check.name, check.detail);
    }
    println!();
    if all_passed {
        println!("All diagnostic checks passed! Ready to stream.");
    } else {
        println!(
            "Some checks reported warnings. Run './install.sh' to configure PipeWire and systemd."
        );
    }
}

/// Display live PipeWire sink and MPRIS status.
async fn run_status(conf: &SonusConfig) {
    let running = is_sink_running(&conf.sink_name);
    let (vol, muted) = get_sink_volume_and_mute(&conf.sink_name).unwrap_or((0, false));
    let meta = get_active_player_metadata();

    println!("=== sonus-rs Live Status ===");
    println!(
        "  Target HomePod : {} ({}:{})",
        conf.homepod_name, conf.homepod_ip, conf.homepod_port
    );
    println!(
        "  PipeWire Sink  : '{}' ({})",
        conf.sink_name,
        if running { "RUNNING" } else { "IDLE" }
    );
    println!(
        "  Volume / Mute  : {}% ({:.1} dBFS){}",
        vol,
        if muted {
            -144.0
        } else {
            pct_to_dbfs(vol as f32)
        },
        if muted { " [MUTED]" } else { "" }
    );
    println!(
        "  Presentation   : {} frames ({:.1} ms)",
        conf.latency_frames,
        conf.presentation_latency_ms()
    );
    println!(
        "  MPRIS Player   : {}",
        if meta.playing {
            "Playing"
        } else {
            "Paused / Idle"
        }
    );
    println!("  Track Title    : {}", meta.title);
    println!("  Track Artist   : {}", meta.artist);
    println!("  Track Album    : {}", meta.album);
}

/// Run production daemon orchestrating DACP server, mDNS advertisement, PipeWire monitor, and AirPlay 2 streaming loop.
async fn run_daemon(conf: SonusConfig) -> Result<(), SonusError> {
    info!(
        "Starting sonus-rs daemon for HomePod '{}' ({}:{})",
        conf.homepod_name, conf.homepod_ip, conf.homepod_port
    );
    info!(
        "Presentation latency clamped to: {} frames ({:.1}ms)",
        conf.latency_frames,
        conf.presentation_latency_ms()
    );

    // 1. Configure PipeWire virtual sink properties (250ms ProcessLatency for A/V lip-sync + resample.quality=10)
    let latency_ns = ((conf.latency_frames as u64) * 1_000_000_000) / (SAMPLE_RATE as u64);
    if let Err(e) = configure_pipewire_sink(&conf.sink_name, conf.latency_frames, latency_ns) {
        warn!("Could not apply initial PipeWire sink properties: {}", e);
    } else {
        info!(
            "Configured PipeWire sink '{}' with ProcessLatency={}ns ({:.1}ms) and resample.quality=10",
            conf.sink_name,
            latency_ns,
            conf.presentation_latency_ms()
        );
    }

    // 2. Advertise _dacp._tcp.local. on mDNS and start DACP HTTP server on port 3689
    let _mdns_adv = MdnsDacpAdvertiser::spawn(&conf.dacp_id, conf.dacp_port, &conf.homepod_ip)
        .await
        .ok();

    let mut dacp = DacpServer::new(conf.dacp_port);
    let playback_state_handle = dacp.playback_state_handle();
    let mut dacp_rx = dacp
        .take_command_receiver()
        .expect("DACP command receiver already taken");

    tokio::spawn(async move {
        if let Err(e) = dacp.run().await {
            error!("DACP server terminated with error: {}", e);
        }
    });

    // Channel for pushing hardware volume updates (dBFS) to the active RTSP session
    let (hw_vol_tx, mut hw_vol_rx) = mpsc::channel::<f32>(32);

    // Shared timestamp (epoch millis) until which Linux volume change events are suppressed (echo suppression)
    let suppress_echo_until_ms = Arc::new(std::sync::atomic::AtomicU64::new(0));

    // 3. Handle incoming DACP HTTP commands from HomePod
    let sink_for_dacp = conf.sink_name.clone();
    let hw_vol_tx_dacp = hw_vol_tx.clone();
    let suppress_dacp = Arc::clone(&suppress_echo_until_ms);
    tokio::spawn(async move {
        while let Some(cmd) = dacp_rx.recv().await {
            match cmd {
                DacpCommand::PlayPause => {
                    info!("[DACP] PlayPause triggered -> dispatching to MPRIS");
                    tokio::task::spawn_blocking(|| {
                        dispatch_mpris_command("PlayPause");
                    });
                }
                DacpCommand::Play => {
                    info!("[DACP] Play triggered -> dispatching to MPRIS");
                    tokio::task::spawn_blocking(|| {
                        dispatch_mpris_command("Play");
                    });
                }
                DacpCommand::Pause => {
                    info!("[DACP] Pause triggered -> dispatching to MPRIS");
                    tokio::task::spawn_blocking(|| {
                        dispatch_mpris_command("Pause");
                    });
                }
                DacpCommand::Stop => {
                    info!("[DACP] Stop triggered -> dispatching to MPRIS");
                    tokio::task::spawn_blocking(|| {
                        dispatch_mpris_command("Stop");
                    });
                }
                DacpCommand::Next => {
                    info!("[DACP] Next track triggered -> dispatching to MPRIS");
                    tokio::task::spawn_blocking(|| {
                        dispatch_mpris_command("Next");
                    });
                }
                DacpCommand::Previous => {
                    info!("[DACP] Previous track triggered -> dispatching to MPRIS");
                    tokio::task::spawn_blocking(|| {
                        dispatch_mpris_command("Previous");
                    });
                }
                DacpCommand::VolumeUp => {
                    let s = sink_for_dacp.clone();
                    let tx = hw_vol_tx_dacp.clone();
                    tokio::task::spawn_blocking(move || {
                        adjust_sink_volume_delta(&s, "+5%");
                        if let Some((pct, muted)) = get_sink_volume_and_mute(&s) {
                            let dbfs = if muted {
                                -144.0
                            } else {
                                pct_to_dbfs(pct as f32)
                            };
                            let _ = tx.blocking_send(dbfs);
                        }
                    });
                }
                DacpCommand::VolumeDown => {
                    let s = sink_for_dacp.clone();
                    let tx = hw_vol_tx_dacp.clone();
                    tokio::task::spawn_blocking(move || {
                        adjust_sink_volume_delta(&s, "-5%");
                        if let Some((pct, muted)) = get_sink_volume_and_mute(&s) {
                            let dbfs = if muted {
                                -144.0
                            } else {
                                pct_to_dbfs(pct as f32)
                            };
                            let _ = tx.blocking_send(dbfs);
                        }
                    });
                }
                DacpCommand::MuteToggle => {
                    let s = sink_for_dacp.clone();
                    let tx = hw_vol_tx_dacp.clone();
                    tokio::task::spawn_blocking(move || {
                        toggle_sink_mute(&s);
                        if let Some((pct, muted)) = get_sink_volume_and_mute(&s) {
                            let dbfs = if muted {
                                -144.0
                            } else {
                                pct_to_dbfs(pct as f32)
                            };
                            let _ = tx.blocking_send(dbfs);
                        }
                    });
                }
                DacpCommand::SetVolume(val) => {
                    let pct = if val <= 0.0 {
                        dbfs_to_pct(val).round() as u8
                    } else if val <= 1.0 {
                        (val * 100.0).round() as u8
                    } else {
                        val.clamp(0.0, 100.0).round() as u8
                    };
                    suppress_dacp.store(now_epoch_ms() + 600, Ordering::Relaxed);
                    let s = sink_for_dacp.clone();
                    tokio::task::spawn_blocking(move || {
                        set_sink_volume_percent(&s, pct);
                    });
                }
            }
        }
    });

    // 4. Spawn persistent zero-polling PipeWire sink event listener (`pactl subscribe`)
    let (sink_ev_tx, mut sink_ev_rx) = mpsc::channel::<SinkEvent>(64);
    let _sink_listener = spawn_sink_event_listener(conf.sink_name.clone(), sink_ev_tx);

    let sink_running_flag = Arc::new(AtomicBool::new(is_sink_running(&conf.sink_name)));
    let sink_running_notify = Arc::new(tokio::sync::Notify::new());

    let running_flag_clone = Arc::clone(&sink_running_flag);
    let notify_clone = Arc::clone(&sink_running_notify);
    let pb_state_clone = Arc::clone(&playback_state_handle);
    let suppress_sink = Arc::clone(&suppress_echo_until_ms);
    let hw_vol_tx_sink = hw_vol_tx.clone();

    tokio::spawn(async move {
        while let Some(ev) = sink_ev_rx.recv().await {
            match ev {
                SinkEvent::StateChanged(state) => {
                    let is_run = state == SinkState::Running;
                    running_flag_clone.store(is_run, Ordering::SeqCst);
                    pb_state_clone.store(
                        if is_run {
                            PlaybackState::Playing as u8
                        } else {
                            PlaybackState::Paused as u8
                        },
                        Ordering::Relaxed,
                    );
                    notify_clone.notify_waiters();
                }
                SinkEvent::VolumeChanged { percent, muted } => {
                    if now_epoch_ms() > suppress_sink.load(Ordering::Relaxed) {
                        let dbfs = if muted {
                            -144.0
                        } else {
                            pct_to_dbfs(percent as f32)
                        };
                        info!(
                            "Linux sink volume changed to {}% (muted={}) -> syncing {:.1} dBFS to HomePod DSP",
                            percent, muted, dbfs
                        );
                        let _ = hw_vol_tx_sink.send(dbfs).await;
                    }
                }
            }
        }
    });

    info!(
        "sonus-rs daemon initialized. Monitoring PipeWire sink '{}'...",
        conf.sink_name
    );

    // 5. Main AirPlay 2 session lifecycle loop
    loop {
        if !sink_running_flag.load(Ordering::SeqCst) {
            tokio::select! {
                _ = sink_running_notify.notified() => {},
                _ = tokio::time::sleep(Duration::from_millis(500)) => {
                    let live_run = tokio::task::spawn_blocking({
                        let s = conf.sink_name.clone();
                        move || is_sink_running(&s)
                    }).await.unwrap_or(false);
                    if live_run {
                        sink_running_flag.store(true, Ordering::SeqCst);
                    }
                }
                _ = signal::ctrl_c() => {
                    info!("Received shutdown signal. Stopping sonus-rs daemon...");
                    break;
                }
            }
        }

        if !sink_running_flag.load(Ordering::SeqCst) {
            continue;
        }

        // Drain any stale volume updates before starting fresh session
        while hw_vol_rx.try_recv().is_ok() {}

        info!(
            "Active audio detected on '{}'! Connecting to HomePod ({}:{})...",
            conf.sink_name, conf.homepod_ip, conf.homepod_port
        );

        let session_res = run_active_airplay_session(
            &conf,
            Arc::clone(&sink_running_flag),
            &mut hw_vol_rx,
            Arc::clone(&suppress_echo_until_ms),
        )
        .await;

        if let Err(e) = session_res {
            warn!("AirPlay 2 streaming session ended: {}", e);
            tokio::time::sleep(Duration::from_millis(1000)).await;
        } else {
            info!("AirPlay 2 session closed cleanly; returning to idle monitor.");
        }
    }

    Ok(())
}

/// Execute an active encrypted AirPlay 2 streaming session with EventChannel, NTP timing, and SpaDLL pacing.
async fn run_active_airplay_session(
    conf: &SonusConfig,
    sink_running: Arc<AtomicBool>,
    hw_vol_rx: &mut mpsc::Receiver<f32>,
    suppress_echo_until_ms: Arc<std::sync::atomic::AtomicU64>,
) -> Result<(), SonusError> {
    let latency_ns = ((conf.latency_frames as u64) * 1_000_000_000) / (SAMPLE_RATE as u64);
    let _ = configure_pipewire_sink(&conf.sink_name, conf.latency_frames, latency_ns);

    // 1. Connect TCP RTSP & run HAP Transient Pairing (SRP-6a 3072-bit + ChaCha20-Poly1305 session framing)
    let mut rtsp = RtspClient::connect(&conf.homepod_ip, conf.homepod_port).await?;
    let _ = rtsp.info().await;
    let (audio_shk, event_read_key, event_write_key) = rtsp.pair_verify_transient().await?;

    // 2. Bind UDP TimingServer & ControlClient
    let timing_server = TimingServer::bind().await?;
    let control_client = ControlClient::bind(&conf.homepod_ip, 0).await?;

    // 3. Stage 1 Base SETUP (negotiates timingPort and HomePod eventPort)
    let event_port = rtsp.setup_base(timing_server.local_port()).await?;
    info!(
        "Stage 1 Base SETUP complete: timingPort={}, eventPort={}",
        timing_server.local_port(),
        event_port
    );

    // 4. Connect encrypted HAP EventChannel to receive HomePod touch events (Play/Pause/Next & dvlc Volume)
    let (hp_ev_tx, mut hp_ev_rx) = mpsc::channel::<HomePodEvent>(32);
    let _event_channel_handle = EventChannelClient::connect(
        &conf.homepod_ip,
        event_port,
        event_read_key,
        event_write_key,
        hp_ev_tx,
    )
    .await?;

    // 5. Stage 2 Audio Stream SETUP (clamped 250ms = 11,025 frames)
    let stream_setup = rtsp
        .setup_stream(control_client.local_port(), &audio_shk)
        .await?;
    control_client.set_server_control_port(stream_setup.server_control_port);
    info!(
        "Stage 2 Stream SETUP complete: dataPort={}, controlPort={}",
        stream_setup.server_data_port, stream_setup.server_control_port
    );

    // 6. Start PipeWire capture before RECORD/FLUSH so prebuffer is ready immediately
    let mut capture = PipeWireCaptureStream::new(&conf.sink_name)?;

    // 7. Push current MPRIS track metadata (DMAP mlit), then RECORD, FLUSH & sync volume
    let initial_rtptime = conf.latency_frames;
    let initial_meta = tokio::task::spawn_blocking(get_active_player_metadata)
        .await
        .unwrap_or_else(|_| sonus_rs::mpris::TrackMetadata {
            title: "Linux System Audio".to_string(),
            artist: "Homelab".to_string(),
            album: "PipeWire Stream".to_string(),
            playing: true,
        });
    let _ = rtsp
        .set_metadata(
            0,
            initial_rtptime,
            &initial_meta.title,
            &initial_meta.artist,
            &initial_meta.album,
        )
        .await;

    rtsp.record().await?;
    let _ = rtsp.flush(0, initial_rtptime).await;

    // Sync initial desktop volume to HomePod hardware DSP
    if let Some((pct, muted)) = get_sink_volume_and_mute(&conf.sink_name) {
        let dbfs = if muted {
            -144.0
        } else {
            pct_to_dbfs(pct as f32)
        };
        let _ = rtsp.set_volume(dbfs).await;
    }

    // Wrap RtspClient in Arc<Mutex> for concurrent feedback, volume, and metadata updates
    let rtsp = Arc::new(Mutex::new(rtsp));

    // Spawn EventChannel event consumer (handles physical HomePod + / - dvlc and Play/Pause taps!)
    let sink_for_ev = conf.sink_name.clone();
    let suppress_ev = Arc::clone(&suppress_echo_until_ms);
    let rtsp_for_ev = Arc::clone(&rtsp);
    let ev_consumer_handle = tokio::spawn(async move {
        while let Some(ev) = hp_ev_rx.recv().await {
            match ev {
                HomePodEvent::Play => {
                    info!("[HomePod Touch] Play -> MPRIS Play");
                    tokio::task::spawn_blocking(|| {
                        dispatch_mpris_command("Play");
                    });
                    let meta = tokio::task::spawn_blocking(get_active_player_metadata)
                        .await
                        .ok();
                    if let Some(m) = meta {
                        let mut r = rtsp_for_ev.lock().await;
                        let _ = r
                            .send_mr_now_playing(&m.title, &m.artist, &m.album, 1.0)
                            .await;
                    }
                }
                HomePodEvent::Pause => {
                    info!("[HomePod Touch] Pause -> MPRIS Pause");
                    tokio::task::spawn_blocking(|| {
                        dispatch_mpris_command("Pause");
                    });
                    let mut r = rtsp_for_ev.lock().await;
                    let _ = r
                        .send_mr_now_playing("Linux System Audio", "Homelab", "Paused", 0.0)
                        .await;
                }
                HomePodEvent::PlayPause => {
                    info!("[HomePod Touch] PlayPause -> MPRIS PlayPause");
                    tokio::task::spawn_blocking(|| {
                        dispatch_mpris_command("PlayPause");
                    });
                }
                HomePodEvent::Stop => {
                    info!("[HomePod Touch] Stop -> MPRIS Stop");
                    tokio::task::spawn_blocking(|| {
                        dispatch_mpris_command("Stop");
                    });
                }
                HomePodEvent::Next => {
                    info!("[HomePod Touch] Double-Tap Next -> MPRIS Next");
                    tokio::task::spawn_blocking(|| {
                        dispatch_mpris_command("Next");
                    });
                }
                HomePodEvent::Previous => {
                    info!("[HomePod Touch] Triple-Tap Previous -> MPRIS Previous");
                    tokio::task::spawn_blocking(|| {
                        dispatch_mpris_command("Previous");
                    });
                }
                HomePodEvent::SeekTo(pos) => {
                    info!("[HomePod Touch] SeekTo {:.1}s", pos);
                    tokio::task::spawn_blocking(move || {
                        dispatch_mpris_seek_seconds(pos);
                    });
                }
                HomePodEvent::VolumePercent(pct) => {
                    info!(
                        "[HomePod Touch] Volume button ('dvlc') -> {}% (syncing to PipeWire slider)",
                        pct
                    );
                    suppress_ev.store(now_epoch_ms() + 600, Ordering::Relaxed);
                    let s = sink_for_ev.clone();
                    tokio::task::spawn_blocking(move || {
                        set_sink_volume_percent(&s, pct);
                    });
                }
                HomePodEvent::InitialVolumeDbfs(dbfs) => {
                    let pct = dbfs_to_pct(dbfs).round() as u8;
                    debug!("HomePod reported initialVolume={:.2} dBFS ({}%)", dbfs, pct);
                }
            }
        }
    });

    // 9. Bind UDP audio socket & re-anchor RTP clock to live NTP time right before first packet
    let audio_socket = UdpSocket::bind("0.0.0.0:0").await?;
    let target_addr: SocketAddr = format!("{}:{}", conf.homepod_ip, stream_setup.server_data_port)
        .parse()
        .map_err(|e| SonusError::Config(format!("Invalid target socket address: {e}")))?;

    let session_ssrc = {
        let r = rtsp.lock().await;
        r.session_id() as u32
    };
    let mut packetizer = Packetizer::new(session_ssrc);
    packetizer.reanchor_timestamp(initial_rtptime);

    // Emit immediate 0x90 SyncPacket to lock HomePod's 250ms playout window
    control_client
        .send_initial_sync(initial_rtptime, conf.latency_frames)
        .await?;

    let mut cipher = AirPlayAudioCipher::new(&audio_shk);
    let mut silence_pacer = SilencePacer::new(conf.idle_timeout_secs);

    info!(
        "AirPlay 2 RAOP stream active ({} -> {}). Streaming real-time audio...",
        conf.sink_name, target_addr
    );

    let mut last_feedback = Instant::now();
    let mut was_idle = false;
    let stream_start = Instant::now();
    let mut total_frames_sent: u64 = 0;
    const MAX_PACKETS_COMPENSATE: usize = 4;

    loop {
        // Handle pending desktop volume changes -> push SET_PARAMETER volume to HomePod DSP
        while let Ok(dbfs) = hw_vol_rx.try_recv() {
            let rtsp_clone = Arc::clone(&rtsp);
            tokio::spawn(async move {
                let mut r = rtsp_clone.lock().await;
                let _ = r.set_volume(dbfs).await;
            });
        }

        // Send periodic RTSP POST /feedback every 2 seconds to keep audioOS watchdog happy
        if last_feedback.elapsed() >= Duration::from_secs(2) {
            last_feedback = Instant::now();
            let rtsp_clone = Arc::clone(&rtsp);
            tokio::spawn(async move {
                let mut r = rtsp_clone.lock().await;
                let _ = r.feedback().await;
            });
        }

        let is_active = sink_running.load(Ordering::Relaxed);
        if is_active && was_idle {
            was_idle = false;
            silence_pacer.reset_active();
            info!("Sink resumed active playback; continuing AirPlay 2 stream seamlessly.");
            let rtsp_clone = Arc::clone(&rtsp);
            tokio::spawn(async move {
                if let Ok(m) = tokio::task::spawn_blocking(get_active_player_metadata).await {
                    let mut r = rtsp_clone.lock().await;
                    let _ = r
                        .send_mr_now_playing(&m.title, &m.artist, &m.album, 1.0)
                        .await;
                }
            });
        } else if !is_active && !was_idle {
            was_idle = true;
            info!(
                "Sink state became idle/paused. Holding AirPlay 2 session hot for {}s...",
                conf.idle_timeout_secs
            );
            let rtsp_clone = Arc::clone(&rtsp);
            tokio::spawn(async move {
                let mut r = rtsp_clone.lock().await;
                let _ = r
                    .send_mr_now_playing("Linux System Audio", "Homelab", "Paused", 0.0)
                    .await;
            });
        }

        // Determine how many packets to send this tick (1 normal + up to 4 catch-up if behind)
        let expected_frames = (stream_start.elapsed().as_secs_f64() * (SAMPLE_RATE as f64)) as u64;
        let frames_behind = expected_frames.saturating_sub(total_frames_sent);
        let packets_to_send =
            1 + ((frames_behind / (SAMPLES_PER_FRAME as u64)) as usize).min(MAX_PACKETS_COMPENSATE);

        let mut session_ended = false;
        for _ in 0..packets_to_send {
            let rtp_pkt = if is_active {
                match capture.read_packet().await {
                    Some(pcm_frame) => packetizer.packetize(&pcm_frame)?,
                    None => {
                        session_ended = true;
                        break;
                    }
                }
            } else {
                match silence_pacer.generate_silence_packet(&mut packetizer)? {
                    Some(pkt) => pkt,
                    None => {
                        info!(
                            "Sink idle for {}s. Tearing down AirPlay 2 session to save power.",
                            conf.idle_timeout_secs
                        );
                        session_ended = true;
                        break;
                    }
                }
            };

            let seq = rtp_pkt.sequence_number();
            let encrypted_payload =
                cipher.encrypt_audio_payload(rtp_pkt.header(), rtp_pkt.payload())?;

            let mut wire_pkt = Vec::with_capacity(12 + encrypted_payload.len());
            wire_pkt.extend_from_slice(rtp_pkt.header());
            wire_pkt.extend_from_slice(&encrypted_payload);

            let _ = audio_socket.send_to(&wire_pkt, target_addr).await;
            control_client.store_packet(seq, wire_pkt);
            control_client.update_rtptime(packetizer.current_timestamp());
            total_frames_sent += SAMPLES_PER_FRAME as u64;
        }

        if session_ended {
            break;
        }

        // Exact monotonic crystal-clock pacing (`abs_time_stream - rel_to_start`)
        let abs_time_stream =
            Duration::from_secs_f64((total_frames_sent as f64) / (SAMPLE_RATE as f64));
        let rel_to_start = stream_start.elapsed();
        if abs_time_stream > rel_to_start {
            tokio::time::sleep(abs_time_stream - rel_to_start).await;
        }
    }

    ev_consumer_handle.abort();
    capture.stop().await;
    timing_server.shutdown();

    {
        let mut r = rtsp.lock().await;
        let _ = r.teardown().await;
    }

    Ok(())
}

/// Stream synthetic sine wave tone over a real HAP-authenticated AirPlay 2 session.
async fn run_stream_tone(
    host: &str,
    port: u16,
    freq: f32,
    duration: u64,
) -> Result<(), SonusError> {
    info!(
        "Testing low-latency AirPlay 2 playback: {:.1} Hz tone to {}:{}",
        freq, host, port
    );

    let mut rtsp = RtspClient::connect(host, port).await?;
    let (audio_shk, _ev_read, _ev_write) = rtsp.pair_verify_transient().await?;

    let timing_server = TimingServer::bind().await?;
    let control_client = ControlClient::bind(host, 0).await?;

    let event_port = rtsp.setup_base(timing_server.local_port()).await?;
    info!("Stage 1 Base SETUP complete (eventPort={})", event_port);

    let setup_resp = rtsp
        .setup_stream(control_client.local_port(), &audio_shk)
        .await?;
    control_client.set_server_control_port(setup_resp.server_control_port);
    info!(
        "Stage 2 Stream SETUP complete: dataPort={}, controlPort={}",
        setup_resp.server_data_port, setup_resp.server_control_port
    );

    rtsp.record().await?;
    let start_ntp = ntp_now();
    let start_rtptime = ntp2ts(start_ntp, SAMPLE_RATE);
    let _ = rtsp.flush(0, start_rtptime).await;

    let local_socket = UdpSocket::bind("0.0.0.0:0").await?;
    let target_addr: SocketAddr = format!("{}:{}", host, setup_resp.server_data_port)
        .parse()
        .map_err(|e| SonusError::Config(format!("Invalid socket address: {e}")))?;

    let mut cipher = AirPlayAudioCipher::new(&audio_shk);
    let mut packetizer = Packetizer::new(rtsp.session_id() as u32);
    packetizer.reanchor_timestamp(start_rtptime);
    control_client
        .send_initial_sync(start_rtptime, 11_025)
        .await?;

    let mut tone_gen = SineToneSource::new(freq);
    let mut pcm_buf = vec![0u8; PCM_PACKET_BYTES];

    let packet_dur = Packetizer::packet_duration();
    let mut interval = tokio::time::interval(packet_dur);

    let start_time = tokio::time::Instant::now();
    let max_dur = if duration > 0 {
        Some(Duration::from_secs(duration))
    } else {
        None
    };

    let mut packets_sent = 0u64;

    loop {
        interval.tick().await;

        if let Some(limit) = max_dur {
            if start_time.elapsed() >= limit {
                break;
            }
        }

        let bytes_read = tone_gen.read_chunk(&mut pcm_buf)?;
        let rtp_pkt = packetizer.packetize(&pcm_buf[..bytes_read])?;
        let seq = rtp_pkt.sequence_number();

        let encrypted_payload =
            cipher.encrypt_audio_payload(rtp_pkt.header(), rtp_pkt.payload())?;

        let mut wire_pkt = Vec::with_capacity(12 + encrypted_payload.len());
        wire_pkt.extend_from_slice(rtp_pkt.header());
        wire_pkt.extend_from_slice(&encrypted_payload);

        let _ = local_socket.send_to(&wire_pkt, target_addr).await?;
        control_client.store_packet(seq, wire_pkt);
        control_client.update_rtptime(packetizer.current_timestamp());
        packets_sent += 1;
    }

    info!(
        "Stream completed. Sent {} packets ({:.2}s). Tearing down session...",
        packets_sent,
        start_time.elapsed().as_secs_f32()
    );
    let _ = rtsp.teardown().await;
    timing_server.shutdown();
    info!("Session torn down cleanly.");

    Ok(())
}

/// Probe HomePod RTSP endpoint and verify HAP transient pairing handshake.
async fn run_probe(host: &str, port: u16) -> Result<(), SonusError> {
    info!("Probing HomePod mini at {}:{}...", host, port);
    let t0 = Instant::now();
    let mut rtsp = RtspClient::connect(host, port).await?;
    let info_resp = rtsp.info().await?;
    info!(
        "GET /info responded with {} ({} bytes body)",
        info_resp.status_line,
        info_resp.body.len()
    );

    let (shk, _, _) = rtsp.pair_verify_transient().await?;
    info!(
        "HAP Transient SRP-6a + ChaCha20-Poly1305 handshake verified in {:.1}ms (derived 32B shk={:02x?})",
        t0.elapsed().as_secs_f64() * 1000.0,
        &shk[..4]
    );
    Ok(())
}

fn now_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
