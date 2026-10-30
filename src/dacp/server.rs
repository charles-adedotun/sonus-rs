//! Embedded DACP (Digital Audio Control Protocol) HTTP server on port 3689.
//!
//! Intercepts physical touch surface taps (single tap = PlayPause, double tap = Next,
//! volume buttons = +/-5%) and Siri playback commands from the Apple HomePod.

use crate::dacp::dmap::{build_playstatus_update, build_volume_property, PlaybackState};
use crate::error::SonusError;
use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::mpsc;
use tracing::{debug, error, info};

/// DACP touch and playback commands emitted by HomePod.
#[derive(Debug, Clone, PartialEq)]
pub enum DacpCommand {
    PlayPause,
    Play,
    Pause,
    Stop,
    Next,
    Previous,
    VolumeUp,
    VolumeDown,
    MuteToggle,
    SetVolume(f32),
}

/// DACP Server listening for HomePod touch actions and status polling.
pub struct DacpServer {
    port: u16,
    revision: Arc<AtomicU32>,
    playback_state: Arc<AtomicU8>,
    cmd_sender: mpsc::Sender<DacpCommand>,
    cmd_receiver: Option<mpsc::Receiver<DacpCommand>>,
}

impl DacpServer {
    /// Create a new DACP server instance on the specified port (default 3689).
    pub fn new(port: u16) -> Self {
        let (tx, rx) = mpsc::channel(32);
        Self {
            port,
            revision: Arc::new(AtomicU32::new(1)),
            playback_state: Arc::new(AtomicU8::new(PlaybackState::Playing as u8)),
            cmd_sender: tx,
            cmd_receiver: Some(rx),
        }
    }

    /// Access the shared atomic playback state handle (Playing = 2, Paused = 3, Stopped = 0).
    pub fn playback_state_handle(&self) -> Arc<AtomicU8> {
        Arc::clone(&self.playback_state)
    }

    /// Take the command receiver stream to listen for touch events.
    pub fn take_command_receiver(&mut self) -> Option<mpsc::Receiver<DacpCommand>> {
        self.cmd_receiver.take()
    }

    /// Start listening for inbound HomePod HTTP requests.
    pub async fn run(self) -> Result<(), SonusError> {
        let addr_str = format!("0.0.0.0:{}", self.port);
        let sock_addr: std::net::SocketAddr = addr_str.parse().map_err(|e| {
            SonusError::Config(format!("Invalid DACP socket address {addr_str}: {e}"))
        })?;

        let socket = match sock_addr {
            std::net::SocketAddr::V4(_) => TcpSocket::new_v4()?,
            std::net::SocketAddr::V6(_) => TcpSocket::new_v6()?,
        };
        socket.set_reuseaddr(true)?;
        #[cfg(unix)]
        let _ = socket.set_reuseport(true);

        socket.bind(sock_addr).map_err(|e| {
            SonusError::Config(format!("Failed to bind DACP server on {addr_str}: {e}"))
        })?;

        let listener = socket.listen(1024).map_err(|e| {
            SonusError::Config(format!(
                "Failed to listen on DACP server on {addr_str}: {e}"
            ))
        })?;

        info!(
            "DACP HTTP server listening on {} for HomePod touch controls (SO_REUSEADDR enabled)",
            addr_str
        );

        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    debug!("DACP client connected from {}", peer_addr);
                    let tx = self.cmd_sender.clone();
                    let rev = Arc::clone(&self.revision);
                    let state = Arc::clone(&self.playback_state);
                    tokio::spawn(async move {
                        if let Err(e) = handle_dacp_connection(stream, tx, rev, state).await {
                            debug!("DACP connection closed: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Error accepting DACP connection: {}", e);
                }
            }
        }
    }
}

pub async fn handle_dacp_connection(
    mut stream: TcpStream,
    cmd_sender: mpsc::Sender<DacpCommand>,
    revision: Arc<AtomicU32>,
    playback_state: Arc<AtomicU8>,
) -> Result<(), SonusError> {
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    let req_str = String::from_utf8_lossy(&buf[..n]);
    let first_line = req_str.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("GET");
    let uri = parts.next().unwrap_or("/");

    debug!("DACP Request: {} {}", method, uri);

    if uri.starts_with("/ctrl-int/1/playstatusupdate") {
        let rev = revision.fetch_add(1, Ordering::SeqCst);
        let state_val = playback_state.load(Ordering::SeqCst);
        let state = PlaybackState::from_u8(state_val);
        let payload = build_playstatus_update(rev, state);

        let resp_headers = format!(
            "HTTP/1.1 200 OK\r\n\
             Server: iTunes/10.6 (Mac OS X)\r\n\
             DAAP-Server: iTunes/10.6 (Mac OS X)\r\n\
             Content-Type: application/x-dmap-tagged\r\n\
             Content-Length: {}\r\n\
             \r\n",
            payload.len()
        );

        stream.write_all(resp_headers.as_bytes()).await?;
        stream.write_all(&payload).await?;
        stream.flush().await?;
        return Ok(());
    }

    if uri.starts_with("/ctrl-int/1/getproperty") {
        let payload = build_volume_property(65);
        let resp_headers = format!(
            "HTTP/1.1 200 OK\r\n\
             Server: iTunes/10.6 (Mac OS X)\r\n\
             DAAP-Server: iTunes/10.6 (Mac OS X)\r\n\
             Content-Type: application/x-dmap-tagged\r\n\
             Content-Length: {}\r\n\
             \r\n",
            payload.len()
        );

        stream.write_all(resp_headers.as_bytes()).await?;
        stream.write_all(&payload).await?;
        stream.flush().await?;
        return Ok(());
    }

    // Parse command from path /ctrl-int/1/{cmd} (both GET and POST accepted)
    let command = if let Some(stripped) = uri.strip_prefix("/ctrl-int/1/") {
        let cmd_name = stripped
            .split('?')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        match cmd_name.as_str() {
            "playpause" => Some(DacpCommand::PlayPause),
            "play" => {
                playback_state.store(PlaybackState::Playing as u8, Ordering::SeqCst);
                Some(DacpCommand::Play)
            }
            "pause" => {
                playback_state.store(PlaybackState::Paused as u8, Ordering::SeqCst);
                Some(DacpCommand::Pause)
            }
            "stop" => {
                playback_state.store(PlaybackState::Stopped as u8, Ordering::SeqCst);
                Some(DacpCommand::Stop)
            }
            "nextitem" | "next" => Some(DacpCommand::Next),
            "previtem" | "prev" | "previous" => Some(DacpCommand::Previous),
            "volumeup" => Some(DacpCommand::VolumeUp),
            "volumedown" => Some(DacpCommand::VolumeDown),
            "mutetoggle" => Some(DacpCommand::MuteToggle),
            "setproperty" => {
                let vol_source = if uri.contains("dmcp.volume=") {
                    uri
                } else {
                    &req_str
                };
                if let Some(vol_str) = vol_source.split("dmcp.volume=").nth(1) {
                    let vol_raw = vol_str
                        .split(&['&', ' ', '\r', '\n'][..])
                        .next()
                        .unwrap_or("0");
                    if let Ok(val) = vol_raw.parse::<f32>() {
                        Some(DacpCommand::SetVolume(val))
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            _ => None,
        }
    } else {
        None
    };

    if let Some(cmd) = command {
        info!(
            "HomePod physical control triggered (via {}): {:?}",
            method, cmd
        );
        let _ = cmd_sender.send(cmd).await;
    }

    // Respond with 204 No Content
    let resp = "HTTP/1.1 204 No Content\r\n\
                Server: iTunes/10.6 (Mac OS X)\r\n\
                DAAP-Server: iTunes/10.6 (Mac OS X)\r\n\
                Content-Type: application/x-dmap-tagged\r\n\
                Content-Length: 0\r\n\
                \r\n";

    stream.write_all(resp.as_bytes()).await?;
    stream.flush().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_playback_state_handle() {
        let server = DacpServer::new(3689);
        let handle = server.playback_state_handle();
        assert_eq!(handle.load(Ordering::SeqCst), PlaybackState::Playing as u8);

        handle.store(PlaybackState::Paused as u8, Ordering::SeqCst);
        assert_eq!(
            server.playback_state_handle().load(Ordering::SeqCst),
            PlaybackState::Paused as u8
        );

        handle.store(PlaybackState::Stopped as u8, Ordering::SeqCst);
        assert_eq!(
            server.playback_state_handle().load(Ordering::SeqCst),
            PlaybackState::Stopped as u8
        );
    }
}
