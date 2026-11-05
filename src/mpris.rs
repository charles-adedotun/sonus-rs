//! Linux D-Bus MPRIS2 media player controller and metadata bridge.
//!
//! Provides zero-dependency native D-Bus integration for querying MPRIS2 media
//! players (e.g. Chrome/YouTube, Spotify, Firefox, MPV) and dispatching
//! playback control commands (`PlayPause`, `Next`, `Previous`, `Seek`).

/// Track metadata extracted from an active MPRIS2 player.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrackMetadata {
    pub title: String,
    pub artist: String,
    pub album: String,
    pub playing: bool,
}

/// Parse D-Bus `ListNames` output text and extract all `org.mpris.MediaPlayer2.*` bus names.
pub fn parse_dbus_list_names(output: &str) -> Vec<String> {
    let mut players = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(start) = trimmed.find("string \"") {
            let rest = &trimmed[start + 8..];
            if let Some(end) = rest.find('"') {
                let name = &rest[..end];
                if name.starts_with("org.mpris.MediaPlayer2.")
                    && !players.contains(&name.to_string())
                {
                    players.push(name.to_string());
                }
            }
        }
    }
    players
}

/// Parse D-Bus `PlaybackStatus` property output text.
///
/// Returns `"Playing"`, `"Paused"`, or `"Stopped"`. Defaults to `"Stopped"`.
pub fn parse_dbus_playback_status(output: &str) -> String {
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(start) = trimmed.find("string \"") {
            let rest = &trimmed[start + 8..];
            if let Some(end) = rest.find('"') {
                let status = &rest[..end];
                match status {
                    "Playing" | "Paused" | "Stopped" => return status.to_string(),
                    _ => {}
                }
            }
        }
    }
    "Stopped".to_string()
}

/// Helper to extract string literal inside `string "..."` from a D-Bus line.
fn extract_string_literal(line: &str) -> Option<String> {
    if let Some(idx) = line.find("string \"") {
        let after = &line[idx + 8..];
        if let Some(end) = after.rfind('"') {
            return Some(after[..end].to_string());
        }
    }
    None
}

/// Parse D-Bus `Metadata` dictionary output text into `(title, artist, album)`.
pub fn parse_dbus_metadata(output: &str) -> (String, String, String) {
    let mut title = String::new();
    let mut artists: Vec<String> = Vec::new();
    let mut album = String::new();

    let lines: Vec<&str> = output.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i].trim();
        if line.starts_with("dict entry(") {
            i += 1;
            // The first string in dict entry is the key name
            let mut key = String::new();
            while i < lines.len() {
                let l = lines[i].trim();
                if let Some(k) = extract_string_literal(l) {
                    key = k;
                    i += 1;
                    break;
                }
                if l.starts_with(')') {
                    break;
                }
                i += 1;
            }

            match key.as_str() {
                "xesam:title" => {
                    while i < lines.len() {
                        let l = lines[i].trim();
                        if l.starts_with(')') {
                            break;
                        }
                        if let Some(val) = extract_string_literal(l) {
                            title = val;
                            break;
                        }
                        i += 1;
                    }
                }
                "xesam:album" => {
                    while i < lines.len() {
                        let l = lines[i].trim();
                        if l.starts_with(')') {
                            break;
                        }
                        if let Some(val) = extract_string_literal(l) {
                            album = val;
                            break;
                        }
                        i += 1;
                    }
                }
                "xesam:artist" => {
                    while i < lines.len() {
                        let l = lines[i].trim();
                        if l.starts_with(')') {
                            break;
                        }
                        if let Some(val) = extract_string_literal(l) {
                            artists.push(val);
                        }
                        i += 1;
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }

    let artist_str = artists.join(", ");
    (title, artist_str, album)
}

/// List all available MPRIS2 players registered on the user session D-Bus.
///
/// Queries `org.freedesktop.DBus.ListNames` via `dbus-send` (with fallback to `playerctl -l`).
pub fn list_mpris_players() -> Vec<String> {
    // 1. Try dbus-send
    if let Ok(output) = std::process::Command::new("dbus-send")
        .args([
            "--session",
            "--dest=org.freedesktop.DBus",
            "--type=method_call",
            "--print-reply",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus.ListNames",
        ])
        .output()
    {
        if output.status.success() {
            let out_str = String::from_utf8_lossy(&output.stdout);
            let players = parse_dbus_list_names(&out_str);
            if !players.is_empty() {
                return players;
            }
        }
    }

    // 2. Fallback to playerctl -l if available
    if let Ok(output) = std::process::Command::new("playerctl")
        .args(["-l"])
        .output()
    {
        if output.status.success() {
            let out_str = String::from_utf8_lossy(&output.stdout);
            return out_str
                .lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty())
                .map(|p| {
                    if p.starts_with("org.mpris.MediaPlayer2.") {
                        p.to_string()
                    } else {
                        format!("org.mpris.MediaPlayer2.{p}")
                    }
                })
                .collect();
        }
    }

    Vec::new()
}

/// Query playback status (`Playing`, `Paused`, `Stopped`) for the given player bus name.
pub fn get_player_status(bus_name: &str) -> String {
    let output = std::process::Command::new("dbus-send")
        .args([
            "--session",
            &format!("--dest={bus_name}"),
            "--type=method_call",
            "--print-reply",
            "/org/mpris/MediaPlayer2",
            "org.freedesktop.DBus.Properties.Get",
            "string:org.mpris.MediaPlayer2.Player",
            "string:PlaybackStatus",
        ])
        .output();

    if let Ok(out) = output {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout);
            return parse_dbus_playback_status(&s);
        }
    }

    "Stopped".to_string()
}

/// Extract title, artist, album, and playback status from the active MPRIS2 player.
///
/// Priority is given to a currently `Playing` media player, falling back to the
/// first available player on the bus.
pub fn get_active_player_metadata() -> TrackMetadata {
    let players = list_mpris_players();
    if players.is_empty() {
        return TrackMetadata::default();
    }

    // Prioritize a player that is actively playing
    let mut chosen_player = None;
    for p in &players {
        if get_player_status(p) == "Playing" {
            chosen_player = Some((p.clone(), true));
            break;
        }
    }

    let (player, is_playing) = match chosen_player {
        Some(cp) => cp,
        None => {
            let first = players[0].clone();
            let status = get_player_status(&first);
            let playing = status == "Playing";
            (first, playing)
        }
    };

    if let Ok(output) = std::process::Command::new("dbus-send")
        .args([
            "--session",
            &format!("--dest={player}"),
            "--type=method_call",
            "--print-reply",
            "/org/mpris/MediaPlayer2",
            "org.freedesktop.DBus.Properties.Get",
            "string:org.mpris.MediaPlayer2.Player",
            "string:Metadata",
        ])
        .output()
    {
        if output.status.success() {
            let out_str = String::from_utf8_lossy(&output.stdout);
            let (title, artist, album) = parse_dbus_metadata(&out_str);
            return TrackMetadata {
                title,
                artist,
                album,
                playing: is_playing,
            };
        }
    }

    TrackMetadata {
        title: String::new(),
        artist: String::new(),
        album: String::new(),
        playing: is_playing,
    }
}

/// Dispatch a playback control command (`PlayPause`, `Play`, `Pause`, `Stop`, `Next`, `Previous`)
/// to the currently playing or first available MPRIS2 player.
pub fn dispatch_mpris_command(action: &str) -> bool {
    let players = list_mpris_players();
    if players.is_empty() {
        return false;
    }

    let target = players
        .iter()
        .find(|p| get_player_status(p) == "Playing")
        .unwrap_or(&players[0]);

    let method = format!("org.mpris.MediaPlayer2.Player.{action}");
    let output = std::process::Command::new("dbus-send")
        .args([
            "--session",
            &format!("--dest={target}"),
            "--type=method_call",
            "/org/mpris/MediaPlayer2",
            &method,
        ])
        .status();

    match output {
        Ok(status) => status.success(),
        Err(_) => false,
    }
}

/// Seek relative to current playback position by `offset_secs` (positive = forward, negative = backward).
///
/// Converts seconds to 64-bit microsecond integer as required by the MPRIS2 `Seek` method.
pub fn dispatch_mpris_seek_seconds(offset_secs: f64) -> bool {
    let players = list_mpris_players();
    if players.is_empty() {
        return false;
    }

    let target = players
        .iter()
        .find(|p| get_player_status(p) == "Playing")
        .unwrap_or(&players[0]);

    let offset_us = (offset_secs * 1_000_000.0) as i64;
    let arg = format!("int64:{offset_us}");

    let output = std::process::Command::new("dbus-send")
        .args([
            "--session",
            &format!("--dest={target}"),
            "--type=method_call",
            "/org/mpris/MediaPlayer2",
            "org.mpris.MediaPlayer2.Player.Seek",
            &arg,
        ])
        .status();

    match output {
        Ok(status) => status.success(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dbus_list_names() {
        let sample = r#"
method return time=1793996669.315311 sender=org.freedesktop.DBus -> destination=:1.182 serial=4294967295 reply_serial=2
   array [
      string "org.freedesktop.DBus"
      string ":1.0"
      string "com.mitchellh.ghostty"
      string "org.mpris.MediaPlayer2.chromium.instance478736"
      string "org.mpris.MediaPlayer2.spotify"
      string "org.pipewire.Telephony"
   ]
"#;
        let players = parse_dbus_list_names(sample);
        assert_eq!(
            players,
            vec![
                "org.mpris.MediaPlayer2.chromium.instance478736".to_string(),
                "org.mpris.MediaPlayer2.spotify".to_string()
            ]
        );
    }

    #[test]
    fn test_parse_dbus_playback_status() {
        let sample_playing = r#"
method return time=1793996675.701017 sender=:1.138 -> destination=:1.186 serial=258 reply_serial=2
   variant       string "Playing"
"#;
        assert_eq!(parse_dbus_playback_status(sample_playing), "Playing");

        let sample_paused = r#"
method return time=1793996675.701017 sender=:1.138 -> destination=:1.186 serial=258 reply_serial=2
   variant       string "Paused"
"#;
        assert_eq!(parse_dbus_playback_status(sample_paused), "Paused");

        let sample_stopped = r#"
method return time=1793996675.701017 sender=:1.138 -> destination=:1.186 serial=258 reply_serial=2
   variant       string "Stopped"
"#;
        assert_eq!(parse_dbus_playback_status(sample_stopped), "Stopped");

        let sample_empty = "";
        assert_eq!(parse_dbus_playback_status(sample_empty), "Stopped");
    }

    #[test]
    fn test_parse_dbus_metadata_array_artist() {
        let sample = r#"
method return time=1793996683.297630 sender=:1.138 -> destination=:1.187 serial=259 reply_serial=2
   variant       array [
         dict entry(
            string "mpris:artUrl"
            variant                string "file:///tmp/.com.google.Chrome.2CJT61"
         )
         dict entry(
            string "mpris:length"
            variant                int64 2832201000
         )
         dict entry(
            string "xesam:album"
            variant                string "Discovery"
         )
         dict entry(
            string "xesam:artist"
            variant                array [
                  string "Daft Punk"
                  string "Romanthony"
               ]
         )
         dict entry(
            string "xesam:title"
            variant                string "One More Time"
         )
      ]
"#;
        let (title, artist, album) = parse_dbus_metadata(sample);
        assert_eq!(title, "One More Time");
        assert_eq!(artist, "Daft Punk, Romanthony");
        assert_eq!(album, "Discovery");
    }

    #[test]
    fn test_parse_dbus_metadata_single_artist_and_empty_album() {
        let sample = r#"
method return time=1793996683.297630 sender=:1.138 -> destination=:1.187 serial=259 reply_serial=2
   variant       array [
         dict entry(
            string "xesam:album"
            variant                string ""
         )
         dict entry(
            string "xesam:artist"
            variant                string "dopecaesar"
         )
         dict entry(
            string "xesam:title"
            variant                string "Dope Caesar - Catalyst Set"
         )
      ]
"#;
        let (title, artist, album) = parse_dbus_metadata(sample);
        assert_eq!(title, "Dope Caesar - Catalyst Set");
        assert_eq!(artist, "dopecaesar");
        assert_eq!(album, "");
    }
}
