//! Apple Binary Plist (bplist00) payload builders and parsers for AirPlay 2 sessions.
//!
//! Includes:
//! - Stage 1 Base SETUP dictionary with NTP timingPort and eventPort negotiation.
//! - Stage 2 Stream SETUP dictionary for sub-250ms interactive HAL audio pipeline (`streamType: 2`).
//! - MediaRemote supported commands (`updateMRSupportedCommands`) and now-playing metadata (`updateMRNowPlayingInfo`).
//! - Decibel Full Scale (dBFS) to/from linear percentage conversion (`-144.0` / `-30.0..=0.0 dBFS`).

use crate::config::{MAX_LATENCY_FRAMES, MIN_LATENCY_FRAMES, SAMPLES_PER_FRAME, SAMPLE_RATE};
use crate::error::SonusError;
use plist::{Dictionary, Value};

/// Converts linear volume percentage (0..=100%) to AirPlay 2 dBFS value.
/// - 0% maps to -144.0 dBFS (silence/mute).
/// - 1..=100% maps linearly from -30.0 dBFS to 0.0 dBFS.
pub fn pct_to_dbfs(pct: f32) -> f32 {
    if pct <= 0.0 {
        -144.0
    } else {
        let clamped = pct.clamp(0.0, 100.0);
        -30.0 + (clamped / 100.0) * 30.0
    }
}

/// Converts AirPlay 2 dBFS value to linear volume percentage (0..=100%).
/// - Values <= -30.0 dBFS map to 0%.
/// - Values >= 0.0 dBFS map to 100%.
/// - Intermediate values map linearly between -30.0 and 0.0 dBFS.
pub fn dbfs_to_pct(dbfs: f32) -> f32 {
    if dbfs <= -30.0 {
        0.0
    } else if dbfs >= 0.0 {
        100.0
    } else {
        ((dbfs + 30.0) / 30.0) * 100.0
    }
}

/// Builds the Stage 1 AirPlay 2 base SETUP binary plist payload.
///
/// Announces client capabilities, sender UUID, NTP timingPort, and initiates event channel allocation.
pub fn build_base_setup_plist(timing_port: u16, session_uuid: &str) -> Result<Vec<u8>, SonusError> {
    let mut dict = Dictionary::new();
    dict.insert(
        "deviceID".to_string(),
        Value::String("AA:BB:CC:DD:EE:FF".to_string()),
    );
    dict.insert(
        "sessionUUID".to_string(),
        Value::String(session_uuid.to_string()),
    );
    dict.insert("timingPort".to_string(), Value::Integer(timing_port.into()));
    dict.insert(
        "timingProtocol".to_string(),
        Value::String("NTP".to_string()),
    );
    dict.insert("isMultiSelectAirPlay".to_string(), Value::Boolean(true));
    dict.insert(
        "groupContainsGroupLeader".to_string(),
        Value::Boolean(false),
    );
    dict.insert(
        "macAddress".to_string(),
        Value::String("AA:BB:CC:DD:EE:FF".to_string()),
    );
    dict.insert("model".to_string(), Value::String("iPhone14,3".to_string()));
    dict.insert("name".to_string(), Value::String("sonus-rs".to_string()));
    dict.insert(
        "osBuildVersion".to_string(),
        Value::String("20F66".to_string()),
    );
    dict.insert("osName".to_string(), Value::String("iPhone OS".to_string()));
    dict.insert("osVersion".to_string(), Value::String("16.5".to_string()));
    dict.insert("senderSupportsRelay".to_string(), Value::Boolean(false));
    dict.insert(
        "sourceVersion".to_string(),
        Value::String("690.7.1".to_string()),
    );
    dict.insert("statsCollectionEnabled".to_string(), Value::Boolean(false));

    let root_val = Value::Dictionary(dict);
    let mut output = Vec::new();
    plist::to_writer_binary(&mut output, &root_val).map_err(SonusError::Plist)?;
    Ok(output)
}

/// Parses the Stage 1 base SETUP binary plist response from the HomePod to extract `eventPort`.
pub fn parse_base_setup_response(body: &[u8]) -> Result<u16, SonusError> {
    let cursor = std::io::Cursor::new(body);
    let val = Value::from_reader(cursor).map_err(SonusError::Plist)?;
    let root = val
        .as_dictionary()
        .ok_or_else(|| SonusError::Rtsp("Base SETUP response is not a dictionary".to_string()))?;

    let event_port = root
        .get("eventPort")
        .and_then(|v| v.as_unsigned_integer())
        .ok_or_else(|| SonusError::Rtsp("Base SETUP response missing 'eventPort'".to_string()))?
        as u16;

    Ok(event_port)
}

/// Builds the binary plist payload sent in the Stage 2 RTSP SETUP request to initiate
/// a sub-250ms interactive HAL audio pipeline (`streamType: 2`).
pub fn build_stream_setup_plist(
    session_id: u64,
    control_port: u16,
    shared_secret: &[u8],
) -> Result<Vec<u8>, SonusError> {
    let mut stream_dict = Dictionary::new();
    stream_dict.insert("audioFormat".to_string(), Value::Integer(0x800.into()));
    stream_dict.insert(
        "audioMode".to_string(),
        Value::String("default".to_string()),
    );
    stream_dict.insert(
        "controlPort".to_string(),
        Value::Integer(control_port.into()),
    );
    stream_dict.insert("ct".to_string(), Value::Integer(1.into())); // Raw PCM 16-bit
    stream_dict.insert("isMedia".to_string(), Value::Boolean(false)); // INTERACTIVE (No 2s buffer)
    stream_dict.insert("streamType".to_string(), Value::Integer(2.into())); // Real-time interactive stream
    stream_dict.insert(
        "latencyMax".to_string(),
        Value::Integer(MAX_LATENCY_FRAMES.into()),
    ); // 11,025 frames = 250ms
    stream_dict.insert(
        "latencyMin".to_string(),
        Value::Integer(MIN_LATENCY_FRAMES.into()),
    ); // 11,025 frames = 250ms
    stream_dict.insert("shk".to_string(), Value::Data(shared_secret.to_vec()));
    stream_dict.insert(
        "spf".to_string(),
        Value::Integer((SAMPLES_PER_FRAME as i64).into()),
    ); // 352 samples per frame
    stream_dict.insert(
        "sr".to_string(),
        Value::Integer((SAMPLE_RATE as i64).into()),
    ); // 44,100 Hz
    stream_dict.insert("type".to_string(), Value::Integer(0x60.into())); // RTP payload type 96
    stream_dict.insert("supportsDynamicStreamID".to_string(), Value::Boolean(false));
    stream_dict.insert(
        "streamConnectionID".to_string(),
        Value::Integer((session_id as i64).into()),
    );

    let mut root_dict = Dictionary::new();
    root_dict.insert(
        "streams".to_string(),
        Value::Array(vec![Value::Dictionary(stream_dict)]),
    );

    let root_val = Value::Dictionary(root_dict);

    let mut output = Vec::new();
    plist::to_writer_binary(&mut output, &root_val).map_err(SonusError::Plist)?;

    Ok(output)
}

/// Builds the Stage 2 RTSP SETUP binary plist payload for HomePod OS (`isMedia: true`, 250ms clamped latency).
pub fn build_homepod_stream_setup_plist(
    session_id: u64,
    control_port: u16,
    shared_secret: &[u8],
) -> Result<Vec<u8>, SonusError> {
    let mut stream_dict = Dictionary::new();
    stream_dict.insert("audioFormat".to_string(), Value::Integer(0x800.into()));
    stream_dict.insert(
        "audioMode".to_string(),
        Value::String("default".to_string()),
    );
    stream_dict.insert(
        "controlPort".to_string(),
        Value::Integer(control_port.into()),
    );
    stream_dict.insert("ct".to_string(), Value::Integer(1.into())); // Raw PCM 16-bit
    stream_dict.insert("isMedia".to_string(), Value::Boolean(true)); // Enables MediaRemote touch controls on HomePod
    stream_dict.insert(
        "latencyMax".to_string(),
        Value::Integer(MAX_LATENCY_FRAMES.into()),
    ); // 11,025 frames = 250ms
    stream_dict.insert(
        "latencyMin".to_string(),
        Value::Integer(MIN_LATENCY_FRAMES.into()),
    ); // 11,025 frames = 250ms
    stream_dict.insert("shk".to_string(), Value::Data(shared_secret.to_vec()));
    stream_dict.insert(
        "spf".to_string(),
        Value::Integer((SAMPLES_PER_FRAME as i64).into()),
    ); // 352 samples per frame
    stream_dict.insert(
        "sr".to_string(),
        Value::Integer((SAMPLE_RATE as i64).into()),
    ); // 44,100 Hz
    stream_dict.insert("type".to_string(), Value::Integer(0x60.into())); // RTP payload type 96
    stream_dict.insert("supportsDynamicStreamID".to_string(), Value::Boolean(false));
    stream_dict.insert(
        "streamConnectionID".to_string(),
        Value::Integer((session_id as i64).into()),
    );

    let mut root_dict = Dictionary::new();
    root_dict.insert(
        "streams".to_string(),
        Value::Array(vec![Value::Dictionary(stream_dict)]),
    );

    let root_val = Value::Dictionary(root_dict);
    let mut output = Vec::new();
    plist::to_writer_binary(&mut output, &root_val).map_err(SonusError::Plist)?;
    Ok(output)
}

/// Parsed stream configuration returned by HomePod in SETUP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupStreamResponse {
    pub server_data_port: u16,
    pub server_control_port: u16,
}

/// Parses the HomePod binary plist SETUP response to extract the UDP audio dataPort
/// and controlPort allocated by the speaker.
pub fn parse_stream_setup_response(body: &[u8]) -> Result<SetupStreamResponse, SonusError> {
    let cursor = std::io::Cursor::new(body);
    let val = Value::from_reader(cursor).map_err(SonusError::Plist)?;

    let root = val
        .as_dictionary()
        .ok_or_else(|| SonusError::Rtsp("SETUP response root is not a dictionary".to_string()))?;

    let streams = root
        .get("streams")
        .and_then(|v| v.as_array())
        .ok_or_else(|| SonusError::Rtsp("SETUP response missing 'streams' array".to_string()))?;

    let first_stream = streams
        .first()
        .and_then(|v| v.as_dictionary())
        .ok_or_else(|| {
            SonusError::Rtsp("SETUP response streams array is empty or invalid".to_string())
        })?;

    let data_port = first_stream
        .get("dataPort")
        .and_then(|v| v.as_unsigned_integer())
        .ok_or_else(|| SonusError::Rtsp("SETUP response stream missing 'dataPort'".to_string()))?
        as u16;

    let control_port = first_stream
        .get("controlPort")
        .and_then(|v| v.as_unsigned_integer())
        .ok_or_else(|| {
            SonusError::Rtsp("SETUP response stream missing 'controlPort'".to_string())
        })? as u16;

    Ok(SetupStreamResponse {
        server_data_port: data_port,
        server_control_port: control_port,
    })
}

/// Builds the `updateMRSupportedCommands` binary plist informing the HomePod which transport
/// controls are enabled (`0=Play, 1=Pause, 2=PlayPause, 3=Stop, 4=Next, 5=Previous, 8..11, 45=SeekTo`).
pub fn build_mr_supported_commands_plist() -> Result<Vec<u8>, SonusError> {
    let commands = [0, 1, 2, 3, 4, 5, 8, 9, 10, 11, 45];
    let mut cmd_array = Vec::with_capacity(commands.len());

    for &cmd in &commands {
        let mut cmd_dict = Dictionary::new();
        cmd_dict.insert(
            "kCommandInfoCommandKey".to_string(),
            Value::Integer(cmd.into()),
        );
        cmd_dict.insert("kCommandInfoEnabledKey".to_string(), Value::Boolean(true));
        cmd_array.push(Value::Dictionary(cmd_dict));
    }

    let mut params_dict = Dictionary::new();
    params_dict.insert(
        "mrSupportedCommandsFromSender".to_string(),
        Value::Array(cmd_array),
    );

    let mut root_dict = Dictionary::new();
    root_dict.insert(
        "type".to_string(),
        Value::String("updateMRSupportedCommands".to_string()),
    );
    root_dict.insert(
        "command".to_string(),
        Value::String("updateMRSupportedCommands".to_string()),
    );
    root_dict.insert("params".to_string(), Value::Dictionary(params_dict));

    let root_val = Value::Dictionary(root_dict);
    let mut output = Vec::new();
    plist::to_writer_binary(&mut output, &root_val).map_err(SonusError::Plist)?;
    Ok(output)
}

/// Builds the `updateMRNowPlayingInfo` binary plist informing the HomePod of active track metadata.
pub fn build_mr_now_playing_plist(
    title: &str,
    artist: &str,
    album: &str,
    playback_rate: f64,
) -> Result<Vec<u8>, SonusError> {
    let mut info_dict = Dictionary::new();
    info_dict.insert(
        "kMRMediaRemoteNowPlayingInfoTitle".to_string(),
        Value::String(title.to_string()),
    );
    info_dict.insert(
        "kMRMediaRemoteNowPlayingInfoArtist".to_string(),
        Value::String(artist.to_string()),
    );
    info_dict.insert(
        "kMRMediaRemoteNowPlayingInfoAlbum".to_string(),
        Value::String(album.to_string()),
    );
    info_dict.insert(
        "kMRMediaRemoteNowPlayingInfoPlaybackRate".to_string(),
        Value::Real(playback_rate),
    );

    // Standard simplified keys for broad compatibility
    info_dict.insert("title".to_string(), Value::String(title.to_string()));
    info_dict.insert("artist".to_string(), Value::String(artist.to_string()));
    info_dict.insert("album".to_string(), Value::String(album.to_string()));
    info_dict.insert("playbackRate".to_string(), Value::Real(playback_rate));

    let mut root_dict = Dictionary::new();
    root_dict.insert(
        "type".to_string(),
        Value::String("updateMRNowPlayingInfo".to_string()),
    );
    root_dict.insert(
        "command".to_string(),
        Value::String("updateMRNowPlayingInfo".to_string()),
    );
    root_dict.insert("params".to_string(), Value::Dictionary(info_dict));

    let root_val = Value::Dictionary(root_dict);
    let mut output = Vec::new();
    plist::to_writer_binary(&mut output, &root_val).map_err(SonusError::Plist)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_volume_dbfs_conversions() {
        assert_eq!(pct_to_dbfs(0.0), -144.0);
        assert_eq!(pct_to_dbfs(-10.0), -144.0);
        assert_eq!(pct_to_dbfs(100.0), 0.0);
        assert_eq!(pct_to_dbfs(50.0), -15.0);

        assert_eq!(dbfs_to_pct(-144.0), 0.0);
        assert_eq!(dbfs_to_pct(-30.0), 0.0);
        assert_eq!(dbfs_to_pct(0.0), 100.0);
        assert_eq!(dbfs_to_pct(-15.0), 50.0);
    }

    #[test]
    fn test_base_setup_plist_roundtrip() {
        let bytes = build_base_setup_plist(7010, "TEST-SESSION-UUID-1234").unwrap();
        assert!(bytes.starts_with(b"bplist00"));

        let cursor = std::io::Cursor::new(&bytes);
        let val = Value::from_reader(cursor).unwrap();
        let dict = val.as_dictionary().unwrap();

        assert_eq!(
            dict.get("timingPort")
                .unwrap()
                .as_unsigned_integer()
                .unwrap(),
            7010
        );
        assert_eq!(
            dict.get("sessionUUID").unwrap().as_string().unwrap(),
            "TEST-SESSION-UUID-1234"
        );
        assert_eq!(
            dict.get("model").unwrap().as_string().unwrap(),
            "iPhone14,3"
        );
        assert_eq!(dict.get("name").unwrap().as_string().unwrap(), "sonus-rs");
    }

    #[test]
    fn test_parse_base_setup_response() {
        let mut dict = Dictionary::new();
        dict.insert("eventPort".to_string(), Value::Integer(49152.into()));
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &Value::Dictionary(dict)).unwrap();

        let event_port = parse_base_setup_response(&body).unwrap();
        assert_eq!(event_port, 49152);
    }

    #[test]
    fn test_build_mr_supported_commands() {
        let bytes = build_mr_supported_commands_plist().unwrap();
        assert!(bytes.starts_with(b"bplist00"));

        let cursor = std::io::Cursor::new(&bytes);
        let val = Value::from_reader(cursor).unwrap();
        let root = val.as_dictionary().unwrap();
        assert_eq!(
            root.get("type").unwrap().as_string().unwrap(),
            "updateMRSupportedCommands"
        );

        let params = root.get("params").unwrap().as_dictionary().unwrap();
        let cmds = params
            .get("mrSupportedCommandsFromSender")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(cmds.len(), 11);
    }

    #[test]
    fn test_build_mr_now_playing() {
        let bytes =
            build_mr_now_playing_plist("Track One", "Artist Two", "Album Three", 1.0).unwrap();
        assert!(bytes.starts_with(b"bplist00"));

        let cursor = std::io::Cursor::new(&bytes);
        let val = Value::from_reader(cursor).unwrap();
        let root = val.as_dictionary().unwrap();
        assert_eq!(
            root.get("type").unwrap().as_string().unwrap(),
            "updateMRNowPlayingInfo"
        );

        let params = root.get("params").unwrap().as_dictionary().unwrap();
        assert_eq!(
            params
                .get("kMRMediaRemoteNowPlayingInfoTitle")
                .unwrap()
                .as_string()
                .unwrap(),
            "Track One"
        );
        assert_eq!(
            params
                .get("kMRMediaRemoteNowPlayingInfoArtist")
                .unwrap()
                .as_string()
                .unwrap(),
            "Artist Two"
        );
        assert_eq!(
            params
                .get("kMRMediaRemoteNowPlayingInfoAlbum")
                .unwrap()
                .as_string()
                .unwrap(),
            "Album Three"
        );
        assert_eq!(
            params
                .get("kMRMediaRemoteNowPlayingInfoPlaybackRate")
                .unwrap()
                .as_real()
                .unwrap(),
            1.0
        );
    }

    #[test]
    fn test_build_stream_setup_plist() {
        let dummy_secret = [0x42u8; 32];
        let bytes = build_stream_setup_plist(12345678, 5002, &dummy_secret).unwrap();

        assert!(bytes.starts_with(b"bplist00"));

        let cursor = std::io::Cursor::new(bytes);
        let val = Value::from_reader(cursor).unwrap();
        let root = val.as_dictionary().unwrap();
        let streams = root.get("streams").unwrap().as_array().unwrap();
        let s = streams[0].as_dictionary().unwrap();

        assert_eq!(
            s.get("latencyMax").unwrap().as_unsigned_integer().unwrap(),
            11025
        );
        assert_eq!(
            s.get("latencyMin").unwrap().as_unsigned_integer().unwrap(),
            11025
        );
        assert_eq!(
            s.get("streamType").unwrap().as_unsigned_integer().unwrap(),
            2
        );
        assert!(!s.get("isMedia").unwrap().as_boolean().unwrap());
        assert_eq!(s.get("spf").unwrap().as_unsigned_integer().unwrap(), 352);
    }
}
