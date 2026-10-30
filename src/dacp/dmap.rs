//! Apple DMAP (Digital Media Access Protocol) binary tag encoder and decoder.
//!
//! DMAP uses 4-byte ASCII FourCC codes, followed by a 4-byte big-endian length,
//! followed by the tag payload (integers, strings, or nested container tags).

use crate::error::SonusError;

/// Individual DMAP binary tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmapTag {
    pub code: [u8; 4],
    pub data: Vec<u8>,
}

impl DmapTag {
    /// Return the 4-character ASCII code of the tag.
    pub fn code_str(&self) -> String {
        String::from_utf8_lossy(&self.code).to_string()
    }

    /// Read data as 8-bit unsigned integer.
    pub fn as_u8(&self) -> Result<u8, SonusError> {
        if self.data.len() == 1 {
            Ok(self.data[0])
        } else {
            Err(SonusError::Dmap(format!(
                "Tag {} data length {} != 1 for u8",
                self.code_str(),
                self.data.len()
            )))
        }
    }

    /// Read data as 16-bit unsigned integer (big-endian).
    pub fn as_u16(&self) -> Result<u16, SonusError> {
        if self.data.len() == 2 {
            Ok(u16::from_be_bytes([self.data[0], self.data[1]]))
        } else {
            Err(SonusError::Dmap(format!(
                "Tag {} data length {} != 2 for u16",
                self.code_str(),
                self.data.len()
            )))
        }
    }

    /// Read data as 32-bit unsigned integer (big-endian).
    pub fn as_u32(&self) -> Result<u32, SonusError> {
        if self.data.len() == 4 {
            Ok(u32::from_be_bytes([
                self.data[0],
                self.data[1],
                self.data[2],
                self.data[3],
            ]))
        } else {
            Err(SonusError::Dmap(format!(
                "Tag {} data length {} != 4 for u32",
                self.code_str(),
                self.data.len()
            )))
        }
    }

    /// Read data as UTF-8 string.
    pub fn as_string(&self) -> Result<String, SonusError> {
        String::from_utf8(self.data.clone()).map_err(|e| {
            SonusError::Dmap(format!("Invalid UTF-8 in tag {}: {}", self.code_str(), e))
        })
    }
}

/// Create a 1-byte unsigned integer tag (`u8`).
pub fn uint8_tag(code: &[u8; 4], val: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(9);
    out.extend_from_slice(code);
    out.extend_from_slice(&1u32.to_be_bytes()); // length: 1
    out.push(val);
    out
}

/// Create a 2-byte unsigned integer tag (`u16`).
pub fn uint16_tag(code: &[u8; 4], val: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(10);
    out.extend_from_slice(code);
    out.extend_from_slice(&2u32.to_be_bytes()); // length: 2
    out.extend_from_slice(&val.to_be_bytes());
    out
}

/// Create a 4-byte unsigned integer tag (`u32`).
pub fn uint32_tag(code: &[u8; 4], val: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    out.extend_from_slice(code);
    out.extend_from_slice(&4u32.to_be_bytes()); // length: 4
    out.extend_from_slice(&val.to_be_bytes());
    out
}

/// Create a string tag.
pub fn string_tag(code: &[u8; 4], s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(8 + b.len());
    out.extend_from_slice(code);
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
    out
}

/// Create a container tag enclosing nested DMAP tags.
pub fn container_tag(code: &[u8; 4], children_bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + children_bytes.len());
    out.extend_from_slice(code);
    out.extend_from_slice(&(children_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(children_bytes);
    out
}

/// Decode a sequence of DMAP tags from a binary buffer.
pub fn decode_dmap_tags(buf: &[u8]) -> Result<Vec<DmapTag>, SonusError> {
    let mut tags = Vec::new();
    let mut offset = 0;

    while offset < buf.len() {
        if offset + 8 > buf.len() {
            return Err(SonusError::Dmap(format!(
                "Unexpected EOF reading tag header at offset {offset}"
            )));
        }

        let code = [
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ];
        let len = u32::from_be_bytes([
            buf[offset + 4],
            buf[offset + 5],
            buf[offset + 6],
            buf[offset + 7],
        ]) as usize;

        offset += 8;

        if offset + len > buf.len() {
            return Err(SonusError::Dmap(format!(
                "Tag payload truncated: expected {} bytes at offset {}, available {}",
                len,
                offset,
                buf.len() - offset
            )));
        }

        let data = buf[offset..offset + len].to_vec();
        offset += len;

        tags.push(DmapTag { code, data });
    }

    Ok(tags)
}

/// Playback status code in DMAP:
/// - 2: Playing
/// - 3: Paused
/// - 0: Stopped
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaybackState {
    Stopped = 0,
    Playing = 2,
    Paused = 3,
}

impl PlaybackState {
    pub fn from_u8(val: u8) -> Self {
        match val {
            2 => PlaybackState::Playing,
            3 => PlaybackState::Paused,
            _ => PlaybackState::Stopped,
        }
    }
}

impl From<u8> for PlaybackState {
    fn from(val: u8) -> Self {
        Self::from_u8(val)
    }
}

/// Build standard `/ctrl-int/1/playstatusupdate` DMAP response (`cmst` container).
pub fn build_playstatus_update(revision: u32, state: PlaybackState) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&uint32_tag(b"mstt", 200)); // Status: 200 OK
    payload.extend_from_slice(&uint32_tag(b"cmsr", revision)); // Revision
    payload.extend_from_slice(&uint8_tag(b"caps", state as u8)); // Playback state (2/3/0)
    payload.extend_from_slice(&uint8_tag(b"cavc", 1)); // Volume controllable: true

    container_tag(b"cmst", &payload)
}

/// Build standard `/ctrl-int/1/getproperty?properties=dmcp.volume` DMAP response (`cmgt` container).
pub fn build_volume_property(volume_pct: u8) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&uint32_tag(b"mstt", 200)); // Status: 200 OK
    payload.extend_from_slice(&uint32_tag(b"cmvo", volume_pct.min(100) as u32)); // Volume 0..=100

    container_tag(b"cmgt", &payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dmap_encode_decode() {
        let update_bytes = build_playstatus_update(42, PlaybackState::Playing);
        assert_eq!(&update_bytes[0..4], b"cmst");

        let tags = decode_dmap_tags(&update_bytes).unwrap();
        assert_eq!(tags.len(), 1);

        let cmst = &tags[0];
        assert_eq!(cmst.code_str(), "cmst");

        // Decode inner container tags
        let inner_tags = decode_dmap_tags(&cmst.data).unwrap();
        assert_eq!(inner_tags.len(), 4);

        assert_eq!(inner_tags[0].code_str(), "mstt");
        assert_eq!(inner_tags[0].as_u32().unwrap(), 200);

        assert_eq!(inner_tags[1].code_str(), "cmsr");
        assert_eq!(inner_tags[1].as_u32().unwrap(), 42);

        assert_eq!(inner_tags[2].code_str(), "caps");
        assert_eq!(inner_tags[2].as_u8().unwrap(), 2);

        assert_eq!(inner_tags[3].code_str(), "cavc");
        assert_eq!(inner_tags[3].as_u8().unwrap(), 1);
    }
}
