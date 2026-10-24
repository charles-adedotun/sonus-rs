//! ChaCha20-Poly1305 AEAD audio encryption with 8-byte nonce framing.
//!
//! Apple AirPlay 2 RAOP encrypts each 1,408-byte audio frame using:
//! - Key: 32-byte shared secret derived from pairing or transient handshake.
//! - Nonce: 12-byte buffer consisting of 4 zero bytes followed by an 8-byte little-endian counter.
//! - AAD: Bytes 4..12 of the RTP header (Timestamp + SSRC).
//! - Suffix: The 8-byte little-endian counter appended to the encrypted payload.

use crate::error::SonusError;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};

/// Encryptor/Decryptor managing ChaCha20-Poly1305 state and monotonic counter sequence.
pub struct AirPlayAudioCipher {
    cipher: ChaCha20Poly1305,
    out_counter: u64,
    in_counter: u64,
}

impl AirPlayAudioCipher {
    /// Initialize with a 32-byte shared secret key.
    pub fn new(shared_secret: &[u8; 32]) -> Self {
        let key = Key::from_slice(shared_secret);
        let cipher = ChaCha20Poly1305::new(key);
        Self {
            cipher,
            out_counter: 0,
            in_counter: 0,
        }
    }

    /// Construct a 12-byte RFC 7539 nonce from an 8-byte counter.
    /// `[0x00, 0x00, 0x00, 0x00, counter[0..8] (LE)]`
    fn make_nonce(counter: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        let counter_le = counter.to_le_bytes();
        nonce[4..12].copy_from_slice(&counter_le);
        nonce
    }

    /// Encrypt an audio PCM payload for an RTP packet.
    ///
    /// # Arguments
    /// * `rtp_header` - 12-byte RTP header. Bytes 4..12 are used as AAD.
    /// * `pcm_payload` - 1,408 bytes of stereo 16-bit PCM audio.
    ///
    /// # Returns
    /// Ciphertext (1,408B) + Poly1305 Tag (16B) + Nonce Suffix (8B) = 1,432 bytes.
    pub fn encrypt_audio_payload(
        &mut self,
        rtp_header: &[u8],
        pcm_payload: &[u8],
    ) -> Result<Vec<u8>, SonusError> {
        if rtp_header.len() < 12 {
            return Err(SonusError::Crypto(
                "RTP header must be at least 12 bytes".to_string(),
            ));
        }

        let aad = &rtp_header[4..12];
        let counter = self.out_counter;
        self.out_counter = self.out_counter.wrapping_add(1);

        let nonce_bytes = Self::make_nonce(counter);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let payload = Payload {
            msg: pcm_payload,
            aad,
        };

        let mut encrypted = self
            .cipher
            .encrypt(nonce, payload)
            .map_err(|e| SonusError::Crypto(format!("ChaCha20 encryption failed: {e}")))?;

        // Append 8-byte nonce counter suffix
        encrypted.extend_from_slice(&counter.to_le_bytes());

        Ok(encrypted)
    }

    /// Decrypt an encrypted audio payload.
    ///
    /// # Arguments
    /// * `rtp_header` - 12-byte RTP header.
    /// * `encrypted_with_suffix` - Ciphertext + 16B tag + 8B nonce suffix.
    ///
    /// # Returns
    /// Plaintext 1,408 bytes of PCM audio.
    pub fn decrypt_audio_payload(
        &mut self,
        rtp_header: &[u8],
        encrypted_with_suffix: &[u8],
    ) -> Result<Vec<u8>, SonusError> {
        if rtp_header.len() < 12 {
            return Err(SonusError::Crypto(
                "RTP header must be at least 12 bytes".to_string(),
            ));
        }
        if encrypted_with_suffix.len() < 24 {
            // At least 16B tag + 8B suffix
            return Err(SonusError::Crypto(
                "Encrypted payload too short".to_string(),
            ));
        }

        let aad = &rtp_header[4..12];
        let suffix_idx = encrypted_with_suffix.len() - 8;
        let cipher_and_tag = &encrypted_with_suffix[..suffix_idx];
        let counter_bytes = &encrypted_with_suffix[suffix_idx..];

        let counter = u64::from_le_bytes(
            counter_bytes
                .try_into()
                .map_err(|_| SonusError::Crypto("Invalid nonce suffix length".to_string()))?,
        );

        let nonce_bytes = Self::make_nonce(counter);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let payload = Payload {
            msg: cipher_and_tag,
            aad,
        };

        let decrypted = self
            .cipher
            .decrypt(nonce, payload)
            .map_err(|e| SonusError::Crypto(format!("ChaCha20 decryption failed: {e}")))?;

        self.in_counter = counter.wrapping_add(1);

        Ok(decrypted)
    }

    pub fn current_out_counter(&self) -> u64 {
        self.out_counter
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha20_roundtrip() {
        let key = [0x7au8; 32];
        let mut cipher = AirPlayAudioCipher::new(&key);

        let mut rtp_header = [0u8; 12];
        rtp_header[0] = 0x80;
        rtp_header[1] = 0x60;
        rtp_header[2..4].copy_from_slice(&1u16.to_be_bytes()); // Seq 1
        rtp_header[4..8].copy_from_slice(&44100u32.to_be_bytes()); // Timestamp
        rtp_header[8..12].copy_from_slice(&0xdeadbeefu32.to_be_bytes()); // SSRC

        let original_pcm = vec![0x11u8; 1408];

        let encrypted = cipher
            .encrypt_audio_payload(&rtp_header, &original_pcm)
            .unwrap();
        assert_eq!(encrypted.len(), 1408 + 16 + 8); // 1432 bytes

        // Decrypt with fresh cipher
        let mut decrypt_cipher = AirPlayAudioCipher::new(&key);
        let decrypted = decrypt_cipher
            .decrypt_audio_payload(&rtp_header, &encrypted)
            .unwrap();

        assert_eq!(decrypted, original_pcm);
    }
}
