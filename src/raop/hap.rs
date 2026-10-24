//! Apple HomeKit Accessory Protocol (HAP) Transient Pairing and Framing Session.
//!
//! Implements:
//! - TLV8 serialization and chunking/reassembly for fragments > 255 bytes.
//! - RFC 5054 SRP-6a 3072-bit (SHA-512) Transient Client (`Pair-Setup` with PIN `3939`).
//! - HKDF-SHA512 key derivation for Control and Events/Audio streams.
//! - 1024-byte framed ChaCha20-Poly1305 AEAD cipher (`HapSession`) with 12-byte nonces.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use num_bigint::BigUint;
use rand::RngCore;
use sha2::{Digest, Sha512};
use std::collections::HashMap;

use crate::error::SonusError;

/// RFC 5054 3072-bit prime modulus N (384 bytes).
pub const PRIME_3072_BYTES: [u8; 384] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc9, 0x0f, 0xda, 0xa2, 0x21, 0x68, 0xc2, 0x34,
    0xc4, 0xc6, 0x62, 0x8b, 0x80, 0xdc, 0x1c, 0xd1, 0x29, 0x02, 0x4e, 0x08, 0x8a, 0x67, 0xcc, 0x74,
    0x02, 0x0b, 0xbe, 0xa6, 0x3b, 0x13, 0x9b, 0x22, 0x51, 0x4a, 0x08, 0x79, 0x8e, 0x34, 0x04, 0xdd,
    0xef, 0x95, 0x19, 0xb3, 0xcd, 0x3a, 0x43, 0x1b, 0x30, 0x2b, 0x0a, 0x6d, 0xf2, 0x5f, 0x14, 0x37,
    0x4f, 0xe1, 0x35, 0x6d, 0x6d, 0x51, 0xc2, 0x45, 0xe4, 0x85, 0xb5, 0x76, 0x62, 0x5e, 0x7e, 0xc6,
    0xf4, 0x4c, 0x42, 0xe9, 0xa6, 0x37, 0xed, 0x6b, 0x0b, 0xff, 0x5c, 0xb6, 0xf4, 0x06, 0xb7, 0xed,
    0xee, 0x38, 0x6b, 0xfb, 0x5a, 0x89, 0x9f, 0xa5, 0xae, 0x9f, 0x24, 0x11, 0x7c, 0x4b, 0x1f, 0xe6,
    0x49, 0x28, 0x66, 0x51, 0xec, 0xe4, 0x5b, 0x3d, 0xc2, 0x00, 0x7c, 0xb8, 0xa1, 0x63, 0xbf, 0x05,
    0x98, 0xda, 0x48, 0x36, 0x1c, 0x55, 0xd3, 0x9a, 0x69, 0x16, 0x3f, 0xa8, 0xfd, 0x24, 0xcf, 0x5f,
    0x83, 0x65, 0x5d, 0x23, 0xdc, 0xa3, 0xad, 0x96, 0x1c, 0x62, 0xf3, 0x56, 0x20, 0x85, 0x52, 0xbb,
    0x9e, 0xd5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6d, 0x67, 0x0c, 0x35, 0x4e, 0x4a, 0xbc, 0x98, 0x04,
    0xf1, 0x74, 0x6c, 0x08, 0xca, 0x18, 0x21, 0x7c, 0x32, 0x90, 0x5e, 0x46, 0x2e, 0x36, 0xce, 0x3b,
    0xe3, 0x9e, 0x77, 0x2c, 0x18, 0x0e, 0x86, 0x03, 0x9b, 0x27, 0x83, 0xa2, 0xec, 0x07, 0xa2, 0x8f,
    0xb5, 0xc5, 0x5d, 0xf0, 0x6f, 0x4c, 0x52, 0xc9, 0xde, 0x2b, 0xcb, 0xf6, 0x95, 0x58, 0x17, 0x18,
    0x39, 0x95, 0x49, 0x7c, 0xea, 0x95, 0x6a, 0xe5, 0x15, 0xd2, 0x26, 0x18, 0x98, 0xfa, 0x05, 0x10,
    0x15, 0x72, 0x8e, 0x5a, 0x8a, 0xaa, 0xc4, 0x2d, 0xad, 0x33, 0x17, 0x0d, 0x04, 0x50, 0x7a, 0x33,
    0xa8, 0x55, 0x21, 0xab, 0xdf, 0x1c, 0xba, 0x64, 0xec, 0xfb, 0x85, 0x04, 0x58, 0xdb, 0xef, 0x0a,
    0x8a, 0xea, 0x71, 0x57, 0x5d, 0x06, 0x0c, 0x7d, 0xb3, 0x97, 0x0f, 0x85, 0xa6, 0xe1, 0xe4, 0xc7,
    0xab, 0xf5, 0xae, 0x8c, 0xdb, 0x09, 0x33, 0xd7, 0x1e, 0x8c, 0x94, 0xe0, 0x4a, 0x25, 0x61, 0x9d,
    0xce, 0xe3, 0xd2, 0x26, 0x1a, 0xd2, 0xee, 0x6b, 0xf1, 0x2f, 0xfa, 0x06, 0xd9, 0x8a, 0x08, 0x64,
    0xd8, 0x76, 0x02, 0x73, 0x3e, 0xc8, 0x6a, 0x64, 0x52, 0x1f, 0x2b, 0x18, 0x17, 0x7b, 0x20, 0x0c,
    0xbb, 0xe1, 0x17, 0x57, 0x7a, 0x61, 0x5d, 0x6c, 0x77, 0x09, 0x88, 0xc0, 0xba, 0xd9, 0x46, 0xe2,
    0x08, 0xe2, 0x4f, 0xa0, 0x74, 0xe5, 0xab, 0x31, 0x43, 0xdb, 0x5b, 0xfc, 0xe0, 0xfd, 0x10, 0x8e,
    0x4b, 0x82, 0xd1, 0x20, 0xa9, 0x3a, 0xd2, 0xca, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

/// HAP standardized TLV8 tags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TlvTag {
    Method = 0x00,
    Identifier = 0x01,
    Salt = 0x02,
    PublicKey = 0x03,
    Proof = 0x04,
    EncryptedData = 0x05,
    SeqNo = 0x06,
    Error = 0x07,
    Flags = 0x13,
}

/// Encodes key-value pairs into TLV8 format.
/// Values longer than 255 bytes are automatically fragmented into consecutive chunks
/// with identical tags according to Apple HAP specifications.
pub fn encode_tlv8(entries: &[(u8, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for &(tag, val) in entries {
        if val.is_empty() {
            out.push(tag);
            out.push(0);
        } else {
            for chunk in val.chunks(255) {
                out.push(tag);
                out.push(chunk.len() as u8);
                out.extend_from_slice(chunk);
            }
        }
    }
    out
}

/// Decodes TLV8 bytes into a map of tags to accumulated byte values.
/// Consecutive and repeated tags are concatenated to support fragmented entries.
pub fn decode_tlv8(data: &[u8]) -> HashMap<u8, Vec<u8>> {
    let mut map: HashMap<u8, Vec<u8>> = HashMap::new();
    let mut pos = 0;
    while pos + 2 <= data.len() {
        let tag = data[pos];
        let len = data[pos + 1] as usize;
        let start = pos + 2;
        let end = start + len;
        if end > data.len() {
            break;
        }
        map.entry(tag)
            .or_default()
            .extend_from_slice(&data[start..end]);
        pos = end;
    }
    map
}

/// Left-pads a big-endian byte slice with zeroes to `target_len` bytes.
fn pad_be(bytes: &[u8], target_len: usize) -> Vec<u8> {
    if bytes.len() >= target_len {
        bytes[bytes.len() - target_len..].to_vec()
    } else {
        let mut padded = vec![0u8; target_len - bytes.len()];
        padded.extend_from_slice(bytes);
        padded
    }
}

/// Result of processing the HomePod SRP-6a M2 challenge.
#[derive(Debug, Clone)]
pub struct SrpExchangeResult {
    /// 64-byte shared secret key derived from SRP premaster secret K = SHA512(S).
    pub shared_key: [u8; 64],
    /// 64-byte client proof M1 sent in M3 request.
    pub client_proof_m1: [u8; 64],
    /// 64-byte expected server proof M2 to verify against M4 response.
    pub expected_server_proof_m2: [u8; 64],
}

/// SRP-6a 3072-bit (SHA-512) Transient Client.
///
/// Implements RFC 5054 with:
/// - Username: `"Pair-Setup"`
/// - Password (PIN): `"3939"`
/// - Generator: `g = 5`
/// - Prime: RFC 5054 3072-bit N
/// - Hash: SHA-512
pub struct HapSrpClient {
    a_priv: BigUint,
    a_pub_bytes: Vec<u8>,
}

impl Default for HapSrpClient {
    fn default() -> Self {
        Self::new()
    }
}

impl HapSrpClient {
    /// Creates a new SRP client with an ephemeral cryptographically secure 256-bit private key `a`.
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let mut a_bytes = [0u8; 32];
        rng.fill_bytes(&mut a_bytes);
        Self::with_private_key(&a_bytes)
    }

    /// Initializes SRP client with an explicit private key (useful for deterministic tests).
    pub fn with_private_key(private_bytes: &[u8]) -> Self {
        let a_priv = BigUint::from_bytes_be(private_bytes);
        let n = BigUint::from_bytes_be(&PRIME_3072_BYTES);
        let g = BigUint::from(5u32);
        let a_pub = g.modpow(&a_priv, &n);
        let a_pub_bytes = a_pub.to_bytes_be();
        Self {
            a_priv,
            a_pub_bytes,
        }
    }

    /// Returns the client public key `A = g^a % N` serialized as big-endian bytes.
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.a_pub_bytes
    }

    /// Processes server public key `B` and `salt` received from HomePod in M2,
    /// calculating the client proof `M1`, expected server proof `M2`, and session key `K`.
    pub fn process_server_response(
        &self,
        b_pub_bytes: &[u8],
        salt: &[u8],
    ) -> Result<SrpExchangeResult, SonusError> {
        let n = BigUint::from_bytes_be(&PRIME_3072_BYTES);
        let b_pub = BigUint::from_bytes_be(b_pub_bytes);
        let zero = BigUint::from(0u32);

        if &b_pub % &n == zero {
            return Err(SonusError::Crypto(
                "Server public key mod N is zero".to_string(),
            ));
        }

        // k = H(N | PAD(g))
        let mut k_hasher = Sha512::new();
        k_hasher.update(PRIME_3072_BYTES);
        k_hasher.update(pad_be(&[5], 384));
        let k = BigUint::from_bytes_be(&k_hasher.finalize());

        // x = H(s | H(I | ":" | P))
        let inner_hash = Sha512::digest(b"Pair-Setup:3939");
        let mut x_hasher = Sha512::new();
        x_hasher.update(salt);
        x_hasher.update(inner_hash);
        let x = BigUint::from_bytes_be(&x_hasher.finalize());

        // v = g^x % N
        let g = BigUint::from(5u32);
        let v = g.modpow(&x, &n);

        // u = H(PAD(A) | PAD(B))
        let pad_a = pad_be(&self.a_pub_bytes, 384);
        let pad_b = pad_be(b_pub_bytes, 384);
        let mut u_hasher = Sha512::new();
        u_hasher.update(&pad_a);
        u_hasher.update(&pad_b);
        let u = BigUint::from_bytes_be(&u_hasher.finalize());
        if u == zero {
            return Err(SonusError::Crypto("SRP u value is zero".to_string()));
        }

        // S = (B - k * v) ^ (a + u * x) % N
        let kv = (&k * &v) % &n;
        let base = if b_pub >= kv {
            (&b_pub - &kv) % &n
        } else {
            &n - (&kv - &b_pub) % &n
        };
        let exp = &self.a_priv + (&u * &x);
        let s = base.modpow(&exp, &n);

        // K = H(S)
        let s_bytes = s.to_bytes_be();
        let session_key = Sha512::digest(&s_bytes);

        // M1 = H(H(N) ^ H(g) | H(U) | s | A | B | K)
        let h_n = Sha512::digest(PRIME_3072_BYTES);
        let h_g = Sha512::digest([0x05]);
        let mut xor_bytes = [0u8; 64];
        for i in 0..64 {
            xor_bytes[i] = h_n[i] ^ h_g[i];
        }
        let h_user = Sha512::digest(b"Pair-Setup");

        let mut m1_hasher = Sha512::new();
        m1_hasher.update(xor_bytes);
        m1_hasher.update(h_user);
        m1_hasher.update(salt);
        m1_hasher.update(&self.a_pub_bytes);
        m1_hasher.update(b_pub_bytes);
        m1_hasher.update(session_key);
        let m1 = m1_hasher.finalize();

        // Expected M2 = H(A | M1 | K)
        let mut m2_hasher = Sha512::new();
        m2_hasher.update(&self.a_pub_bytes);
        m2_hasher.update(m1);
        m2_hasher.update(session_key);
        let m2 = m2_hasher.finalize();

        let mut shared_key_arr = [0u8; 64];
        shared_key_arr.copy_from_slice(&session_key);

        let mut m1_arr = [0u8; 64];
        m1_arr.copy_from_slice(&m1);

        let mut m2_arr = [0u8; 64];
        m2_arr.copy_from_slice(&m2);

        Ok(SrpExchangeResult {
            shared_key: shared_key_arr,
            client_proof_m1: m1_arr,
            expected_server_proof_m2: m2_arr,
        })
    }
}

/// Derives a 32-byte key using RFC 5869 HKDF-SHA512.
pub fn hkdf_sha512(salt: &[u8], info: &[u8], ikm: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha512>::new(Some(salt), ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .expect("32 bytes is valid length for HKDF-SHA512");
    okm
}

/// HAP framing cipher managing ChaCha20-Poly1305 state across 1024-byte chunks.
///
/// Each chunk is framed on the wire as:
/// - 2 bytes: little-endian payload length `len_le` (up to 1024)
/// - `len` bytes ciphertext + 16 bytes Poly1305 authentication tag
///
/// Nonces are 12 bytes: 4 zero bytes followed by monotonic 8-byte little-endian counters.
pub struct HapSession {
    out_cipher: ChaCha20Poly1305,
    in_cipher: ChaCha20Poly1305,
    out_counter: u64,
    in_counter: u64,
    dec_buffer: Vec<u8>,
}

impl HapSession {
    /// Creates a new HAP session cipher with 32-byte outgoing write key and incoming read key.
    pub fn new(write_key: &[u8; 32], read_key: &[u8; 32]) -> Self {
        Self {
            out_cipher: ChaCha20Poly1305::new(Key::from_slice(write_key)),
            in_cipher: ChaCha20Poly1305::new(Key::from_slice(read_key)),
            out_counter: 0,
            in_counter: 0,
            dec_buffer: Vec::new(),
        }
    }

    /// Construct 12-byte nonce: `[0, 0, 0, 0, counter.to_le_bytes()]`.
    fn make_nonce(counter: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&counter.to_le_bytes());
        nonce
    }

    /// Encrypts outgoing TCP data in chunks of up to 1024 bytes.
    ///
    /// For each chunk:
    /// - 2-byte little-endian length `len_le`
    /// - ChaCha20Poly1305 ciphertext with `len_le` passed as AAD
    /// - Monotonic `out_counter` incremented per block
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, SonusError> {
        if plaintext.is_empty() {
            return Ok(Vec::new());
        }

        let chunk_count = plaintext.len().div_ceil(1024);
        let mut output = Vec::with_capacity(plaintext.len() + chunk_count * 18);

        for chunk in plaintext.chunks(1024) {
            let len_le = (chunk.len() as u16).to_le_bytes();
            let nonce_bytes = Self::make_nonce(self.out_counter);
            self.out_counter = self.out_counter.wrapping_add(1);

            let nonce = Nonce::from_slice(&nonce_bytes);
            let payload = Payload {
                msg: chunk,
                aad: &len_le,
            };

            let ciphertext = self
                .out_cipher
                .encrypt(nonce, payload)
                .map_err(|e| SonusError::Crypto(format!("HAP frame encryption failed: {e}")))?;

            output.extend_from_slice(&len_le);
            output.extend_from_slice(&ciphertext);
        }

        Ok(output)
    }

    /// Decrypts incoming TCP stream buffer.
    ///
    /// Reads 2-byte little-endian length `L`, waits until `2 + L + 16` bytes are buffered,
    /// decrypts with `aad = &len_le` and `in_counter`, and advances the buffer.
    pub fn decrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, SonusError> {
        self.dec_buffer.extend_from_slice(input);
        let mut output = Vec::new();

        while self.dec_buffer.len() >= 2 {
            let chunk_len = u16::from_le_bytes([self.dec_buffer[0], self.dec_buffer[1]]) as usize;
            let total_frame_len = 2 + chunk_len + 16;
            if self.dec_buffer.len() < total_frame_len {
                break;
            }

            let len_le = [self.dec_buffer[0], self.dec_buffer[1]];
            let ciphertext_and_tag = &self.dec_buffer[2..total_frame_len];
            let nonce_bytes = Self::make_nonce(self.in_counter);
            self.in_counter = self.in_counter.wrapping_add(1);

            let nonce = Nonce::from_slice(&nonce_bytes);
            let payload = Payload {
                msg: ciphertext_and_tag,
                aad: &len_le,
            };

            let plaintext = self
                .in_cipher
                .decrypt(nonce, payload)
                .map_err(|e| SonusError::Crypto(format!("HAP frame decryption failed: {e}")))?;

            output.extend_from_slice(&plaintext);
            self.dec_buffer.drain(0..total_frame_len);
        }

        Ok(output)
    }

    /// Returns true if unparsed bytes remain in the internal decryption buffer.
    pub fn has_buffered_bytes(&self) -> bool {
        !self.dec_buffer.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tlv8_roundtrip() {
        let original_data = vec![0x42u8; 300]; // Longer than 255 bytes to test chunking
        let entries = [
            (TlvTag::Method as u8, &[0x00u8][..]),
            (TlvTag::SeqNo as u8, &[0x01u8][..]),
            (TlvTag::PublicKey as u8, &original_data[..]),
        ];

        let encoded = encode_tlv8(&entries);
        assert!(encoded.len() > 300);

        let decoded = decode_tlv8(&encoded);
        assert_eq!(decoded.get(&(TlvTag::Method as u8)).unwrap(), &[0x00]);
        assert_eq!(decoded.get(&(TlvTag::SeqNo as u8)).unwrap(), &[0x01]);
        assert_eq!(
            decoded.get(&(TlvTag::PublicKey as u8)).unwrap(),
            &original_data
        );
    }

    #[test]
    fn test_srp_against_python_test_vector() {
        // Test vector generated with srptools SRPContext('Pair-Setup', '3939')
        let a_priv_bytes = [0x01u8; 32];
        let client = HapSrpClient::with_private_key(&a_priv_bytes);

        let b_pub = [0x02u8; 384];
        let salt = [0x03u8; 16];

        let result = client.process_server_response(&b_pub, &salt).unwrap();

        let expected_m1 = [
            0x30, 0x04, 0xa1, 0x0f, 0x4d, 0xf8, 0x10, 0x48, 0x8f, 0x42, 0x22, 0x0c, 0xd9, 0x73,
            0x2a, 0xa5, 0xf9, 0xd9, 0xbf, 0xf5, 0x2d, 0x56, 0x13, 0x29, 0x10, 0x33, 0x4b, 0x23,
            0x33, 0xcc, 0xb5, 0x93, 0xd5, 0xc8, 0xcb, 0xe5, 0x70, 0x9b, 0x7d, 0xf0, 0xcc, 0xc3,
            0xb4, 0xf9, 0xe1, 0x5c, 0xb4, 0x92, 0xa8, 0x4e, 0x53, 0xe5, 0xfc, 0x97, 0x7e, 0x47,
            0xef, 0x83, 0x35, 0x15, 0xde, 0xf1, 0xb8, 0x19,
        ];
        assert_eq!(result.client_proof_m1, expected_m1);

        let expected_m2 = [
            0x1a, 0x3c, 0x6a, 0x97, 0xa0, 0xc8, 0xec, 0x0f, 0x8b, 0xa3, 0xe0, 0x8d, 0x38, 0xbb,
            0xab, 0x52, 0xa2, 0x26, 0x16, 0xb0, 0x84, 0x09, 0x83, 0x20, 0x61, 0x4e, 0xb4, 0x88,
            0xac, 0xda, 0x14, 0xac, 0x33, 0x17, 0x37, 0xb7, 0x5f, 0x3f, 0xdc, 0x01, 0x93, 0xc9,
            0x56, 0xa0, 0x55, 0x07, 0x0f, 0x0e, 0x35, 0x51, 0x4e, 0x1b, 0x95, 0x45, 0x8a, 0xc1,
            0x1d, 0x1a, 0xee, 0x11, 0xf1, 0xc3, 0x56, 0xc5,
        ];
        assert_eq!(result.expected_server_proof_m2, expected_m2);

        let expected_k = [
            0x8e, 0x3c, 0xd6, 0x5e, 0x4d, 0x3f, 0xe7, 0x1d, 0x16, 0x80, 0xa4, 0x8b, 0x4d, 0x45,
            0x9e, 0x3e, 0x83, 0x19, 0x6a, 0x62, 0xb7, 0x7f, 0xf9, 0xb7, 0x30, 0x44, 0x1a, 0xa6,
            0x80, 0x0c, 0x94, 0x3e, 0x21, 0x6c, 0xdd, 0xfc, 0x98, 0x0f, 0x52, 0xb2, 0x72, 0x77,
            0x65, 0x3b, 0x77, 0x08, 0x45, 0x92, 0x1b, 0x1c, 0x27, 0x30, 0x20, 0x3c, 0x78, 0x16,
            0x27, 0x2e, 0x83, 0xa8, 0xd2, 0xa1, 0xdf, 0x37,
        ];
        assert_eq!(result.shared_key, expected_k);
    }

    #[test]
    fn test_hkdf_sha512() {
        let salt = b"Control-Salt";
        let info = b"Control-Write-Encryption-Key";
        let ikm = [0x30u8; 64];
        let derived = hkdf_sha512(salt, info, &ikm);
        assert_eq!(derived.len(), 32);
    }

    #[test]
    fn test_hap_session_roundtrip() {
        let key_a = [0x11u8; 32];
        let key_b = [0x22u8; 32];

        let mut client_session = HapSession::new(&key_a, &key_b);
        let mut server_session = HapSession::new(&key_b, &key_a);

        let plaintext = vec![0xa5u8; 2500]; // Multiple chunks (> 2 * 1024)
        let encrypted = client_session.encrypt(&plaintext).unwrap();

        // Feed encrypted in 27-byte slices to test fragmentation and reassembly
        let mut decrypted = Vec::new();
        for chunk in encrypted.chunks(27) {
            let part = server_session.decrypt(chunk).unwrap();
            decrypted.extend_from_slice(&part);
        }

        assert_eq!(decrypted, plaintext);
    }
}
