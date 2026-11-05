//! Unit tests verifying 352-sample RTP packetization, timing, framing, and cryptography.

use sonus_rs::config::{ENCRYPTED_RTP_PACKET_BYTES, PCM_PACKET_BYTES, SAMPLES_PER_FRAME};
use sonus_rs::pacer::{Packetizer, SilencePacer};
use sonus_rs::raop::AirPlayAudioCipher;

#[test]
fn test_rtp_timing_math() {
    // Each packet contains 352 samples at 44.1 kHz
    let duration = Packetizer::packet_duration();
    let expected_nanos = (352u128 * 1_000_000_000) / 44_100;
    assert_eq!(duration.as_nanos(), expected_nanos);
    assert_eq!(duration.as_nanos(), 7_981_859); // ~7.98 ms
}

#[test]
fn test_rtp_header_structure_and_rollover() {
    let session_id = 0xdeadbeef;
    let mut p = Packetizer::new(session_id).with_initial_seq(65534);

    // Packet 0: Seq 65534, Marker bit set (0xE0)
    let pkt0 = p.packetize(&[0x11; PCM_PACKET_BYTES]).unwrap();
    assert_eq!(pkt0.header[0], 0x80); // V=2
    assert_eq!(pkt0.header[1], 0xE0); // PT=96 with Marker bit
    assert_eq!(pkt0.sequence_number(), 65534);
    assert_eq!(pkt0.timestamp(), 0);
    assert_eq!(&pkt0.header[8..12], &session_id.to_be_bytes());

    // Packet 1: Seq 65535, Marker bit cleared (0x60)
    let pkt1 = p.packetize(&[0x22; PCM_PACKET_BYTES]).unwrap();
    assert_eq!(pkt1.header[1], 0x60);
    assert_eq!(pkt1.sequence_number(), 65535);
    assert_eq!(pkt1.timestamp(), SAMPLES_PER_FRAME as u32);

    // Packet 2: Seq rolls over from 65535 to 0
    let pkt2 = p.packetize(&[0x33; PCM_PACKET_BYTES]).unwrap();
    assert_eq!(pkt2.sequence_number(), 0);
    assert_eq!(pkt2.timestamp(), (SAMPLES_PER_FRAME * 2) as u32);
}

#[test]
fn test_rtp_payload_padding() {
    let mut p = Packetizer::new(0x42);
    // Submit only 100 bytes of audio instead of 1408
    let short_data = vec![0xAB; 100];
    let pkt = p.packetize(&short_data).unwrap();

    assert_eq!(pkt.payload().len(), PCM_PACKET_BYTES);
    assert_eq!(&pkt.payload()[..100], &short_data[..]);
    assert!(pkt.payload()[100..].iter().all(|&b| b == 0));
}

#[test]
fn test_chacha20_aead_wire_framing() {
    let key = [0x99u8; 32];
    let mut cipher = AirPlayAudioCipher::new(&key);
    let mut packetizer = Packetizer::new(0x12345678);

    let raw_pcm = vec![0x42u8; PCM_PACKET_BYTES];
    let rtp_packet = packetizer.packetize(&raw_pcm).unwrap();

    let encrypted_payload = cipher
        .encrypt_audio_payload(rtp_packet.header(), rtp_packet.payload())
        .unwrap();

    // 1408 (PCM) + 16 (Poly1305 MAC) + 8 (Nonce suffix) = 1432 bytes
    assert_eq!(encrypted_payload.len(), 1408 + 16 + 8);

    // Full packet on the wire includes 12-byte RTP header: 12 + 1432 = 1444 bytes
    let mut wire_packet = Vec::with_capacity(ENCRYPTED_RTP_PACKET_BYTES);
    wire_packet.extend_from_slice(rtp_packet.header());
    wire_packet.extend_from_slice(&encrypted_payload);

    assert_eq!(wire_packet.len(), ENCRYPTED_RTP_PACKET_BYTES);
    assert_eq!(wire_packet.len(), 1444);

    // Verify decryption round-trip
    let mut decrypt_cipher = AirPlayAudioCipher::new(&key);
    let decrypted = decrypt_cipher
        .decrypt_audio_payload(rtp_packet.header(), &encrypted_payload)
        .unwrap();

    assert_eq!(decrypted, raw_pcm);
}

#[test]
fn test_silence_pacer_pacing_and_timeout() {
    let mut pacer = SilencePacer::new(2); // 2 second timeout
    let mut packetizer = Packetizer::new(0xABC);

    // First silence tick
    let s1 = pacer
        .generate_silence_packet(&mut packetizer)
        .unwrap()
        .unwrap();
    assert_eq!(s1.payload().len(), PCM_PACKET_BYTES);
    assert!(s1.payload().iter().all(|&b| b == 0));
    assert_eq!(pacer.silence_packets_count(), 1);

    // Audio becomes active again -> reset
    pacer.reset_active();
    assert_eq!(pacer.silence_packets_count(), 0);
    assert!(!pacer.is_timed_out());
}
