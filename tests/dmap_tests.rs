//! Unit tests verifying DMAP binary encoding and decoding for Apple HomePod DACP.

use sonus_rs::dacp::{
    build_playstatus_update, decode_dmap_tags,
    dmap::{container_tag, string_tag, uint16_tag, uint32_tag, uint8_tag},
    PlaybackState,
};

#[test]
fn test_primitive_dmap_tags() {
    let t_u8 = uint8_tag(b"caps", 2);
    assert_eq!(&t_u8[0..4], b"caps");
    assert_eq!(&t_u8[4..8], &1u32.to_be_bytes());
    assert_eq!(t_u8[8], 2);

    let t_u16 = uint16_tag(b"mstt", 200);
    assert_eq!(&t_u16[0..4], b"mstt");
    assert_eq!(&t_u16[4..8], &2u32.to_be_bytes());
    assert_eq!(&t_u16[8..10], &200u16.to_be_bytes());

    let t_u32 = uint32_tag(b"cmsr", 1024);
    assert_eq!(&t_u32[0..4], b"cmsr");
    assert_eq!(&t_u32[4..8], &4u32.to_be_bytes());
    assert_eq!(&t_u32[8..12], &1024u32.to_be_bytes());

    let t_str = string_tag(b"cann", "Sonus Live Audio");
    assert_eq!(&t_str[0..4], b"cann");
    assert_eq!(
        &t_str[4..8],
        &("Sonus Live Audio".len() as u32).to_be_bytes()
    );
    assert_eq!(&t_str[8..], b"Sonus Live Audio");
}

#[test]
fn test_container_and_decoder() {
    let mut inner = Vec::new();
    inner.extend_from_slice(&uint32_tag(b"mstt", 200));
    inner.extend_from_slice(&string_tag(b"cann", "Test Track"));
    let container = container_tag(b"cmst", &inner);

    let parsed = decode_dmap_tags(&container).unwrap();
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].code_str(), "cmst");

    let inner_tags = decode_dmap_tags(&parsed[0].data).unwrap();
    assert_eq!(inner_tags.len(), 2);
    assert_eq!(inner_tags[0].code_str(), "mstt");
    assert_eq!(inner_tags[0].as_u32().unwrap(), 200);
    assert_eq!(inner_tags[1].code_str(), "cann");
    assert_eq!(inner_tags[1].as_string().unwrap(), "Test Track");
}

#[test]
fn test_playstatusupdate_schema() {
    let update = build_playstatus_update(55, PlaybackState::Paused);
    let tags = decode_dmap_tags(&update).unwrap();
    assert_eq!(tags.len(), 1);

    let cmst = &tags[0];
    assert_eq!(cmst.code_str(), "cmst");

    let children = decode_dmap_tags(&cmst.data).unwrap();
    assert_eq!(children.len(), 4);

    // Status: 200 OK
    assert_eq!(children[0].code_str(), "mstt");
    assert_eq!(children[0].as_u32().unwrap(), 200);

    // Revision: 55
    assert_eq!(children[1].code_str(), "cmsr");
    assert_eq!(children[1].as_u32().unwrap(), 55);

    // Playback state: Paused (3)
    assert_eq!(children[2].code_str(), "caps");
    assert_eq!(children[2].as_u8().unwrap(), 3);

    // Volume controllable: true (1)
    assert_eq!(children[3].code_str(), "cavc");
    assert_eq!(children[3].as_u8().unwrap(), 1);
}
