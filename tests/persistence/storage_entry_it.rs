use clustor::{EntryFrame, EntryFrameBuilder};

#[test]
fn entry_frame_encode_decode_round_trip() {
    let frame = EntryFrameBuilder::new(7, 42)
        .metadata(vec![1, 2, 3])
        .payload(b"hello".to_vec())
        .build();
    let bytes = frame.encode();
    let decoded = EntryFrame::decode(&bytes).expect("decode succeeds");
    assert_eq!(frame, decoded);
}
