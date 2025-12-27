use clustor::{EntryFrameBuilder, SegmentManager};

#[test]
fn segment_manager_flushes_in_order() {
    let mut manager = SegmentManager::with_capacity(32);
    manager.append(&EntryFrameBuilder::new(1, 1).payload(vec![0; 16]).build());
    manager.append(&EntryFrameBuilder::new(1, 2).payload(vec![0; 20]).build());
    manager.flush();
    let flushes = manager.drain_flushes();
    assert_eq!(flushes.len(), 2);
}
