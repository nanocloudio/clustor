use clustor::observability::system_log::SystemLogEntry;

#[test]
fn membership_change_round_trip() {
    let entry = SystemLogEntry::MembershipChange {
        old_members: vec!["a".into()],
        new_members: vec!["b".into(), "c".into()],
        routing_epoch: 7,
    };
    let encoded = entry.encode().expect("entry encodes");
    let decoded = SystemLogEntry::decode(&encoded).expect("entry decodes");
    assert_eq!(entry, decoded);
}

#[test]
fn rollback_with_optional_field() {
    let entry = SystemLogEntry::MembershipRollback {
        reason: "quorum".into(),
        failing_nodes: vec!["x".into()],
        override_ref: Some("ticket-1".into()),
    };
    let encoded = entry.encode().expect("entry encodes");
    assert_eq!(encoded[0], 0x02);
    let decoded = SystemLogEntry::decode(&encoded).expect("entry decodes");
    assert_eq!(entry, decoded);
}

#[test]
fn define_activate_round_trip() {
    let entry = SystemLogEntry::DefineActivate {
        bundle_id: "bundle-1".into(),
        barrier_id: "barrier-1".into(),
        partitions: vec!["p1".into(), "p2".into()],
        readiness_digest: "0xcafebabe".into(),
    };
    let encoded = entry.encode().expect("entry encodes");
    assert_eq!(encoded[0], 0x05);
    let decoded = SystemLogEntry::decode(&encoded).expect("entry decodes");
    assert_eq!(entry, decoded);
}
