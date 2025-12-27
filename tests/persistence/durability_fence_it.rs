use clustor::persistence::durability::fence::{DrFenceError, DrFenceManager};

#[test]
fn dr_fence_commits_when_all_ack() {
    let mut manager = DrFenceManager::new();
    manager
        .begin(7, "manifest", ["a", "b"])
        .expect("fence accepted");
    manager.ack(7, "a").unwrap();
    assert!(!manager.is_committed());
    manager.ack(7, "b").unwrap();
    assert!(manager.is_committed());
}

#[test]
fn dr_fence_rejects_unknown_participant() {
    let mut manager = DrFenceManager::new();
    manager.begin(1, "m", ["a"]).unwrap();
    let err = manager.ack(1, "z").unwrap_err();
    assert!(matches!(
        err,
        DrFenceError::UnknownParticipant { participant }
        if participant == "z"
    ));
}
