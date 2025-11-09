use clustor::{
    SnapshotFallbackController, SnapshotReadError, SnapshotReadRequest, SnapshotReadiness,
    StrictFallbackState,
};

fn readiness() -> SnapshotReadiness {
    SnapshotReadiness {
        manifest_id: "m1".into(),
        base_index: 500,
        content_hash: "0xabc".into(),
        applied_index_snapshot: 450,
        last_advertised_ready_index: 500,
        manifest_generated_ms: 1_000,
    }
}

#[test]
fn snapshot_read_checkpoint_handles_cp_outage() {
    let ready = readiness();
    let controller = SnapshotFallbackController::new(ready.clone());
    let mut request = SnapshotReadRequest {
        partition_id: "p1".into(),
        read_semantics_snapshot_only: false,
        strict_state: StrictFallbackState::LocalOnly,
        cp_cache_age_ms: 120_000,
    };
    assert!(matches!(
        controller.handle_request(request.clone()),
        Err(SnapshotReadError::MissingSnapshotOnlyHeader)
    ));

    request.read_semantics_snapshot_only = true;
    request.strict_state = StrictFallbackState::Healthy;
    assert!(matches!(
        controller.handle_request(request.clone()),
        Err(SnapshotReadError::StrictStateUnavailable { .. })
    ));

    request.strict_state = StrictFallbackState::LocalOnly;
    let response = controller.handle_request(request.clone()).unwrap();
    assert!(response.headers.snapshot_only);
    assert_eq!(response.headers.cp_cache_age_ms, 120_000);

    let mut degraded = SnapshotFallbackController::new(ready.clone());
    degraded.update_readiness(SnapshotReadiness {
        applied_index_snapshot: 10,
        manifest_generated_ms: 500,
        ..ready.clone()
    });
    assert!(matches!(
        degraded.handle_request(request),
        Err(SnapshotReadError::SnapshotOnlyUnavailable)
    ));
}
