use clustor::{
    bootstrap::{
        FsyncProbeResult, GroupFsyncDecision, GroupFsyncGuard, GroupFsyncGuardConfig,
        GuardrailReason,
    },
    cp::{CpProofCoordinator, CpUnavailableReason},
    ConsensusCore, ConsensusCoreConfig, DurabilityProof,
};
use std::time::{Duration, Instant};

#[test]
fn strict_fallback_demotion_and_probe_guardrail_checkpoint() {
    let config = ConsensusCoreConfig::new(Duration::from_millis(5), Duration::from_millis(8));
    let mut kernel = ConsensusCore::new(config);
    let start = Instant::now();
    kernel.enter_strict_fallback(DurabilityProof::new(5, 50), start);

    let status = kernel.status(start + Duration::from_millis(9));
    assert!(status.should_alert, "alert should trip before demotion");
    assert!(
        status.demotion.should_demote,
        "demotion timer should fire after configured window"
    );

    let history = vec![slow_probe(24), slow_probe(25), slow_probe(26)];
    let decision = GroupFsyncGuard::evaluate(&history, GroupFsyncGuardConfig::default());

    match decision {
        GroupFsyncDecision::ForceStrict(GuardrailReason::ProbeTooSlow {
            consecutive_failures,
            ..
        }) => assert!(
            consecutive_failures >= 3,
            "three slow probes should trigger strict guardrail"
        ),
        _ => panic!("slow probes must force Strict mode"),
    }

    let mut coordinator = CpProofCoordinator::new(kernel);
    let err = coordinator
        .guard_read_index(start + Duration::from_millis(10))
        .expect_err("ReadIndex should be blocked while LocalOnly persists");
    assert_eq!(
        err.response().reason,
        CpUnavailableReason::NeededForReadIndex
    );
}

fn slow_probe(p99_ms: u64) -> FsyncProbeResult {
    FsyncProbeResult {
        p99_ms,
        sample_count: 128,
        dataset_guid: "dataset-guid".into(),
        wal_path: "/wal".into(),
        device_serials: vec!["disk0".into()],
        measured_at_ms: 0,
    }
}
