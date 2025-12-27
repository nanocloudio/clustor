use clustor::control_plane::core::{
    CommitVisibility, ReadGateClause, ReadGateEvaluator, ReadGateInputs, ReadGateTelemetry,
};
use clustor::replication::consensus::DurabilityProof;

#[test]
fn evaluates_success_when_predicate_passes() {
    let inputs = ReadGateInputs {
        commit_visibility: CommitVisibility::DurableOnly,
        wal_committed_index: 10,
        raft_commit_index: 10,
    };
    let decision =
        ReadGateEvaluator::evaluate(false, true, Some(proof(1, 10)), Some(proof(1, 10)), &inputs);
    assert!(decision.allowed);
    assert!(decision.failed_clause.is_none());
    assert_eq!(decision.telemetry, ReadGateTelemetry::allowed());
}

#[test]
fn detects_commit_visibility_violation() {
    let inputs = ReadGateInputs {
        commit_visibility: CommitVisibility::CommitAllowsPreDurable,
        wal_committed_index: 10,
        raft_commit_index: 10,
    };
    let decision =
        ReadGateEvaluator::evaluate(false, true, Some(proof(1, 10)), Some(proof(1, 10)), &inputs);
    assert!(!decision.allowed);
    assert_eq!(
        decision.failed_clause,
        Some(ReadGateClause::CommitVisibility)
    );
}

#[test]
fn detects_proof_mismatch() {
    let inputs = ReadGateInputs {
        commit_visibility: CommitVisibility::DurableOnly,
        wal_committed_index: 10,
        raft_commit_index: 10,
    };
    let decision =
        ReadGateEvaluator::evaluate(false, true, Some(proof(1, 10)), Some(proof(2, 10)), &inputs);
    assert!(!decision.allowed);
    assert_eq!(
        decision.failed_clause,
        Some(ReadGateClause::ControlPlaneProofMismatch)
    );
}

#[test]
fn detects_index_inequality() {
    let inputs = ReadGateInputs {
        commit_visibility: CommitVisibility::DurableOnly,
        wal_committed_index: 9,
        raft_commit_index: 10,
    };
    let decision =
        ReadGateEvaluator::evaluate(false, true, Some(proof(1, 10)), Some(proof(1, 10)), &inputs);
    assert!(!decision.allowed);
    assert_eq!(
        decision.failed_clause,
        Some(ReadGateClause::IndexInequality)
    );
}

#[test]
fn detects_cache_state_and_strict_fallback() {
    let inputs = ReadGateInputs {
        commit_visibility: CommitVisibility::DurableOnly,
        wal_committed_index: 10,
        raft_commit_index: 10,
    };
    let decision =
        ReadGateEvaluator::evaluate(true, true, Some(proof(1, 10)), Some(proof(1, 10)), &inputs);
    assert_eq!(decision.failed_clause, Some(ReadGateClause::StrictFallback));

    let decision = ReadGateEvaluator::evaluate(
        false,
        false,
        Some(proof(1, 10)),
        Some(proof(1, 10)),
        &inputs,
    );
    assert_eq!(decision.failed_clause, Some(ReadGateClause::CacheNotFresh));
}

#[test]
fn telemetry_labels_failed_clause() {
    let telemetry = ReadGateTelemetry::blocked(ReadGateClause::CacheNotFresh);
    assert!(!telemetry.can_serve);
    assert_eq!(telemetry.failed_clause, Some(ReadGateClause::CacheNotFresh));
    assert_eq!(telemetry.clause_metric(), 3);
}

fn proof(term: u64, index: u64) -> DurabilityProof {
    DurabilityProof::new(term, index)
}
