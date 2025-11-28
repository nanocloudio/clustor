use crate::replication::consensus::DurabilityProof;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitVisibility {
    DurableOnly,
    CommitAllowsPreDurable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadGateClause {
    StrictFallback,
    CommitVisibility,
    CacheNotFresh,
    ControlPlaneProofMismatch,
    IndexInequality,
}

impl ReadGateClause {
    pub fn metric_id(self) -> u64 {
        match self {
            ReadGateClause::StrictFallback => 1,
            ReadGateClause::CommitVisibility => 2,
            ReadGateClause::CacheNotFresh => 3,
            ReadGateClause::ControlPlaneProofMismatch => 4,
            ReadGateClause::IndexInequality => 5,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadGateTelemetry {
    pub can_serve: bool,
    pub failed_clause: Option<ReadGateClause>,
}

impl ReadGateTelemetry {
    pub fn allowed() -> Self {
        Self {
            can_serve: true,
            failed_clause: None,
        }
    }

    pub fn blocked(clause: ReadGateClause) -> Self {
        Self {
            can_serve: false,
            failed_clause: Some(clause),
        }
    }

    pub fn clause_metric(&self) -> u64 {
        self.failed_clause
            .map(|clause| clause.metric_id())
            .unwrap_or(0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadGateInputs {
    pub commit_visibility: CommitVisibility,
    pub wal_committed_index: u64,
    pub raft_commit_index: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadGateDecision {
    pub allowed: bool,
    pub failed_clause: Option<ReadGateClause>,
    pub telemetry: ReadGateTelemetry,
}

pub struct ReadGateEvaluator;

impl ReadGateEvaluator {
    pub fn evaluate(
        strict_fallback: bool,
        cache_fresh: bool,
        ledger_proof: Option<DurabilityProof>,
        published_proof: Option<DurabilityProof>,
        inputs: &ReadGateInputs,
    ) -> ReadGateDecision {
        if strict_fallback {
            return Self::blocked(ReadGateClause::StrictFallback);
        }
        if !cache_fresh {
            return Self::blocked(ReadGateClause::CacheNotFresh);
        }
        if inputs.commit_visibility == CommitVisibility::CommitAllowsPreDurable {
            return Self::blocked(ReadGateClause::CommitVisibility);
        }
        match (ledger_proof, published_proof) {
            (Some(local), Some(published)) if local == published => {}
            _ => return Self::blocked(ReadGateClause::ControlPlaneProofMismatch),
        }
        if inputs.wal_committed_index != inputs.raft_commit_index {
            return Self::blocked(ReadGateClause::IndexInequality);
        }
        Self::allowed()
    }

    fn allowed() -> ReadGateDecision {
        ReadGateDecision {
            allowed: true,
            failed_clause: None,
            telemetry: ReadGateTelemetry::allowed(),
        }
    }

    fn blocked(clause: ReadGateClause) -> ReadGateDecision {
        ReadGateDecision {
            allowed: false,
            failed_clause: Some(clause),
            telemetry: ReadGateTelemetry::blocked(clause),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proof(term: u64, index: u64) -> DurabilityProof {
        DurabilityProof::new(term, index)
    }

    #[test]
    fn evaluates_success_when_predicate_passes() {
        let inputs = ReadGateInputs {
            commit_visibility: CommitVisibility::DurableOnly,
            wal_committed_index: 10,
            raft_commit_index: 10,
        };
        let decision = ReadGateEvaluator::evaluate(
            false,
            true,
            Some(proof(1, 10)),
            Some(proof(1, 10)),
            &inputs,
        );
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
        let decision = ReadGateEvaluator::evaluate(
            false,
            true,
            Some(proof(1, 10)),
            Some(proof(1, 10)),
            &inputs,
        );
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
        let decision = ReadGateEvaluator::evaluate(
            false,
            true,
            Some(proof(1, 10)),
            Some(proof(2, 10)),
            &inputs,
        );
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
        let decision = ReadGateEvaluator::evaluate(
            false,
            true,
            Some(proof(1, 10)),
            Some(proof(1, 10)),
            &inputs,
        );
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
        let decision = ReadGateEvaluator::evaluate(
            true,
            true,
            Some(proof(1, 10)),
            Some(proof(1, 10)),
            &inputs,
        );
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
}
