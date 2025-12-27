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
