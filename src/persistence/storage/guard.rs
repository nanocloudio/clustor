use crate::lifecycle::bootstrap::probe::{
    FsyncProbeResult, GroupFsyncDecision, GroupFsyncGuard, GroupFsyncGuardConfig,
};
use crate::terminology::{RuntimeTerm, TERM_GROUP_FSYNC, TERM_STRICT};
use log::{info, warn};

const GROUP_FSYNC_SPEC: &str = "§6.2.GroupFsync";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsyncMode {
    Strict,
    Group,
}

impl FsyncMode {
    pub fn runtime_term(&self) -> RuntimeTerm {
        match self {
            FsyncMode::Strict => TERM_STRICT,
            FsyncMode::Group => TERM_GROUP_FSYNC,
        }
    }
}

#[derive(Debug)]
pub struct GroupFsyncPolicy {
    history: Vec<FsyncProbeResult>,
    mode: FsyncMode,
    config: GroupFsyncGuardConfig,
}

impl GroupFsyncPolicy {
    pub fn new(config: GroupFsyncGuardConfig) -> Self {
        Self {
            history: Vec::new(),
            mode: FsyncMode::Strict,
            config,
        }
    }

    pub fn record_probe(&mut self, result: FsyncProbeResult) {
        self.history.push(result);
        if self.history.len() > 8 {
            self.history.remove(0);
        }
        let previous = self.mode;
        match GroupFsyncGuard::evaluate(&self.history, self.config) {
            GroupFsyncDecision::Eligible => {
                self.mode = FsyncMode::Group;
            }
            GroupFsyncDecision::ForceStrict(reason) => {
                self.mode = FsyncMode::Strict;
                warn!(
                    "event=group_fsync_guard clause={} io_writer_mode_gate_state=Strict reason={:?}",
                    GROUP_FSYNC_SPEC,
                    reason
                );
            }
        }
        if previous != self.mode {
            info!(
                "event=group_fsync_mode clause={} io_writer_mode_gate_state={:?} previous_mode={:?}",
                GROUP_FSYNC_SPEC,
                self.mode,
                previous
            );
        }
    }

    pub fn mode(&self) -> FsyncMode {
        self.mode
    }

    pub fn telemetry(&self) -> GroupFsyncPolicyTelemetry {
        GroupFsyncPolicyTelemetry {
            mode: self.mode,
            mode_term: self.mode.runtime_term(),
            recent_probes: self.history.len(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupFsyncPolicyTelemetry {
    pub mode: FsyncMode,
    pub mode_term: RuntimeTerm,
    pub recent_probes: usize,
}
