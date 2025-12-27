use super::api::{DurabilityMode, ShrinkPlanState, ShrinkPlanStatus, ShrinkTargetPlacement};
use std::fmt;

#[derive(Debug, Clone)]
pub(crate) struct DurabilityState {
    pub(crate) mode: DurabilityMode,
    pub(crate) epoch: u64,
}

impl DurabilityState {
    pub(crate) fn new() -> Self {
        Self {
            mode: DurabilityMode::Strict,
            epoch: 0,
        }
    }

    pub(crate) fn mode(&self) -> DurabilityMode {
        self.mode.clone()
    }

    pub(crate) fn epoch(&self) -> u64 {
        self.epoch
    }

    pub(crate) fn set_mode(&mut self, mode: DurabilityMode) {
        self.mode = mode;
        self.epoch = self.epoch.saturating_add(1);
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ShrinkTarget {
    pub prg_id: String,
    pub target_members: Vec<String>,
    pub target_routing_epoch: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct ShrinkPlanRecord {
    pub(crate) plan_id: String,
    pub(crate) targets: Vec<ShrinkTarget>,
    pub(crate) state: ShrinkPlanState,
    pub(crate) created_at_ms: u64,
    pub(crate) armed_at_ms: Option<u64>,
    pub(crate) cancelled_at_ms: Option<u64>,
}

impl ShrinkPlanRecord {
    pub(crate) fn new(plan_id: String, targets: Vec<ShrinkTarget>, created_at_ms: u64) -> Self {
        Self {
            plan_id,
            targets,
            state: ShrinkPlanState::Draft,
            created_at_ms,
            armed_at_ms: None,
            cancelled_at_ms: None,
        }
    }

    pub(crate) fn status(&self) -> ShrinkPlanStatus {
        ShrinkPlanStatus {
            plan_id: self.plan_id.clone(),
            state: self.state.clone(),
            target_placements: self
                .targets
                .iter()
                .map(|target| ShrinkTargetPlacement {
                    prg_id: target.prg_id.clone(),
                    target_members: target.target_members.clone(),
                    target_routing_epoch: target.target_routing_epoch,
                })
                .collect(),
            created_at_ms: self.created_at_ms,
            armed_at_ms: self.armed_at_ms,
            cancelled_at_ms: self.cancelled_at_ms,
        }
    }

    pub(crate) fn arm(&mut self, now_ms: u64) {
        self.state = ShrinkPlanState::Armed;
        self.armed_at_ms = Some(now_ms);
        self.cancelled_at_ms = None;
    }

    pub(crate) fn cancel(&mut self, now_ms: u64) {
        self.cancelled_at_ms = Some(now_ms);
        self.state = match self.state {
            ShrinkPlanState::Armed => ShrinkPlanState::RolledBack,
            ShrinkPlanState::Cancelled => ShrinkPlanState::Cancelled,
            _ => ShrinkPlanState::Cancelled,
        };
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ShrinkPlanTelemetry {
    pub total: usize,
    pub armed: usize,
    pub cancelled: usize,
}

impl fmt::Display for ShrinkPlanTelemetry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "total={} armed={} cancelled={}",
            self.total, self.armed, self.cancelled
        )
    }
}
