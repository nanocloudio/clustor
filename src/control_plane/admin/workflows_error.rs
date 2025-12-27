use crate::control_plane::core::{CpGuardError, CpUnavailableResponse};
use thiserror::Error;

use super::api::DurabilityMode;

#[derive(Debug, Error)]
pub enum AdminError {
    #[error("partition not registered in placement cache")]
    UnknownPartition,
    #[error("control plane unavailable ({clause})")]
    CpUnavailable {
        clause: &'static str,
        response: Box<CpUnavailableResponse>,
    },
    #[error("mode conflict: requested {requested:?} while current is {current:?}")]
    ModeConflict {
        current: DurabilityMode,
        requested: DurabilityMode,
    },
    #[error("invalid shrink plan: {reason}")]
    InvalidShrinkPlan { reason: String },
    #[error("shrink plan {plan_id} already exists")]
    ShrinkPlanExists { plan_id: String },
    #[error("shrink plan {plan_id} not found")]
    ShrinkPlanNotFound { plan_id: String },
    #[error("shrink plan {plan_id} already armed")]
    ShrinkPlanActive { plan_id: String },
    #[error("shrink plan {plan_id} is cancelled")]
    ShrinkPlanCancelled { plan_id: String },
}

impl From<CpGuardError> for AdminError {
    fn from(err: CpGuardError) -> Self {
        match err {
            CpGuardError::Unavailable { clause, response } => {
                AdminError::CpUnavailable { clause, response }
            }
        }
    }
}
