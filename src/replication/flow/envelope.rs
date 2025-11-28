use serde::{Deserialize, Serialize};

use super::pid::PidAutoTuneState;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CreditHint {
    Recover,
    Hold,
    Shed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IngestStatusCode {
    Healthy,
    TransientBackpressure,
    PermanentDurability,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowThrottleState {
    Open,
    Throttled(FlowThrottleReason),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowThrottleReason {
    ByteCreditDebt { byte_credit: i64 },
    EntryCreditsDepleted,
    QuotaExceeded { tenant: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowThrottleEnvelope {
    pub state: FlowThrottleState,
    pub credit_hint: CreditHint,
    pub ingest_status: IngestStatusCode,
}

impl FlowThrottleEnvelope {
    pub fn new(
        state: FlowThrottleState,
        credit_hint: CreditHint,
        ingest_status: IngestStatusCode,
    ) -> Self {
        Self {
            state,
            credit_hint,
            ingest_status,
        }
    }

    pub fn explain(&self) -> String {
        match &self.state {
            FlowThrottleState::Open => "flow controller open".to_string(),
            FlowThrottleState::Throttled(reason) => match reason {
                FlowThrottleReason::ByteCreditDebt { byte_credit } => {
                    format!("byte credit debt {} exceeds PID allowance", byte_credit)
                }
                FlowThrottleReason::EntryCreditsDepleted => {
                    "entry credits depleted; throttle applied".to_string()
                }
                FlowThrottleReason::QuotaExceeded { tenant } => {
                    format!("tenant {tenant} exceeded quota; throttle enforced")
                }
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct FlowDecision {
    pub entry_credits: i64,
    pub entry_credit_max: i64,
    pub byte_credits: i64,
    pub byte_credit_max: i64,
    pub applied_output: f64,
    pub throttle: FlowThrottleEnvelope,
    pub credit_hint: CreditHint,
    pub ingest_status: IngestStatusCode,
    pub pid_auto_tune_state: PidAutoTuneState,
}

#[derive(Debug, Clone)]
pub struct FlowReadyzRecord {
    pub profile: super::profile::FlowProfile,
    pub pid_auto_tune_state: PidAutoTuneState,
    pub credit_hint: CreditHint,
    pub ingest_status: IngestStatusCode,
    pub entry_credits: i64,
    pub entry_credit_max: i64,
    pub byte_credits: i64,
    pub byte_credit_max: i64,
}
