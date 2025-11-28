use std::time::Instant;

use super::envelope::{
    CreditHint, FlowDecision, FlowThrottleEnvelope, FlowThrottleReason, FlowThrottleState,
    IngestStatusCode,
};
use super::profile::FlowProfile;

#[derive(Debug, Clone, Copy)]
pub(crate) struct PidParams {
    pub(crate) kp: f64,
    pub(crate) ki: f64,
    pub(crate) kd: f64,
    pub(crate) derivative_tau_ms: f64,
    pub(crate) entry_credit_max: i64,
    pub(crate) byte_credit_max: i64,
    pub(crate) integral_clamp: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PidAutoTuneState {
    Enabled,
    Disabled,
    Revoked,
}

#[derive(Debug, Clone)]
pub struct DualCreditPidController {
    profile: FlowProfile,
    pub(crate) params: PidParams,
    pub(crate) integral: f64,
    last_error: f64,
    derivative_state: f64,
    last_sample: Option<Instant>,
    pub(crate) entry_credits: i64,
    pub(crate) byte_credits: i64,
    pub(crate) auto_tune_state: PidAutoTuneState,
}

impl DualCreditPidController {
    pub fn new(profile: FlowProfile) -> Self {
        let params = profile.params();
        Self {
            profile,
            params,
            integral: 0.0,
            last_error: 0.0,
            derivative_state: 0.0,
            last_sample: None,
            entry_credits: params.entry_credit_max / 2,
            byte_credits: 0,
            auto_tune_state: match profile {
                FlowProfile::Latency => PidAutoTuneState::Disabled,
                _ => PidAutoTuneState::Enabled,
            },
        }
    }

    pub fn profile(&self) -> FlowProfile {
        self.profile
    }

    pub fn record_sample(&mut self, setpoint: f64, observed: f64, now: Instant) -> FlowDecision {
        let dt = self
            .last_sample
            .map(|previous| now.saturating_duration_since(previous).as_secs_f64())
            .unwrap_or(1.0);
        let error = setpoint - observed;
        self.integral += error * dt;
        self.integral = self
            .integral
            .clamp(-self.params.integral_clamp, self.params.integral_clamp);
        let derivative = self.ema_derivative(error, dt);
        let raw_output =
            self.params.kp * error + self.params.ki * self.integral + self.params.kd * derivative;
        self.last_error = error;
        self.last_sample = Some(now);
        self.apply_output(raw_output);
        let credit_hint = self.credit_hint();
        let throttle_state = self.throttle_state();
        let ingest_status = self.ingest_status(&throttle_state);
        let throttle = FlowThrottleEnvelope::new(throttle_state, credit_hint, ingest_status);
        FlowDecision {
            entry_credits: self.entry_credits,
            entry_credit_max: self.params.entry_credit_max,
            byte_credits: self.byte_credits,
            byte_credit_max: self.params.byte_credit_max,
            applied_output: raw_output,
            throttle,
            credit_hint,
            ingest_status,
            pid_auto_tune_state: self.auto_tune_state,
        }
    }

    fn ema_derivative(&mut self, error: f64, dt: f64) -> f64 {
        if dt <= 0.0 || self.last_sample.is_none() {
            self.derivative_state = 0.0;
            return 0.0;
        }
        let raw = (error - self.last_error) / dt;
        let tau = (self.params.derivative_tau_ms / 1_000.0).max(f64::EPSILON);
        let alpha = dt / (tau + dt);
        self.derivative_state += alpha * (raw - self.derivative_state);
        self.derivative_state
    }

    fn apply_output(&mut self, output: f64) {
        let max_delta = (self
            .params
            .entry_credit_max
            .max(self.params.byte_credit_max)) as f64;
        let capped = output.clamp(-max_delta, max_delta);
        if capped >= 0.0 {
            let grant = capped.round() as i64;
            self.entry_credits = (self.entry_credits + grant).min(self.params.entry_credit_max);
            self.byte_credits = (self.byte_credits - grant).max(0);
        } else {
            let debt = (-capped).round() as i64;
            self.byte_credits = (self.byte_credits + debt).min(self.params.byte_credit_max);
            self.entry_credits = (self.entry_credits - debt).max(0);
        }
    }

    fn credit_hint(&self) -> CreditHint {
        let entry_ratio =
            (self.entry_credits as f64 / self.params.entry_credit_max as f64).clamp(0.0, 1.0);
        let byte_availability =
            1.0 - (self.byte_credits as f64 / self.params.byte_credit_max as f64);
        let byte_ratio = byte_availability.clamp(0.0, 1.0);
        if entry_ratio >= 0.75 && byte_ratio >= 0.75 {
            CreditHint::Recover
        } else if entry_ratio >= 0.25 && byte_ratio >= 0.25 {
            CreditHint::Hold
        } else {
            CreditHint::Shed
        }
    }

    fn ingest_status(&self, state: &FlowThrottleState) -> IngestStatusCode {
        match state {
            FlowThrottleState::Open => IngestStatusCode::Healthy,
            FlowThrottleState::Throttled(_) => IngestStatusCode::TransientBackpressure,
        }
    }

    fn throttle_state(&self) -> FlowThrottleState {
        if self.byte_credits > 0 {
            FlowThrottleState::Throttled(FlowThrottleReason::ByteCreditDebt {
                byte_credit: self.byte_credits,
            })
        } else if self.entry_credits == 0 {
            FlowThrottleState::Throttled(FlowThrottleReason::EntryCreditsDepleted)
        } else {
            FlowThrottleState::Open
        }
    }
}
