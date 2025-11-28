use crate::feature_guard::FeatureGateState;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ReadyzCapabilityRecord {
    pub feature: &'static str,
    pub slug: &'static str,
    pub gate_state: FeatureGateState,
    pub predicate_digest: String,
    pub gate_state_digest: String,
}
