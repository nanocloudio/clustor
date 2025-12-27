//! Crate-internal re-exports that should never leak into the public API.
//!
//! New modules should add their internal-only types here instead of making them
//! `pub` or reaching across domains ad-hoc.

#[cfg(feature = "admin-http")]
pub(crate) mod admin {
    pub(crate) use crate::control_plane::admin::workflows_state::{
        DurabilityState, ShrinkPlanRecord, ShrinkTarget,
    };
}
