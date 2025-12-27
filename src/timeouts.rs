//! Centralized timeout and shutdown policies for async components.
//!
//! Keeping these values in one place makes it clear which parts of the system
//! share behaviour (HTTP deadlines, graceful shutdown windows, etc.) and gives
//! us a single knob to turn if we need to tighten or relax limits.

use std::time::Duration;

/// Maximum time an admin HTTP request is allowed to run.
pub const ADMIN_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Maximum time for Readyz/Why HTTP requests.
pub const CONTROL_PLANE_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Grace period granted to blocking servers when asked to shut down.
pub const SERVER_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// Shared helper for naming the Readyz request timeout.
pub const READYZ_REQUEST_TIMEOUT: Duration = CONTROL_PLANE_REQUEST_TIMEOUT;
/// Shared helper for naming the Why request timeout.
pub const WHY_REQUEST_TIMEOUT: Duration = CONTROL_PLANE_REQUEST_TIMEOUT;

/// Convenience wrapper around `tokio::time::timeout` that is only available
/// when the async runtime is enabled.
#[cfg(feature = "async-net")]
pub async fn with_timeout<F, T>(
    duration: Duration,
    fut: F,
) -> Result<T, tokio::time::error::Elapsed>
where
    F: std::future::Future<Output = T>,
{
    tokio::time::timeout(duration, fut).await
}
