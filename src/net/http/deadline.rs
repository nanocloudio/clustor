#![cfg(feature = "net")]

use super::response::write_timeout_response;
use crate::net::{HttpError, NetError};
use std::time::{Duration, Instant};

/// Tracks the absolute expiration for a single HTTP request.
///
/// Each connection stores a deadline so higher level handlers can short-circuit
/// expensive work and map timeouts into `HttpError::RequestTimeout`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RequestDeadline {
    expires_at: Instant,
}

impl RequestDeadline {
    pub(crate) fn from_timeout(timeout: Duration) -> Self {
        let bounded = if timeout.is_zero() {
            Duration::from_millis(1)
        } else {
            timeout
        };
        Self {
            expires_at: Instant::now() + bounded,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_deadline(expires_at: Instant) -> Self {
        Self { expires_at }
    }

    pub(crate) fn remaining(&self) -> Option<Duration> {
        self.expires_at.checked_duration_since(Instant::now())
    }

    pub(crate) fn is_expired(&self) -> bool {
        match self.remaining() {
            Some(remaining) => remaining.is_zero(),
            None => true,
        }
    }

    pub(crate) fn enforce(&self) -> Result<(), NetError> {
        if self.is_expired() {
            Err(NetError::from(HttpError::RequestTimeout))
        } else {
            Ok(())
        }
    }

    pub(crate) fn respond_if_expired(
        &self,
        stream: &mut (impl std::io::Write + ?Sized),
    ) -> Result<bool, NetError> {
        if self.enforce().is_err() {
            write_timeout_response(stream)?;
            return Ok(false);
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::RequestDeadline;
    use crate::net::{HttpError, NetError};
    use std::time::{Duration, Instant};

    #[test]
    fn expired_deadline_writes_timeout() {
        let deadline = RequestDeadline::with_deadline(Instant::now() - Duration::from_secs(1));
        let mut buffer = Vec::new();
        let expired = deadline
            .respond_if_expired(&mut buffer)
            .expect("writes response");
        assert!(!expired);
        let resp = String::from_utf8(buffer).expect("utf8");
        assert!(resp.contains("408"));
    }

    #[test]
    fn enforce_returns_error_when_expired() {
        let deadline = RequestDeadline::with_deadline(Instant::now() - Duration::from_secs(1));
        let err = deadline.enforce().expect_err("should error");
        match err {
            NetError::Http(HttpError::RequestTimeout) => {}
            other => panic!("unexpected error: {other}"),
        }
    }
}
