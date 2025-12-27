#![cfg(feature = "net")]

use clustor::net::RequestDeadline;
use std::time::{Duration, Instant};

pub fn expired_deadline() -> RequestDeadline {
    RequestDeadline::from_deadline(Instant::now() - Duration::from_secs(1))
}

pub fn short_deadline() -> RequestDeadline {
    RequestDeadline::from_deadline(Instant::now() + Duration::from_millis(5))
}
