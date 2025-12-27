#![cfg(feature = "net")]

mod core;

#[cfg(feature = "admin-http")]
pub(crate) use core::lock_or_poison;
pub(crate) use core::{spawn_listener, ServerHandle};
