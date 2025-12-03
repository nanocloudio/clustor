#![cfg(feature = "net")]

mod core;

#[cfg_attr(not(feature = "admin-http"), allow(unused_imports))]
pub(crate) use core::{lock_or_poison, spawn_listener, ServerHandle};
