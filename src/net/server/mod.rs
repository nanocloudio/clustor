#![cfg(feature = "net")]

mod core;

pub(crate) use core::{lock_or_poison, spawn_listener, ServerHandle};
