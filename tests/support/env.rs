#![allow(dead_code)]

use std::env;
use std::sync::{Mutex, MutexGuard, OnceLock};

static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

/// RAII guard that serialises environment mutations for tests.
pub struct EnvVarGuard {
    key: &'static str,
    original: Option<String>,
    _lock: MutexGuard<'static, ()>,
}

impl EnvVarGuard {
    fn acquire_lock() -> MutexGuard<'static, ()> {
        ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    /// Sets the provided environment variable and restores the original value on drop.
    pub fn set(key: &'static str, value: &str) -> Self {
        let lock = Self::acquire_lock();
        let original = env::var(key).ok();
        env::set_var(key, value);
        Self {
            key,
            original,
            _lock: lock,
        }
    }

    /// Clears the provided environment variable and restores the original value on drop.
    pub fn clear(key: &'static str) -> Self {
        let lock = Self::acquire_lock();
        let original = env::var(key).ok();
        env::remove_var(key);
        Self {
            key,
            original,
            _lock: lock,
        }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        if let Some(value) = &self.original {
            env::set_var(self.key, value);
        } else {
            env::remove_var(self.key);
        }
    }
}
