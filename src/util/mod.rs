//! Miscellaneous shared helpers (config paths, retry policies).

pub mod config;
pub mod error;
pub mod retry;

pub use config::{resolve_relative, state_dir_for_node};
pub use error::{ClustorError, GuardError, SerializationError, StorageError};
pub use retry::{RetryHandle, RetryPolicy, RetryStrategy};
