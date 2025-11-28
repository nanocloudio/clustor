use crate::security::SecurityError;
use thiserror::Error;

#[cfg(feature = "net")]
use crate::net::NetError;

#[derive(Debug, Error)]
pub enum SerializationError {
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("storage I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Serialization(#[from] SerializationError),
    #[error("{0}")]
    Other(String),
}

impl From<serde_json::Error> for StorageError {
    fn from(err: serde_json::Error) -> Self {
        StorageError::Serialization(SerializationError::from(err))
    }
}

#[derive(Debug, Error)]
pub enum GuardError {
    #[cfg(feature = "net")]
    #[error(transparent)]
    Network(#[from] NetError),
    #[error(transparent)]
    Security(#[from] SecurityError),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Serialization(#[from] SerializationError),
    #[error("{0}")]
    Other(String),
}

#[derive(Debug, Error)]
pub enum ClustorError {
    #[error(transparent)]
    Guard(#[from] GuardError),
    #[cfg(feature = "net")]
    #[error(transparent)]
    Network(#[from] NetError),
    #[error(transparent)]
    Security(#[from] SecurityError),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Serialization(#[from] SerializationError),
    #[error("{0}")]
    Other(String),
}
