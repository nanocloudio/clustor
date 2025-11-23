use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

pub(crate) const LOG_BINARY_HEADER: [u8; 8] = *b"CLLOGv01";

#[derive(Debug, Clone, Copy)]
pub(crate) enum LogEncoding {
    Json,
    Binary,
}

impl LogEncoding {
    pub(crate) fn default_for_new_file() -> Self {
        match std::env::var("CLUSTOR_LOG_ENCODING") {
            Ok(value) if value.eq_ignore_ascii_case("binary") => LogEncoding::Binary,
            _ => LogEncoding::Json,
        }
    }

    pub(crate) fn detect(path: &Path) -> io::Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        let mut file = File::open(path)?;
        let mut header = [0u8; LOG_BINARY_HEADER.len()];
        let read = file.read(&mut header)?;
        if read < LOG_BINARY_HEADER.len() {
            return Ok(Some(LogEncoding::Json));
        }
        if header == LOG_BINARY_HEADER {
            Ok(Some(LogEncoding::Binary))
        } else {
            Ok(Some(LogEncoding::Json))
        }
    }
}
