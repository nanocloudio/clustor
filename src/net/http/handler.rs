#![cfg(feature = "net")]

use super::RequestDeadline;
use crate::net::NetError;
use crate::security::Certificate;
use std::io::Write;

/// Shared metadata for handling a single HTTP request over an established TLS stream.
#[derive(Clone)]
pub(crate) struct HttpRequestContext {
    #[cfg_attr(not(feature = "admin-http"), allow(dead_code))]
    pub peer_certificate: Certificate,
    pub deadline: RequestDeadline,
}

impl HttpRequestContext {
    pub(crate) fn new(peer_certificate: Certificate, deadline: RequestDeadline) -> Self {
        Self {
            peer_certificate,
            deadline,
        }
    }

    pub(crate) fn check_deadline(
        &self,
        stream: &mut (impl Write + ?Sized),
        stage: &'static str,
    ) -> Result<(), HttpHandlerError> {
        let alive = self
            .deadline
            .respond_if_expired(stream)
            .map_err(|err| HttpHandlerError::request(stage, err))?;
        if alive {
            Ok(())
        } else {
            Err(HttpHandlerError::DeadlineExpired { stage })
        }
    }
}

/// Connection-level failures surfaced by HTTP request handlers.
#[derive(Debug)]
pub(crate) enum HttpHandlerError {
    DeadlineExpired {
        stage: &'static str,
    },
    Request {
        stage: &'static str,
        error: NetError,
    },
    Response {
        stage: &'static str,
        error: NetError,
    },
}

impl HttpHandlerError {
    pub(crate) fn request(stage: &'static str, error: NetError) -> Self {
        Self::Request { stage, error }
    }

    pub(crate) fn response(stage: &'static str, error: NetError) -> Self {
        Self::Response { stage, error }
    }
}
