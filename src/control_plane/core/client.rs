use crate::control_plane::core::{CpPlacementClient, PlacementRecord};
use crate::feature_guard::FeatureManifest;
#[cfg(feature = "net")]
use crate::net::NetError;
use crate::security::{Certificate, MtlsIdentityManager, SecurityError};
use serde::de::DeserializeOwned;
use std::time::Instant;
use thiserror::Error;

pub trait CpApiTransport {
    fn get(&self, path: &str) -> Result<TransportResponse, CpClientError>;
}

#[derive(Debug, Clone)]
pub struct TransportResponse {
    pub body: Vec<u8>,
    pub server_certificate: Certificate,
}

pub struct CpControlPlaneClient<T> {
    transport: T,
    mtls: MtlsIdentityManager,
    routing_endpoint: String,
    feature_endpoint: String,
}

impl<T> CpControlPlaneClient<T> {
    pub fn new(
        transport: T,
        mtls: MtlsIdentityManager,
        routing_endpoint: impl Into<String>,
        feature_endpoint: impl Into<String>,
    ) -> Self {
        Self {
            transport,
            mtls,
            routing_endpoint: routing_endpoint.into(),
            feature_endpoint: feature_endpoint.into(),
        }
    }

    pub fn apply_revocation_waiver(&mut self, reason: impl Into<String>, now: Instant) {
        self.mtls.apply_revocation_waiver(reason, now);
    }
}

impl<T: CpApiTransport> CpControlPlaneClient<T> {
    pub fn fetch_routing_bundle(
        &mut self,
        placement: &mut CpPlacementClient,
        now: Instant,
    ) -> Result<(), CpClientError> {
        let response = self.transport.get(&self.routing_endpoint)?;
        self.mtls
            .verify_peer(&response.server_certificate, now)
            .map_err(CpClientError::Security)?;
        let records: Vec<PlacementRecord> = decode_json(&response.body)?;
        for record in records {
            placement.update(record, now);
        }
        Ok(())
    }

    pub fn fetch_feature_manifest(
        &mut self,
        now: Instant,
    ) -> Result<FeatureManifest, CpClientError> {
        let response = self.transport.get(&self.feature_endpoint)?;
        self.mtls
            .verify_peer(&response.server_certificate, now)
            .map_err(CpClientError::Security)?;
        decode_json(&response.body)
    }
}

fn decode_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CpClientError> {
    serde_json::from_slice(bytes).map_err(CpClientError::Decode)
}

#[derive(Debug, Error)]
pub enum CpClientError {
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),
    #[error("security error: {0}")]
    Security(#[from] SecurityError),
    #[error("decode error: {0}")]
    Decode(#[from] serde_json::Error),
}

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("no route for {path}")]
    NoRoute { path: String },
    #[cfg(feature = "net")]
    #[error(transparent)]
    Network(#[from] NetError),
}
