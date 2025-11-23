use crate::cp_raft::{CpPlacementClient, PlacementRecord};
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::{SerialNumber, SpiffeId};
    use std::collections::HashMap;

    #[test]
    fn routing_bundle_updates_cache() {
        let now = Instant::now();
        let transport = MockTransport::new(success_response(
            r#"[{"partition_id":"p1","routing_epoch":7,"lease_epoch":5,"members":["a","b"]}]"#,
            "spiffe://cp.internal/nodes/1",
            now,
        ));
        let mtls = client_identity(now);
        let mut client = CpControlPlaneClient::new(transport, mtls, "/routing", "/features");
        let mut placements = CpPlacementClient::new(std::time::Duration::from_secs(60));
        client
            .fetch_routing_bundle(&mut placements, now)
            .expect("bundle fetch");
        let snapshot = placements
            .placement_snapshot("p1")
            .expect("placement cached");
        assert_eq!(snapshot.record.routing_epoch, 7);
        assert_eq!(snapshot.record.members, vec!["a", "b"]);
    }

    #[test]
    fn feature_manifest_fetches_and_parses() {
        let now = Instant::now();
        let manifest = FeatureManifest {
            schema_version: 1,
            generated_at_ms: 123,
            features: vec![],
            signature: "deadbeef".into(),
        };
        let payload = serde_json::to_string(&manifest).unwrap();
        let transport = MockTransport::new(success_response(
            &payload,
            "spiffe://cp.internal/nodes/1",
            now,
        ));
        let mtls = client_identity(now);
        let mut client = CpControlPlaneClient::new(transport, mtls, "/routing", "/features");
        let fetched = client.fetch_feature_manifest(now).expect("manifest");
        assert_eq!(fetched.schema_version, 1);
        assert_eq!(fetched.generated_at_ms, 123);
    }

    #[test]
    fn mtls_verification_blocks_foreign_trust_domain() {
        let now = Instant::now();
        let transport =
            MockTransport::new(success_response("[]", "spiffe://other.domain/nodes/1", now));
        let mtls = client_identity(now);
        let mut client = CpControlPlaneClient::new(transport, mtls, "/routing", "/features");
        let mut placements = CpPlacementClient::new(std::time::Duration::from_secs(60));
        let err = client
            .fetch_routing_bundle(&mut placements, now)
            .expect_err("foreign cert should fail");
        match err {
            CpClientError::Security(security_err) => {
                assert!(format!("{security_err:?}").contains("TrustDomainMismatch"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    fn client_identity(now: Instant) -> MtlsIdentityManager {
        let cert = certificate("spiffe://cp.internal/clients/node", 1, now);
        MtlsIdentityManager::new(
            cert,
            "cp.internal",
            std::time::Duration::from_secs(600),
            now,
        )
    }

    fn success_response(body: &str, server_spiffe: &str, now: Instant) -> TransportResponse {
        TransportResponse {
            body: body.as_bytes().to_vec(),
            server_certificate: certificate(server_spiffe, 42, now),
        }
    }

    fn certificate(spiffe: &str, serial: u64, now: Instant) -> Certificate {
        Certificate {
            spiffe_id: SpiffeId::parse(spiffe).unwrap(),
            serial: SerialNumber::from_u64(serial),
            valid_from: now - std::time::Duration::from_secs(5),
            valid_until: now + std::time::Duration::from_secs(60),
        }
    }

    struct MockTransport {
        responses: HashMap<String, TransportResponse>,
    }

    impl MockTransport {
        fn new(response: TransportResponse) -> Self {
            let mut responses = HashMap::new();
            responses.insert("/routing".into(), response.clone());
            responses.insert("/features".into(), response);
            Self { responses }
        }
    }

    impl CpApiTransport for MockTransport {
        fn get(&self, path: &str) -> Result<TransportResponse, CpClientError> {
            self.responses.get(path).cloned().ok_or_else(|| {
                TransportError::NoRoute {
                    path: path.to_string(),
                }
                .into()
            })
        }
    }
}
