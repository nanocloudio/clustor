use clustor::admin::{AdminHandler, AdminService};
use clustor::consensus::{ConsensusCore, ConsensusCoreConfig};
use clustor::control_plane::core::{CpPlacementClient, CpProofCoordinator};
use clustor::IdempotencyLedger;
use clustor::{RbacManifest, RbacManifestCache, RbacPrincipal, RbacRole};
use std::time::{Duration, Instant};

/// Builds an [`AdminService`] seeded with a single operator principal.
pub fn admin_service(now: Instant, principal: &str) -> AdminService {
    let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
    let cp_guard = CpProofCoordinator::new(kernel);
    let placements = CpPlacementClient::new(Duration::from_secs(60));
    let ledger = IdempotencyLedger::new(Duration::from_secs(60));
    let handler = AdminHandler::new(cp_guard, placements, ledger);
    let mut rbac = RbacManifestCache::new(Duration::from_secs(600));
    rbac.load_manifest(
        RbacManifest {
            roles: vec![RbacRole {
                name: "operator".into(),
                capabilities: vec![
                    "CreatePartition".into(),
                    "ManageShrinkPlan".into(),
                    "ArmShrinkPlan".into(),
                    "ListShrinkPlans".into(),
                ],
            }],
            principals: vec![RbacPrincipal {
                spiffe_id: principal.into(),
                role: "operator".into(),
            }],
        },
        now,
    )
    .expect("rbac manifest loads");
    AdminService::new(handler, rbac)
}
