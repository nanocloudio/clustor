use crate::state::{append_local_entry, EventRecord};
use crate::NodeState;
use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use clustor::consensus::GateViolation;
use log::{info, warn};

#[derive(Debug, serde::Deserialize)]
pub struct EventRequest {
    pub message: String,
}

#[derive(serde::Serialize)]
pub struct StatsResponse {
    pub node_id: String,
    pub last_applied_index: u64,
    pub log_tail_index: u64,
    pub last_quorum_fsynced_index: u64,
    pub pending_entries: u64,
}

pub fn build_router(node_state: NodeState) -> Router {
    Router::new()
        .route("/events", post(handle_post_event))
        .route("/events", get(handle_list_events))
        .route("/stats", get(handle_stats))
        .with_state(node_state)
}

async fn handle_post_event(
    State(node): State<NodeState>,
    Json(body): Json<EventRequest>,
) -> Result<Json<EventRecord>, (StatusCode, String)> {
    if body.message.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "message must not be empty".into()));
    }

    if !node.raft.is_leader() {
        let leader = node
            .raft
            .leader_id()
            .unwrap_or_else(|| "unknown".into());
        return Err((
            StatusCode::FORBIDDEN,
            format!(
                "node {} is not the leader (current leader: {})",
                node.app.node_id, leader
            ),
        ));
    }
    if !node.raft.has_leader_quorum() {
        return Err(gate_violation_response(
            &node.app.node_id,
            GateViolation::CpUnavailableNeededForReadIndex,
        ));
    }

    let state = node.app.clone();
    let record = EventRecord {
        source: state.node_id.clone(),
        message: body.message.clone(),
    };
    info!(
        "node {} accepted local event payload: {}",
        state.node_id, record.message
    );
    let entry = append_local_entry(&state, &record, node.raft.current_term())
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err))?;

    if let Err(err) = node.raft.replicate_from(entry.index).await {
        warn!("replication warning: {err}");
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            format!("replication failed: {err}"),
        ));
    }
    Ok(Json(record))
}

async fn handle_list_events(
    State(node): State<NodeState>,
) -> Result<Json<Vec<EventRecord>>, (StatusCode, String)> {
    let state = node.app.clone();
    let has_quorum = node.raft.has_leader_quorum();
    if let Err(violation) = state.guard_read() {
        match violation {
            GateViolation::CpUnavailableNeededForReadIndex | GateViolation::CpUnavailableCacheExpired
                if has_quorum =>
            {
                warn!(
                    "node {} degrading read gate due to ControlPlane outage (local quorum intact)",
                    state.node_id
                );
            }
            other => {
                return Err(gate_violation_response(&state.node_id, other));
            }
        }
    }
    if node.raft.is_leader() && !has_quorum {
        return Err(gate_violation_response(
            &state.node_id,
            GateViolation::CpUnavailableNeededForReadIndex,
        ));
    }
    let snapshot = state.events.lock().clone();
    Ok(Json(snapshot))
}

async fn handle_stats(State(node): State<NodeState>) -> Json<StatsResponse> {
    let state = node.app.clone();
    let log_tail = state.log.lock().last_index();
    let quorum = state.last_quorum_fsynced.load(std::sync::atomic::Ordering::SeqCst);
    let stats = StatsResponse {
        node_id: state.node_id.clone(),
        last_applied_index: state.last_applied.load(std::sync::atomic::Ordering::SeqCst),
        log_tail_index: log_tail,
        last_quorum_fsynced_index: quorum,
        pending_entries: log_tail.saturating_sub(quorum),
    };
    Json(stats)
}

fn gate_violation_response(
    node_id: &str,
    violation: GateViolation,
) -> (StatusCode, String) {
    let reason = match violation {
        GateViolation::ModeConflictStrictFallback => "ModeConflict(strict_fallback)",
        GateViolation::CpUnavailableNeededForReadIndex => {
            "ControlPlaneUnavailable{reason=NeededForReadIndex}"
        }
        GateViolation::CpUnavailableCacheExpired => {
            "ControlPlaneUnavailable{reason=CacheExpired}"
        }
        GateViolation::FollowerCapabilityRevoked => "FollowerCapabilityRevoked",
    };
    warn!(
        "node {} strict fallback gate blocked read: {}",
        node_id, reason
    );
    (
        StatusCode::SERVICE_UNAVAILABLE,
        format!("strict fallback gate blocked read: {}", reason),
    )
}
