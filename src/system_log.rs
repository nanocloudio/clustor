use crate::transport::{CatalogNegotiationReport, ForwardCompatTracker};
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SystemLogEntry {
    MembershipChange {
        old_members: Vec<String>,
        new_members: Vec<String>,
        routing_epoch: u64,
    },
    MembershipRollback {
        reason: String,
        failing_nodes: Vec<String>,
        override_ref: Option<String>,
    },
    DurabilityTransition {
        from_mode: String,
        to_mode: String,
        effective_index: u64,
        durability_mode_epoch: u64,
    },
    FenceCommit {
        fence_epoch: u64,
        manifest_id: String,
        dr_cluster_id: String,
    },
    DefineActivate {
        bundle_id: String,
        barrier_id: String,
        partitions: Vec<String>,
        readiness_digest: String,
    },
    AdminAuditSpill {
        action: String,
        partition_id: String,
        reason: Option<String>,
    },
}

impl SystemLogEntry {
    pub fn encode(&self) -> Result<Vec<u8>, SystemLogError> {
        let mut buf = Vec::new();
        buf.write_all(&[self.wire_id()])?;
        match self {
            SystemLogEntry::MembershipChange {
                old_members,
                new_members,
                routing_epoch,
            } => {
                write_string_array(&mut buf, old_members)?;
                write_string_array(&mut buf, new_members)?;
                buf.write_all(&routing_epoch.to_le_bytes())?;
            }
            SystemLogEntry::MembershipRollback {
                reason,
                failing_nodes,
                override_ref,
            } => {
                write_string(&mut buf, reason)?;
                write_string_array(&mut buf, failing_nodes)?;
                write_optional_string(&mut buf, override_ref)?;
            }
            SystemLogEntry::DurabilityTransition {
                from_mode,
                to_mode,
                effective_index,
                durability_mode_epoch,
            } => {
                write_string(&mut buf, from_mode)?;
                write_string(&mut buf, to_mode)?;
                buf.write_all(&effective_index.to_le_bytes())?;
                buf.write_all(&durability_mode_epoch.to_le_bytes())?;
            }
            SystemLogEntry::FenceCommit {
                fence_epoch,
                manifest_id,
                dr_cluster_id,
            } => {
                buf.write_all(&fence_epoch.to_le_bytes())?;
                write_string(&mut buf, manifest_id)?;
                write_string(&mut buf, dr_cluster_id)?;
            }
            SystemLogEntry::DefineActivate {
                bundle_id,
                barrier_id,
                partitions,
                readiness_digest,
            } => {
                write_string(&mut buf, bundle_id)?;
                write_string(&mut buf, barrier_id)?;
                write_string_array(&mut buf, partitions)?;
                write_string(&mut buf, readiness_digest)?;
            }
            SystemLogEntry::AdminAuditSpill {
                action,
                partition_id,
                reason,
            } => {
                write_string(&mut buf, action)?;
                write_string(&mut buf, partition_id)?;
                write_optional_string(&mut buf, reason)?;
            }
        }
        Ok(buf)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SystemLogError> {
        let mut tracker = ForwardCompatTracker::noop();
        Self::decode_with_tracker(bytes, &mut tracker)
    }

    pub fn decode_with_report(
        bytes: &[u8],
        report: &mut CatalogNegotiationReport,
    ) -> Result<Self, SystemLogError> {
        let mut tracker = ForwardCompatTracker::new(report);
        Self::decode_with_tracker(bytes, &mut tracker)
    }

    pub fn decode_with_tracker(
        mut bytes: &[u8],
        tracker: &mut ForwardCompatTracker<'_>,
    ) -> Result<Self, SystemLogError> {
        let mut id = [0u8; 1];
        bytes.read_exact(&mut id)?;
        Ok(match id[0] {
            0x01 => SystemLogEntry::MembershipChange {
                old_members: read_string_array(&mut bytes)?,
                new_members: read_string_array(&mut bytes)?,
                routing_epoch: read_u64(&mut bytes)?,
            },
            0x02 => SystemLogEntry::MembershipRollback {
                reason: read_string(&mut bytes)?,
                failing_nodes: read_string_array(&mut bytes)?,
                override_ref: read_optional_string(&mut bytes)?,
            },
            0x03 => SystemLogEntry::DurabilityTransition {
                from_mode: read_string(&mut bytes)?,
                to_mode: read_string(&mut bytes)?,
                effective_index: read_u64(&mut bytes)?,
                durability_mode_epoch: read_u64(&mut bytes)?,
            },
            0x04 => SystemLogEntry::FenceCommit {
                fence_epoch: read_u64(&mut bytes)?,
                manifest_id: read_string(&mut bytes)?,
                dr_cluster_id: read_string(&mut bytes)?,
            },
            0x05 => SystemLogEntry::DefineActivate {
                bundle_id: read_string(&mut bytes)?,
                barrier_id: read_string(&mut bytes)?,
                partitions: read_string_array(&mut bytes)?,
                readiness_digest: read_string(&mut bytes)?,
            },
            0x06 => SystemLogEntry::AdminAuditSpill {
                action: read_string(&mut bytes)?,
                partition_id: read_string(&mut bytes)?,
                reason: read_optional_string(&mut bytes)?,
            },
            other => {
                if let Err(err) =
                    tracker.note_unknown_field(format!("system_log.wire_entry_id=0x{other:02x}"))
                {
                    return Err(SystemLogError::ForwardCompat(err));
                }
                return Err(SystemLogError::UnknownWireId(other));
            }
        })
    }

    fn wire_id(&self) -> u8 {
        match self {
            SystemLogEntry::MembershipChange { .. } => 0x01,
            SystemLogEntry::MembershipRollback { .. } => 0x02,
            SystemLogEntry::DurabilityTransition { .. } => 0x03,
            SystemLogEntry::FenceCommit { .. } => 0x04,
            SystemLogEntry::DefineActivate { .. } => 0x05,
            SystemLogEntry::AdminAuditSpill { .. } => 0x06,
        }
    }
}

fn write_string(writer: &mut Vec<u8>, value: &str) -> Result<(), io::Error> {
    let bytes = value.as_bytes();
    writer.write_all(&(bytes.len() as u32).to_le_bytes())?;
    writer.write_all(bytes)?;
    Ok(())
}

fn write_optional_string(writer: &mut Vec<u8>, value: &Option<String>) -> Result<(), io::Error> {
    match value {
        Some(v) => {
            writer.write_all(&[1])?;
            write_string(writer, v)?;
        }
        None => writer.write_all(&[0])?,
    }
    Ok(())
}

fn write_string_array(writer: &mut Vec<u8>, values: &[String]) -> Result<(), io::Error> {
    writer.write_all(&(values.len() as u16).to_le_bytes())?;
    for value in values {
        write_string(writer, value)?;
    }
    Ok(())
}

fn read_string(reader: &mut &[u8]) -> Result<String, SystemLogError> {
    let mut len = [0u8; 4];
    reader.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len) as usize;
    if reader.len() < len {
        return Err(SystemLogError::Truncated);
    }
    let (head, tail) = reader.split_at(len);
    *reader = tail;
    let value = std::str::from_utf8(head).map_err(|_| SystemLogError::InvalidUtf8)?;
    Ok(value.to_string())
}

fn read_optional_string(reader: &mut &[u8]) -> Result<Option<String>, SystemLogError> {
    let mut flag = [0u8; 1];
    reader.read_exact(&mut flag)?;
    if flag[0] == 0 {
        return Ok(None);
    }
    Ok(Some(read_string(reader)?))
}

fn read_string_array(reader: &mut &[u8]) -> Result<Vec<String>, SystemLogError> {
    let mut count = [0u8; 2];
    reader.read_exact(&mut count)?;
    let count = u16::from_le_bytes(count);
    let mut values = Vec::with_capacity(count as usize);
    for _ in 0..count {
        values.push(read_string(reader)?);
    }
    Ok(values)
}

fn read_u64(reader: &mut &[u8]) -> Result<u64, SystemLogError> {
    let mut bytes = [0u8; 8];
    reader.read_exact(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

#[derive(Debug, Error)]
pub enum SystemLogError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid UTF-8 in system log payload")]
    InvalidUtf8,
    #[error("unexpected end of system log payload")]
    Truncated,
    #[error("unknown wire id {0:#x}")]
    UnknownWireId(u8),
    #[error("failed to record forward-compatibility violation: {0}")]
    ForwardCompat(#[from] crate::wire::NegotiationError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn membership_change_round_trip() {
        let entry = SystemLogEntry::MembershipChange {
            old_members: vec!["a".into()],
            new_members: vec!["b".into(), "c".into()],
            routing_epoch: 7,
        };
        let encoded = entry.encode().unwrap();
        let decoded = SystemLogEntry::decode(&encoded).unwrap();
        assert_eq!(entry, decoded);
    }

    #[test]
    fn rollback_with_optional_field() {
        let entry = SystemLogEntry::MembershipRollback {
            reason: "quorum".into(),
            failing_nodes: vec!["x".into()],
            override_ref: Some("ticket-1".into()),
        };
        let encoded = entry.encode().unwrap();
        assert_eq!(encoded[0], 0x02);
        let decoded = SystemLogEntry::decode(&encoded).unwrap();
        assert_eq!(entry, decoded);
    }

    #[test]
    fn define_activate_round_trip() {
        let entry = SystemLogEntry::DefineActivate {
            bundle_id: "bundle-1".into(),
            barrier_id: "barrier-1".into(),
            partitions: vec!["p1".into(), "p2".into()],
            readiness_digest: "0xcafebabe".into(),
        };
        let encoded = entry.encode().unwrap();
        assert_eq!(encoded[0], 0x05);
        let decoded = SystemLogEntry::decode(&encoded).unwrap();
        assert_eq!(entry, decoded);
    }
}
