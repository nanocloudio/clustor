// Attachment registry — the `att/<attachment_id>` namespace of the session
// directory: the boundaries a private service attachment is admitted under
// (rfc_lb_vip §11.12, §22), each attachment's committed generation and
// each service's revocation generation. Wormhole's broker
// (`wormhole/modules/common/traffic/attachment_core.rs`) admits a
// connection only when the Kagi-verified grant names exactly these two
// generations (`AttachmentBoundary`), and stops new connections the moment
// a service's revocation boundary moves past the grant.
//
// Pure no_std, zero-alloc, DETERMINISTIC: `AttachmentRegistry::apply` is a
// pure function of (state, committed command body); every replica applying
// the same committed sequence holds byte-identical state. No clocks, no
// randomness, no I/O. The PIC module wrapper
// (`modules/app/session_directory/mod.rs`) hosts it beside the other
// registries, dispatching on the `"AT"` magic; `clustor-common` mounts it
// for host tests and for the broker.
//
// Two record kinds, each in its own arena:
//
// - **an attachment** `attachment_id[16]`, bound at its first commit to one
//   service `(producer_tenant, service_id)`, holding its generation;
// - **a service** `(producer_tenant, service_id)`, holding its revocation
//   generation, created at 1 by the first attachment committed to it.
//
// What the registry enforces:
//
// - **generations only increase.** COMMIT advances an attachment's
//   generation to the one it names, which must be strictly greater than
//   the committed one (a new attachment starts at any generation ≥ 1);
//   anything else is `STALE`. An attachment never changes service: a
//   COMMIT naming another is `CONFLICT`.
// - **revocation is a boundary.** REVOKE advances a service's revocation
//   generation, strictly; every grant issued under an older one stops
//   admitting new connections. The reply counts the attachments the
//   boundary covers.
// - **reads through the log.** READ answers an attachment's boundary at
//   this log position and changes nothing, so a restarted broker reads
//   what the group committed, never a follower's older view.
// - **idempotent operations.** Every mutating command carries
//   `operation_id[16]`; each record remembers its last one, whole: a
//   byte-identical retry repeats the recorded reply, another command under
//   the same id is `CONFLICT`.
// - **records live as long as the group.** An attachment or service record
//   is never freed, so a generation can never restart lower under a reused
//   identity; the arenas bound the distinct attachments and services a
//   group ever commits.

use super::slot_index::{SlotIndex, SlotSet};

// ── Capacity ────────────────────────────────────────────────────────

/// Profiles: attachments and services per group.
pub const AT_PROFILE_RP2350: usize = 32;
pub const AT_SERVICES_RP2350: usize = 8;
pub const AT_PROFILE_PI5: usize = 1024;
pub const AT_SERVICES_PI5: usize = 256;
pub const AT_PROFILE_SERVER: usize = 16384;
pub const AT_SERVICES_SERVER: usize = 4096;

// ── Commands ────────────────────────────────────────────────────────

pub const AT_ID: usize = 16;
pub const AT_TENANT: usize = 16;
pub const AT_SERVICE: usize = 16;
pub const AT_OP_ID: usize = 16;
/// Service key: `[producer_tenant:16][service_id:16]`.
pub const AT_SERVICE_KEY: usize = AT_TENANT + AT_SERVICE;

/// `[op_id:16][attachment_id:16][producer_tenant:16][service_id:16]
/// [attachment_generation:8]`.
pub const AT_OP_COMMIT: u8 = 1;
/// `[op_id:16][producer_tenant:16][service_id:16][revocation_generation:8]`.
pub const AT_OP_REVOKE: u8 = 2;
/// `[attachment_id:16]`: the boundary at this log position (a read).
pub const AT_OP_READ: u8 = 3;

pub const AT_COMMIT_LEN: usize = 1 + AT_OP_ID + AT_ID + AT_SERVICE_KEY + 8;
pub const AT_REVOKE_LEN: usize = 1 + AT_OP_ID + AT_SERVICE_KEY + 8;
pub const AT_READ_LEN: usize = 1 + AT_ID;
/// Largest command body (COMMIT).
pub const AT_MAX_CMD: usize = AT_COMMIT_LEN;

pub const AT_ST_OK: u8 = 0;
pub const AT_ST_INVALID: u8 = 1;
/// A generation that does not advance the committed one.
pub const AT_ST_STALE: u8 = 2;
/// Operation id reused by another command, or an attachment named under
/// another service.
pub const AT_ST_CONFLICT: u8 = 3;
pub const AT_ST_UNKNOWN: u8 = 4;
/// A new attachment or service past the admitted count.
pub const AT_ST_CAPACITY: u8 = 5;

pub fn build_commit(
    dst: &mut [u8],
    op_id: &[u8; AT_OP_ID],
    attachment: &[u8; AT_ID],
    producer_tenant: &[u8; AT_TENANT],
    service_id: &[u8; AT_SERVICE],
    generation: u64,
) -> usize {
    if dst.len() < AT_COMMIT_LEN || generation == 0 {
        return 0;
    }
    dst[0] = AT_OP_COMMIT;
    dst[1..17].copy_from_slice(op_id);
    dst[17..33].copy_from_slice(attachment);
    dst[33..49].copy_from_slice(producer_tenant);
    dst[49..65].copy_from_slice(service_id);
    dst[65..73].copy_from_slice(&generation.to_le_bytes());
    AT_COMMIT_LEN
}

pub fn build_revoke(
    dst: &mut [u8],
    op_id: &[u8; AT_OP_ID],
    producer_tenant: &[u8; AT_TENANT],
    service_id: &[u8; AT_SERVICE],
    revocation_generation: u64,
) -> usize {
    if dst.len() < AT_REVOKE_LEN || revocation_generation == 0 {
        return 0;
    }
    dst[0] = AT_OP_REVOKE;
    dst[1..17].copy_from_slice(op_id);
    dst[17..33].copy_from_slice(producer_tenant);
    dst[33..49].copy_from_slice(service_id);
    dst[49..57].copy_from_slice(&revocation_generation.to_le_bytes());
    AT_REVOKE_LEN
}

pub fn build_read(dst: &mut [u8], attachment: &[u8; AT_ID]) -> usize {
    if dst.len() < AT_READ_LEN {
        return 0;
    }
    dst[0] = AT_OP_READ;
    dst[1..17].copy_from_slice(attachment);
    AT_READ_LEN
}

fn u32_at(src: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([src[o], src[o + 1], src[o + 2], src[o + 3]])
}

fn u64_at(src: &[u8], o: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&src[o..o + 8]);
    u64::from_le_bytes(b)
}

// ── Reply ───────────────────────────────────────────────────────────

/// Encoded reply: `[op:1][status:1][reserved:2][covered:4]
/// [attachment_id:16][producer_tenant:16][service_id:16]
/// [attachment_generation:8][revocation_generation:8]` — Wormhole's
/// `AttachmentBoundary` in its last 16 bytes. `covered` is, for REVOKE,
/// the attachments the service's boundary covers.
pub const AT_REPLY_LEN: usize = 8 + AT_ID + AT_SERVICE_KEY + 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct AttachmentReply {
    pub op: u8,
    pub status: u8,
    pub covered: u32,
    pub attachment_id: [u8; AT_ID],
    pub producer_tenant: [u8; AT_TENANT],
    pub service_id: [u8; AT_SERVICE],
    pub attachment_generation: u64,
    pub revocation_generation: u64,
}

impl AttachmentReply {
    pub const fn zero() -> Self {
        AttachmentReply {
            op: 0,
            status: 0,
            covered: 0,
            attachment_id: [0; AT_ID],
            producer_tenant: [0; AT_TENANT],
            service_id: [0; AT_SERVICE],
            attachment_generation: 0,
            revocation_generation: 0,
        }
    }

    fn fail(op: u8, status: u8) -> Self {
        AttachmentReply {
            op,
            status,
            ..Self::zero()
        }
    }

    pub fn encode(&self, dst: &mut [u8]) -> i32 {
        if dst.len() < AT_REPLY_LEN {
            return -1;
        }
        dst[0] = self.op;
        dst[1] = self.status;
        dst[2..4].copy_from_slice(&[0; 2]);
        dst[4..8].copy_from_slice(&self.covered.to_le_bytes());
        dst[8..24].copy_from_slice(&self.attachment_id);
        dst[24..40].copy_from_slice(&self.producer_tenant);
        dst[40..56].copy_from_slice(&self.service_id);
        dst[56..64].copy_from_slice(&self.attachment_generation.to_le_bytes());
        dst[64..72].copy_from_slice(&self.revocation_generation.to_le_bytes());
        AT_REPLY_LEN as i32
    }

    pub fn decode(src: &[u8]) -> Option<AttachmentReply> {
        if src.len() < AT_REPLY_LEN || src[2..4] != [0; 2] {
            return None;
        }
        let mut r = AttachmentReply::zero();
        r.op = src[0];
        r.status = src[1];
        r.covered = u32_at(src, 4);
        r.attachment_id.copy_from_slice(&src[8..24]);
        r.producer_tenant.copy_from_slice(&src[24..40]);
        r.service_id.copy_from_slice(&src[40..56]);
        r.attachment_generation = u64_at(src, 56);
        r.revocation_generation = u64_at(src, 64);
        Some(r)
    }
}

// ── State ───────────────────────────────────────────────────────────

/// A record's last operation, whole, and the reply to repeat to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct AtOpMemo {
    pub present: bool,
    pub cmd_len: u8,
    pub cmd: [u8; AT_MAX_CMD],
    pub reply: AttachmentReply,
}

impl AtOpMemo {
    /// `[present:1][cmd_len:1][cmd: AT_MAX_CMD][reply: AT_REPLY_LEN]`.
    pub const LEN: usize = 2 + AT_MAX_CMD + AT_REPLY_LEN;

    pub const fn empty() -> Self {
        AtOpMemo {
            present: false,
            cmd_len: 0,
            cmd: [0; AT_MAX_CMD],
            reply: AttachmentReply::zero(),
        }
    }

    fn check(&self, body: &[u8]) -> Result<Option<AttachmentReply>, ()> {
        if !self.present || self.cmd[1..17] != body[1..17] {
            return Ok(None);
        }
        if self.cmd_len as usize == body.len() && self.cmd[..body.len()] == *body {
            return Ok(Some(self.reply));
        }
        Err(())
    }

    fn record(&mut self, body: &[u8], reply: AttachmentReply) {
        let n = body.len().min(AT_MAX_CMD);
        self.cmd = [0; AT_MAX_CMD];
        self.cmd[..n].copy_from_slice(&body[..n]);
        self.cmd_len = n as u8;
        self.present = true;
        self.reply = reply;
    }

    fn encode(&self, dst: &mut [u8]) {
        dst[0] = self.present as u8;
        dst[1] = self.cmd_len;
        dst[2..2 + AT_MAX_CMD].copy_from_slice(&self.cmd);
        let _ = self.reply.encode(&mut dst[2 + AT_MAX_CMD..Self::LEN]);
    }

    fn decode(src: &[u8]) -> Option<AtOpMemo> {
        if src[0] > 1 || src[1] as usize > AT_MAX_CMD || (src[0] == 0) != (src[1] == 0) {
            return None;
        }
        let mut m = AtOpMemo::empty();
        m.present = src[0] != 0;
        m.cmd_len = src[1];
        m.cmd.copy_from_slice(&src[2..2 + AT_MAX_CMD]);
        m.reply = AttachmentReply::decode(&src[2 + AT_MAX_CMD..Self::LEN])?;
        Some(m)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct AttachmentSlot {
    pub attachment_id: [u8; AT_ID],
    /// The service slot it belongs to.
    pub service: u32,
    pub generation: u64,
    pub last_op: AtOpMemo,
}

impl AttachmentSlot {
    pub const fn empty() -> Self {
        AttachmentSlot {
            attachment_id: [0; AT_ID],
            service: 0,
            generation: 0,
            last_op: AtOpMemo::empty(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct ServiceSlot {
    pub key: [u8; AT_SERVICE_KEY],
    pub revocation_generation: u64,
    /// Attachments committed to it.
    pub attachments: u32,
    pub last_op: AtOpMemo,
}

impl ServiceSlot {
    pub const fn empty() -> Self {
        ServiceSlot {
            key: [0; AT_SERVICE_KEY],
            revocation_generation: 0,
            attachments: 0,
            last_op: AtOpMemo::empty(),
        }
    }
}

/// The replicated state machine: `N` attachments, `S` services (both
/// powers of two).
#[repr(C)]
pub struct AttachmentRegistry<const N: usize, const S: usize> {
    pub attachments: [AttachmentSlot; N],
    pub services: [ServiceSlot; S],
    /// Derived; rebuilt on restore.
    at_index: SlotIndex<N, AT_ID>,
    at_used: SlotSet<N>,
    sv_index: SlotIndex<S, AT_SERVICE_KEY>,
    sv_used: SlotSet<S>,
    pub admitted: u32,
    pub admitted_services: u32,
    pub attachment_count: u32,
    pub service_count: u32,
    pub applied: u64,
}

impl<const N: usize, const S: usize> Default for AttachmentRegistry<N, S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize, const S: usize> AttachmentRegistry<N, S> {
    const PROFILE_OK: () = assert!(
        N.is_power_of_two() && S.is_power_of_two(),
        "attachment profile: N and S must be powers of two"
    );

    pub const fn new() -> Self {
        let () = Self::PROFILE_OK;
        AttachmentRegistry {
            attachments: [AttachmentSlot::empty(); N],
            services: [ServiceSlot::empty(); S],
            at_index: SlotIndex::new(),
            at_used: SlotSet::new(),
            sv_index: SlotIndex::new(),
            sv_used: SlotSet::new(),
            admitted: N as u32,
            admitted_services: S as u32,
            attachment_count: 0,
            service_count: 0,
            applied: 0,
        }
    }

    /// Initialise in place, admitting `attachments` and `services` (each
    /// clamped to its arena): every byte of the state.
    pub fn reset(&mut self, attachments: u32, services: u32) {
        let () = Self::PROFILE_OK;
        let mut i = 0;
        while i < N {
            self.attachments[i] = AttachmentSlot::empty();
            i += 1;
        }
        i = 0;
        while i < S {
            self.services[i] = ServiceSlot::empty();
            i += 1;
        }
        self.at_index.reset();
        self.at_used.reset();
        self.sv_index.reset();
        self.sv_used.reset();
        self.admitted = attachments.min(N as u32);
        self.admitted_services = services.min(S as u32);
        self.attachment_count = 0;
        self.service_count = 0;
        self.applied = 0;
    }

    /// Empty an initialised registry, keeping what it admits.
    pub fn clear(&mut self) {
        let mut at = 0;
        while let Some(i) = self.at_used.next_used(at) {
            self.attachments[i] = AttachmentSlot::empty();
            at = i + 1;
        }
        at = 0;
        while let Some(i) = self.sv_used.next_used(at) {
            self.services[i] = ServiceSlot::empty();
            at = i + 1;
        }
        self.at_index.reset();
        self.at_used.reset();
        self.sv_index.reset();
        self.sv_used.reset();
        self.attachment_count = 0;
        self.service_count = 0;
        self.applied = 0;
    }

    pub fn lookup(&self, attachment: &[u8; AT_ID]) -> Option<&AttachmentSlot> {
        self.at_index
            .find(attachment)
            .map(|i| &self.attachments[i as usize])
    }

    pub fn service(&self, key: &[u8; AT_SERVICE_KEY]) -> Option<&ServiceSlot> {
        self.sv_index.find(key).map(|i| &self.services[i as usize])
    }

    /// An attachment's committed boundary: `(attachment_generation,
    /// revocation_generation)`.
    pub fn boundary(&self, attachment: &[u8; AT_ID]) -> Option<(u64, u64)> {
        let a = self.lookup(attachment)?;
        Some((
            a.generation,
            self.services[a.service as usize].revocation_generation,
        ))
    }

    fn reply_for(&self, op: u8, status: u8, a: usize) -> AttachmentReply {
        let at = &self.attachments[a];
        let sv = &self.services[at.service as usize];
        let mut r = self.reply_service(op, status, at.service as usize);
        r.attachment_id = at.attachment_id;
        r.attachment_generation = at.generation;
        r.covered = sv.attachments;
        r
    }

    fn reply_service(&self, op: u8, status: u8, sv: usize) -> AttachmentReply {
        let s = &self.services[sv];
        let mut r = AttachmentReply::fail(op, status);
        r.producer_tenant.copy_from_slice(&s.key[..16]);
        r.service_id.copy_from_slice(&s.key[16..]);
        r.revocation_generation = s.revocation_generation;
        r.covered = s.attachments;
        r
    }

    /// Apply one committed command body. DETERMINISTIC.
    pub fn apply(&mut self, body: &[u8]) -> AttachmentReply {
        self.applied = self.applied.wrapping_add(1);
        let Some(&op) = body.first() else {
            return AttachmentReply::fail(0, AT_ST_INVALID);
        };
        match op {
            AT_OP_COMMIT if body.len() == AT_COMMIT_LEN => self.apply_commit(body),
            AT_OP_REVOKE if body.len() == AT_REVOKE_LEN => self.apply_revoke(body),
            AT_OP_READ if body.len() == AT_READ_LEN => {
                let mut id = [0u8; AT_ID];
                id.copy_from_slice(&body[1..17]);
                match self.at_index.find(&id) {
                    Some(i) => self.reply_for(op, AT_ST_OK, i as usize),
                    None => {
                        let mut r = AttachmentReply::fail(op, AT_ST_UNKNOWN);
                        r.attachment_id = id;
                        r
                    }
                }
            }
            _ => AttachmentReply::fail(op, AT_ST_INVALID),
        }
    }

    /// The service slot for `key`, created at revocation generation 1.
    fn service_slot(&mut self, key: &[u8; AT_SERVICE_KEY]) -> Option<usize> {
        if let Some(i) = self.sv_index.find(key) {
            return Some(i as usize);
        }
        if self.service_count >= self.admitted_services {
            return None;
        }
        let i = self.sv_used.lowest_free()?;
        if !self.sv_index.insert(key, i as u32) {
            return None;
        }
        self.sv_used.mark(i);
        self.services[i] = ServiceSlot {
            key: *key,
            revocation_generation: 1,
            attachments: 0,
            last_op: AtOpMemo::empty(),
        };
        self.service_count += 1;
        Some(i)
    }

    fn apply_commit(&mut self, body: &[u8]) -> AttachmentReply {
        let op = AT_OP_COMMIT;
        let mut id = [0u8; AT_ID];
        id.copy_from_slice(&body[17..33]);
        let mut key = [0u8; AT_SERVICE_KEY];
        key.copy_from_slice(&body[33..65]);
        let generation = u64_at(body, 65);
        if id == [0; AT_ID] || key[..16] == [0; 16] || key[16..] == [0; 16] || generation == 0 {
            return AttachmentReply::fail(op, AT_ST_INVALID);
        }
        if let Some(i) = self.at_index.find(&id) {
            let i = i as usize;
            match self.attachments[i].last_op.check(body) {
                Ok(Some(r)) => return r,
                Ok(None) => {}
                Err(()) => return self.reply_for(op, AT_ST_CONFLICT, i),
            }
            let sv = self.attachments[i].service as usize;
            let reply = if self.services[sv].key != key {
                self.reply_for(op, AT_ST_CONFLICT, i)
            } else if generation <= self.attachments[i].generation {
                self.reply_for(op, AT_ST_STALE, i)
            } else {
                self.attachments[i].generation = generation;
                self.reply_for(op, AT_ST_OK, i)
            };
            self.attachments[i].last_op.record(body, reply);
            return reply;
        }
        if self.attachment_count >= self.admitted {
            return AttachmentReply::fail(op, AT_ST_CAPACITY);
        }
        let Some(sv) = self.service_slot(&key) else {
            return AttachmentReply::fail(op, AT_ST_CAPACITY);
        };
        let Some(i) = self.at_used.lowest_free() else {
            return AttachmentReply::fail(op, AT_ST_CAPACITY);
        };
        if !self.at_index.insert(&id, i as u32) {
            return AttachmentReply::fail(op, AT_ST_CAPACITY);
        }
        self.at_used.mark(i);
        self.attachments[i] = AttachmentSlot {
            attachment_id: id,
            service: sv as u32,
            generation,
            last_op: AtOpMemo::empty(),
        };
        self.attachment_count += 1;
        self.services[sv].attachments += 1;
        let reply = self.reply_for(op, AT_ST_OK, i);
        self.attachments[i].last_op.record(body, reply);
        reply
    }

    fn apply_revoke(&mut self, body: &[u8]) -> AttachmentReply {
        let op = AT_OP_REVOKE;
        let mut key = [0u8; AT_SERVICE_KEY];
        key.copy_from_slice(&body[17..49]);
        let generation = u64_at(body, 49);
        if generation == 0 {
            return AttachmentReply::fail(op, AT_ST_INVALID);
        }
        let Some(sv) = self.sv_index.find(&key).map(|i| i as usize) else {
            let mut r = AttachmentReply::fail(op, AT_ST_UNKNOWN);
            r.producer_tenant.copy_from_slice(&key[..16]);
            r.service_id.copy_from_slice(&key[16..]);
            return r;
        };
        match self.services[sv].last_op.check(body) {
            Ok(Some(r)) => return r,
            Ok(None) => {}
            Err(()) => return self.reply_service(op, AT_ST_CONFLICT, sv),
        }
        let reply = if generation <= self.services[sv].revocation_generation {
            self.reply_service(op, AT_ST_STALE, sv)
        } else {
            self.services[sv].revocation_generation = generation;
            self.reply_service(op, AT_ST_OK, sv)
        };
        self.services[sv].last_op.record(body, reply);
        reply
    }

    // ── Snapshot (streamed, versioned) ──────────────────────────────
    //
    //   header  [version:u16 = 1][reserved:u16][arena N:u32][services S:u32]
    //           [admitted:u32][admitted_services:u32][service_count:u32]
    //           [attachment_count:u32][applied:u64]
    //   service [slot:u32][key:32][revocation_generation:8][reserved:4]
    //           [last_op: AtOpMemo::LEN] × service_count, slot order (a
    //           service's attachment count is derived, rebuilt from the
    //           attachments)
    //   attach  [slot:u32][attachment_id:16][service:4][generation:8]
    //           [last_op: AtOpMemo::LEN] × attachment_count, slot order

    pub const SNAPSHOT_VERSION: u16 = 1;

    pub fn snapshot_len(&self) -> usize {
        AT_SNAP_HDR_LEN
            + self.service_count as usize * AT_SNAP_SERVICE_LEN
            + self.attachment_count as usize * AT_SNAP_ATTACH_LEN
    }

    pub fn snapshot(&self, dst: &mut [u8]) -> i32 {
        if dst.len() < self.snapshot_len() {
            return -1;
        }
        let mut cur = AtExportCursor::new();
        let mut o = 0;
        loop {
            let n = self.export_next(&mut cur, &mut dst[o..]);
            if n == 0 {
                break;
            }
            o += n;
        }
        o as i32
    }

    /// Next unit of the streamed export into `dst` (≥ `AT_SNAP_MAX_UNIT`);
    /// 0 once complete.
    pub fn export_next(&self, cur: &mut AtExportCursor, dst: &mut [u8]) -> usize {
        loop {
            match cur.stage {
                AT_EXPORT_HEADER => {
                    if dst.len() < AT_SNAP_HDR_LEN {
                        return 0;
                    }
                    dst[0..2].copy_from_slice(&Self::SNAPSHOT_VERSION.to_le_bytes());
                    dst[2..4].copy_from_slice(&[0; 2]);
                    dst[4..8].copy_from_slice(&(N as u32).to_le_bytes());
                    dst[8..12].copy_from_slice(&(S as u32).to_le_bytes());
                    dst[12..16].copy_from_slice(&self.admitted.to_le_bytes());
                    dst[16..20].copy_from_slice(&self.admitted_services.to_le_bytes());
                    dst[20..24].copy_from_slice(&self.service_count.to_le_bytes());
                    dst[24..28].copy_from_slice(&self.attachment_count.to_le_bytes());
                    dst[28..36].copy_from_slice(&self.applied.to_le_bytes());
                    cur.stage = AT_EXPORT_SERVICES;
                    cur.pos = 0;
                    return AT_SNAP_HDR_LEN;
                }
                AT_EXPORT_SERVICES => match self.sv_used.next_used(cur.pos as usize) {
                    Some(i) => {
                        if dst.len() < AT_SNAP_SERVICE_LEN {
                            return 0;
                        }
                        let s = &self.services[i];
                        dst[0..4].copy_from_slice(&(i as u32).to_le_bytes());
                        dst[4..36].copy_from_slice(&s.key);
                        dst[36..44].copy_from_slice(&s.revocation_generation.to_le_bytes());
                        dst[44..48].copy_from_slice(&[0; 4]);
                        s.last_op.encode(&mut dst[48..48 + AtOpMemo::LEN]);
                        cur.pos = i as u32 + 1;
                        return AT_SNAP_SERVICE_LEN;
                    }
                    None => {
                        cur.stage = AT_EXPORT_ATTACHMENTS;
                        cur.pos = 0;
                    }
                },
                AT_EXPORT_ATTACHMENTS => match self.at_used.next_used(cur.pos as usize) {
                    Some(i) => {
                        if dst.len() < AT_SNAP_ATTACH_LEN {
                            return 0;
                        }
                        let a = &self.attachments[i];
                        dst[0..4].copy_from_slice(&(i as u32).to_le_bytes());
                        dst[4..20].copy_from_slice(&a.attachment_id);
                        dst[20..24].copy_from_slice(&a.service.to_le_bytes());
                        dst[24..32].copy_from_slice(&a.generation.to_le_bytes());
                        a.last_op.encode(&mut dst[32..32 + AtOpMemo::LEN]);
                        cur.pos = i as u32 + 1;
                        return AT_SNAP_ATTACH_LEN;
                    }
                    None => {
                        cur.stage = AT_EXPORT_DONE;
                        return 0;
                    }
                },
                _ => return 0,
            }
        }
    }

    /// Whole-image restore (host convenience). Fails closed with the
    /// registry cleared.
    pub fn restore(&mut self, src: &[u8]) -> bool {
        let mut ins = self.install_begin();
        let mut o = 0;
        while o < src.len() {
            match self.install_feed(&mut ins, &src[o..]) {
                Ok(n) if n > 0 => o += n,
                _ => break,
            }
        }
        if o != src.len() {
            ins.failed = true;
        }
        self.install_finish(&mut ins)
    }

    pub fn install_begin(&mut self) -> AtInstaller {
        self.clear();
        AtInstaller::new()
    }

    pub fn install_feed(
        &mut self,
        ins: &mut AtInstaller,
        bytes: &[u8],
    ) -> Result<usize, AtInstallRejected> {
        if ins.failed {
            return Err(AtInstallRejected);
        }
        let mut taken = 0;
        while ins.stage != AT_EXPORT_DONE && taken < bytes.len() {
            let want = AtInstaller::stage_len(ins.stage);
            let need = want - ins.carry_len as usize;
            let take = need.min(bytes.len() - taken);
            ins.carry[ins.carry_len as usize..ins.carry_len as usize + take]
                .copy_from_slice(&bytes[taken..taken + take]);
            ins.carry_len += take as u16;
            taken += take;
            if (ins.carry_len as usize) < want {
                break;
            }
            let ok = self.install_unit(ins);
            ins.carry_len = 0;
            if !ok {
                ins.failed = true;
                self.clear();
                return Err(AtInstallRejected);
            }
        }
        Ok(taken)
    }

    /// The stage after the services (or in place of none).
    fn after_services(ins: &AtInstaller) -> u8 {
        if ins.seen < ins.services {
            AT_EXPORT_SERVICES
        } else if ins.seen < ins.services + ins.attachments {
            AT_EXPORT_ATTACHMENTS
        } else {
            AT_EXPORT_DONE
        }
    }

    fn install_unit(&mut self, ins: &mut AtInstaller) -> bool {
        let unit = ins.carry;
        match ins.stage {
            AT_EXPORT_HEADER => {
                if u16::from_le_bytes([unit[0], unit[1]]) != Self::SNAPSHOT_VERSION
                    || unit[2..4] != [0; 2]
                    || u32_at(&unit, 4) != N as u32
                    || u32_at(&unit, 8) != S as u32
                    || u32_at(&unit, 12) != self.admitted
                    || u32_at(&unit, 16) != self.admitted_services
                {
                    return false;
                }
                ins.services = u32_at(&unit, 20);
                ins.attachments = u32_at(&unit, 24);
                if ins.services > self.admitted_services || ins.attachments > self.admitted {
                    return false;
                }
                self.applied = u64_at(&unit, 28);
                ins.stage = Self::after_services(ins);
                true
            }
            AT_EXPORT_SERVICES => {
                let slot = u32_at(&unit, 0) as usize;
                let mut key = [0u8; AT_SERVICE_KEY];
                key.copy_from_slice(&unit[4..36]);
                let rev = u64_at(&unit, 36);
                let Some(last_op) = AtOpMemo::decode(&unit[48..48 + AtOpMemo::LEN]) else {
                    return false;
                };
                if slot >= S
                    || self.sv_used.is_used(slot)
                    || rev == 0
                    || unit[44..48] != [0; 4]
                    || self.sv_index.find(&key).is_some()
                    || !self.sv_index.insert(&key, slot as u32)
                {
                    return false;
                }
                self.sv_used.mark(slot);
                // The attachment count is rebuilt from the attachments.
                self.services[slot] = ServiceSlot {
                    key,
                    revocation_generation: rev,
                    attachments: 0,
                    last_op,
                };
                self.service_count += 1;
                ins.seen += 1;
                ins.stage = Self::after_services(ins);
                true
            }
            AT_EXPORT_ATTACHMENTS => {
                let slot = u32_at(&unit, 0) as usize;
                let mut id = [0u8; AT_ID];
                id.copy_from_slice(&unit[4..20]);
                let sv = u32_at(&unit, 20) as usize;
                let generation = u64_at(&unit, 24);
                let Some(last_op) = AtOpMemo::decode(&unit[32..32 + AtOpMemo::LEN]) else {
                    return false;
                };
                if slot >= N
                    || self.at_used.is_used(slot)
                    || sv >= S
                    || !self.sv_used.is_used(sv)
                    || generation == 0
                    || id == [0; AT_ID]
                    || self.at_index.find(&id).is_some()
                    || !self.at_index.insert(&id, slot as u32)
                {
                    return false;
                }
                self.at_used.mark(slot);
                self.attachments[slot] = AttachmentSlot {
                    attachment_id: id,
                    service: sv as u32,
                    generation,
                    last_op,
                };
                self.services[sv].attachments += 1;
                self.attachment_count += 1;
                ins.seen += 1;
                ins.stage = Self::after_services(ins);
                true
            }
            _ => false,
        }
    }

    pub fn install_finish(&mut self, ins: &mut AtInstaller) -> bool {
        let complete = !ins.failed && ins.stage == AT_EXPORT_DONE && ins.carry_len == 0;
        if !complete {
            ins.failed = true;
            self.clear();
        }
        complete
    }
}

pub const AT_SNAP_HDR_LEN: usize = 36;
pub const AT_SNAP_SERVICE_LEN: usize = 48 + AtOpMemo::LEN;
pub const AT_SNAP_ATTACH_LEN: usize = 32 + AtOpMemo::LEN;
pub const AT_SNAP_MAX_UNIT: usize = AT_SNAP_SERVICE_LEN;

pub const AT_EXPORT_HEADER: u8 = 0;
pub const AT_EXPORT_SERVICES: u8 = 1;
pub const AT_EXPORT_ATTACHMENTS: u8 = 2;
pub const AT_EXPORT_DONE: u8 = 3;

/// A streamed install rejected the image; the registry is left cleared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AtInstallRejected;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct AtExportCursor {
    pub stage: u8,
    pub pos: u32,
}

impl Default for AtExportCursor {
    fn default() -> Self {
        Self::new()
    }
}

impl AtExportCursor {
    pub const fn new() -> Self {
        AtExportCursor {
            stage: AT_EXPORT_HEADER,
            pos: 0,
        }
    }

    pub fn done(&self) -> bool {
        self.stage == AT_EXPORT_DONE
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct AtInstaller {
    pub stage: u8,
    pub failed: bool,
    pub carry_len: u16,
    /// Records the header promises, and those seen.
    pub services: u32,
    pub attachments: u32,
    pub seen: u32,
    pub carry: [u8; AT_SNAP_MAX_UNIT],
}

impl Default for AtInstaller {
    fn default() -> Self {
        Self::new()
    }
}

impl AtInstaller {
    pub const fn new() -> Self {
        AtInstaller {
            stage: AT_EXPORT_HEADER,
            failed: false,
            carry_len: 0,
            services: 0,
            attachments: 0,
            seen: 0,
            carry: [0; AT_SNAP_MAX_UNIT],
        }
    }

    pub fn done(&self) -> bool {
        self.stage == AT_EXPORT_DONE && !self.failed
    }

    /// Bytes one unit of `stage` occupies.
    pub fn stage_len(stage: u8) -> usize {
        match stage {
            AT_EXPORT_HEADER => AT_SNAP_HDR_LEN,
            AT_EXPORT_SERVICES => AT_SNAP_SERVICE_LEN,
            AT_EXPORT_ATTACHMENTS => AT_SNAP_ATTACH_LEN,
            _ => 0,
        }
    }
}
