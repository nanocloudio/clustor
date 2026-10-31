// Region registry — the `rg/<service>` namespace of the session directory:
// the global tier, where a low-rate global group commits each service's
// region owner set, its disaster-recovery generation and regional
// invalidation (docs/architecture/multi_site.md).
//
// Pure no_std, zero-alloc, DETERMINISTIC: `RegionRegistry::apply` is a pure
// function of (state, committed command body, digest fn); every replica
// applying the same committed sequence holds byte-identical state. No
// clocks, no randomness, no I/O. The PIC module wrapper
// (`modules/app/session_directory/mod.rs`) hosts it beside the other
// registries, dispatching on the `"RG"` magic; `clustor-common` mounts it
// for host tests and for Wormhole's region controller.
//
// **The owner set is a VIP binding of regions.** A service's global
// binding is exactly the `vip/` state machine (`vip_registry.rs`) — owner
// sets in active/active, exclusive ownership with confirmed fencing in
// active/passive, per-command epochs, idempotent operation ids,
// unsafe-recovery voiding, emission tokens — with regions as owners, keyed
// by the service's global key (`vip_key` over its anycast prefix). Every
// `VB_OP_*` command is accepted here byte-for-byte in its `vip/` layout,
// so a region controller built on the VIP builders drives `rg/` unchanged,
// and every reply carries the `VipReply` it already reads. The registry is
// as wide as the deployment has regions (`RG_OWNERS_*`), not as wide as a
// cell's ingress set.
//
// What this namespace adds:
//
// - **the DR generation.** Each binding counts its committed owner-set
//   changes: an ACTIVATE that commits a region, a RELEASE that removes one
//   or ends the set, a RECOVERY_MARK that voids it (only a binding the mark
//   actually voids), an ABORT that leaves a recovered claim's record void,
//   an INVALIDATE that voids one of its regions' owners (only owners not
//   already void under an earlier INVALIDATE). A retry changes nothing and
//   counts nothing. The count is replicated state, so a restarted
//   controller, or the other region's, reads the generation the group
//   committed rather than re-counting; every reply carries the binding's
//   current one (`RgReply::dr_generation`), a retry's included. It
//   saturates at `u64::MAX`.
// - **regional invalidation.** INVALIDATE `[op_id:16][region:16]
//   [readiness:8]` records that `region`'s authority ends at readiness
//   generation `readiness`, across every binding of the group: an owner
//   of that region admitted at or below it does not verify a token or
//   reissue one, an ACTIVATE that would commit it is refused, and a claim
//   naming it at or below it is refused — the region comes back only
//   through a claim under a newer readiness generation (a fresh boot and
//   readiness). Per region the readiness only advances. The owner
//   stays in the set until a RELEASE or a replacing claim removes it under
//   the VIP rules (a confirmed regional fence), so invalidation never
//   stands in for a fence; it is the committed, group-wide statement that
//   a lost or drained region's old authority is void.
// - **region boot incarnation.** A region owner's `boot_incarnation` is
//   `[tag:8][readiness_generation:u64 LE]` (Wormhole's `region_boot`): the
//   readiness it was admitted under is the boot's second half.
// - **its own seed.** Tokens are minted under a seed derived from the
//   group's capability seed (`adopt_seed`: SHA-256 over a domain tag and
//   the VIP seed, applied when the directory's VIP SEED commits), so a
//   `vip/` token and an `rg/` token for the same key and host never
//   verify for each other. SEED is not accepted in this namespace.
//
// A proposer routes a service to the global group like any directory key;
// the module's `partition_id` names the group this registry holds.

use super::vip_registry::{
    DigestFn, EmissionToken, VbExportCursor, VbInstaller, VipRegistry, VipReply,
    VB_BOOT_INCARNATION, VB_HOST_ID, VB_KEY, VB_MAX_CMD, VB_OP_ACTIVATE, VB_OP_CLAIM_PREPARE,
    VB_OP_ID, VB_OP_RECOVERY_MARK, VB_OP_SEED, VB_OP_TOKEN_REISSUE, VB_PHASE_FENCING_OLD,
    VB_REPLY_LEN, VB_SEED, VB_SEED_LEN, VB_SNAP_MAX_UNIT, VB_ST_CAPACITY, VB_ST_CONFLICT,
    VB_ST_INVALID, VB_ST_OK, VB_ST_RECOVERY_STALE,
};

// ── Capacity ────────────────────────────────────────────────────────

/// Profiles: services per global group, and regions one service's owner
/// set admits. The global tier is low-rate and low-volume: few bindings,
/// wide sets.
pub const RG_PROFILE_RP2350: usize = 4;
pub const RG_OWNERS_RP2350: usize = 8;
pub const RG_PROFILE_PI5: usize = 64;
pub const RG_OWNERS_PI5: usize = 16;
pub const RG_PROFILE_SERVER: usize = 1024;
pub const RG_OWNERS_SERVER: usize = 64;

/// Regions the invalidation table holds: one entry per region ever
/// invalidated (a later invalidation of the same region advances its
/// entry), so it bounds the regions of a deployment, not the events.
pub const RG_MAX_REGIONS: usize = 64;

// ── Commands ────────────────────────────────────────────────────────

/// Regional invalidation: `[op:1][op_id:16][region:16][readiness:8]`.
pub const RG_OP_INVALIDATE: u8 = 32;
pub const RG_INVALIDATE_LEN: usize = 1 + VB_OP_ID + VB_HOST_ID + 8;
/// Largest command body: a VIP command (CLAIM_PREPARE).
pub const RG_MAX_CMD: usize = if VB_MAX_CMD > RG_INVALIDATE_LEN {
    VB_MAX_CMD
} else {
    RG_INVALIDATE_LEN
};

/// The region (or one its readiness names) is invalidated at or above the
/// readiness the command needs.
pub const RG_ST_INVALIDATED: u8 = 32;

pub fn build_invalidate(
    dst: &mut [u8],
    op_id: &[u8; VB_OP_ID],
    region: &[u8; VB_HOST_ID],
    readiness: u64,
) -> usize {
    if dst.len() < RG_INVALIDATE_LEN || *region == [0; VB_HOST_ID] || readiness == 0 {
        return 0;
    }
    dst[0] = RG_OP_INVALIDATE;
    dst[1..17].copy_from_slice(op_id);
    dst[17..33].copy_from_slice(region);
    dst[33..41].copy_from_slice(&readiness.to_le_bytes());
    RG_INVALIDATE_LEN
}

/// The readiness generation a region owner's boot incarnation names.
pub fn boot_readiness(boot: &[u8; VB_BOOT_INCARNATION]) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&boot[8..16]);
    u64::from_le_bytes(b)
}

const RG_SEED_TAG: [u8; 16] = *b"clustor-rg-seed1";

// ── Reply ───────────────────────────────────────────────────────────

/// Encoded reply: `[VipReply: VB_REPLY_LEN][dr_generation:8]
/// [invalidated_readiness:8]`. For a VIP command, `dr_generation` is the
/// binding's after the apply and `invalidated_readiness` the readiness a
/// refused region is invalidated at (0 otherwise); for INVALIDATE, the
/// count of bindings whose DR generation advanced and the readiness now
/// recorded.
pub const RG_REPLY_LEN: usize = VB_REPLY_LEN + 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct RgReply {
    pub vip: VipReply,
    pub dr_generation: u64,
    pub invalidated_readiness: u64,
}

impl RgReply {
    pub const fn zero() -> Self {
        RgReply {
            vip: VipReply::zero(),
            dr_generation: 0,
            invalidated_readiness: 0,
        }
    }

    pub fn encode(&self, dst: &mut [u8]) -> i32 {
        if dst.len() < RG_REPLY_LEN || self.vip.encode(dst) < 0 {
            return -1;
        }
        dst[VB_REPLY_LEN..VB_REPLY_LEN + 8].copy_from_slice(&self.dr_generation.to_le_bytes());
        dst[VB_REPLY_LEN + 8..RG_REPLY_LEN]
            .copy_from_slice(&self.invalidated_readiness.to_le_bytes());
        RG_REPLY_LEN as i32
    }

    pub fn decode(src: &[u8]) -> Option<RgReply> {
        if src.len() < RG_REPLY_LEN {
            return None;
        }
        Some(RgReply {
            vip: VipReply::decode(src)?,
            dr_generation: u64_at(src, VB_REPLY_LEN),
            invalidated_readiness: u64_at(src, VB_REPLY_LEN + 8),
        })
    }
}

fn u32_at(src: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([src[o], src[o + 1], src[o + 2], src[o + 3]])
}

fn u64_at(src: &[u8], o: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&src[o..o + 8]);
    u64::from_le_bytes(b)
}

// ── State ───────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct RgInvalidation {
    pub region: [u8; VB_HOST_ID],
    /// Owners of `region` admitted at or below this readiness are void.
    pub readiness: u64,
}

impl RgInvalidation {
    pub const fn empty() -> Self {
        RgInvalidation {
            region: [0; VB_HOST_ID],
            readiness: 0,
        }
    }
}

/// The last INVALIDATE the registry answered, whole (the VIP registry
/// keeps its own memos for binding and registry commands).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct RgOpMemo {
    pub present: bool,
    pub cmd: [u8; RG_INVALIDATE_LEN],
    pub reply: RgReply,
}

impl RgOpMemo {
    /// `[present:1][cmd: RG_INVALIDATE_LEN][reply: RG_REPLY_LEN]`.
    pub const LEN: usize = 1 + RG_INVALIDATE_LEN + RG_REPLY_LEN;

    pub const fn empty() -> Self {
        RgOpMemo {
            present: false,
            cmd: [0; RG_INVALIDATE_LEN],
            reply: RgReply::zero(),
        }
    }

    fn encode(&self, dst: &mut [u8]) {
        dst[0] = self.present as u8;
        dst[1..1 + RG_INVALIDATE_LEN].copy_from_slice(&self.cmd);
        let _ = self
            .reply
            .encode(&mut dst[1 + RG_INVALIDATE_LEN..Self::LEN]);
    }

    /// A memo the registry could have written: absent and all zero, or
    /// an INVALIDATE naming a region and a readiness.
    fn decode(src: &[u8]) -> Option<RgOpMemo> {
        if src[0] > 1 {
            return None;
        }
        let mut m = RgOpMemo::empty();
        m.present = src[0] != 0;
        m.cmd.copy_from_slice(&src[1..1 + RG_INVALIDATE_LEN]);
        m.reply = RgReply::decode(&src[1 + RG_INVALIDATE_LEN..Self::LEN])?;
        if !m.present {
            return (m == Self::empty()).then_some(m);
        }
        let named = m.cmd[17..33] != [0; 16] && m.cmd[33..41] != [0; 8];
        (m.cmd[0] == RG_OP_INVALIDATE && named).then_some(m)
    }
}

/// The replicated state machine: `N` services (a power of two), owner sets
/// `O` regions wide.
#[repr(C)]
pub struct RegionRegistry<const N: usize, const O: usize> {
    /// The owner sets: the VIP state machine, regions as owners.
    pub vip: VipRegistry<N, O>,
    /// Each binding's DR generation, by the VIP registry's slot.
    pub dr_generation: [u64; N],
    pub invalidations: [RgInvalidation; RG_MAX_REGIONS],
    pub invalidation_count: u32,
    pub applied: u64,
    pub last_op: RgOpMemo,
    /// Transient, within one RECOVERY_MARK: the bindings not yet void
    /// before it. Zero between commands; never serialized.
    unvoided: [bool; N],
}

impl<const N: usize, const O: usize> RegionRegistry<N, O> {
    /// `seed` is the group's capability seed (all-zero: unseeded); the
    /// registry mints under the seed derived from it.
    pub fn new(seed: &[u8; VB_SEED], digest: DigestFn) -> Self {
        let mut r = RegionRegistry {
            vip: VipRegistry::new(&[0; VB_SEED]),
            dr_generation: [0; N],
            invalidations: [RgInvalidation::empty(); RG_MAX_REGIONS],
            invalidation_count: 0,
            applied: 0,
            last_op: RgOpMemo::empty(),
            unvoided: [false; N],
        };
        if *seed != [0; VB_SEED] {
            r.vip.seed = Self::derive_seed(seed, digest);
        }
        r
    }

    /// Initialise in place, admitting `admitted` services: every byte of
    /// the state, unseeded.
    pub fn reset(&mut self, admitted: u32) {
        self.vip.reset(admitted);
        self.dr_generation = [0; N];
        self.invalidations = [RgInvalidation::empty(); RG_MAX_REGIONS];
        self.invalidation_count = 0;
        self.applied = 0;
        self.last_op = RgOpMemo::empty();
        self.unvoided = [false; N];
    }

    /// Empty an initialised registry, keeping what it admits.
    pub fn clear(&mut self) {
        self.vip.clear();
        self.dr_generation = [0; N];
        self.invalidations = [RgInvalidation::empty(); RG_MAX_REGIONS];
        self.invalidation_count = 0;
        self.applied = 0;
        self.last_op = RgOpMemo::empty();
        self.unvoided = [false; N];
    }

    fn derive_seed(seed: &[u8; VB_SEED], digest: DigestFn) -> [u8; VB_SEED] {
        let mut m = [0u8; 16 + VB_SEED];
        m[..16].copy_from_slice(&RG_SEED_TAG);
        m[16..].copy_from_slice(seed);
        digest(&m)
    }

    /// The directory's VIP SEED committed (`seed_cmd` is its body): seed
    /// this namespace under the derived seed. DETERMINISTIC, once per
    /// group's life like the VIP seed; a second adoption changes nothing.
    pub fn adopt_seed(&mut self, seed_cmd: &[u8], digest: DigestFn) {
        if seed_cmd.len() < VB_SEED_LEN || seed_cmd[0] != VB_OP_SEED || self.vip.seeded() {
            return;
        }
        let mut seed = [0u8; VB_SEED];
        seed.copy_from_slice(&seed_cmd[17..49]);
        if seed == [0; VB_SEED] {
            return;
        }
        let mut body = [0u8; VB_SEED_LEN];
        body.copy_from_slice(&seed_cmd[..VB_SEED_LEN]);
        body[17..49].copy_from_slice(&Self::derive_seed(&seed, digest));
        let _ = self.vip.apply(&body, digest);
    }

    /// The readiness `region` is invalidated at (0: never).
    pub fn invalidated_at(&self, region: &[u8; VB_HOST_ID]) -> u64 {
        let mut i = 0;
        while i < self.invalidation_count as usize {
            if self.invalidations[i].region == *region {
                return self.invalidations[i].readiness;
            }
            i += 1;
        }
        0
    }

    /// Whether `region` admitted under `boot` is void.
    pub fn void(&self, region: &[u8; VB_HOST_ID], boot: &[u8; VB_BOOT_INCARNATION]) -> bool {
        let at = self.invalidated_at(region);
        at != 0 && boot_readiness(boot) <= at
    }

    pub fn dr_generation_of(&self, key: &[u8; VB_KEY]) -> Option<u64> {
        self.vip.slot_of(key).map(|i| self.dr_generation[i])
    }

    /// The token region `host` holds for `key`, unless it is void.
    pub fn emission_token(
        &self,
        key: &[u8; VB_KEY],
        host: &[u8; VB_HOST_ID],
        digest: DigestFn,
    ) -> Option<EmissionToken> {
        let t = self.vip.emission_token(key, host, digest)?;
        if self.void(&t.owner_host, &t.boot_incarnation) {
            return None;
        }
        Some(t)
    }

    /// The VIP verification, then the invalidation: a void region's token
    /// is `RG_ST_INVALIDATED`.
    pub fn verify_emission_token(&self, token: &EmissionToken, digest: DigestFn) -> Result<(), u8> {
        self.vip.verify_emission_token(token, digest)?;
        if self.void(&token.owner_host, &token.boot_incarnation) {
            return Err(RG_ST_INVALIDATED);
        }
        Ok(())
    }

    fn wrap(&self, vip: VipReply) -> RgReply {
        RgReply {
            vip,
            dr_generation: self.dr_generation_of(&vip.key).unwrap_or(0),
            invalidated_readiness: 0,
        }
    }

    /// A VIP command refused here before the VIP registry sees it.
    fn refuse(&self, op: u8, key: &[u8; VB_KEY], status: u8, readiness: u64) -> RgReply {
        let mut v = VipReply::zero();
        v.op = op;
        v.status = status;
        v.key = *key;
        v.unsafe_recovery_generation = self.vip.unsafe_recovery_generation;
        if let Some(s) = self.vip.lookup(key) {
            v.phase = s.phase;
            v.mode = s.mode;
            v.owner_count = s.owner_count;
            v.vip_epoch = s.vip_epoch;
            v.authority_generation = s.authority_generation;
        }
        let mut r = self.wrap(v);
        r.invalidated_readiness = readiness;
        r
    }

    /// The owner set as a DR generation sees it: a change to any of these
    /// is one committed owner-set change.
    fn owner_state(&self, slot: usize) -> (u64, u8, bool, [[u8; VB_HOST_ID]; O]) {
        let s = &self.vip.slots[slot];
        (s.authority_generation, s.owner_count, s.voided, s.owners)
    }

    /// Apply one committed command body. DETERMINISTIC given `digest`.
    pub fn apply(&mut self, body: &[u8], digest: DigestFn) -> RgReply {
        self.applied = self.applied.wrapping_add(1);
        let Some(&op) = body.first() else {
            let mut r = RgReply::zero();
            r.vip.status = VB_ST_INVALID;
            return r;
        };
        match op {
            RG_OP_INVALIDATE => return self.apply_invalidate(body),
            VB_OP_SEED => {
                let mut r = RgReply::zero();
                r.vip.op = op;
                r.vip.status = VB_ST_INVALID;
                return r;
            }
            VB_OP_RECOVERY_MARK => {
                // Only a binding the mark voids has had its owner set
                // changed: one already void, or a claim in flight (voided
                // by its ABORT, if it comes), is not counted here.
                let mut at = 0;
                while let Some(i) = self.vip.next_binding(at) {
                    self.unvoided[i] = !self.vip.slots[i].voided;
                    at = i + 1;
                }
                let r = self.vip.apply(body, digest);
                let mut at = 0;
                while let Some(i) = self.vip.next_binding(at) {
                    if self.unvoided[i] && self.vip.slots[i].voided {
                        self.dr_generation[i] = self.dr_generation[i].saturating_add(1);
                    }
                    self.unvoided[i] = false;
                    at = i + 1;
                }
                return self.wrap(r);
            }
            _ => {}
        }
        // Binding commands carry their key at [17..51] (a short body is the
        // VIP registry's to refuse).
        if body.len() < 51 {
            let r = self.vip.apply(body, digest);
            return self.wrap(r);
        }
        let mut key = [0u8; VB_KEY];
        key.copy_from_slice(&body[17..51]);
        let slot = self.vip.slot_of(&key);
        let retry = slot.is_some_and(|i| {
            let m = &self.vip.slots[i].last_op;
            m.present && m.cmd_len as usize == body.len() && m.cmd[..body.len()] == *body
        });
        if !retry {
            if let Some(refused) = self.invalidation_gate(op, body, &key, slot) {
                return refused;
            }
        }
        let before = slot.map(|i| self.owner_state(i));
        let mut r = self.vip.apply(body, digest);
        if let Some(i) = self.vip.slot_of(&key) {
            let changed = match before {
                Some(b) => b != self.owner_state(i),
                None => self.vip.slots[i].owner_count != 0,
            };
            if changed && r.status == VB_ST_OK {
                self.dr_generation[i] = self.dr_generation[i].saturating_add(1);
            }
        }
        if op == VB_OP_TOKEN_REISSUE
            && r.token_present
            && self.void(&r.token.owner_host, &r.token.boot_incarnation)
        {
            let at = self.invalidated_at(&r.token.owner_host);
            r.token_present = false;
            r.token = EmissionToken::zero();
            r.status = RG_ST_INVALIDATED;
            let mut w = self.wrap(r);
            w.invalidated_readiness = at;
            return w;
        }
        self.wrap(r)
    }

    /// A claim naming a void region, or an ACTIVATE that would commit one,
    /// is refused before the VIP registry applies it.
    fn invalidation_gate(
        &self,
        op: u8,
        body: &[u8],
        key: &[u8; VB_KEY],
        slot: Option<usize>,
    ) -> Option<RgReply> {
        let (host, boot) = match op {
            VB_OP_CLAIM_PREPARE if body.len() >= 92 => {
                let mut host = [0u8; VB_HOST_ID];
                host.copy_from_slice(&body[60..76]);
                let mut boot = [0u8; VB_BOOT_INCARNATION];
                boot.copy_from_slice(&body[76..92]);
                (host, boot)
            }
            VB_OP_ACTIVATE => {
                let s = &self.vip.slots[slot?];
                if s.phase != VB_PHASE_FENCING_OLD || s.prepared_count == 0 {
                    return None;
                }
                (s.prepared[0], s.prepared_boot[0])
            }
            _ => return None,
        };
        if self.void(&host, &boot) {
            return Some(self.refuse(op, key, RG_ST_INVALIDATED, self.invalidated_at(&host)));
        }
        None
    }

    fn apply_invalidate(&mut self, body: &[u8]) -> RgReply {
        let mut r = RgReply::zero();
        r.vip.op = RG_OP_INVALIDATE;
        r.vip.unsafe_recovery_generation = self.vip.unsafe_recovery_generation;
        if body.len() != RG_INVALIDATE_LEN {
            r.vip.status = VB_ST_INVALID;
            return r;
        }
        if self.last_op.present && self.last_op.cmd[1..17] == body[1..17] {
            if self.last_op.cmd[..] == *body {
                return self.last_op.reply;
            }
            r.vip.status = VB_ST_CONFLICT;
            return r;
        }
        let mut region = [0u8; VB_HOST_ID];
        region.copy_from_slice(&body[17..33]);
        let readiness = u64_at(body, 33);
        let reply = if region == [0; VB_HOST_ID] || readiness == 0 {
            r.vip.status = VB_ST_INVALID;
            r
        } else {
            self.invalidate(region, readiness, r)
        };
        self.last_op.present = true;
        self.last_op.cmd.copy_from_slice(body);
        self.last_op.reply = reply;
        reply
    }

    fn invalidate(&mut self, region: [u8; VB_HOST_ID], readiness: u64, mut r: RgReply) -> RgReply {
        let n = self.invalidation_count as usize;
        let at = (0..n).find(|&i| self.invalidations[i].region == region);
        // Owners admitted at or below the earlier readiness were void
        // already: only the ones this raise reaches change their set.
        let earlier = at.map_or(0, |i| self.invalidations[i].readiness);
        match at {
            Some(i) if readiness <= self.invalidations[i].readiness => {
                r.vip.status = VB_ST_RECOVERY_STALE;
                r.invalidated_readiness = self.invalidations[i].readiness;
                return r;
            }
            Some(i) => self.invalidations[i].readiness = readiness,
            None if n >= RG_MAX_REGIONS => {
                r.vip.status = VB_ST_CAPACITY;
                return r;
            }
            None => {
                self.invalidations[n] = RgInvalidation { region, readiness };
                self.invalidation_count += 1;
            }
        }
        // Every binding the region holds authority in under a readiness
        // this raise voids has had its owner set changed.
        let mut touched = 0u64;
        let mut i = 0;
        while let Some(b) = self.vip.next_binding(i) {
            let s = &self.vip.slots[b];
            let holds = (0..s.owner_count as usize).any(|k| {
                let at = boot_readiness(&s.owner_boot[k]);
                s.owners[k] == region && at > earlier && at <= readiness
            });
            if holds {
                self.dr_generation[b] = self.dr_generation[b].saturating_add(1);
                touched += 1;
            }
            i = b + 1;
        }
        r.vip.status = VB_ST_OK;
        r.dr_generation = touched;
        r.invalidated_readiness = readiness;
        r
    }

    // ── Snapshot (streamed, versioned) ──────────────────────────────
    //
    //   header [version:u16 = 1][owner width O:u16][arena N:u32]
    //          [invalidation_count:u32][reserved:u32][applied:u64]
    //          [last_op: RgOpMemo::LEN]
    //   then the VIP registry's own image (`VipRegistry::export_next`)
    //   dr     [slot:u32][dr_generation:u64] × the VIP image's record
    //          count, in slot order
    //   inval  [region:16][readiness:u64] × invalidation_count, in table
    //          order

    pub const SNAPSHOT_VERSION: u16 = 1;

    pub fn snapshot_len(&self) -> usize {
        RG_SNAP_HDR_LEN
            + self.vip.snapshot_len()
            + self.vip.live as usize * RG_SNAP_DR_LEN
            + self.invalidation_count as usize * RG_SNAP_INVAL_LEN
    }

    pub fn snapshot(&self, dst: &mut [u8]) -> i32 {
        if dst.len() < self.snapshot_len() {
            return -1;
        }
        let mut cur = RgExportCursor::new();
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

    /// Next unit of the streamed export into `dst` (≥ `RG_SNAP_MAX_UNIT`);
    /// 0 once complete.
    pub fn export_next(&self, cur: &mut RgExportCursor, dst: &mut [u8]) -> usize {
        loop {
            match cur.stage {
                RG_EXPORT_HEADER => {
                    if dst.len() < RG_SNAP_HDR_LEN {
                        return 0;
                    }
                    dst[0..2].copy_from_slice(&Self::SNAPSHOT_VERSION.to_le_bytes());
                    dst[2..4].copy_from_slice(&(O as u16).to_le_bytes());
                    dst[4..8].copy_from_slice(&(N as u32).to_le_bytes());
                    dst[8..12].copy_from_slice(&self.invalidation_count.to_le_bytes());
                    dst[12..16].copy_from_slice(&0u32.to_le_bytes());
                    dst[16..24].copy_from_slice(&self.applied.to_le_bytes());
                    self.last_op.encode(&mut dst[24..24 + RgOpMemo::LEN]);
                    cur.stage = RG_EXPORT_VIP;
                    return RG_SNAP_HDR_LEN;
                }
                RG_EXPORT_VIP => {
                    let n = self.vip.export_next(&mut cur.vb, dst);
                    if n > 0 {
                        return n;
                    }
                    // Zero is the VIP image's end, or a `dst` too short for
                    // its next unit: its cursor says which.
                    if !cur.vb.done() {
                        return 0;
                    }
                    cur.stage = RG_EXPORT_DR;
                    cur.pos = 0;
                }
                RG_EXPORT_DR => match self.vip.next_binding(cur.pos as usize) {
                    Some(i) => {
                        if dst.len() < RG_SNAP_DR_LEN {
                            return 0;
                        }
                        dst[0..4].copy_from_slice(&(i as u32).to_le_bytes());
                        dst[4..12].copy_from_slice(&self.dr_generation[i].to_le_bytes());
                        cur.pos = i as u32 + 1;
                        return RG_SNAP_DR_LEN;
                    }
                    None => {
                        cur.stage = RG_EXPORT_INVAL;
                        cur.pos = 0;
                    }
                },
                RG_EXPORT_INVAL => {
                    if cur.pos >= self.invalidation_count {
                        cur.stage = RG_EXPORT_DONE;
                        return 0;
                    }
                    if dst.len() < RG_SNAP_INVAL_LEN {
                        return 0;
                    }
                    let e = &self.invalidations[cur.pos as usize];
                    dst[0..16].copy_from_slice(&e.region);
                    dst[16..24].copy_from_slice(&e.readiness.to_le_bytes());
                    cur.pos += 1;
                    return RG_SNAP_INVAL_LEN;
                }
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

    pub fn install_begin(&mut self) -> RgInstaller {
        self.clear();
        let mut ins = RgInstaller::new();
        ins.vb = self.vip.install_begin();
        ins
    }

    pub fn install_feed(
        &mut self,
        ins: &mut RgInstaller,
        bytes: &[u8],
    ) -> Result<usize, RgInstallRejected> {
        if ins.failed {
            return Err(RgInstallRejected);
        }
        let mut taken = 0;
        while ins.stage != RG_EXPORT_DONE && taken < bytes.len() {
            if ins.stage == RG_EXPORT_VIP {
                let Ok(n) = self.vip.install_feed(&mut ins.vb, &bytes[taken..]) else {
                    return Err(self.reject(ins));
                };
                taken += n;
                if !ins.vb.done() {
                    if n == 0 {
                        return Err(self.reject(ins));
                    }
                    continue;
                }
                ins.expected = self.vip.live;
                ins.seen = 0;
                ins.stage = Self::after_dr(ins);
                continue;
            }
            let want = RgInstaller::stage_len(ins.stage);
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
                return Err(self.reject(ins));
            }
        }
        Ok(taken)
    }

    fn reject(&mut self, ins: &mut RgInstaller) -> RgInstallRejected {
        ins.failed = true;
        self.clear();
        RgInstallRejected
    }

    /// The stage after the DR records (or in place of none).
    fn after_dr(ins: &RgInstaller) -> u8 {
        if ins.seen < ins.expected {
            RG_EXPORT_DR
        } else if ins.inval_expected > 0 {
            RG_EXPORT_INVAL
        } else {
            RG_EXPORT_DONE
        }
    }

    fn install_unit(&mut self, ins: &mut RgInstaller) -> bool {
        let unit = ins.carry;
        match ins.stage {
            RG_EXPORT_HEADER => {
                if u16::from_le_bytes([unit[0], unit[1]]) != Self::SNAPSHOT_VERSION
                    || u16::from_le_bytes([unit[2], unit[3]]) as usize != O
                    || u32_at(&unit, 4) != N as u32
                    || u32_at(&unit, 12) != 0
                {
                    return false;
                }
                let count = u32_at(&unit, 8);
                if count as usize > RG_MAX_REGIONS {
                    return false;
                }
                let Some(last_op) = RgOpMemo::decode(&unit[24..24 + RgOpMemo::LEN]) else {
                    return false;
                };
                ins.inval_expected = count;
                self.applied = u64_at(&unit, 16);
                self.last_op = last_op;
                ins.stage = RG_EXPORT_VIP;
                true
            }
            RG_EXPORT_DR => {
                let slot = u32_at(&unit, 0) as usize;
                // Every binding, once, in slot order.
                if slot >= N
                    || !self.vip.slots[slot].used
                    || (ins.seen > 0 && slot as u32 <= ins.last_slot)
                {
                    return false;
                }
                self.dr_generation[slot] = u64_at(&unit, 4);
                ins.last_slot = slot as u32;
                ins.seen += 1;
                ins.stage = Self::after_dr(ins);
                true
            }
            RG_EXPORT_INVAL => {
                let mut region = [0u8; VB_HOST_ID];
                region.copy_from_slice(&unit[0..16]);
                let readiness = u64_at(&unit, 16);
                if region == [0; VB_HOST_ID] || readiness == 0 || self.invalidated_at(&region) != 0
                {
                    return false;
                }
                let n = self.invalidation_count as usize;
                self.invalidations[n] = RgInvalidation { region, readiness };
                self.invalidation_count += 1;
                if self.invalidation_count == ins.inval_expected {
                    ins.stage = RG_EXPORT_DONE;
                }
                true
            }
            _ => false,
        }
    }

    pub fn install_finish(&mut self, ins: &mut RgInstaller) -> bool {
        let vip = self.vip.install_finish(&mut ins.vb);
        let complete = vip && !ins.failed && ins.stage == RG_EXPORT_DONE && ins.carry_len == 0;
        if !complete {
            ins.failed = true;
            self.clear();
        }
        complete
    }
}

pub const RG_SNAP_HDR_LEN: usize = 24 + RgOpMemo::LEN;
pub const RG_SNAP_DR_LEN: usize = 4 + 8;
pub const RG_SNAP_INVAL_LEN: usize = VB_HOST_ID + 8;
/// Largest unit the registry stages itself (the VIP units go through the
/// VIP installer's own carry).
pub const RG_SNAP_OWN_UNIT: usize = RG_SNAP_HDR_LEN;
/// Largest unit an export writes: the header or a VIP unit.
pub const RG_SNAP_MAX_UNIT: usize = if RG_SNAP_HDR_LEN > VB_SNAP_MAX_UNIT {
    RG_SNAP_HDR_LEN
} else {
    VB_SNAP_MAX_UNIT
};

pub const RG_EXPORT_HEADER: u8 = 0;
pub const RG_EXPORT_VIP: u8 = 1;
pub const RG_EXPORT_DR: u8 = 2;
pub const RG_EXPORT_INVAL: u8 = 3;
pub const RG_EXPORT_DONE: u8 = 4;

/// A streamed install rejected the image; the registry is left cleared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RgInstallRejected;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct RgExportCursor {
    pub stage: u8,
    pub pos: u32,
    pub vb: VbExportCursor,
}

impl Default for RgExportCursor {
    fn default() -> Self {
        Self::new()
    }
}

impl RgExportCursor {
    pub const fn new() -> Self {
        RgExportCursor {
            stage: RG_EXPORT_HEADER,
            pos: 0,
            vb: VbExportCursor::new(),
        }
    }

    pub fn done(&self) -> bool {
        self.stage == RG_EXPORT_DONE
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct RgInstaller {
    pub stage: u8,
    pub failed: bool,
    pub carry_len: u16,
    /// DR records the VIP image's record count promises, and those seen.
    pub expected: u32,
    pub seen: u32,
    pub last_slot: u32,
    pub inval_expected: u32,
    pub vb: VbInstaller,
    pub carry: [u8; RG_SNAP_OWN_UNIT],
}

impl Default for RgInstaller {
    fn default() -> Self {
        Self::new()
    }
}

impl RgInstaller {
    pub const fn new() -> Self {
        RgInstaller {
            stage: RG_EXPORT_HEADER,
            failed: false,
            carry_len: 0,
            expected: 0,
            seen: 0,
            last_slot: 0,
            inval_expected: 0,
            vb: VbInstaller::new(),
            carry: [0; RG_SNAP_OWN_UNIT],
        }
    }

    pub fn done(&self) -> bool {
        self.stage == RG_EXPORT_DONE && !self.failed
    }

    /// Bytes one of the registry's own units of `stage` occupies.
    pub fn stage_len(stage: u8) -> usize {
        match stage {
            RG_EXPORT_HEADER => RG_SNAP_HDR_LEN,
            RG_EXPORT_DR => RG_SNAP_DR_LEN,
            RG_EXPORT_INVAL => RG_SNAP_INVAL_LEN,
            _ => 0,
        }
    }
}
