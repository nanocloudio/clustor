// VIP registry — the `vip/<service_address>` namespace of the session
// directory: the replicated authority for who may
// source a service address, under which epoch, and the opaque emission
// token that proves it.
//
// Pure no_std, zero-alloc, DETERMINISTIC: `VipRegistry::apply` is a pure
// function of (state, committed command body, digest fn); every replica
// applying the same committed sequence holds byte-identical state. No
// clocks, no randomness, no I/O. The digest (the SDK's SHA-256) is passed
// in by the caller so this file stays pure; the capability seed is
// replicated state (set at construction for host tests, or by the SEED
// command the module proposes from the kernel CSPRNG once per group), so
// every replica mints the same token and any replica can verify one.
//
// One record per `(service_id, address_family, prefix, prefix_len)`. The
// phase sequence moves forward one step at a time:
//
//   UNASSIGNED → PREPARING_NEW → FENCING_OLD → OWNER_COMMITTED →
//   ADDRESS_INSTALLED → ADVERTISED → ACTIVE → DRAINING → WITHDRAWN →
//   EMISSION_DISABLED → RELEASED
//
// What the registry enforces:
//
// - **a claim is an epoch.** CLAIM_PREPARE starts `PREPARING_NEW` under a
//   new `vip_epoch` from an unowned record (UNASSIGNED / RELEASED) or as a
//   takeover of an owned one (any phase from OWNER_COMMITTED on); a claim
//   already in flight must be ABORTed first. Every command names the epoch
//   it expects and a stale one is refused `STALE_EPOCH`.
// - **no owner commits past an unfenced predecessor.** The hosts owning
//   the address when a takeover claim lands are its previous owners; each
//   needs a FENCE_CONFIRM carrying the fence agent's custody generation
//   before ACTIVATE commits the new owner, or the claim stays
//   `BLOCKED_FENCE`. A predecessor that gracefully disabled emission
//   (EMISSION_DISABLED) is its own acknowledgement and needs no fence.
//   ACTIVATE also carries the ready-graph attestation; without it the
//   claim is `NOT_READY`.
// - **abort before commit only.** ABORT returns a claim in PREPARING_NEW or
//   FENCING_OLD to the phase the record held when the claim was made —
//   UNASSIGNED for a first claim. Past OWNER_COMMITTED a claim completes
//   forward: the address may already be installed under the new owner.
// - **emission tokens are minted here and nowhere else.** ACTIVATE mints
//   an `EmissionToken` bound to `(service_id, prefix, owner_host,
//   boot_incarnation, vip_epoch, authority_generation,
//   unsafe_recovery_generation, allowed_interfaces)` plus a 16-byte
//   capability: the first 16 bytes of SHA-256 over the replicated seed
//   followed by those fields. Seed and fields are fixed-length, so no
//   extension of a valid input is itself a valid input and the keyed
//   digest is a sound MAC without HMAC's second pass. Tokens are a pure
//   function of replicated state: any replica re-derives an owner's
//   current token (`emission_token`), and a token stops verifying the
//   moment authority moves past it. TOKEN_REISSUE is how an owner reads
//   its current token back over the wire (below). `verify_emission_token`
//   is what a Fluxor `ip` / announcer side asks: it fails closed on a recovery
//   generation or vip epoch behind the registry's, an authority generation
//   that is not the current one, a host that is not a current owner under
//   that boot incarnation, owners that may not emit — before their commit,
//   or once DISABLE ended their emission, including through a takeover
//   claim made after it — or a capability that does not recompute.
// - **active/active is an owner set.** Mode is fixed at the first claim.
//   In active/active a claim adds the prepared host to the set (bounded by
//   the registry's owner width `O` — `VB_MAX_OWNERS` unless the profile
//   names a wider one — `CAPACITY` beyond) without fencing the owners that
//   stay; RELEASE naming a fenced owner removes just that host while the
//   set is ACTIVE. A claim over an EMISSION_DISABLED set replaces it: the
//   disabled owners acknowledged their cutoff and are not re-admitted by
//   another host's commit.
// - **an owner re-reads its token.** Every ACTIVATE advances the binding's
//   authority generation, and in an active/active set the owners already
//   in it are not the proposer of the join that advanced it, so the reply
//   carrying the new token never reaches them. TOKEN_REISSUE `[common]
//   [host:16][boot:16]` is that owner asking, in log order, for the token
//   `emission_token` derives for it now. It is a read: it changes no
//   binding, records no operation (a retry of the record's last mutating
//   command still repeats its reply), and is answered with a token only
//   when the epoch is the binding's, the host is a committed owner under
//   that boot incarnation, the owners may emit, no confirmed fence names
//   the host, and the binding's authority is not void — neither voided by
//   RECOVERY_MARK nor older than the registry's recovery generation. The
//   token names the binding's current generations, so it stops verifying
//   at the next authority move like any other.
// - **unsafe recovery invalidates authority.** RECOVERY_MARK bumps
//   `unsafe_recovery_generation`, returns a claim in FENCING_OLD to
//   PREPARING_NEW with its fences voided, and marks every committed
//   binding voided: its tokens no longer verify and its phase cannot
//   advance until a new claim re-admits the owner through a fresh fence:
//   re-admission after a recovery is explicit, never implied. A claim in
//   flight over an owned record is re-fenced the same way: every current
//   owner becomes a previous owner to fence (an active/active add becomes
//   a replacement), and an ABORT returns the record voided.
// - **idempotent operations.** Every command carries `operation_id[16]`;
//   the record (or the registry, for SEED and RECOVERY_MARK) remembers its
//   last one, whole: a byte-identical retry gets the recorded reply, a
//   different command under the same id `CONFLICT`.

use super::slot_index::{SlotIndex, SlotSet};

// ── Capacity ────────────────────────────────────────────────────────

/// Owners (active/active set), prepared hosts and fences one binding names
/// by default: the owner width of `VipRegistry<N>` and of the RP2350
/// profile. A registry is `VipRegistry<N, O>`; the width is a compile-time
/// size like the arena, and the image records it.
pub const VB_MAX_OWNERS: usize = 8;

/// Owner width per profile: hosts one active/active set admits. Every
/// binding reserves `O` rows of host tables (`VB_SNAP_ROW_LEN` bytes
/// each), so the width multiplies the arena: a wider set is bought with
/// fewer bindings or more memory, never by changing the record format.
pub const VB_OWNERS_RP2350: usize = 8;
pub const VB_OWNERS_PI5: usize = 16;
pub const VB_OWNERS_SERVER: usize = 32;
/// The widest set any registry may declare: owner counts are carried as
/// one byte, and the global tier's region sets (`region_registry.rs`) are
/// the widest consumer.
pub const VB_OWNERS_MAX: usize = 64;

/// Profiles: bindings per group (one group's share of a profile's
/// concurrent VIP/prefix intents; VIP records are low-volume and reserved
/// independently of sessions). A record lives as long as the group: a
/// released binding keeps its `vip_epoch` so a stale coordinator's
/// command for an old epoch is still refused, so the arena bounds the
/// distinct keys a group ever claims.
pub const VB_PROFILE_RP2350: usize = 16;
pub const VB_PROFILE_PI5: usize = 1024;
pub const VB_PROFILE_SERVER: usize = 16384;

// ── Phases ──────────────────────────────────────────────────────────

pub const VB_PHASE_UNASSIGNED: u8 = 0;
pub const VB_PHASE_PREPARING_NEW: u8 = 1;
pub const VB_PHASE_FENCING_OLD: u8 = 2;
pub const VB_PHASE_OWNER_COMMITTED: u8 = 3;
pub const VB_PHASE_ADDRESS_INSTALLED: u8 = 4;
pub const VB_PHASE_ADVERTISED: u8 = 5;
pub const VB_PHASE_ACTIVE: u8 = 6;
pub const VB_PHASE_DRAINING: u8 = 7;
pub const VB_PHASE_WITHDRAWN: u8 = 8;
pub const VB_PHASE_EMISSION_DISABLED: u8 = 9;
pub const VB_PHASE_RELEASED: u8 = 10;

// ── Modes ───────────────────────────────────────────────────────────

pub const VB_MODE_ACTIVE_PASSIVE: u8 = 0;
pub const VB_MODE_ACTIVE_ACTIVE: u8 = 1;

// ── Command opcodes ─────────────────────────────────────────────────

pub const VB_OP_CLAIM_PREPARE: u8 = 1;
pub const VB_OP_ABORT: u8 = 2;
pub const VB_OP_FENCE_REQUEST: u8 = 3;
pub const VB_OP_FENCE_CONFIRM: u8 = 4;
pub const VB_OP_ACTIVATE: u8 = 5;
pub const VB_OP_INSTALLED: u8 = 6;
pub const VB_OP_ADVERTISED: u8 = 7;
pub const VB_OP_ACTIVE: u8 = 8;
pub const VB_OP_WITHDRAW: u8 = 9;
pub const VB_OP_DISABLE: u8 = 10;
pub const VB_OP_RELEASE: u8 = 11;
pub const VB_OP_RECOVERY_MARK: u8 = 12;
pub const VB_OP_SEED: u8 = 13;
/// Read an owner's current emission token (changes nothing).
pub const VB_OP_TOKEN_REISSUE: u8 = 14;

// ── Status codes ────────────────────────────────────────────────────

pub const VB_ST_OK: u8 = 0;
/// Identical operation already completed (reserved: a retry is answered
/// with the recorded reply, whose status is the original's).
pub const VB_ST_DUPLICATE: u8 = 1;
pub const VB_ST_INVALID: u8 = 2;
pub const VB_ST_UNAUTHORIZED: u8 = 3;
pub const VB_ST_STALE_EPOCH: u8 = 4;
pub const VB_ST_FUTURE_EPOCH: u8 = 5;
pub const VB_ST_CONFLICT: u8 = 6;
pub const VB_ST_CAPACITY: u8 = 7;
/// Ready-graph attestation absent, or the registry is not yet seeded.
pub const VB_ST_NOT_READY: u8 = 8;
/// A previous owner has no confirmed fence.
pub const VB_ST_BLOCKED_FENCE: u8 = 9;
/// Not an edge of the phase sequence from the current phase.
pub const VB_ST_UNSUPPORTED_STATE: u8 = 10;
pub const VB_ST_INVARIANT_FAILURE: u8 = 11;
pub const VB_ST_UNKNOWN_BINDING: u8 = 12;
/// Voided by unsafe recovery until re-claimed.
pub const VB_ST_RECOVERY_VOID: u8 = 13;
pub const VB_ST_RECOVERY_STALE: u8 = 14;

// ── Field sizes / payload layouts ───────────────────────────────────

pub const VB_OP_ID: usize = 16;
pub const VB_HOST_ID: usize = 16;
pub const VB_BOOT_INCARNATION: usize = 16;
pub const VB_POLICY_ID: usize = 16;
pub const VB_SEED: usize = 32;
pub const VB_CAPABILITY: usize = 16;
/// Binding key: `[service_id:16][family:1][prefix_len:1][prefix:16]`.
pub const VB_KEY: usize = 34;

// Command layouts (after the opcode byte), all LE. Every binding command
// begins `[op_id:16][key:34][expected_epoch:8]`.
//
//   CLAIM_PREPARE [common][mode:1][host:16][boot:16][policy:16]
//                 [allowed_interfaces:4]
//   ABORT         [common]
//   FENCE_REQUEST [common][host:16]     (zero host: nothing to fence)
//   FENCE_CONFIRM [common][host:16][fence_gen:4]
//   ACTIVATE      [common][ready_graph:1]
//   INSTALLED / ADVERTISED / ACTIVE [common]
//   WITHDRAW / DISABLE / RELEASE    [common][host:16]
//                 (host names the owner in active/active; zero for the set)
//   RECOVERY_MARK [op_id:16][recovery_generation:8]
//   TOKEN_REISSUE [common][host:16][boot:16]
//   SEED          [op_id:16][seed:32]

pub const VB_COMMON_LEN: usize = 1 + VB_OP_ID + VB_KEY + 8;
pub const VB_CLAIM_PREPARE_LEN: usize =
    VB_COMMON_LEN + 1 + VB_HOST_ID + VB_BOOT_INCARNATION + VB_POLICY_ID + 4;
pub const VB_ABORT_LEN: usize = VB_COMMON_LEN;
pub const VB_FENCE_REQUEST_LEN: usize = VB_COMMON_LEN + VB_HOST_ID;
pub const VB_FENCE_CONFIRM_LEN: usize = VB_COMMON_LEN + VB_HOST_ID + 4;
pub const VB_ACTIVATE_LEN: usize = VB_COMMON_LEN + 1;
pub const VB_STEP_LEN: usize = VB_COMMON_LEN;
pub const VB_HOST_STEP_LEN: usize = VB_COMMON_LEN + VB_HOST_ID;
pub const VB_RECOVERY_MARK_LEN: usize = 1 + VB_OP_ID + 8;
pub const VB_SEED_LEN: usize = 1 + VB_OP_ID + VB_SEED;
pub const VB_TOKEN_REISSUE_LEN: usize = VB_COMMON_LEN + VB_HOST_ID + VB_BOOT_INCARNATION;
/// Largest command body (CLAIM_PREPARE).
pub const VB_MAX_CMD: usize = VB_CLAIM_PREPARE_LEN;

// ── Emission token ──────────────────────────────────────────────────

/// `[service_id:16][family:1][prefix_len:1][prefix:16][owner_host:16]
/// [boot_incarnation:16][vip_epoch:8][authority_generation:8]
/// [unsafe_recovery_generation:8][allowed_interfaces:4][capability:16]`
pub const VB_TOKEN_LEN: usize =
    VB_KEY + VB_HOST_ID + VB_BOOT_INCARNATION + 8 + 8 + 8 + 4 + VB_CAPABILITY;
const VB_TOKEN_FIELDS: usize = VB_TOKEN_LEN - VB_CAPABILITY;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct EmissionToken {
    pub key: [u8; VB_KEY],
    pub owner_host: [u8; VB_HOST_ID],
    pub boot_incarnation: [u8; VB_BOOT_INCARNATION],
    pub vip_epoch: u64,
    pub authority_generation: u64,
    pub unsafe_recovery_generation: u64,
    pub allowed_interfaces: u32,
    pub capability: [u8; VB_CAPABILITY],
}

impl EmissionToken {
    pub const fn zero() -> Self {
        EmissionToken {
            key: [0; VB_KEY],
            owner_host: [0; VB_HOST_ID],
            boot_incarnation: [0; VB_BOOT_INCARNATION],
            vip_epoch: 0,
            authority_generation: 0,
            unsafe_recovery_generation: 0,
            allowed_interfaces: 0,
            capability: [0; VB_CAPABILITY],
        }
    }

    fn encode_fields(&self, dst: &mut [u8]) {
        dst[0..34].copy_from_slice(&self.key);
        dst[34..50].copy_from_slice(&self.owner_host);
        dst[50..66].copy_from_slice(&self.boot_incarnation);
        dst[66..74].copy_from_slice(&self.vip_epoch.to_le_bytes());
        dst[74..82].copy_from_slice(&self.authority_generation.to_le_bytes());
        dst[82..90].copy_from_slice(&self.unsafe_recovery_generation.to_le_bytes());
        dst[90..94].copy_from_slice(&self.allowed_interfaces.to_le_bytes());
    }

    pub fn encode(&self, dst: &mut [u8]) -> usize {
        if dst.len() < VB_TOKEN_LEN {
            return 0;
        }
        self.encode_fields(dst);
        dst[VB_TOKEN_FIELDS..VB_TOKEN_LEN].copy_from_slice(&self.capability);
        VB_TOKEN_LEN
    }

    pub fn decode(src: &[u8]) -> Option<EmissionToken> {
        if src.len() < VB_TOKEN_LEN {
            return None;
        }
        let mut t = EmissionToken::zero();
        t.key.copy_from_slice(&src[0..34]);
        t.owner_host.copy_from_slice(&src[34..50]);
        t.boot_incarnation.copy_from_slice(&src[50..66]);
        t.vip_epoch = u64_at(src, 66);
        t.authority_generation = u64_at(src, 74);
        t.unsafe_recovery_generation = u64_at(src, 82);
        t.allowed_interfaces = u32_at(src, 90);
        t.capability
            .copy_from_slice(&src[VB_TOKEN_FIELDS..VB_TOKEN_LEN]);
        Some(t)
    }

    /// The capability: the first 16 bytes of `digest(seed || fields)`. The
    /// seed never leaves the registry's replicated state; a holder cannot
    /// forge a token for another epoch, host or incarnation.
    fn capability_for(
        seed: &[u8; VB_SEED],
        fields: &[u8],
        digest: DigestFn,
    ) -> [u8; VB_CAPABILITY] {
        let mut m = [0u8; VB_SEED + VB_TOKEN_FIELDS];
        m[..VB_SEED].copy_from_slice(seed);
        m[VB_SEED..].copy_from_slice(&fields[..VB_TOKEN_FIELDS]);
        let d = digest(&m);
        let mut c = [0u8; VB_CAPABILITY];
        c.copy_from_slice(&d[..VB_CAPABILITY]);
        c
    }
}

/// SHA-256 (the SDK's `crypto/sha256.rs::sha256`), passed in by the host.
pub type DigestFn = fn(&[u8]) -> [u8; 32];

/// Equality in time independent of where the inputs differ, so comparing
/// a presented capability against the true one reveals nothing about how
/// much of it was right.
fn ct_eq(a: &[u8; VB_CAPABILITY], b: &[u8; VB_CAPABILITY]) -> bool {
    let mut diff = 0u8;
    let mut i = 0;
    while i < VB_CAPABILITY {
        diff |= a[i] ^ b[i];
        i += 1;
    }
    core::hint::black_box(diff) == 0
}

// ── Reply ───────────────────────────────────────────────────────────

/// `[op:1][status:1][phase:1][mode:1][owner_count:1][token_present:1]
/// [key:34][vip_epoch:8][authority_generation:8]
/// [unsafe_recovery_generation:8][token: VB_TOKEN_LEN]`
/// The token is zero unless `token_present` (ACTIVATE, TOKEN_REISSUE). A
/// RECOVERY_MARK
/// reply names no binding: its `vip_epoch` is the count of bindings it
/// voided.
pub const VB_REPLY_LEN: usize = 6 + VB_KEY + 8 + 8 + 8 + VB_TOKEN_LEN;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct VipReply {
    pub op: u8,
    pub status: u8,
    pub phase: u8,
    pub mode: u8,
    pub owner_count: u8,
    pub token_present: bool,
    pub key: [u8; VB_KEY],
    pub vip_epoch: u64,
    pub authority_generation: u64,
    pub unsafe_recovery_generation: u64,
    pub token: EmissionToken,
}

impl VipReply {
    pub const fn zero() -> Self {
        VipReply {
            op: 0,
            status: 0,
            phase: 0,
            mode: 0,
            owner_count: 0,
            token_present: false,
            key: [0; VB_KEY],
            vip_epoch: 0,
            authority_generation: 0,
            unsafe_recovery_generation: 0,
            token: EmissionToken::zero(),
        }
    }

    pub fn encode(&self, dst: &mut [u8]) -> i32 {
        if dst.len() < VB_REPLY_LEN {
            return -1;
        }
        dst[0] = self.op;
        dst[1] = self.status;
        dst[2] = self.phase;
        dst[3] = self.mode;
        dst[4] = self.owner_count;
        dst[5] = self.token_present as u8;
        dst[6..40].copy_from_slice(&self.key);
        dst[40..48].copy_from_slice(&self.vip_epoch.to_le_bytes());
        dst[48..56].copy_from_slice(&self.authority_generation.to_le_bytes());
        dst[56..64].copy_from_slice(&self.unsafe_recovery_generation.to_le_bytes());
        let _ = self.token.encode(&mut dst[64..64 + VB_TOKEN_LEN]);
        VB_REPLY_LEN as i32
    }

    pub fn decode(src: &[u8]) -> Option<VipReply> {
        if src.len() < VB_REPLY_LEN || src[5] > 1 {
            return None;
        }
        let mut r = VipReply::zero();
        r.op = src[0];
        r.status = src[1];
        r.phase = src[2];
        r.mode = src[3];
        r.owner_count = src[4];
        r.token_present = src[5] != 0;
        r.key.copy_from_slice(&src[6..40]);
        r.vip_epoch = u64_at(src, 40);
        r.authority_generation = u64_at(src, 48);
        r.unsafe_recovery_generation = u64_at(src, 56);
        r.token = EmissionToken::decode(&src[64..64 + VB_TOKEN_LEN])?;
        Some(r)
    }
}

fn u32_at(src: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([src[o], src[o + 1], src[o + 2], src[o + 3]])
}

fn u64_at(src: &[u8], o: usize) -> u64 {
    u64::from_le_bytes([
        src[o],
        src[o + 1],
        src[o + 2],
        src[o + 3],
        src[o + 4],
        src[o + 5],
        src[o + 6],
        src[o + 7],
    ])
}

// ── Command builders (proposer side) ────────────────────────────────

/// Address families a binding key names. A key's prefix is in the
/// canonical 16-byte form its producer (the VIP controller's `VipTarget`) keys by:
/// IPv4 in bytes 12..16 with the first twelve zero, IPv6 in all sixteen.
pub const VB_FAMILY_V4: u8 = 4;
pub const VB_FAMILY_V6: u8 = 6;

/// Whether `addr` — a Fluxor address slot, IPv4 in bytes 0..4 with the
/// rest zero, IPv6 in all sixteen — lies inside the prefix a binding key
/// names. An unknown family, a length past the family's width, a
/// non-canonical IPv4 key, or an IPv4 slot with bytes past its fourth set
/// is outside every prefix.
pub fn key_covers(key: &[u8; VB_KEY], addr: &[u8; 16]) -> bool {
    let len = key[17] as usize;
    let canonical = &key[18..34];
    let (prefix, bits, width): (&[u8], &[u8], usize) = match key[16] {
        VB_FAMILY_V4
            if canonical[..12].iter().all(|&b| b == 0) && addr[4..].iter().all(|&b| b == 0) =>
        {
            (&canonical[12..], &addr[..4], 32)
        }
        VB_FAMILY_V6 => (canonical, &addr[..], 128),
        _ => return false,
    };
    if len > width {
        return false;
    }
    let whole = len / 8;
    if bits[..whole] != prefix[..whole] {
        return false;
    }
    let rest = len % 8;
    if rest == 0 {
        return true;
    }
    let mask = 0xFFu8 << (8 - rest);
    bits[whole] & mask == prefix[whole] & mask
}

/// The binding key for `(service_id, family, prefix, prefix_len)`.
pub fn vip_key(
    service_id: &[u8; 16],
    family: u8,
    prefix: &[u8; 16],
    prefix_len: u8,
) -> [u8; VB_KEY] {
    let mut k = [0u8; VB_KEY];
    k[0..16].copy_from_slice(service_id);
    k[16] = family;
    k[17] = prefix_len;
    k[18..34].copy_from_slice(prefix);
    k
}

fn put_common(
    dst: &mut [u8],
    op: u8,
    op_id: &[u8; VB_OP_ID],
    key: &[u8; VB_KEY],
    expected_epoch: u64,
) -> usize {
    dst[0] = op;
    dst[1..17].copy_from_slice(op_id);
    dst[17..51].copy_from_slice(key);
    dst[51..59].copy_from_slice(&expected_epoch.to_le_bytes());
    VB_COMMON_LEN
}

/// What a claim prepares: the mode, the host (under its boot
/// incarnation) that will own the address, the advertisement policy and
/// the interfaces/queues the token admits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClaimPrepare {
    pub mode: u8,
    pub host: [u8; VB_HOST_ID],
    pub boot: [u8; VB_BOOT_INCARNATION],
    pub policy: [u8; VB_POLICY_ID],
    pub allowed_interfaces: u32,
}

pub fn build_claim_prepare(
    dst: &mut [u8],
    op_id: &[u8; VB_OP_ID],
    key: &[u8; VB_KEY],
    expected_epoch: u64,
    claim: &ClaimPrepare,
) -> usize {
    if dst.len() < VB_CLAIM_PREPARE_LEN || claim.mode > VB_MODE_ACTIVE_ACTIVE {
        return 0;
    }
    let mut o = put_common(dst, VB_OP_CLAIM_PREPARE, op_id, key, expected_epoch);
    dst[o] = claim.mode;
    o += 1;
    dst[o..o + 16].copy_from_slice(&claim.host);
    o += 16;
    dst[o..o + 16].copy_from_slice(&claim.boot);
    o += 16;
    dst[o..o + 16].copy_from_slice(&claim.policy);
    o += 16;
    dst[o..o + 4].copy_from_slice(&claim.allowed_interfaces.to_le_bytes());
    VB_CLAIM_PREPARE_LEN
}

/// ABORT, INSTALLED, ADVERTISED and ACTIVE: a bare step.
pub fn build_step(
    dst: &mut [u8],
    op: u8,
    op_id: &[u8; VB_OP_ID],
    key: &[u8; VB_KEY],
    expected_epoch: u64,
) -> usize {
    if dst.len() < VB_STEP_LEN
        || !matches!(
            op,
            VB_OP_ABORT | VB_OP_INSTALLED | VB_OP_ADVERTISED | VB_OP_ACTIVE
        )
    {
        return 0;
    }
    put_common(dst, op, op_id, key, expected_epoch)
}

/// FENCE_REQUEST, WITHDRAW, DISABLE and RELEASE: a step naming a host.
pub fn build_host_step(
    dst: &mut [u8],
    op: u8,
    op_id: &[u8; VB_OP_ID],
    key: &[u8; VB_KEY],
    expected_epoch: u64,
    host: &[u8; VB_HOST_ID],
) -> usize {
    if dst.len() < VB_HOST_STEP_LEN
        || !matches!(
            op,
            VB_OP_FENCE_REQUEST | VB_OP_WITHDRAW | VB_OP_DISABLE | VB_OP_RELEASE
        )
    {
        return 0;
    }
    let o = put_common(dst, op, op_id, key, expected_epoch);
    dst[o..o + 16].copy_from_slice(host);
    VB_HOST_STEP_LEN
}

/// `fence_gen` is the fence agent's custody generation (`MSG_ADDR_FENCED`);
/// zero is never a generation.
pub fn build_fence_confirm(
    dst: &mut [u8],
    op_id: &[u8; VB_OP_ID],
    key: &[u8; VB_KEY],
    expected_epoch: u64,
    host: &[u8; VB_HOST_ID],
    fence_gen: u32,
) -> usize {
    if dst.len() < VB_FENCE_CONFIRM_LEN || fence_gen == 0 {
        return 0;
    }
    let o = put_common(dst, VB_OP_FENCE_CONFIRM, op_id, key, expected_epoch);
    dst[o..o + 16].copy_from_slice(host);
    dst[o + 16..o + 20].copy_from_slice(&fence_gen.to_le_bytes());
    VB_FENCE_CONFIRM_LEN
}

pub fn build_activate(
    dst: &mut [u8],
    op_id: &[u8; VB_OP_ID],
    key: &[u8; VB_KEY],
    expected_epoch: u64,
    ready_graph: bool,
) -> usize {
    if dst.len() < VB_ACTIVATE_LEN {
        return 0;
    }
    let o = put_common(dst, VB_OP_ACTIVATE, op_id, key, expected_epoch);
    dst[o] = ready_graph as u8;
    VB_ACTIVATE_LEN
}

/// TOKEN_REISSUE: `host` asks for its current token under
/// `expected_epoch`, naming the boot incarnation it was admitted under.
pub fn build_token_reissue(
    dst: &mut [u8],
    op_id: &[u8; VB_OP_ID],
    key: &[u8; VB_KEY],
    expected_epoch: u64,
    host: &[u8; VB_HOST_ID],
    boot: &[u8; VB_BOOT_INCARNATION],
) -> usize {
    if dst.len() < VB_TOKEN_REISSUE_LEN
        || *host == [0; VB_HOST_ID]
        || *boot == [0; VB_BOOT_INCARNATION]
    {
        return 0;
    }
    let o = put_common(dst, VB_OP_TOKEN_REISSUE, op_id, key, expected_epoch);
    dst[o..o + 16].copy_from_slice(host);
    dst[o + 16..o + 32].copy_from_slice(boot);
    VB_TOKEN_REISSUE_LEN
}

pub fn build_recovery_mark(dst: &mut [u8], op_id: &[u8; VB_OP_ID], generation: u64) -> usize {
    if dst.len() < VB_RECOVERY_MARK_LEN {
        return 0;
    }
    dst[0] = VB_OP_RECOVERY_MARK;
    dst[1..17].copy_from_slice(op_id);
    dst[17..25].copy_from_slice(&generation.to_le_bytes());
    VB_RECOVERY_MARK_LEN
}

pub fn build_seed(dst: &mut [u8], op_id: &[u8; VB_OP_ID], seed: &[u8; VB_SEED]) -> usize {
    if dst.len() < VB_SEED_LEN || *seed == [0; VB_SEED] {
        return 0;
    }
    dst[0] = VB_OP_SEED;
    dst[1..17].copy_from_slice(op_id);
    dst[17..49].copy_from_slice(seed);
    VB_SEED_LEN
}

// ── Seed pacing ─────────────────────────────────────────────────────

/// How long a barrier or `SEED` proposal may go without its log position
/// (the proposal assignment) before it counts as lost and the leader
/// starts over from a fresh barrier.
pub const VB_SEED_RETRY_MS: u64 = 1_000;

/// What the leader proposes next for the group's capability seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeedStep {
    /// Nothing: not the leader, already seeded, or a proposal in flight.
    Wait,
    /// Propose a barrier (an empty entry) in this term.
    Barrier,
    /// Propose the `SEED`: this term's barrier has applied, so every
    /// entry any earlier leader appended has applied too, and the
    /// registry is still unseeded.
    Seed,
}

/// Paces the one `SEED` a group commits. The leader proposes it as soon
/// as it leads, barrier first: the barrier is proposed in the leader's
/// own term and, once it has applied, no entry an earlier leader left in
/// the log can still commit after it. A `SEED` proposed after that
/// barrier, unseeded, is therefore the only one in the log, unless the
/// leader loses its term with it in flight. Pure state over
/// (leadership, term, seeded, applied cursor, clock): the module feeds it
/// the proposals it made and the assignments raft answers them with.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SeedPacer {
    /// The term the in-flight proposals belong to (0: none).
    term: u64,
    /// The barrier's correlation (0: none proposed this round).
    barrier_corr: u64,
    /// The barrier's log index (0: not yet assigned).
    barrier_idx: u64,
    barrier_ms: u64,
    /// The `SEED`'s correlation (0: none proposed this round).
    seed_corr: u64,
    /// The `SEED`'s log index (0: not yet assigned).
    seed_idx: u64,
    seed_ms: u64,
}

impl SeedPacer {
    pub const fn new() -> Self {
        SeedPacer {
            term: 0,
            barrier_corr: 0,
            barrier_idx: 0,
            barrier_ms: 0,
            seed_corr: 0,
            seed_idx: 0,
            seed_ms: 0,
        }
    }

    /// The next step at `now_ms` for a node that `leads` term `term`, with
    /// the registry `seeded` or not and its applied cursor at `applied`.
    /// Losing leadership or a new term forgets the round: proposals of
    /// another term are not this leader's to wait on.
    pub fn next(
        &mut self,
        leads: bool,
        term: u64,
        seeded: bool,
        applied: u64,
        now_ms: u64,
    ) -> SeedStep {
        if seeded || !leads {
            *self = SeedPacer::new();
            return SeedStep::Wait;
        }
        if term != self.term {
            *self = SeedPacer::new();
            self.term = term;
        }
        if self.seed_corr != 0 {
            // A placed SEED commits, or the term ends with it; one never
            // placed is lost and the round starts over from a barrier,
            // which orders any late placement of it before the next SEED.
            if self.seed_idx != 0 || now_ms.wrapping_sub(self.seed_ms) <= VB_SEED_RETRY_MS {
                return SeedStep::Wait;
            }
            *self = SeedPacer {
                term,
                ..SeedPacer::new()
            };
            return SeedStep::Barrier;
        }
        if self.barrier_corr == 0 {
            return SeedStep::Barrier;
        }
        if self.barrier_idx == 0 {
            if now_ms.wrapping_sub(self.barrier_ms) > VB_SEED_RETRY_MS {
                return SeedStep::Barrier;
            }
            return SeedStep::Wait;
        }
        if applied >= self.barrier_idx {
            SeedStep::Seed
        } else {
            SeedStep::Wait
        }
    }

    /// The barrier went out under correlation `corr` at `now_ms`.
    pub fn barrier_proposed(&mut self, corr: u64, now_ms: u64) {
        self.barrier_corr = corr;
        self.barrier_idx = 0;
        self.barrier_ms = now_ms;
    }

    /// The `SEED` went out under correlation `corr` at `now_ms`.
    pub fn seed_proposed(&mut self, corr: u64, now_ms: u64) {
        self.seed_corr = corr;
        self.seed_idx = 0;
        self.seed_ms = now_ms;
    }

    /// Raft placed the proposal `corr` at log index `index` of this
    /// group. False when `corr` is none of this round's.
    pub fn assigned(&mut self, corr: u64, index: u64) -> bool {
        if corr == 0 || index == 0 {
            return false;
        }
        if corr == self.barrier_corr {
            self.barrier_idx = index;
            true
        } else if corr == self.seed_corr {
            self.seed_idx = index;
            true
        } else {
            false
        }
    }
}

// ── State ───────────────────────────────────────────────────────────

/// The last operation a record (or the registry) answered: the whole
/// command body, so a retry is recognised by comparing bytes — never by a
/// hash, which a different command could collide with and be answered as
/// if it had applied — and the reply to repeat to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct VipOpMemo {
    pub present: bool,
    pub cmd_len: u8,
    pub cmd: [u8; VB_MAX_CMD],
    pub reply: VipReply,
}

impl VipOpMemo {
    /// `[present:1][cmd_len:1][cmd: VB_MAX_CMD][reply: VB_REPLY_LEN]`.
    pub const LEN: usize = 1 + 1 + VB_MAX_CMD + VB_REPLY_LEN;

    pub const fn empty() -> Self {
        VipOpMemo {
            present: false,
            cmd_len: 0,
            cmd: [0; VB_MAX_CMD],
            reply: VipReply::zero(),
        }
    }

    /// `Some(reply)` for a byte-identical retry; `Err(())` for a
    /// conflicting reuse of the operation id; `Ok(None)` for a new
    /// operation. `body` carries its operation id at `[1..17]`.
    fn check(&self, body: &[u8]) -> Result<Option<VipReply>, ()> {
        if !self.present || self.cmd[1..17] != body[1..17] {
            return Ok(None);
        }
        if self.cmd_len as usize == body.len() && self.cmd[..body.len()] == *body {
            return Ok(Some(self.reply));
        }
        Err(())
    }

    fn record(&mut self, body: &[u8], reply: VipReply) {
        let n = body.len().min(VB_MAX_CMD);
        self.cmd = [0; VB_MAX_CMD];
        self.cmd[..n].copy_from_slice(&body[..n]);
        self.cmd_len = n as u8;
        self.present = true;
        self.reply = reply;
    }

    fn encode(&self, dst: &mut [u8]) {
        dst[0] = self.present as u8;
        dst[1] = self.cmd_len;
        dst[2..2 + VB_MAX_CMD].copy_from_slice(&self.cmd);
        let _ = self
            .reply
            .encode(&mut dst[2 + VB_MAX_CMD..2 + VB_MAX_CMD + VB_REPLY_LEN]);
    }

    fn decode(src: &[u8]) -> Option<VipOpMemo> {
        if src[0] > 1 || src[1] as usize > VB_MAX_CMD {
            return None;
        }
        let mut m = VipOpMemo::empty();
        m.present = src[0] != 0;
        m.cmd_len = src[1];
        m.cmd.copy_from_slice(&src[2..2 + VB_MAX_CMD]);
        m.reply = VipReply::decode(&src[2 + VB_MAX_CMD..2 + VB_MAX_CMD + VB_REPLY_LEN])?;
        Some(m)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct VipSlot<const O: usize = VB_MAX_OWNERS> {
    pub used: bool,
    pub voided: bool,
    pub mode: u8,
    pub phase: u8,
    /// Phase the record held when the in-flight claim was made; ABORT
    /// returns to it.
    pub prior_phase: u8,
    pub owner_count: u8,
    pub prepared_count: u8,
    pub previous_count: u8,
    pub fence_count: u8,
    pub key: [u8; VB_KEY],
    pub vip_epoch: u64,
    /// Bumped by every ACTIVATE; tokens name it.
    pub authority_generation: u64,
    /// The vip epoch the current owners' tokens were minted under (an
    /// aborted later claim does not invalidate them).
    pub token_epoch: u64,
    /// Registry recovery generation at the last ACTIVATE.
    pub unsafe_recovery_generation: u64,
    pub allowed_interfaces: u32,
    pub advertisement_policy_id: [u8; VB_POLICY_ID],
    pub owners: [[u8; VB_HOST_ID]; O],
    pub owner_boot: [[u8; VB_BOOT_INCARNATION]; O],
    pub prepared: [[u8; VB_HOST_ID]; O],
    pub prepared_boot: [[u8; VB_BOOT_INCARNATION]; O],
    /// Owners the in-flight claim replaces: each needs a confirmed fence.
    pub previous_owners: [[u8; VB_HOST_ID]; O],
    pub fenced_hosts: [[u8; VB_HOST_ID]; O],
    pub fence_gens: [u32; O],
    pub last_op: VipOpMemo,
}

impl<const O: usize> VipSlot<O> {
    pub const fn empty() -> Self {
        VipSlot {
            used: false,
            voided: false,
            mode: VB_MODE_ACTIVE_PASSIVE,
            phase: VB_PHASE_UNASSIGNED,
            prior_phase: VB_PHASE_UNASSIGNED,
            owner_count: 0,
            prepared_count: 0,
            previous_count: 0,
            fence_count: 0,
            key: [0; VB_KEY],
            vip_epoch: 0,
            authority_generation: 0,
            token_epoch: 0,
            unsafe_recovery_generation: 0,
            allowed_interfaces: 0,
            advertisement_policy_id: [0; VB_POLICY_ID],
            owners: [[0; VB_HOST_ID]; O],
            owner_boot: [[0; VB_BOOT_INCARNATION]; O],
            prepared: [[0; VB_HOST_ID]; O],
            prepared_boot: [[0; VB_BOOT_INCARNATION]; O],
            previous_owners: [[0; VB_HOST_ID]; O],
            fenced_hosts: [[0; VB_HOST_ID]; O],
            fence_gens: [0; O],
            last_op: VipOpMemo::empty(),
        }
    }

    fn owner_index(&self, host: &[u8; VB_HOST_ID]) -> Option<usize> {
        (0..self.owner_count as usize).find(|&i| self.owners[i] == *host)
    }

    fn is_previous(&self, host: &[u8; VB_HOST_ID]) -> bool {
        (0..self.previous_count as usize).any(|i| self.previous_owners[i] == *host)
    }

    fn fence_index(&self, host: &[u8; VB_HOST_ID]) -> Option<usize> {
        (0..self.fence_count as usize).find(|&i| self.fenced_hosts[i] == *host)
    }

    fn every_previous_fenced(&self) -> bool {
        (0..self.previous_count as usize)
            .all(|i| self.fence_index(&self.previous_owners[i]).is_some())
    }

    /// Whether the current owners may source the address: from the commit
    /// that made them owners until DISABLE ends their emission. A takeover
    /// claim in flight leaves them that authority until its own commit —
    /// unless the claim began after they had disabled emission, which is
    /// why such a claim needs no fence.
    fn owners_emit(&self) -> bool {
        let emitting = |p: u8| (VB_PHASE_OWNER_COMMITTED..=VB_PHASE_WITHDRAWN).contains(&p);
        match self.phase {
            VB_PHASE_PREPARING_NEW | VB_PHASE_FENCING_OLD => emitting(self.prior_phase),
            p => emitting(p),
        }
    }

    fn clear_claim(&mut self) {
        self.prepared = [[0; VB_HOST_ID]; O];
        self.prepared_boot = [[0; VB_BOOT_INCARNATION]; O];
        self.prepared_count = 0;
        self.previous_owners = [[0; VB_HOST_ID]; O];
        self.previous_count = 0;
        self.clear_fences();
    }

    fn clear_fences(&mut self) {
        self.fenced_hosts = [[0; VB_HOST_ID]; O];
        self.fence_gens = [0; O];
        self.fence_count = 0;
    }

    fn remove_owner(&mut self, i: usize) {
        let n = self.owner_count as usize;
        let mut j = i;
        while j + 1 < n {
            self.owners[j] = self.owners[j + 1];
            self.owner_boot[j] = self.owner_boot[j + 1];
            j += 1;
        }
        self.owners[n - 1] = [0; VB_HOST_ID];
        self.owner_boot[n - 1] = [0; VB_BOOT_INCARNATION];
        self.owner_count -= 1;
    }

    /// Snapshot head unit (fixed `VB_SLOT_HEAD_LEN`, whatever the owner
    /// width): the scalar fields in declaration order, then the memo. The
    /// host tables follow as `O` row units (`encode_row`), so a unit's
    /// size never depends on how wide a profile's owner sets are.
    fn encode_head(&self, dst: &mut [u8]) {
        dst[0] = self.used as u8;
        dst[1] = self.voided as u8;
        dst[2] = self.mode;
        dst[3] = self.phase;
        dst[4] = self.prior_phase;
        dst[5] = self.owner_count;
        dst[6] = self.prepared_count;
        dst[7] = self.previous_count;
        dst[8] = self.fence_count;
        dst[9..12].copy_from_slice(&[0; 3]);
        dst[12..46].copy_from_slice(&self.key);
        dst[46..48].copy_from_slice(&[0; 2]);
        dst[48..56].copy_from_slice(&self.vip_epoch.to_le_bytes());
        dst[56..64].copy_from_slice(&self.authority_generation.to_le_bytes());
        dst[64..72].copy_from_slice(&self.token_epoch.to_le_bytes());
        dst[72..80].copy_from_slice(&self.unsafe_recovery_generation.to_le_bytes());
        dst[80..84].copy_from_slice(&self.allowed_interfaces.to_le_bytes());
        dst[84..100].copy_from_slice(&self.advertisement_policy_id);
        self.last_op.encode(&mut dst[100..100 + VipOpMemo::LEN]);
    }

    /// Row `k` of the host tables (fixed `VB_SNAP_ROW_LEN`): `[owner:16]
    /// [owner_boot:16][prepared:16][prepared_boot:16][previous:16]
    /// [fenced:16][fence_gen:4]`.
    fn encode_row(&self, k: usize, dst: &mut [u8]) {
        let cols: [&[u8; 16]; 6] = [
            &self.owners[k],
            &self.owner_boot[k],
            &self.prepared[k],
            &self.prepared_boot[k],
            &self.previous_owners[k],
            &self.fenced_hosts[k],
        ];
        let mut o = 0;
        for c in cols {
            dst[o..o + 16].copy_from_slice(c);
            o += 16;
        }
        dst[o..o + 4].copy_from_slice(&self.fence_gens[k].to_le_bytes());
    }

    fn decode_head(src: &[u8]) -> Option<VipSlot<O>> {
        let mut s = VipSlot::empty();
        if src[0] > 1
            || src[1] > 1
            || src[2] > VB_MODE_ACTIVE_ACTIVE
            || src[3] > VB_PHASE_RELEASED
            || src[4] > VB_PHASE_RELEASED
            || src[5..9].iter().any(|&c| c as usize > O)
            || src[9..12] != [0; 3]
            || src[46..48] != [0; 2]
        {
            return None;
        }
        s.used = src[0] != 0;
        s.voided = src[1] != 0;
        s.mode = src[2];
        s.phase = src[3];
        s.prior_phase = src[4];
        s.owner_count = src[5];
        s.prepared_count = src[6];
        s.previous_count = src[7];
        s.fence_count = src[8];
        s.key.copy_from_slice(&src[12..46]);
        s.vip_epoch = u64_at(src, 48);
        s.authority_generation = u64_at(src, 56);
        s.token_epoch = u64_at(src, 64);
        s.unsafe_recovery_generation = u64_at(src, 72);
        s.allowed_interfaces = u32_at(src, 80);
        s.advertisement_policy_id.copy_from_slice(&src[84..100]);
        s.last_op = VipOpMemo::decode(&src[100..100 + VipOpMemo::LEN])?;
        Some(s)
    }

    fn decode_row(&mut self, k: usize, src: &[u8]) {
        let cols: [&mut [u8; 16]; 6] = [
            &mut self.owners[k],
            &mut self.owner_boot[k],
            &mut self.prepared[k],
            &mut self.prepared_boot[k],
            &mut self.previous_owners[k],
            &mut self.fenced_hosts[k],
        ];
        let mut o = 0;
        for c in cols {
            c.copy_from_slice(&src[o..o + 16]);
            o += 16;
        }
        self.fence_gens[k] = u32_at(src, o);
    }

    /// Whether the host tables are what apply could have left: every row
    /// past a table's count empty (a free row is the empty record, which
    /// whole-table copies rely on), every counted owner, prepared host and
    /// previous owner named, and every counted fence a named host with a
    /// custody generation.
    fn rows_valid(&self) -> bool {
        let tails_zero = |t: &[[u8; 16]; O], n: u8| (n as usize..O).all(|k| t[k] == [0; 16]);
        let named =
            |t: &[[u8; 16]; O], n: u8| (0..n as usize).all(|k| t[k] != [0; 16]) && tails_zero(t, n);
        named(&self.owners, self.owner_count)
            && tails_zero(&self.owner_boot, self.owner_count)
            && named(&self.prepared, self.prepared_count)
            && tails_zero(&self.prepared_boot, self.prepared_count)
            && named(&self.previous_owners, self.previous_count)
            && named(&self.fenced_hosts, self.fence_count)
            && (0..O).all(|k| (self.fence_gens[k] != 0) == (k < self.fence_count as usize))
    }
}

/// The replicated state machine. `N` is the binding arena (a power of two).
#[repr(C)]
pub struct VipRegistry<const N: usize, const O: usize = VB_MAX_OWNERS> {
    pub slots: [VipSlot<O>; N],
    /// binding key → slot. Derived; rebuilt on restore.
    index: SlotIndex<N, VB_KEY>,
    /// Which slots hold a binding; a new key takes the lowest free one.
    /// Derived; rebuilt on restore.
    occupied: SlotSet<N>,
    pub admitted: u32,
    pub live: u32,
    /// Monotone; bumped by RECOVERY_MARK. Every token names the value it
    /// was minted under and fails closed when behind.
    pub unsafe_recovery_generation: u64,
    pub applied: u64,
    /// Capability seed: all-zero until seeded (ACTIVATE is NOT_READY).
    pub seed: [u8; VB_SEED],
    pub last_op: VipOpMemo,
}

impl<const N: usize, const O: usize> Default for VipRegistry<N, O> {
    fn default() -> Self {
        Self::new(&[0; VB_SEED])
    }
}

impl<const N: usize, const O: usize> VipRegistry<N, O> {
    const PROFILE_OK: () = assert!(
        N.is_power_of_two() && O >= 1 && O <= VB_OWNERS_MAX,
        "vip profile: N must be a power of two and O within 1..=VB_OWNERS_MAX"
    );

    /// `seed` is the capability seed — in deployment the kernel CSPRNG's
    /// 32 bytes, replicated by the module through SEED so every replica
    /// mints the same tokens; all-zero means "not yet seeded".
    pub const fn new(seed: &[u8; VB_SEED]) -> Self {
        let () = Self::PROFILE_OK;
        VipRegistry {
            slots: [VipSlot::empty(); N],
            index: SlotIndex::new(),
            occupied: SlotSet::new(),
            admitted: N as u32,
            live: 0,
            unsafe_recovery_generation: 0,
            applied: 0,
            seed: *seed,
            last_op: VipOpMemo::empty(),
        }
    }

    /// Initialise in place, admitting `admitted` bindings (clamped to
    /// `N`), unseeded: every byte of the state, so it is what makes a raw
    /// state block a registry.
    pub fn reset(&mut self, admitted: u32) {
        let () = Self::PROFILE_OK;
        let mut i = 0;
        while i < N {
            self.slots[i] = VipSlot::empty();
            i += 1;
        }
        self.index.reset();
        self.occupied.reset();
        self.admitted = if admitted as usize > N {
            N as u32
        } else {
            admitted
        };
        self.clear_counters();
    }

    /// Empty an initialised registry, keeping what it admits; the seed is
    /// cleared with the rest (an installed image carries its own). A free
    /// slot is always `VipSlot::empty()`, so only the occupied ones are
    /// cleared.
    pub fn clear(&mut self) {
        let mut at = 0;
        while let Some(i) = self.occupied.next_used(at) {
            self.slots[i] = VipSlot::empty();
            at = i + 1;
        }
        self.index.reset();
        self.occupied.reset();
        self.clear_counters();
    }

    fn clear_counters(&mut self) {
        self.live = 0;
        self.unsafe_recovery_generation = 0;
        self.applied = 0;
        self.seed = [0; VB_SEED];
        self.last_op = VipOpMemo::empty();
    }

    pub const fn capacity(&self) -> usize {
        N
    }

    pub fn seeded(&self) -> bool {
        self.seed != [0; VB_SEED]
    }

    fn find(&self, key: &[u8; VB_KEY]) -> Option<usize> {
        self.index.find(key).map(|i| i as usize)
    }

    /// The slot a new binding takes: the lowest free one, while the
    /// admitted count has room.
    fn find_free(&self) -> Option<usize> {
        if self.live >= self.admitted {
            return None;
        }
        self.occupied.lowest_free()
    }

    pub fn lookup(&self, key: &[u8; VB_KEY]) -> Option<&VipSlot<O>> {
        self.find(key).map(|i| &self.slots[i])
    }

    /// The slot `key`'s binding occupies: placement is replicated state,
    /// so a namespace layered on this one (`region_registry.rs`) keys its
    /// own per-binding state by it.
    pub fn slot_of(&self, key: &[u8; VB_KEY]) -> Option<usize> {
        self.find(key)
    }

    /// The first binding's slot at or after `at`, in slot order.
    pub fn next_binding(&self, at: usize) -> Option<usize> {
        self.occupied.next_used(at)
    }

    fn reply(&self, op: u8, status: u8, slot: &VipSlot<O>) -> VipReply {
        VipReply {
            op,
            status,
            phase: slot.phase,
            mode: slot.mode,
            owner_count: slot.owner_count,
            token_present: false,
            key: slot.key,
            vip_epoch: slot.vip_epoch,
            authority_generation: slot.authority_generation,
            unsafe_recovery_generation: self.unsafe_recovery_generation,
            token: EmissionToken::zero(),
        }
    }

    fn reply_bare(&self, op: u8, status: u8, key: &[u8; VB_KEY]) -> VipReply {
        VipReply {
            op,
            status,
            key: *key,
            unsafe_recovery_generation: self.unsafe_recovery_generation,
            ..VipReply::zero()
        }
    }

    /// Whether `slot`'s owners hold authority under the registry's current
    /// recovery generation: not voided by RECOVERY_MARK, and committed at
    /// it. A claim in flight over an owned record at a recovery is not
    /// voided (it re-fences instead), but its owners' authority predates
    /// the recovery all the same.
    fn authority_current(&self, slot: &VipSlot<O>) -> bool {
        !slot.voided && slot.unsafe_recovery_generation == self.unsafe_recovery_generation
    }

    /// Derive the token the current owner `host` of `key` holds (any
    /// replica computes the same one), or `None` when the host is not a
    /// committed owner that may emit under the current recovery generation.
    pub fn emission_token(
        &self,
        key: &[u8; VB_KEY],
        host: &[u8; VB_HOST_ID],
        digest: DigestFn,
    ) -> Option<EmissionToken> {
        let slot = self.lookup(key)?;
        if !self.authority_current(slot) || !slot.owners_emit() || !self.seeded() {
            return None;
        }
        let i = slot.owner_index(host)?;
        Some(self.mint(slot, i, digest))
    }

    fn mint(&self, slot: &VipSlot<O>, owner: usize, digest: DigestFn) -> EmissionToken {
        let mut t = EmissionToken {
            key: slot.key,
            owner_host: slot.owners[owner],
            boot_incarnation: slot.owner_boot[owner],
            vip_epoch: slot.token_epoch,
            authority_generation: slot.authority_generation,
            unsafe_recovery_generation: slot.unsafe_recovery_generation,
            allowed_interfaces: slot.allowed_interfaces,
            capability: [0; VB_CAPABILITY],
        };
        let mut fields = [0u8; VB_TOKEN_FIELDS];
        t.encode_fields(&mut fields);
        t.capability = EmissionToken::capability_for(&self.seed, &fields, digest);
        t
    }

    /// An address provider's check before it arms under `arm_authority`,
    /// as Fluxor's `ip` asks it on `auth_req` (`MSG_ARM_AUTH_CHECK` 0x7A:
    /// `[addr:16][generation:u32 LE][boot_incarnation:16][auth_len:u16 LE]
    /// [auth]`, the auth a VIP emission token), answered as
    /// `ARM_AUTH_VERDICT` (0x7B) wants it: `[addr][generation]
    /// [sha256(auth):32][verdict]` — 0 for a token that verifies, names the
    /// asking boot, and covers the address being armed; otherwise `0x80 |`
    /// the refusal. The provider does not parse the token, so this is the
    /// only place the address is checked against the authority it carries:
    /// a token for one address arms no other. `None` for a check that is
    /// not one.
    pub fn answer_arm_check(
        &self,
        req: &[u8],
        digest: DigestFn,
        out: &mut [u8; 16 + 4 + 32 + 1],
    ) -> Option<u8> {
        if req.len() < 38 {
            return None;
        }
        let auth_len = usize::from(u16::from_le_bytes([req[36], req[37]]));
        if 38 + auth_len != req.len() {
            return None;
        }
        let auth = &req[38..];
        let mut addr = [0u8; 16];
        addr.copy_from_slice(&req[..16]);
        let verdict = match EmissionToken::decode(auth) {
            Some(t)
                if auth.len() == VB_TOKEN_LEN
                    && t.boot_incarnation[..] == req[20..36]
                    && key_covers(&t.key, &addr) =>
            {
                match self.verify_emission_token(&t, digest) {
                    Ok(()) => 0,
                    Err(code) => 0x80 | code,
                }
            }
            _ => 0x80 | VB_ST_UNAUTHORIZED,
        };
        out[..20].copy_from_slice(&req[..20]);
        out[20..52].copy_from_slice(&digest(auth));
        out[52] = verdict;
        Some(verdict)
    }

    /// What a Fluxor `ip` / NIC provider or `route_announcer` asks before
    /// sourcing an address or originating a prefix: is this token the
    /// current authority? Fails closed (`Err(VB_ST_*)`) on a recovery
    /// generation or vip epoch behind the registry's, a stale authority
    /// generation, a host that is not a committed owner under that boot
    /// incarnation, a voided or non-emitting phase, or a capability that
    /// does not recompute from the replicated seed.
    pub fn verify_emission_token(&self, token: &EmissionToken, digest: DigestFn) -> Result<(), u8> {
        if !self.seeded() {
            return Err(VB_ST_NOT_READY);
        }
        if token.unsafe_recovery_generation < self.unsafe_recovery_generation {
            return Err(VB_ST_STALE_EPOCH);
        }
        if token.unsafe_recovery_generation > self.unsafe_recovery_generation {
            return Err(VB_ST_FUTURE_EPOCH);
        }
        let Some(slot) = self.lookup(&token.key) else {
            return Err(VB_ST_UNKNOWN_BINDING);
        };
        if slot.voided {
            return Err(VB_ST_RECOVERY_VOID);
        }
        if slot.owner_count == 0 || !slot.owners_emit() {
            return Err(VB_ST_UNSUPPORTED_STATE);
        }
        if token.vip_epoch < slot.token_epoch {
            return Err(VB_ST_STALE_EPOCH);
        }
        if token.vip_epoch > slot.token_epoch {
            return Err(VB_ST_FUTURE_EPOCH);
        }
        if token.authority_generation != slot.authority_generation {
            return Err(VB_ST_STALE_EPOCH);
        }
        let Some(i) = slot.owner_index(&token.owner_host) else {
            return Err(VB_ST_UNAUTHORIZED);
        };
        if slot.owner_boot[i] != token.boot_incarnation
            || slot.allowed_interfaces != token.allowed_interfaces
        {
            return Err(VB_ST_UNAUTHORIZED);
        }
        let expect = self.mint(slot, i, digest);
        if !ct_eq(&expect.capability, &token.capability) {
            return Err(VB_ST_UNAUTHORIZED);
        }
        Ok(())
    }

    /// Apply one committed command body. DETERMINISTIC given `digest`.
    pub fn apply(&mut self, body: &[u8], digest: DigestFn) -> VipReply {
        self.applied = self.applied.wrapping_add(1);
        if body.is_empty() {
            return VipReply {
                status: VB_ST_INVALID,
                ..VipReply::zero()
            };
        }
        let op = body[0];
        match op {
            VB_OP_RECOVERY_MARK | VB_OP_SEED => return self.apply_registry_op(body),
            VB_OP_TOKEN_REISSUE => return self.apply_token_reissue(body, digest),
            _ => {}
        }
        let want = match op {
            VB_OP_CLAIM_PREPARE => VB_CLAIM_PREPARE_LEN,
            VB_OP_ABORT | VB_OP_INSTALLED | VB_OP_ADVERTISED | VB_OP_ACTIVE => VB_STEP_LEN,
            VB_OP_FENCE_REQUEST | VB_OP_WITHDRAW | VB_OP_DISABLE | VB_OP_RELEASE => {
                VB_HOST_STEP_LEN
            }
            VB_OP_FENCE_CONFIRM => VB_FENCE_CONFIRM_LEN,
            VB_OP_ACTIVATE => VB_ACTIVATE_LEN,
            _ => {
                return VipReply {
                    op,
                    status: VB_ST_INVALID,
                    ..VipReply::zero()
                }
            }
        };
        if body.len() < want {
            return VipReply {
                op,
                status: VB_ST_INVALID,
                ..VipReply::zero()
            };
        }
        let mut key = [0u8; VB_KEY];
        key.copy_from_slice(&body[17..51]);
        let expected = u64_at(body, 51);
        let found = self.find(&key);
        if let Some(i) = found {
            match self.slots[i].last_op.check(body) {
                Ok(Some(r)) => return r,
                Ok(None) => {}
                Err(()) => return self.reply(op, VB_ST_CONFLICT, &self.slots[i]),
            }
        }
        let reply = if op == VB_OP_CLAIM_PREPARE {
            self.apply_claim(body, found, &key, expected, digest)
        } else {
            let Some(i) = found else {
                return self.reply_bare(op, VB_ST_UNKNOWN_BINDING, &key);
            };
            if self.slots[i].vip_epoch != expected {
                self.reply(op, VB_ST_STALE_EPOCH, &self.slots[i])
            } else {
                match op {
                    VB_OP_ABORT => self.apply_abort(i),
                    VB_OP_FENCE_REQUEST => self.apply_fence_request(body, i),
                    VB_OP_FENCE_CONFIRM => self.apply_fence_confirm(body, i),
                    VB_OP_ACTIVATE => self.apply_activate(body, i, digest),
                    VB_OP_INSTALLED | VB_OP_ADVERTISED | VB_OP_ACTIVE => self.apply_forward(op, i),
                    _ => self.apply_host_step(op, body, i),
                }
            }
        };
        if let Some(i) = self.find(&key) {
            self.slots[i].last_op.record(body, reply);
        }
        reply
    }

    /// TOKEN_REISSUE: answered from the replicated state at this log
    /// position, changing none of it. No operation memo is consulted or
    /// recorded: a read cannot conflict with a command, and recording it
    /// would displace the record's last mutating command, whose retry must
    /// still repeat its reply.
    fn apply_token_reissue(&self, body: &[u8], digest: DigestFn) -> VipReply {
        let op = VB_OP_TOKEN_REISSUE;
        if body.len() < VB_TOKEN_REISSUE_LEN {
            return VipReply {
                op,
                status: VB_ST_INVALID,
                ..VipReply::zero()
            };
        }
        let mut key = [0u8; VB_KEY];
        key.copy_from_slice(&body[17..51]);
        let expected = u64_at(body, 51);
        let mut host = [0u8; VB_HOST_ID];
        host.copy_from_slice(&body[59..75]);
        let mut boot = [0u8; VB_BOOT_INCARNATION];
        boot.copy_from_slice(&body[75..91]);
        if host == [0; VB_HOST_ID] || boot == [0; VB_BOOT_INCARNATION] {
            return self.reply_bare(op, VB_ST_INVALID, &key);
        }
        let Some(i) = self.find(&key) else {
            return self.reply_bare(op, VB_ST_UNKNOWN_BINDING, &key);
        };
        let slot = &self.slots[i];
        let status = if !self.seeded() {
            VB_ST_NOT_READY
        } else if expected < slot.vip_epoch {
            VB_ST_STALE_EPOCH
        } else if expected > slot.vip_epoch {
            VB_ST_FUTURE_EPOCH
        } else if !self.authority_current(slot) {
            VB_ST_RECOVERY_VOID
        } else if slot.owner_count == 0 || !slot.owners_emit() {
            VB_ST_UNSUPPORTED_STATE
        } else {
            match slot.owner_index(&host) {
                Some(k) if slot.owner_boot[k] == boot && slot.fence_index(&host).is_none() => {
                    let mut r = self.reply(op, VB_ST_OK, slot);
                    r.token_present = true;
                    r.token = self.mint(slot, k, digest);
                    return r;
                }
                // Not an owner, an owner under another boot incarnation
                // (its authority died with the boot it was admitted
                // under), or one whose fence is confirmed (cut off).
                _ => VB_ST_UNAUTHORIZED,
            }
        };
        self.reply(op, status, slot)
    }

    fn apply_registry_op(&mut self, body: &[u8]) -> VipReply {
        let op = body[0];
        let want = if op == VB_OP_SEED {
            VB_SEED_LEN
        } else {
            VB_RECOVERY_MARK_LEN
        };
        if body.len() < want {
            return VipReply {
                op,
                status: VB_ST_INVALID,
                ..VipReply::zero()
            };
        }
        match self.last_op.check(body) {
            Ok(Some(r)) => return r,
            Ok(None) => {}
            Err(()) => return self.reply_bare(op, VB_ST_CONFLICT, &[0; VB_KEY]),
        }
        let reply = if op == VB_OP_SEED {
            // One seed per group's life: re-seeding would invalidate every
            // token without a recovery generation to explain it.
            let mut seed = [0u8; VB_SEED];
            seed.copy_from_slice(&body[17..49]);
            if self.seeded() || seed == [0; VB_SEED] {
                self.reply_bare(op, VB_ST_CONFLICT, &[0; VB_KEY])
            } else {
                self.seed = seed;
                self.reply_bare(op, VB_ST_OK, &[0; VB_KEY])
            }
        } else {
            let generation = u64_at(body, 17);
            if generation <= self.unsafe_recovery_generation {
                self.reply_bare(op, VB_ST_RECOVERY_STALE, &[0; VB_KEY])
            } else {
                self.unsafe_recovery_generation = generation;
                let mut voided = 0u64;
                let mut at = 0;
                while let Some(i) = self.occupied.next_used(at) {
                    let s = &mut self.slots[i];
                    if s.phase == VB_PHASE_PREPARING_NEW || s.phase == VB_PHASE_FENCING_OLD {
                        // The fences were evidence under the old
                        // generation; the claim re-fences. Owners it was
                        // to keep (an active/active add) hold authority
                        // from before the recovery: they are fenced like
                        // any predecessor, and the add becomes a
                        // replacement. Owners that disabled emission
                        // acknowledged their own cutoff already.
                        s.phase = VB_PHASE_PREPARING_NEW;
                        s.clear_fences();
                        if s.previous_count == 0
                            && s.owner_count > 0
                            && s.prior_phase != VB_PHASE_EMISSION_DISABLED
                        {
                            s.previous_owners = s.owners;
                            s.previous_count = s.owner_count;
                        }
                    } else if s.phase >= VB_PHASE_OWNER_COMMITTED && s.phase < VB_PHASE_RELEASED {
                        s.voided = true;
                        voided += 1;
                    }
                    at = i + 1;
                }
                let mut r = self.reply_bare(op, VB_ST_OK, &[0; VB_KEY]);
                // A registry-level reply names no binding; its epoch field
                // carries how many bindings the recovery voided.
                r.vip_epoch = voided;
                r
            }
        };
        self.last_op.record(body, reply);
        reply
    }

    fn apply_claim(
        &mut self,
        body: &[u8],
        found: Option<usize>,
        key: &[u8; VB_KEY],
        expected: u64,
        _digest: DigestFn,
    ) -> VipReply {
        let mode = body[59];
        let mut host = [0u8; VB_HOST_ID];
        host.copy_from_slice(&body[60..76]);
        let mut boot = [0u8; VB_BOOT_INCARNATION];
        boot.copy_from_slice(&body[76..92]);
        let mut policy = [0u8; VB_POLICY_ID];
        policy.copy_from_slice(&body[92..108]);
        let allowed = u32_at(body, 108);
        if mode > VB_MODE_ACTIVE_ACTIVE
            || host == [0; VB_HOST_ID]
            || boot == [0; VB_BOOT_INCARNATION]
        {
            return self.reply_bare(VB_OP_CLAIM_PREPARE, VB_ST_INVALID, key);
        }
        let i = match found {
            Some(i) => i,
            None => {
                if expected != 0 {
                    return self.reply_bare(VB_OP_CLAIM_PREPARE, VB_ST_STALE_EPOCH, key);
                }
                let Some(i) = self.find_free() else {
                    return self.reply_bare(VB_OP_CLAIM_PREPARE, VB_ST_CAPACITY, key);
                };
                if !self.index.insert(key, i as u32) {
                    return self.reply_bare(VB_OP_CLAIM_PREPARE, VB_ST_CAPACITY, key);
                }
                self.occupied.mark(i);
                self.slots[i] = VipSlot::empty();
                self.slots[i].used = true;
                self.slots[i].key = *key;
                self.slots[i].mode = mode;
                self.live += 1;
                i
            }
        };
        let recovery = self.unsafe_recovery_generation;
        let slot = &mut self.slots[i];
        if slot.vip_epoch != expected {
            return Self::reply_of(recovery, VB_OP_CLAIM_PREPARE, VB_ST_STALE_EPOCH, slot);
        }
        if slot.mode != mode {
            return Self::reply_of(recovery, VB_OP_CLAIM_PREPARE, VB_ST_INVALID, slot);
        }
        match slot.phase {
            VB_PHASE_PREPARING_NEW | VB_PHASE_FENCING_OLD => {
                // A claim in flight: abort it first.
                return Self::reply_of(
                    recovery,
                    VB_OP_CLAIM_PREPARE,
                    VB_ST_UNSUPPORTED_STATE,
                    slot,
                );
            }
            _ => {}
        }
        let owned = slot.phase >= VB_PHASE_OWNER_COMMITTED && slot.phase < VB_PHASE_RELEASED;
        // A disabled set is not joined: its owners acknowledged their
        // cutoff, and another host's commit must not re-admit them.
        let adding = owned
            && slot.mode == VB_MODE_ACTIVE_ACTIVE
            && !slot.voided
            && slot.phase != VB_PHASE_EMISSION_DISABLED;
        if adding && slot.owner_index(&host).is_some() {
            return Self::reply_of(recovery, VB_OP_CLAIM_PREPARE, VB_ST_INVALID, slot);
        }
        if adding && slot.owner_count as usize + 1 > O {
            return Self::reply_of(recovery, VB_OP_CLAIM_PREPARE, VB_ST_CAPACITY, slot);
        }
        slot.clear_claim();
        // Previous owners: the hosts this claim displaces. Adding to an
        // active/active set displaces nobody; a predecessor that disabled
        // emission gracefully acknowledged its own cutoff.
        if owned && !adding && slot.phase != VB_PHASE_EMISSION_DISABLED {
            slot.previous_owners = slot.owners;
            slot.previous_count = slot.owner_count;
        }
        slot.prior_phase = slot.phase;
        slot.prepared[0] = host;
        slot.prepared_boot[0] = boot;
        slot.prepared_count = 1;
        slot.advertisement_policy_id = policy;
        slot.allowed_interfaces = allowed;
        slot.vip_epoch += 1;
        slot.phase = VB_PHASE_PREPARING_NEW;
        Self::reply_of(recovery, VB_OP_CLAIM_PREPARE, VB_ST_OK, slot)
    }

    fn reply_of(recovery: u64, op: u8, status: u8, slot: &VipSlot<O>) -> VipReply {
        VipReply {
            op,
            status,
            phase: slot.phase,
            mode: slot.mode,
            owner_count: slot.owner_count,
            token_present: false,
            key: slot.key,
            vip_epoch: slot.vip_epoch,
            authority_generation: slot.authority_generation,
            unsafe_recovery_generation: recovery,
            token: EmissionToken::zero(),
        }
    }

    fn apply_abort(&mut self, i: usize) -> VipReply {
        let recovery = self.unsafe_recovery_generation;
        let slot = &mut self.slots[i];
        if slot.phase != VB_PHASE_PREPARING_NEW && slot.phase != VB_PHASE_FENCING_OLD {
            // Past commit a claim completes forward.
            return Self::reply_of(recovery, VB_OP_ABORT, VB_ST_UNSUPPORTED_STATE, slot);
        }
        slot.clear_claim();
        slot.phase = slot.prior_phase;
        // Back to an owned record whose authority predates a recovery that
        // landed while the claim was in flight: void, as the recovery
        // would have left it had the claim not been there.
        if slot.owner_count > 0
            && slot.phase >= VB_PHASE_OWNER_COMMITTED
            && slot.phase < VB_PHASE_RELEASED
            && slot.unsafe_recovery_generation < recovery
        {
            slot.voided = true;
        }
        Self::reply_of(recovery, VB_OP_ABORT, VB_ST_OK, slot)
    }

    fn apply_fence_request(&mut self, body: &[u8], i: usize) -> VipReply {
        let recovery = self.unsafe_recovery_generation;
        let mut host = [0u8; VB_HOST_ID];
        host.copy_from_slice(&body[59..75]);
        let slot = &mut self.slots[i];
        if slot.phase != VB_PHASE_PREPARING_NEW && slot.phase != VB_PHASE_FENCING_OLD {
            return Self::reply_of(recovery, VB_OP_FENCE_REQUEST, VB_ST_UNSUPPORTED_STATE, slot);
        }
        if host != [0; VB_HOST_ID] && !slot.is_previous(&host) {
            return Self::reply_of(recovery, VB_OP_FENCE_REQUEST, VB_ST_INVALID, slot);
        }
        slot.phase = VB_PHASE_FENCING_OLD;
        Self::reply_of(recovery, VB_OP_FENCE_REQUEST, VB_ST_OK, slot)
    }

    fn apply_fence_confirm(&mut self, body: &[u8], i: usize) -> VipReply {
        let recovery = self.unsafe_recovery_generation;
        let mut host = [0u8; VB_HOST_ID];
        host.copy_from_slice(&body[59..75]);
        let fence_gen = u32_at(body, 75);
        let slot = &mut self.slots[i];
        // A fence is evidence about a previous owner of a claim being
        // fenced, or about a current owner of an active/active set being
        // removed; anything else is not a fence this record can use.
        let fencing_claim = slot.phase == VB_PHASE_FENCING_OLD && slot.is_previous(&host);
        let removing = slot.mode == VB_MODE_ACTIVE_ACTIVE
            && slot.phase == VB_PHASE_ACTIVE
            && !slot.voided
            && slot.owner_index(&host).is_some();
        if fence_gen == 0 || !(fencing_claim || removing) {
            return Self::reply_of(recovery, VB_OP_FENCE_CONFIRM, VB_ST_INVALID, slot);
        }
        if let Some(k) = slot.fence_index(&host) {
            slot.fence_gens[k] = fence_gen;
        } else {
            let k = slot.fence_count as usize;
            if k >= O {
                return Self::reply_of(recovery, VB_OP_FENCE_CONFIRM, VB_ST_CAPACITY, slot);
            }
            slot.fenced_hosts[k] = host;
            slot.fence_gens[k] = fence_gen;
            slot.fence_count += 1;
        }
        Self::reply_of(recovery, VB_OP_FENCE_CONFIRM, VB_ST_OK, slot)
    }

    fn apply_activate(&mut self, body: &[u8], i: usize, digest: DigestFn) -> VipReply {
        let recovery = self.unsafe_recovery_generation;
        let ready = body[59] != 0;
        let seeded = self.seeded();
        let slot = &mut self.slots[i];
        if slot.phase != VB_PHASE_FENCING_OLD {
            return Self::reply_of(recovery, VB_OP_ACTIVATE, VB_ST_UNSUPPORTED_STATE, slot);
        }
        if !ready || !seeded {
            return Self::reply_of(recovery, VB_OP_ACTIVATE, VB_ST_NOT_READY, slot);
        }
        if !slot.every_previous_fenced() {
            return Self::reply_of(recovery, VB_OP_ACTIVATE, VB_ST_BLOCKED_FENCE, slot);
        }
        if slot.prepared_count != 1 {
            return Self::reply_of(recovery, VB_OP_ACTIVATE, VB_ST_INVARIANT_FAILURE, slot);
        }
        // The claim was an add to a live set (see `apply_claim`): nobody
        // to fence, a set that was not disabled, authority not void.
        let keep_set = slot.mode == VB_MODE_ACTIVE_ACTIVE
            && slot.previous_count == 0
            && !slot.voided
            && slot.prior_phase != VB_PHASE_EMISSION_DISABLED
            && slot.unsafe_recovery_generation == recovery;
        let owner = if keep_set {
            let k = slot.owner_count as usize;
            if k >= O {
                return Self::reply_of(recovery, VB_OP_ACTIVATE, VB_ST_CAPACITY, slot);
            }
            slot.owners[k] = slot.prepared[0];
            slot.owner_boot[k] = slot.prepared_boot[0];
            slot.owner_count += 1;
            k
        } else {
            slot.owners = [[0; VB_HOST_ID]; O];
            slot.owner_boot = [[0; VB_BOOT_INCARNATION]; O];
            slot.owners[0] = slot.prepared[0];
            slot.owner_boot[0] = slot.prepared_boot[0];
            slot.owner_count = 1;
            0
        };
        slot.clear_claim();
        slot.authority_generation += 1;
        slot.token_epoch = slot.vip_epoch;
        slot.unsafe_recovery_generation = recovery;
        slot.voided = false;
        slot.phase = VB_PHASE_OWNER_COMMITTED;
        let snapshot = *slot;
        let token = self.mint(&snapshot, owner, digest);
        let mut r = Self::reply_of(recovery, VB_OP_ACTIVATE, VB_ST_OK, &snapshot);
        r.token_present = true;
        r.token = token;
        r
    }

    /// INSTALLED, ADVERTISED, ACTIVE: one step forward each.
    fn apply_forward(&mut self, op: u8, i: usize) -> VipReply {
        let recovery = self.unsafe_recovery_generation;
        let slot = &mut self.slots[i];
        let (from, to) = match op {
            VB_OP_INSTALLED => (VB_PHASE_OWNER_COMMITTED, VB_PHASE_ADDRESS_INSTALLED),
            VB_OP_ADVERTISED => (VB_PHASE_ADDRESS_INSTALLED, VB_PHASE_ADVERTISED),
            _ => (VB_PHASE_ADVERTISED, VB_PHASE_ACTIVE),
        };
        if slot.voided {
            return Self::reply_of(recovery, op, VB_ST_RECOVERY_VOID, slot);
        }
        if slot.phase != from {
            return Self::reply_of(recovery, op, VB_ST_UNSUPPORTED_STATE, slot);
        }
        slot.phase = to;
        Self::reply_of(recovery, op, VB_ST_OK, slot)
    }

    /// WITHDRAW (ACTIVE → DRAINING → WITHDRAWN), DISABLE (→
    /// EMISSION_DISABLED), RELEASE (→ RELEASED; or, in an ACTIVE
    /// active/active set, remove the fenced owner it names).
    fn apply_host_step(&mut self, op: u8, body: &[u8], i: usize) -> VipReply {
        let recovery = self.unsafe_recovery_generation;
        let mut host = [0u8; VB_HOST_ID];
        host.copy_from_slice(&body[59..75]);
        let slot = &mut self.slots[i];
        if slot.voided {
            return Self::reply_of(recovery, op, VB_ST_RECOVERY_VOID, slot);
        }
        let removing_one = op == VB_OP_RELEASE
            && slot.mode == VB_MODE_ACTIVE_ACTIVE
            && slot.phase == VB_PHASE_ACTIVE
            && host != [0; VB_HOST_ID];
        if removing_one {
            let Some(k) = slot.owner_index(&host) else {
                return Self::reply_of(recovery, op, VB_ST_INVALID, slot);
            };
            if slot.owner_count < 2 {
                return Self::reply_of(recovery, op, VB_ST_UNSUPPORTED_STATE, slot);
            }
            if slot.fence_index(&host).is_none() {
                return Self::reply_of(recovery, op, VB_ST_BLOCKED_FENCE, slot);
            }
            slot.remove_owner(k);
            slot.clear_fences();
            return Self::reply_of(recovery, op, VB_ST_OK, slot);
        }
        if host != [0; VB_HOST_ID] && slot.owner_index(&host).is_none() {
            return Self::reply_of(recovery, op, VB_ST_INVALID, slot);
        }
        let to = match (op, slot.phase) {
            (VB_OP_WITHDRAW, VB_PHASE_ACTIVE) => VB_PHASE_DRAINING,
            (VB_OP_WITHDRAW, VB_PHASE_DRAINING) => VB_PHASE_WITHDRAWN,
            (VB_OP_DISABLE, VB_PHASE_WITHDRAWN) => VB_PHASE_EMISSION_DISABLED,
            (VB_OP_RELEASE, VB_PHASE_EMISSION_DISABLED) => VB_PHASE_RELEASED,
            _ => return Self::reply_of(recovery, op, VB_ST_UNSUPPORTED_STATE, slot),
        };
        slot.phase = to;
        if to == VB_PHASE_RELEASED {
            slot.owners = [[0; VB_HOST_ID]; O];
            slot.owner_boot = [[0; VB_BOOT_INCARNATION]; O];
            slot.owner_count = 0;
            slot.clear_fences();
        }
        Self::reply_of(recovery, op, VB_ST_OK, slot)
    }

    // ── Snapshot (streamed, versioned) ──────────────────────────────
    //
    //   header [version:u16 = 1][owner width O:u16][arena N:u32]
    //          [admitted:u32][record_count:u32]
    //          [unsafe_recovery_generation:u64][applied:u64][seed:32]
    //          [last_op: VipOpMemo::LEN]
    //   record [slot:u32][head: VB_SLOT_HEAD_LEN] then O × [row:
    //          VB_SNAP_ROW_LEN], × record_count, in slot order
    //
    // The header carries the owner width `O`: an image is installed only by
    // a registry of the same arena and the same width, so a profile whose
    // owner sets are wider never reads a narrower one's records as its own.

    pub const SNAPSHOT_VERSION: u16 = 1;

    pub fn snapshot_len(&self) -> usize {
        VB_SNAP_HDR_LEN + self.live as usize * vb_snap_record_len(O)
    }

    pub fn snapshot(&self, dst: &mut [u8]) -> i32 {
        if dst.len() < self.snapshot_len() {
            return -1;
        }
        let mut cur = VbExportCursor::new();
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

    pub fn export_next(&self, cur: &mut VbExportCursor, dst: &mut [u8]) -> usize {
        if cur.stage == VB_EXPORT_RECORDS {
            match self.occupied.next_used(cur.pos as usize) {
                Some(i) => cur.pos = i as u32,
                None => cur.stage = VB_EXPORT_DONE,
            }
        }
        if dst.len() < VbInstaller::stage_len(cur.stage) {
            return 0;
        }
        match cur.stage {
            VB_EXPORT_HEADER => {
                dst[0..2].copy_from_slice(&Self::SNAPSHOT_VERSION.to_le_bytes());
                dst[2..4].copy_from_slice(&(O as u16).to_le_bytes());
                dst[4..8].copy_from_slice(&(N as u32).to_le_bytes());
                dst[8..12].copy_from_slice(&self.admitted.to_le_bytes());
                dst[12..16].copy_from_slice(&self.live.to_le_bytes());
                dst[16..24].copy_from_slice(&self.unsafe_recovery_generation.to_le_bytes());
                dst[24..32].copy_from_slice(&self.applied.to_le_bytes());
                dst[32..64].copy_from_slice(&self.seed);
                self.last_op.encode(&mut dst[64..64 + VipOpMemo::LEN]);
                cur.stage = VB_EXPORT_RECORDS;
                cur.pos = 0;
                VB_SNAP_HDR_LEN
            }
            VB_EXPORT_RECORDS => {
                dst[0..4].copy_from_slice(&cur.pos.to_le_bytes());
                self.slots[cur.pos as usize].encode_head(&mut dst[4..4 + VB_SLOT_HEAD_LEN]);
                cur.stage = VB_EXPORT_ROWS;
                cur.row = 0;
                4 + VB_SLOT_HEAD_LEN
            }
            VB_EXPORT_ROWS => {
                self.slots[cur.pos as usize].encode_row(cur.row as usize, dst);
                cur.row += 1;
                if cur.row as usize == O {
                    cur.pos += 1;
                    cur.stage = VB_EXPORT_RECORDS;
                }
                VB_SNAP_ROW_LEN
            }
            _ => 0,
        }
    }

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

    pub fn install_begin(&mut self) -> VbInstaller {
        self.clear();
        VbInstaller::new()
    }

    pub fn install_feed(
        &mut self,
        ins: &mut VbInstaller,
        bytes: &[u8],
    ) -> Result<usize, InstallRejected> {
        if ins.failed {
            return Err(InstallRejected);
        }
        let mut taken = 0;
        while ins.stage != VB_EXPORT_DONE && taken < bytes.len() {
            let want = VbInstaller::stage_len(ins.stage);
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
                return Err(InstallRejected);
            }
        }
        Ok(taken)
    }

    fn install_unit(&mut self, ins: &mut VbInstaller) -> bool {
        let unit = ins.carry;
        match ins.stage {
            VB_EXPORT_HEADER => {
                if u16::from_le_bytes([unit[0], unit[1]]) != Self::SNAPSHOT_VERSION
                    || u16::from_le_bytes([unit[2], unit[3]]) as usize != O
                    || u32_at(&unit, 4) != N as u32
                {
                    return false;
                }
                let admitted = u32_at(&unit, 8);
                let count = u32_at(&unit, 12);
                if admitted != self.admitted || count > admitted {
                    return false;
                }
                let Some(last_op) = VipOpMemo::decode(&unit[64..64 + VipOpMemo::LEN]) else {
                    return false;
                };
                ins.expected = count;
                self.unsafe_recovery_generation = u64_at(&unit, 16);
                self.applied = u64_at(&unit, 24);
                self.seed.copy_from_slice(&unit[32..64]);
                self.last_op = last_op;
                ins.stage = if count == 0 {
                    VB_EXPORT_DONE
                } else {
                    VB_EXPORT_RECORDS
                };
                true
            }
            VB_EXPORT_RECORDS => {
                let slot = u32_at(&unit, 0) as usize;
                let Some(rec) = VipSlot::<O>::decode_head(&unit[4..4 + VB_SLOT_HEAD_LEN]) else {
                    return false;
                };
                if slot >= N || !rec.used || self.occupied.is_used(slot) {
                    return false;
                }
                if self.find(&rec.key).is_some() || !self.index.insert(&rec.key, slot as u32) {
                    return false;
                }
                self.occupied.mark(slot);
                self.slots[slot] = rec;
                self.live += 1;
                ins.slot = slot as u32;
                ins.row = 0;
                ins.stage = VB_EXPORT_ROWS;
                true
            }
            VB_EXPORT_ROWS => {
                self.slots[ins.slot as usize].decode_row(ins.row as usize, &unit);
                ins.row += 1;
                if (ins.row as usize) < O {
                    return true;
                }
                if !self.slots[ins.slot as usize].rows_valid() {
                    return false;
                }
                ins.seen += 1;
                ins.stage = if ins.seen == ins.expected {
                    VB_EXPORT_DONE
                } else {
                    VB_EXPORT_RECORDS
                };
                true
            }
            _ => false,
        }
    }

    pub fn install_finish(&mut self, ins: &mut VbInstaller) -> bool {
        let complete = !ins.failed && ins.stage == VB_EXPORT_DONE && ins.carry_len == 0;
        if !complete {
            ins.failed = true;
            self.clear();
        }
        complete
    }
}

/// Snapshot head unit (see `VipSlot::encode_head`): 100 scalar bytes, the
/// memo.
pub const VB_SLOT_HEAD_LEN: usize = 100 + VipOpMemo::LEN;
/// One row of the host tables (see `VipSlot::encode_row`): six 16-byte
/// identities and a fence generation.
pub const VB_SNAP_ROW_LEN: usize = 6 * 16 + 4;

/// Bytes one binding occupies in an image of owner width `owners`.
pub const fn vb_snap_record_len(owners: usize) -> usize {
    4 + VB_SLOT_HEAD_LEN + owners * VB_SNAP_ROW_LEN
}

/// One binding's record at the default width (`VB_MAX_OWNERS`).
pub const VB_SLOT_SNAP_LEN: usize = VB_SLOT_HEAD_LEN + VB_MAX_OWNERS * VB_SNAP_ROW_LEN;
pub const VB_SNAP_RECORD_LEN: usize = vb_snap_record_len(VB_MAX_OWNERS);
pub const VB_SNAP_HDR_LEN: usize = 64 + VipOpMemo::LEN;
/// Largest unit, whatever the owner width: the header or a record head.
pub const VB_SNAP_MAX_UNIT: usize = if VB_SNAP_HDR_LEN > 4 + VB_SLOT_HEAD_LEN {
    VB_SNAP_HDR_LEN
} else {
    4 + VB_SLOT_HEAD_LEN
};

pub const VB_EXPORT_HEADER: u8 = 0;
pub const VB_EXPORT_RECORDS: u8 = 1;
pub const VB_EXPORT_DONE: u8 = 2;
pub const VB_EXPORT_ROWS: u8 = 3;

/// A streamed install rejected the image; the registry is left cleared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstallRejected;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct VbExportCursor {
    pub stage: u8,
    pub pos: u32,
    /// The host-table row next streamed for the binding at `pos`.
    pub row: u32,
}

impl Default for VbExportCursor {
    fn default() -> Self {
        Self::new()
    }
}

impl VbExportCursor {
    pub const fn new() -> Self {
        VbExportCursor {
            stage: VB_EXPORT_HEADER,
            pos: 0,
            row: 0,
        }
    }

    pub fn done(&self) -> bool {
        self.stage == VB_EXPORT_DONE
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct VbInstaller {
    pub stage: u8,
    pub failed: bool,
    pub carry_len: u16,
    pub expected: u32,
    pub seen: u32,
    /// The binding whose host-table rows are arriving, and the next row.
    pub slot: u32,
    pub row: u32,
    pub carry: [u8; VB_SNAP_MAX_UNIT],
}

impl Default for VbInstaller {
    fn default() -> Self {
        Self::new()
    }
}

impl VbInstaller {
    pub const fn new() -> Self {
        VbInstaller {
            stage: VB_EXPORT_HEADER,
            failed: false,
            carry_len: 0,
            expected: 0,
            seen: 0,
            slot: 0,
            row: 0,
            carry: [0; VB_SNAP_MAX_UNIT],
        }
    }

    pub fn done(&self) -> bool {
        self.stage == VB_EXPORT_DONE && !self.failed
    }

    pub fn stage_len(stage: u8) -> usize {
        match stage {
            VB_EXPORT_HEADER => VB_SNAP_HDR_LEN,
            VB_EXPORT_RECORDS => 4 + VB_SLOT_HEAD_LEN,
            VB_EXPORT_ROWS => VB_SNAP_ROW_LEN,
            _ => 0,
        }
    }
}
