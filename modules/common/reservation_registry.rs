// Reservation registry — the `rs/` namespace of the session directory: the
// strict reservations rfc_lb_vip §22 asks of Clustor for what must never be
// issued twice, without putting per-flow churn through consensus. Two
// record kinds, each in its own arena:
//
// - **egress blocks** `egress/<identity>/<protocol>/<block>`: a block of an
//   egress identity's ports, reserved to one gateway boot incarnation —
//   the authority behind Wormhole's `egress_core::BlockAuthority`. Per-flow
//   tuples stay local to the gateway's shard; only blocks are committed.
// - **address ranges** `addr/<record_id>`: a service address or routed
//   prefix reserved to a tenant — the allocation truth behind Wormhole's
//   `address_core` — never overlapping another live or quarantined range.
//
// Pure no_std, zero-alloc, DETERMINISTIC: `ReservationRegistry::apply` is a
// pure function of (state, committed command body, committed logical
// time); every replica applying the same committed sequence holds
// byte-identical state. Time is the session directory's replicated logical
// clock (`timing.rs`), passed in by the module from the state at this log
// position, never a local clock. `clustor-common` mounts it for host tests
// and for the gateway and address manager.
//
// What the registry enforces:
//
// - **a block belongs to one incarnation.** RESERVE grants the lowest
//   block of the pool that is free, released, or held by an incarnation
//   that was retired and whose horizon has passed; a block held by a live
//   incarnation, or a retired one inside its horizon, is never granted
//   (`EXHAUSTED` when none is). The holder's next boot is another
//   incarnation: it cannot have its predecessor's blocks either.
// - **release by the holder, or after its horizon.** RELEASE frees a
//   block, and only its holder may. RETIRE_BOOT declares an incarnation
//   gone: each of its blocks becomes grantable once `horizon_ms` of
//   committed time has passed, the time a late packet of its flows may
//   still arrive (TIME-WAIT, the UDP hold).
// - **moves for continuity.** MOVE hands a block from its holder to
//   another incarnation (a successor importing the selected tuples); the
//   reply names the previous holder's horizon (`until`), before which the
//   new holder issues none of the block's ports but the imported ones
//   (`adopt_block(block, quarantine_until)`).
// - **ranges never overlap.** ADDR_RESERVE holds a range for a tenant only
//   if no other held range, and no quarantined one inside its horizon, of
//   the same family overlaps it. ADDR_RELEASE quarantines the range for
//   `horizon_ms` (the longest flow, DNS, neighbour and abuse-attribution
//   horizon); a range is reusable only after it.
// - **generations.** Every grant, move and re-reservation advances the
//   record's generation, which the reply carries.
// - **idempotent operations.** Every command carries `operation_id[16]`. A
//   record remembers its last command whole, so a byte-identical retry of
//   RELEASE, MOVE or an address command repeats its recorded reply and
//   another command under the same id is `CONFLICT`; a RESERVE is
//   recognised by the block whose grant it was, while that grant is held;
//   RETIRE_BOOT by the registry's own memo.
//
// Committed time may lag wall time by the module's admission staleness
// bound when a horizon is set (the module's freshness barrier proposes a
// time advance first), so a horizon is counted from no earlier than that:
// callers declare horizons with that margin.

use super::slot_index::{SlotIndex, SlotSet};

// ── Capacity ────────────────────────────────────────────────────────

/// Profiles: egress block records and address records per group. A block
/// record lives as long as its pool (released blocks keep their
/// generation), so the block arena bounds the blocks of every pool the
/// group serves.
pub const RS_BLOCKS_RP2350: usize = 64;
pub const RS_ADDRS_RP2350: usize = 32;
pub const RS_BLOCKS_PI5: usize = 4096;
pub const RS_ADDRS_PI5: usize = 1024;
pub const RS_BLOCKS_SERVER: usize = 65536;
pub const RS_ADDRS_SERVER: usize = 4096;

/// Blocks one pool may declare: a RESERVE searches at most this many.
pub const RS_POOL_BLOCKS_MAX: usize = 1024;

// ── Commands ────────────────────────────────────────────────────────

pub const RS_OP_ID: usize = 16;
pub const RS_IDENTITY: usize = 16;
pub const RS_GATEWAY: usize = 16;
pub const RS_RECORD_ID: usize = 16;
pub const RS_TENANT: usize = 16;
/// Block key: `[identity:16][protocol:1][block:4]`.
pub const RS_BLOCK_KEY: usize = RS_IDENTITY + 1 + 4;

/// `[op_id:16][identity:16][protocol:1][gateway:16][boot:8][pool_blocks:4]`.
pub const RS_OP_RESERVE: u8 = 1;
/// `[op_id:16][identity:16][protocol:1][block:4][gateway:16][boot:8]`.
pub const RS_OP_RELEASE: u8 = 2;
/// `[op_id:16][gateway:16][boot:8][horizon_ms:8]`.
pub const RS_OP_RETIRE_BOOT: u8 = 3;
/// `[op_id:16][identity:16][protocol:1][block:4][from_gateway:16]
/// [from_boot:8][to_gateway:16][to_boot:8]`.
pub const RS_OP_MOVE: u8 = 4;
/// `[op_id:16][record_id:16][tenant:16][family:1][len:1][prefix:16]`.
pub const RS_OP_ADDR_RESERVE: u8 = 5;
/// `[op_id:16][record_id:16][horizon_ms:8]`.
pub const RS_OP_ADDR_RELEASE: u8 = 6;

pub const RS_RESERVE_LEN: usize = 1 + RS_OP_ID + RS_IDENTITY + 1 + RS_GATEWAY + 8 + 4;
pub const RS_RELEASE_LEN: usize = 1 + RS_OP_ID + RS_BLOCK_KEY + RS_GATEWAY + 8;
pub const RS_RETIRE_BOOT_LEN: usize = 1 + RS_OP_ID + RS_GATEWAY + 8 + 8;
pub const RS_MOVE_LEN: usize = 1 + RS_OP_ID + RS_BLOCK_KEY + 2 * (RS_GATEWAY + 8);
pub const RS_ADDR_RESERVE_LEN: usize = 1 + RS_OP_ID + RS_RECORD_ID + RS_TENANT + 2 + 16;
pub const RS_ADDR_RELEASE_LEN: usize = 1 + RS_OP_ID + RS_RECORD_ID + 8;
/// Largest command body (MOVE).
pub const RS_MAX_CMD: usize = RS_MOVE_LEN;

/// Whether a command carries a horizon counted from committed time (the
/// module admits these behind its time-freshness barrier).
pub fn carries_horizon(body: &[u8]) -> bool {
    matches!(
        body.first(),
        Some(&RS_OP_RETIRE_BOOT) | Some(&RS_OP_ADDR_RELEASE)
    )
}

pub const RS_ST_OK: u8 = 0;
pub const RS_ST_INVALID: u8 = 1;
pub const RS_ST_CONFLICT: u8 = 2;
/// No block of the pool is grantable now.
pub const RS_ST_EXHAUSTED: u8 = 3;
/// The command names a holder the block does not have.
pub const RS_ST_NOT_HOLDER: u8 = 4;
/// The range overlaps a held range, or a quarantined one inside its
/// horizon (`until` names when that one ends).
pub const RS_ST_OVERLAP: u8 = 5;
/// A new record past the admitted count.
pub const RS_ST_CAPACITY: u8 = 6;
pub const RS_ST_UNKNOWN: u8 = 7;

/// Record kinds, as the reply names them.
pub const RS_KIND_BLOCK: u8 = 1;
pub const RS_KIND_ADDR: u8 = 2;

/// Block states.
pub const RS_BLOCK_FREE: u8 = 0;
pub const RS_BLOCK_HELD: u8 = 1;
/// Held by an incarnation declared gone: grantable at `free_at`.
pub const RS_BLOCK_RETIRING: u8 = 2;

/// Address states.
pub const RS_ADDR_HELD: u8 = 1;
pub const RS_ADDR_QUARANTINED: u8 = 2;

pub const RS_FAMILY_V4: u8 = 4;
pub const RS_FAMILY_V6: u8 = 6;

fn put_block_key(dst: &mut [u8], identity: &[u8; 16], protocol: u8, block: u32) {
    dst[0..16].copy_from_slice(identity);
    dst[16] = protocol;
    dst[17..21].copy_from_slice(&block.to_le_bytes());
}

pub fn build_reserve(
    dst: &mut [u8],
    op_id: &[u8; RS_OP_ID],
    identity: &[u8; RS_IDENTITY],
    protocol: u8,
    gateway: &[u8; RS_GATEWAY],
    boot: u64,
    pool_blocks: u32,
) -> usize {
    if dst.len() < RS_RESERVE_LEN
        || boot == 0
        || pool_blocks == 0
        || pool_blocks as usize > RS_POOL_BLOCKS_MAX
    {
        return 0;
    }
    dst[0] = RS_OP_RESERVE;
    dst[1..17].copy_from_slice(op_id);
    dst[17..33].copy_from_slice(identity);
    dst[33] = protocol;
    dst[34..50].copy_from_slice(gateway);
    dst[50..58].copy_from_slice(&boot.to_le_bytes());
    dst[58..62].copy_from_slice(&pool_blocks.to_le_bytes());
    RS_RESERVE_LEN
}

pub fn build_release(
    dst: &mut [u8],
    op_id: &[u8; RS_OP_ID],
    identity: &[u8; RS_IDENTITY],
    protocol: u8,
    block: u32,
    gateway: &[u8; RS_GATEWAY],
    boot: u64,
) -> usize {
    if dst.len() < RS_RELEASE_LEN {
        return 0;
    }
    dst[0] = RS_OP_RELEASE;
    dst[1..17].copy_from_slice(op_id);
    put_block_key(&mut dst[17..38], identity, protocol, block);
    dst[38..54].copy_from_slice(gateway);
    dst[54..62].copy_from_slice(&boot.to_le_bytes());
    RS_RELEASE_LEN
}

pub fn build_retire_boot(
    dst: &mut [u8],
    op_id: &[u8; RS_OP_ID],
    gateway: &[u8; RS_GATEWAY],
    boot: u64,
    horizon_ms: u64,
) -> usize {
    if dst.len() < RS_RETIRE_BOOT_LEN || boot == 0 {
        return 0;
    }
    dst[0] = RS_OP_RETIRE_BOOT;
    dst[1..17].copy_from_slice(op_id);
    dst[17..33].copy_from_slice(gateway);
    dst[33..41].copy_from_slice(&boot.to_le_bytes());
    dst[41..49].copy_from_slice(&horizon_ms.to_le_bytes());
    RS_RETIRE_BOOT_LEN
}

pub fn build_move(
    dst: &mut [u8],
    op_id: &[u8; RS_OP_ID],
    identity: &[u8; RS_IDENTITY],
    protocol: u8,
    block: u32,
    from: (&[u8; RS_GATEWAY], u64),
    to: (&[u8; RS_GATEWAY], u64),
) -> usize {
    if dst.len() < RS_MOVE_LEN || to.1 == 0 {
        return 0;
    }
    dst[0] = RS_OP_MOVE;
    dst[1..17].copy_from_slice(op_id);
    put_block_key(&mut dst[17..38], identity, protocol, block);
    dst[38..54].copy_from_slice(from.0);
    dst[54..62].copy_from_slice(&from.1.to_le_bytes());
    dst[62..78].copy_from_slice(to.0);
    dst[78..86].copy_from_slice(&to.1.to_le_bytes());
    RS_MOVE_LEN
}

pub fn build_addr_reserve(
    dst: &mut [u8],
    op_id: &[u8; RS_OP_ID],
    record_id: &[u8; RS_RECORD_ID],
    tenant: &[u8; RS_TENANT],
    family: u8,
    len: u8,
    prefix: &[u8; 16],
) -> usize {
    if dst.len() < RS_ADDR_RESERVE_LEN || !range_valid(family, len, prefix) {
        return 0;
    }
    dst[0] = RS_OP_ADDR_RESERVE;
    dst[1..17].copy_from_slice(op_id);
    dst[17..33].copy_from_slice(record_id);
    dst[33..49].copy_from_slice(tenant);
    dst[49] = family;
    dst[50] = len;
    dst[51..67].copy_from_slice(prefix);
    RS_ADDR_RESERVE_LEN
}

pub fn build_addr_release(
    dst: &mut [u8],
    op_id: &[u8; RS_OP_ID],
    record_id: &[u8; RS_RECORD_ID],
    horizon_ms: u64,
) -> usize {
    if dst.len() < RS_ADDR_RELEASE_LEN {
        return 0;
    }
    dst[0] = RS_OP_ADDR_RELEASE;
    dst[1..17].copy_from_slice(op_id);
    dst[17..33].copy_from_slice(record_id);
    dst[33..41].copy_from_slice(&horizon_ms.to_le_bytes());
    RS_ADDR_RELEASE_LEN
}

/// A canonical range: a known family, a length within it, the prefix's
/// bits past the length zero (an IPv4 prefix in the first 4 bytes, the
/// rest zero).
pub fn range_valid(family: u8, len: u8, prefix: &[u8; 16]) -> bool {
    let width = match family {
        RS_FAMILY_V4 => 32,
        RS_FAMILY_V6 => 128,
        _ => return false,
    };
    if len > width {
        return false;
    }
    let mut bit = len as usize;
    while bit < 128 {
        if prefix[bit / 8] & (0x80 >> (bit % 8)) != 0 {
            return false;
        }
        bit += 1;
    }
    true
}

/// Whether two ranges of one family overlap: one contains the other, so
/// they agree on the shorter one's leading bits.
pub fn ranges_overlap(a: &[u8; 16], a_len: u8, b: &[u8; 16], b_len: u8) -> bool {
    let n = a_len.min(b_len) as usize;
    let mut bit = 0;
    while bit < n {
        let m = 0x80 >> (bit % 8);
        if a[bit / 8] & m != b[bit / 8] & m {
            return false;
        }
        bit += 1;
    }
    true
}

fn u32_at(src: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([src[o], src[o + 1], src[o + 2], src[o + 3]])
}

fn u64_at(src: &[u8], o: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&src[o..o + 8]);
    u64::from_le_bytes(b)
}

fn id16(src: &[u8], o: usize) -> [u8; 16] {
    let mut b = [0u8; 16];
    b.copy_from_slice(&src[o..o + 16]);
    b
}

// ── Reply ───────────────────────────────────────────────────────────

/// Encoded reply: `[op:1][status:1][kind:1][state:1][block:4][count:4]
/// [reserved:4][generation:8][until:8][holder:16][holder_boot:8]
/// [subject:16]`. For a block: its number, holder and boot, and `until`
/// the committed time it is (or was) grantable from — after a MOVE, the
/// previous holder's horizon; `subject` the identity. For an address: the
/// tenant as holder, `until` the quarantine's end, `subject` the record
/// id. `count` is RETIRE_BOOT's blocks retired.
pub const RS_REPLY_LEN: usize = 24 + 8 + 16 + 8 + 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct ReservationReply {
    pub op: u8,
    pub status: u8,
    pub kind: u8,
    pub state: u8,
    pub block: u32,
    pub count: u32,
    pub generation: u64,
    pub until: u64,
    pub holder: [u8; 16],
    pub holder_boot: u64,
    pub subject: [u8; 16],
}

impl ReservationReply {
    pub const fn zero() -> Self {
        ReservationReply {
            op: 0,
            status: 0,
            kind: 0,
            state: 0,
            block: 0,
            count: 0,
            generation: 0,
            until: 0,
            holder: [0; 16],
            holder_boot: 0,
            subject: [0; 16],
        }
    }

    fn fail(op: u8, status: u8) -> Self {
        ReservationReply {
            op,
            status,
            ..Self::zero()
        }
    }

    pub fn encode(&self, dst: &mut [u8]) -> i32 {
        if dst.len() < RS_REPLY_LEN {
            return -1;
        }
        dst[0] = self.op;
        dst[1] = self.status;
        dst[2] = self.kind;
        dst[3] = self.state;
        dst[4..8].copy_from_slice(&self.block.to_le_bytes());
        dst[8..12].copy_from_slice(&self.count.to_le_bytes());
        dst[12..16].copy_from_slice(&[0; 4]);
        dst[16..24].copy_from_slice(&self.generation.to_le_bytes());
        dst[24..32].copy_from_slice(&self.until.to_le_bytes());
        dst[32..48].copy_from_slice(&self.holder);
        dst[48..56].copy_from_slice(&self.holder_boot.to_le_bytes());
        dst[56..72].copy_from_slice(&self.subject);
        RS_REPLY_LEN as i32
    }

    pub fn decode(src: &[u8]) -> Option<ReservationReply> {
        if src.len() < RS_REPLY_LEN || src[12..16] != [0; 4] {
            return None;
        }
        Some(ReservationReply {
            op: src[0],
            status: src[1],
            kind: src[2],
            state: src[3],
            block: u32_at(src, 4),
            count: u32_at(src, 8),
            generation: u64_at(src, 16),
            until: u64_at(src, 24),
            holder: id16(src, 32),
            holder_boot: u64_at(src, 48),
            subject: id16(src, 56),
        })
    }
}

// ── State ───────────────────────────────────────────────────────────

/// A record's (or the registry's) last command, whole, and its reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct RsOpMemo {
    pub present: bool,
    pub cmd_len: u8,
    pub cmd: [u8; RS_MAX_CMD],
    pub reply: ReservationReply,
}

impl RsOpMemo {
    /// `[present:1][cmd_len:1][cmd: RS_MAX_CMD][reply: RS_REPLY_LEN]`.
    pub const LEN: usize = 2 + RS_MAX_CMD + RS_REPLY_LEN;

    pub const fn empty() -> Self {
        RsOpMemo {
            present: false,
            cmd_len: 0,
            cmd: [0; RS_MAX_CMD],
            reply: ReservationReply::zero(),
        }
    }

    fn check(&self, body: &[u8]) -> Result<Option<ReservationReply>, ()> {
        if !self.present || self.cmd[1..17] != body[1..17] {
            return Ok(None);
        }
        if self.cmd_len as usize == body.len() && self.cmd[..body.len()] == *body {
            return Ok(Some(self.reply));
        }
        Err(())
    }

    fn record(&mut self, body: &[u8], reply: ReservationReply) {
        let n = body.len().min(RS_MAX_CMD);
        self.cmd = [0; RS_MAX_CMD];
        self.cmd[..n].copy_from_slice(&body[..n]);
        self.cmd_len = n as u8;
        self.present = true;
        self.reply = reply;
    }

    fn encode(&self, dst: &mut [u8]) {
        dst[0] = self.present as u8;
        dst[1] = self.cmd_len;
        dst[2..2 + RS_MAX_CMD].copy_from_slice(&self.cmd);
        let _ = self.reply.encode(&mut dst[2 + RS_MAX_CMD..Self::LEN]);
    }

    fn decode(src: &[u8]) -> Option<RsOpMemo> {
        if src[0] > 1 || src[1] as usize > RS_MAX_CMD || (src[0] == 0) != (src[1] == 0) {
            return None;
        }
        let mut m = RsOpMemo::empty();
        m.present = src[0] != 0;
        m.cmd_len = src[1];
        m.cmd.copy_from_slice(&src[2..2 + RS_MAX_CMD]);
        m.reply = ReservationReply::decode(&src[2 + RS_MAX_CMD..Self::LEN])?;
        Some(m)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct BlockSlot {
    pub key: [u8; RS_BLOCK_KEY],
    pub state: u8,
    pub holder: [u8; RS_GATEWAY],
    pub holder_boot: u64,
    /// RETIRING: the committed time the block becomes grantable. After a
    /// MOVE out of RETIRING it stays the quarantine the new holder honours.
    pub free_at: u64,
    pub generation: u64,
    /// The RESERVE that granted it to its holder (its retry is that grant).
    pub grant_op: [u8; RS_OP_ID],
    pub last_op: RsOpMemo,
}

impl BlockSlot {
    pub const fn empty() -> Self {
        BlockSlot {
            key: [0; RS_BLOCK_KEY],
            state: RS_BLOCK_FREE,
            holder: [0; RS_GATEWAY],
            holder_boot: 0,
            free_at: 0,
            generation: 0,
            grant_op: [0; RS_OP_ID],
            last_op: RsOpMemo::empty(),
        }
    }

    pub fn block(&self) -> u32 {
        u32_at(&self.key, 17)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct AddrSlot {
    pub record_id: [u8; RS_RECORD_ID],
    pub tenant: [u8; RS_TENANT],
    pub family: u8,
    pub len: u8,
    pub state: u8,
    pub prefix: [u8; 16],
    pub quarantine_until: u64,
    pub generation: u64,
    pub last_op: RsOpMemo,
}

impl AddrSlot {
    pub const fn empty() -> Self {
        AddrSlot {
            record_id: [0; RS_RECORD_ID],
            tenant: [0; RS_TENANT],
            family: 0,
            len: 0,
            state: 0,
            prefix: [0; 16],
            quarantine_until: 0,
            generation: 0,
            last_op: RsOpMemo::empty(),
        }
    }

    /// Whether the range still excludes overlapping reservations at `now`.
    fn live(&self, now: u64) -> bool {
        self.state == RS_ADDR_HELD
            || (self.state == RS_ADDR_QUARANTINED && now < self.quarantine_until)
    }
}

/// The replicated state machine: `B` block records, `A` address records
/// (both powers of two).
#[repr(C)]
pub struct ReservationRegistry<const B: usize, const A: usize> {
    pub blocks: [BlockSlot; B],
    pub addrs: [AddrSlot; A],
    /// Derived; rebuilt on restore.
    bk_index: SlotIndex<B, RS_BLOCK_KEY>,
    bk_used: SlotSet<B>,
    ad_index: SlotIndex<A, RS_RECORD_ID>,
    ad_used: SlotSet<A>,
    pub admitted_blocks: u32,
    pub admitted_addrs: u32,
    pub block_count: u32,
    pub addr_count: u32,
    /// The latest horizon any record was given (derived): while committed
    /// time is short of it a horizon is pending, and the module keeps time
    /// moving.
    pub latest_horizon: u64,
    pub applied: u64,
    /// RETIRE_BOOT's memo.
    pub last_op: RsOpMemo,
}

impl<const B: usize, const A: usize> Default for ReservationRegistry<B, A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const B: usize, const A: usize> ReservationRegistry<B, A> {
    const PROFILE_OK: () = assert!(
        B.is_power_of_two() && A.is_power_of_two(),
        "reservation profile: B and A must be powers of two"
    );

    pub const fn new() -> Self {
        let () = Self::PROFILE_OK;
        ReservationRegistry {
            blocks: [BlockSlot::empty(); B],
            addrs: [AddrSlot::empty(); A],
            bk_index: SlotIndex::new(),
            bk_used: SlotSet::new(),
            ad_index: SlotIndex::new(),
            ad_used: SlotSet::new(),
            admitted_blocks: B as u32,
            admitted_addrs: A as u32,
            block_count: 0,
            addr_count: 0,
            latest_horizon: 0,
            applied: 0,
            last_op: RsOpMemo::empty(),
        }
    }

    /// Initialise in place, admitting `blocks` and `addrs` (each clamped
    /// to its arena): every byte of the state.
    pub fn reset(&mut self, blocks: u32, addrs: u32) {
        let () = Self::PROFILE_OK;
        let mut i = 0;
        while i < B {
            self.blocks[i] = BlockSlot::empty();
            i += 1;
        }
        i = 0;
        while i < A {
            self.addrs[i] = AddrSlot::empty();
            i += 1;
        }
        self.bk_index.reset();
        self.bk_used.reset();
        self.ad_index.reset();
        self.ad_used.reset();
        self.admitted_blocks = blocks.min(B as u32);
        self.admitted_addrs = addrs.min(A as u32);
        self.clear_counters();
    }

    /// Empty an initialised registry, keeping what it admits.
    pub fn clear(&mut self) {
        let mut at = 0;
        while let Some(i) = self.bk_used.next_used(at) {
            self.blocks[i] = BlockSlot::empty();
            at = i + 1;
        }
        at = 0;
        while let Some(i) = self.ad_used.next_used(at) {
            self.addrs[i] = AddrSlot::empty();
            at = i + 1;
        }
        self.bk_index.reset();
        self.bk_used.reset();
        self.ad_index.reset();
        self.ad_used.reset();
        self.clear_counters();
    }

    fn clear_counters(&mut self) {
        self.block_count = 0;
        self.addr_count = 0;
        self.latest_horizon = 0;
        self.applied = 0;
        self.last_op = RsOpMemo::empty();
    }

    /// Whether some horizon has not passed at committed time `now`.
    pub fn horizon_pending(&self, now: u64) -> bool {
        self.latest_horizon > now
    }

    pub fn block(&self, identity: &[u8; 16], protocol: u8, block: u32) -> Option<&BlockSlot> {
        let mut k = [0u8; RS_BLOCK_KEY];
        put_block_key(&mut k, identity, protocol, block);
        self.bk_index.find(&k).map(|i| &self.blocks[i as usize])
    }

    pub fn addr(&self, record_id: &[u8; RS_RECORD_ID]) -> Option<&AddrSlot> {
        self.ad_index
            .find(record_id)
            .map(|i| &self.addrs[i as usize])
    }

    /// Whether `(gateway, boot)` holds `block` of the pool now: what a
    /// gateway's shard checks before issuing a port of it.
    pub fn holds(
        &self,
        identity: &[u8; 16],
        protocol: u8,
        block: u32,
        gateway: &[u8; 16],
        boot: u64,
    ) -> bool {
        self.block(identity, protocol, block).is_some_and(|b| {
            b.state != RS_BLOCK_FREE && b.holder == *gateway && b.holder_boot == boot
        })
    }

    fn block_reply(op: u8, status: u8, b: &BlockSlot) -> ReservationReply {
        ReservationReply {
            op,
            status,
            kind: RS_KIND_BLOCK,
            state: b.state,
            block: b.block(),
            count: 0,
            generation: b.generation,
            until: b.free_at,
            holder: b.holder,
            holder_boot: b.holder_boot,
            subject: id16(&b.key, 0),
        }
    }

    fn addr_reply(op: u8, status: u8, a: &AddrSlot) -> ReservationReply {
        ReservationReply {
            op,
            status,
            kind: RS_KIND_ADDR,
            state: a.state,
            block: 0,
            count: 0,
            generation: a.generation,
            until: a.quarantine_until,
            holder: a.tenant,
            holder_boot: 0,
            subject: a.record_id,
        }
    }

    /// Apply one committed command body at committed logical time `now`.
    /// DETERMINISTIC.
    pub fn apply(&mut self, body: &[u8], now: u64) -> ReservationReply {
        self.applied = self.applied.wrapping_add(1);
        let Some(&op) = body.first() else {
            return ReservationReply::fail(0, RS_ST_INVALID);
        };
        let want = match op {
            RS_OP_RESERVE => RS_RESERVE_LEN,
            RS_OP_RELEASE => RS_RELEASE_LEN,
            RS_OP_RETIRE_BOOT => RS_RETIRE_BOOT_LEN,
            RS_OP_MOVE => RS_MOVE_LEN,
            RS_OP_ADDR_RESERVE => RS_ADDR_RESERVE_LEN,
            RS_OP_ADDR_RELEASE => RS_ADDR_RELEASE_LEN,
            _ => 0,
        };
        if want == 0 || body.len() != want {
            return ReservationReply::fail(op, RS_ST_INVALID);
        }
        match op {
            RS_OP_RESERVE => self.apply_reserve(body, now),
            RS_OP_RELEASE | RS_OP_MOVE => self.apply_block_step(op, body),
            RS_OP_RETIRE_BOOT => self.apply_retire(body, now),
            RS_OP_ADDR_RESERVE => self.apply_addr_reserve(body, now),
            _ => self.apply_addr_release(body, now),
        }
    }

    fn apply_reserve(&mut self, body: &[u8], now: u64) -> ReservationReply {
        let op = RS_OP_RESERVE;
        let mut op_id = [0u8; RS_OP_ID];
        op_id.copy_from_slice(&body[1..17]);
        let identity = id16(body, 17);
        let protocol = body[33];
        let gateway = id16(body, 34);
        let boot = u64_at(body, 50);
        let pool = u32_at(body, 58);
        if boot == 0 || gateway == [0; 16] || pool == 0 || pool as usize > RS_POOL_BLOCKS_MAX {
            return ReservationReply::fail(op, RS_ST_INVALID);
        }
        let mut key = [0u8; RS_BLOCK_KEY];
        // A retry is the grant it made, while that grant is held.
        let mut pick: Option<(u32, Option<usize>)> = None;
        let mut b = 0;
        while b < pool {
            put_block_key(&mut key, &identity, protocol, b);
            match self.bk_index.find(&key).map(|i| i as usize) {
                Some(i) => {
                    let s = &self.blocks[i];
                    if s.state == RS_BLOCK_HELD
                        && s.grant_op == op_id
                        && s.holder == gateway
                        && s.holder_boot == boot
                    {
                        return Self::block_reply(op, RS_ST_OK, s);
                    }
                    let grantable = s.state == RS_BLOCK_FREE
                        || (s.state == RS_BLOCK_RETIRING && now >= s.free_at);
                    if grantable && pick.is_none() {
                        pick = Some((b, Some(i)));
                    }
                }
                None => {
                    if pick.is_none() && self.block_count < self.admitted_blocks {
                        pick = Some((b, None));
                    }
                }
            }
            b += 1;
        }
        let Some((b, at)) = pick else {
            let mut r = ReservationReply::fail(op, RS_ST_EXHAUSTED);
            r.kind = RS_KIND_BLOCK;
            r.subject = identity;
            return r;
        };
        let i = match at {
            Some(i) => i,
            None => {
                put_block_key(&mut key, &identity, protocol, b);
                let Some(i) = self.bk_used.lowest_free() else {
                    return ReservationReply::fail(op, RS_ST_CAPACITY);
                };
                if !self.bk_index.insert(&key, i as u32) {
                    return ReservationReply::fail(op, RS_ST_CAPACITY);
                }
                self.bk_used.mark(i);
                self.blocks[i] = BlockSlot::empty();
                self.blocks[i].key = key;
                self.block_count += 1;
                i
            }
        };
        let s = &mut self.blocks[i];
        s.state = RS_BLOCK_HELD;
        s.holder = gateway;
        s.holder_boot = boot;
        s.free_at = 0;
        s.generation += 1;
        s.grant_op = op_id;
        Self::block_reply(op, RS_ST_OK, s)
    }

    fn apply_block_step(&mut self, op: u8, body: &[u8]) -> ReservationReply {
        let mut key = [0u8; RS_BLOCK_KEY];
        key.copy_from_slice(&body[17..38]);
        let from = id16(body, 38);
        let from_boot = u64_at(body, 54);
        let Some(i) = self.bk_index.find(&key).map(|i| i as usize) else {
            let mut r = ReservationReply::fail(op, RS_ST_UNKNOWN);
            r.kind = RS_KIND_BLOCK;
            r.block = u32_at(&key, 17);
            r.subject = id16(&key, 0);
            return r;
        };
        match self.blocks[i].last_op.check(body) {
            Ok(Some(r)) => return r,
            Ok(None) => {}
            Err(()) => return Self::block_reply(op, RS_ST_CONFLICT, &self.blocks[i]),
        }
        let s = &mut self.blocks[i];
        let reply = if s.state == RS_BLOCK_FREE || s.holder != from || s.holder_boot != from_boot {
            Self::block_reply(op, RS_ST_NOT_HOLDER, s)
        } else if op == RS_OP_RELEASE {
            s.state = RS_BLOCK_FREE;
            s.holder = [0; RS_GATEWAY];
            s.holder_boot = 0;
            s.free_at = 0;
            s.grant_op = [0; RS_OP_ID];
            Self::block_reply(op, RS_ST_OK, s)
        } else {
            let to = id16(body, 62);
            let to_boot = u64_at(body, 78);
            if to == [0; 16] || to_boot == 0 || (to == from && to_boot == from_boot) {
                Self::block_reply(op, RS_ST_INVALID, s)
            } else {
                // The new holder honours the old one's horizon, if it had
                // one: `free_at` stays as the quarantine it adopts under.
                s.state = RS_BLOCK_HELD;
                s.holder = to;
                s.holder_boot = to_boot;
                s.generation += 1;
                s.grant_op = [0; RS_OP_ID];
                Self::block_reply(op, RS_ST_OK, s)
            }
        };
        self.blocks[i].last_op.record(body, reply);
        reply
    }

    fn apply_retire(&mut self, body: &[u8], now: u64) -> ReservationReply {
        let op = RS_OP_RETIRE_BOOT;
        match self.last_op.check(body) {
            Ok(Some(r)) => return r,
            Ok(None) => {}
            Err(()) => return ReservationReply::fail(op, RS_ST_CONFLICT),
        }
        let gateway = id16(body, 17);
        let boot = u64_at(body, 33);
        let horizon = u64_at(body, 41);
        let mut reply = ReservationReply::fail(op, RS_ST_OK);
        reply.kind = RS_KIND_BLOCK;
        reply.holder = gateway;
        reply.holder_boot = boot;
        if boot == 0 || gateway == [0; 16] {
            reply.status = RS_ST_INVALID;
        } else {
            let until = now.saturating_add(horizon);
            reply.until = until;
            let mut at = 0;
            while let Some(i) = self.bk_used.next_used(at) {
                let s = &mut self.blocks[i];
                if s.state == RS_BLOCK_HELD && s.holder == gateway && s.holder_boot == boot {
                    s.state = RS_BLOCK_RETIRING;
                    s.free_at = until;
                    reply.count += 1;
                }
                at = i + 1;
            }
            if reply.count > 0 && until > self.latest_horizon {
                self.latest_horizon = until;
            }
        }
        self.last_op.record(body, reply);
        reply
    }

    fn apply_addr_reserve(&mut self, body: &[u8], now: u64) -> ReservationReply {
        let op = RS_OP_ADDR_RESERVE;
        let record_id = id16(body, 17);
        let tenant = id16(body, 33);
        let family = body[49];
        let len = body[50];
        let prefix = id16(body, 51);
        if record_id == [0; 16] || tenant == [0; 16] || !range_valid(family, len, &prefix) {
            return ReservationReply::fail(op, RS_ST_INVALID);
        }
        let found = self.ad_index.find(&record_id).map(|i| i as usize);
        if let Some(i) = found {
            match self.addrs[i].last_op.check(body) {
                Ok(Some(r)) => return r,
                Ok(None) => {}
                Err(()) => return Self::addr_reply(op, RS_ST_CONFLICT, &self.addrs[i]),
            }
            if self.addrs[i].state == RS_ADDR_HELD {
                let r = Self::addr_reply(op, RS_ST_CONFLICT, &self.addrs[i]);
                self.addrs[i].last_op.record(body, r);
                return r;
            }
        }
        // No other live range of the family may overlap, its own
        // quarantined predecessor included.
        let mut at = 0;
        while let Some(j) = self.ad_used.next_used(at) {
            let a = &self.addrs[j];
            if a.live(now) && a.family == family && ranges_overlap(&a.prefix, a.len, &prefix, len) {
                // Which range is in the way, and until when; never whose.
                let mut r = Self::addr_reply(op, RS_ST_OVERLAP, a);
                r.subject = record_id;
                r.holder = [0; 16];
                r.generation = 0;
                if let Some(i) = found {
                    self.addrs[i].last_op.record(body, r);
                }
                return r;
            }
            at = j + 1;
        }
        let i = match found {
            Some(i) => i,
            None => {
                let Some(i) = self.addr_slot(now) else {
                    return ReservationReply::fail(op, RS_ST_CAPACITY);
                };
                if !self.ad_index.insert(&record_id, i as u32) {
                    return ReservationReply::fail(op, RS_ST_CAPACITY);
                }
                self.ad_used.mark(i);
                self.addrs[i] = AddrSlot::empty();
                self.addrs[i].record_id = record_id;
                self.addr_count += 1;
                i
            }
        };
        let a = &mut self.addrs[i];
        a.tenant = tenant;
        a.family = family;
        a.len = len;
        a.prefix = prefix;
        a.state = RS_ADDR_HELD;
        a.quarantine_until = 0;
        a.generation += 1;
        let r = Self::addr_reply(op, RS_ST_OK, a);
        a.last_op.record(body, r);
        r
    }

    /// The slot a new address record takes: the lowest free one while the
    /// admitted count has room, else the lowest whose quarantine has
    /// passed (its record id is forgotten with it).
    fn addr_slot(&mut self, now: u64) -> Option<usize> {
        if self.addr_count < self.admitted_addrs {
            return self.ad_used.lowest_free();
        }
        let mut at = 0;
        while let Some(i) = self.ad_used.next_used(at) {
            if !self.addrs[i].live(now) {
                let id = self.addrs[i].record_id;
                let _ = self.ad_index.remove(&id);
                self.ad_used.free(i);
                self.addrs[i] = AddrSlot::empty();
                self.addr_count -= 1;
                return Some(i);
            }
            at = i + 1;
        }
        None
    }

    fn apply_addr_release(&mut self, body: &[u8], now: u64) -> ReservationReply {
        let op = RS_OP_ADDR_RELEASE;
        let record_id = id16(body, 17);
        let horizon = u64_at(body, 33);
        let Some(i) = self.ad_index.find(&record_id).map(|i| i as usize) else {
            let mut r = ReservationReply::fail(op, RS_ST_UNKNOWN);
            r.kind = RS_KIND_ADDR;
            r.subject = record_id;
            return r;
        };
        match self.addrs[i].last_op.check(body) {
            Ok(Some(r)) => return r,
            Ok(None) => {}
            Err(()) => return Self::addr_reply(op, RS_ST_CONFLICT, &self.addrs[i]),
        }
        let r = if self.addrs[i].state != RS_ADDR_HELD {
            Self::addr_reply(op, RS_ST_NOT_HOLDER, &self.addrs[i])
        } else {
            let until = now.saturating_add(horizon);
            let a = &mut self.addrs[i];
            a.state = RS_ADDR_QUARANTINED;
            a.quarantine_until = until;
            if until > self.latest_horizon {
                self.latest_horizon = until;
            }
            Self::addr_reply(op, RS_ST_OK, &self.addrs[i])
        };
        self.addrs[i].last_op.record(body, r);
        r
    }

    // ── Snapshot (streamed, versioned) ──────────────────────────────
    //
    //   header [version:u16 = 1][reserved:u16][arena B:u32][arena A:u32]
    //          [admitted_blocks:u32][admitted_addrs:u32][block_count:u32]
    //          [addr_count:u32][applied:u64][last_op: RsOpMemo::LEN]
    //   block  [slot:u32][key:21][state:1][reserved:2][holder:16]
    //          [holder_boot:8][free_at:8][generation:8][grant_op:16]
    //          [last_op: RsOpMemo::LEN] × block_count, slot order
    //   addr   [slot:u32][record_id:16][tenant:16][family:1][len:1]
    //          [state:1][reserved:1][prefix:16][quarantine_until:8]
    //          [generation:8][last_op: RsOpMemo::LEN] × addr_count, slot order
    //
    // `latest_horizon` is derived, rebuilt from the records.

    pub const SNAPSHOT_VERSION: u16 = 1;

    pub fn snapshot_len(&self) -> usize {
        RS_SNAP_HDR_LEN
            + self.block_count as usize * RS_SNAP_BLOCK_LEN
            + self.addr_count as usize * RS_SNAP_ADDR_LEN
    }

    pub fn snapshot(&self, dst: &mut [u8]) -> i32 {
        if dst.len() < self.snapshot_len() {
            return -1;
        }
        let mut cur = RsExportCursor::new();
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

    /// Next unit of the streamed export into `dst` (≥ `RS_SNAP_MAX_UNIT`);
    /// 0 once complete.
    pub fn export_next(&self, cur: &mut RsExportCursor, dst: &mut [u8]) -> usize {
        loop {
            match cur.stage {
                RS_EXPORT_HEADER => {
                    if dst.len() < RS_SNAP_HDR_LEN {
                        return 0;
                    }
                    dst[0..2].copy_from_slice(&Self::SNAPSHOT_VERSION.to_le_bytes());
                    dst[2..4].copy_from_slice(&[0; 2]);
                    dst[4..8].copy_from_slice(&(B as u32).to_le_bytes());
                    dst[8..12].copy_from_slice(&(A as u32).to_le_bytes());
                    dst[12..16].copy_from_slice(&self.admitted_blocks.to_le_bytes());
                    dst[16..20].copy_from_slice(&self.admitted_addrs.to_le_bytes());
                    dst[20..24].copy_from_slice(&self.block_count.to_le_bytes());
                    dst[24..28].copy_from_slice(&self.addr_count.to_le_bytes());
                    dst[28..36].copy_from_slice(&self.applied.to_le_bytes());
                    self.last_op.encode(&mut dst[36..36 + RsOpMemo::LEN]);
                    cur.stage = RS_EXPORT_BLOCKS;
                    cur.pos = 0;
                    return RS_SNAP_HDR_LEN;
                }
                RS_EXPORT_BLOCKS => match self.bk_used.next_used(cur.pos as usize) {
                    Some(i) => {
                        if dst.len() < RS_SNAP_BLOCK_LEN {
                            return 0;
                        }
                        let b = &self.blocks[i];
                        dst[0..4].copy_from_slice(&(i as u32).to_le_bytes());
                        dst[4..25].copy_from_slice(&b.key);
                        dst[25] = b.state;
                        dst[26..28].copy_from_slice(&[0; 2]);
                        dst[28..44].copy_from_slice(&b.holder);
                        dst[44..52].copy_from_slice(&b.holder_boot.to_le_bytes());
                        dst[52..60].copy_from_slice(&b.free_at.to_le_bytes());
                        dst[60..68].copy_from_slice(&b.generation.to_le_bytes());
                        dst[68..84].copy_from_slice(&b.grant_op);
                        b.last_op.encode(&mut dst[84..84 + RsOpMemo::LEN]);
                        cur.pos = i as u32 + 1;
                        return RS_SNAP_BLOCK_LEN;
                    }
                    None => {
                        cur.stage = RS_EXPORT_ADDRS;
                        cur.pos = 0;
                    }
                },
                RS_EXPORT_ADDRS => match self.ad_used.next_used(cur.pos as usize) {
                    Some(i) => {
                        if dst.len() < RS_SNAP_ADDR_LEN {
                            return 0;
                        }
                        let a = &self.addrs[i];
                        dst[0..4].copy_from_slice(&(i as u32).to_le_bytes());
                        dst[4..20].copy_from_slice(&a.record_id);
                        dst[20..36].copy_from_slice(&a.tenant);
                        dst[36] = a.family;
                        dst[37] = a.len;
                        dst[38] = a.state;
                        dst[39] = 0;
                        dst[40..56].copy_from_slice(&a.prefix);
                        dst[56..64].copy_from_slice(&a.quarantine_until.to_le_bytes());
                        dst[64..72].copy_from_slice(&a.generation.to_le_bytes());
                        a.last_op.encode(&mut dst[72..72 + RsOpMemo::LEN]);
                        cur.pos = i as u32 + 1;
                        return RS_SNAP_ADDR_LEN;
                    }
                    None => {
                        cur.stage = RS_EXPORT_DONE;
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

    pub fn install_begin(&mut self) -> RsInstaller {
        self.clear();
        RsInstaller::new()
    }

    pub fn install_feed(
        &mut self,
        ins: &mut RsInstaller,
        bytes: &[u8],
    ) -> Result<usize, RsInstallRejected> {
        if ins.failed {
            return Err(RsInstallRejected);
        }
        let mut taken = 0;
        while ins.stage != RS_EXPORT_DONE && taken < bytes.len() {
            let want = RsInstaller::stage_len(ins.stage);
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
                return Err(RsInstallRejected);
            }
        }
        Ok(taken)
    }

    fn next_stage(ins: &RsInstaller) -> u8 {
        if ins.seen < ins.blocks {
            RS_EXPORT_BLOCKS
        } else if ins.seen < ins.blocks + ins.addrs {
            RS_EXPORT_ADDRS
        } else {
            RS_EXPORT_DONE
        }
    }

    fn install_unit(&mut self, ins: &mut RsInstaller) -> bool {
        let unit = ins.carry;
        match ins.stage {
            RS_EXPORT_HEADER => {
                if u16::from_le_bytes([unit[0], unit[1]]) != Self::SNAPSHOT_VERSION
                    || unit[2..4] != [0; 2]
                    || u32_at(&unit, 4) != B as u32
                    || u32_at(&unit, 8) != A as u32
                    || u32_at(&unit, 12) != self.admitted_blocks
                    || u32_at(&unit, 16) != self.admitted_addrs
                {
                    return false;
                }
                ins.blocks = u32_at(&unit, 20);
                ins.addrs = u32_at(&unit, 24);
                if ins.blocks > self.admitted_blocks || ins.addrs > self.admitted_addrs {
                    return false;
                }
                let Some(last_op) = RsOpMemo::decode(&unit[36..36 + RsOpMemo::LEN]) else {
                    return false;
                };
                self.applied = u64_at(&unit, 28);
                self.last_op = last_op;
                ins.stage = Self::next_stage(ins);
                true
            }
            RS_EXPORT_BLOCKS => {
                let slot = u32_at(&unit, 0) as usize;
                let mut b = BlockSlot::empty();
                b.key.copy_from_slice(&unit[4..25]);
                b.state = unit[25];
                b.holder = id16(&unit, 28);
                b.holder_boot = u64_at(&unit, 44);
                b.free_at = u64_at(&unit, 52);
                b.generation = u64_at(&unit, 60);
                b.grant_op = id16(&unit, 68);
                let Some(last_op) = RsOpMemo::decode(&unit[84..84 + RsOpMemo::LEN]) else {
                    return false;
                };
                b.last_op = last_op;
                let held = b.state != RS_BLOCK_FREE;
                if slot >= B
                    || self.bk_used.is_used(slot)
                    || b.state > RS_BLOCK_RETIRING
                    || unit[26..28] != [0; 2]
                    || b.block() as usize >= RS_POOL_BLOCKS_MAX
                    || held != (b.holder != [0; 16] && b.holder_boot != 0)
                    || (b.state == RS_BLOCK_RETIRING && b.free_at == 0)
                    || self.bk_index.find(&b.key).is_some()
                    || !self.bk_index.insert(&b.key, slot as u32)
                {
                    return false;
                }
                if b.free_at > self.latest_horizon {
                    self.latest_horizon = b.free_at;
                }
                self.bk_used.mark(slot);
                self.blocks[slot] = b;
                self.block_count += 1;
                ins.seen += 1;
                ins.stage = Self::next_stage(ins);
                true
            }
            RS_EXPORT_ADDRS => {
                let slot = u32_at(&unit, 0) as usize;
                let mut a = AddrSlot::empty();
                a.record_id = id16(&unit, 4);
                a.tenant = id16(&unit, 20);
                a.family = unit[36];
                a.len = unit[37];
                a.state = unit[38];
                a.prefix = id16(&unit, 40);
                a.quarantine_until = u64_at(&unit, 56);
                a.generation = u64_at(&unit, 64);
                let Some(last_op) = RsOpMemo::decode(&unit[72..72 + RsOpMemo::LEN]) else {
                    return false;
                };
                a.last_op = last_op;
                if slot >= A
                    || self.ad_used.is_used(slot)
                    || unit[39] != 0
                    || !(a.state == RS_ADDR_HELD || a.state == RS_ADDR_QUARANTINED)
                    || !range_valid(a.family, a.len, &a.prefix)
                    || a.generation == 0
                    || self.ad_index.find(&a.record_id).is_some()
                    || !self.ad_index.insert(&a.record_id, slot as u32)
                {
                    return false;
                }
                if a.quarantine_until > self.latest_horizon {
                    self.latest_horizon = a.quarantine_until;
                }
                self.ad_used.mark(slot);
                self.addrs[slot] = a;
                self.addr_count += 1;
                ins.seen += 1;
                ins.stage = Self::next_stage(ins);
                true
            }
            _ => false,
        }
    }

    pub fn install_finish(&mut self, ins: &mut RsInstaller) -> bool {
        let complete = !ins.failed && ins.stage == RS_EXPORT_DONE && ins.carry_len == 0;
        if !complete {
            ins.failed = true;
            self.clear();
        }
        complete
    }
}

pub const RS_SNAP_HDR_LEN: usize = 36 + RsOpMemo::LEN;
pub const RS_SNAP_BLOCK_LEN: usize = 84 + RsOpMemo::LEN;
pub const RS_SNAP_ADDR_LEN: usize = 72 + RsOpMemo::LEN;
pub const RS_SNAP_MAX_UNIT: usize = RS_SNAP_BLOCK_LEN;

pub const RS_EXPORT_HEADER: u8 = 0;
pub const RS_EXPORT_BLOCKS: u8 = 1;
pub const RS_EXPORT_ADDRS: u8 = 2;
pub const RS_EXPORT_DONE: u8 = 3;

/// A streamed install rejected the image; the registry is left cleared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RsInstallRejected;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct RsExportCursor {
    pub stage: u8,
    pub pos: u32,
}

impl Default for RsExportCursor {
    fn default() -> Self {
        Self::new()
    }
}

impl RsExportCursor {
    pub const fn new() -> Self {
        RsExportCursor {
            stage: RS_EXPORT_HEADER,
            pos: 0,
        }
    }

    pub fn done(&self) -> bool {
        self.stage == RS_EXPORT_DONE
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct RsInstaller {
    pub stage: u8,
    pub failed: bool,
    pub carry_len: u16,
    pub blocks: u32,
    pub addrs: u32,
    pub seen: u32,
    pub carry: [u8; RS_SNAP_MAX_UNIT],
}

impl Default for RsInstaller {
    fn default() -> Self {
        Self::new()
    }
}

impl RsInstaller {
    pub const fn new() -> Self {
        RsInstaller {
            stage: RS_EXPORT_HEADER,
            failed: false,
            carry_len: 0,
            blocks: 0,
            addrs: 0,
            seen: 0,
            carry: [0; RS_SNAP_MAX_UNIT],
        }
    }

    pub fn done(&self) -> bool {
        self.stage == RS_EXPORT_DONE && !self.failed
    }

    /// Bytes one unit of `stage` occupies.
    pub fn stage_len(stage: u8) -> usize {
        match stage {
            RS_EXPORT_HEADER => RS_SNAP_HDR_LEN,
            RS_EXPORT_BLOCKS => RS_SNAP_BLOCK_LEN,
            RS_EXPORT_ADDRS => RS_SNAP_ADDR_LEN,
            _ => 0,
        }
    }
}
