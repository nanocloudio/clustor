# The Multi-Site Group

Wormhole's traffic fabric puts authority in
three tiers — a cell, a region, the world — and asks two things of Clustor
that a group inside one site cannot give: a group whose committed state
outlives the loss of a whole site, and a rule for which state may live in
such a group at all. This document is the design; `modules/common/types.rs`
(`SiteMap`), `consensus`, `durability`, `session_directory`
(`scope`, `modules/common/directory_scope.rs`) are the implementation, and
`tests/site_quorum.rs`, `tests/directory_scope.rs` and
`tests/site_loss_e2e.rs` the proof.

## Table of Contents

1. [Sites and the tiers](#sites-and-the-tiers)
2. [Site-aware quorum](#site-aware-quorum)
3. [Membership and placement](#membership-and-placement)
4. [What a site loss does](#what-a-site-loss-does)
5. [Partitions, time and leases](#partitions-time-and-leases)
6. [Data locality: what the global tier holds](#data-locality-what-the-global-tier-holds)
7. [How the directory and `rg/` use it](#how-the-directory-and-rg-use-it)
8. [Configuration](#configuration)
9. [Proof](#proof)
10. [Not here](#not-here)

## Sites and the tiers

A **site** is a failure domain whose members a single event takes out
together: a building's power, a site's uplinks, a zone. The fabric's tiers
map onto groups like this:

| Tier | Group | Voters | Holds |
|---|---|---|---|
| Cell | one or more directory groups per regional cell | inside the cell's site (or the zones of one region, as sites of a regional group) | sessions, flows and their emitters, VIP owner sets and tokens, failover records, attachment boundaries, reservations, takeover and evacuation records |
| Region | the cell groups of the region's sites; a regional multi-site group when a region spans zones | the region's zones as sites | the region's own cells' state, unchanged |
| Global | one low-rate multi-site group | spread over sites in several regions | `rg/`: each service's region owner set, its DR generation and regional invalidation; REGION and EVACUATION operation records |

Ordinary connection churn stays in the cell; only rare, site-level
ownership changes go to the global group, globally ordered. A
deployment confined to one region omits the global tier rather than
emulate it: its directory serves both namespaces (`scope: all`, the
default).

## Site-aware quorum

Every voter names its site. A set of voters is a **quorum** when it is

1. a majority of the voter set (Raft's rule), and
2. spread over at least `min_sites` distinct sites.

The same rule decides everything quorum decides:

| Decision | Where | Rule |
|---|---|---|
| Commit index | `consensus::commit` (`quorum_index_sited`) | the highest index held by a quorum of match indices |
| Durable index | `durability::ledger` (same function) | the highest index held by a quorum of fsync acks; under the strict and group-fsync durability modes commit takes the minimum of the two, so both must count the same quorum. The ledger holds no map of its own: raft hands it the voter sets and the map (`MSG_QUORUM_CONFIG`) ahead of the entries they govern, and until it has them nothing is durable. The relaxed mode commits on the match quorum alone, and with it an entry is in `min_sites` sites' memory, not yet their disks. |
| Election, pre-vote and vote | `raft::set_majority` (`SiteMap::quorum`) | the granted ballots form a quorum |
| ReadIndex confirmation | `raft::set_majority` | the confirming replies form a quorum |
| Joint consensus | all of the above | a quorum of each configuration, site rule included |

Why this is safe and what it buys:

- **Safety is Raft's.** Half (1) alone makes any two quorums share a voter,
  so two leaders in one term, or two committed entries at one index, stay
  impossible. Half (2) only removes quorums; it can delay a commit, never
  admit one Raft would not.
- **Durability across sites.** An entry is committed only once it is in
  `min_sites` sites, so the loss of any `min_sites − 1` whole sites cannot
  take a committed entry with it (`a_committed_entry_survives_any_one_site_s_loss`).
- **No site decides alone.** With `min_sites ≥ 2` the voters of one site
  never commit, elect or confirm a read by themselves, even if they are a
  majority — a site cut off from the rest cannot run ahead
  (`a_majority_inside_one_site_commits_nothing`).
- **Flat is Raft.** One site (`site_map: 0`) or `min_sites: 1` is the
  plain majority, bit for bit (`a_flat_map_is_a_plain_majority`), so a
  graph that declares no sites gets Raft's group exactly.

## Membership and placement

`SiteMap::check(voters)` judges a placement against the loss of one whole
site:

| Placement | Verdict | At boot |
|---|---|---|
| any one site's loss leaves a quorum (5 voters A{0,1} B{2,3} C{4}, `min_sites: 2`) | survives one site | boots |
| one site's loss leaves no majority, or fewer than `min_sites` sites (A{0,1,2} B{3} C{4}; two sites at `min_sites: 2`) | stops on that loss | boots, logs `[raft] sites: one site's loss stops this group` |
| the voters span fewer than `min_sites` sites | can never commit | refused at construction, at a runtime slot activation, and as a voter change |

The middle row is a posture, not a fault: two sites at `min_sites: 2`
commit every entry in both (a recovery point of zero across the pair) and
stop when either goes, until an operator re-forms the group. The global
tier should be placed as the first row — at least three sites, no site
holding enough voters that its loss leaves less than a majority — so a
site's loss needs no human at all.

Membership changes keep the rule. The joint configuration's two quorums
are each site-aware, and raft refuses a voter change whose new set spans
fewer than `min_sites` sites: the joint configuration would commit under
the old set, after which nothing — not even a corrective change — could
commit under the new one. A change that leaves the new set unable to
survive a site's loss is accepted, as the same placement is at boot; that
posture is the operator's to choose (see [lifecycle.md](lifecycle.md) for
the change itself). Sites are named per replica id in the graph
(`site_map`), so a replica's site is configuration, not something a peer
can claim.

## What a site loss does

Take the global tier as five voters over three sites, A{0,1} B{2,3} C{4},
`min_sites: 2`.

- **A is lost.** Three voters remain, in B and C: a majority over two
  sites. If the leader was in A, B and C elect one (pre-vote, vote, both
  site-aware); otherwise the leader just keeps going. Every committed entry
  is in B or C already, because it was in two sites. The group commits on.
  For the fabric this is the moment the region controllers act: the
  global group commits `rg/` INVALIDATE for the lost region and a new owner
  set under the DR policy (`ACTIVATE`), each raising the binding's DR
  generation; the lost region's tokens stop verifying.
- **C is lost too.** B's two voters are neither a majority of five nor two
  sites. Nothing more commits: no new DR generation, no new owner set, no
  INVALIDATE. The current owners and their route generations continue:
  with the quorum lost there is no new committed epoch, emitter or VIP
  takeover, and nothing that was committed is taken back. Loss of global
  quorum never lets two regions invent conflicting generations, because
  neither half can commit at all.
- **A returns.** Its replicas rejoin as followers, catch up by log or
  snapshot, and count toward quorum again; no reconfiguration is needed.

A cell group inside the lost site is simply gone with it: its sessions
and flows are the lost region's, and their fate is the declared
per-protocol outcome: reconnect, resume, or continuity only where
transport state was mirrored across sites.

## Partitions, time and leases

A site's loss and a site's isolation look the same to the others, and the
group never needs to tell them apart: an isolated site holds no quorum, so
it cannot commit, elect or confirm a read; the rest proceed exactly as if
it were lost. When it heals, Raft's term rules make its stale leader step
down at the first higher term it hears (pre-vote keeps it from disturbing
the healthy side while isolated).

Clustor depends on no clock across the WAN:

- there is no leader lease — leadership changes only by election timeout,
  a higher term, or explicit transfer ([replication.md](replication.md));
- reads are ReadIndex, confirmed by a site-aware quorum per read;
- the directory's horizons and TTLs run on **committed logical time**
  (`timing.rs`): the leader proposes time, every replica applies the same
  committed value, so a quarantine or a deadline ends at the same log
  entry everywhere regardless of skew;
- `election_timeout_ms` and `heartbeat_interval_ms` are the only timing
  parameters a WAN deployment sizes (above the inter-site round trip, with
  margin for its jitter).

## Data locality: what the global tier holds

The global tier's log is replicated to every site it spans, so what it
holds leaves its region. The directory therefore runs with a `scope` and
refuses, before proposing (so it never enters the log), a request in a
namespace the other tier owns (`directory_scope::scope_admits`), answering
`MSG_DIR_OUT_OF_SCOPE` (`[request id][request msg][reason]`):

| `scope` | Admits | Refuses |
|---|---|---|
| `all` (0, default) | everything — one region, no global tier | nothing |
| `cell` (1) | `session/`, `transport/`, `vip/`, `fo/`, `att/`, `rs/`; `op/` TAKEOVER and EVACUATION records | `rg/` (reason 1); `op/` REGION (reason 2) |
| `global` (2) | `rg/`; `op/` REGION and EVACUATION records, and REPLAY of those | every other namespace (reason 1); `op/` TAKEOVER (reason 2) |

A session's binding, a flow's emitter and mirror horizon, a VIP's owner
set and emission tokens, an attachment's boundary and an egress block
never replicate across sites; the global log carries what a site's loss
must not take away and nothing a session is bound by.

## How the directory and `rg/` use it

`rg/<service>` ([session_directory.md](session_directory.md) §Region
namespace) is the global tier's state machine. Under a multi-site group:

- a region owner set changes (`CLAIM` … `ACTIVATE`, `RELEASE`) and each
  change raises the binding's DR generation, committed in two sites before
  any region controller is answered;
- a site loss is answered by INVALIDATE of the lost region at the
  readiness it last held — its authority void across every binding at
  once — and an `ACTIVATE` of the surviving region(s) under the DR policy
  (`dr_core` in Wormhole drives both, its REGION operation record in `op/`
  of the same group);
- an emission token minted by the global tier verifies against committed
  state that is in two sites, so a token never outlives the record that
  minted it;
- `op/` REGION and EVACUATION records (a region's DR operation, a whole
  cell's or region's evacuation) live beside it, so the operation and the
  ownership it moves are ordered in one log.

The cell's directory keeps `vip/`, `transport/` and `session/` under its
own (single-site or zone-spread) group.

## Configuration

| Module | Param | Meaning |
|---|---|---|
| `consensus` | `site_map` (u32) | each replica id's site, four bits per id, id 0 lowest (A{0,1} B{2,3} C{4} is `0x21100`) |
| `consensus` | `min_sites` (u8, default 1) | the fewest distinct sites a quorum spans |
| `session_directory` | `scope` (`all` / `cell` / `global`) | which tier this directory serves |
| `session_directory` | `smoke: 3` | the site-loss smoke: the leader commits a regional INVALIDATE one readiness higher every 300 ms; every replica logs `[sess_dir] site smoke applied readiness=N` |

`configs/session-directory-5node-sites.yaml` is the global tier as a
five-voter, three-site graph; `configs/session-directory-2site.yaml` the
two-site, RPO-zero posture.

## Proof

- `tests/site_quorum.rs` — flat equals Raft; the sited index never passes
  the plain one and is always held in `min_sites` sites; it only rises;
  every committed entry survives any one site's loss; elections need the
  same quorum; two quorums always share a voter; placement checks; every
  placement `check` accepts keeps a quorum after any one loss (exhaustive
  over five voters and three sites).
- `tests/raft_fault_matrix.rs` — with a site's only replica appending
  every entry but fsyncing none, nothing commits under the two-site map
  though one site's majority has fsynced it all, and it all commits once
  that site fsyncs; a ledger offered a configuration for another initial
  voter set adopts none and nothing commits.
- `tests/directory_scope.rs` — the cell / global split of requests.
- `tests/site_loss_e2e.rs` — five real replicas over three sites commit
  through the loss of a whole site (the leader's or not) and stop at the
  second; three replicas over two sites at `min_sites: 2` stop when one
  site goes although the other holds a majority.

## Not here

- **Real sites.** The e2e runs every replica on one host; WAN latency,
  real power and link failures are hardware work.
- **Automatic reconfiguration after a site loss.** A group that survives
  a site does not shrink itself; re-forming a group that stopped (the
  two-site posture) is an operator's joint-consensus change.
- **Which region a session is moved to.** That is Wormhole's DR policy
  (`dr_core`), driven over `rg/` and `op/`; this group only orders it.
