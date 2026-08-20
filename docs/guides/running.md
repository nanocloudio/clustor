# Running Clustor

This guide brings up a live cluster on one Linux machine and smoke
checks it over HTTP. It is self-contained: the deployment configs are
embedded below and pipe straight into `fluxor run`, so there is
nothing else to fetch. Ports and node identity come from the command
line; the config carries only the graph.

## Prerequisites

Clustor runs on the [fluxor](../../../fluxor/) runtime. One-time
setup on a development machine:

```sh
git clone git@github.com:nanocloudio/fluxor.git ../fluxor
make -C ../fluxor install    # put the fluxor CLI on PATH
make -C ../fluxor publish    # publish SDK, runtime, and foundation modules

# in this repository
fluxor modules build --all   # build clustor's modules; pre-flight
                             # materialises pinned artefacts from fluxor.lock
```

See [consuming_fluxor.md](consuming_fluxor.md) for the dependency
workflow behind these commands.

## How replica mode works

`fluxor run --replicas N` treats its config as a template, renders it
once per replica, and spawns N processes side by side, each in its
own working directory. `-` as the config argument reads the template
from stdin, so the whole deployment is one shell command. The
template placeholders are filled per replica ordinal `i`:

| Placeholder       | Value                                        |
|-------------------|----------------------------------------------|
| `__SELF_ID__`     | replica index `i` (0-based)                  |
| `__LISTEN_PORT__` | `--base-port + i` (default base 9090)        |
| `__PEER<j>_PORT__`| `--base-port + j`                            |
| `__HTTP_PORT__`   | `__LISTEN_PORT__ + --http-offset` (default 10000) |

Any other placeholder is supplied with `--var KEY=VALUE`, applied
uniformly to every replica.

## Single node

One node is its own quorum (`voter_count: 1`): proposals commit at
local durability without peer traffic. Wire port 9090, diagnostic
HTTP port 19090 by default.

```sh
fluxor run --replicas 1 - <<'EOF'
target: linux
tick_us: 1000

scheduler:
  accept_cycles: true

platform:
  net: {}

modules:
  - name: peer_router
    params:
      self_id: __SELF_ID__
      peer_count: 1
      listen_port: __LISTEN_PORT__
      peer0_port: __LISTEN_PORT__
  - name: gateway
    params:
      self_id: __SELF_ID__
  - name: consensus
    params:
      self_id: __SELF_ID__
      voter_count: 1
      heartbeat_interval_ms: 150
      peer_count: 1
  - name: durability
    params:
      self_id: __SELF_ID__
      voter_count: 1
      partition_id: 0
  - name: control_plane
  - name: admission
  - name: operations
    params:
      listen_port: __HTTP_PORT__
wiring:
  # ── linux_net ↔ peer_router (no TLS) ─────────────────────
  - from: linux_net.net_out
    to: peer_router.net_in
  - from: peer_router.net_out
    to: linux_net.net_in

  # ── peer_router → application ────────────────────────────
  - from: peer_router.cleartext
    to: gateway.requests
  - from: peer_router.peer_rx
    to: consensus.ack
  - from: peer_router.raft_rpc
    to: consensus.rpc

  # ── HTTP routing ─────────────────────────────────────────
  - from: gateway.admin_req
    to: operations.admin_req
  - from: gateway.responses
    to: peer_router.client_resp

  # ── Client pipeline ──────────────────────────────────────
  - from: gateway.proposals_tagged
    to: consensus.proposals_tagged
  - from: consensus.proposal_assigned
    to: gateway.proposal_assigned
  - from: consensus.leader_state
    to: gateway.leader_state

  # ── HTTP /propose bridge ──────────────────────────────────
  - from: operations.proposal
    to: gateway.proposals
    rate: transaction
  - from: consensus.proposal_assigned
    to: operations.proposal_assigned
  - from: gateway.rejected
    to: operations.proposal_rejected
    rate: transaction

  # ── Flow control ──────────────────────────────────────────
  - from: admission.credits
    to: gateway.credit_supply

  # ── Raft replication ──────────────────────────────────────
  - from: consensus.net_out
    to: peer_router.peer_tx
  - from: consensus.lag_signal
    to: admission.lag
  - from: consensus.rpc_out
    to: peer_router.peer_tx

  # ── Persistence ───────────────────────────────────────────
  - from: consensus.log_append
    to: durability.entries
  - from: durability.replay_complete
    to: consensus.wal_replay_complete
    rate: transaction
  - from: durability.flushed
    to: consensus.wal_flushed
  - from: consensus.cross_durability_ack
    to: durability.ack
  - from: durability.quorum_durable
    to: consensus.durable

  # ── Commit → apply ────────────────────────────────────────
  - from: consensus.entry_request
    to: durability.entry_request
    rate: transaction
  - from: durability.entry_reply
    to: consensus.entry_reply
  - from: gateway.reads
    to: consensus.read
  - from: consensus.applied
    to: gateway.applied
  - from: consensus.applied
    to: operations.applied
    rate: transaction

  # ── Snapshots ─────────────────────────────────────────────
  - from: durability.export_chunks
    to: consensus.snapshot_rx
  - from: consensus.snapshot_import
    to: durability.import_chunks
  - from: durability.manifest_auth
    to: peer_router.peer_tx
  - from: durability.installed_local
    to: consensus.snapshot_installed

  # ── Keys ──────────────────────────────────────────────────

  # ── Control plane ─────────────────────────────────────────
  - from: control_plane.proof
    to: admission.proof
  - from: admission.cache_state
    to: consensus.cp_state
  - from: admission.strict_fallback
    to: consensus.cp_state
  - from: admission.permits
    to: consensus.read_permits
  - from: control_plane.routing
    to: gateway.placement

  # ── Admin ─────────────────────────────────────────────────
  - from: operations.denied
    to: gateway.admin_responses
  - from: operations.raft_commands
    to: consensus.admin_proposals
  - from: consensus.admin_applied
    to: operations.admin_applied
  - from: operations.responses
    to: gateway.admin_responses
  - from: operations.raft_proposal
    to: consensus.proposals

  # ── Telemetry ─────────────────────────────────────────────
  - from: consensus.metrics
    to: operations.ingest
  - from: durability.metrics
    to: operations.ingest
  - from: admission.metrics
    to: operations.ingest
  - from: peer_router.metrics
    to: operations.ingest
  - from: gateway.metrics
    to: operations.ingest
  - from: operations.readyz
    to: gateway.readyz_data
  - from: operations.why
    to: gateway.why_data
  - from: operations.export
    to: gateway.metrics_data

  # ── HTTP diagnostic surface ──────────────────────────────────
  - from: linux_net.net_out
    to: operations.net_in
  - from: operations.net_out
    to: linux_net.net_in
EOF
```

Smoke checks from another terminal:

```sh
curl -i http://127.0.0.1:19090/readyz
# HTTP/1.1 200 OK once the node is ready (about a second)

curl -X POST --data 'hello' http://127.0.0.1:19090/propose
# "committed" — the entry was replicated, fsynced, and applied

curl -s http://127.0.0.1:19090/metrics | wc -c
# non-zero: the binary metrics export (decode with clustor-scrape,
# see tools/clustor-bench)
```

Ctrl+C stops the node. Each run starts clean: node state (the WAL
under `wal/`, Raft metadata) lives in a per-run scratch directory,
printed as `scratch:` at startup, along with each node's log path.

## Three nodes

Three replicas on localhost: wire ports 9090–9092, HTTP ports
19090–19092, each process in its own working directory with its own
WAL. `voter_count: 3` means majority quorum is 2, so the cluster
tolerates one node failure.

```sh
fluxor run --replicas 3 - <<'EOF'
target: linux
tick_us: 1000

scheduler:
  accept_cycles: true

platform:
  net: {}

modules:
  - name: peer_router
    params:
      self_id: __SELF_ID__
      peer_count: 3
      listen_port: __LISTEN_PORT__
      peer0_port: __PEER0_PORT__
      peer1_port: __PEER1_PORT__
      peer2_port: __PEER2_PORT__

  - name: gateway
    params:
      self_id: __SELF_ID__
  - name: consensus
    params:
      self_id: __SELF_ID__
      voter_count: 3
      heartbeat_interval_ms: 150
      peer_count: 3
  - name: durability
    params:
      self_id: __SELF_ID__
      voter_count: 3
      partition_id: 0
  - name: control_plane
  - name: admission
  - name: operations
    params:
      listen_port: __HTTP_PORT__
wiring:
  # ── Transport: linux_net ↔ peer_router ─────────────────────
  - from: linux_net.net_out
    to: peer_router.net_in
  - from: peer_router.net_out
    to: linux_net.net_in

  # ── Inbound peer traffic ───────────────────────────────────
  - from: peer_router.peer_rx
    to: consensus.ack
    buffer_bytes: 16384
  - from: peer_router.raft_rpc
    to: consensus.rpc
    buffer_bytes: 16384

  # ── Outbound peer traffic ──────────────────────────────────
  - from: consensus.rpc_out
    to: peer_router.peer_tx
    buffer_bytes: 16384
  - from: consensus.net_out
    to: peer_router.repl_tx
    buffer_bytes: 16384

  # ── HTTP/client routing ────────────────────────────────────
  - from: peer_router.cleartext
    to: gateway.requests
  - from: gateway.admin_req
    to: operations.admin_req
  - from: gateway.responses
    to: peer_router.client_resp

  # ── Client pipeline ────────────────────────────────────────
  - from: gateway.proposals_tagged
    to: consensus.proposals_tagged
  - from: consensus.proposal_assigned
    to: gateway.proposal_assigned
  - from: consensus.leader_state
    to: gateway.leader_state

  # ── HTTP /propose bridge ───────────────────────────────────
  - from: operations.proposal
    to: gateway.proposals
    rate: transaction
  - from: consensus.proposal_assigned
    to: operations.proposal_assigned
  - from: gateway.rejected
    to: operations.proposal_rejected
    rate: transaction

  # ── Flow control ───────────────────────────────────────────
  - from: admission.credits
    to: gateway.credit_supply

  # ── Raft replication ───────────────────────────────────────
  - from: consensus.lag_signal
    to: admission.lag

  # ── Persistence ────────────────────────────────────────────
  - from: consensus.log_append
    to: durability.entries
  - from: durability.replay_complete
    to: consensus.wal_replay_complete
    rate: transaction
    buffer_bytes: 16384
  - from: consensus.wal_compact
    to: durability.compact_before
  - from: durability.flushed
    to: consensus.wal_flushed
  - from: consensus.cross_durability_ack
    to: durability.ack
  - from: consensus.entry_request
    to: durability.entry_request
    buffer_bytes: 8192
  - from: durability.entry_reply
    to: consensus.entry_reply
    buffer_bytes: 8192
  - from: durability.quorum_durable
    to: consensus.durable

  # ── Commit → apply ─────────────────────────────────────────
  - from: gateway.reads
    to: consensus.read
  - from: consensus.applied
    to: gateway.applied
  - from: consensus.applied
    to: operations.applied
    rate: transaction

  # ── Snapshots ──────────────────────────────────────────────
  - from: durability.export_chunks
    to: consensus.snapshot_rx
  - from: consensus.snapshot_import
    to: durability.import_chunks
  - from: durability.manifest_auth
    to: peer_router.peer_tx
  - from: durability.installed_local
    to: consensus.snapshot_installed

  # ── Keys ───────────────────────────────────────────────────

  # ── Control plane ──────────────────────────────────────────
  - from: control_plane.proof
    to: admission.proof
  - from: admission.cache_state
    to: consensus.cp_state
  - from: admission.strict_fallback
    to: consensus.cp_state
  - from: admission.permits
    to: consensus.read_permits
  - from: control_plane.routing
    to: gateway.placement

  # ── Admin ──────────────────────────────────────────────────
  - from: operations.denied
    to: gateway.admin_responses
  - from: operations.raft_commands
    to: consensus.admin_proposals
  - from: consensus.admin_applied
    to: operations.admin_applied
  - from: operations.responses
    to: gateway.admin_responses
  - from: operations.raft_proposal
    to: consensus.proposals

  # ── Telemetry ──────────────────────────────────────────────
  - from: consensus.metrics
    to: operations.ingest
  - from: durability.metrics
    to: operations.ingest
  - from: admission.metrics
    to: operations.ingest
  - from: peer_router.metrics
    to: operations.ingest
  - from: gateway.metrics
    to: operations.ingest
  - from: operations.readyz
    to: gateway.readyz_data
  - from: operations.why
    to: gateway.why_data
  - from: operations.export
    to: gateway.metrics_data

  # ── HTTP diagnostic surface ──────────────────────────────────
  - from: linux_net.net_out
    to: operations.net_in
  - from: operations.net_out
    to: linux_net.net_in
EOF
```

Find the leader by proposing to each node:

```sh
for p in 19090 19091 19092; do
  curl -s -X POST --data "via-$p" -w " [$p: %{http_code}]\n" \
    http://127.0.0.1:$p/propose
done
# the leader answers 200 "committed"; followers answer
# 503 "proposal timeout" after 10 s (there is no leader forwarding)
```

To watch a failover, kill the leader's pid (printed at startup) and
propose to a surviving node. Within a few seconds one of the
remaining two wins an election and commits.

## Ports and other overrides

The templates carry no fixed ports, so a cluster on a different port
range is only a flag away:

```sh
fluxor run --replicas 3 --base-port 7000 - <<'EOF'
...same template as above...
EOF
# wire 7000-7002, HTTP 17000-17002
```

## Running nodes by hand

For one node per host, or full control over placement, save the
template to a file, render each node's config yourself, and run it
directly:

```sh
fluxor render-template cluster.yaml \
    --var SELF_ID=0 --var LISTEN_PORT=9090 --var HTTP_PORT=19090 \
    --var PEER0_PORT=9090 --var PEER1_PORT=9091 --var PEER2_PORT=9092 \
    > n0.yaml
fluxor run n0.yaml
```

Run each node in its own working directory: the durability module
persists its WAL under `./wal/` relative to the process cwd, and two
nodes sharing a directory would interleave their logs.

## Reading the graph

The embedded configs are the canonical graph definitions: the module
set and every channel edge between them. The module list is short --
`peer_router` (peer transport demux), `gateway` (client framing and
admission), `consensus` (elections, replication, apply),
`durability` (WAL, quorum tracking, snapshots), `control_plane`
(proof and placement feed), `admission` (read gate and flow
control), `operations` (admin, telemetry, diagnostic HTTP) — and
the wiring below it is the substrate's actual topology.
[architecture/modules.md](../architecture/modules.md) explains each
edge group.

## The diagnostic HTTP surface

Each node's `operations` module serves, on `__HTTP_PORT__`:

| Route              | Behaviour |
|--------------------|-----------|
| `GET /readyz`      | 200 when ready, 503 otherwise; one-byte body |
| `GET /why`         | two bytes: version, timing-pause reason |
| `GET /metrics`     | binary metrics export (see [architecture/observability.md](../architecture/observability.md)) |
| `POST /propose`    | submits the body (≤ 1 KiB) as a replicated entry; answers `committed` when applied, 503 on timeout or reject |
| `POST /admin/<op>` | admin commands (`freeze`, `thaw`, …); see [architecture/modules.md](../architecture/modules.md) |

HTTP admin is admitted as the `default_role` (operator by default)
because HTTP carries no peer identity. Deployments that must not
accept HTTP admin set an observer `default_role` or select the
`headless` variant of `operations`; the templates note this too.
