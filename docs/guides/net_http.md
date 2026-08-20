# Diagnostic HTTP Surface

Every cluster node runs a diagnostic HTTP listener on
`LISTEN_PORT + 10000` (so `peer_router` on 9090 has its HTTP sibling
on 19090). The deterministic mapping means `fluxor run --replicas`
and `fluxor render-template` substitute `__HTTP_PORT__` against this
formula with no separate allocator.

## Topology

The listener rides the target's network module: `linux_net` on the
Linux host target, the `ip` module (over the target's NIC driver) on
bare metal. The wiring is the same pair of edges either way:
`operations.net_out → <net>.net_in` and back (the "HTTP diagnostic
surface" group in the graph embedded in [running.md](running.md)
for the host, and the equivalent `ip` edges on bare metal).

One network-module instance serves both anchors: `peer_router` and
`operations` each bind their own listen port on it via `CMD_BIND`.
Accept events on the shared `net_in` broadcast carry the accepting
local port, and `ingress` claims only connections accepted on its
own listen port — without that filter it would answer 404s on the
wire protocol's connections.

```
                              ┌───────── operations ─────────┐
curl ──tcp──▶ net module ──▶  │ ingress ──request──▶ http    │
                              │                        │     │
      curl ◀── net module ◀── │ ingress ◀──response────┘     │
                              └──────────────────────────────┘
```

HTTP framing is clustor's, not a fluxor foundation primitive. On the
listener path above, the request/response exchange between the
`ingress` and `http` components is carried in-module. The same
message shapes also exist as graph ports: the `diag` variant of
`operations` publishes `request` (accepting `MSG_HTTP_REQUEST`, msg
type `0x74`) and `response` (emitting `MSG_HTTP_RESPONSE`, `0x75`),
so a consumer that terminates HTTP on its own shared client port can
feed the same `http::on_request` handling and receive replies over
the graph. Foundation modules stay app-agnostic either way.

The HTTP components ship only in the `diag` variant. A deployment
that must not expose an HTTP surface selects `variant: headless` on
`operations`, which compiles them out and omits the HTTP ports
(`net_in`, `net_out`, `request`, `response`, `proposal`,
`proposal_assigned`, `applied`, `proposal_rejected`) from the
module's port set; readiness and metrics still publish on `readyz`,
`why` and `export`.

## Endpoints and method handling

The endpoint surface is the GET diagnostics `/readyz`, `/why` and
`/metrics`, plus `POST /admin/<op>` and `POST /propose`. Routing in
`http::on_request` is method-gated only for the two POST paths (the
verb's first byte must be `P`); the diagnostic paths match on path
alone, so a POST to `/metrics` is answered like a GET. Unknown paths
answer 404. No route ever answers 405 — the status appears in the
response formatter's reason table but nothing sends it.

`GET /readyz` is short-circuited entirely inside `ingress` from the
readiness byte delivered each telemetry emit tick; the high-rate
probe path never enters the request pipeline and is intentionally
unlogged.

`POST /admin/<op>` is admitted through the `rbac` component like
every other admin command. HTTP carries no peer identity, so it
evaluates as `default_role` and is denied with 403 when that role is
insufficient — a property of the module's dispatch table, not of the
graph wiring. An authorised command answers 202 immediately: 202
means the envelope reached the admin component, and the command's
real outcome still answers on the module's `responses` port rather
than over HTTP. An unknown op name answers 400; a body exceeding the
1 KiB admin envelope answers 503.

## POST /propose — the write bridge

`POST /propose` is the synchronous write bridge into Raft
(`modules/app/operations/http.rs`). The `http` component allocates a
private correlation id (bit 63 set, keeping the namespace disjoint
from the codec component's), frames the request body as a tagged
`MSG_CLIENT_PROPOSAL` and emits it on the module's `proposal` port.
The response is deferred: when Raft assigns a WAL index the
correlation slot becomes an index slot, and when apply acknowledges
that index the client receives `200 committed`.

Failure answers are all 503: `propose queue unavailable` when the
proposal cannot be emitted (proposal port unwired or full, body over
1 KiB, or no free correlation slot); `proposal rejected` when the
throttle rejects it; `proposal timeout` or `commit timeout` when a
slot waits longer than `HTTP_PROPOSAL_TIMEOUT_MS` (10 s) for
assignment or apply.

The bridge needs four graph edges (the "HTTP /propose bridge" group
in the graph embedded in [running.md](running.md), plus the apply
feedback):

- `operations.proposal` → `gateway.proposals`
- `consensus.proposal_assigned` → `operations.proposal_assigned`
- `gateway.rejected` → `operations.proposal_rejected`
- `consensus.applied` → `operations.applied`

A graph without these edges fails closed: every `POST /propose`
answers `503 propose queue unavailable`.

## Parser limits

`ingress` is a minimal sequential HTTP/1.1 keep-alive server with 32
connection slots (`modules/app/operations/ingress.rs`). What it
actually enforces:

- Body length comes from `Content-Length` alone; a missing or
  malformed header means a zero-length body. Transfer encodings are
  not inspected — there is no chunked support and no explicit
  rejection of it.
- Each connection has a 2 KiB receive buffer (`RX_BUF`). A header
  block that fills the buffer without terminating answers `431` and
  the connection is closed.
- Request bodies are capped at 1024 bytes (`MAX_BODY`). A request
  advertising a larger `Content-Length` answers `413` and the
  connection is closed — never truncated, whose excess bytes would
  reparse as a smuggled pipelined request.
- Connections are persistent by default, per HTTP/1.1. A client's
  explicit `Connection: close` is honoured; every other response
  carries `Connection: keep-alive`. The `clustor-bench` load client
  depends on keep-alive. Pipelining is not supported: one request may
  be in flight per connection, and inbound bytes that arrive while a
  response is pending are dropped.
- Header bytes are not validated as ASCII, and there are no
  timeouts: no request deadline, no socket read/write timeout, no 408
  path. An idle or stalled connection holds its slot until the client
  or the transport closes it.

The parser is sized for the control-plane and diagnostic endpoints
and assumes trusted clients inside the cluster perimeter.

## Stderr signals

Signals the surface emits on stderr:

| Signal | Meaning |
|---|---|
| `[linux_net] listening on port 19090` | the network module bound the HTTP listen port (host target; the `ip` module logs the bare-metal equivalent) |
| `[ingress] init listen_port=19090` | listener brought up |
| `[ingress] accepted conn_id=N` | client connected |
| `[ingress] request M /path body=N conn_id=K` | request parsed and handed to `http`; `M` is the single method byte (`G`/`P`). Never emitted for `/readyz` |
| `[ingress] closed conn_id=N` | connection torn down |
| `[http] admin op=N conn_id=M` | admin request authorised and routed to the admin component |

## See also

- [architecture/observability.md](../architecture/observability.md) —
  the `/readyz`, `/why`, `/metrics` endpoints this surface exposes
  and what they assert about node state.
- [architecture/modules.md](../architecture/modules.md) —
  `operations` and its components in the module reference.
- [`../modules/common/http_admin.rs`](../../modules/common/http_admin.rs)
  — the canonical path → op-code mapping the `http` component uses.
