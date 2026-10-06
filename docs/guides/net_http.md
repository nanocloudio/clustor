# Diagnostic HTTP Surface

Every cluster node runs a diagnostic HTTP listener on
`LISTEN_PORT + 10000` (so `peer_router` on 9090 has its HTTP sibling
on 19090). The deterministic mapping means `fluxor run --replicas`
and `fluxor render-template` substitute `__HTTP_PORT__` against this
formula with no separate allocator.

## Topology

HTTP mechanics and HTTP meaning live in different modules. Wave's
`http` module (`app` variant) terminates the wire — parsing, framing,
connection state, bounded bodies — and hands each matched request to
`operations` as an exchange: wave's `http` is the requester and
`operations` the provider, speaking the fluxor SDK exchange contract
(`contracts/exchange.rs`, described in fluxor's
`docs/architecture/exchange.md`). `operations`' `http` component owns
what the request means: the diagnostic paths, admin admission, and the
`/propose` bridge. Neither module knows the other's internals; the seam
is the exchange port pair.

The listener rides the target's network module: `linux_net` on the
Linux host target, the `ip` module (over the target's NIC driver) on
bare metal. One network-module instance serves both anchors:
`peer_router` and `http` each bind their own listen port on it via
`CMD_BIND`. Accept events on the shared `net_in` broadcast carry the
accepting local port, and each anchor claims only connections
accepted on its own listen port.

```
curl ──tcp──▶ net module ──▶ http (wave) ──request_out──▶ operations.request_in
curl ◀──tcp── net module ◀── http (wave) ◀──response_in── operations.response_out
```

The graph carries four edges (the "HTTP diagnostic surface" group in
every diag config under `configs/`):

- `<net>.net_out` → `http.net_in` and `http.net_out` → `<net>.net_in`
- `http.request_out` → `operations.request_in` and
  `operations.response_out` → `http.response_in`. Both are framed
  `ExchangeRequest`/`ExchangeResponse` edges, so the build gives each a
  mailbox of its own and one channel record is one whole exchange
  record; the wiring names nothing else.

The wave module block is uniform across the configs:

```yaml
- name: http
  variant: app
  port: 19090
  host_tcp: 1        # linux_net downstream only; omit on bare metal
  routes:
    - path: "/"
      app: true      # catch-all: operations owns the 404
```

Answers are correlated by the 14-byte exchange id wave chooses for each
request and `operations` echoes verbatim. The id names one request, so
an answer deferred through Raft (`/propose`) can never land on a client
that merely inherited a recycled connection. `operations` treats the id
as opaque.

The `http` component ships only in the `diag` variant of
`operations`. A deployment that must not expose an HTTP surface
selects `variant: headless`, which compiles it out and omits the
HTTP ports (`request_in`, `response_out`, `proposal`, `proposal_assigned`,
`applied`, `proposal_rejected`) from the module's port set; readiness
and metrics still publish on `readyz`, `why` and `export`. Such a
graph carries no wave modules at all.

## Endpoints and method handling

The endpoint surface is the GET diagnostics `/readyz`, `/why` and
`/metrics`, plus `POST /admin/<op>` and `POST /propose`. Routing in
`http::on_request` is method-gated only for the two POST paths
(the request HEAD's method must be `METHOD_POST`); the diagnostic
paths match on the target alone, so a POST to `/metrics` is answered
like a GET. Unknown targets answer 404. Every answer is `text/plain`.

Every answer is one response record: a HEAD with the whole body inline
and no MORE. `/metrics` is the largest — the telemetry export, capped
by `telemetry::SAFE_EXPORT_MAX` — and a compile-time assertion holds it
inside one record, so nothing streams and no response credit is spent.
Wave derives `Content-Length` from the record.

`POST /admin/<op>` is admitted through the `rbac` component like
every other admin command. HTTP carries no peer identity, so it
evaluates as `default_role` and is denied with 403 when that role is
insufficient — a property of the module's dispatch table, not of the
graph wiring. An authorised command answers 202 immediately: 202
means the envelope reached the admin component, and the command's
real outcome still answers on the module's `responses` port rather
than over HTTP. An unknown op name answers 400; a body exceeding the
1 KiB admin envelope answers 503 (or 413 past the request body bound
below).

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

The bridge needs four graph edges (beyond the surface's own four):

- `operations.proposal` → `gateway.proposals`
- `consensus.proposal_assigned` → `operations.proposal_assigned`
- `gateway.rejected` → `operations.proposal_rejected`
- `consensus.applied` → `operations.applied`

A graph without these edges fails closed: every `POST /propose`
answers `503 propose queue unavailable`.

## Limits

The wire-side limits are wave's (see wave's
`modules/foundation/http/README.md` and its per-target sizing):
connection slots, receive/send buffers, keep-alive, and the
application timeout that answers 504 when `operations` never answers.

On the meaning side, `operations` collects each request whole with the
contract's `Collector` and enforces its own bounds:

| Bound | Value | Past it |
|---|---|---|
| exchanges collected at once | 4 | 503 |
| request target (path and query) | 256 bytes | 413 |
| forwarded header block | 2048 bytes | 413 |
| request body | 1024 bytes | 413 |
| body announced with MORE, unfinished | 10 s | 408 |

Wave inlines a body it already holds whole in the request HEAD; a body
announced with MORE is granted the rest of the 1024-byte bound at once,
and the request is handled when its last BODY record arrives. A record
out of order for its exchange answers 400. A requester ABORT frees the
exchange, and a deferred `/propose` answer for it is never written.

Every record `operations` writes is placed through the SDK's
`ExchangeOutbox`: a record `response_out` has no room for is held and
placed on a later step, never dropped, and no request or feedback is
pulled while one is held — so a saturated answer path stalls the pull
and wave feels the backpressure. The `responses_dropped` counter
records an answer that could not be composed; it stays at zero.

The surface is sized for the control-plane and diagnostic endpoints
and assumes trusted clients inside the cluster perimeter.

## Stderr signals

Signals the surface emits on stderr:

| Signal | Meaning |
|---|---|
| `[linux_net] listening on port 19090` | the network module bound the HTTP listen port (host target; the `ip` module logs the bare-metal equivalent) |
| `[http] bound, waiting for connections` | wave's bind acknowledgement reached the module |
| `[http] admin op=N conn_id=M` | admin request authorised and routed to the admin component; `M` is the HTTP surface's admin sequence, the breadcrumb the admin envelope carries |

Per-request logging is intentionally absent on both sides: logging
every health-check hit would violate the per-packet severity
discipline (standards/observability.md §2).

## See also

- [architecture/observability.md](../architecture/observability.md) —
  the `/readyz`, `/why`, `/metrics` endpoints this surface exposes
  and what they assert about node state.
- [architecture/modules.md](../architecture/modules.md) —
  `operations` and its components in the module reference.
- [`../modules/common/http_admin.rs`](../../modules/common/http_admin.rs)
  — the canonical path → op-code mapping the `http` component uses.
