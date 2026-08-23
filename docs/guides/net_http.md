# Diagnostic HTTP Surface

Every cluster node runs a diagnostic HTTP listener on
`LISTEN_PORT + 10000` (so `peer_router` on 9090 has its HTTP sibling
on 19090). The deterministic mapping means `fluxor run --replicas`
and `fluxor render-template` substitute `__HTTP_PORT__` against this
formula with no separate allocator.

## Topology

HTTP mechanics and HTTP meaning live in different modules. Wave's
`http` module (`app` variant) terminates the wire — parsing, framing,
connection state, bounded bodies — and forwards each matched request
to `operations` as an `HttpRequest` envelope on its `HANDLER_APP`
fan-out. `operations`' `http` component owns what the request means:
the diagnostic paths, admin admission, and the `/propose` bridge.
Neither module knows the other's internals; the seam is the two
envelope ports.

The listener rides the target's network module: `linux_net` on the
Linux host target, the `ip` module (over the target's NIC driver) on
bare metal. One network-module instance serves both anchors:
`peer_router` and `http` each bind their own listen port on it via
`CMD_BIND`. Accept events on the shared `net_in` broadcast carry the
accepting local port, and each anchor claims only connections
accepted on its own listen port.

```
curl ──tcp──▶ net module ──▶ http (wave) ──req_out───▶ operations.request
curl ◀──tcp── net module ◀── http (wave) ◀──resp_in─── operations.response
```

The graph carries four edges (the "HTTP diagnostic surface" group in
every diag config under `configs/`):

- `<net>.net_out` → `http.net_in` and `http.net_out` → `<net>.net_in`
- `http.req_out` → `operations.request` and
  `operations.response` → `http.resp_in`, each with a distinct
  non-zero `buffer_group` — mailbox mode, one write = one whole
  envelope. Omitting the group does not fail loudly; it delivers
  fragmented envelopes.

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

Responses are correlated by `(conn_id, stream_id)` — wave stamps a
per-request generation into `stream_id` and `operations` echoes it,
so a reply deferred through Raft (`/propose`) can never land on a
client that merely inherited a recycled conn id.

The `http` component ships only in the `diag` variant of
`operations`. A deployment that must not expose an HTTP surface
selects `variant: headless`, which compiles it out and omits the
HTTP ports (`request`, `response`, `proposal`, `proposal_assigned`,
`applied`, `proposal_rejected`) from the module's port set; readiness
and metrics still publish on `readyz`, `why` and `export`. Such a
graph carries no wave modules at all.

## Endpoints and method handling

The endpoint surface is the GET diagnostics `/readyz`, `/why` and
`/metrics`, plus `POST /admin/<op>` and `POST /propose`. Routing in
`http::on_request` is method-gated only for the two POST paths
(wave's method byte must be `METHOD_POST`); the diagnostic paths
match on path alone, so a POST to `/metrics` is answered like a GET.
Unknown paths answer 404.

`/metrics` exceeds one wave send buffer, so `operations` streams it:
the first envelope carries `MORE_BODY`, a `Content-Length` header and
the first slice; continuation envelopes carry the rest as the
`response` port drains. One export streams at a time — a concurrent
`/metrics` answers 503 until the slot frees, and the cached export is
not refreshed mid-stream so the declared length stays true.

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
connection slots, receive/send buffers, keep-alive, and the 30 s
application timeout that answers 504 when `operations` never
replies. On the meaning side, `operations` enforces its own bounds:
request paths over 64 bytes answer 404, and bodies over the 1 KiB
admin envelope — or streamed request bodies, which nothing here
accepts — answer 413.

`operations` pulls a request only when its `response` port can take
the answer, so a saturated reply path stalls the pull rather than
losing the reply, and wave applies the backpressure. The
`responses_dropped` counter records a reply the port refused anyway;
it should stay at zero, and a rising count means the `response` edge
is undersized.

The surface is sized for the control-plane and diagnostic endpoints
and assumes trusted clients inside the cluster perimeter.

## Stderr signals

Signals the surface emits on stderr:

| Signal | Meaning |
|---|---|
| `[linux_net] listening on port 19090` | the network module bound the HTTP listen port (host target; the `ip` module logs the bare-metal equivalent) |
| `[http] bound, waiting for connections` | wave's bind acknowledgement reached the module |
| `[http] admin op=N conn_id=M` | admin request authorised and routed to the admin component |

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
