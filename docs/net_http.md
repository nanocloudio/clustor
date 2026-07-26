# Diagnostic HTTP Surface

Every cluster node runs a diagnostic HTTP listener on
`LISTEN_PORT + 10000` (so `peer_router` on 9090 has its HTTP sibling
on 19090). The deterministic mapping means
[`fluxor render-template`](../fluxor.toml) and the cluster harness
substitute `__HTTP_PORT__` against this formula with no separate
allocator.

## Topology

Two `linux_net` instances run per node — one bound to the clustor
wire socket (`peer_router`), one bound to the HTTP listener
(`operations.net_in` / `operations.net_out`). Fluxor supports the
multi-instance pattern by design (see fluxor's
`src/platform/linux/providers.rs` and the YAML loader in
`tools/src/config.rs`).

```
                                 ┌───────── operations ─────────┐
curl ──tcp──▶ linux_net_http ──▶ │ ingress ──request──▶ http    │
                                 │                        │     │
      curl ◀── linux_net_http ◀──│ ingress ◀──response────┘     │
                                 └──────────────────────────────┘
```

HTTP framing is clustor's, not a fluxor foundation primitive —
the request/response exchange (`MSG_HTTP_REQUEST` /
`MSG_HTTP_RESPONSE`, msg types `0x74` / `0x75`) is a private
protocol between the `ingress` and `http` components of
`operations`, carried in-module rather than over the graph.
Foundation modules stay app-agnostic.

The two components ship only in the `diag` variant. A deployment
that must not expose an HTTP surface selects
`variant: headless` on `operations`, which compiles them out and
omits `net_in` / `net_out` from the module's port set; readiness
and metrics still publish on `readyz`, `why` and `export`.

The endpoint surface today is GET-only diagnostics (`/readyz`,
`/why`, `/metrics`) plus the `POST /admin/<op>` and `POST /propose`
paths. Other methods on diagnostic routes return 405 from the
`http` component; requests are one-shot (`Connection: close`).

`POST /admin/<op>` is admitted through the `rbac` component like
every other admin command. HTTP carries no peer identity, so it
evaluates as `default_role` and is denied with 403 when that role
is insufficient — a property of the module's dispatch table, not of
the graph wiring.

## Parser limits

Clustor ships a small HTTP/1.1 implementation that is just large
enough for control-plane and diagnostic endpoints. The parser
intentionally omits a number of features:

- Only requests with an explicit `Content-Length` header are
  accepted. Chunked transfer encoding and streaming bodies are
  rejected with `HttpError::ChunkedEncodingUnsupported`.
- Header names and values must be ASCII and the total header
  section is capped at 64 KiB. Larger payloads result in
  `HttpError::HeadersTooLarge`.
- Request bodies are buffered eagerly and limited to 4 MiB per
  request. Clients attempting to send more data receive
  `HttpError::BodyTooLarge`.
- The parser does not implement HTTP keep-alive negotiation;
  every response ends with `Connection: close` and the client is
  expected to reconnect.
- Timeouts are enforced by `RequestDeadline` and socket-level
  read/write timeouts inside each server. When a deadline expires
  the connection is closed with a `408 Request Timeout` response.

These constraints keep the networking surface area extremely
small. The manual parser is for trusted systems inside the cluster
perimeter and is not a general-purpose HTTP framework.

## Stderr signals

The assertion vocabulary HTTP-gated tests rely on:

| Signal | Meaning |
|---|---|
| `[linux_net] listening on port 19090` | second `linux_net` instance bound |
| `[ingress] init listen_port=19090` | listener brought up |
| `[ingress] accepted conn_id=N` | client connected |
| `[ingress] request <METHOD> <PATH> conn_id=N` | request parsed |
| `[ingress] closed conn_id=N` | connection torn down |
| `[http] admin op=N conn_id=M` | admin request accepted for dispatch |

## See also

- [architecture/observability.md](architecture/observability.md) —
  the `/readyz`, `/why`, `/metrics` endpoints this surface exposes
  and what they assert about node state.
- [architecture/modules.md](architecture/modules.md) —
  `operations` and its components in the four-domain module map.
- [`../modules/common/http_admin.rs`](../modules/common/http_admin.rs)
  — the canonical path → op-code mapping shared between the `http`
  component and host tests.
