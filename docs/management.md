# Management HTTP endpoint

The `management` feature exposes a single mTLS listener that routes Readyz, Why, and
Admin requests over one TCP port. It reuses the existing per-service handlers so
payloads and deadlines stay identical to the standalone servers.

## Feature flag

Enable the `management` feature (requires `net` + `admin-http`) in your
`Cargo.toml`:

```toml
clustor = { version = "...", features = ["net", "admin-http", "management"] }
```

## Routing

The management listener handles:

- `/readyz` and `/readyz/why/<partition>`
- `/why/not-leader/<partition>` (plus `/why/snapshot-blocked/<partition>` when enabled)
- `/admin/*` (full Admin API with RBAC + mTLS)

Unknown paths return `404`, and unsupported methods return `405`.

## Mini-cluster demo

The `examples/mini-cluster` binary starts the management server when
`management_bind` is provided in `cluster.yaml`. Each node’s TLS identity acts as
an operator principal for the Admin API.

Example request:

```bash
curl -k --cacert certs/ca.pem \
     --cert certs/node-a-cert.pem --key certs/node-a-key.pem \
     https://127.0.0.1:7301/readyz | jq
```
