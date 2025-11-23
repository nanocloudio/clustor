# Mini Cluster Example

This example binary launches a self-contained TLS-enabled Raft transport plus an HTTPS
event API so you can run three local nodes and experiment with sending events over
HTTP while the nodes talk Raft over raw TLS.

The project is intentionally standalone: everything lives inside `examples/mini-cluster/`
including its own `Cargo.toml`, configuration, and certificate directory.

> **Note:** This demo is intentionally minimal. It does **not** implement the full Clustor
> consensus core; it simply showcases how to wire the transport primitives together.

## 1. Generate certificates with `nanocloud ca`

Use the sibling `nanocloud` repository to generate a CA plus node certificates. All
artifacts stay within this example directory.

Run `nanocloud ca <node-name>` once per node; the command prints JSON that embeds the
base64-encoded key, certificate, and CA bundle. Decode those blobs into the expected PEM files (requires `jq` + `base64`):

```bash
mkdir -p ./examples/mini-cluster/certs

for node in node-a node-b node-c; do
  json="$(nanocloud ca "${node}")"
  printf '%s\n' "${json}" | jq -r '.key'  | base64 -d > "./examples/mini-cluster/certs/${node}-key.pem"
  printf '%s\n' "${json}" | jq -r '.cert' | base64 -d > "./examples/mini-cluster/certs/${node}.pem"
  printf '%s\n' "${json}" | jq -r '.ca'   | base64 -d > "./examples/mini-cluster/certs/ca.pem"
done
```

The CA output is identical for every node; overwriting `ca.pem` inside the loop is safe. The
`cluster.yaml` file already references these paths. If you regenerate certificates, keep the
filenames consistent or update the config accordingly.

## 2. Build the example binary

```bash
cd ./examples/mini-cluster
cargo build
```

## 3. Run three nodes

Use three terminals (one per node) so each instance can keep running:

```bash
# Terminal 1
cargo run -- --config cluster.yaml --node node-a

# Terminal 2
cargo run -- --config cluster.yaml --node node-b

# Terminal 3
cargo run -- --config cluster.yaml --node node-c
```

Each node exposes:

- A Raft TLS listener (see `cluster.yaml` for the port)
- An HTTPS API on the corresponding `http_bind` address
- A consolidated management endpoint on `management_bind` (mTLS) serving `/readyz`, `/readyz/why/<id>`, `/why/not-leader/<id>`, and `/admin/*`

By default every node keeps its Raft log under `./state/<node-id>/raft.log`, resolved
relative to the configuration file. You can choose a different location with
`--state-dir /path/to/state`. Remove the node's state directory if you want to wipe
its history before rerunning the example.

> **Logging tip:** The binary configures `env_logger` with the default filter
> `info,clustor=info`, so you'll see the structured `event=...` logs from the Clustor
> core alongside the example's own messages without setting environment variables.
> Pass `--log-filter <spec>` (same syntax as `RUST_LOG`, e.g. `--log-filter clustor::snapshot=debug`)
> if you want to override the filter at runtime. The example now renders logs with the
> same clause/event vocabulary as the core crate, and the terminal output is color-coded by
> log level so lifecycle events (node joins, peer disconnects, durability proofs, etc.) are easy to spot.
>
> The demo now wires up the full Clustor consensus core: durability proofs, strict-fallback
> gating, and ControlPlane read guards all run inside the example. Every HTTP read hits the
> ReadIndex gate, quorum fsyncs produce ledger proofs, and the structured `event=` logs cited
> in the specification stream directly to your terminal.

## 4. Send events and query state

With all three nodes running, use `curl` (or any HTTPS client that trusts the demo CA)
to send events and list the replicated log. Below, `node-a` listens on `127.0.0.1:7201`
and `node-c` on `127.0.0.1:7203`.

```bash
# Send an event to node A
curl -k --cacert certs/ca.pem \
     -H "content-type: application/json" \
     -d '{"message":"hello raft"}' \
     https://127.0.0.1:7201/events

# Post another event
curl -k --cacert certs/ca.pem \
     -H "content-type: application/json" \
     -d '{"message":"from node c"}' \
     https://127.0.0.1:7203/events

# Query any node to see the replicated log
curl -k --cacert certs/ca.pem https://127.0.0.1:7202/events | jq

# Query the management API (mTLS)
curl -k --cacert certs/ca.pem \
     --cert certs/node-a-cert.pem --key certs/node-a-key.pem \
     https://127.0.0.1:7301/readyz | jq
```

You should see each node report both events even though you only posted to two of them.
Replication happens via the raw TLS Raft transport included in this demo.

## 5. Clean up

When you are done experimenting, stop each node with `Ctrl+C`. All generated
certificates live under `examples/mini-cluster/certs/`, so you can delete that directory
to nuke the demo CA.
