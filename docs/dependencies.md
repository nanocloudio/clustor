# Dependency Overview

Arguments for each direct dependency and the default feature stance. All crates are listed exactly as pinned in `Cargo.toml`.

| Crate | Why it's needed | Feature stance |
| --- | --- | --- |
| `serde`, `serde_json` | Serialization glue for durability logs, management HTTP payloads, and audit artifacts. Only the `derive` feature on `serde` is enabled; no other defaults are pulled in. | Keep minimal `derive` feature. |
| `thiserror` | Derive-based error ergonomics throughout the codebase (see `src/util/error.rs`). No local patches or vendored copies. | Upstream crate directly from crates.io. |
| `rand`, `rand_chacha` | Generating entropy for tokens, key material, and fuzz-friendly tests. Uses explicit RNGs to avoid pulling in `getrandom` twice. | Default features only. |
| `crc32fast`, `sha2`, `aes-gcm`, `hmac`, `hex`, `zeroize` | Storage integrity, crypto helpers for snapshot manifests, and key management. All crates run in `std` mode with the smallest surface that satisfies persistence requirements. | `sha2` is built without default features; `zeroize` only uses the core crate. |
| `ed25519-dalek` | Signing snapshot manifests and verifying capabilities. Uses the `std` feature for deterministic builds. | `default-features = false` with a targeted feature list. |
| `memmap2` | Efficient WAL access without copying entire segments into memory. | Default configuration. |
| `httparse` | Minimal HTTP parser for the in-tree admin/readyz servers. | Optional under the `net` feature. |
| `log` | Sole logging facade used everywhere (`docs/architecture.md` details the policy). | Default configuration. |
| `rustls`, `rustls-pemfile`, `tokio-rustls` | TLS termination for admin/readyz/raft transports. `rustls` runs with `default-features = false` and the minimal TLS12 surface; async servers go through `tokio-rustls`. | Controlled via the `net` / `async-net` feature flags. |
| `url`, `x509-parser` | Admin client parsing and SPIFFE certificate verification. Both are optional and only compiled when networking is enabled. | Optional (`net`). |
| `tokio` | Unified async runtime for every async feature (see `tools/check_async_runtime.sh`). Only the features that the transports need (`rt`, `rt-multi-thread`, `time`, `macros`, `sync`, `net`, `io-util`) are enabled. | Behind the `async-net` feature. |
| `parking_lot` | Faster mutexes for telemetry/state caches where poisoning semantics make sense. | Default configuration. |
| `tempfile`, `rcgen` | Dev/test-only helpers for TLS fixtures and temporary on-disk datasets. | Under `[dev-dependencies]` only. |

Every additional dependency must be accompanied by an entry in this file explaining why it is needed and how its features are constrained. This keeps Task 14’s “dependency minimisation” bar enforceable.

## Auditing

Run `tools/audit.sh` to dump the current dependency tree (both normal and feature-expanded) and, when available, run `cargo audit` for vulnerability checks. The script deliberately avoids adding runtime dependencies; install `cargo-audit` locally if you want the extra check.
