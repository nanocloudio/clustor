# clustor Makefile — the lifecycle only: clean / build / test /
# lint / ci / publish, plus the two project targets that earn their
# names under standards/make.md §1: `bench` (canonicalizes the
# criterion flags the CI-fast run uses) and `e2e` (composes the
# sequential, thread-bounded cluster/chaos/partition/wal harness
# runs). Anything else is the `fluxor` CLI directly.

.PHONY: help build test bench lint ci e2e publish clean

SHELL       := /bin/bash
.SHELLFLAGS := -euo pipefail -c

.DEFAULT_GOAL := build

# The registry-resolved fluxor tree — SDK sources, the fmod palette
# and the `fluxor-linux` runtime — is staged under `target/fluxor/`,
# so `cargo clean` takes it with it. That tree is a build *input*, not
# an output: `modules/app/*/mod.rs` and `tests/wal_scan.rs` `include!`
# the SDK sources at compile time, so without it even `cargo build
# --all-targets` fails to resolve its includes.
#
# Declared as a file prerequisite rather than a `sync` target:
# standards/make.md §1 reserves the target namespace for lifecycle
# stages and forbids aliasing a CLI command, and this adds no name to
# type — it just lets the lifecycle targets restage their own input.
# Re-staging is a no-op when the tree is already present (~50ms), and
# `cargo clean` removes it wholesale, so the sentinel never goes stale
# against a partially-populated tree.
FLUXOR_SDK := target/fluxor/fluxor-abi/sdk/abi.rs

$(FLUXOR_SDK):
	fluxor sync

help:
	@echo "clustor lifecycle:"
	@echo "  make build     cargo build --workspace --all-targets"
	@echo "  make test      cargo test --workspace (TEST_THREADS=$(TEST_THREADS))"
	@echo "  make lint      rustfmt --check + clippy -D warnings + palette lint"
	@echo "  make ci        fluxor ci — the full gate (lints, hygiene,"
	@echo "                 tests, strict module build, lockfile checks)"
	@echo "  make publish   fluxor publish — canonical registry publish"
	@echo "  make clean     cargo clean + module artefacts (the staged"
	@echo "                 fluxor tree restages itself on next build)"
	@echo "clustor-specific:"
	@echo "  make bench     host L0/L1 micro-benches (criterion, --quick)"
	@echo "  make e2e       strict cluster/chaos/partition/wal e2e"
	@echo "                 (sequential, thread-bounded; hard-fails on skip)"
	@echo ""
	@echo "Not make targets (use the CLI directly):"
	@echo "  fluxor modules build [--target …]   PIC modules"
	@echo "  fluxor run / up                     bring-up"
	@echo "  fluxor update / sync                registry consumption"
	@echo "One-time setup: make -C ../fluxor install"

build: $(FLUXOR_SDK)
	cargo build --workspace --all-targets

# Cluster e2e tests (`tests/cluster.rs`, `chaos.rs`, `partition.rs`)
# each spin up 1–3 `fluxor-linux` child processes. Default cargo
# parallelism saturates a 4-core Pi-class host and Raft commit
# budgets miss their deadlines. `--test-threads=4` keeps the
# concurrent-cluster count bounded; individual unit-test binaries
# (fast, no children) still run with full intra-binary parallelism.
TEST_THREADS ?= 4
test: $(FLUXOR_SDK)
	cargo test --workspace -- --test-threads=$(TEST_THREADS)

# Host L0/L1 micro-benches (RFC §7.1). `--quick` keeps it CI-fast;
# drop the flag for full criterion sampling when chasing a
# regression.
bench: $(FLUXOR_SDK)
	cargo bench --benches -- --quick

lint: $(FLUXOR_SDK)
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets --all-features -- -D warnings
	tools/palette-lint.sh

ci: $(FLUXOR_SDK)
	fluxor ci

# End-to-end cluster/chaos/partition/wal tests. Each spins up real
# `fluxor-linux` child processes, so they need the clustor modules
# built at the harness's resolution path
# (`target/fluxor/<silicon>/modules`) and a `fluxor-linux` runtime
# materialised — both come from the staged tree above.
#
# CLUSTOR_REQUIRE_E2E=1 turns the harness's soft-skip into a HARD
# failure, so CI cannot report green by silently skipping the
# resilience suite — a permanently green-by-skip chaos suite
# removes the regression signal.
#
# Each test binary is a SEPARATE, sequential `cargo test`
# invocation rather than one combined command. cargo runs distinct
# test binaries in parallel, so a combined run would spin up
# cluster + chaos + partition clusters at once — 16+ `fluxor-linux`
# nodes on a 4-core host. That oversubscription starves the
# convergence-sensitive tests (e.g. follower catch-up) past their
# budgets. One binary at a time, at a modest intra-binary thread
# count, keeps it to a few concurrent 3-node clusters.
E2E_THREADS ?= 2
e2e: $(FLUXOR_SDK)
	fluxor modules build --all
	CLUSTOR_REQUIRE_E2E=1 cargo test --test wal_replay -- --test-threads=$(E2E_THREADS)
	# wal_group_fsync's 4 tests all launch single-node clusters through
	# `Cluster::launch`, which wipes and recreates one hardcoded, shared
	# `<workspace>/wal/` directory per launch (the WAL module resolves
	# `wal/p...` relative to the spawned process's cwd, with no per-node
	# override). Concurrent launches within this binary race on that one
	# directory — confirmed by direct reproduction: 3/3 clean at
	# --test-threads=1, 3/3 deterministic cross-contamination at
	# --test-threads=2. Force single-threaded until the harness gives
	# each node its own WAL directory.
	CLUSTOR_REQUIRE_E2E=1 cargo test --test wal_group_fsync -- --test-threads=1
	CLUSTOR_REQUIRE_E2E=1 cargo test --test partition -- --test-threads=$(E2E_THREADS)
	CLUSTOR_REQUIRE_E2E=1 cargo test --test chaos -- --test-threads=$(E2E_THREADS)
	CLUSTOR_REQUIRE_E2E=1 cargo test --test cluster -- --test-threads=$(E2E_THREADS)
	CLUSTOR_REQUIRE_E2E=1 cargo test --test session_directory_e2e --test timing_cluster_e2e -- --test-threads=1

publish:
	fluxor publish

clean:
	cargo clean
	fluxor modules clean
