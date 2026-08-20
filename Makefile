# clustor Makefile — the lifecycle only: help / build / test / lint /
# ci / publish / clean, plus the two project targets that earn their
# names under standards/make.md §1: `bench` (canonicalizes the
# criterion flags the CI-fast run uses) and `e2e` (composes the
# sequential, thread-bounded cluster/chaos/partition/wal harness
# runs). Anything else is the `fluxor` CLI directly
# (`fluxor modules build`, `fluxor run`, `fluxor update`, `fluxor sync`,
# `fluxor build --check …`) — a make target that merely renames one CLI
# command is bloat, not convenience.

SHELL       := /bin/bash
.SHELLFLAGS := -euo pipefail -c

.DEFAULT_GOAL := build

.PHONY: help build test bench lint ci e2e publish clean

help:
	@fluxor help --make

build:
	fluxor build

test:
	fluxor test

lint:
	fluxor lint

ci:
	fluxor ci

publish:
	fluxor publish

clean:
	fluxor clean

# ---------------------------------------------------------------------
# Project targets (standards/make.md §1: flag canonicalizer / genuine
# composition). These run cargo directly, so each first restages the
# registry-resolved fluxor tree (SDK sources, fmod palette,
# `fluxor-linux` runtime) under `target/fluxor/` — a build *input*,
# not output: `modules/app/*/mod.rs` and `tests/wal_scan.rs`
# `include!` the SDK sources at compile time, and `cargo clean` takes
# the tree with it. Re-staging is a no-op when present (~50ms).

# Host L0/L1 micro-benches (RFC §7.1). `--quick` keeps it CI-fast;
# drop the flag for full criterion sampling when chasing a
# regression.
bench:
	fluxor sync
	cargo bench --benches -- --quick

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
e2e:
	fluxor sync
	fluxor modules build --all
	# Host-only module-core suites: no fluxor-linux or .fmod prereqs, so
	# they cannot skip. They ride this target because it is the only
	# gate `fluxor ci` reaches for anything under tests/ (phase 4 needs
	# a tests/harness sub-workspace, which this project does not have).
	cargo test --test raft_meta --test wal_scan
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
	# volatile_cluster binds real ports per test and its deep-catch-up
	# case drives hundreds of proposals through one 3-node cluster:
	# serialise the binary like the other port-heavy suites.
	CLUSTOR_REQUIRE_E2E=1 cargo test --test volatile_cluster -- --test-threads=1
	CLUSTOR_REQUIRE_E2E=1 cargo test --test session_directory_e2e --test timing_cluster_e2e -- --test-threads=1
