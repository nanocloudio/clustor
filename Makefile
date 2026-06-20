# clustor Makefile — fluxor-based. See ~/Development/nanocloudio/standards/make.md.

.PHONY: help build test bench fmt fmt-check clippy lint ci verify e2e modules-std \
        modules modules-all modules-clean up up-cluster clean setup \
        update sync sync-dry publish publish-local

SHELL       := /bin/bash
.SHELLFLAGS := -euo pipefail -c
CARGO       ?= cargo
FLUXOR      ?= fluxor
TARGET      ?= bcm2712

.DEFAULT_GOAL := build

help:
	@echo "clustor make targets"
	@echo "  make build          host build"
	@echo "  make test           cargo test --workspace"
	@echo "  make bench          host micro-benches (L0/L1, criterion)"
	@echo "  make fmt|fmt-check  rustfmt"
	@echo "  make clippy|lint    clippy + fmt-check"
	@echo "  make modules        build PIC modules for TARGET=$(TARGET)"
	@echo "  make modules-all    build modules for every target in fluxor.toml"
	@echo "  make up             render+run a single replica (CONFIG=, NODE_ID=)"
	@echo "  make up-cluster     spawn REPLICAS replicas (CONFIG=, REPLICAS=)"
	@echo "  make ci             full CI gate (fluxor ci)"
	@echo "  make e2e            strict cluster/chaos/partition/wal e2e (needs synced fluxor-linux)"
	@echo "  make verify         ci + e2e (the resilience regression gate)"
	@echo "  make clean          cargo clean + module artefacts"
	@echo "  make setup          install fluxor CLI onto PATH"
	@echo "  Fluxor registry consumption (see standards/dependencies.md):"
	@echo "  make update         resolve fluxor.lock against the local registry"
	@echo "  make sync[-dry]     install lockfile-resolved fmods + runtimes"
	@echo "  make publish        canonical publish of clustor's artefacts"
	@echo "  make publish-local  content-hashed local-only publish"

setup:
	cargo install --locked --path ../fluxor/tools

build:      ; $(CARGO) build --workspace --all-targets
# Cluster e2e tests (`tests/cluster.rs`, `chaos.rs`, `partition.rs`)
# each spin up 1–3 `fluxor-linux` child processes. Default cargo
# parallelism saturates a 4-core Pi-class host and Raft commit
# budgets miss their deadlines. `--test-threads=4` keeps the
# concurrent-cluster count bounded; individual unit-test binaries
# (fast, no children) still run with full intra-binary parallelism.
TEST_THREADS ?= 4
test:       ; $(CARGO) test --workspace -- --test-threads=$(TEST_THREADS)
# Host L0/L1 micro-benches (RFC §7.1). `--quick` keeps it CI-fast;
# drop the flag for full criterion sampling when chasing a regression.
bench:      ; $(CARGO) bench --benches -- --quick
fmt:        ; $(CARGO) fmt --all
fmt-check:  ; $(CARGO) fmt --all -- --check
clippy:     ; $(CARGO) clippy --workspace --all-targets --all-features -- -D warnings
lint:       fmt-check clippy

modules:
	$(FLUXOR) modules build --target $(TARGET) --out target

modules-all:
	$(FLUXOR) modules build --all --out target

modules-clean:
	$(FLUXOR) modules clean --out target

CONFIG  ?= configs/single.yaml
NODE_ID ?= 0
up: modules
	$(FLUXOR) run --template $(CONFIG) --node-id $(NODE_ID)

REPLICAS ?= 3
up-cluster: modules
	$(FLUXOR) up $(CONFIG) --replicas $(REPLICAS)

ci:
	$(FLUXOR) ci

# End-to-end cluster/chaos/partition/wal tests. Each spins up real
# `fluxor-linux` child processes, so they need (a) the clustor modules built
# at the harness's standard resolution path (`target/fluxor/<silicon>/modules`,
# distinct from `make modules`' legacy `target/` path) and (b) a `fluxor-linux`
# runtime materialised (`make sync`, or a live workspace checkout).
#
# CLUSTOR_REQUIRE_E2E=1 turns the harness's soft-skip into a HARD failure, so
# CI cannot report green by silently skipping the resilience suite — a
# permanently green-by-skip chaos suite removes the regression signal.
#
# Each test binary is a SEPARATE, sequential `cargo test` invocation rather
# than one combined command. cargo runs distinct test binaries in parallel, so
# a combined run would spin up cluster + chaos + partition clusters at once —
# 16+ `fluxor-linux` nodes on a 4-core host. That oversubscription starves the
# convergence-sensitive tests (e.g. follower catch-up) past their budgets. Run
# them one binary at a time, at a modest intra-binary thread count, so no run
# exceeds a few concurrent 3-node clusters.
E2E_THREADS ?= 2
e2e: modules-std
	CLUSTOR_REQUIRE_E2E=1 $(CARGO) test --test wal_replay --test wal_group_fsync -- --test-threads=$(E2E_THREADS)
	CLUSTOR_REQUIRE_E2E=1 $(CARGO) test --test partition -- --test-threads=$(E2E_THREADS)
	CLUSTOR_REQUIRE_E2E=1 $(CARGO) test --test chaos -- --test-threads=$(E2E_THREADS)
	CLUSTOR_REQUIRE_E2E=1 $(CARGO) test --test cluster -- --test-threads=$(E2E_THREADS)

# Build modules to the e2e harness's standard resolution path. (`make modules`
# targets the legacy `target/` path used by the registry/`fluxor run` flow.)
modules-std:
	$(FLUXOR) modules build --target $(TARGET) --out target/fluxor

verify: ci e2e

clean:
	$(CARGO) clean
	$(FLUXOR) modules clean --out target

# ── Registry consumption (RFC §11 / standards/dependencies.md) ─────────
#
# `make update` regenerates fluxor.lock from clustor's [dependencies].
# `make sync` materialises every lockfile-resolved fmod + runtime +
# source crate into clustor's target/ tree. Run sync after every
# upstream `fluxor publish`.

update:
	$(FLUXOR) update

sync:
	$(FLUXOR) sync
sync-dry:
	$(FLUXOR) sync --dry-run

publish:
	$(FLUXOR) publish
publish-local:
	$(FLUXOR) publish --local
