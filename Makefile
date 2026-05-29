# clustor Makefile — fluxor-based. See ~/Development/nanocloudio/standards/make.md.

.PHONY: help build test fmt fmt-check clippy lint ci verify \
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
	@echo "  make fmt|fmt-check  rustfmt"
	@echo "  make clippy|lint    clippy + fmt-check"
	@echo "  make modules        build PIC modules for TARGET=$(TARGET)"
	@echo "  make modules-all    build modules for every target in fluxor.toml"
	@echo "  make up             render+run a single replica (CONFIG=, NODE_ID=)"
	@echo "  make up-cluster     spawn REPLICAS replicas (CONFIG=, REPLICAS=)"
	@echo "  make ci             full CI gate (fluxor ci)"
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

verify: ci

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
