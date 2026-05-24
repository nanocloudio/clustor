# clustor Makefile — fluxor-based. See ~/Development/nanocloudio/standards/make.md.

.PHONY: help build test fmt fmt-check clippy lint ci verify \
        modules modules-all modules-clean up up-cluster clean setup \
        link-fluxor unlink-fluxor

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
	@echo "  make setup          init submodules + install fluxor CLI onto PATH"
	@echo "  make link-fluxor    swap deps/fluxor submodule for a symlink to FLUXOR_DEV_PATH (dev override)"
	@echo "  make unlink-fluxor  restore deps/fluxor from the submodule pin"

setup:
	git submodule update --init --recursive
	cargo install --locked --path deps/fluxor/tools

# Dev override: replace the submodule checkout at deps/fluxor with a
# symlink to a sibling working tree, so local fluxor edits flow into
# clustor builds without a commit-and-bump round trip. The submodule
# pin in the index doesn't move — `git status` shows the divergence
# until `make unlink-fluxor` restores the submodule contents.
#
# `FLUXOR_DEV_PATH` is interpreted relative to the clustor repo root
# (default `../fluxor`, i.e. a sibling checkout). The link itself is
# stored relative to `deps/`, so the resolved target survives moving
# the parent workspace, as long as the sibling layout is preserved.
FLUXOR_DEV_PATH ?= ../fluxor
link-fluxor:
	@target_abs=$$(realpath -m $(FLUXOR_DEV_PATH)); \
	if [ ! -d "$$target_abs" ]; then \
		echo "FLUXOR_DEV_PATH=$$target_abs doesn't exist. Clone fluxor as a sibling or pass FLUXOR_DEV_PATH=<absolute-or-clustor-relative-path>."; \
		exit 1; \
	fi; \
	if [ -L deps/fluxor ]; then \
		echo "deps/fluxor is already a symlink ($$(readlink deps/fluxor) -> $$(readlink -f deps/fluxor)). Nothing to do."; \
		exit 0; \
	fi; \
	rm -rf deps/fluxor; \
	link_target=$$(case $(FLUXOR_DEV_PATH) in /*) echo $(FLUXOR_DEV_PATH);; *) echo ../$(FLUXOR_DEV_PATH);; esac); \
	ln -s "$$link_target" deps/fluxor; \
	echo "deps/fluxor -> $$link_target  (resolves to $$target_abs; submodule pin unchanged in index)"

unlink-fluxor:
	@if [ ! -L deps/fluxor ]; then \
		echo "deps/fluxor is not a symlink; nothing to restore."; \
		exit 0; \
	fi; \
	rm deps/fluxor; \
	git submodule update --init deps/fluxor
	@echo "deps/fluxor restored from submodule pin ($$(git -C deps/fluxor rev-parse --short HEAD))"

build:      ; $(CARGO) build --all-targets
test:       ; $(CARGO) test --workspace
fmt:        ; $(CARGO) fmt --all
fmt-check:  ; $(CARGO) fmt --all -- --check
clippy:     ; $(CARGO) clippy --all-targets --all-features -- -D warnings
lint:       fmt-check clippy

modules:
	$(FLUXOR) modules build --target $(TARGET) --out target/fluxor

modules-all:
	$(FLUXOR) modules build --all --out target/fluxor

modules-clean:
	$(FLUXOR) modules clean --out target/fluxor

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
	$(FLUXOR) modules clean --out target/fluxor
