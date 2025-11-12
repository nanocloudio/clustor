.PHONY: help fmt fmt-check clippy lint build build-release test bench verify clean

CARGO ?= cargo
CLIPPY_ARGS ?= -D warnings

help:
	@echo "clustor make targets"
	@echo "  make build          # debug build for all targets"
	@echo "  make build-release  # optimized build"
	@echo "  make test           # run full test suite"
	@echo "  make fmt/fmt-check  # rustfmt (check mode available)"
	@echo "  make clippy|lint    # clippy with warnings-as-errors"
	@echo "  make bench          # run cargo bench (configure BENCH_TARGET)"
	@echo "  make verify         # run fmt-check + clippy + tests"
	@echo "  make clean          # remove target artifacts"

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

clippy:
	$(CARGO) clippy --all-targets --all-features -- $(CLIPPY_ARGS)

lint: fmt-check clippy

build:
	$(CARGO) build --all-targets

build-release:
	$(CARGO) build --all-targets --release

test:
	$(CARGO) test --all --all-features

bench:
	$(CARGO) bench --all

verify: fmt-check clippy test

clean:
	$(CARGO) clean
