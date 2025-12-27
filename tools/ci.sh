#!/bin/sh
set -eu

sh tools/forbid_src_tests.sh
sh tools/check_async_runtime.sh
cargo fmt --all -- --check
RUSTFLAGS="-Dwarnings" cargo test --all-targets
cargo clippy --all-targets -- -D warnings
