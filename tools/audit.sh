#!/bin/sh
set -eu

echo "+ cargo tree"
cargo tree

echo "+ cargo tree -e features"
cargo tree -e features

if command -v cargo-audit >/dev/null 2>&1; then
    echo "+ cargo audit"
    cargo audit
else
    echo "cargo-audit not installed; skipping vulnerability scan" >&2
    echo "install with: cargo install cargo-audit" >&2
fi
