#!/bin/sh
set -eu

AUDIT_DIR=".context/audit"
mkdir -p "$AUDIT_DIR"

run_and_capture() {
    output_file="$1"
    shift
    echo "Running: $*"
    "$@" > "$AUDIT_DIR/$output_file"
}

run_and_capture layout.txt tree -a -I target
run_and_capture allow_attrs.txt rg -n "#\\[allow\\(" -S .
run_and_capture async_runtimes.txt rg -n "tokio::|async_std::|smol::|ntex::" -S src tests examples
run_and_capture cargo-metadata.json cargo metadata --format-version 1
run_and_capture cargo-tree-features.txt cargo tree -e features
