#!/bin/sh
set -eu

if rg -n "async_std::|smol::|ntex::" -S src tests examples >/dev/null; then
    echo "error: detected disallowed async runtime symbols (only tokio is permitted)" >&2
    exit 1
fi
