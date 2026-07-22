#!/usr/bin/env bash
# CI phase 3.5 (project-e2e) entry point. Delegates to `make e2e` —
# the single home of the sequential, thread-bounded cluster/chaos/
# partition/wal composition (standards/make.md §4) — so the gate and
# the human-run suite can never drift. `fluxor ci` runs this from the
# project root after the strict module build.
set -euo pipefail
make e2e
