#!/usr/bin/env bash
# CI phase 3.5 (project-e2e) entry point. Delegates to `make e2e` —
# the single home of the sequential, thread-bounded cluster/chaos/
# partition/wal composition (standards/make.md §4) — so the gate and
# the human-run suite can never drift. `fluxor ci` runs this from the
# project root after the strict module build.
set -euo pipefail

# Shadow-checkout guard (standards/test-tracking.md §7): tests/ and
# benches/ are shadow-tracked, so a runner holding only the primary
# repo has zero files there and `cargo test --tests` would pass
# vacuously. Hard-fail instead of reporting a green gate that ran
# nothing.
cd "$(dirname "$0")/.."
if [ -z "$(ls -A tests 2>/dev/null)" ] || [ -z "$(ls -A benches 2>/dev/null)" ]; then
  echo "ci-e2e: tests/ or benches/ is empty — the shadow-tracked trees" >&2
  echo "are not materialised on this machine (standards/test-tracking.md §7)." >&2
  exit 1
fi

# Palette lint: shipped artefacts must describe the module palette as
# it is. Cheap and fail-fast, so it runs before the expensive suites.
"$(dirname "$0")/palette-lint.sh" "$(dirname "$0")/.."
make e2e
