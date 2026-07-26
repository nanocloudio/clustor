#!/usr/bin/env bash
# palette-lint.sh — enforce that shipped artefacts describe the module
# palette as it is.
#
# Two classes of violation:
#
#   1. A retired module name used as a graph module type — a name that
#      no longer exists in `modules/app/`. These read as instructions to
#      wire something that cannot be wired.
#   2. Change narration — "formerly", "migration", "phase N" and friends
#      applied to the module structure. Shipped docs and code describe
#      what IS; design history lives in `.context/` and in git.
#
# Scope is deliberately the SHIPPED surface: source, configs, tests,
# docs, README. Excluded: `.context/` (private design record),
# `tests/hardware/baselines/*.json` (measurement records — data, not
# prose), `target/`, `deps/`, `.git/`.
#
# Usage: tools/palette-lint.sh          # lint this repo
#        tools/palette-lint.sh <dir>…   # lint other repos (quantum, lattice)
# Exit 1 on any violation, printing file:line for each.

set -uo pipefail

ROOTS=("${@:-.}")

# Names that were graph module types and no longer are. A bare word
# here is NOT enough to flag — several are legitimate component or
# domain words (wal, rbac, raft). We flag the compound forms that can
# only mean "the old module".
RETIRED='raft_engine|commit_tracker|apply_pipeline|client_surface|client_codec|throttle_gate|flow_controller|cp_proof_cache|cp_bridge|placement_router|durability_ledger|snapshot_engine|key_manager|telemetry_agg|admin_handler|http_adapter|http_ingress|net_service_mux'

# Names that are BOTH a retired module and a live component name
# (`replicator` in `consensus`, `read_gate` in `admission`). A bare
# mention is legitimate — the component really is called that. Only
# graph-level usage is a violation: declared as a type, or used as the
# owner of a wiring endpoint.
RETIRED_QUALIFIED='replicator\.(entries|ack|snapshot_rx|wal_reply|voter_set|net_out|match_indices|lag_signal|snapshot_import|metrics|wal_request|snapshot_request|cross_durability_ack)|read_gate\.(cache|permits)|type:\s*(replicator|read_gate)'

# Change narration about the module structure.
#
# Deliberately does NOT flag bare "migration": session-state migration
# between anchors and wire/ABI format migration are legitimate domain
# vocabulary. Only structural-change narration is caught, plus the
# compounds where "migration" can only mean this restructuring.
NARRATION='\b(formerly|previously known as|used to be|renamed from|merged from|consolidat(ed|ion)|pre-consolidation|post-consolidation)\b|\b(module|palette|graph|RFC ....)[ -]migration\b'

# `data/` and `*.log` hold captured runtime output — measurement
# records, not prose. Same reasoning as `baselines/`: a log that
# recorded what a past graph did is evidence, and rewriting it would
# falsify the record.
EXCLUDES=(
  --exclude-dir=.git --exclude-dir=target --exclude-dir=deps
  --exclude-dir=.context --exclude-dir=node_modules
  --exclude-dir=baselines --exclude-dir=data
  --exclude=*.log --exclude=*.json
)

fail=0

scan() { # scan <label> <pattern>
    local label="$1" pattern="$2" hits
    hits=$(grep -rnIE "${EXCLUDES[@]}" "$pattern" "${ROOTS[@]}" 2>/dev/null \
           | grep -vE '^[^:]*/palette-lint\.sh:' \
           | grep -vE '^[^:]*/attach-surface\.sh:')
    if [ -n "$hits" ]; then
        echo "── $label ─────────────────────────────────────────"
        echo "$hits"
        echo
        fail=1
    fi
}

scan "retired module names used as graph types" "$RETIRED"
scan "retired port owners" "$RETIRED_QUALIFIED"
scan "change narration in shipped text" "$NARRATION"

if [ "$fail" -ne 0 ]; then
    cat <<'MSG'
palette-lint FAILED.

Shipped artefacts must describe the module palette as it is. Name the
composite module for graph-level facts (types, ports, wiring) and its
component for internal behaviour. Design history belongs in .context/
and in git history, not in code, configs, tests or docs.
MSG
    exit 1
fi

echo "palette-lint: clean"
