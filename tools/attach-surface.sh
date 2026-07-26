#!/usr/bin/env bash
# attach-surface.sh — compute the substrate palette's published attach surface.
#
# Parses every wiring edge (`from: X.a` / `to: Y.b`) in the graph configs of
# clustor and of the downstream projects that instantiate the palette
# (quantum, lattice), and classifies each substrate port:
#
#   published — at least one edge connects it to a non-substrate module
#               (a downstream app module or a platform anchor). These ports
#               are the palette's API and must exist on the owning module.
#   plumbing  — every edge referencing it runs substrate-to-substrate.
#               These are wiring interior to the palette and are eligible
#               for internalization.
#
# Usage: tools/attach-surface.sh [output-file]
#   TSV: port <TAB> published|plumbing <TAB> referencing repos.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NANO="$(cd "$ROOT/.." && pwd)"
OUT="${1:-/dev/stdout}"

# Substrate module types (palette modules and their components).
SUBSTRATE='peer_router consensus durability gateway admission control_plane operations raft_engine replicator commit_tracker apply_pipeline wal durability_ledger snapshot_engine client_codec client_surface throttle_gate flow_controller read_gate cp_bridge cp_proof_cache placement_router partition_router key_manager telemetry_agg rbac admin_handler http_adapter http_ingress session_directory'

edges() { # edges <label> <dir>... -> "from_port to_port label" per edge
    local label="$1"; shift
    local d f
    for d in "$@"; do
        [ -d "$d" ] || continue
        while IFS= read -r f; do
            awk -v label="$label" '
                /^[[:space:]]*-?[[:space:]]*from:[[:space:]]/ {
                    sub(/.*from:[[:space:]]*/, ""); gsub(/["\047[:space:]]/, "");
                    from = $0; next
                }
                /^[[:space:]]*to:[[:space:]]/ && from != "" {
                    sub(/.*to:[[:space:]]*/, ""); gsub(/["\047[:space:]]/, "");
                    print from, $0, label; from = ""
                }
            ' "$f"
        done < <(find "$d" -name '*.yaml' -o -name '*.yml')
    done
}

{
    edges clustor "$ROOT/configs" "$ROOT/tests"
    edges quantum "$NANO/quantum/configs"
    edges lattice "$NANO/lattice/configs"
} | awk -v substrate="$SUBSTRATE" '
    BEGIN { n = split(substrate, s, " "); for (i = 1; i <= n; i++) sub_[s[i]] = 1 }
    # Strip a _p<N> partition suffix so suffixed instances
    # (consensus_p0, durability_p1) resolve to their module type.
    function mod(p)  { split(p, a, "."); m = a[1]; sub(/_p[0-9]+$/, "", m); return m }
    function note(p, external, repo) {
        if (!(mod(p) in sub_)) return
        if (external) pub[p] = 1
        seen[p] = 1
        if (!(index(repos[p], repo))) repos[p] = repos[p] == "" ? repo : repos[p] "," repo
    }
    {
        ext = !((mod($1) in sub_) && (mod($2) in sub_))
        note($1, ext, $3); note($2, ext, $3)
    }
    END {
        for (p in seen)
            print p "\t" (p in pub ? "published" : "plumbing") "\t" repos[p]
    }
' | sort > "$OUT"
