#!/usr/bin/env bash
# CLI-applet E2E: the clustor operator CLI as a PIC fmod behind
# `fluxor exec clustor` (rfc_cli_execution.md). wal-frame/wal-scan run the
# SAME Crc32c core and frame validation the durability module runs at replay,
# so a frame produced here must scan clean, and a corrupted or torn image
# must fail closed with a non-zero exit.
set -u
cd "$(dirname "$0")/.."
FLX=${FLUXOR_BIN:-fluxor}

pass=0
fail=0
ok() { echo "  PASS  $1"; pass=$((pass + 1)); }
no() { echo "  FAIL  $1: $2"; fail=$((fail + 1)); }
finish() { echo "== $pass passed, $fail failed =="; [ "$fail" -eq 0 ]; }
want() { case "$1" in *"$2"*) return 0 ;; *) return 1 ;; esac }

timeout 900 "$FLX" modules build --target bcm2712 >/dev/null 2>&1 \
  || { no cli "fluxor modules build failed"; finish; exit; }
timeout 300 "$FLX" install packaging/cli/workload.toml >/dev/null 2>&1 \
  || { no cli "applet install failed"; finish; exit; }

got=$(timeout 30 "$FLX" exec clustor -- help 2>/dev/null)
if want "$got" "wal-scan <segment_hex>"; then
  ok "cli help lists the command surface"
else
  no "cli help" "got='$got'"
fi

# CRC32C("123456789") — the canonical Castagnoli check vector. Proves the
# applet runs the same core the WAL uses for frame integrity.
got=$(timeout 30 "$FLX" exec clustor -- crc 313233343536373839 2>/dev/null)
if want "$got" "e3069283"; then
  ok "cli crc matches the canonical crc32c vector"
else
  no "cli crc" "got='$got'"
fi

# Frame a 16-byte payload (term=3, index=7 LE — the WAL entry prologue) and
# require the scan to recover exactly that entry: frame → scan round-trip
# through the replay-identical validation path.
PAYLOAD=03000000000000000700000000000000
FRAME=$(timeout 30 "$FLX" exec clustor -- wal-frame $PAYLOAD 2>/dev/null)
got=$(timeout 30 "$FLX" exec clustor -- wal-scan "$FRAME" 2>/dev/null)
if want "$got" "term=3 index=7 len=16" && want "$got" "ok: 1 entry(s), 24 byte(s) durable"; then
  ok "cli wal-frame round-trips through the replay-exact wal-scan"
else
  no "cli wal-frame/scan" "frame='$FRAME' got='$got'"
fi

# Corrupt one payload byte (first byte after the 8-byte header): the stored
# CRC no longer matches, so the scan must stop and exit non-zero.
CORRUPT="${FRAME:0:16}ff${FRAME:18}"
if timeout 30 "$FLX" exec clustor -- wal-scan "$CORRUPT" >/dev/null 2>&1; then
  no "cli wal-scan fail-closed" "corrupt payload exited 0"
else
  ok "cli wal-scan fails closed on a corrupt payload (non-zero exit)"
fi

# A header claiming an impossible length is a torn header — replay stops
# there, and so must the scan.
if timeout 30 "$FLX" exec clustor -- wal-scan ffffffff00000000 >/dev/null 2>&1; then
  no "cli wal-scan torn-header" "impossible length exited 0"
else
  ok "cli wal-scan fails closed on a torn header (non-zero exit)"
fi

if timeout 30 "$FLX" exec clustor -- frobnicate >/dev/null 2>&1; then
  no "cli unknown-command" "unknown command exited 0"
else
  ok "cli rejects an unknown command (non-zero exit)"
fi

finish
