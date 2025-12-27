#!/bin/sh
set -eu

SEARCH_DIR="src"
FAIL=0
TMP_OUTPUT="$(mktemp)"
TMP_ERR="$(mktemp)"
trap 'rm -f "$TMP_OUTPUT" "$TMP_ERR"' EXIT

check_pattern() {
    pattern="$1"
    description="$2"
    if rg -n --color=never "$pattern" "$SEARCH_DIR" >"$TMP_OUTPUT" 2>"$TMP_ERR"; then
        printf 'Found forbidden %s in %s matching pattern "%s":\n' "$description" "$SEARCH_DIR" "$pattern" >&2
        cat "$TMP_OUTPUT" >&2
        FAIL=1
    else
        status=$?
        if [ "$status" -ne 1 ]; then
            cat "$TMP_ERR" >&2
            exit "$status"
        fi
    fi
}

check_pattern '#\[cfg\(test\)\]' 'cfg test annotation'
check_pattern 'mod tests' 'tests module'
check_pattern '#\[test\]' 'unit test attribute'

exit "$FAIL"
