#!/usr/bin/env bash
# tests/e2e.sh — end-to-end tests against an installed credman daemon.
#
# Requires:
#   - credman.service running (systemctl status credman)
#   - invoking user in the 'credman' group (newgrp credman)
#   - jq in PATH
#
# Optional:
#   - sudo (enables the error-sanitization test that corrupts a cred file)
#   - journalctl readable by this user (enables the audit-log shape test)
#
# Usage: ./tests/e2e.sh
# Exits 0 on full pass, 1 on any failure. Always self-cleans creds it created.

set -euo pipefail

# ── Output helpers ────────────────────────────────────────────────────────────
red()   { printf '\033[0;31m%s\033[0m' "$*"; }
green() { printf '\033[0;32m%s\033[0m' "$*"; }
yellow(){ printf '\033[1;33m%s\033[0m' "$*"; }
gray()  { printf '\033[2m%s\033[0m'    "$*"; }

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
FAILED_NAMES=()

pass() { printf '  %s  %s\n' "$(green '✓')"  "$*"; PASS_COUNT=$((PASS_COUNT+1)); }
fail() { printf '  %s  %s\n' "$(red   '✗')"  "$*"; FAIL_COUNT=$((FAIL_COUNT+1)); FAILED_NAMES+=("$*"); }
skip() { printf '  %s  %s\n' "$(yellow '–')" "$(gray "SKIP: $*")"; SKIP_COUNT=$((SKIP_COUNT+1)); }
step() { printf '\n%s\n' "$(yellow "── $* ──")"; }

# ── Cleanup ───────────────────────────────────────────────────────────────────
# Every cred created by this script uses this prefix; cleanup walks
# `credman list --json` and deletes anything starting with it.
PREFIX="E2E_$$_$(date +%s)_"

cleanup() {
    local names
    names=$(credman --json list 2>/dev/null \
            | jq -r --arg p "$PREFIX" '.credentials[]?.name | select(startswith($p))' \
            2>/dev/null || true)
    for n in $names; do
        credman --json delete "$n" >/dev/null 2>&1 || true
    done
}
trap cleanup EXIT

# ── Preflight ─────────────────────────────────────────────────────────────────
command -v credman >/dev/null || { echo "credman not in PATH"; exit 1; }
command -v jq      >/dev/null || { echo "jq not in PATH — install jq first"; exit 1; }

# Socket reachable? `credman list` fails with a connect error if not.
if ! credman --json list >/dev/null 2>&1; then
    echo "Cannot reach the credman daemon — is credman.service running,"
    echo "and are you in the 'credman' group? (try: newgrp credman)"
    exit 1
fi

# ── 1. Happy path ─────────────────────────────────────────────────────────────
step "1. happy path (set --generate, get, list, check, delete)"

NAME="${PREFIX}HAPPY"
credman --json set "$NAME" --generate >/dev/null \
    && pass "set $NAME --generate" \
    || fail "set $NAME --generate"

val=$(credman get "$NAME" --quiet) || val=""
if [ -n "$val" ]; then pass "get $NAME --quiet returned a non-empty value"
else fail "get $NAME --quiet returned empty"; fi

if credman --json list | jq -e --arg n "$NAME" '.credentials[]?.name | select(. == $n)' >/dev/null; then
    pass "list contains $NAME"
else
    fail "list does not contain $NAME"
fi

if credman --json check | jq -e --arg n "$NAME" '.results[$n] == "ok"' >/dev/null; then
    pass "check reports $NAME ok"
else
    fail "check did not report $NAME ok"
fi

credman --json delete "$NAME" >/dev/null \
    && pass "delete $NAME" \
    || fail "delete $NAME"

if credman --json get "$NAME" | jq -e '.ok == false' >/dev/null; then
    pass "get after delete reports not found"
else
    fail "get after delete unexpectedly succeeded"
fi

# ── 2. Value round-trip ───────────────────────────────────────────────────────
step "2. value round-trip preserves exact bytes"

NAME="${PREFIX}ROUND"
SECRET="some string with spaces and !@# chars"

credman --json set "$NAME" --value "$SECRET" >/dev/null \
    && pass "set $NAME --value <literal>" \
    || fail "set $NAME --value <literal>"

got=$(credman get "$NAME" --quiet) || got=""
if [ "$got" = "$SECRET" ]; then
    pass "value exact match after round-trip"
else
    fail "value changed in round-trip (got $(printf '%q' "$got"))"
fi

# ── 3. Generator kinds — format properties ────────────────────────────────────
step "3. every generator kind produces the documented format"

check_kind() {
    local kind=$1 expected_len=$2 regex=$3
    local name="${PREFIX}GEN_${kind^^}"
    credman --json set "$name" --generate --gen-kind "$kind" >/dev/null \
        || { fail "set --gen-kind $kind"; return; }
    local v
    v=$(credman get "$name" --quiet) || { fail "get after --gen-kind $kind"; return; }

    local len=${#v}
    if [ "$len" != "$expected_len" ]; then
        fail "$kind: length $len != $expected_len"
        return
    fi
    if [[ ! "$v" =~ $regex ]]; then
        fail "$kind: value fails format regex"
        return
    fi
    pass "$kind: length $expected_len, format ok"
}

check_kind hex    64  '^[0-9a-f]+$'
check_kind base62 48  '^[A-Za-z0-9]+$'
check_kind uuid   36  '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'

# Pass is tested via complexity, not a single regex
NAME="${PREFIX}GEN_PASS"
credman --json set "$NAME" --generate --gen-kind pass >/dev/null
passval=$(credman get "$NAME" --quiet)
if [ "${#passval}" = 32 ] \
    && [[ "$passval" =~ [A-Z] ]] \
    && [[ "$passval" =~ [a-z] ]] \
    && [[ "$passval" =~ [0-9] ]] \
    && [[ "$passval" =~ [\!@#\$%^\&*_=+\-] ]]; then
    pass "pass: length 32 with upper/lower/digit/symbol"
else
    fail "pass: complexity requirements not met"
fi

# ── 4. Daemon-side name validation ────────────────────────────────────────────
# Proves validate_name runs in daemon.rs — not just the client's uppercase filter.
step "4. daemon rejects invalid names"

# The client uppercases the positional arg to FOO/BAR, which contains '/' —
# validate_name in the daemon must reject it. We also assert the error names
# the offending character, proving validate_name's own error text is reaching
# the client untruncated (not a generic "bad request").
out=$(credman --json set 'foo/bar' --value x 2>&1 || true)
if echo "$out" | jq -e ".ok == false and (.error | test(\"invalid character '/'\"))" >/dev/null; then
    pass "set with '/' rejected, error names the character"
else
    fail "set with '/' not rejected cleanly: $out"
fi

out=$(credman --json set 'foo.bar' --value x 2>&1 || true)
if echo "$out" | jq -e ".ok == false and (.error | test(\"invalid character '\\\\.'\"))" >/dev/null; then
    pass "set with '.' rejected, error names the character"
else
    fail "set with '.' not rejected cleanly: $out"
fi

# ── 5. Overwrite via --value ──────────────────────────────────────────────────
# The interactive "Overwrite? [y/N]" prompt is intentionally NOT tested — it
# reads stdin twice (the answer, then read_masked for the value) which makes
# pipe-driven tests fragile. --value skips both prompts and just overwrites.
step "5. --value overwrites an existing cred"

NAME="${PREFIX}OVER"
credman --json set "$NAME" --value "first"  >/dev/null
credman --json set "$NAME" --value "second" >/dev/null
got=$(credman get "$NAME" --quiet)
if [ "$got" = "second" ]; then
    pass "second set --value replaced first"
else
    fail "overwrite failed — got $(printf '%q' "$got")"
fi

# ── 6. JSON mode shape ────────────────────────────────────────────────────────
step "6. --json output is valid JSON in both success and failure"

if credman --json list | jq -e '.ok == true and (.credentials | type == "array")' >/dev/null; then
    pass "--json list: ok=true, credentials is array"
else
    fail "--json list shape wrong"
fi

MISSING="${PREFIX}DEFINITELY_NOT_HERE"
if credman --json get "$MISSING" \
    | jq -e '.ok == false and (.error | type == "string" and length > 0)' >/dev/null; then
    pass "--json get on missing cred: ok=false, error is non-empty string"
else
    fail "--json get on missing cred shape wrong"
fi

# ── 7. Error sanitization (requires root or sudo) ─────────────────────────────
# Corrupt a cred file as root so decrypt fails, then assert the client-visible
# error does NOT leak internal tool names. This is the project's strongest
# stated guarantee (crypto::sanitize_error).
step "7. decrypt errors are sanitized (strip internal tool names)"

# We look for any of: the internal tool name, its install path, or flag names.
FORBIDDEN_RE='systemd-creds|/usr/bin/[a-z-]*-creds|--with-key'

can_root=0
if [ "$(id -u)" = 0 ]; then can_root=1
elif sudo -n true 2>/dev/null; then can_root=1
fi

if [ "$can_root" = 1 ]; then
    NAME="${PREFIX}CORRUPT"
    credman --json set "$NAME" --value "ok" >/dev/null
    # The on-disk name mirrors what store::to_cred_name builds.
    UID_NUM=$(id -u)
    DISK_NAME="credman-${UID_NUM}-$(echo "$NAME" | tr '[:upper:]_' '[:lower:]-')"
    DISK_PATH="/etc/credstore.encrypted/${DISK_NAME}"

    run_root() { if [ "$(id -u)" = 0 ]; then "$@"; else sudo -n "$@"; fi }
    run_root sh -c "echo 'not-a-real-encrypted-cred' > '$DISK_PATH'"

    out=$(credman --json get "$NAME" 2>&1 || true)
    err_msg=$(echo "$out" | jq -r '.error // ""')

    if [ -z "$err_msg" ]; then
        fail "corrupted get did not return an error message"
    elif echo "$err_msg" | grep -Eq "$FORBIDDEN_RE"; then
        fail "error leaks internal tool name: $err_msg"
    else
        pass "error is sanitized (no forbidden substrings)"
    fi
else
    skip "no root/sudo — cannot corrupt a cred file to force a decrypt failure"
fi

# ── 8. Audit log shape (requires journal read access) ─────────────────────────
step "8. audit log records op=get without leaking the value"

if ! journalctl -t credman-daemon -n 1 >/dev/null 2>&1; then
    skip "journalctl not readable by this user (join group 'systemd-journal' or 'adm')"
else
    NAME="${PREFIX}AUDIT"
    SECRET_VAL="audit-sentinel-$(date +%N)"
    credman --json set "$NAME" --value "$SECRET_VAL" >/dev/null
    credman --json get "$NAME" >/dev/null
    sleep 0.3  # journal write is async

    # Grab the most recent get-ok entry matching our name
    entry=$(journalctl -t credman-daemon \
            CREDMAN_OP=get CREDMAN_NAME="$NAME" CREDMAN_RESULT=ok \
            --since='10 seconds ago' -o json -n 1 2>/dev/null || echo "")
    if [ -z "$entry" ]; then
        fail "no audit entry found for op=get name=$NAME"
    else
        uid_logged=$(echo "$entry" | jq -r '.CREDMAN_UID // ""')
        if [ "$uid_logged" != "$(id -u)" ]; then
            fail "audit CREDMAN_UID=$uid_logged, expected $(id -u)"
        elif echo "$entry" | grep -q "$SECRET_VAL"; then
            fail "audit entry contains the secret value!"
        else
            pass "audit entry present, UID matches, no secret value leaked"
        fi
    fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
printf '\n%s  %d passed, %d failed, %d skipped\n' \
    "$(yellow '──')" "$PASS_COUNT" "$FAIL_COUNT" "$SKIP_COUNT"

if [ "$FAIL_COUNT" -gt 0 ]; then
    printf '\n%s\n' "$(red 'Failures:')"
    for n in "${FAILED_NAMES[@]}"; do printf '  - %s\n' "$n"; done
    exit 1
fi
echo
