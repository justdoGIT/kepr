#!/usr/bin/env bash
# tests/e2e.sh — end-to-end tests against an installed kepr daemon.
#
# Requires:
#   - kepr.service running (systemctl status kepr)
#   - invoking user in the 'kepr' group (newgrp kepr)
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
# `kepr list --json` and deletes anything starting with it.
PREFIX="E2E_$$_$(date +%s)_"

cleanup() {
    local names
    names=$(kepr --json list 2>/dev/null \
            | jq -r --arg p "$PREFIX" '.credentials[]?.name | select(startswith($p))' \
            2>/dev/null || true)
    for n in $names; do
        kepr --json delete "$n" >/dev/null 2>&1 || true
    done
}
trap cleanup EXIT

# ── Preflight ─────────────────────────────────────────────────────────────────
command -v kepr >/dev/null || { echo "kepr not in PATH"; exit 1; }
command -v jq      >/dev/null || { echo "jq not in PATH — install jq first"; exit 1; }

# Socket reachable? `kepr list` fails with a connect error if not.
if ! kepr --json list >/dev/null 2>&1; then
    echo "Cannot reach the kepr daemon — is kepr.service running,"
    echo "and are you in the 'kepr' group? (try: newgrp kepr)"
    exit 1
fi

# ── 1. Happy path ─────────────────────────────────────────────────────────────
step "1. happy path (set --generate, get, list, check, delete)"

NAME="${PREFIX}HAPPY"
if kepr --json set "$NAME" --generate >/dev/null; then
    pass "set $NAME --generate"
else
    fail "set $NAME --generate"
fi

val=$(kepr get "$NAME" --quiet) || val=""
if [ -n "$val" ]; then pass "get $NAME --quiet returned a non-empty value"
else fail "get $NAME --quiet returned empty"; fi

if kepr --json list | jq -e --arg n "$NAME" '.credentials[]?.name | select(. == $n)' >/dev/null; then
    pass "list contains $NAME"
else
    fail "list does not contain $NAME"
fi

if kepr --json check | jq -e --arg n "$NAME" '.results[$n] == "ok"' >/dev/null; then
    pass "check reports $NAME ok"
else
    fail "check did not report $NAME ok"
fi

if kepr --json delete "$NAME" >/dev/null; then
    pass "delete $NAME"
else
    fail "delete $NAME"
fi

# `kepr --json get` on a missing cred exits 1; `set -o pipefail` would
# then make the whole `| jq` pipeline exit 1 even when jq matched. Capture
# first, then pipe — same pattern as tests 4 and 7.
out=$(kepr --json get "$NAME" || true)
if echo "$out" | jq -e '.kind == "err"' >/dev/null; then
    pass "get after delete reports not found"
else
    fail "get after delete unexpectedly succeeded"
fi

# ── 2. Value round-trip ───────────────────────────────────────────────────────
step "2. value round-trip preserves exact bytes"

NAME="${PREFIX}ROUND"
SECRET="some string with spaces and !@# chars"

if kepr --json set "$NAME" --value "$SECRET" >/dev/null; then
    pass "set $NAME --value <literal>"
else
    fail "set $NAME --value <literal>"
fi

got=$(kepr get "$NAME" --quiet) || got=""
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
    kepr --json set "$name" --generate --gen-kind "$kind" >/dev/null \
        || { fail "set --gen-kind $kind"; return; }
    local v
    v=$(kepr get "$name" --quiet) || { fail "get after --gen-kind $kind"; return; }

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
kepr --json set "$NAME" --generate --gen-kind pass >/dev/null
passval=$(kepr get "$NAME" --quiet)
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
out=$(kepr --json set 'foo/bar' --value x 2>&1 || true)
if echo "$out" | jq -e ".kind == \"err\" and (.error | test(\"invalid character '/'\"))" >/dev/null; then
    pass "set with '/' rejected, error names the character"
else
    fail "set with '/' not rejected cleanly: $out"
fi

out=$(kepr --json set 'foo.bar' --value x 2>&1 || true)
if echo "$out" | jq -e ".kind == \"err\" and (.error | test(\"invalid character '\\\\.'\"))" >/dev/null; then
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
kepr --json set "$NAME" --value "first"  >/dev/null
kepr --json set "$NAME" --value "second" >/dev/null
got=$(kepr get "$NAME" --quiet)
if [ "$got" = "second" ]; then
    pass "second set --value replaced first"
else
    fail "overwrite failed — got $(printf '%q' "$got")"
fi

# ── 6. JSON mode shape ────────────────────────────────────────────────────────
step "6. --json output is valid JSON in both success and failure"

if kepr --json list | jq -e '.kind == "list_ok" and (.credentials | type == "array")' >/dev/null; then
    pass "--json list: kind=list_ok, credentials is array"
else
    fail "--json list shape wrong"
fi

MISSING="${PREFIX}DEFINITELY_NOT_HERE"
# Same pipefail trap as test 1: kepr exits 1 on not-found. Capture first.
out=$(kepr --json get "$MISSING" || true)
if echo "$out" \
    | jq -e '.kind == "err" and (.error | type == "string" and length > 0)' >/dev/null; then
    pass "--json get on missing cred: kind=err, error is non-empty string"
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
    kepr --json set "$NAME" --value "ok" >/dev/null
    # The on-disk name mirrors what store::to_cred_name builds.
    UID_NUM=$(id -u)
    DISK_NAME="kepr-${UID_NUM}-$(echo "$NAME" | tr '[:upper:]_' '[:lower:]-')"
    DISK_PATH="/etc/credstore.encrypted/${DISK_NAME}"

    run_root() { if [ "$(id -u)" = 0 ]; then "$@"; else sudo -n "$@"; fi }
    run_root sh -c "echo 'not-a-real-encrypted-cred' > '$DISK_PATH'"

    out=$(kepr --json get "$NAME" 2>&1 || true)
    err_msg=$(echo "$out" | jq -r '.error // ""')

    if [ -z "$err_msg" ]; then
        fail "corrupted get did not return an error message"
    elif echo "$err_msg" | grep -Eq "$FORBIDDEN_RE"; then
        fail "error leaks internal tool name: $err_msg"
    else
        pass "error is sanitized (no forbidden substrings)"
    fi

    # The corrupted file is still on disk. Leaving it there makes later
    # tests (e.g. `kepr check` in test 10) exit 1 under -o pipefail
    # because one cred no longer decrypts. Remove it here so each test
    # stays isolated.
    kepr --json delete "$NAME" >/dev/null 2>&1 || true
else
    skip "no root/sudo — cannot corrupt a cred file to force a decrypt failure"
fi

# ── 8. Audit log shape (requires journal read access) ─────────────────────────
step "8. audit log records op=get without leaking the value"

# A bare `journalctl -t kepr-daemon` returns exit 0 even when the user
# cannot see system messages — journald silently filters to the user's own
# session. So probe group membership directly: root, `systemd-journal`, or
# `adm` can read the daemon's audit log; anyone else sees "No entries".
can_journal=0
if [ "$(id -u)" = 0 ]; then can_journal=1
elif id -nG | tr ' ' '\n' | grep -qxE 'systemd-journal|adm'; then can_journal=1
fi

if [ "$can_journal" = 0 ]; then
    skip "journalctl not readable by this user (join group 'systemd-journal' or 'adm')"
else
    NAME="${PREFIX}AUDIT"
    SECRET_VAL="audit-sentinel-$(date +%N)"
    kepr --json set "$NAME" --value "$SECRET_VAL" >/dev/null
    kepr --json get "$NAME" >/dev/null
    sleep 0.3  # journal write is async

    # Grab the most recent get-ok entry matching our name
    entry=$(journalctl -t kepr-daemon \
            KEPR_OP=get KEPR_NAME="$NAME" KEPR_RESULT=ok \
            --since='10 seconds ago' -o json -n 1 2>/dev/null || echo "")
    if [ -z "$entry" ]; then
        fail "no audit entry found for op=get name=$NAME"
    else
        uid_logged=$(echo "$entry" | jq -r '.KEPR_UID // ""')
        if [ "$uid_logged" != "$(id -u)" ]; then
            fail "audit KEPR_UID=$uid_logged, expected $(id -u)"
        elif echo "$entry" | grep -q "$SECRET_VAL"; then
            fail "audit entry contains the secret value!"
        else
            pass "audit entry present, UID matches, no secret value leaked"
        fi
    fi
fi

# ── 9. Colour opt-in model ────────────────────────────────────────────────────
# Colour is OFF by default, even under a TTY. --color enables it; NO_COLOR=1
# and --no-color override --color. Uses util-linux `script` to fake a TTY —
# without it, is_tty() is already false and we can't distinguish "TTY with
# colour suppressed" from "not a TTY".
step "9. colour opt-in (default off, --color enables, NO_COLOR/--no-color override)"

if ! command -v script >/dev/null 2>&1; then
    skip "util-linux 'script' not available — cannot fake a TTY"
else
    NAME="${PREFIX}COLOR"
    kepr --json set "$NAME" --value "x" >/dev/null

    pty_run() { script -q -e -c "$*" /dev/null 2>/dev/null | tr -d '\r'; }
    has_ansi() { printf '%s' "$1" | grep -q $'\x1b\['; }

    # Default behaviour: no ANSI even under a TTY.
    if ! has_ansi "$(pty_run "kepr list")"; then
        pass "default: no ANSI under TTY"
    else
        fail "default emitted ANSI; colour should be opt-in"
    fi

    # --color must enable ANSI under a TTY. If the baseline doesn't light
    # up even with --color, the PTY emulation isn't detectable as a TTY —
    # skip the override checks instead of reporting false failures.
    base=$(pty_run "kepr --color list")
    if ! has_ansi "$base"; then
        skip "'kepr --color list' under PTY emitted no ANSI (non-TTY detection)"
    else
        pass "--color enables ANSI under TTY"

        if ! has_ansi "$(pty_run "kepr --color --no-color list")"; then
            pass "--no-color overrides --color"
        else
            fail "--no-color did NOT override --color"
        fi
        if ! has_ansi "$(pty_run "NO_COLOR=1 kepr --color list")"; then
            pass "NO_COLOR=1 overrides --color"
        else
            fail "NO_COLOR=1 did NOT override --color"
        fi
    fi
fi

# ── 10. check output is sorted ────────────────────────────────────────────────
# Daemon returns a HashMap — order undefined. Client must sort.
step "10. check output is deterministic (sorted by name)"

for s in ZETA_C ALPHA_A MIKE_B; do
    kepr --json set "${PREFIX}${s}" --value "x" >/dev/null
done

names1=$(kepr check 2>/dev/null | grep -oE "${PREFIX}[A-Z_]+" | grep -E '(ZETA_C|ALPHA_A|MIKE_B)')
names2=$(kepr check 2>/dev/null | grep -oE "${PREFIX}[A-Z_]+" | grep -E '(ZETA_C|ALPHA_A|MIKE_B)')
sorted=$(printf '%s\n' "$names1" | sort)

if [ "$names1" = "$sorted" ]; then
    pass "check output is sorted"
else
    fail "check output not sorted: $(printf '%s' "$names1" | tr '\n' ' ')"
fi

if [ "$names1" = "$names2" ]; then
    pass "check output is stable across runs"
else
    fail "check output changed between runs"
fi

# ── 11. JSON mode stderr hygiene ──────────────────────────────────────────────
# Clean errors (missing NAME, unknown command) must NOT print anything to
# stderr in --json mode. Scripts rely on stdout having one JSON object.
step "11. --json mode: no stderr noise on clean errors"

# These CLI calls exit non-zero; under `set -e`, $() would abort the script.
# `|| true` keeps the script running so we can inspect stderr.
errout=$(kepr --json get 2>&1 >/dev/null || true)
if [ -z "$errout" ]; then
    pass "--json get (no NAME): stderr empty"
else
    fail "--json get (no NAME) leaked stderr: $errout"
fi

errout=$(kepr --json delete 2>&1 >/dev/null || true)
if [ -z "$errout" ]; then
    pass "--json delete (no NAME): stderr empty"
else
    fail "--json delete (no NAME) leaked stderr: $errout"
fi

errout=$(kepr --json nosuchcommand 2>&1 >/dev/null || true)
if [ -z "$errout" ]; then
    pass "--json unknown command: stderr empty"
else
    fail "--json unknown command leaked stderr: $errout"
fi

jsonout=$(kepr --json nosuchcommand 2>/dev/null || true)
if echo "$jsonout" | jq -e '.kind == "err" and (.error | test("unknown command"))' >/dev/null; then
    pass "--json unknown command: valid JSON with kind=err"
else
    fail "--json unknown command did not return structured JSON"
fi

# ── 12. --force skips the delete confirmation ─────────────────────────────────
step "12. delete --force skips the interactive prompt"

NAME="${PREFIX}FORCE_DEL"
kepr --json set "$NAME" --value "x" >/dev/null

# stdin closed: if --force didn't skip the prompt, read_line would hit EOF and
# the delete would be aborted — leaving the cred present.
if kepr delete "$NAME" --force </dev/null >/dev/null 2>&1; then
    pass "delete --force exited cleanly with no stdin"
else
    fail "delete --force failed with no stdin"
fi

out=$(kepr --json get "$NAME" || true)
if echo "$out" | jq -e '.kind == "err"' >/dev/null; then
    pass "credential actually removed by --force"
else
    fail "credential still present after delete --force"
fi

# ── 13. Command aliases: ls, rm ───────────────────────────────────────────────
step "13. command aliases (ls, rm)"

NAME="${PREFIX}ALIAS"
kepr --json set "$NAME" --value "x" >/dev/null

if kepr --json ls | jq -e --arg n "$NAME" '.credentials[]?.name | select(. == $n)' >/dev/null; then
    pass "ls alias returns same shape as list"
else
    fail "ls alias did not return credential"
fi

if kepr rm "$NAME" --force </dev/null >/dev/null 2>&1; then
    pass "rm alias + --force deleted credential"
else
    fail "rm alias failed"
fi

# ── 14. InProc magic prefix on disk (requires root or sudo) ──────────────────
# After Phase 0 α3, every cred file is written by the in-process AEAD
# backend and starts with the bytes `kepr_v1\n`. A different magic (or
# no magic) means the daemon is silently using the legacy path or the
# wire format has drifted. Pin the contract.
step "14. on-disk cred starts with the kepr_v1 magic"

if [ "$can_root" = 1 ]; then
    NAME="${PREFIX}MAGIC"
    kepr --json set "$NAME" --value "x" >/dev/null
    UID_NUM=$(id -u)
    DISK_NAME="kepr-${UID_NUM}-$(echo "$NAME" | tr '[:upper:]_' '[:lower:]-')"
    DISK_PATH="/etc/credstore.encrypted/${DISK_NAME}"

    # Guard against the file being missing/unreadable BEFORE the
    # head-pipeline pipefail-aborts the whole script. Codex flagged
    # the bare `$(head | od | tr)` form on first review.
    if ! run_root test -r "$DISK_PATH"; then
        fail "cred file missing or unreadable: $DISK_PATH"
    else
        # od -c renders bytes as escaped chars: \n shows as "\n", a-z as a-z.
        # `kepr_v1\n` is the magic; check both segments to avoid a partial match.
        head=$(run_root head -c 8 "$DISK_PATH" | od -An -c | tr -d ' \n')
        if [ "$head" = "kepr_v1\\n" ]; then
            pass "on-disk cred starts with kepr_v1\\n"
        else
            fail "on-disk magic mismatch (got: $head, expected: kepr_v1\\n)"
        fi
    fi
    kepr --json delete "$NAME" >/dev/null 2>&1 || true
else
    skip "no root/sudo — cannot read /etc/credstore.encrypted/ to inspect on-disk magic"
fi

# ── 15. Master key is sealed at /var/lib/kepr/master.key (root or sudo) ──────
# The Phase 0 α2b loader writes the sealed master key to a known path
# at first daemon start; from there every restart unseals it without
# re-deriving. Verify both the file's existence and its mode (0600,
# root-owned) — anything wider exposes the seal blob.
step "15. master key file exists with root:root 0600"

if [ "$can_root" = 1 ]; then
    KEY_PATH="/var/lib/kepr/master.key"
    if run_root test -f "$KEY_PATH"; then
        mode=$(run_root stat -c '%a %U %G' "$KEY_PATH")
        if [ "$mode" = "600 root root" ]; then
            pass "master key present at 0600 root:root"
        else
            fail "master key has wrong perms/owner: $mode"
        fi
    else
        fail "master key not found at $KEY_PATH (daemon never bootstrapped?)"
    fi
else
    skip "no root/sudo — cannot stat /var/lib/kepr/master.key"
fi

# ── 16. Legacy-cred sweep on daemon restart (root or sudo) ───────────────────
# Plant a fake legacy file (no kepr_v1 magic) under /etc/credstore.encrypted/
# with a kepr-* prefix, then bounce the daemon. The startup sweep should
# delete it. Idempotent: a second restart finds nothing to do.
step "16. daemon sweeps legacy systemd-creds files on restart"

if [ "$can_root" = 1 ] && command -v systemctl >/dev/null; then
    UID_NUM=$(id -u)
    LEGACY_NAME="kepr-${UID_NUM}-legacy-sweep-test"
    LEGACY_PATH="/etc/credstore.encrypted/${LEGACY_NAME}"

    # Plant a file that looks like the old systemd-creds blob: no kepr_v1
    # magic, just opaque bytes. The sweep should pick it up because the
    # filename matches the kepr-* prefix.
    run_root sh -c "echo 'pretend-systemd-creds-blob' > '$LEGACY_PATH'"

    if run_root systemctl restart kepr.service 2>/dev/null; then
        # Give the daemon a beat to come up and run sweep_legacy_credstore.
        # The accept loop is reachable via `kepr list` once it's listening.
        # Track whether the daemon ever came back: if it didn't, the
        # legacy-file check is meaningless and we must report a real
        # failure rather than a false PASS — Codex flagged the loop as
        # silently swallowing a permanent-down daemon on first review.
        ready=0
        for _ in 1 2 3 4 5; do
            if kepr --json list >/dev/null 2>&1; then
                ready=1
                break
            fi
            sleep 1
        done

        if [ "$ready" = 0 ]; then
            fail "daemon did not come back after restart — sweep result is undecidable"
            run_root rm -f "$LEGACY_PATH" || true
        elif run_root test -e "$LEGACY_PATH"; then
            fail "legacy file still present after restart: $LEGACY_PATH"
            run_root rm -f "$LEGACY_PATH" || true
        else
            pass "legacy file swept on restart"
        fi
    else
        skip "systemctl restart kepr.service failed (test cannot proceed)"
        run_root rm -f "$LEGACY_PATH" || true
    fi
else
    skip "no root/sudo or no systemctl — cannot exercise the daemon-restart sweep"
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
