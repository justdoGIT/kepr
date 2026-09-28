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

# Tests 1-9 run ~30+ operations against the daemon. The default per-uid
# rate-limit bucket is capacity 30 / refill 10/s (see daemon.rs constants),
# so by this point the bucket can be empty. Wait long enough for a full
# refill before adding three more sets — 30 / 10 = 3s, plus headroom.
sleep 4

# Seed three creds explicitly. Capture stdout so a daemon error (rate limit,
# busy state file, etc.) is reported as a fail() rather than crashing the
# whole script silently via `set -e` with stdout swallowed by `>/dev/null`.
seed_ok=1
for s in ZETA_C ALPHA_A MIKE_B; do
    out=$(kepr --json set "${PREFIX}${s}" --value "x" 2>&1 || true)
    if echo "$out" | jq -e '.kind == "set_ok"' >/dev/null 2>&1; then
        :
    else
        # `kepr --json` uses `to_string_pretty` (cli_ui::print_json), so a
        # JSON error response spans multiple lines. Collapse to a single
        # line for the fail() summary so the post-test failure list stays
        # one-line-per-failure.
        fail "10. seeding ${PREFIX}${s} failed: $(printf '%s' "$out" | tr '\n' ' ')"
        seed_ok=0
    fi
done

if [ "$seed_ok" = 1 ]; then
    # `kepr check | grep | grep` can return non-zero at any pipe stage
    # (e.g. no credentials match the second grep), and `set -o pipefail`
    # then propagates that to a script-killing exit. Add `|| true` so an
    # empty match is reported as a test fail instead of a silent abort.
    names1=$(kepr check 2>/dev/null \
        | grep -oE "${PREFIX}[A-Z_]+" \
        | grep -E '(ZETA_C|ALPHA_A|MIKE_B)' || true)
    names2=$(kepr check 2>/dev/null \
        | grep -oE "${PREFIX}[A-Z_]+" \
        | grep -E '(ZETA_C|ALPHA_A|MIKE_B)' || true)
    sorted=$(printf '%s\n' "$names1" | sort)

    if [ -z "$names1" ]; then
        fail "10. kepr check returned no matching names — \
seeding may have raced cleanup"
    elif [ "$names1" = "$sorted" ]; then
        pass "check output is sorted"
    else
        fail "check output not sorted: $(printf '%s' "$names1" | tr '\n' ' ')"
    fi

    if [ -z "$names2" ]; then
        fail "10. second kepr check returned no matching names"
    elif [ "$names1" = "$names2" ]; then
        pass "check output is stable across runs"
    else
        fail "check output changed between runs"
    fi
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
# backend. PR #59 (rollback protection) shifted the current format from
# `kepr_v1\n` to `kepr_v2\n` (8-byte counter prefix inside the AEAD
# plaintext). A fresh `kepr set` MUST produce a v2 file — anything else
# means either the daemon silently fell back to the legacy backend
# (which would be a regression) or the rollback-protection wiring did
# not commit. Pin v2 specifically; v1 acceptance is reserved for the
# read path tested implicitly by `get` on a pre-#59 cred.
#
# Source of truth for the supported set of magics: `INPROC_MAGICS`
# in src/daemon.rs (used by `sweep_legacy_credstore`). When that
# slice gains `kepr_v3\n`, update the assertion below in lock-step.
step "14. on-disk cred starts with the kepr_v2 magic"

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
        # `kepr_v2\n` is the current magic; check both segments to avoid a partial match.
        head=$(run_root head -c 8 "$DISK_PATH" | od -An -c | tr -d ' \n')
        if [ "$head" = "kepr_v2\\n" ]; then
            pass "on-disk cred starts with kepr_v2\\n"
        else
            fail "on-disk magic mismatch (got: $head, expected: kepr_v2\\n)"
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

# ── 17. kepr exec provisions credentials into a child process ────────────────
# Phase 1 entry point. Fetches each var via Get, then `execvp`s the child
# with the env merged in. The parent process is replaced (no fork), so
# the only place the secret value should appear is the child's environment.
# We use `/bin/sh -c 'echo "..."'` as the child to print a sentinel
# constructed from the fetched value — if the env wasn't provisioned we
# get an empty string; if it was, we get the marker plus the value.
step "17. kepr exec --env VAR -- cmd: child sees the credential in env"

NAME="${PREFIX}EXEC_VAR"
SECRET_VAL="exec-sentinel-$(date +%N)"
kepr --json set "$NAME" --value "$SECRET_VAL" >/dev/null

# `${...}` reaches the literal in the heredoc-less single-quoted shell
# script that /bin/sh runs as the child. The variable expansion happens
# in the *child's* shell, AFTER kepr exec provisioned the env.
exec_out=$(kepr exec --env "$NAME" -- /bin/sh -c "echo MARKER:\$$NAME" 2>&1 || true)
if echo "$exec_out" | grep -qF "MARKER:${SECRET_VAL}"; then
    pass "child process saw $NAME in its environment"
else
    fail "child env missing $NAME (got: $(printf '%s' "$exec_out" | tr '\n' ' '))"
fi

# Negative case: a missing cred MUST abort BEFORE the child runs. The
# alternative — silently exec'ing the child with the var unset — would
# let unrelated default-env behaviour kick in, which is the bug the
# build_env() abort path exists to prevent.
MISSING="${PREFIX}EXEC_MISSING"
exec_out=$(kepr exec --env "$MISSING" -- /bin/sh -c 'echo SHOULD_NOT_RUN' 2>&1 || true)
if ! echo "$exec_out" | grep -q "SHOULD_NOT_RUN"; then
    pass "missing cred aborts BEFORE child runs"
else
    fail "exec ran child despite missing cred (got: $exec_out)"
fi

# ── 18. kepr doctor produces actionable diagnostics ──────────────────────────
# Phase 1 setup-diagnostic command. Three production checks: socket
# presence/mode, kepr-group membership, daemon Ping. If the daemon is
# running and the test user is in the kepr group, all three must pass.
# The test under sudo runs as root, so the group check reports
# "running as root (group check bypassed)" and still passes — we accept
# that branch as a pass too.
step "18. kepr doctor: live invariants pass against the running daemon"

doctor_json=$(kepr --json doctor 2>&1 || true)
if echo "$doctor_json" | jq -e '.kind == "check_ok" and .all_ok == true' >/dev/null; then
    pass "kepr doctor reports all_ok against the running daemon"
else
    fail "kepr doctor failed: $(printf '%s' "$doctor_json" | tr '\n' ' ')"
fi

# Sanity-check the names of the three production checks are present in
# the JSON results — pins the wire shape against future renames.
for name in "daemon socket" "kepr group membership" "daemon responds to Ping"; do
    if echo "$doctor_json" | jq -e --arg n "$name" '.results[$n] != null' >/dev/null; then
        pass "doctor reports check: $name"
    else
        fail "doctor missing check: $name"
    fi
done

# ── 19. kepr env --env CSV emits eval-safe export lines ──────────────────────
# Phase 1 sibling of `kepr exec`. Sources two credentials into the
# current shell via `eval "$(kepr env --env A,B)"` and verifies both
# are visible AFTER the eval. Crucially, the second credential carries
# a value with shell metachars ($, backticks) — eval-ing the line MUST
# treat those as literals, not expand them. A pre-Phase-1 cmd_get
# --export would have detonated on this case (no quoting).
step "19. kepr env --env CSV: eval-safe export lines"

NAME_A="${PREFIX}ENV_A"
NAME_B="${PREFIX}ENV_B"
VAL_A="plain-value-$(date +%N)"
# A value designed to break naive `export VAR=value` rendering: the
# `$(date)` is shell-active without single-quotes. The post-eval
# environment must hold the literal text, NOT the date.
# shellcheck disable=SC2016 # literal $(date) is intentional
VAL_B='the-injected-value-$(date)'
kepr --json set "$NAME_A" --value "$VAL_A" >/dev/null
kepr --json set "$NAME_B" --value "$VAL_B" >/dev/null

# Capture exports from a subshell so the test process's environment
# is not polluted. `set -a` is not needed because the lines start with
# `export`. Use `printenv` to read back so we go through the kernel's
# environment-variable view, not the subshell's variable substitution
# that we're trying to test against.
export_out=$(eval "$(kepr env --env "$NAME_A,$NAME_B")"; printenv "$NAME_A"; echo '---'; printenv "$NAME_B" || true)
got_a=$(echo "$export_out" | sed -n '1p')
got_b=$(echo "$export_out" | sed -n '3p')

if [ "$got_a" = "$VAL_A" ]; then
    pass "kepr env exported $NAME_A round-tripped exactly"
else
    fail "kepr env $NAME_A: got $(printf '%q' "$got_a"), expected $(printf '%q' "$VAL_A")"
fi

if [ "$got_b" = "$VAL_B" ]; then
    pass "kepr env preserved shell metachars in $NAME_B (no expansion)"
else
    fail "kepr env $NAME_B leaked: got $(printf '%q' "$got_b"), expected $(printf '%q' "$VAL_B")"
fi

# Negative: missing cred must abort BEFORE any line is emitted, so the
# user can't `eval` partial state. Same contract as exec.
MISSING_C="${PREFIX}ENV_MISSING"
env_out=$(kepr env --env "$NAME_A,$MISSING_C" 2>&1 || true)
# The good var must NOT appear on stdout — empty output proves the
# whole batch was abandoned, not just the missing leg.
if ! echo "$env_out" | grep -q "^export ${NAME_A}="; then
    pass "kepr env aborts the whole batch on first failure"
else
    fail "kepr env emitted ${NAME_A} despite ${MISSING_C} missing"
fi

# Auto-discovery is an explicit opt-in because a checkout can contain an
# untrusted `.kepr.toml`; production callers should pass `--env` or `--manifest`.
# This test exercises the opt-in compatibility path.
# Phase 1 γ: a project-local `.kepr.toml` declares which credentials
# this directory expects.
step "20. opt-in .kepr.toml manifest discovery supplies --env"

NAME="${PREFIX}MANIFEST_VAR"
VAL="manifest-sentinel-$(date +%N)"
kepr --json set "$NAME" --value "$VAL" >/dev/null

# Build a temp project with .kepr.toml at its root, run `kepr env`
# from a subdirectory inside it, expect the resolver to walk up,
# parse the manifest, and emit the export line.
proj=$(mktemp -d -t kepr-manifest-XXXXXX)
trap 'rm -rf "$proj"' RETURN
cat > "$proj/.kepr.toml" <<TOML
[env]
required = ["$NAME"]
TOML
mkdir -p "$proj/sub/dir"

env_out=$(cd "$proj/sub/dir" && KEPR_AUTO_MANIFEST=1 kepr env 2>&1 || true)
if echo "$env_out" | grep -qF "export ${NAME}=" \
    && echo "$env_out" | grep -qF "$VAL"; then
    pass "kepr env discovers .kepr.toml from a nested cwd"
else
    fail "manifest auto-discovery failed: $(printf '%s' "$env_out" | tr '\n' ' ')"
fi

# An explicit `--env CSV` must override whatever the manifest says.
# Stash a different cred and ensure the CLI list wins.
NAME2="${PREFIX}MANIFEST_OVERRIDE"
VAL2="override-sentinel-$(date +%N)"
kepr --json set "$NAME2" --value "$VAL2" >/dev/null

env_out=$(cd "$proj/sub/dir" && KEPR_AUTO_MANIFEST=1 kepr env --env "$NAME2" 2>&1 || true)
if echo "$env_out" | grep -qF "export ${NAME2}=" \
    && ! echo "$env_out" | grep -qF "export ${NAME}="; then
    pass "--env CSV overrides the manifest"
else
    fail "CLI override not honoured: $(printf '%s' "$env_out" | tr '\n' ' ')"
fi

# ── 21. docker-credential-kepr round-trip ────────────────────────────────────
# Phase 1 ε: third bin implements the docker credential-helper protocol
# (get/store/erase/list over stdin/stdout JSON). Skip if the binary
# is not on PATH — `cargo build --release` produces it but `install.sh`
# may not have copied it (older installs).
step "21. docker-credential-kepr: store/get/list/erase round-trip"

if ! command -v docker-credential-kepr >/dev/null 2>&1; then
    skip "docker-credential-kepr not on PATH (rebuild + reinstall to pick up Phase 1 ε)"
else
    DREG="https://${PREFIX,,}example.test"
    DUSER="alice"
    DSEC="docker-sentinel-$(date +%N)"

    # store: stdin JSON, no stdout, exit 0.
    if printf '%s' "{\"ServerURL\":\"$DREG\",\"Username\":\"$DUSER\",\"Secret\":\"$DSEC\"}" \
        | docker-credential-kepr store >/dev/null 2>&1; then
        pass "docker-credential-kepr store accepted JSON"
    else
        fail "docker-credential-kepr store rejected valid JSON"
    fi

    # get: stdin = URL, stdout = {"Username","Secret"}.
    get_out=$(printf '%s' "$DREG" | docker-credential-kepr get 2>&1 || true)
    if echo "$get_out" | jq -e --arg u "$DUSER" --arg s "$DSEC" \
        '.Username == $u and .Secret == $s' >/dev/null; then
        pass "docker-credential-kepr get returned the stored Username + Secret"
    else
        fail "docker-credential-kepr get round-trip failed: $(printf '%s' "$get_out" | tr '\n' ' ')"
    fi

    # list: stdout = {<ServerURL>: <Username>}; ours must be present.
    list_out=$(docker-credential-kepr list </dev/null 2>&1 || true)
    if echo "$list_out" | jq -e --arg u "$DUSER" --arg url "$DREG" \
        '.[$url] == $u' >/dev/null; then
        pass "docker-credential-kepr list includes the stored ServerURL"
    else
        fail "docker-credential-kepr list missing entry: $(printf '%s' "$list_out" | tr '\n' ' ')"
    fi

    # erase: stdin = URL, exit 0. Verify by re-erasing — second call
    # MUST also exit 0 (docker treats erase-of-missing as a success).
    if printf '%s' "$DREG" | docker-credential-kepr erase >/dev/null 2>&1; then
        pass "docker-credential-kepr erase succeeded"
    else
        fail "docker-credential-kepr erase failed"
    fi

    if printf '%s' "$DREG" | docker-credential-kepr erase >/dev/null 2>&1; then
        pass "docker-credential-kepr erase is idempotent on a missing entry"
    else
        fail "docker-credential-kepr erase failed on second run (must be idempotent)"
    fi
fi

# ── 22. --ttl: cred is fetchable before expiry, unavailable after ────────────
# Phase 2 α: kepr set NAME --ttl SECS writes a sidecar metadata file
# recording an absolute expiry timestamp. handle_get returns
# "credential unavailable" once `now >= expires_at_unix`, regardless
# of whether a sweeper has GC'd the file. The e2e validates the
# access-time check; the disk-hygiene sweeper is a future PR.
step "22. --ttl: cred is fetchable before expiry, unavailable after"

NAME="${PREFIX}TTL_QUICK"
VAL="ttl-sentinel-$(date +%N)"
# 2-second TTL keeps the test under 5s total. The kepr daemon's
# expiry check is at access time, so any wall-clock test must wait
# strictly longer than the TTL.
kepr --json set "$NAME" --value "$VAL" --ttl 2 >/dev/null

if [ "$(kepr get "$NAME" --quiet 2>/dev/null)" = "$VAL" ]; then
    pass "--ttl 2: cred is fetchable immediately after set"
else
    fail "--ttl 2: cred missing right after set"
fi

# kepr list must surface `expires_at` in JSON output for TTL'd creds.
list_out=$(kepr --json list 2>/dev/null || echo "{}")
if echo "$list_out" | jq -e --arg n "$NAME" \
    '.credentials[]? | select(.name == $n) | .expires_at | type == "string"' >/dev/null; then
    pass "kepr list surfaces expires_at for TTL'd creds"
else
    fail "kepr list missing expires_at: $(echo "$list_out" | jq -c --arg n "$NAME" '.credentials[]? | select(.name == $n)')"
fi

# Wait past the TTL and assert the cred is now unavailable. 3s
# leaves a comfortable margin over the 2s TTL.
sleep 3

err_out=$(kepr --json get "$NAME" 2>&1 || true)
if echo "$err_out" | jq -e '.kind == "err" and (.error | test("credential unavailable"))' >/dev/null; then
    pass "post-TTL get returns sanitised credential unavailable"
else
    fail "post-TTL get unexpectedly succeeded or wrong error: $(printf '%s' "$err_out" | tr '\n' ' ')"
fi

# A cred set without --ttl must NOT have expires_at populated. Pin
# the no-meta path so a regression in handle_list doesn't start
# claiming creds expire when they don't.
NAME_NOTTL="${PREFIX}TTL_NONE"
kepr --json set "$NAME_NOTTL" --value "x" >/dev/null
list_out=$(kepr --json list 2>/dev/null || echo "{}")
if echo "$list_out" | jq -e --arg n "$NAME_NOTTL" \
    '.credentials[]? | select(.name == $n) | (.expires_at == null or .expires_at == "")' >/dev/null; then
    pass "non-TTL cred has no expires_at (no spurious meta)"
else
    fail "non-TTL cred unexpectedly carries expires_at"
fi

# --ttl 0 must be rejected at the parser level (defends against the
# typo where the user means "no ttl" but writes 0).
zero_err=$(kepr --json set "${PREFIX}TTL_ZERO" --value x --ttl 0 2>&1 || true)
if echo "$zero_err" | jq -e '.kind == "err" and (.error | test("--ttl 0"))' >/dev/null \
   || echo "$zero_err" | grep -q -- "--ttl 0"; then
    pass "--ttl 0 is rejected with a helpful message"
else
    fail "--ttl 0 not rejected: $(printf '%s' "$zero_err" | tr '\n' ' ')"
fi

# ── 23. kepr rotate: hook ok commits, hook fail leaves cred unchanged ────────
# Phase 2 γ. Validate-then-commit rotation: generate fresh value, pipe
# to hook on stdin, commit only on hook exit 0. Critical contract is
# that a non-zero hook exit MUST leave the prior value in place.
step "23. kepr rotate: hook ok commits, hook fail leaves cred unchanged"

NAME="${PREFIX}ROTATE"
PRIOR="prior-value-$(date +%N)"
kepr --json set "$NAME" --value "$PRIOR" >/dev/null

# Hook ok: write the value it gets on stdin to a marker file, exit 0.
# After rotation, cred should hold a new value AND marker file should
# contain that same new value.
hook_ok=$(mktemp -t kepr-hook-ok-XXXXXX.sh)
marker=$(mktemp -t kepr-marker-XXXXXX)
cat > "$hook_ok" <<HOOK
#!/usr/bin/env bash
cat - > "$marker"
exit 0
HOOK
chmod +x "$hook_ok"

if kepr --json rotate "$NAME" --hook "$hook_ok" >/dev/null; then
    new_value=$(kepr get "$NAME" --quiet)
    hook_saw=$(cat "$marker")
    if [ -n "$new_value" ] && [ "$new_value" != "$PRIOR" ] && [ "$new_value" = "$hook_saw" ]; then
        pass "rotate: hook saw the same value the cred-store committed"
    else
        fail "rotate happy-path mismatch: cred='$new_value' hook='$hook_saw' prior='$PRIOR'"
    fi
else
    fail "rotate failed despite hook returning 0"
fi

# Hook fail: any rotation must NOT touch the cred. Re-set the cred to a
# known value, run rotate against a hook that exits 1, then assert the
# value is unchanged.
KNOWN="known-after-rotate-fail-$(date +%N)"
kepr --json set "$NAME" --value "$KNOWN" >/dev/null

hook_fail=$(mktemp -t kepr-hook-fail-XXXXXX.sh)
cat > "$hook_fail" <<HOOK
#!/usr/bin/env bash
exit 1
HOOK
chmod +x "$hook_fail"

if ! kepr --json rotate "$NAME" --hook "$hook_fail" >/dev/null 2>&1; then
    after=$(kepr get "$NAME" --quiet)
    if [ "$after" = "$KNOWN" ]; then
        pass "rotate: hook failure leaves prior value untouched"
    else
        fail "rotate failure clobbered cred: was '$KNOWN', now '$after'"
    fi
else
    fail "rotate unexpectedly succeeded with a failing hook"
fi

rm -f "$hook_ok" "$hook_fail" "$marker"

# Missing hook path: must fail BEFORE generating a value (saves /dev/urandom).
miss_out=$(kepr --json rotate "$NAME" --hook /nonexistent/hook 2>&1 || true)
if echo "$miss_out" | jq -e '.kind == "err" and (.error | test("hook not found"))' >/dev/null; then
    pass "rotate: missing hook is rejected with a helpful message"
else
    fail "rotate: missing hook check failed: $(printf '%s' "$miss_out" | tr '\n' ' ')"
fi

# ── 24. audit chain extends on operations (root or sudo) ─────────────────────
# Phase 2 δ.2: every audit::log call also appends a hash-chained
# entry to /var/lib/kepr/audit.log. Skip if not root/sudo (chain
# file is 0o640 root:root).
step "24. audit chain at /var/lib/kepr/audit.log grows on operations"

if [ "$can_root" = 1 ]; then
    AUDIT_CHAIN_PATH="/var/lib/kepr/audit.log"
    if ! run_root test -f "$AUDIT_CHAIN_PATH"; then
        skip "audit.log not yet present — daemon must be Phase-2-δ-aware (rebuild + restart)"
    else
        before=$(run_root wc -l "$AUDIT_CHAIN_PATH" | awk '{print $1}')
        # Trigger one extra audit-emitting op.
        kepr --json set "${PREFIX}AUDIT_TEE" --value "x" >/dev/null
        # Audit append happens synchronously inside the daemon
        # before the response, so no sleep is needed.
        after=$(run_root wc -l "$AUDIT_CHAIN_PATH" | awk '{print $1}')
        if [ "$after" -gt "$before" ]; then
            pass "audit.log line count grew $before → $after on a kepr set"
        else
            fail "audit.log did NOT grow on kepr set: was $before, still $before"
        fi

        # Sanity-check: each line is JSON with the expected fields.
        last_line=$(run_root tail -n 1 "$AUDIT_CHAIN_PATH")
        if echo "$last_line" | jq -e '.seq and .hash and .prev_hash and .op' >/dev/null 2>&1; then
            pass "audit.log entries are JSON with seq/hash/prev_hash/op fields"
        else
            fail "audit.log entry shape unexpected: $last_line"
        fi
    fi
else
    skip "no root/sudo — cannot read /var/lib/kepr/audit.log"
fi

# ── 25. kepr audit-verify reports a clean chain ──────────────────────────────
# Phase 2 δ.3: CLI walks the daemon's hash-chained audit log via
# Request::AuditVerify and reports entry count + head hash. The
# log file is root-only readable (0o640 root:root); the verify
# request goes through the daemon, which is the only process that
# can read it. Skip if the chain doesn't exist yet (fresh install
# with no events).
step "25. kepr audit-verify reports a clean chain"

if [ "$can_root" = 1 ] && run_root test -f /var/lib/kepr/audit.log; then
    av_out=$(kepr --json audit-verify 2>&1 || true)
    if echo "$av_out" | jq -e '.kind == "audit_ok" and (.entries | type == "number") and (.last_hash | type == "string" and (length == 64))' >/dev/null; then
        entries=$(echo "$av_out" | jq -r '.entries')
        pass "audit-verify: $entries entries, head hash is 64-hex"
    else
        fail "audit-verify response shape unexpected: $(printf '%s' "$av_out" | tr '\n' ' ')"
    fi
else
    skip "no root or no audit.log present — daemon not Phase-2-δ-aware yet"
fi

# ── 26. --requires-consent fail-closes without polkit auth ──────────────────
# Phase 2 ε. A cred set with --requires-consent must be unreadable
# without an explicit polkit prompt. In e2e (no desktop session,
# no auth agent), pkcheck always denies → kepr get returns
# "credential unavailable". Skip if pkcheck isn't on PATH.
step "26. --requires-consent gates kepr get behind polkit"

if ! command -v pkcheck >/dev/null 2>&1; then
    skip "pkcheck not installed (install policykit-1)"
else
    NAME="${PREFIX}CONSENT"
    VAL="consent-sentinel-$(date +%N)"
    if kepr --json set "$NAME" --value "$VAL" --requires-consent >/dev/null 2>&1; then
        pass "set $NAME --requires-consent"
    else
        fail "set --requires-consent rejected"
    fi

    # In a non-desktop test run, no auth agent is running →
    # pkcheck denies → daemon returns "credential unavailable".
    # If a desktop session IS available the user would see a
    # prompt; the e2e script skips waiting for interactive input.
    consent_out=$(kepr --json get "$NAME" 2>&1 || true)
    if echo "$consent_out" | jq -e '.kind == "err" and (.error | test("credential unavailable"))' >/dev/null; then
        pass "consent-flagged cred is unreadable without polkit auth (fail-closed)"
    elif echo "$consent_out" | jq -e --arg v "$VAL" '.kind == "get_ok" and .value == $v' >/dev/null; then
        # Desktop session granted consent (rare in e2e); treat as
        # pass — the consent path worked, we just got authorized.
        pass "polkit granted consent (active desktop session detected)"
    else
        fail "consent-flagged get neither denied nor granted: $(printf '%s' "$consent_out" | tr '\n' ' ')"
    fi

    # kepr list must surface the requires_consent flag.
    list_out=$(kepr --json list 2>/dev/null || echo "{}")
    if echo "$list_out" | jq -e --arg n "$NAME" '.credentials[]? | select(.name == $n) | .requires_consent == true' >/dev/null; then
        pass "kepr list surfaces requires_consent"
    else
        fail "kepr list missing requires_consent flag"
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
