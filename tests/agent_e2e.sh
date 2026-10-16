#!/usr/bin/env bash
# tests/agent_e2e.sh — "malicious agent" end-to-end test for sealed
# credentials and kepr-gate (agent vault plan, ticket T1.17).
#
# Self-contained: starts its own user-mode kepr-daemon in a temporary
# HOME, so no installed service is needed. Uses the binaries in
# $KEPR_BIN_DIR (default: target/debug; run `cargo build --workspace`).
#
# The "agent" is a probe script started through `kepr agent run`. It
# tries every way to obtain the real key and must fail at each, then
# checks the gate's 401 / DLP 403 behaviour. Forwarding to the real
# provider is not exercised (it needs network access and a real key).
#
# Usage: ./tests/agent_e2e.sh      Exits 0 on full pass, 1 on any failure.

set -euo pipefail

BIN_DIR="${KEPR_BIN_DIR:-$(cd "$(dirname "$0")/.." && pwd)/target/debug}"
for b in kepr kepr-daemon kepr-gate; do
    [ -x "$BIN_DIR/$b" ] || { echo "missing $BIN_DIR/$b — run: cargo build --workspace"; exit 1; }
done
command -v curl >/dev/null || { echo "curl not in PATH"; exit 1; }

WORK=$(mktemp -d)
DAEMON_PID=""
cleanup() {
    [ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

export HOME="$WORK/home" XDG_RUNTIME_DIR="$WORK/run" KEPR_GATE_BIN="$BIN_DIR/kepr-gate"
mkdir -p "$HOME" "$XDG_RUNTIME_DIR"
chmod 700 "$XDG_RUNTIME_DIR"
KEPR="$BIN_DIR/kepr"

PASS=0
FAIL=0
pass() { printf '  \033[0;32m✓\033[0m  %s\n' "$*"; PASS=$((PASS + 1)); }
fail() { printf '  \033[0;31m✗\033[0m  %s\n' "$*"; FAIL=$((FAIL + 1)); }
check() { if [ "$1" = ok ]; then pass "$2"; else fail "$2"; fi; }

"$BIN_DIR/kepr-daemon" --user >"$WORK/daemon.log" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 50); do
    "$KEPR" status >/dev/null 2>&1 && break
    sleep 0.1
done

REAL="sk-ant-api03-E2E$(date +%s)SECRETVALUE0123456789"
echo "── sealed storage"
if printf '%s\n' "$REAL" | "$KEPR" agent add ANTHROPIC_API_KEY --stdin >/dev/null; then
    pass "agent add stores a sealed credential"
else
    fail "agent add"; cat "$WORK/daemon.log"; exit 1
fi
if "$KEPR" get ANTHROPIC_API_KEY >/dev/null 2>&1; then fail "kepr get returned a sealed value"; else pass "kepr get refused"; fi
if "$KEPR" agent ls | grep -q "api.anthropic.com"; then pass "agent ls shows the binding"; else fail "agent ls"; fi

# Exported real key in the user's shell must not reach the agent.
export ANTHROPIC_API_KEY="$REAL"

cat >"$WORK/probe.sh" <<'PROBE'
#!/usr/bin/env bash
r() { echo "$1 $2"; }
case "$ANTHROPIC_API_KEY" in kepr-ph-*) r ok "agent sees only a placeholder";; *) r bad "agent key is not a placeholder";; esac
if env | grep -qF "$(cat "$REAL_FILE")"; then r bad "real key in agent env"; else r ok "real key not in agent env"; fi
if grep -lF "$(cat "$REAL_FILE")" /proc/[0-9]*/environ 2>/dev/null | grep -q .; then r bad "real key in some /proc/*/environ"; else r ok "no /proc/*/environ holds the real key"; fi
if "$KEPR" get ANTHROPIC_API_KEY >/dev/null 2>&1; then r bad "kepr get works inside the session"; else r ok "kepr get refused inside the session"; fi
GATE=$(pgrep -x kepr-gate | head -1)
if [ "$(id -u)" != 0 ]; then
    if head -c1 "/proc/$GATE/mem" >/dev/null 2>&1; then r bad "gate memory readable"; else r ok "gate memory unreadable"; fi
    if cat "/proc/$GATE/environ" >/dev/null 2>&1; then r bad "gate environ readable"; else r ok "gate environ unreadable"; fi
else
    r skip "running as root: ptrace/proc protections are bypassed by design"
fi
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'x-api-key: sk-ant-guess' "$ANTHROPIC_BASE_URL/v1/messages" -d '{}')
[ "$code" = 401 ] && r ok "guessed key rejected (401)" || r bad "guessed key got $code"
body=$(curl -s -H "x-api-key: $ANTHROPIC_API_KEY" "$ANTHROPIC_BASE_URL/v1/messages" -d "{\"c\":\"$(cat "$REAL_FILE")\"}")
case "$body" in *kepr_blocked*) case "$body" in *ANTHROPIC_API_KEY*) r ok "DLP blocks a prompt containing the key";; *) r bad "DLP reply does not name the key";; esac;; *) r bad "DLP did not block: $body";; esac
case "$body" in *"$(cat "$REAL_FILE")"*) r bad "DLP reply echoes the key";; *) r ok "DLP reply does not echo the key";; esac
PROBE
chmod +x "$WORK/probe.sh"
printf '%s' "$REAL" >"$WORK/real"
chmod 600 "$WORK/real"

echo "── malicious agent probe"
OUT=$(REAL_FILE="$WORK/real" KEPR="$KEPR" "$KEPR" agent run claude -- "$WORK/probe.sh" 2>&1) || true
while read -r status msg; do
    case "$status" in
        ok) pass "$msg" ;;
        bad) fail "$msg" ;;
        skip) printf '  –  SKIP: %s\n' "$msg" ;;
    esac
done <<<"$OUT"

sleep 2.5
# Only this run's gates: the daemon spawns them as its children, and other
# kepr runs on the same machine may have gates of their own.
if pgrep -x kepr-gate -P "$DAEMON_PID" >/dev/null; then fail "gate outlived the agent"; else pass "gate exited with the agent"; fi

echo "── request cap"
# The first request passes the cap (and may fail upstream); the second must
# be refused by the gate itself.
codes=$("$KEPR" agent run claude --max-requests 1 -- sh -c '
    for _ in 1 2; do
        curl -s -o /dev/null -w "%{http_code} " -X POST -H "x-api-key: $ANTHROPIC_API_KEY" \
            -d "{}" "$ANTHROPIC_BASE_URL/v1/messages"
    done' 2>/dev/null) || true
case "$codes" in
    *" 403 ") pass "gate enforces --max-requests ($codes)" ;;
    *) fail "request cap not enforced (codes: $codes)" ;;
esac

echo "── request journal"
sleep 1
LOGS=$("$KEPR" agent logs -n 50 2>&1) || true
case "$LOGS" in *"/v1/messages"*"blocked: dlp"*) pass "agent logs shows the DLP refusal" ;; *) fail "agent logs: $LOGS" ;; esac
case "$LOGS" in *"blocked: limit"*) pass "agent logs shows the request cap" ;; *) fail "agent logs misses the cap" ;; esac
case "$LOGS" in *"$REAL"*) fail "agent logs prints the real key" ;; *) pass "agent logs never prints the key" ;; esac

echo "── sandbox"
cat >"$WORK/sbprobe.sh" <<'PROBE'
#!/usr/bin/env bash
r() { echo "$1 $2"; }
ll_mode=${1:-default}
n=$(ls -d /proc/[0-9]* | wc -l)
[ "$n" -lt 10 ] && r ok "only sandbox processes visible ($n)" || r bad "$n processes visible"
[ -z "$(ls -A "$HOME/.local/share/kepr" 2>/dev/null)" ] && r ok "credential store hidden" || r bad "credential store visible"
[ -z "$(ls -A "$HOME/.local/state/kepr" 2>/dev/null)" ] && r ok "daemon state hidden" || r bad "daemon state visible"
[ -z "$(ls -A "$XDG_RUNTIME_DIR/kepr" 2>/dev/null)" ] && r ok "daemon socket hidden" || r bad "daemon socket visible"
if command -v python3 >/dev/null; then
    e=$(python3 -c "import ctypes;l=ctypes.CDLL(None,use_errno=True);l.ptrace(0,0,0,0);print(ctypes.get_errno())")
    [ "$e" = 1 ] && r ok "ptrace denied (seccomp)" || r bad "ptrace errno $e"
fi
if [ "$ll_mode" = default ]; then
    t="$HOME/.kepr-e2e-rename"
    if echo a >"$t.tmp" && mv -f "$t.tmp" "$t" && [ "$(cat "$t")" = a ]; then
        r ok "a file in \$HOME can be replaced by rename"
    else
        r bad "a file in \$HOME cannot be replaced by rename"
    fi
    rm -f "$t" "$t.tmp"
elif command -v python3 >/dev/null; then
    ll=$(python3 -c 'import ctypes, os, sys
if ctypes.CDLL(None, use_errno=True).syscall(444, None, 0, 1) < 1: print("skip")
else:
    try: os.listdir(sys.argv[1]); print("open")
    except PermissionError: print("denied")' "$HOME/.local/share/kepr")
    case "$ll" in denied) r ok "Landlock denies the store dir";; open) r bad "store dir listable under Landlock";; esac
fi
grep -q "CapEff:	0000000000000000" /proc/self/status && r ok "no capabilities" || r bad "capabilities present"
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'x-api-key: wrong' "$ANTHROPIC_BASE_URL/v1/messages" -d '{}')
[ "$code" = 401 ] && r ok "gate reachable from the sandbox" || r bad "gate unreachable ($code)"
PROBE
chmod +x "$WORK/sbprobe.sh"
for run in "strict:" "strict:--isolate-net" "default:"; do
    ll="${run%%:*}" mode="${run#*:}"
    if ! SB=$(KEPR_LANDLOCK=$ll "$KEPR" agent run claude --strict-sandbox $mode -- "$WORK/sbprobe.sh" "$ll" 2>&1); then
        case "$SB" in *"sandbox unavailable"*) printf '  –  SKIP: sandbox unavailable here %s\n' "$mode"; continue;; esac
    fi
    while read -r status msg; do
        case "$status" in ok) pass "$msg ${mode} ($ll)";; bad) fail "$msg ${mode} ($ll)";; esac
    done <<<"$SB"
done

echo "── public socket"
if command -v python3 >/dev/null; then
    resp=$(python3 - "$XDG_RUNTIME_DIR/kepr/kepr.sock" <<'PY'
import json, socket, struct, sys
s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
p = json.dumps({"cmd": "resolve", "name": "ANTHROPIC_API_KEY", "host": "api.anthropic.com", "port": 443}).encode()
s.sendall(struct.pack(">I", len(p)) + p)
n = struct.unpack(">I", s.recv(4))[0]; print(s.recv(n).decode())
PY
)
    case "$resp" in *resolve_ok*|*sk-ant*) fail "public socket answered resolve";; *) pass "resolve rejected on the public socket";; esac
else
    printf '  –  SKIP: python3 not available\n'
fi

echo "── output masking"
"$KEPR" set E2E_MASK --value "mask-me-0123456789" -q >/dev/null 2>&1
masked=$("$KEPR" exec --env E2E_MASK --mask -- sh -c 'echo "v=$E2E_MASK"')
check "$([ "$masked" = "v=****" ] && echo ok)" "exec --mask hides the value"

echo "── egress proxy"
printf 'ghp_%s\n' E2EGITHUBTOKEN0123456789abcdefghij | "$KEPR" agent add E2E_GH --stdin >/dev/null 2>&1
cat >"$WORK/egress.sh" <<'PROBE'
case "$GH_TOKEN" in kepr-ph-*) echo "ok placeholder in GH_TOKEN";; *) echo "bad GH_TOKEN is not a placeholder";; esac
c=$(curl -s -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer ghp_guess' https://api.github.com/user)
[ "$c" = 401 ] && echo "ok egress proxy refuses a guessed token ($c)" || echo "bad egress proxy answered $c to a guessed token"
c=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $GH_TOKEN" https://api.github.com/user)
case "$c" in 000) echo "bad TLS to the gate failed (session CA not trusted)";; *) echo "ok TLS via the session CA ($c)";; esac
PROBE
OUT=$(GH_TOKEN=ghp_real_in_shell "$KEPR" agent run claude --no-sandbox -- sh "$WORK/egress.sh" 2>&1) || true
while read -r status msg; do
    case "$status" in ok) pass "$msg" ;; bad) fail "$msg" ;; esac
done <<<"$OUT"
"$KEPR" delete E2E_GH --force >/dev/null 2>&1 || true

echo "── history and restore"
"$KEPR" set E2E_HIST --value one -q >/dev/null 2>&1
"$KEPR" set E2E_HIST --value two -q >/dev/null 2>&1
check "$("$KEPR" list | grep -q '~' || echo ok)" "history slots hidden from list"
"$KEPR" restore E2E_HIST --version 1 >/dev/null 2>&1
check "$([ "$("$KEPR" get E2E_HIST -q 2>/dev/null)" = one ] && echo ok)" "restore brings back the replaced value"
sleep 3 # the daemon rate-limits each uid (burst 30, 10/s): let it refill
"$KEPR" set ANTHROPIC_API_KEY --value replaced-value -q >/dev/null 2>&1
check "$("$KEPR" get ANTHROPIC_API_KEY >/dev/null 2>&1 || echo ok)" "a plain set keeps a sealed credential sealed"
printf '#!/bin/sh\ncat >/dev/null\n' >"$WORK/hook.sh"
chmod +x "$WORK/hook.sh"
check "$("$KEPR" rotate ANTHROPIC_API_KEY --hook "$WORK/hook.sh" >/dev/null 2>&1 && echo ok)" "rotate --hook commits over a sealed credential"
check "$("$KEPR" get ANTHROPIC_API_KEY >/dev/null 2>&1 || echo ok)" "the rotated value stays sealed"
check "$("$KEPR" restore ANTHROPIC_API_KEY --version 2 >/dev/null 2>&1 && echo ok)" "the sealed version restores into the still-sealed credential"
check "$("$KEPR" get ANTHROPIC_API_KEY >/dev/null 2>&1 || echo ok)" "the restored value stays sealed"

echo "── usage report"
uses=$("$KEPR" usage 2>/dev/null | awk '$1 == "E2E_MASK" { print $2 }')
check "$([ "${uses:-0}" -ge 1 ] && echo ok)" "usage counts the masked exec read"

echo "── health"
# Under load a request here can meet the per-uid rate limit: retry, and show
# the report (names and flags only) if it still never flags the password.
weak=""
for _ in 1 2 3; do
    "$KEPR" set E2E_WEAK --value password1 -q >/dev/null 2>&1 || { sleep 1; continue; }
    weak=$("$KEPR" health 2>&1) || true
    if printf '%s\n' "$weak" | grep -q '^E2E_WEAK: common password'; then break; fi
    sleep 1
done
if printf '%s\n' "$weak" | grep -q '^E2E_WEAK: common password'; then
    pass "health flags a common password"
else
    fail "health flags a common password"
    printf '%s\n' "$weak" | head -20 | sed 's/^/      /'
fi

echo "── typed records"
"$KEPR" record add E2E_REC --type login --field username=me --field password=pw-123 >/dev/null 2>&1
check "$([ "$("$KEPR" record get E2E_REC password 2>/dev/null)" = pw-123 ] && echo ok)" "record field readable"
printf 'u=kepr://E2E_REC/username\n' >"$WORK/rec.tpl"
check "$([ "$("$KEPR" inject -i "$WORK/rec.tpl" 2>/dev/null)" = "u=me" ] && echo ok)" "kepr://NAME/field renders"

echo "── recovery kit"
out=$(printf 'nope\n' | "$KEPR" recovery-kit create 2>&1) || true
check "$(echo "$out" | grep -q 'passphrase' && echo ok)" "recovery kit refused without a passphrase-protected store"
if printf 'kepr1-2-1-0000000000000000-00\nkepr1-2-2-0000000000000000-00\n\nx\nx\n' \
    | "$KEPR" recovery-kit restore >/dev/null 2>&1; then
    fail "recovery restore accepted bogus shares"
else
    pass "recovery restore refuses bogus shares"
fi

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]
