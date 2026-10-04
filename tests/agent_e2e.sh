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
if pgrep -x kepr-gate >/dev/null; then fail "gate outlived the agent"; else pass "gate exited with the agent"; fi

echo "── sandbox"
cat >"$WORK/sbprobe.sh" <<'PROBE'
#!/usr/bin/env bash
r() { echo "$1 $2"; }
n=$(ls -d /proc/[0-9]* | wc -l)
[ "$n" -lt 10 ] && r ok "only sandbox processes visible ($n)" || r bad "$n processes visible"
[ -z "$(ls -A "$HOME/.local/share/kepr" 2>/dev/null)" ] && r ok "credential store hidden" || r bad "credential store visible"
[ -z "$(ls -A "$HOME/.local/state/kepr" 2>/dev/null)" ] && r ok "daemon state hidden" || r bad "daemon state visible"
[ -z "$(ls -A "$XDG_RUNTIME_DIR/kepr" 2>/dev/null)" ] && r ok "daemon socket hidden" || r bad "daemon socket visible"
if command -v python3 >/dev/null; then
    e=$(python3 -c "import ctypes;l=ctypes.CDLL(None,use_errno=True);l.ptrace(0,0,0,0);print(ctypes.get_errno())")
    [ "$e" = 1 ] && r ok "ptrace denied (seccomp)" || r bad "ptrace errno $e"
fi
grep -q "CapEff:	0000000000000000" /proc/self/status && r ok "no capabilities" || r bad "capabilities present"
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'x-api-key: wrong' "$ANTHROPIC_BASE_URL/v1/messages" -d '{}')
[ "$code" = 401 ] && r ok "gate reachable from the sandbox" || r bad "gate unreachable ($code)"
PROBE
chmod +x "$WORK/sbprobe.sh"
for mode in "" "--isolate-net"; do
    if ! SB=$("$KEPR" agent run claude --strict-sandbox $mode -- "$WORK/sbprobe.sh" 2>&1); then
        case "$SB" in *"sandbox unavailable"*) printf '  –  SKIP: sandbox unavailable here %s\n' "$mode"; continue;; esac
    fi
    while read -r status msg; do
        case "$status" in ok) pass "$msg ${mode}";; bad) fail "$msg ${mode}";; esac
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

echo "── history and restore"
"$KEPR" set E2E_HIST --value one -q >/dev/null 2>&1
"$KEPR" set E2E_HIST --value two -q >/dev/null 2>&1
check "$("$KEPR" list | grep -q '~' || echo ok)" "history slots hidden from list"
"$KEPR" restore E2E_HIST --version 1 >/dev/null 2>&1
check "$([ "$("$KEPR" get E2E_HIST -q 2>/dev/null)" = one ] && echo ok)" "restore brings back the replaced value"
"$KEPR" set ANTHROPIC_API_KEY --value now-readable -q >/dev/null 2>&1
if "$KEPR" restore ANTHROPIC_API_KEY --version 1 >/dev/null 2>&1; then
    fail "sealed version restored into a readable credential"
else
    pass "sealed version not restorable into a readable credential"
fi

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]
