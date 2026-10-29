#!/usr/bin/env bash
# secret_service_e2e.sh — kepr as the desktop's Secret Service, against a
# real session bus (dbus-daemon) and real libsecret clients.
#
# Needs: dbus-daemon + dbus-run-session, secret-tool (libsecret-tools),
# python3 (the SecretStorage / DH check is skipped without the module) and a
# built tree (`cargo build --workspace`; KEPR_BIN_DIR overrides target/debug).
# Everything runs in a temp HOME on a private session bus; nothing outside
# it is touched. It checks that:
#   * secret-tool store / lookup / search / clear work, a second store with
#     the same attributes replaces, and an arbitrary-bytes secret survives
#     over a DH-encrypted session (SecretStorage);
#   * `kepr secret ls` shows the items, `kepr ls` folds them, `kepr get`
#     refuses them, and the log names the program that asked;
#   * with kepr locked a lookup asks for the passphrase through
#     KEPR_ASKPASS, the right one opens it, a wrong one is refused and not
#     asked again at once, and a server that starts while kepr is locked
#     asks on its first call;
#   * the per-program policy refuses and reloads on SIGHUP;
#   * `takeover` makes the bus start kepr by itself and `restore` undoes it;
#   * `import` copies another provider's items (another kepr profile here)
#     and a second import changes nothing;
#   * a `kepr agent run` sandbox cannot reach the bus (skipped where the
#     sandbox can't start).
# shellcheck disable=SC2015  # `check && ok || bad` reports; ok never fails
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
command -v dbus-daemon >/dev/null || { echo "skip: dbus-daemon not installed"; exit 0; }
command -v dbus-run-session >/dev/null || { echo "skip: dbus-run-session not installed"; exit 0; }
command -v secret-tool >/dev/null || { echo "skip: secret-tool not installed (libsecret-tools)"; exit 0; }
BIN="${KEPR_BIN_DIR:-$PWD/target/debug}"
for b in kepr kepr-daemon; do
	[ -x "$BIN/$b" ] || { echo "skip: build first ($BIN/$b missing)"; exit 0; }
done

if [ -z "${SS_E2E_INNER:-}" ]; then
	# The bus must start with the temp HOME already in its environment: it
	# reads the user's service files from there.
	T="$(mktemp -d)"
	export SS_E2E_DIR="$T"
	export HOME="$T/home" XDG_DATA_HOME="$T/home/data" XDG_STATE_HOME="$T/home/state"
	export XDG_CONFIG_HOME="$T/home/config" XDG_RUNTIME_DIR="$T/run" KEPR_LOCK_ON_SLEEP=0
	export KEPR_GATE_BIN="$BIN/kepr-gate"
	mkdir -p "$HOME" "$XDG_CONFIG_HOME/kepr" "$XDG_DATA_HOME" "$XDG_RUNTIME_DIR"
	chmod 700 "$XDG_RUNTIME_DIR"
	SS_E2E_INNER=1 dbus-run-session -- "$0" "$@"
	rc=$?
	rm -rf "$T"
	exit "$rc"
fi

T="$SS_E2E_DIR"
KEPR="$BIN/kepr"
PW="e2e-pass-$$"
FAILS=0
ok() { echo "  ok  $*"; }
# `grep -q` would close the pipe early and, with pipefail, fail the pipeline.
has() { local all; all="$(cat)"; case "$all" in *"$1"*) return 0 ;; esac; return 1; }
bad() { echo "  FAIL $*"; FAILS=$((FAILS + 1)); }
DPID="" SPID=""

cleanup() {
	[ -n "$SPID" ] && kill "$SPID" 2>/dev/null
	[ -n "$DPID" ] && kill "$DPID" 2>/dev/null
	for p in "$T"/pid-*; do [ -f "$p" ] && kill "$(cat "$p")" 2>/dev/null; done
	true
}
trap cleanup EXIT

# The unlock dialog's stand-in: prints whatever passphrase is in $T/pass.
cat >"$T/askpass" <<EOF
#!/bin/sh
echo x >>"$T/asked"
cat "$T/pass"
EOF
chmod 700 "$T/askpass"
printf '%s\n' "$PW" >"$T/pass"
: >"$T/asked"

"$BIN/kepr-daemon" --user >"$T/daemon.log" 2>&1 &
DPID=$!
for _ in $(seq 50); do "$KEPR" status >/dev/null 2>&1 && break; sleep 0.2; done

# Lock the store again (it already has a passphrase: `panic` locks it, as a
# suspend or the idle timer would). The daemon rate-limits each user, so wait
# for the bucket to refill after a burst of requests.
lock_now() {
	sleep 2
	"$KEPR" panic >"$T/lock.out" 2>&1 </dev/null
	sleep 2.5 # the lock watcher
	"$KEPR" status 2>&1 | has "Store: locked" || echo "  ! lock failed: $(cat "$T/lock.out")"
}

start_server() { # env assignments ... (e.g. KEPR_ASKPASS=...)
	[ -n "$SPID" ] && kill "$SPID" 2>/dev/null && wait "$SPID" 2>/dev/null
	env "$@" "$KEPR" secret-service run >"$T/server.log" 2>&1 &
	SPID=$!
	for _ in $(seq 50); do
		"$KEPR" secret-service status 2>&1 | has "served by kepr" && return 0
		sleep 0.2
	done
	return 1
}
stop_server() {
	[ -n "$SPID" ] && kill "$SPID" 2>/dev/null && wait "$SPID" 2>/dev/null
	SPID=""
	sleep 0.3
}

echo "── secret-tool"
start_server KEPR_ASKPASS="$T/askpass" && ok "kepr owns org.freedesktop.secrets" || { bad "the server did not start: $(cat "$T/server.log")"; exit 1; }
printf 'hunter2' | secret-tool store --label="Mail" service imap user alice && ok "store" || bad "store"
[ "$(secret-tool lookup service imap user alice)" = hunter2 ] && ok "lookup returns the secret" || bad "lookup"
printf 'changed' | secret-tool store --label="Mail" service imap user alice
[ "$(secret-tool lookup service imap user alice)" = changed ] && ok "a second store with the same attributes replaces" || bad "replace"
[ "$("$KEPR" secret ls | grep -c .)" = 1 ] && ok "one item, not two" || bad "duplicate item: $("$KEPR" secret ls)"
secret-tool search --all service imap 2>&1 | has "attribute.user = alice" && ok "search shows the attributes" || bad "search: $(secret-tool search --all service imap 2>&1 | head -5)"
secret-tool lookup service imap user nobody >/dev/null 2>&1 && bad "lookup of a missing item succeeded" || ok "a missing item is not found"

if python3 -c "import secretstorage" 2>/dev/null; then
	out="$(python3 - <<'PY'
import secretstorage
conn = secretstorage.dbus_init()
c = secretstorage.get_default_collection(conn)
raw = bytes(range(256))
it = c.create_item("Binary", {"app": "e2e", "kind": "bytes"}, raw, replace=True)
back = it.get_secret()
print("bytes-ok" if back == raw else "bytes-differ")
it.set_label("Renamed")
print("label-ok" if it.get_label() == "Renamed" else "label-differ")
it.delete()
print("deleted-ok" if not list(c.search_items({"app": "e2e"})) else "still-there")
PY
)"
	case "$out" in *bytes-ok*) ok "arbitrary bytes survive a DH-encrypted session";; *) bad "DH session: $out";; esac
	case "$out" in *label-ok*) ok "a label can be changed";; *) bad "label: $out";; esac
	case "$out" in *deleted-ok*) ok "an item can be deleted";; *) bad "delete: $out";; esac
else
	echo "  –  SKIP: python3 SecretStorage not installed (DH session check)"
fi

echo "── the store and the log"
"$KEPR" ls 2>&1 | has "Secret Service item" && ok "kepr ls folds the items into one line" || bad "kepr ls: $("$KEPR" ls 2>&1)"
"$KEPR" ls 2>&1 | has "SSI_" && bad "kepr ls lists the item credentials" || ok "no SSI_ credential in kepr ls"
id="$("$KEPR" ls --folder secret-service 2>/dev/null | grep -o 'SSI_[A-Z2-7]*' | head -1)"
[ -n "$id" ] && ok "kepr ls --folder secret-service shows them" || bad "no items in the folder listing"
"$KEPR" get "$id" >/dev/null 2>&1 && bad "kepr get read a Secret Service item" || ok "kepr get refuses an item (use kepr secret lookup)"
[ "$("$KEPR" secret lookup service imap user alice)" = changed ] && ok "kepr secret lookup reads it" || bad "kepr secret lookup"
"$KEPR" secret-service log | has "secret-tool" && ok "the log names the program" || bad "log: $("$KEPR" secret-service log)"
"$KEPR" secret-service log | has "changed" && bad "the log shows a secret" || ok "no secret in the log"

echo "── locked"
# The first lock sets the passphrase (asked twice) and locks the store.
sleep 2 # let the daemon's per-user rate limit refill
lockout="$(printf '%s\n%s\n' "$PW" "$PW" | "$KEPR" lock 2>&1)"
sleep 2.5 # the lock watcher
"$KEPR" status 2>&1 | has "Store: locked" && ok "kepr is locked" || bad "kepr did not lock: $lockout"
[ "$(secret-tool lookup service imap user alice)" = changed ] && ok "a lookup while locked asks for the passphrase and then answers" || bad "locked lookup"
"$KEPR" status 2>&1 | has "Store: unlocked" && ok "and kepr is unlocked now" || bad "still locked"
lock_now
printf 'wrong-%s\n' "$PW" >"$T/pass"
secret-tool lookup service imap user alice >/dev/null 2>&1 && bad "a wrong passphrase opened it" || ok "a wrong passphrase is refused"
"$KEPR" secret-service log | has "refused" && ok "and the refusal is logged" || bad "no refusal in the log"
printf '%s\n' "$PW" >"$T/pass"
sleep 11 # the daemon backs off after wrong passphrases
[ "$(secret-tool lookup service imap user alice)" = changed ] && ok "the right passphrase opens it on the next ask" || bad "lookup with the right passphrase"

echo "── a server that starts while kepr is locked"
lock_now
stop_server
printf 'wrong-%s\n' "$PW" >"$T/pass"
start_server KEPR_ASKPASS="$T/askpass" >/dev/null
secret-tool lookup service imap user alice >/dev/null 2>&1 && bad "a cold start opened with a wrong passphrase" || ok "the first call after a cold start asks, and a wrong passphrase fails it"
asked="$(wc -l <"$T/asked")"
secret-tool lookup service imap user alice >/dev/null 2>&1 && bad "opened with a wrong passphrase" || ok "an immediate retry fails too"
[ "$(wc -l <"$T/asked")" = "$asked" ] && ok "without showing the dialog again (cool-down)" || bad "the dialog was shown again at once"
printf '%s\n' "$PW" >"$T/pass"
sleep 11 # the cool-down after a refusal
[ "$(secret-tool lookup service imap user alice)" = changed ] && ok "after the cool-down the right passphrase opens it" || bad "lookup after the cool-down"

echo "── policy"
cat >"$XDG_CONFIG_HOME/kepr/secret-service.toml" <<'EOF'
[[rule]]
exe = "*/secret-tool"
op = "read"
action = "deny"
EOF
kill -HUP "$SPID"
sleep 1
secret-tool lookup service imap user alice >/dev/null 2>&1 && bad "the policy did not refuse secret-tool" || ok "a rule refuses the program (after SIGHUP)"
secret-tool search --all service imap >/dev/null 2>&1 && ok "searching is still allowed" || bad "search refused"
"$KEPR" secret-service policy check /usr/bin/secret-tool read | has Deny && ok "policy check agrees" || bad "policy check"
rm -f "$XDG_CONFIG_HOME/kepr/secret-service.toml"
kill -HUP "$SPID"
sleep 1
[ "$(secret-tool lookup service imap user alice)" = changed ] && ok "removing the file allows it again" || bad "lookup after removing the policy"

echo "── takeover: the bus starts kepr"
stop_server
"$KEPR" secret-service takeover --no-import >"$T/takeover.log" 2>&1 && ok "takeover" || bad "takeover failed: $(cat "$T/takeover.log")"
[ -f "$XDG_DATA_HOME/dbus-1/services/org.freedesktop.secrets.service" ] && ok "the bus service file is written" || bad "no bus service file"
[ "$(KEPR_ASKPASS="$T/askpass" secret-tool lookup service imap user alice)" = changed ] && ok "a program asking an empty bus gets kepr, started by the bus" || bad "activation: $(cat "$T/server.log" 2>/dev/null)"
"$KEPR" secret-service status 2>&1 | has "takeover: on" && ok "status says takeover is on" || bad "status"
"$KEPR" secret-service restore >/dev/null 2>&1 && ok "restore" || bad "restore"
[ -f "$XDG_DATA_HOME/dbus-1/services/org.freedesktop.secrets.service" ] && bad "restore left the service file" || ok "restore removes the service file"
# The activated server is still running; let it go.
owner="$("$KEPR" secret-service status 2>&1 | sed -n 's/.*(pid \([0-9][0-9]*\)).*/\1/p' | head -1)"
if [ -n "$owner" ]; then kill "$owner" 2>/dev/null; else bad "cannot find the activated server's pid"; fi
sleep 0.7

echo "── import from another provider"
# Another kepr profile is the "old keyring"; the default profile is the target.
SRC="e2esrc$$"
env KEPR_PROFILE="$SRC" "$BIN/kepr-daemon" --user >"$T/src-daemon.log" 2>&1 &
echo $! >"$T/pid-srcd"
for _ in $(seq 50); do env KEPR_PROFILE="$SRC" "$KEPR" status >/dev/null 2>&1 && break; sleep 0.2; done
env KEPR_PROFILE="$SRC" "$KEPR" secret-service run >"$T/src-server.log" 2>&1 &
echo $! >"$T/pid-src"
for _ in $(seq 50); do "$KEPR" secret-service status 2>&1 | has "served by kepr" && break; sleep 0.2; done
printf 'one' | secret-tool store --label="Imported A" site a.example user u
printf 'two' | secret-tool store --label="Imported B" site b.example user u
"$KEPR" secret-service import --dry-run >"$T/dry.log" 2>&1
grep -q "would import" "$T/dry.log" && ok "a dry run lists what it would import" || bad "dry run: $(cat "$T/dry.log")"
grep -q -e one -e two "$T/dry.log" && bad "the dry run printed a secret" || ok "and prints no secret"
"$KEPR" secret ls 2>/dev/null | has "Imported A" && bad "the dry run wrote" || ok "a dry run writes nothing"
"$KEPR" secret-service import >"$T/import.log" 2>&1 && ok "import" || bad "import: $(cat "$T/import.log")"
[ "$("$KEPR" secret lookup site a.example user u)" = one ] && [ "$("$KEPR" secret lookup site b.example user u)" = two ] && ok "both items arrived with their secrets" || bad "imported secrets differ"
"$KEPR" secret-service import 2>&1 | has "imported 0" && ok "a second import changes nothing" || bad "second import"
kill "$(cat "$T/pid-src")" 2>/dev/null
rm -f "$T/pid-src"
sleep 0.5

echo "── a sandboxed agent cannot reach the bus"
start_server KEPR_ASKPASS="$T/askpass" >/dev/null
if printf 'sk-ant-api03-%s' abcdefghijklmnopqrstuvwxyz0123456789 | "$KEPR" agent add ANTHROPIC_API_KEY --stdin >/dev/null 2>&1 && [ -x "$BIN/kepr-gate" ]; then
	out="$("$KEPR" agent run claude --strict-sandbox -- sh -c 'secret-tool lookup service imap user alice; echo rc=$?' 2>&1)"
	case "$out" in
	*rc=0*) bad "a sandboxed program read the secret: $out" ;;
	*rc=*) ok "inside the sandbox the lookup fails" ;;
	*) echo "  –  SKIP: the sandbox did not start here: $out" ;;
	esac
	out="$(KEPR_SANDBOX_DBUS=allow "$KEPR" agent run claude --strict-sandbox -- sh -c 'secret-tool lookup service imap user alice; echo rc=$?' 2>&1)"
	case "$out" in *rc=0*) ok "KEPR_SANDBOX_DBUS=allow leaves the bus reachable"; "$KEPR" secret-service log | has sandboxed && ok "and the log marks the caller as sandboxed" || bad "no [sandboxed] mark";; *) echo "  –  SKIP: $out";; esac
else
	echo "  –  SKIP: cannot seal a key or find kepr-gate"
fi

echo
[ "$FAILS" = 0 ] && echo "passed" || { echo "$FAILS failure(s)"; exit 1; }
