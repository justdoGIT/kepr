#!/usr/bin/env bash
# pam_e2e.sh — pam_kepr.so against a real PAM stack (pamtester).
#
# Needs root, pamtester and a built tree:
#   cargo build --workspace
#   cargo build --release --manifest-path crates/kepr-pam/Cargo.toml
# Makes a throwaway user and PAM service, starts that user's daemon with a
# store protected by the user's login password, then checks that logging in
# through PAM unlocks it (and that a wrong password, an untrusted kepr
# binary and root do not). Removes everything on exit.
set -uo pipefail
cd "$(dirname "$0")/.."
[ "$(id -u)" = 0 ] || { echo "skip: needs root"; exit 0; }
command -v pamtester >/dev/null || { echo "skip: pamtester not installed"; exit 0; }
BIN="${KEPR_BIN_DIR:-$PWD/target/debug}"
SO="$PWD/crates/kepr-pam/target/release/libpam_kepr.so"
[ -x "$BIN/kepr" ] && [ -x "$BIN/kepr-daemon" ] && [ -f "$SO" ] || { echo "skip: build first (see header)"; exit 0; }

USERN="keprpam$$"
SVC="kepr-pam-test-$$"
PW="Login-pass-$$"
T="$(mktemp -d)"
chmod 755 "$T"
FAILS=0
ok() { echo "  ok  $*"; }
bad() { echo "  FAIL $*"; FAILS=$((FAILS + 1)); }

cleanup() {
	pkill -u "$USERN" kepr-daemon 2>/dev/null
	rm -f "/etc/pam.d/$SVC"
	userdel -r "$USERN" 2>/dev/null
	rm -rf "$T"
}
trap cleanup EXIT

# Root-owned, closed copies: pam_kepr runs only a binary like that.
install -m 755 -o root "$BIN/kepr" "$T/kepr"
install -m 755 -o root "$BIN/kepr-daemon" "$T/kepr-daemon"
install -m 777 -o root "$BIN/kepr" "$T/kepr-open" # group/other writable: refused
cp "$SO" "$T/pam_kepr.so"

useradd -m "$USERN" && echo "$USERN:$PW" | chpasswd
UID_N="$(id -u "$USERN")"
mkdir "$T/log" && chown "$USERN" "$T/log"
mkdir -p "/run/user/$UID_N" && chown "$USERN" "/run/user/$UID_N" && chmod 700 "/run/user/$UID_N"
as_user() { su "$USERN" -s /bin/bash -c "export XDG_RUNTIME_DIR=/run/user/$UID_N HOME=$(getent passwd "$USERN" | cut -d: -f6); $*"; }

service() { # $1: kepr binary the module may run
	cat >"/etc/pam.d/$SVC" <<CONF
auth     required  pam_unix.so
auth     optional  $T/pam_kepr.so kepr=$1
account  required  pam_permit.so
session  optional  $T/pam_kepr.so kepr=$1
session  required  pam_permit.so
CONF
}
start_locked_daemon() {
	pkill -u "$USERN" kepr-daemon 2>/dev/null
	sleep 1
	as_user "nohup $T/kepr-daemon --user >$T/log/daemon.log 2>&1 &"
	sleep 2
}
daemon_up() { as_user "$T/kepr status --json" | grep -q '"kind": "status_ok"'; }
locked() { as_user "$T/kepr status --json" | grep -q '"locked": true'; }
wait_unlocked() {
	for _ in 1 2 3 4 5 6 7 8; do
		sleep 1
		locked || return 0
	done
	return 1
}

# A store protected by the login password.
as_user "nohup $T/kepr-daemon --user >$T/log/daemon.log 2>&1 &"
sleep 2
as_user "printf '%s\n%s\n' '$PW' '$PW' | $T/kepr lock" >/dev/null 2>&1

echo "── pam_kepr"
service "$T/kepr"
start_locked_daemon
daemon_up && locked && ok "the daemon is up and the store starts locked" || bad "no daemon, or the store did not start locked"
printf '%s\n' "$PW" | pamtester "$SVC" "$USERN" authenticate open_session >/dev/null 2>&1 && ok "login succeeds" || bad "login failed"
wait_unlocked && ok "the login password unlocked the store" || bad "still locked after login"

start_locked_daemon
printf '%s\n' "wrong-$PW" | pamtester "$SVC" "$USERN" authenticate open_session >/dev/null 2>&1 && bad "a wrong password logged in"
sleep 4
locked && ok "a wrong login password leaves it locked" || bad "unlocked without the password"

service "$T/kepr-open"
start_locked_daemon
printf '%s\n' "$PW" | pamtester "$SVC" "$USERN" authenticate open_session >/dev/null 2>&1 && ok "login still succeeds" || bad "login failed with an untrusted kepr"
sleep 5
locked && ok "an untrusted kepr binary is never run" || bad "ran a group/other-writable kepr"

echo
[ "$FAILS" = 0 ] && echo "passed" || { echo "$FAILS failure(s)"; exit 1; }
