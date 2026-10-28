#!/usr/bin/env bash
# pam_e2e.sh — pam_kepr.so against a real PAM stack (pamtester + libpam).
#
# Needs root, pamtester, python3 and a built tree:
#   cargo build --workspace
#   cargo build --release --manifest-path crates/kepr-pam/Cargo.toml
# Makes two throwaway users and PAM services, starts each user's daemon with a
# store protected by the (shared) login password, and checks that:
#   * a login unlocks the store only when the user turned login unlock on,
#     only with the right password, only through a root-owned kepr;
#   * a session for another user (sudo -u) is never given the password;
#   * a changed password moves the store passphrase (passwd, and an expired
#     password changed at login), and the new one opens the store;
#   * the screen-lock options unlock, and a login with no password says why
#     kepr stays locked;
#   * no daemon at all never delays or fails a login.
# Removes everything on exit.
# shellcheck disable=SC2015  # `check && ok || bad` reports; ok never fails
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
[ "$(id -u)" = 0 ] || { echo "skip: needs root"; exit 0; }
command -v pamtester >/dev/null || { echo "skip: pamtester not installed"; exit 0; }
command -v python3 >/dev/null || { echo "skip: python3 not installed"; exit 0; }
command -v cc >/dev/null || { echo "skip: needs a C compiler for tests/pam_setitems.c"; exit 0; }
BIN="${KEPR_BIN_DIR:-$PWD/target/debug}"
SO="$PWD/crates/kepr-pam/target/release/libpam_kepr.so"
[ -x "$BIN/kepr" ] && [ -x "$BIN/kepr-daemon" ] && [ -f "$SO" ] || { echo "skip: build first (see header)"; exit 0; }

A="keprpam$$"
B="keprpamb$$"
SVC="kepr-pam-test-$$"
PW="Login-pass-$$"
PW2="New-login-pass-$$"
T="$(mktemp -d)"
chmod 755 "$T"
FAILS=0
ok() { echo "  ok  $*"; }
bad() { echo "  FAIL $*"; FAILS=$((FAILS + 1)); }

cleanup() {
	pkill -u "$A" kepr-daemon 2>/dev/null
	pkill -u "$B" kepr-daemon 2>/dev/null
	rm -f "/etc/pam.d/$SVC" "/etc/pam.d/$SVC-h"
	userdel -r "$A" 2>/dev/null
	userdel -r "$B" 2>/dev/null
	rm -rf "$T"
}
trap cleanup EXIT

# Root-owned, closed copies: pam_kepr runs only a binary like that.
install -m 755 -o root "$BIN/kepr" "$T/kepr"
install -m 755 -o root "$BIN/kepr-daemon" "$T/kepr-daemon"
install -m 777 -o root "$BIN/kepr" "$T/kepr-open" # group/other writable: refused
cp "$SO" "$T/pam_kepr.so"
cc -shared -fPIC -o "$T/pam_setitems.so" tests/pam_setitems.c || { echo "skip: cannot build tests/pam_setitems.c"; exit 0; }

for u in "$A" "$B"; do
	useradd -m "$u" && echo "$u:$PW" | chpasswd
	n="$(id -u "$u")"
	mkdir "$T/log-$u" && chown "$u" "$T/log-$u"
	mkdir -p "/run/user/$n" && chown "$u" "/run/user/$n" && chmod 700 "/run/user/$n"
done
as_user() { # $1 user, $2 shell command
	local n h
	n="$(id -u "$1")"
	h="$(getent passwd "$1" | cut -d: -f6)"
	su "$1" -s /bin/bash -c "export XDG_RUNTIME_DIR=/run/user/$n HOME=$h; $2"
}

# $1: kepr binary the module may run; $2...: module options
service() {
	local k="$1"
	shift
	local m="$T/pam_kepr.so kepr=$k $*"
	cat >"/etc/pam.d/$SVC" <<CONF
auth     required  pam_unix.so
auth     optional  $m
account  required  pam_permit.so
session  optional  $m
session  required  pam_permit.so
CONF
	# The same without a password check, so a step can set the items itself.
	cat >"/etc/pam.d/$SVC-h" <<CONF
auth     required  $T/pam_setitems.so
auth     optional  $m
account  required  pam_permit.so
password required  $T/pam_setitems.so
password optional  $m
session  optional  $m
session  required  pam_permit.so
CONF
}
start_locked_daemon() { # $1 user
	pkill -u "$1" kepr-daemon 2>/dev/null
	sleep 1
	as_user "$1" "nohup $T/kepr-daemon --user >$T/log-$1/daemon.log 2>&1 &"
	sleep 2
}
daemon_up() { as_user "$1" "$T/kepr status --json" | grep -q '"kind": "status_ok"'; }
locked() { as_user "$1" "$T/kepr status --json" | grep -q '"locked": true'; }
wait_unlocked() { # $1 user
	for _ in 1 2 3 4 5 6 7 8; do
		sleep 1
		locked "$1" || return 0
	done
	return 1
}
harness() { python3 tests/pam_harness.py "$SVC-h" "$@"; }
unlock_with() { as_user "$1" "printf '%s\n' '$2' | $T/kepr unlock" >/dev/null 2>&1; }

# A store protected by the login password, for both users.
for u in "$A" "$B"; do
	as_user "$u" "nohup $T/kepr-daemon --user >$T/log-$u/daemon.log 2>&1 &"
	sleep 2
	as_user "$u" "printf '%s\n%s\n' '$PW' '$PW' | $T/kepr lock" >/dev/null 2>&1
	as_user "$u" "$T/kepr login-unlock on" >/dev/null 2>&1
done

echo "── logins"
service "$T/kepr"
start_locked_daemon "$A"
daemon_up "$A" && locked "$A" && ok "the daemon is up and the store starts locked" || bad "no daemon, or the store did not start locked"
printf '%s\n' "$PW" | pamtester "$SVC" "$A" authenticate open_session >/dev/null 2>&1 && ok "login succeeds" || bad "login failed"
wait_unlocked "$A" && ok "the login password unlocked the store" || bad "still locked after login"

start_locked_daemon "$A"
printf '%s\n' "wrong-$PW" | pamtester "$SVC" "$A" authenticate open_session >/dev/null 2>&1 && bad "a wrong password logged in"
sleep 4
locked "$A" && ok "a wrong login password leaves it locked" || bad "unlocked without the password"

as_user "$A" "$T/kepr login-unlock off" >/dev/null 2>&1
start_locked_daemon "$A"
printf '%s\n' "$PW" | pamtester "$SVC" "$A" authenticate open_session >/dev/null 2>&1 && ok "login succeeds with login unlock off" || bad "login failed"
sleep 4
locked "$A" && ok "login unlock off: the password is not used" || bad "unlocked although login unlock is off"
as_user "$A" "$T/kepr login-unlock on" >/dev/null 2>&1

service "$T/kepr-open"
start_locked_daemon "$A"
printf '%s\n' "$PW" | pamtester "$SVC" "$A" authenticate open_session >/dev/null 2>&1 && ok "login still succeeds" || bad "login failed with an untrusted kepr"
sleep 5
locked "$A" && ok "an untrusted kepr binary is never run" || bad "ran a group/other-writable kepr"

echo "── another user's session (sudo -u)"
service "$T/kepr"
start_locked_daemon "$A"
start_locked_daemon "$B"
# Both stores have the same passphrase: if A's password were handed to B's
# kepr, B would open.
harness "$A" authtok="$PW" auth user="$B" open >/dev/null
sleep 5
locked "$B" && ok "the session for another user got no password" || bad "A's password unlocked B's store"
harness "$A" authtok="$PW" auth open >/dev/null
wait_unlocked "$A" && ok "the same login for the right user unlocks" || bad "right user did not unlock"

echo "── screen lock and hints"
service "$T/kepr" unlock
start_locked_daemon "$A"
harness "$A" authtok="$PW" auth setcred >/dev/null
wait_unlocked "$A" && ok "unlock: pam_setcred hands the password over" || bad "setcred did not unlock"
service "$T/kepr" unlock=auth
start_locked_daemon "$A"
harness "$A" authtok="$PW" auth >/dev/null
wait_unlocked "$A" && ok "unlock=auth: the authentication hook unlocks" || bad "auth did not unlock"
service "$T/kepr" hint
start_locked_daemon "$A"
out="$(harness "$A" open)"
echo "$out" | grep -q "INFO: kepr: no password was typed.*kepr unlock" && ok "a login without a password says kepr stays locked" || bad "no hint: $out"
out="$(harness "$B" open)"
echo "$out" | grep -q "INFO: kepr" && ok "hint for a user with the store locked" || bad "no hint for B: $out"
unlock_with "$A" "$PW"
out="$(harness "$A" open)"
echo "$out" | grep -q "INFO" && bad "hint although kepr is unlocked: $out" || ok "no hint when kepr is already unlocked"

echo "── password changes"
service "$T/kepr"
start_locked_daemon "$A"
out="$(harness "$A" oldtok="$PW" authtok="$PW2" chauthtok)"
echo "$out" | grep -q "INFO: kepr: the store passphrase follows" && ok "passwd tells the user kepr followed" || bad "no message: $out"
start_locked_daemon "$A"
unlock_with "$A" "$PW"
locked "$A" && ok "the old password no longer opens the store" || bad "old password still opens it"
sleep 2 # the wrong one backs the next attempt off for a second
unlock_with "$A" "$PW2"
locked "$A" && bad "the new password does not open the store" || ok "the new login password opens the store"

# An expired password changed during the login: the session uses the new one.
start_locked_daemon "$A"
harness "$A" authtok="$PW2" auth oldtok="$PW2" authtok="$PW" chauthtok open >/dev/null
wait_unlocked "$A" && ok "expired password: the session unlocks with the new one" || bad "expired-password login did not unlock"

# A refused change leaves the login working and says why.
start_locked_daemon "$A"
out="$(harness "$A" oldtok="not-$PW" authtok="$PW2" chauthtok)"
echo "$out" | grep -q "INFO: kepr: the store passphrase was not changed" && ok "a refused change is explained" || bad "no explanation: $out"
echo "$out" | grep -q "chauthtok=0" && ok "and the password change itself still succeeds" || bad "chauthtok failed: $out"

echo "── kepr never decides a login"
pkill -u "$A" kepr-daemon 2>/dev/null
sleep 1
t0="$(date +%s%N)"
printf '%s\n' "$PW" | pamtester "$SVC" "$A" authenticate open_session >/dev/null 2>&1 && ok "login succeeds with no daemon" || bad "login failed with no daemon"
ms=$((($(date +%s%N) - t0) / 1000000))
[ "$ms" -lt 3000 ] && ok "and is not held up (${ms} ms)" || bad "login took ${ms} ms with no daemon"
t0="$(date +%s%N)"
out="$(harness "$A" oldtok="$PW" authtok="$PW2" chauthtok)"
ms=$((($(date +%s%N) - t0) / 1000000))
echo "$out" | grep -q "chauthtok=0" && ok "passwd succeeds with no daemon" || bad "passwd failed with no daemon: $out"
[ "$ms" -lt 5000 ] && ok "and is not held up (${ms} ms)" || bad "passwd took ${ms} ms with no daemon"
echo "$out" | grep -q "INFO: kepr: it is not running" && ok "and says the passphrase is unchanged" || bad "no message: $out"

echo
[ "$FAILS" = 0 ] && echo "passed" || { echo "$FAILS failure(s)"; exit 1; }
