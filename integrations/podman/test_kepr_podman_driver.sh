#!/usr/bin/env bash
# Tests for kepr-podman-driver (T10.07) against a fake `kepr` that keeps
# values in files. Drives the commands the way Podman's shell driver does:
# /bin/sh -c with SECRET_ID set, data on stdin for store.
# Run: bash integrations/podman/test_kepr_podman_driver.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRIVER="$HERE/kepr-podman-driver"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/store"
FAILS=0

fail() {
	echo "FAIL: $*"
	FAILS=$((FAILS + 1))
}
ok() { echo "ok: $*"; }
# check DESCRIPTION COMMAND...: ok when COMMAND succeeds.
check() {
	local d="$1"
	shift
	if "$@"; then ok "$d"; else fail "$d"; fi
}

# Fake kepr: set --stdin (drops one newline), get --quiet (adds one),
# delete --force, list --json (pretty, like the real one). Logs argv.
cat >"$T/bin/kepr" <<'FAKE'
#!/usr/bin/env bash
echo "kepr $*" >>"$FAKE_DIR/log"
case "$1" in
set)
	[ "$3" = "--stdin" ] || exit 2
	v="$(cat; printf x)"
	v="${v%x}"
	printf '%s' "${v%$'\n'}" >"$FAKE_DIR/store/$2"
	;;
get)
	[ "$3" = "--quiet" ] || exit 2
	[ -f "$FAKE_DIR/store/$2" ] || { echo "credential unavailable" >&2; exit 1; }
	cat "$FAKE_DIR/store/$2"
	echo
	;;
delete) rm -f "$FAKE_DIR/store/$2" ;;
list)
	printf '{\n  "kind": "list_ok",\n  "credentials": [\n'
	for f in "$FAKE_DIR"/store/*; do
		[ -e "$f" ] || continue
		n="$(basename "$f")"
		printf '    {\n      "name": "%s",\n      "cred_name": "kepr-0-%s"\n    },\n' "$n" "${n,,}"
	done
	printf '  ]\n}\n'
	;;
esac
FAKE
chmod +x "$T/bin/kepr"

# Run one driver operation as Podman would.
drive() {
	local op="$1" id="$2"
	env -i PATH="$T/bin:/usr/bin:/bin" FAKE_DIR="$T" SECRET_ID="$id" \
		/bin/sh -c "\"$DRIVER\" $op"
}

ID=0a1b2c3d4e5f60718293a4b5c
# ── store + lookup round trip (exact bytes, no added newline) ──
printf 'p@ss word\nline2' | drive store "$ID"
if [ "$(cat "$T/store/PODMAN_0A1B2C3D4E5F60718293A4B5C")" = $'p@ss word\nline2' ]; then
	ok "store keeps the value under PODMAN_<ID>"
else
	fail "stored: $(ls "$T/store")"
fi
drive lookup "$ID" >"$T/out"
if cmp -s "$T/out" <(printf 'p@ss word\nline2'); then ok "lookup prints the exact value"; else fail "lookup: $(od -c "$T/out")"; fi

# ── the documented dry run: the lookup command line with a fake kepr ──
: >"$T/log"
drive lookup "$ID" >/dev/null
if grep -qx "kepr get PODMAN_0A1B2C3D4E5F60718293A4B5C --quiet" "$T/log"; then
	ok "lookup runs kepr get NAME --quiet"
else
	fail "kepr calls: $(cat "$T/log")"
fi

# ── references follow the current value of another credential ──
printf 'v1' >"$T/store/DB_PASS"
printf 'kepr://DB_PASS' | drive store abc123
check "kepr://NAME reference resolves" test "$(drive lookup abc123)" = "v1"
printf 'v2' >"$T/store/DB_PASS"
check "reference sees rotation" test "$(drive lookup abc123)" = "v2"

# ── list: lowercase podman ids, only PODMAN_ credentials ──
got="$(drive list "" | sort | tr '\n' ' ')"
check "list prints podman ids ($got)" test "$got" = "0a1b2c3d4e5f60718293a4b5c abc123 "

# ── delete ──
drive delete abc123
check "delete removes it" test ! -e "$T/store/PODMAN_ABC123"
check "delete leaves the referenced credential" test -e "$T/store/DB_PASS"

# ── refusals ──
for bad in "" "../x" "ABC" "a b" 'x;rm' "$(printf 'a%.0s' {1..101})"; do
	if drive lookup "$bad" >/dev/null 2>&1; then fail "accepted SECRET_ID=$bad"; fi
done
ok "non-hex SECRET_IDs are refused"
if drive lookup ffff >"$T/out" 2>"$T/err"; then fail "missing secret looked up"; else ok "missing secret fails"; fi
check "nothing on stdout for a failure" test ! -s "$T/out"
if drive bogus "$ID" 2>/dev/null; then fail "unknown op accepted"; else ok "unknown op refused"; fi

if [ "$FAILS" -ne 0 ]; then
	echo "$FAILS failure(s)"
	exit 1
fi
echo "all passed"
