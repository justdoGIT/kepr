#!/usr/bin/env bash
# Tests for kepr-ci.sh (plan T8.07): masking, pull/export, input checks,
# OIDC exchanges with a stub curl, and the GitLab template's embedded copy.
# Needs bash, jq. Run: bash integrations/ci/test_kepr_ci.sh
# Assertions use `check && ok || fail` on purpose (ok never fails), and
# single-quoted snippets are expanded by the inner shell.
# shellcheck disable=SC2015,SC2016
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB="$HERE/kepr-ci.sh"
GITLAB="$HERE/../gitlab/kepr.gitlab-ci.yml"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin"
FAILS=0

fail() {
	echo "FAIL: $*"
	FAILS=$((FAILS + 1))
}
ok() { echo "ok: $*"; }

# Stub kepr: logs its argv; `get` prints a two-line value with a % in it.
cat >"$T/bin/kepr" <<'EOF'
#!/usr/bin/env bash
echo "kepr $*" >>"$KEPR_STUB_LOG"
case "$1" in
get) printf 'v-%s one\nline%%2-%s\n' "$2" "$2" ;;
esac
EOF
chmod +x "$T/bin/kepr"

# Run the library in a subshell with a clean environment.
run_lib() {
	env -i PATH="$T/bin:$PATH" HOME="$T" KEPR_STUB_LOG="$T/kepr.log" KEPR_CI_START_DAEMON=false "$@" \
		bash -c 'KEPR_CI_LIB=1 source "$0"; '"${CMD:-kepr_ci_main run}" "$LIB"
}

# ── masking ──
out="$(CMD='kepr_ci_mask "$V"' run_lib GITHUB_ACTIONS=true V=$'a%b\n\n   \nsecond line\r')"
expected=$'::add-mask::a%25b\n::add-mask::second line'
[ "$out" = "$expected" ] && ok "mask escapes % and masks each non-blank line" || fail "mask output: $out"
out="$(CMD='kepr_ci_mask "$V"' run_lib V=secret)"
[ -z "$out" ] && ok "no mask commands outside GitHub" || fail "masked outside GitHub: $out"

# ── pull, no export ──
: >"$T/kepr.log"
: >"$T/env"
SECRETS=$'# comment\ndb_pass = aws-sm:prod/db\n\nAPI=vault:secret/api # trailing'
out="$(run_lib GITHUB_ACTIONS=true GITHUB_ENV="$T/env" KEPR_SECRETS="$SECRETS" 2>"$T/err")"
grep -qx 'kepr sync-pull DB_PASS --url aws-sm:prod/db' "$T/kepr.log" &&
	grep -qx 'kepr sync-pull API --url vault:secret/api' "$T/kepr.log" && ok "sync-pull per line, names upper-cased" ||
	fail "kepr calls: $(cat "$T/kepr.log")"
for want in '::add-mask::v-DB_PASS one' '::add-mask::line%252-DB_PASS' '::add-mask::v-API one' '::add-mask::line%252-API'; do
	grep -qxF "$want" <<<"$out" || fail "missing mask $want"
done
if grep -v '^::add-mask::' <<<"$out" | grep -q 'v-'; then fail "a value was printed unmasked"; else ok "values only appear in mask commands"; fi
grep -q 'v-' "$T/err" && fail "a value reached stderr" || ok "stderr carries no value"
[ -s "$T/env" ] && fail "GITHUB_ENV written without KEPR_EXPORT" || ok "nothing exported unless asked"

# ── pull, export ──
: >"$T/env"
run_lib GITHUB_ACTIONS=true GITHUB_ENV="$T/env" KEPR_EXPORT=true KEPR_SECRETS='X=gcp-sm:projects/p/secrets/x' >/dev/null 2>&1
delim="$(sed -n '1s/^X<<//p' "$T/env")"
if [[ "$delim" =~ ^KEPR_EOF_[0-9a-f]{32}$ ]] && [ "$(sed -n 2p "$T/env")" = "v-X one" ] &&
	[ "$(sed -n 3p "$T/env")" = "line%2-X" ] && [ "$(sed -n 4p "$T/env")" = "$delim" ]; then
	ok "export writes a multi-line heredoc entry"
else
	fail "GITHUB_ENV: $(cat "$T/env")"
fi

# ── bad input never reaches kepr ──
for bad in 'BAD-NAME=vault:x' 'NAME' 'NAME=noscheme' '../x=vault:a' ''; do
	: >"$T/kepr.log"
	if run_lib KEPR_SECRETS="$bad" >/dev/null 2>&1; then fail "accepted: '$bad'"; fi
	[ -s "$T/kepr.log" ] && fail "kepr called for '$bad'"
done
ok "invalid secret specs are refused before any pull"

out="$(CMD='kepr_ci_names' run_lib KEPR_SECRETS=$'A=vault:a\n# B=vault:b\nc=aws-sm:c')"
[ "$out" = "A,c" ] && ok "names CSV" || fail "names: $out"

# ── OIDC logins with a stub curl ──
cat >"$T/bin/curl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$T_CURL_ARGV"
stdin="$(cat)"
printf '%s\n' "$stdin" >>"$T_CURL_STDIN"
case "$*" in
*sts.amazonaws.com*) echo '{"AssumeRoleWithWebIdentityResponse":{"AssumeRoleWithWebIdentityResult":{"Credentials":{"AccessKeyId":"AKIAEXAMPLE","SecretAccessKey":"aws-secret-key","SessionToken":"aws-session"}}}}' ;;
*/v1/auth/jwt/login*) echo '{"auth":{"client_token":"hvs.vault-token"}}' ;;
*sts.googleapis.com*) echo '{"access_token":"gcp-federated"}' ;;
*iamcredentials*) echo '{"accessToken":"gcp-sa-token"}' ;;
esac
EOF
chmod +x "$T/bin/curl"
JWT="eyJ.jwt-secret.sig"
login() {
	: >"$T/argv"
	: >"$T/stdin"
	CMD="kepr_ci_login; env" run_lib GITHUB_ACTIONS=true T_CURL_ARGV="$T/argv" T_CURL_STDIN="$T/stdin" KEPR_ID_TOKEN="$JWT" "$@"
}
out="$(login KEPR_CLOUD=aws KEPR_AWS_ROLE_ARN=arn:aws:iam::1:role/r AWS_REGION=us-east-1)"
grep -qx 'AWS_SECRET_ACCESS_KEY=aws-secret-key' <<<"$out" && grep -qx '::add-mask::aws-secret-key' <<<"$out" &&
	grep -qx '::add-mask::aws-session' <<<"$out" && ok "aws: credentials exported and masked" || fail "aws: $out"
grep -qF "$JWT" "$T/argv" && fail "aws: JWT on curl's command line" || ok "aws: JWT not in argv"
grep -qF "$JWT" "$T/stdin" && ok "aws: JWT sent on stdin" || fail "aws: JWT not sent"

out="$(login KEPR_CLOUD=vault VAULT_ADDR=https://vault.example KEPR_VAULT_ROLE=ci)"
grep -qx 'VAULT_TOKEN=hvs.vault-token' <<<"$out" && grep -qx '::add-mask::hvs.vault-token' <<<"$out" &&
	ok "vault: token exported and masked" || fail "vault: $out"
grep -qF "$JWT" "$T/argv" && fail "vault: JWT in argv" || ok "vault: JWT not in argv"

out="$(login KEPR_CLOUD=gcp KEPR_GCP_WIF_PROVIDER=projects/1/locations/global/workloadIdentityPools/p/providers/x \
	KEPR_GCP_SERVICE_ACCOUNT=ci@p.iam.gserviceaccount.com)"
grep -qx 'GCP_ACCESS_TOKEN=gcp-sa-token' <<<"$out" && grep -qx '::add-mask::gcp-federated' <<<"$out" &&
	ok "gcp: impersonated token exported, federated token masked" || fail "gcp: $out"
grep -q 'gcp-federated' "$T/argv" && fail "gcp: bearer token in argv" || ok "gcp: bearer token not in argv"

if run_lib KEPR_CLOUD=azure >/dev/null 2>&1; then fail "unknown cloud accepted"; else ok "unknown cloud refused"; fi

# ── the GitLab template embeds this exact script ──
embedded="$(sed -n '/<<'"'"'KEPR_CI_EOF'"'"'$/,/^ *KEPR_CI_EOF$/p' "$GITLAB" | sed '1d;$d' | sed 's/^      //')"
if [ "$embedded" = "$(cat "$LIB")" ]; then
	ok "GitLab template carries the current kepr-ci.sh"
else
	fail "GitLab template is out of date; run: bash integrations/ci/sync-gitlab.sh"
fi

echo
if [ "$FAILS" -eq 0 ]; then echo "all kepr-ci tests passed"; else echo "$FAILS failure(s)"; exit 1; fi
