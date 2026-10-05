#!/usr/bin/env bash
# sync-gitlab.sh: embed the current kepr-ci.sh into the GitLab template
# (between the KEPR_CI_EOF heredoc markers). test_kepr_ci.sh checks it.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
yml="$here/../gitlab/kepr.gitlab-ci.yml"
tmp="$(mktemp)"
awk -v lib="$here/kepr-ci.sh" '
	skip && /^ *KEPR_CI_EOF$/ { skip = 0 }
	!skip { print }
	/<<'"'"'KEPR_CI_EOF'"'"'$/ {
		while ((getline l < lib) > 0) print (l == "" ? "" : "      " l)
		skip = 1
	}
' "$yml" >"$tmp"
cat "$tmp" >"$yml"
rm -f "$tmp"
