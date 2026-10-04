// cli_help.rs — `kepr --help` text.
//
// Split out of cli_args.rs (Phase 4 OSS-launch cleanup): the parser and
// the help string are two different concerns that happened to share a
// file, and the help text alone is long enough to push argv parsing
// over the 350-LOC ceiling. No logic lives here beyond printing.

use crate::cli_args::VERSION;

pub fn print_help() {
    print!(
        r#"kepr {VERSION} — credential manager

USAGE:
  kepr [--json] [--color] COMMAND [args]

COMMANDS:
  set KEY [--stdin|--value V|--generate] [--gen-kind hex|base62|pass|uuid] [--ttl SECS] [--requires-consent] [--requires-fido2]
  get KEY [--quiet] [--export]
  list                                 (alias: ls)
  delete KEY [--force]                 (alias: rm)
  lock | unlock | status               password-protect or inspect the store
  exec [--env CSV|--memfd CSV|--manifest PATH] [--mask] -- CMD ARGS  run CMD with creds in env/memfd
                                       (--mask prints stored values in CMD's output as ****)
  doctor                               diagnose common setup issues
  env [--env CSV|--manifest PATH]      emit `export VAR='value'` lines for eval
  rotate KEY --hook PATH [--gen-kind hex|base62|pass|uuid]   atomic rotation
  audit-verify                         verify the hash-chained audit log
  sync-push KEY --url SCHEME:PATH      push KEY's value to a remote (vault:|aws-sm:|gcp-sm:)
  sync-pull KEY --url SCHEME:PATH      pull from a remote and set KEY locally
  fido2-register LABEL CRED_ID COSE_KEY register a FIDO2 key for assertions
  fido2-list                             list registered FIDO2 keys
  agent add KEY [--for PROVIDER] [--requires-consent]  store a write-only key (paste once)
  agent run HARNESS [--isolate-net|--no-sandbox|--strict-sandbox]
            [--max-requests N] [--max-tokens N] [--rate N/min] [-- ARGV]
                                       run claude|codex|grok-cli|aider|omp|grok sandboxed, with
                                       placeholders; a local gate injects the real key on the wire
  agent install omp|grok               point the harness's config file at the gate (once)
  agent adopt [FILE...] [--yes] [--remove]  move keys from .env / shell rc files into kepr
  agent ls | agent revoke KEY          list / delete sealed keys
  mcp                                  MCP server (stdio): list keys, call provider APIs, no values
  panic                                stop all agent gates; lock the store if passphrase-protected
  leaked KEY [--yes]                   key exposed: stop agent sessions, delete it + history, log an
                                       incident, show where to revoke it at the provider
  totp KEY                             current 2FA code from a stored TOTP seed / otpauth:// URI
  inject -i TEMPLATE [-o OUT]          fill kepr://NAME references (OUT created 0600)
  scan [PATH...] [--staged]            find leaked API keys / private keys (pre-commit friendly)
  copy KEY [--clear SECS]              copy to the clipboard, cleared after SECS (default 20)
  history KEY                          previous values kept (last 5), no values shown
  restore KEY --version N              make version N current again (undoable)
  usage [--days N]                     uses / refusals / last use per key; flags never-used keys
  health [--max-age DAYS] [--breach]   weak / reused / old keys; --breach checks breach lists (k-anonymity)
  discover [--seal] [--overwrite] [--yes]  find plain-text creds in aws/git/netrc/npm/pypi/docker/gh/kube
                                       configs and import them (source files are left alone)
  import FILE [--format auto|csv|json|env] [--prefix P] [--seal] [--overwrite] [--yes]
                                       from 1Password/Bitwarden/KeePassXC/LastPass/browser CSV,
                                       Bitwarden/Keeper/Doppler/Infisical JSON or .env
  ssh generate KEY [--comment C] | ssh import KEY FILE | ssh list
                                       SSH keys that stay in the daemon (sign-only)
  ssh-agent [--foreground] [--socket PATH]  ssh-agent for those keys: eval "$(kepr ssh-agent)"

GLOBAL FLAGS:
  --json       machine-readable output; no stderr on clean errors
  --color      enable ANSI colours (default is plain text)
  --no-color   force plain text (overrides CLICOLOR_FORCE=1)

ENVIRONMENT:
  NO_COLOR           any value disables colours (overrides --color)
  CLICOLOR_FORCE=1   enables colours without --color

EXAMPLES:
  kepr set OPENAI_API_KEY              # interactive, masked input
  kepr set BOB_TOKEN --generate        # auto-generate
  printf '%s\n' secret | kepr set MY_KEY --stdin  # no argv exposure
  kepr set TMP_TOKEN --generate --ttl 3600   # expires in 1h
  kepr lock                             # Argon2id-protect the master key
  kepr unlock                           # unlock with the masked password prompt
  kepr status                           # show locked/protection state
  kepr set API_KEY --value secret --requires-fido2   # FIDO2 touch required on every get
  kepr get OPENAI_API_KEY              # decrypt and print
  kepr get OPENAI_API_KEY --export     # print as: export VAR=value
  kepr get OPENAI_API_KEY --quiet      # raw value only
  kepr --json get OPENAI_API_KEY       # json output for scripts
  kepr ls                              # alias for list
  kepr rm BOB_TOKEN --force            # delete without prompt
  kepr check                           # verify all decrypt ok
  kepr exec --memfd OPENAI_API_KEY -- python train.py # RAM-sealed memfd delivery
  kepr exec --env OPENAI_API_KEY -- python train.py  # provision creds in env
  kepr doctor                          # ✓/✗ list of setup checks
  kepr agent add ANTHROPIC_API_KEY     # paste once; can never be read back
  kepr agent run claude                # Claude Code sees only a placeholder
  kepr rotate STRIPE_KEY --hook ./bin/refresh-stripe.sh
                                       # generate, validate via hook, commit on hook exit 0
  kepr sync-push DB_PASS --url vault:secret/team/db_pass
                                       # VAULT_ADDR + VAULT_TOKEN env vars supply auth
  kepr sync-push DB_PASS --url aws-sm:prod/db/password
                                       # AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY + AWS_REGION
  kepr sync-push DB_PASS --url gcp-sm:projects/myproj/secrets/db_pass
                                       # GCP_ACCESS_TOKEN env var (gcloud auth print-access-token)
  eval "$(kepr env --env DB_PASS,DB_USER)"  # source creds into the current shell
  kepr exec -- python train.py         # uses .kepr.toml in/above PWD

MANIFEST:
  Place a `.kepr.toml` in the project root:
    [env]
    required = ["DB_PASS", "DB_USER", "OPENAI_API_KEY"]
  Then `kepr exec -- python train.py` and `kepr env` need no flags.
  --env CSV overrides the manifest; --manifest path pins a different file.

  View audit log: journalctl -t kepr-daemon
    journalctl -t kepr-daemon KEPR_OP=get
"#
    );
}
