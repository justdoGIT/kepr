// cli_args.rs — argv parsing and --help rendering.

use crate::cli_activity::CliActivity;
use crate::cli_mode;
use kepr_core::generate::GenKind;

const VERSION: &str = env!("CARGO_PKG_VERSION");

pub struct Args {
    pub command: CliActivity,
    pub name: Option<String>,
    pub value: Option<String>,
    pub generate: bool,
    pub gen_kind: GenKind,
    pub quiet: bool,
    pub export: bool,
    pub json: bool,
    pub force: bool,
    /// `kepr set` only: read the secret from stdin instead of argv.
    pub stdin: bool,
    /// `kepr exec` only: env-var names from `--env CSV`. Parser does CSV-split + uppercasing.
    pub env_vars: Vec<String>,
    /// `kepr exec` only: memfd names from `--memfd CSV`. Delivered via sealed RAM descriptors.
    pub memfd_vars: Vec<String>,
    /// `kepr exec` only: argv after `--`. First element is the binary.
    pub exec_argv: Vec<String>,
    /// Explicit `.kepr.toml` path. Falls back to walk-up then no-manifest.
    pub manifest_path: Option<std::path::PathBuf>,
    /// `kepr set` only: TTL in seconds. Daemon writes sidecar meta; None = no expiry.
    pub ttl_secs: Option<u64>,
    /// `kepr rotate` only: validation hook path. Candidate piped on stdin.
    pub hook_path: Option<std::path::PathBuf>,
    /// `kepr sync-push|pull`: scheme-prefixed remote URL. Phase 2 ζ.
    pub url: Option<String>,
    /// `kepr set` only: polkit consent gate. Phase 2 ε.
    pub requires_consent: bool,
    /// `kepr set` only: FIDO2 hardware-key assertion gate. Phase 2 η.
    pub requires_fido2: bool,
    /// `kepr fido2-register` only: hex credential ID from authenticator.
    pub fido2_credential_id: Option<String>,
    /// `kepr fido2-register` only: hex COSE_Key public key from authenticator.
    pub fido2_public_key_cose: Option<String>,
}

pub fn parse_args() -> Result<Args, String> {
    // Gather raw flags + positional into locals, then build Args at the
    // end. Keeps `command` typed as CliActivity the whole way through —
    // no `String::new()` placeholder that could leak out as an invalid
    // activity.
    let raw: Vec<String> = std::env::args().collect();

    // Compute the process-wide CliMode from argv + env *before* any
    // parse error can fire, so error paths (unknown verb, missing
    // required value) see the correct --json / --color state.
    cli_mode::init_from_argv(&raw);

    let mut name: Option<String> = None;
    let mut value: Option<String> = None;
    let mut generate = false;
    let mut gen_kind = GenKind::Hex;
    let mut quiet = false;
    let mut export = false;
    let mut json = false;
    let mut force = false;
    let mut env_vars: Vec<String> = Vec::new();
    let mut memfd_vars: Vec<String> = Vec::new();
    let mut exec_argv: Vec<String> = Vec::new();
    let mut manifest_path: Option<std::path::PathBuf> = None;
    let mut stdin = false;
    let mut ttl_secs: Option<u64> = None;
    let mut hook_path: Option<std::path::PathBuf> = None;
    let mut url: Option<String> = None;
    let mut requires_consent = false;
    let mut requires_fido2 = false;
    let mut fido2_credential_id: Option<String> = None;
    let mut fido2_public_key_cose: Option<String> = None;

    let mut i = 1usize;

    while i < raw.len() && raw[i].starts_with("--") {
        match raw[i].as_str() {
            "--json" => {
                json = true;
                i += 1;
            }
            "--color" => {
                i += 1;
            }
            "--no-color" => {
                i += 1;
            }
            "--version" => {
                println!("kepr {VERSION}");
                std::process::exit(0);
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            _ => break,
        }
    }

    let command_verb = raw.get(i).ok_or("no command — try: kepr --help")?;
    let command = CliActivity::parse(command_verb)?;
    i += 1;

    if i < raw.len() && !raw[i].starts_with('-') {
        name = Some(raw[i].to_uppercase());
        i += 1;
    }

    while i < raw.len() {
        match raw[i].as_str() {
            "--generate" | "-g" => {
                generate = true;
                i += 1;
            }
            "--quiet" | "-q" => {
                quiet = true;
                i += 1;
            }
            "--export" | "-e" => {
                export = true;
                i += 1;
            }
            "--force" | "-f" => {
                force = true;
                i += 1;
            }
            "--json" => {
                json = true;
                i += 1;
            }
            "--color" => {
                i += 1;
            }
            "--no-color" => {
                i += 1;
            }
            "--stdin" => {
                stdin = true;
                i += 1;
            }
            "--value" | "-v" => {
                i += 1;
                value = Some(raw.get(i).ok_or("--value needs a value")?.clone());
                i += 1;
            }
            "--gen-kind" => {
                i += 1;
                let k = raw.get(i).ok_or("--gen-kind needs a value")?;
                gen_kind = GenKind::from_str(k)
                    .ok_or(format!("unknown gen-kind: {k} (hex|base62|pass|uuid)"))?;
                i += 1;
            }
            "--env" => {
                i += 1;
                let csv = raw.get(i).ok_or("--env needs a CSV of variable names")?;
                env_vars = crate::cli_exec::parse_env_csv(csv)?;
                i += 1;
            }
            "--memfd" => {
                i += 1;
                let csv = raw.get(i).ok_or("--memfd needs a CSV of variable names")?;
                memfd_vars = crate::cli_exec::parse_env_csv(csv)?;
                i += 1;
            }
            "--manifest" => {
                i += 1;
                let p = raw.get(i).ok_or("--manifest needs a path")?;
                manifest_path = Some(std::path::PathBuf::from(p));
                i += 1;
            }
            "--url" => {
                i += 1;
                let v = raw.get(i).ok_or("--url needs a value")?;
                url = Some(v.clone());
                i += 1;
            }
            "--requires-consent" => {
                requires_consent = true;
                i += 1;
            }
            "--requires-fido2" => {
                requires_fido2 = true;
                i += 1;
            }
            "--hook" => {
                // `kepr rotate NAME --hook ./refresh.sh` — path to
                // the validation hook. We don't existence-check
                // here so the parser stays pure; cli_rotate
                // re-checks before generating.
                i += 1;
                let p = raw.get(i).ok_or("--hook needs a path")?;
                hook_path = Some(std::path::PathBuf::from(p));
                i += 1;
            }
            "--ttl" => {
                // `kepr set NAME --ttl 60` → cred expires 60 seconds
                // from now. Reject 0 (would expire instantly, which
                // is almost certainly a typo for "no ttl") and any
                // value the parser can't fit into u64 (overflow).
                i += 1;
                let raw_val = raw.get(i).ok_or("--ttl needs a number of seconds")?;
                let secs: u64 = raw_val
                    .parse()
                    .map_err(|_| format!("--ttl must be a non-negative integer, got: {raw_val}"))?;
                if secs == 0 {
                    return Err("--ttl 0 would expire the credential instantly; \
                         omit --ttl for no expiry"
                        .to_string());
                }
                ttl_secs = Some(secs);
                i += 1;
            }
            "--" => {
                // Everything after `--` is the child argv. Bash's
                // own getopt convention: the separator is consumed
                // and never appears in `exec_argv`.
                i += 1;
                exec_argv = raw[i..].to_vec();
                break;
            }
            s if !s.starts_with('-') => {
                if name.is_none() {
                    name = Some(s.to_uppercase());
                } else if fido2_credential_id.is_none() {
                    fido2_credential_id = Some(s.to_string());
                } else if fido2_public_key_cose.is_none() {
                    fido2_public_key_cose = Some(s.to_string());
                } else {
                    return Err(format!("unexpected extra argument: {s}"));
                }
                i += 1;
            }
            other => return Err(format!("unknown flag: {other}")),
        }
    }

    Ok(Args {
        command,
        name,
        value,
        generate,
        gen_kind,
        quiet,
        export,
        json,
        stdin,
        force,
        env_vars,
        memfd_vars,
        exec_argv,
        manifest_path,
        ttl_secs,
        hook_path,
        url,
        requires_consent,
        requires_fido2,
        fido2_credential_id,
        fido2_public_key_cose,
    })
}

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
  exec [--env CSV|--memfd CSV|--manifest PATH] -- CMD ARGS  run CMD with creds in env/memfd
  doctor                               diagnose common setup issues
  env [--env CSV|--manifest PATH]      emit `export VAR='value'` lines for eval
  rotate KEY --hook PATH [--gen-kind hex|base62|pass|uuid]   atomic rotation
  audit-verify                         verify the hash-chained audit log
  sync-push KEY --url SCHEME:PATH      push KEY's value to a remote (vault:|aws-sm:|gcp-sm:)
  sync-pull KEY --url SCHEME:PATH      pull from a remote and set KEY locally
  fido2-register LABEL CRED_ID COSE_KEY register a FIDO2 key for assertions
  fido2-list                             list registered FIDO2 keys

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
