// cli_args.rs — argv parsing. `--help` text lives in cli_help.rs.

use crate::cli_activity::CliActivity;
use crate::cli_mode;
use kepr_core::generate::GenKind;

pub(crate) const VERSION: &str = env!("CARGO_PKG_VERSION");

pub struct Args {
    pub command: CliActivity,
    pub name: Option<String>,
    pub value: Option<String>,
    pub generate: bool,
    pub gen_kind: GenKind,
    /// `kepr set --profile P` (T5.04): generate from a profile; implies --generate.
    pub profile: Option<String>,
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
    /// `kepr exec` only: mask secret values in the child's output.
    pub mask: bool,
    /// `kepr exec` only: argv after `--`. First element is the binary.
    pub exec_argv: Vec<String>,
    /// Explicit `.kepr.toml` path. Falls back to walk-up then no-manifest.
    pub manifest_path: Option<std::path::PathBuf>,
    /// `kepr exec|env --stage S`: the manifest's `[env.S]` set (T5.02).
    pub stage: Option<String>,
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
    /// `kepr lock --fido2`: the passphrase and a security key (T4.09).
    pub lock_fido2: bool,
    /// `kepr fido2-register` only: hex credential ID from authenticator.
    pub fido2_credential_id: Option<String>,
    /// `kepr fido2-register` only: hex COSE_Key public key from authenticator.
    pub fido2_public_key_cose: Option<String>,
    /// Flags of the `store` batch on core verbs (`ls --tag/--folder`, …).
    pub store: crate::cli_store::StoreFlags,
    /// Flags of the `session` batch on core verbs (`set --reauth`).
    pub session: crate::cli_session::SessionFlags,
    /// Flags of the `aws` batch on core verbs (`rotate --aws-iam`).
    pub aws: crate::cli_aws::AwsFlags,
    /// Flags of the `platform` batch on core verbs (`unlock --fingerprint`).
    pub platform: crate::cli_platform::PlatformFlags,
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
    let mut profile: Option<String> = None;
    let mut quiet = false;
    let mut export = false;
    let mut json = false;
    let mut force = false;
    let mut env_vars: Vec<String> = Vec::new();
    let mut memfd_vars: Vec<String> = Vec::new();
    let mut exec_argv: Vec<String> = Vec::new();
    let mut manifest_path: Option<std::path::PathBuf> = None;
    let mut stage: Option<String> = None;
    let mut stdin = false;
    let mut mask = false;
    let mut ttl_secs: Option<u64> = None;
    let mut hook_path: Option<std::path::PathBuf> = None;
    let mut url: Option<String> = None;
    let mut requires_consent = false;
    let mut requires_fido2 = false;
    let mut lock_fido2 = false;
    let mut fido2_credential_id: Option<String> = None;
    let mut fido2_public_key_cose: Option<String> = None;
    let mut store = crate::cli_store::StoreFlags::default();
    let mut session = crate::cli_session::SessionFlags::default();
    let mut aws = crate::cli_aws::AwsFlags::default();
    let mut platform = crate::cli_platform::PlatformFlags::default();

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
                crate::cli_help::print_help();
                std::process::exit(0);
            }
            _ => break,
        }
    }

    let command_verb = raw.get(i).ok_or("no command — try: kepr --help")?;
    let command = CliActivity::parse(command_verb)?;
    i += 1;
    // T9.05: `kepr mcp` parses its own flags (cli_gatex/mcp_tools.rs).
    if command.as_str() == "mcp" {
        i = raw.len();
    }

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
            "--mask" => {
                mask = true;
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
                gen_kind = GenKind::from_str(k).ok_or(format!(
                    "unknown gen-kind: {k} (hex|base62|pass|uuid|words)"
                ))?;
                i += 1;
            }
            "--profile" => {
                profile = Some(raw.get(i + 1).ok_or("--profile needs a name")?.clone());
                generate = true;
                i += 2;
            }
            "--env" => {
                // `kepr exec --env VAR1,VAR2` — defer the CSV split
                // and validation to cli_exec::parse_env_csv so the
                // error path is uniform whether the entries arrive
                // here or from a `.kepr.toml` manifest.
                i += 1;
                let csv = raw.get(i).ok_or("--env needs a CSV of variable names")?;
                env_vars.extend(crate::cli_exec::parse_env_csv(csv)?); // repeatable (T5.06)
                i += 1;
            }
            "--memfd" => {
                // `kepr exec --memfd VAR1,VAR2` — same CSV parsing as
                // `--env`, but delivered as sealed RAM `memfd` file
                // descriptors instead of environment variables.
                i += 1;
                let csv = raw.get(i).ok_or("--memfd needs a CSV of variable names")?;
                memfd_vars = crate::cli_exec::parse_env_csv(csv)?;
                i += 1;
            }
            "--manifest" => {
                // Explicit pin to a `.kepr.toml`; it loses only to an
                // explicit `--env CSV`. Ancestor auto-discovery is opt-in
                // through `KEPR_AUTO_MANIFEST=1`.
                i += 1;
                let p = raw.get(i).ok_or("--manifest needs a path")?;
                manifest_path = Some(std::path::PathBuf::from(p));
                i += 1;
            }
            "--stage" => {
                stage = Some(raw.get(i + 1).ok_or("--stage needs a name")?.clone());
                i += 2;
            }
            "--url" => {
                // Phase 2 ζ. Scheme-prefixed remote URL for
                // `kepr sync-push|pull`. Validated downstream
                // by `sync::pick_syncer`.
                i += 1;
                let v = raw.get(i).ok_or("--url needs a value")?;
                url = Some(v.clone());
                i += 1;
            }
            "--requires-consent" => {
                // Phase 2 ε. No value: presence flips the flag.
                // The daemon translates this into a sidecar
                // `requires_consent: true` field.
                requires_consent = true;
                i += 1;
            }
            "--requires-fido2" => {
                // Phase 2 η. No value: presence flips the flag.
                requires_fido2 = true;
                i += 1;
            }
            "--fido2" => {
                lock_fido2 = true; // T4.09: `kepr lock --fido2`
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
            s if crate::cli_store::FLAGS.contains(&s) => i = store.take(&raw, i)?,
            s if crate::cli_session::FLAGS.contains(&s) => i = session.take(&raw, i)?,
            s if crate::cli_aws::FLAGS.contains(&s) => i = aws.take(&raw, i)?,
            s if crate::cli_platform::FLAGS.contains(&s) => i = platform.take(&raw, i)?,
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
        profile,
        quiet,
        export,
        json,
        stdin,
        force,
        env_vars,
        memfd_vars,
        mask,
        exec_argv,
        manifest_path,
        stage,
        ttl_secs,
        hook_path,
        url,
        requires_consent,
        requires_fido2,
        lock_fido2,
        fido2_credential_id,
        fido2_public_key_cose,
        store,
        session,
        aws,
        platform,
    })
}
