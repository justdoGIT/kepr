// cli_args.rs — argv parsing. `--help` text lives in cli_help.rs.

use crate::cli_activity::CliActivity;
use crate::cli_aws::AwsFlags;
use crate::cli_mode;
use kepr_core::generate::GenKind;

pub(crate) const VERSION: &str = env!("CARGO_PKG_VERSION");

fn option_name(token: &str) -> &str {
    if token == "--" {
        token
    } else {
        token.strip_prefix("--").unwrap_or(token)
    }
}

fn command_needs_name(command: &CliActivity) -> bool {
    matches!(
        command.as_str(),
        "set"
            | "get"
            | "delete"
            | "rotate"
            | "sync-push"
            | "sync-pull"
            | "fido2-register"
            | "protect-agent"
    )
}

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
    /// `kepr exec` only: child argv after options; `--` is an optional separator.
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
    pub stage: Option<String>,
    pub profile: Option<String>,
    pub mask: bool,
    pub lock_fido2: bool,
    pub aws: AwsFlags,
    pub store: crate::cli_store::StoreFlags,
    pub platform: crate::cli_platform::PlatformFlags,
    pub session: crate::cli_session::SessionFlags,
}

pub fn parse_args() -> Result<Args, String> {
    let raw: Vec<String> = std::env::args().collect();
    cli_mode::init_from_argv(&raw);
    parse_args_from(&raw)
}

fn parse_args_from(raw: &[String]) -> Result<Args, String> {
    // Parse options and positionals before constructing typed Args.

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
    let mut fido2_public_key_cose: Option<String> = None;
    let mut requires_fido2 = false;
    let mut fido2_credential_id: Option<String> = None;
    let mut aws = AwsFlags::default();
    let mut store = crate::cli_store::StoreFlags::default();
    let mut platform = crate::cli_platform::PlatformFlags::default();
    let mut session = crate::cli_session::SessionFlags::default();
    let (mut stage, mut profile) = (None, None);
    let (mut mask, mut lock_fido2) = (false, false);

    let mut i = 1;

    while i < raw.len() {
        match option_name(&raw[i]) {
            "json" => {
                json = true;
                i += 1;
            }
            "color" | "no-color" => i += 1,
            "version" => {
                println!("kepr {VERSION}");
                std::process::exit(0);
            }
            _ => break,
        }
    }

    if let Some(request) = crate::cli_help::help_request(&raw[i..]) {
        let topic = match request {
            crate::cli_help::HelpRequest::General => None,
            crate::cli_help::HelpRequest::Command(command) => Some(command),
        };
        if let Err(error) = crate::cli_help::print_help_for(topic.as_deref()) {
            eprintln!("{error}");
            std::process::exit(2);
        }
        std::process::exit(0);
    }

    let command_verb = raw.get(i).ok_or("no command — try: kepr help")?;
    let command = CliActivity::parse(command_verb)?;
    i += 1;

    if command_needs_name(&command) && i < raw.len() && !raw[i].starts_with('-') {
        name = Some(raw[i].to_uppercase());
        i += 1;
    }

    // MCP owns its grant arguments and JSON-RPC stdout framing.
    if command.as_str() == "mcp" {
        i = raw.len();
        json = false;
    }

    while i < raw.len() {
        match option_name(&raw[i]) {
            _ if crate::cli_aws::FLAGS.contains(&raw[i].as_str()) => i = aws.take(raw, i)?,
            _ if crate::cli_store::FLAGS.contains(&raw[i].as_str()) => i = store.take(raw, i)?,
            _ if crate::cli_platform::FLAGS.contains(&raw[i].as_str()) => {
                i = platform.take(raw, i)?
            }
            _ if crate::cli_session::FLAGS.contains(&raw[i].as_str()) => {
                i = session.take(raw, i)?
            }
            "stage" | "profile" => {
                let flag = option_name(&raw[i]);
                let value = raw
                    .get(i + 1)
                    .ok_or_else(|| format!("--{flag} needs a value"))?;
                if flag == "stage" {
                    stage = Some(value.clone());
                } else {
                    profile = Some(value.clone());
                    generate = true;
                }
                i += 2;
            }
            "mask" => {
                mask = true;
                i += 1;
            }
            "fido2" => {
                lock_fido2 = true;
                i += 1;
            }
            "generate" | "-g" => {
                generate = true;
                i += 1;
            }
            "quiet" | "-q" => {
                quiet = true;
                i += 1;
            }
            "export" | "-e" => {
                export = true;
                i += 1;
            }
            "force" | "-f" => {
                force = true;
                i += 1;
            }
            "json" => {
                json = true;
                i += 1;
            }
            "color" => {
                i += 1;
            }
            "no-color" => {
                i += 1;
            }
            "stdin" => {
                stdin = true;
                i += 1;
            }
            "value" | "-v" => {
                i += 1;
                value = Some(raw.get(i).ok_or("--value needs a value")?.clone());
                i += 1;
            }
            "gen-kind" => {
                i += 1;
                let k = raw.get(i).ok_or("--gen-kind needs a value")?;
                gen_kind = GenKind::from_str(k).ok_or(format!(
                    "unknown gen-kind: {k} (hex|base62|pass|uuid|words)"
                ))?;
                i += 1;
            }
            "env" => {
                // Use the same CSV validation for CLI and manifest input.
                i += 1;
                let csv = raw.get(i).ok_or("--env needs a CSV of variable names")?;
                env_vars = crate::cli_exec::parse_env_csv(csv)?;
                i += 1;
            }
            "memfd" => {
                // Reuse CSV validation; deliver through sealed RAM descriptors.
                i += 1;
                let csv = raw.get(i).ok_or("--memfd needs a CSV of variable names")?;
                memfd_vars = crate::cli_exec::parse_env_csv(csv)?;
                i += 1;
            }
            "manifest" => {
                // Explicit env overrides this; auto-discovery requires KEPR_AUTO_MANIFEST.
                i += 1;
                let p = raw.get(i).ok_or("--manifest needs a path")?;
                manifest_path = Some(std::path::PathBuf::from(p));
                i += 1;
            }
            "url" => {
                // Scheme validation is delegated to sync::pick_syncer.
                i += 1;
                let v = raw.get(i).ok_or("--url needs a value")?;
                url = Some(v.clone());
                i += 1;
            }
            "requires-consent" => {
                // Presence enables daemon-side consent metadata.
                requires_consent = true;
                i += 1;
            }
            "requires-fido2" => {
                // Phase 2 η. No value: presence flips the flag.
                requires_fido2 = true;
                i += 1;
            }
            "hook" => {
                // cli_rotate validates this path before generating.
                i += 1;
                let p = raw.get(i).ok_or("--hook needs a path")?;
                hook_path = Some(std::path::PathBuf::from(p));
                i += 1;
            }
            "ttl" => {
                // Reject zero and overflow to avoid immediate expiry or invalid values.
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
                // Consume the separator; all following argv belongs to the child.
                i += 1;
                exec_argv = raw[i..].to_vec();
                break;
            }
            s if !raw[i].starts_with('-') => {
                if command.as_str() == "exec"
                    || (command.as_str() == "protect-agent" && name.is_some())
                {
                    exec_argv = raw[i..].to_vec();
                    break;
                } else if name.is_none() {
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
            _ => return Err(format!("unknown flag: {}", raw[i])),
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
        aws,
        store,
        platform,
        session,
        stage,
        profile,
        mask,
        lock_fido2,
    })
}

include!("cli_args_tests.rs");
