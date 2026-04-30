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
    /// `kepr exec` only: list of env-var names parsed from `--env`.
    /// Empty for every other command. The CLI parser owns the
    /// CSV-split + name uppercasing; downstream code consumes the
    /// list as-is.
    pub env_vars: Vec<String>,
    /// `kepr exec` only: argv to exec, gathered from everything
    /// after the `--` separator. The first element is the binary;
    /// subsequent elements are its arguments.
    pub exec_argv: Vec<String>,
    /// `kepr exec` / `kepr env`: explicit pin to a `.kepr.toml`
    /// manifest. If unset, the resolver falls back to walking up
    /// from `$PWD` and finally to "no manifest". `--env CSV`
    /// overrides whatever the manifest says.
    pub manifest_path: Option<std::path::PathBuf>,
    /// `kepr set` only: optional TTL in seconds. When set, the
    /// daemon writes a sidecar metadata file recording the absolute
    /// expiry time. After that instant, `kepr get` for this name
    /// returns `credential unavailable`. None = no expiry, the
    /// pre-Phase-2 default.
    pub ttl_secs: Option<u64>,
    /// `kepr rotate` only: path to the validation hook. The
    /// rotation orchestration generates a candidate value, pipes
    /// it to this hook on stdin, and only commits if the hook
    /// exits 0. Required for `kepr rotate`; ignored elsewhere.
    pub hook_path: Option<std::path::PathBuf>,
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
    let mut exec_argv: Vec<String> = Vec::new();
    let mut manifest_path: Option<std::path::PathBuf> = None;
    let mut ttl_secs: Option<u64> = None;
    let mut hook_path: Option<std::path::PathBuf> = None;

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
                // `kepr exec --env VAR1,VAR2` — defer the CSV split
                // and validation to cli_exec::parse_env_csv so the
                // error path is uniform whether the entries arrive
                // here or from a `.kepr.toml` manifest.
                i += 1;
                let csv = raw.get(i).ok_or("--env needs a CSV of variable names")?;
                env_vars = crate::cli_exec::parse_env_csv(csv)?;
                i += 1;
            }
            "--manifest" => {
                // Explicit pin to a `.kepr.toml`. Beats auto-discovery,
                // loses to an explicit `--env CSV`. The resolver in
                // cli_manifest::resolve enforces the precedence.
                i += 1;
                let p = raw.get(i).ok_or("--manifest needs a path")?;
                manifest_path = Some(std::path::PathBuf::from(p));
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
            s if !s.starts_with('-') && name.is_none() => {
                name = Some(s.to_uppercase());
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
        force,
        env_vars,
        exec_argv,
        manifest_path,
        ttl_secs,
        hook_path,
    })
}

pub fn print_help() {
    println!("kepr {VERSION} — credential manager");
    println!();
    println!("USAGE:");
    println!("  kepr [--json] [--color] COMMAND [args]");
    println!();
    println!("COMMANDS:");
    println!("  set KEY [--generate] [--value V] [--gen-kind hex|base62|pass|uuid] [--ttl SECS]");
    println!("  get KEY [--quiet] [--export]");
    println!("  list                                 (alias: ls)");
    println!("  delete KEY [--force]                 (alias: rm)");
    println!("  check");
    println!("  exec [--env CSV|--manifest PATH] -- CMD ARGS  run CMD with creds in env");
    println!("  doctor                               diagnose common setup issues");
    println!("  env [--env CSV|--manifest PATH]      emit `export VAR='value'` lines for eval");
    println!("  rotate KEY --hook PATH [--gen-kind hex|base62|pass|uuid]   atomic rotation");
    println!();
    println!("GLOBAL FLAGS:");
    println!("  --json       machine-readable output; no stderr on clean errors");
    println!("  --color      enable ANSI colours (default is plain text)");
    println!("  --no-color   force plain text (overrides CLICOLOR_FORCE=1)");
    println!();
    println!("ENVIRONMENT:");
    println!("  NO_COLOR           any value disables colours (overrides --color)");
    println!("  CLICOLOR_FORCE=1   enables colours without --color");
    println!();
    println!("EXAMPLES:");
    println!("  kepr set OPENAI_API_KEY              # interactive, masked input");
    println!("  kepr set BOB_TOKEN --generate        # auto-generate");
    println!("  kepr set MY_KEY --value abc123       # non-interactive");
    println!("  kepr set TMP_TOKEN --generate --ttl 3600   # expires in 1h");
    println!("  kepr get OPENAI_API_KEY              # decrypt and print");
    println!("  kepr get OPENAI_API_KEY --export     # print as: export VAR=value");
    println!("  kepr get OPENAI_API_KEY --quiet      # raw value only");
    println!("  kepr --json get OPENAI_API_KEY       # json output for scripts");
    println!("  kepr ls                              # alias for list");
    println!("  kepr rm BOB_TOKEN --force            # delete without prompt");
    println!("  kepr check                           # verify all decrypt ok");
    println!("  kepr exec --env OPENAI_API_KEY -- python train.py");
    println!("                                       # provision creds in env, replace process");
    println!("  kepr doctor                          # ✓/✗ list of setup checks");
    println!("  kepr rotate STRIPE_KEY --hook ./bin/refresh-stripe.sh");
    println!("                                       # generate, validate via hook, commit on hook exit 0");
    println!("  eval \"$(kepr env --env DB_PASS,DB_USER)\"  # source creds into the current shell");
    println!("  kepr exec -- python train.py         # uses .kepr.toml in/above PWD");
    println!();
    println!("MANIFEST:");
    println!("  Place a `.kepr.toml` in the project root:");
    println!("    [env]");
    println!("    required = [\"DB_PASS\", \"DB_USER\", \"OPENAI_API_KEY\"]");
    println!("  Then `kepr exec -- python train.py` and `kepr env` need no flags.");
    println!("  --env CSV overrides the manifest; --manifest path pins a different file.");
    println!();
    println!("  View audit log:");
    println!("    journalctl -t kepr-daemon");
    println!("    journalctl -t kepr-daemon KEPR_OP=get");
}
