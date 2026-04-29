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
    })
}

pub fn print_help() {
    println!("kepr {VERSION} — credential manager");
    println!();
    println!("USAGE:");
    println!("  kepr [--json] [--color] COMMAND [args]");
    println!();
    println!("COMMANDS:");
    println!("  set KEY [--generate] [--value V] [--gen-kind hex|base62|pass|uuid]");
    println!("  get KEY [--quiet] [--export]");
    println!("  list                                 (alias: ls)");
    println!("  delete KEY [--force]                 (alias: rm)");
    println!("  check");
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
    println!("  kepr get OPENAI_API_KEY              # decrypt and print");
    println!("  kepr get OPENAI_API_KEY --export     # print as: export VAR=value");
    println!("  kepr get OPENAI_API_KEY --quiet      # raw value only");
    println!("  kepr --json get OPENAI_API_KEY       # json output for scripts");
    println!("  kepr ls                              # alias for list");
    println!("  kepr rm BOB_TOKEN --force            # delete without prompt");
    println!("  kepr check                           # verify all decrypt ok");
    println!();
    println!("  View audit log:");
    println!("    journalctl -t kepr-daemon");
    println!("    journalctl -t kepr-daemon KEPR_OP=get");
}
