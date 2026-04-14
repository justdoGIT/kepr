// cli_args.rs — argv parsing and --help rendering.

use std::sync::atomic::Ordering;

use crate::cli_ui::FORCE_NO_COLOR;
use crate::generate::GenKind;

const VERSION: &str = env!("CARGO_PKG_VERSION");

pub struct Args {
    pub command:  String,
    pub name:     Option<String>,
    pub value:    Option<String>,
    pub generate: bool,
    pub gen_kind: GenKind,
    pub quiet:    bool,
    pub export:   bool,
    pub json:     bool,
    pub force:    bool,
}

pub fn parse_args() -> Result<Args, String> {
    let raw: Vec<String> = std::env::args().collect();
    let mut a = Args {
        command: String::new(), name: None, value: None,
        generate: false, gen_kind: GenKind::Hex,
        quiet: false, export: false, json: false, force: false,
    };

    let mut i = 1usize;

    while i < raw.len() && raw[i].starts_with("--") {
        match raw[i].as_str() {
            "--json"      => { a.json = true; i += 1; }
            "--no-color"  => { FORCE_NO_COLOR.store(true, Ordering::Relaxed); i += 1; }
            "--version"   => { println!("credman {VERSION}"); std::process::exit(0); }
            "--help"|"-h" => { print_help(); std::process::exit(0); }
            _ => break,
        }
    }

    a.command = raw.get(i).ok_or("no command — try: credman --help")?.clone();
    i += 1;

    if i < raw.len() && !raw[i].starts_with('-') {
        a.name = Some(raw[i].to_uppercase());
        i += 1;
    }

    while i < raw.len() {
        match raw[i].as_str() {
            "--generate"|"-g" => { a.generate = true; i += 1; }
            "--quiet"|"-q"    => { a.quiet    = true; i += 1; }
            "--export"|"-e"   => { a.export   = true; i += 1; }
            "--force"|"-f"    => { a.force    = true; i += 1; }
            "--json"          => { a.json     = true; i += 1; }
            "--no-color"      => { FORCE_NO_COLOR.store(true, Ordering::Relaxed); i += 1; }
            "--value"|"-v" => {
                i += 1;
                a.value = Some(raw.get(i).ok_or("--value needs a value")?.clone());
                i += 1;
            }
            "--gen-kind" => {
                i += 1;
                let k = raw.get(i).ok_or("--gen-kind needs a value")?;
                a.gen_kind = GenKind::from_str(k)
                    .ok_or(format!("unknown gen-kind: {k} (hex|base62|pass|uuid)"))?;
                i += 1;
            }
            s if !s.starts_with('-') && a.name.is_none() => {
                a.name = Some(s.to_uppercase());
                i += 1;
            }
            other => return Err(format!("unknown flag: {other}")),
        }
    }

    Ok(a)
}

pub fn print_help() {
    println!("credman {VERSION} — credential manager");
    println!();
    println!("USAGE:");
    println!("  credman [--json] [--no-color] COMMAND [args]");
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
    println!("  --no-color   disable ANSI colors (also honors NO_COLOR env var)");
    println!();
    println!("EXAMPLES:");
    println!("  credman set OPENAI_API_KEY              # interactive, masked input");
    println!("  credman set BOB_TOKEN --generate        # auto-generate");
    println!("  credman set MY_KEY --value abc123       # non-interactive");
    println!("  credman get OPENAI_API_KEY              # decrypt and print");
    println!("  credman get OPENAI_API_KEY --export     # print as: export VAR=value");
    println!("  credman get OPENAI_API_KEY --quiet      # raw value only");
    println!("  credman --json get OPENAI_API_KEY       # json output for scripts");
    println!("  credman ls                              # alias for list");
    println!("  credman rm BOB_TOKEN --force            # delete without prompt");
    println!("  credman check                           # verify all decrypt ok");
    println!();
    println!("  View audit log:");
    println!("    journalctl -t credman-daemon");
    println!("    journalctl -t credman-daemon CREDMAN_OP=get");
}
