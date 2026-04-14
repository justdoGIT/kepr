// main.rs — credman user CLI
//
// Thin client that sends requests to credman-daemon over Unix socket.
// Never calls systemd-creds. Never needs root. Never needs sudo.
// Works as long as the user is in the 'credman' group.

mod protocol;
mod generate;

use std::io::{self, BufRead, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use generate::{generate_secret, GenKind, ZeroString};
use protocol::{Request, Response, SOCKET_PATH, TIMEOUT_SECS, MAX_MSG_BYTES};

const VERSION: &str = env!("CARGO_PKG_VERSION");

static FORCE_NO_COLOR: AtomicBool = AtomicBool::new(false);

// ── Colour helpers ────────────────────────────────────────────────────────────

fn use_color() -> bool {
    if FORCE_NO_COLOR.load(Ordering::Relaxed) { return false; }
    if std::env::var_os("NO_COLOR").is_some() { return false; }
    unsafe { isatty(1) != 0 }
}
extern "C" { fn isatty(fd: i32) -> i32; }

macro_rules! color {
    ($code:expr, $text:expr) => {
        if use_color() { format!("\x1b[{}m{}\x1b[0m", $code, $text) }
        else           { $text.to_string() }
    };
}

fn ok(m: &str)    { println!("  {}  {}", color!("0;32","✓"), m); }
fn err(m: &str)   { eprintln!("  {}  {}", color!("0;31","✗"), m); }
fn warn(m: &str)  { println!("  {}  {}", color!("1;33","⚠"), m); }
fn info(m: &str)  { println!("  {}  {}", color!("0;36","·"), m); }
fn einfo(m: &str) { eprintln!("  {}  {}", color!("0;36","·"), m); }
fn bold(m: &str)  { println!("{}", color!("1", m)); }
fn dim(m: &str)   { println!("{}", color!("2", m)); }

// ── Socket client ─────────────────────────────────────────────────────────────

fn send_request(req: &Request) -> Result<Response, String> {
    let mut stream = UnixStream::connect(SOCKET_PATH)
        .map_err(|e| format!(
            "cannot connect to credential service: {e}\n  Is credman-daemon running? Check: systemctl status credman"
        ))?;

    let timeout = Duration::from_secs(TIMEOUT_SECS);
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(timeout)).ok();

    let json = serde_json::to_vec(req)
        .map_err(|e| format!("request encoding error: {e}"))?;

    stream.write_all(&json)
        .map_err(|e| format!("send error: {e}"))?;

    // Signal end of write so daemon knows request is complete
    stream.shutdown(std::net::Shutdown::Write).ok();

    let mut buf = vec![0u8; MAX_MSG_BYTES];
    let n = stream.read(&mut buf)
        .map_err(|e| format!("receive error: {e}"))?;

    if n == 0 {
        return Err("empty response from credential service".to_string());
    }

    serde_json::from_slice(&buf[..n])
        .map_err(|e| format!("response decode error: {e}"))
}

// ── Masked input ──────────────────────────────────────────────────────────────

fn read_masked(prompt: &str) -> ZeroString {
    eprint!("{}", prompt);
    io::stderr().flush().ok();

    let mut t = get_termios();
    let orig  = t;
    t.c_lflag &= !ECHO;
    set_termios(&t);

    let mut s = String::new();
    io::stdin().lock().read_line(&mut s).ok();
    set_termios(&orig);
    eprintln!();

    ZeroString::from_string(s.trim_end_matches('\n').to_string())
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Termios {
    c_iflag: u32, c_oflag: u32, c_cflag: u32, c_lflag: u32,
    c_line: u8, c_cc: [u8; 32], c_ispeed: u32, c_ospeed: u32,
}
const ECHO: u32 = 0x00000008;
extern "C" {
    fn tcgetattr(fd: i32, t: *mut Termios) -> i32;
    fn tcsetattr(fd: i32, a: i32, t: *const Termios) -> i32;
}
fn get_termios() -> Termios {
    let mut t = Termios { c_iflag:0,c_oflag:0,c_cflag:0,c_lflag:0,
                          c_line:0,c_cc:[0;32],c_ispeed:0,c_ospeed:0 };
    unsafe { tcgetattr(0, &mut t); }
    t
}
fn set_termios(t: &Termios) { unsafe { tcsetattr(0, 0, t); } }

// ── JSON output ───────────────────────────────────────────────────────────────

fn print_json(resp: &Response) {
    println!("{}", serde_json::to_string_pretty(resp).unwrap_or_default());
}

// ── Arg parsing ───────────────────────────────────────────────────────────────

struct Args {
    command:  String,
    name:     Option<String>,
    value:    Option<String>,
    generate: bool,
    gen_kind: GenKind,
    quiet:    bool,
    export:   bool,
    json:     bool,
    force:    bool,
}

fn parse_args() -> Result<Args, String> {
    let raw: Vec<String> = std::env::args().collect();
    let mut a = Args {
        command: String::new(), name: None, value: None,
        generate: false, gen_kind: GenKind::Hex,
        quiet: false, export: false, json: false, force: false,
    };

    let mut i = 1usize;

    while i < raw.len() && raw[i].starts_with("--") {
        match raw[i].as_str() {
            "--json"     => { a.json = true; i += 1; }
            "--no-color" => { FORCE_NO_COLOR.store(true, Ordering::Relaxed); i += 1; }
            "--version"  => { println!("credman {VERSION}"); std::process::exit(0); }
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

fn print_help() {
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

// ── Commands ──────────────────────────────────────────────────────────────────

fn cmd_set(a: &Args) -> Response {
    let name = match &a.name {
        Some(n) => n.clone(),
        None => {
            if a.json { return Response::fail("NAME required"); }
            bold("\n  credman — set credential\n");
            eprint!("  {}", color!("0;36","Credential name (e.g. OPENAI_API_KEY): "));
            io::stderr().flush().ok();
            let mut n = String::new();
            io::stdin().lock().read_line(&mut n).ok();
            n.trim().to_uppercase()
        }
    };

    if name.is_empty() {
        err("Name cannot be empty.");
        return Response::fail("empty name");
    }

    // Determine value to send
    let (value_opt, gen_opt): (Option<String>, Option<String>) = if let Some(v) = &a.value {
        (Some(v.clone()), None)

    } else if a.generate {
        // Generate locally — value travels over socket but socket is protected
        let s = generate_secret(a.gen_kind);
        if !a.json {
            ok(&format!("Generated {} secret ({} chars)", a.gen_kind.as_str(), s.len()));
        }
        (Some(s.to_owned_string()), None)

    } else {
        if a.json {
            return Response::fail("provide --value or --generate in json mode");
        }

        // Interactive
        println!();
        bold(&format!("  Setting: {}", color!("1;33", &name)));

        // Check if exists first
        let check_req = Request::Get { name: name.clone() };
        if let Ok(r) = send_request(&check_req) {
            if r.ok {
                warn(&format!("'{}' already exists.", name));
                eprint!("  {} ", color!("0;36","Overwrite? [y/N]:"));
                io::stderr().flush().ok();
                let mut ans = String::new();
                io::stdin().lock().read_line(&mut ans).ok();
                if ans.trim().to_lowercase() != "y" {
                    info("Aborted.");
                    return Response::fail("aborted");
                }
            }
        }

        dim("  Leave blank to auto-generate. Input is hidden.\n");
        let val = read_masked(&format!("  {} ",
            color!("0;36", &format!("Value for {name} (blank = auto-generate):"))));

        if val.is_empty() {
            println!();
            info("Generating automatically.");
            info("  [1] hex      — 64-char hex token     (default)");
            info("  [2] base62   — 48-char alphanumeric");
            info("  [3] pass     — 32-char mixed symbols");
            info("  [4] uuid     — UUID4 format");
            eprint!("  {}", color!("0;36","Choice [1-4, default=1]: "));
            io::stderr().flush().ok();
            let mut c = String::new();
            io::stdin().lock().read_line(&mut c).ok();
            let kind = match c.trim() {
                "2" => GenKind::Base62,
                "3" => GenKind::Pass,
                "4" => GenKind::Uuid,
                _   => GenKind::Hex,
            };
            let s = generate_secret(kind);
            let preview = format!("{}...{}", &s[..8], &s[s.len()-4..]);
            ok(&format!("Generated: {}", color!("2", &preview)));
            (Some(s.to_owned_string()), None)
        } else {
            (Some(val.to_owned_string()), None)
        }
    };

    let req = Request::Set {
        name:     name.clone(),
        value:    value_opt,
        generate: gen_opt,
    };

    match send_request(&req) {
        Ok(resp) => {
            if resp.ok && !a.json {
                println!();
                ok(&format!("Stored: {}", color!("1", &name)));
                dim(&format!("  Retrieve: credman get {name}"));
                println!();
            } else if !resp.ok && !a.json {
                err(resp.error.as_deref().unwrap_or("unknown error"));
            }
            resp
        }
        Err(e) => { if !a.json { err(&e); } Response::fail(&e) }
    }
}

fn cmd_get(a: &Args) -> Response {
    let name = match &a.name {
        Some(n) => n.clone(),
        None => {
            if !a.json { err("NAME required: credman get KEY"); }
            return Response::fail("NAME required");
        }
    };

    let req = Request::Get { name: name.clone() };

    match send_request(&req) {
        Err(e) => { if !a.json { err(&e); } Response::fail(&e) }
        Ok(resp) => {
            if !resp.ok {
                if !a.json {
                    err(resp.error.as_deref().unwrap_or("not found"));
                    einfo(&format!("Set it with: credman set {name}"));
                }
                return resp;
            }

            let val = resp.value.as_deref().unwrap_or("");

            if a.json  { return resp; }
            if a.quiet { println!("{val}"); return resp; }
            if a.export { println!("export {name}={val}"); return resp; }

            println!();
            bold(&format!("  {name}"));
            println!("  {}", color!("0;32", val));
            println!();
            resp
        }
    }
}

fn cmd_list(a: &Args) -> Response {
    match send_request(&Request::List) {
        Err(e) => { if !a.json { err(&e); } Response::fail(&e) }
        Ok(resp) => {
            if a.json { return resp; }

            let creds = resp.credentials.as_deref().unwrap_or(&[]);
            if creds.is_empty() {
                info("No credentials stored.");
                return resp;
            }

            println!();
            bold(&format!("  Stored credentials ({})\n", creds.len()));
            for c in creds {
                println!("  {:<40} {}",
                    color!("1", &c.name),
                    color!("2", &format!("{}B  {}", c.size, c.modified)));
            }
            println!();
            resp
        }
    }
}

fn cmd_delete(a: &Args) -> Response {
    let name = match &a.name {
        Some(n) => n.clone(),
        None => {
            if !a.json { err("NAME required: credman delete KEY"); }
            return Response::fail("NAME required");
        }
    };

    if !a.json && !a.force {
        warn(&format!("Delete '{name}'?"));
        eprint!("  {} ", color!("0;36","Confirm [y/N]:"));
        io::stderr().flush().ok();
        let mut ans = String::new();
        io::stdin().lock().read_line(&mut ans).ok();
        if ans.trim().to_lowercase() != "y" {
            info("Aborted.");
            return Response::fail("aborted");
        }
    }

    match send_request(&Request::Delete { name: name.clone() }) {
        Err(e) => { if !a.json { err(&e); } Response::fail(&e) }
        Ok(resp) => {
            if resp.ok  && !a.json { ok(&format!("Deleted: {name}")); }
            if !resp.ok && !a.json { err(resp.error.as_deref().unwrap_or("failed")); }
            resp
        }
    }
}

fn cmd_check(a: &Args) -> Response {
    match send_request(&Request::Check) {
        Err(e) => { if !a.json { err(&e); } Response::fail(&e) }
        Ok(resp) => {
            if a.json { return resp; }

            let results = resp.results.as_ref();
            if let Some(r) = results {
                println!();
                bold(&format!("  Checking {} credential(s)...\n", r.len()));
                let mut entries: Vec<(&String, &String)> = r.iter().collect();
                entries.sort_by(|a, b| a.0.cmp(b.0));
                for (name, status) in entries {
                    if status == "ok" {
                        ok(&format!("{:<40}", name));
                    } else {
                        err(&format!("{:<40} FAILED", name));
                    }
                }
                println!();
                if resp.ok {
                    ok("All credentials verified.");
                } else {
                    warn("Some credentials failed.");
                }
                println!();
            } else {
                info("No credentials to check.");
            }
            resp
        }
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    let args = match parse_args() {
        Ok(a)  => a,
        Err(e) => { err(&format!("{e}")); std::process::exit(1); }
    };

    let resp = match args.command.as_str() {
        "set"          => cmd_set(&args),
        "get"          => cmd_get(&args),
        "list" | "ls"  => cmd_list(&args),
        "delete"|"rm"  => cmd_delete(&args),
        "check"        => cmd_check(&args),
        other => {
            let msg = format!("unknown command: {other}");
            if !args.json {
                err(&msg);
                err("try: credman --help");
            }
            Response::fail(&msg)
        }
    };

    if args.json { print_json(&resp); }
    if !resp.ok  { std::process::exit(1); }
}
