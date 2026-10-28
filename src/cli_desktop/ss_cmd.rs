// cli_desktop/ss_cmd.rs — `kepr secret-service`: run the Secret Service
// front end, look at it, and read its log. Moving a desktop session over
// from GNOME Keyring is takeover.rs and import.rs.

use kepr_core::protocol::Response;

use super::ss::{
    audit, bus_caller, names as n,
    policy::{Op, Policy},
    run,
};
use super::{import, takeover, takeover_files};
use crate::{cli_mode, cli_ui};

const USAGE: &str = "\
usage: kepr secret-service run [--replace]
       kepr secret-service status
       kepr secret-service takeover [--now] [--no-import]
       kepr secret-service restore
       kepr secret-service import [--dry-run] [--overwrite]
       kepr secret-service log [-n N]
       kepr secret-service policy [check EXE [read|write|search]]";

fn say(m: &str) {
    if !cli_mode::json_mode() {
        cli_ui::info(m);
    }
}

pub fn cmd(args: &[&str]) -> Response {
    match args {
        ["run", rest @ ..] => match rest {
            [] => {
                run::run(&run::Options::default()).map_or_else(Response::fail, |()| Response::Pong)
            }
            ["--replace"] => {
                let o = run::Options {
                    replace: true,
                    ..Default::default()
                };
                run::run(&o).map_or_else(Response::fail, |()| Response::Pong)
            }
            _ => Response::fail(USAGE),
        },
        ["status"] | [] => status(),
        ["takeover", rest @ ..] => takeover::takeover(rest),
        ["restore"] => takeover::restore(),
        ["import", rest @ ..] => import::cmd(rest),
        ["log", rest @ ..] => log(rest),
        ["policy", rest @ ..] => policy(rest),
        _ => Response::fail(USAGE),
    }
}

fn status() -> Response {
    let conn = match super::bus::connect() {
        Ok(c) => c,
        Err(e) => return Response::fail(e),
    };
    let owner = bus_caller::owner_of(&conn, n::BUS_NAME);
    let line = match &owner {
        Some(o) if o.is_kepr() => format!("{} is served by kepr ({})", n::BUS_NAME, o.describe()),
        Some(o) => format!("{} is owned by {}, not by kepr", n::BUS_NAME, o.describe()),
        None => format!("{} has no owner yet: the first program to ask starts whoever the bus is configured to start", n::BUS_NAME),
    };
    say(&line);
    for l in takeover_files::report() {
        say(&l);
    }
    let pol = run::policy_path();
    say(&match Policy::load(&pol) {
        Ok(_) if pol.exists() => format!("policy: {}", pol.display()),
        Ok(_) => format!(
            "policy: none ({} would restrict programs); every program in this session may use it",
            pol.display()
        ),
        Err(e) => format!("policy: BROKEN, every program is refused: {e}"),
    });
    Response::Pong
}

fn log(args: &[&str]) -> Response {
    let count = match args {
        [] => 20,
        ["-n", v] => match v.parse::<usize>() {
            Ok(c) if c > 0 => c,
            _ => return Response::fail("-n takes a positive number"),
        },
        _ => return Response::fail(USAGE),
    };
    let path = audit::default_path();
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    let lines: Vec<&str> = text.lines().collect();
    if lines.is_empty() {
        say(&format!("nothing logged yet ({})", path.display()));
        return Response::Pong;
    }
    for l in &lines[lines.len().saturating_sub(count)..] {
        match audit::format_line(l) {
            Some(f) => println!("{f}"),
            None => println!("{l}"),
        }
    }
    Response::Pong
}

fn policy(args: &[&str]) -> Response {
    let path = run::policy_path();
    let pol = match Policy::load(&path) {
        Ok(p) => p,
        Err(e) => return Response::fail(e),
    };
    match args {
        [] => {
            say(&format!("policy file: {}", path.display()));
            if path.exists() {
                println!("{}", std::fs::read_to_string(&path).unwrap_or_default());
            } else {
                println!("{}", EXAMPLE);
            }
            Response::Pong
        }
        ["check", exe, rest @ ..] => {
            let op = match rest {
                [] | ["read"] => Op::Read,
                ["write"] => Op::Write,
                ["search"] => Op::Search,
                _ => return Response::fail(USAGE),
            };
            let who = super::ss::caller::Caller {
                name: ":0.0".into(),
                pid: None,
                uid: None,
                exe: Some((*exe).into()),
                sandboxed: false,
            };
            println!("{:?}", pol.check(&who, op));
            Response::Pong
        }
        _ => Response::fail(USAGE),
    }
}

const EXAMPLE: &str = "\
# No policy file yet; every program of the session may use the Secret Service.
# Example ~/.config/kepr/secret-service.toml (first matching rule wins):
#
#   default = \"allow\"
#
#   [[rule]]                  # nothing in a sandbox (kepr agent run) reads secrets
#   sandboxed = true
#   op = \"read\"
#   action = \"deny\"
#
#   [[rule]]                  # a browser may not read them; it may still store and search
#   exe = \"/usr/lib/chromium/chromium\"
#   op = \"read\"
#   action = \"deny\"";
