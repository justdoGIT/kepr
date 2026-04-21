// cli_cmds.rs — user-facing commands (set/get/list/delete/check).
//
// Pure presentation + orchestration: build a Request, call client::send_request,
// render the Response via cli_ui. No socket / crypto logic lives here.

use std::io::{self, BufRead, Write};

use crate::cli_args::Args;
use crate::cli_input::read_masked;
use crate::cli_ui::{bold, color, dim, einfo, err, info, ok, warn};
use crate::client::send_request;
use crate::generate::{generate_secret, GenKind};
use crate::protocol::{Request, Response};

// Dispatch a request, turning transport errors into a Response::Err.
// Centralises the "on send failure, print and fail" pattern.
fn dispatch(a: &Args, req: &Request) -> Response {
    match send_request(req) {
        Ok(resp) => resp,
        Err(e) => {
            if !a.json {
                err(&e);
            }
            Response::fail(e)
        }
    }
}

pub fn cmd_set(a: &Args) -> Response {
    let name = match &a.name {
        Some(n) => n.clone(),
        None => {
            if a.json {
                return Response::fail("NAME required");
            }
            bold("\n  kepr — set credential\n");
            eprint!(
                "  {}",
                color("0;36", "Credential name (e.g. OPENAI_API_KEY): ")
            );
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

    let (value_opt, gen_opt): (Option<String>, Option<String>) = if let Some(v) = &a.value {
        (Some(v.clone()), None)
    } else if a.generate {
        let s = generate_secret(a.gen_kind);
        if !a.json {
            ok(&format!(
                "Generated {} secret ({} chars)",
                a.gen_kind.as_str(),
                s.len()
            ));
        }
        (Some(s.to_owned_string()), None)
    } else {
        if a.json {
            return Response::fail("provide --value or --generate in json mode");
        }

        println!();
        bold(&format!("  Setting: {}", color("1;33", &name)));

        // Peek: does this credential already exist? Ignore network errors here —
        // the actual set call will surface them.
        if let Response::GetOk { .. } = dispatch(a, &Request::Get { name: name.clone() }) {
            warn(&format!("'{}' already exists.", name));
            eprint!("  {} ", color("0;36", "Overwrite? [y/N]:"));
            io::stderr().flush().ok();
            let mut ans = String::new();
            io::stdin().lock().read_line(&mut ans).ok();
            if ans.trim().to_lowercase() != "y" {
                info("Aborted.");
                return Response::fail("aborted");
            }
        }

        dim("  Leave blank to auto-generate. Input is hidden.\n");
        let val = read_masked(&format!(
            "  {} ",
            color(
                "0;36",
                &format!("Value for {name} (blank = auto-generate):")
            )
        ));

        if val.is_empty() {
            println!();
            info("Generating automatically.");
            info("  [1] hex      — 64-char hex token     (default)");
            info("  [2] base62   — 48-char alphanumeric");
            info("  [3] pass     — 32-char mixed symbols");
            info("  [4] uuid     — UUID4 format");
            eprint!("  {}", color("0;36", "Choice [1-4, default=1]: "));
            io::stderr().flush().ok();
            let mut c = String::new();
            io::stdin().lock().read_line(&mut c).ok();
            let kind = match c.trim() {
                "2" => GenKind::Base62,
                "3" => GenKind::Pass,
                "4" => GenKind::Uuid,
                _ => GenKind::Hex,
            };
            let s = generate_secret(kind);
            // Intentionally do not preview the value — even a 12-char
            // slice of a 36-char UUID leaks a third of the secret into
            // stdout (and shell history). Confirm only kind + length.
            ok(&format!(
                "Generated {} secret ({} chars)",
                kind.as_str(),
                s.len()
            ));
            (Some(s.to_owned_string()), None)
        } else {
            (Some(val.to_owned_string()), None)
        }
    };

    let req = Request::Set {
        name: name.clone(),
        value: value_opt,
        generate: gen_opt,
    };
    let resp = dispatch(a, &req);

    match &resp {
        Response::SetOk { name, .. } if !a.json => {
            println!();
            ok(&format!("Stored: {}", color("1", name)));
            dim(&format!("  Retrieve: kepr get {name}"));
            println!();
        }
        Response::Err { error } if !a.json => err(error),
        _ => {}
    }
    resp
}

pub fn cmd_get(a: &Args) -> Response {
    let name = match &a.name {
        Some(n) => n.clone(),
        None => {
            if !a.json {
                err("NAME required: kepr get KEY");
            }
            return Response::fail("NAME required");
        }
    };

    let resp = dispatch(a, &Request::Get { name: name.clone() });

    match &resp {
        Response::GetOk { name, value } => {
            if a.json {
                return resp;
            }
            if a.quiet {
                println!("{value}");
                return resp;
            }
            if a.export {
                println!("export {name}={value}");
                return resp;
            }
            println!();
            bold(&format!("  {name}"));
            println!("  {}", color("0;32", value));
            println!();
            resp
        }
        Response::Err { error } => {
            if !a.json {
                err(error);
                einfo(&format!("Set it with: kepr set {name}"));
            }
            resp
        }
        _ => {
            if !a.json {
                err("unexpected response");
            }
            Response::fail("unexpected response")
        }
    }
}

pub fn cmd_list(a: &Args) -> Response {
    let resp = dispatch(a, &Request::List);
    if a.json {
        return resp;
    }

    match &resp {
        Response::ListOk { credentials, .. } => {
            if credentials.is_empty() {
                info("No credentials stored.");
                return resp;
            }
            println!();
            bold(&format!("  Stored credentials ({})\n", credentials.len()));
            for c in credentials {
                println!(
                    "  {:<40} {}",
                    color("1", &c.name),
                    color("2", &format!("{}B  {}", c.size, c.modified))
                );
            }
            println!();
        }
        Response::Err { error } => err(error),
        _ => err("unexpected response"),
    }
    resp
}

pub fn cmd_delete(a: &Args) -> Response {
    let name = match &a.name {
        Some(n) => n.clone(),
        None => {
            if !a.json {
                err("NAME required: kepr delete KEY");
            }
            return Response::fail("NAME required");
        }
    };

    if !a.json && !a.force {
        warn(&format!("Delete '{name}'?"));
        eprint!("  {} ", color("0;36", "Confirm [y/N]:"));
        io::stderr().flush().ok();
        let mut ans = String::new();
        io::stdin().lock().read_line(&mut ans).ok();
        if ans.trim().to_lowercase() != "y" {
            info("Aborted.");
            return Response::fail("aborted");
        }
    }

    let resp = dispatch(a, &Request::Delete { name: name.clone() });
    match &resp {
        Response::DeleteOk { name } if !a.json => ok(&format!("Deleted: {name}")),
        Response::Err { error } if !a.json => err(error),
        _ => {}
    }
    resp
}

pub fn cmd_check(a: &Args) -> Response {
    let resp = dispatch(a, &Request::Check);
    if a.json {
        return resp;
    }

    match &resp {
        Response::CheckOk {
            results, all_ok, ..
        } => {
            if results.is_empty() {
                info("No credentials to check.");
                return resp;
            }
            println!();
            bold(&format!("  Checking {} credential(s)...\n", results.len()));
            let mut entries: Vec<(&String, &String)> = results.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            for (name, status) in entries {
                if status == "ok" {
                    ok(&format!("{:<40}", name));
                } else {
                    err(&format!("{:<40} FAILED", name));
                }
            }
            println!();
            if *all_ok {
                ok("All credentials verified.");
            } else {
                warn("Some credentials failed.");
            }
            println!();
        }
        Response::Err { error } => err(error),
        _ => err("unexpected response"),
    }
    resp
}
