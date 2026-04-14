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

pub fn cmd_set(a: &Args) -> Response {
    let name = match &a.name {
        Some(n) => n.clone(),
        None => {
            if a.json { return Response::fail("NAME required"); }
            bold("\n  credman — set credential\n");
            eprint!("  {}", color("0;36", "Credential name (e.g. OPENAI_API_KEY): "));
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
            ok(&format!("Generated {} secret ({} chars)", a.gen_kind.as_str(), s.len()));
        }
        (Some(s.to_owned_string()), None)

    } else {
        if a.json {
            return Response::fail("provide --value or --generate in json mode");
        }

        println!();
        bold(&format!("  Setting: {}", color("1;33", &name)));

        let check_req = Request::Get { name: name.clone() };
        if let Ok(r) = send_request(&check_req) {
            if r.ok {
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
        }

        dim("  Leave blank to auto-generate. Input is hidden.\n");
        let val = read_masked(&format!("  {} ",
            color("0;36", &format!("Value for {name} (blank = auto-generate):"))));

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
                _   => GenKind::Hex,
            };
            let s = generate_secret(kind);
            let preview = format!("{}...{}", &s[..8], &s[s.len()-4..]);
            ok(&format!("Generated: {}", color("2", &preview)));
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
                ok(&format!("Stored: {}", color("1", &name)));
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

pub fn cmd_get(a: &Args) -> Response {
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

            if a.json   { return resp; }
            if a.quiet  { println!("{val}"); return resp; }
            if a.export { println!("export {name}={val}"); return resp; }

            println!();
            bold(&format!("  {name}"));
            println!("  {}", color("0;32", val));
            println!();
            resp
        }
    }
}

pub fn cmd_list(a: &Args) -> Response {
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
                    color("1", &c.name),
                    color("2", &format!("{}B  {}", c.size, c.modified)));
            }
            println!();
            resp
        }
    }
}

pub fn cmd_delete(a: &Args) -> Response {
    let name = match &a.name {
        Some(n) => n.clone(),
        None => {
            if !a.json { err("NAME required: credman delete KEY"); }
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

    match send_request(&Request::Delete { name: name.clone() }) {
        Err(e) => { if !a.json { err(&e); } Response::fail(&e) }
        Ok(resp) => {
            if resp.ok  && !a.json { ok(&format!("Deleted: {name}")); }
            if !resp.ok && !a.json { err(resp.error.as_deref().unwrap_or("failed")); }
            resp
        }
    }
}

pub fn cmd_check(a: &Args) -> Response {
    match send_request(&Request::Check) {
        Err(e) => { if !a.json { err(&e); } Response::fail(&e) }
        Ok(resp) => {
            if a.json { return resp; }

            if let Some(r) = resp.results.as_ref() {
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
                if resp.ok { ok("All credentials verified."); }
                else       { warn("Some credentials failed."); }
                println!();
            } else {
                info("No credentials to check.");
            }
            resp
        }
    }
}
