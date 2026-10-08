// cli_cmds.rs — user-facing commands. Build Request, call client::send_request,
// render Response via cli_ui. No socket / crypto logic lives here.

use std::io::{self, BufRead, Read, Write};

use crate::cli_args::Args;
use crate::cli_envdump::shell_escape;
use crate::cli_input::read_masked;
use crate::cli_ui::{bold, color, dim, einfo, err, info, ok, warn};
use crate::client::send_request;
use kepr_core::generate::{generate_secret, GenKind};
use kepr_core::protocol::{Request, Response};

// Dispatch: on send failure, print and fail.
pub(crate) fn dispatch(a: &Args, req: &Request) -> Response {
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

    let (value_opt, gen_opt): (Option<kepr_core::generate::ZeroString>, Option<String>) = if a.stdin
    {
        if a.value.is_some() || a.generate {
            return Response::fail("--stdin cannot be combined with --value or --generate");
        }
        let mut input = Vec::new();
        if let Err(e) = io::stdin().read_to_end(&mut input) {
            return Response::fail(format!("cannot read secret from stdin: {e}"));
        }
        if input.last() == Some(&b'\n') {
            input.pop();
            if input.last() == Some(&b'\r') {
                input.pop();
            }
        }
        let value = match String::from_utf8(input) {
            Ok(v) if !v.is_empty() => v,
            Ok(_) => return Response::fail("stdin secret cannot be empty"),
            Err(_) => return Response::fail("stdin secret must be valid UTF-8"),
        };
        (Some(value.into()), None)
    } else if let Some(v) = &a.value {
        if !a.json {
            warn("Warning: --value exposes the secret in process arguments; prefer --stdin.");
        }
        (Some(v.clone().into()), None)
    } else if a.generate {
        let s = match crate::cli_recordsx::generate::generate(a.gen_kind, a.profile.as_deref()) {
            Ok(s) => s,
            Err(e) => return Response::fail(e),
        };
        if !a.json {
            ok(&format!(
                "Generated {} secret ({} chars)",
                a.profile.as_deref().unwrap_or(a.gen_kind.as_str()),
                s.len()
            ));
        }
        (Some(s), None)
    } else {
        if a.json {
            return Response::fail("provide --stdin, --value, or --generate in json mode");
        }

        println!();
        bold(&format!("  Setting: {}", color("1;33", &name)));

        if crate::cli_session::reauth::exists(dispatch(
            a,
            &Request::Get {
                name: name.clone(),
                fido2_assertion: None,
            },
        )) {
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
            info("  [1] hex    [2] base62   [3] pass   [4] uuid  (default: 1)");
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
            let s = match generate_secret(kind) {
                Ok(s) => s,
                Err(e) => return Response::fail(e),
            };
            ok(&format!(
                "Generated {} secret ({} chars)",
                kind.as_str(),
                s.len()
            ));
            (Some(s), None)
        } else {
            (Some(val), None)
        }
    };

    let req = Request::Set {
        name: name.clone(),
        value: value_opt,
        generate: gen_opt,
        ttl_secs: a.ttl_secs,
        requires_consent: a.requires_consent.then_some(true),
        requires_fido2: a.requires_fido2.then_some(true),
        sealed: None,
        bindings: None,
    };
    let resp = crate::cli_platform::exe::after_set(a, dispatch(a, &req)); // T10.09
    let resp = crate::cli_session::reauth::after_set(a, resp);

    match &resp {
        Response::SetOk {
            name,
            password_protected,
            ..
        } if !a.json => {
            println!();
            ok(&format!("Stored: {}", color("1", name)));
            dim(&format!("  Retrieve: kepr get {name}"));
            if !password_protected {
                warn("  Notice: Master key is un-wrapped at rest. Run `kepr lock` to set an Argon2id passphrase.");
            }
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

    let resp = crate::cli_session::reauth::dispatch_get(
        a,
        &Request::Get {
            name: name.clone(),
            fido2_assertion: None,
        },
    );

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
                // shell_escape prevents injection of $, backticks, quotes.
                println!("export {name}={}", shell_escape(value.as_str()));
                return resp;
            }
            println!();
            bold(&format!("  {name}"));
            println!("  {}", color("0;32", value));
            println!();
            resp
        }
        Response::Fido2Needed {
            challenge,
            credential_ids,
            ..
        } => {
            if !a.json {
                match crate::cli_fido2::run_fido2_ceremony(challenge, credential_ids) {
                    Ok(assertion) => {
                        let resp2 = dispatch(
                            a,
                            &Request::Get {
                                name: name.clone(),
                                fido2_assertion: Some(assertion),
                            },
                        );
                        match &resp2 {
                            Response::GetOk { value, .. } => {
                                if a.quiet {
                                    println!("{value}");
                                } else if a.export {
                                    println!("export {name}={}", shell_escape(value.as_str()));
                                } else {
                                    println!();
                                    bold(&format!("  {name}"));
                                    println!("  {}", color("0;32", value));
                                    println!();
                                }
                            }
                            Response::Err { error } => err(error),
                            _ => err("unexpected response after FIDO2"),
                        }
                        return resp2;
                    }
                    Err(e) => {
                        err(&format!("{} requires FIDO2 assertion.", name));
                        einfo(&format!("Ceremony failed: {e}"));
                        if credential_ids.is_empty() {
                            einfo("No keys. Register: kepr fido2-register LABEL CRED_ID COSE_KEY");
                        }
                    }
                }
            }
            Response::fail("fido2 required")
        }
        Response::Err { error } => {
            if !a.json {
                err(error);
                if !crate::cli_session::reauth::asked() {
                    einfo(&crate::cli_agent_cmd::get_failure_hint(&name));
                }
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
    let resp = crate::cli_store::filter_list(a, dispatch(a, &Request::List));
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
                // Flags from the sidecar meta: TTL, consent, record type.
                let mut tail = format!("{}B  {}", c.size, c.modified);
                if let Some(t) = &c.record_type {
                    tail.push_str(&format!("  [{t}]"));
                }
                if let Some(exp) = &c.expires_at {
                    tail.push_str(&format!("  (expires {exp})"));
                }
                if matches!(c.requires_consent, Some(true)) {
                    tail.push_str("  (consent required)");
                }
                tail.push_str(&crate::cli_store::list_tail(c));
                tail.push_str(crate::cli_session::reauth::list_tail(c)); // T11.14
                tail.push_str(crate::cli_sharing::list_tail(c)); // T6.07
                println!("  {:<40} {}", color("1", &c.name), color("2", &tail));
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
            for (n, s) in entries {
                if s == "ok" {
                    ok(&format!("{:<40}", n));
                } else {
                    err(&format!("{:<40} FAILED", n));
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

/// `kepr audit-verify` — verify the hash-chained audit log (Phase 2 δ.3).
pub fn cmd_audit_verify(a: &Args) -> Response {
    let resp = dispatch(a, &Request::AuditVerify);
    if a.json {
        return resp;
    }
    match &resp {
        Response::AuditOk { entries, last_hash } => {
            println!();
            let s = if *entries == 1 { "y" } else { "ies" };
            ok(&format!("audit chain verified: {entries} entr{s}"));
            dim(&format!("  head: {last_hash}"));
            println!();
        }
        Response::Err { error } => err(error),
        _ => err("unexpected response"),
    }
    resp
}

pub fn cmd_lock(a: &Args) -> Response {
    if a.lock_fido2 {
        return crate::cli_seal::fido2::cmd_lock_fido2(a);
    }
    let first = read_masked("  Lock password: ");
    if first.is_empty() {
        return Response::fail("password cannot be empty");
    }
    let second = read_masked("  Confirm password: ");
    if first.as_str() != second.as_str() {
        return Response::fail("passwords do not match");
    }
    let resp = dispatch(a, &Request::Lock { password: first });
    if !a.json {
        match &resp {
            Response::LockedOk => ok("Credential store locked."),
            Response::Err { error } => err(error),
            _ => err("unexpected response"),
        }
    }
    resp
}

pub fn cmd_unlock(a: &Args) -> Response {
    if let Some(r) = crate::cli_platform::fingerprint::cmd_unlock(a) {
        return r; // T10.03
    }
    // T4.09: with the security key's factor when the store has one.
    let password = match crate::cli_seal::fido2::store_passphrase("  Unlock password: ") {
        Ok(p) => p,
        Err(e) => return crate::cli_seal::fido2::failed(a, e),
    };
    let resp = dispatch(a, &Request::Unlock { password });
    if !a.json {
        match &resp {
            Response::UnlockedOk => ok("Credential store unlocked."),
            Response::Err { error } => err(error),
            _ => err("unexpected response"),
        }
    }
    resp
}

pub use crate::cli_fido2::{cmd_fido2_list, cmd_fido2_register};
pub use crate::cli_status::cmd_status;
