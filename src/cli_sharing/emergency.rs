// cli_sharing/emergency.rs — T6.06 `kepr emergency`.
//
//   (owner)   add CONTACT --delay 7d (--names A,B | --all) | ls | rm CONTACT
//             deny CONTACT
//   (contact) request OWNER_KEY [-o FILE]  make a request (with -o: a file
//             for the owner's machine; without: hand it to this daemon)
//             request --proof FILE         hand a request file to this daemon
//             fetch [-o DIR]               store what was released to you
//                                          (or write the envelopes to DIR)

use kepr_core::protocol::{Request, Response};
use kepr_core::protocol_sharing::{EmergencyInfo, SharingRequest, SharingResponse};

use super::{parse_duration, read_input, send, write_new};
use crate::cli_extra::{flag, positionals};
use crate::{cli_mode, cli_ui};

const USAGE: &str = "usage: kepr emergency add CONTACT --delay 7d (--names A,B | --all) | ls | \
                     rm CONTACT | deny CONTACT | request OWNER_KEY [-o FILE] | \
                     request --proof FILE | fetch [-o DIR]";

fn names_arg(args: &[String]) -> Result<Option<Vec<String>>, Response> {
    match (flag(args, "--names"), args.iter().any(|a| a == "--all")) {
        (Some(_), true) | (None, false) => Err(Response::fail(
            "choose what is released: --names A,B or --all",
        )),
        (None, true) => Ok(None),
        (Some(csv), false) => Ok(Some(
            csv.split(',')
                .map(|n| n.trim().to_uppercase())
                .filter(|n| !n.is_empty())
                .collect(),
        )),
    }
}

fn add(args: &[String]) -> Result<Response, Response> {
    let pos = positionals(args, &["--delay", "--names"]);
    let contact = pos.first().ok_or_else(|| Response::fail(USAGE))?;
    let delay = flag(args, "--delay").ok_or_else(|| Response::fail("--delay is required"))?;
    let delay_secs = parse_duration(delay).map_err(Response::fail)?;
    Ok(send(SharingRequest::EmergencyAdd {
        contact: contact.clone(),
        delay_secs,
        names: names_arg(args)?,
    }))
}

pub(crate) fn grant_line(g: &EmergencyInfo) -> String {
    let what = g
        .names
        .as_ref()
        .map_or_else(|| "all".to_string(), |n| n.join(","));
    let when = match (&g.released_at, &g.release_at) {
        (Some(t), _) => format!("released {t}"),
        (None, Some(t)) => format!("REQUESTED, releases {t} unless denied"),
        _ => "no request".into(),
    };
    format!(
        "  {:<24} {}  delay {}  [{what}]  {when}",
        g.contact,
        g.fingerprint,
        super::human_secs(g.delay_secs)
    )
}

fn request(args: &[String]) -> Result<Response, Response> {
    let proof = match flag(args, "--proof") {
        Some(path) => read_input(Some(path))?,
        None => {
            let pos = positionals(args, &["-o"]);
            let owner = pos.first().ok_or_else(|| Response::fail(USAGE))?;
            let r = send(SharingRequest::EmergencyProve {
                owner: owner.clone(),
            });
            let Response::Sharing(SharingResponse::EmergencyProof { proof }) = r else {
                return Ok(r);
            };
            if let Some(path) = flag(args, "-o") {
                write_new(path, &proof)?;
                if !cli_mode::json_mode() {
                    cli_ui::ok(&format!(
                        "request written to {path}: hand it to the owner's machine \
                         (kepr emergency request --proof {path}); valid 7 days"
                    ));
                }
                return Ok(Response::Pong);
            }
            proof
        }
    };
    Ok(send(SharingRequest::EmergencyRequest {
        proof: proof.trim().to_string(),
    }))
}

fn fetch(args: &[String]) -> Result<Response, Response> {
    let r = send(SharingRequest::EmergencyRelease);
    let Response::Sharing(SharingResponse::EmergencyEnvelopes { envelopes }) = &r else {
        return Ok(r);
    };
    if let Some(dir) = flag(args, "-o") {
        for (i, e) in envelopes.iter().enumerate() {
            let path = format!("{}/kepr-emergency-{}.txt", dir.trim_end_matches('/'), i + 1);
            write_new(&path, e)?;
            println!("{path}");
        }
        return Ok(r);
    }
    let mut stored = 0;
    for e in envelopes {
        let got = crate::client::send_request(&Request::ShareReceive {
            envelope: e.clone(),
            name: None,
        })
        .unwrap_or_else(Response::fail);
        match got {
            Response::SetOk { name, .. } => {
                stored += 1;
                cli_ui::einfo(&format!("stored {name}"));
            }
            Response::Err { error } => cli_ui::einfo(&format!("skipped one: {error}")),
            _ => {}
        }
    }
    Ok(super::done_line(format!(
        "{stored} of {} released credential(s) stored",
        envelopes.len()
    )))
}

pub fn cmd_emergency(args: &[String]) -> Response {
    let rest = args.get(1..).unwrap_or_default();
    let one = |f: fn(String) -> SharingRequest| match rest {
        [who] => Ok(send(f(who.clone()))),
        _ => Err(Response::fail(USAGE)),
    };
    let r = match args.first().map(String::as_str) {
        Some("add") => add(rest),
        Some("ls" | "list") => Ok(send(SharingRequest::EmergencyList)),
        Some("rm" | "remove") => one(|contact| SharingRequest::EmergencyRemove { contact }),
        Some("deny") => one(|contact| SharingRequest::EmergencyDeny { contact }),
        Some("request") => request(rest),
        Some("fetch") => fetch(rest),
        _ => Err(Response::fail(USAGE)),
    };
    let r = r.unwrap_or_else(|e| e);
    if cli_mode::json_mode() {
        return r;
    }
    match &r {
        Response::Sharing(SharingResponse::EmergencyListing { grants }) if grants.is_empty() => {
            cli_ui::info("No emergency contacts (kepr emergency add CONTACT --delay 7d --all).")
        }
        Response::Sharing(SharingResponse::EmergencyListing { grants }) => {
            for g in grants {
                println!("{}", grant_line(g));
            }
        }
        Response::Sharing(SharingResponse::SharingDone { message }) => cli_ui::ok(message),
        _ => {}
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn what_is_released_must_be_chosen() {
        assert!(names_arg(&args(&[])).is_err());
        assert!(names_arg(&args(&["--all", "--names", "A"])).is_err());
        assert_eq!(names_arg(&args(&["--all"])).unwrap(), None);
        assert_eq!(
            names_arg(&args(&["--names", "api_key, db ,"])).unwrap(),
            Some(vec!["API_KEY".to_string(), "DB".to_string()])
        );
    }

    #[test]
    fn grant_lines_show_the_state() {
        let mut g = EmergencyInfo {
            contact: "bob".into(),
            fingerprint: "ab".into(),
            delay_secs: 7 * 86_400,
            names: None,
            state: "requested".into(),
            requested_at: Some("2026-10-01 10:00".into()),
            release_at: Some("2026-10-08 10:00".into()),
            released_at: None,
        };
        let l = grant_line(&g);
        assert!(l.contains("7d") && l.contains("[all]"), "{l}");
        assert!(l.contains("REQUESTED, releases 2026-10-08 10:00"), "{l}");
        g.released_at = Some("2026-10-08 10:01".into());
        assert!(grant_line(&g).ends_with("released 2026-10-08 10:01"));
    }

    #[test]
    fn usage_errors() {
        for bad in [&[][..], &["rm".to_string()][..], &["add".to_string()][..]] {
            assert!(matches!(cmd_emergency(bad), Response::Err { .. }));
        }
    }
}
