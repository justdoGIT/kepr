// cli_syncx/quorum.rs — T7.12 M-of-N approvals.
//
//   kepr quorum set KEY N|off            KEY needs N (2-9) approvals per use
//   kepr quorum request KEY [--for 1h]   ask; prints the request for devices
//   kepr quorum approve ID               the owner, here (polkit prompt)
//   kepr quorum approve ID --with APPROVAL   an enrolled device's approval
//   kepr quorum sign REQUEST             on that device: approve, print it
//   kepr quorum ls
//
// The daemon keeps requests and windows (daemon_syncx/quorum*.rs); texts
// travel between devices by hand (or any channel: they carry no secret,
// and an approval is bound to its request and its device).

use base64::Engine;
use kepr_core::protocol::{Request, Response};
use kepr_core::protocol_syncx::{QuorumState, SyncxRequest, SyncxResponse};
use sha2::{Digest, Sha256};

use crate::{cli_ui, client};

const USAGE: &str = "usage: kepr quorum set KEY N|off | request KEY [--for 1h] \
     | approve ID [--with APPROVAL] | sign REQUEST | ls";
const DEFAULT_WINDOW: u64 = 3600;

fn send(r: SyncxRequest) -> Response {
    match client::send_request(&Request::from(r)) {
        Ok(r) => r,
        Err(e) => Response::fail(e),
    }
}

/// "for 59 more minutes" until `until` (unix seconds).
fn left(until: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mins = until.saturating_sub(now).div_ceil(60);
    format!("for {mins} more minute(s)")
}

fn show(r: &Response) {
    if cli_ui::json_mode() {
        return;
    }
    match r {
        Response::Syncx(SyncxResponse::QuorumStatus(q)) if !q.done => {
            let QuorumState {
                id,
                name,
                action,
                have,
                need,
                ..
            } = &**q;
            cli_ui::info(&format!(
                "request {id}: {action} of {name}, {have} of {need} approvals"
            ));
            println!("{}", q.request);
            cli_ui::einfo(&format!(
                "approve here: kepr quorum approve {id}; on an enrolled device: kepr quorum sign \
                 <the line above>, then here: kepr quorum approve {id} --with <its approval>"
            ));
        }
        Response::Syncx(SyncxResponse::QuorumStatus(q)) => match q.until {
            Some(u) => cli_ui::ok(&format!("approved: {} can be used {}", q.name, left(u))),
            None => cli_ui::ok(&format!("approved: {} of {}", q.action, q.name)),
        },
        Response::Syncx(SyncxResponse::QuorumSetOk { name, approvals: 0 }) => {
            cli_ui::ok(&format!("{name} needs no approvals"))
        }
        Response::Syncx(SyncxResponse::QuorumSetOk { name, approvals }) => {
            cli_ui::ok(&format!("{name} now needs {approvals} approvals per use"))
        }
        Response::Syncx(SyncxResponse::QuorumApproval { approval }) => {
            println!("{approval}");
            cli_ui::einfo(
                "give this approval to the requesting machine (kepr quorum approve ID --with …)",
            );
        }
        Response::Syncx(SyncxResponse::QuorumList { keys, open }) => {
            if keys.is_empty() && open.is_empty() {
                cli_ui::info("No credential needs approvals (kepr quorum set KEY N).");
            }
            for k in keys {
                let w = k.until.map(|u| format!("  open {}", left(u)));
                println!(
                    "{:<32} {} approvals{}",
                    k.name,
                    k.approvals,
                    w.unwrap_or_default()
                );
            }
            for o in open {
                println!(
                    "request {}  {} of {}  {}/{}",
                    o.id, o.action, o.name, o.have, o.need
                );
            }
        }
        _ => {}
    }
}

/// What a request asks, decoded here so the human sees it before the
/// polkit prompt: (name, action, requesting device id).
fn describe(request: &str) -> Option<(String, String, String)> {
    let raw = request.trim().strip_prefix("kepr-quorum1-")?;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(raw)
        .ok()?;
    let v: serde_json::Value = serde_json::from_slice(&raw).ok()?;
    let owner = v["owner"].as_str()?;
    let device = hex::encode(&Sha256::digest(owner.as_bytes())[..4]);
    Some((
        v["name"].as_str()?.into(),
        v["action"].as_str()?.into(),
        device,
    ))
}

fn run(args: &[String]) -> Result<Response, String> {
    let rest = args.get(1..).unwrap_or_default();
    let pos: Vec<&str> = rest
        .iter()
        .map(String::as_str)
        .filter(|a| !a.starts_with('-'))
        .collect();
    Ok(match (args.first().map(String::as_str), pos.as_slice()) {
        (Some("set"), [key, n]) => {
            super::check_flags(rest, &[], &[])?;
            let approvals = match *n {
                "off" => 0,
                n => n.parse().map_err(|_| USAGE.to_string())?,
            };
            send(SyncxRequest::QuorumSet {
                name: key.to_uppercase(),
                approvals,
            })
        }
        (Some("request"), [key] | [key, _]) => {
            super::check_flags(rest, &["--for"], &[])?;
            let secs = match crate::cli_extra::flag(rest, "--for") {
                Some(d) => crate::cli_sharing::parse_duration(d)?,
                None if pos.len() == 1 => DEFAULT_WINDOW,
                None => return Err(USAGE.into()),
            };
            send(SyncxRequest::QuorumRequest {
                name: key.to_uppercase(),
                secs,
            })
        }
        (Some("approve"), [id] | [id, _]) => {
            super::check_flags(rest, &["--with"], &[])?;
            let approval = crate::cli_extra::flag(rest, "--with").map(str::to_string);
            if pos.len() == 2 && approval.is_none() {
                return Err(USAGE.into());
            }
            send(SyncxRequest::QuorumApprove {
                id: id.to_string(),
                approval,
            })
        }
        (Some("sign"), [request]) => {
            super::check_flags(rest, &[], &[])?;
            let (name, action, device) =
                describe(request).ok_or("not a kepr approval request (kepr-quorum1-…)")?;
            if !cli_ui::json_mode() {
                cli_ui::einfo(&format!(
                    "device {device} asks: {action} of {name}; approve it at the prompt"
                ));
            }
            send(SyncxRequest::QuorumSign {
                request: request.to_string(),
            })
        }
        (Some("ls"), []) => send(SyncxRequest::QuorumList),
        _ => return Err(USAGE.into()),
    })
}

pub fn cmd_quorum(args: &[String]) -> Response {
    let r = run(args).unwrap_or_else(Response::fail);
    show(&r);
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn usage_is_checked_before_the_daemon_is_asked() {
        for bad in [
            &[][..],
            &["set", "K"],
            &["set", "K", "two"],
            &["request"],
            &["request", "K", "--for", "soon"],
            &["request", "K", "--until", "1h"],
            &["approve"],
            &["sign", "kepr-quorum1-!!"],
            &["ls", "x"],
        ] {
            assert!(run(&v(bad)).is_err(), "{bad:?}");
        }
        let text = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            br#"{"owner":"kepr-pk2-x","id":"1","name":"API","action":"use for 1h","expires_at":1}"#,
        );
        let (name, action, device) = describe(&format!("kepr-quorum1-{text}")).unwrap();
        assert_eq!(
            (name.as_str(), action.as_str(), device.len()),
            ("API", "use for 1h", 8)
        );
    }
}
