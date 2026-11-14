// cli_session/reauth.rs — client side of re-authentication before reveal
// (T11.14). When the daemon answers a read with exactly `REAUTH_NEEDED`,
// ask for the store passphrase on the terminal, send `Reauth` (which
// opens a 60 s window for that credential) and retry once. Without a
// terminal (scripts, `kepr ui`, MCP) nothing is asked: the error says to
// run `kepr reauth NAME` first.

use std::io::IsTerminal;

use kepr_core::protocol::{CredInfo, Request, Response};
use kepr_core::protocol_session::{SessionRequest, SessionResponse, REAUTH_NEEDED};

use crate::cli_args::Args;
use crate::cli_ui::{dim, json_mode, ok};

/// Is `r` the daemon's "ask for the passphrase first" answer?
pub fn is_needed(r: &Response) -> bool {
    matches!(r, Response::Err { error } if error == REAUTH_NEEDED)
}

fn send(req: SessionRequest) -> Response {
    crate::client::send_request(&Request::Session(req)).unwrap_or_else(Response::fail)
}

/// `kepr set`'s overwrite check: a value that needs re-auth exists too.
pub fn exists(r: Response) -> bool {
    matches!(r, Response::GetOk { .. }) || is_needed(&r)
}

/// Ask for the store passphrase and open `name`'s reveal window.
pub fn ask_and_open(name: &str) -> Result<(), String> {
    if !std::io::stdin().is_terminal() {
        return Err(format!(
            "{name} needs the store passphrase: run `kepr reauth {name}` first"
        ));
    }
    let passphrase =
        crate::cli_input::read_masked(&format!("  Store passphrase to reveal {name}: "));
    match send(SessionRequest::Reauth {
        name: name.to_string(),
        passphrase,
    }) {
        Response::Session(SessionResponse::ReauthOk { .. }) => Ok(()),
        Response::Err { error } => Err(error),
        _ => Err("unexpected daemon response".into()),
    }
}

static ASKED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Did a read in this process run into re-authentication? Its errors
/// already say what to do, so `kepr get` skips its "Set it with" hint.
pub fn asked() -> bool {
    ASKED.load(std::sync::atomic::Ordering::Relaxed)
}

/// `get()`, and once more after the passphrase if the daemon asks for it.
pub fn get_or_ask(
    name: &str,
    get: impl Fn() -> Result<Response, String>,
) -> Result<Response, String> {
    let first = get()?;
    if !is_needed(&first) {
        return Ok(first);
    }
    ASKED.store(true, std::sync::atomic::Ordering::Relaxed);
    ask_and_open(name)?;
    get()
}

/// `kepr get`'s transport: `cli_cmds::dispatch`, asking for the
/// passphrase when needed (not in `--json` mode).
pub fn dispatch_get(a: &Args, req: &Request) -> Response {
    let name = match req {
        Request::Get { name, .. } if !a.json => name.clone(),
        _ => return crate::cli_cmds::dispatch(a, req),
    };
    get_or_ask(&name, || Ok(crate::cli_cmds::dispatch(a, req))).unwrap_or_else(Response::fail)
}

/// `kepr set NAME --reauth`: flag the value just stored.
pub fn after_set(a: &Args, resp: Response) -> Response {
    let (Response::SetOk { name, .. }, true) = (&resp, a.session.reauth) else {
        return resp;
    };
    match send(SessionRequest::ReauthFlag {
        name: name.clone(),
        on: true,
    }) {
        Response::Session(SessionResponse::ReauthFlagOk { .. }) => {
            if !a.json {
                dim("  Revealing it will ask for the store passphrase (60 s per unlock).");
            }
            resp
        }
        Response::Err { error } => Response::fail(format!("{name} was stored, but {error}")),
        _ => Response::fail("unexpected daemon response"),
    }
}

/// `kepr ls` column.
pub fn list_tail(c: &CredInfo) -> &'static str {
    if c.requires_reauth == Some(true) {
        "  (reauth)"
    } else {
        ""
    }
}

/// `kepr reauth NAME [--on|--off]`.
pub fn cmd_reauth(args: &[&str]) -> Response {
    let (name, mode) = match args {
        [name] => (name, None),
        [name, "--on"] => (name, Some(true)),
        [name, "--off"] => (name, Some(false)),
        _ => return Response::fail(USAGE),
    };
    let name = name.to_uppercase();
    let resp = match mode {
        None => match ask_and_open(&name) {
            Ok(()) => Response::Session(SessionResponse::ReauthOk {
                name: name.clone(),
                valid_secs: kepr_core::protocol_session::REAUTH_WINDOW_SECS,
            }),
            Err(e) => Response::fail(e),
        },
        Some(on) => {
            let flag = || {
                Ok(send(SessionRequest::ReauthFlag {
                    name: name.clone(),
                    on,
                }))
            };
            get_or_ask(&name, flag).unwrap_or_else(Response::fail)
        }
    };
    if !json_mode() {
        match &resp {
            Response::Session(SessionResponse::ReauthOk { valid_secs, .. }) => {
                ok(&format!("{name} can be revealed for {valid_secs} s."))
            }
            Response::Session(SessionResponse::ReauthFlagOk { on: true, .. }) => ok(&format!(
                "{name} now asks for the store passphrase before it is revealed."
            )),
            Response::Session(SessionResponse::ReauthFlagOk { on: false, .. }) => {
                ok(&format!("{name} no longer asks for the store passphrase."))
            }
            _ => {}
        }
    }
    resp
}

const USAGE: &str = "usage: kepr reauth KEY [--on|--off]";

/// Flags this batch adds to core verbs, parsed by `cli_args.rs`.
pub const FLAGS: &[&str] = &["--reauth", "--pull"];

#[derive(Debug, Default)]
pub struct SessionFlags {
    /// `set --reauth` (T11.14).
    pub reauth: bool,
    /// `exec --pull A,B` (T3.06), repeatable.
    pub pull: Vec<String>,
}

impl SessionFlags {
    /// Take the flag at `raw[i]`; returns the next index.
    pub fn take(&mut self, raw: &[String], i: usize) -> Result<usize, String> {
        match raw[i].as_str() {
            "--reauth" => self.reauth = true,
            "--pull" => {
                let csv = raw.get(i + 1).ok_or("--pull needs NAME[,NAME…]")?;
                self.pull.extend(super::pull::parse(csv)?);
                return Ok(i + 2);
            }
            other => return Err(format!("unknown flag: {other}")),
        }
        Ok(i + 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn needed() -> Response {
        Response::fail(REAUTH_NEEDED)
    }

    #[test]
    fn only_the_exact_marker_asks() {
        assert!(is_needed(&needed()));
        assert!(!is_needed(&Response::fail("credential unavailable")));
        assert!(!is_needed(&Response::fail("reauth needed!")));
        assert!(exists(needed()));
        assert!(!exists(Response::fail("credential unavailable")));
    }

    #[test]
    fn get_or_ask_retries_only_after_the_marker() {
        let calls = Cell::new(0);
        let r = get_or_ask("K", || {
            calls.set(calls.get() + 1);
            Ok(Response::fail("credential unavailable"))
        });
        assert_eq!(calls.get(), 1);
        assert!(!is_needed(&r.unwrap()));
        // Tests have no terminal: the marker turns into the hint, with
        // no second request. If stdin is a terminal, skip to avoid blocking on read_masked.
        if !std::io::stdin().is_terminal() {
            let calls = Cell::new(0);
            let r = get_or_ask("K", || {
                calls.set(calls.get() + 1);
                Ok(needed())
            });
            assert_eq!(calls.get(), 1);
            assert!(r.unwrap_err().contains("kepr reauth K"));
        }
    }

    #[test]
    fn parses_the_set_flag_and_usage() {
        let raw: Vec<String> = ["kepr", "set", "K", "--reauth"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let mut f = SessionFlags::default();
        assert_eq!(f.take(&raw, 3), Ok(4));
        assert!(f.reauth);
        assert!(cmd_reauth(&[]).err_msg().unwrap().starts_with("usage"));
        assert!(cmd_reauth(&["K", "--maybe"]).err_msg().is_some());
    }

    #[test]
    fn list_column() {
        let mut c: CredInfo = serde_json::from_value(serde_json::json!({
            "name": "K", "cred_name": "", "size": 1, "modified": ""
        }))
        .unwrap();
        assert_eq!(list_tail(&c), "");
        c.requires_reauth = Some(true);
        assert_eq!(list_tail(&c), "  (reauth)");
    }
}
