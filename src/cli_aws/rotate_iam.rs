// rotate_iam.rs — `kepr rotate NAME --aws-iam` (T7.05).
//
// Rotates a stored IAM user access key through the IAM API, in the
// user's CLI process (the daemon has no network):
//
//   1. GetCallerIdentity with the old key (it works; whose it is)
//   2. ListAccessKeys: refuse when the user already has two (IAM limit)
//   3. CreateAccessKey
//   4. GetCallerIdentity with the new key until it answers for the same
//      principal (IAM is eventually consistent). If it never does, the
//      new key is deleted and NAME keeps the old one.
//   5. store the new key with `set` (audited as a regular set)
//   6. DeleteAccessKey for the old key, signed with the new one
//
// Validate-then-commit like `kepr rotate --hook`: the store only ever
// holds a key that AWS has accepted. Sealed keys are refused (their
// value never leaves the gate, so the CLI can't sign with them).

use kepr_core::generate::ZeroString;
use kepr_core::protocol::{Request, Response};
use kepr_core::sigv4_req::AwsKey;

use super::iam;
use super::sts::{self, Endpoint};
use crate::cli_exec::DaemonFetcher;

/// IAM's limit on access keys per user.
const MAX_KEYS: usize = 2;

pub struct Rotation<'a> {
    pub iam: Endpoint,
    pub sts: Endpoint,
    pub now: &'a dyn Fn() -> u64,
    /// Pause before verification attempt `n` (1-based).
    pub pause: &'a dyn Fn(u32),
    pub attempts: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Rotated {
    pub old_id: String,
    pub new_id: String,
}

/// `AKIA…WXYZ`: enough to tell keys apart in messages.
pub fn short(id: &str) -> String {
    let n = id.len();
    if n < 8 || !id.is_ascii() {
        return "…".into();
    }
    format!("{}…{}", &id[..4], &id[n - 4..])
}

/// Steps 1–4; on success the verified new key.
fn create_verified(r: &Rotation, old: &AwsKey) -> Result<AwsKey, String> {
    if old.session_token.is_some() {
        return Err(
            "temporary credentials (with a session token) can't be rotated; \
             store the IAM user's long-lived access key"
                .into(),
        );
    }
    let who = sts::get_caller_identity(&r.sts, old, (r.now)())?;
    let ids = iam::list_access_keys(&r.iam, old, (r.now)())?;
    if ids.len() >= MAX_KEYS {
        return Err(format!(
            "{} already has {} access keys (the IAM limit): delete the one kepr does not \
             hold ({}), then rotate again",
            who.arn,
            ids.len(),
            ids.iter()
                .filter(|i| **i != old.access_key_id)
                .map(|i| short(i))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    let new = iam::create_access_key(&r.iam, old, (r.now)())?;
    let new = AwsKey::parse(new.to_json().as_str()).map_err(|_| "IAM returned a malformed key")?;
    let mut why = String::from("no attempt made");
    for n in 1..=r.attempts {
        (r.pause)(n);
        match sts::get_caller_identity(&r.sts, &new, (r.now)()) {
            Ok(id) if id.arn == who.arn => return Ok(new),
            Ok(id) => {
                why = format!("it answers for {}, not {}", id.arn, who.arn);
                break;
            }
            Err(e) => why = e,
        }
    }
    let cleanup = match iam::delete_access_key(&r.iam, old, &new.access_key_id, (r.now)()) {
        Ok(()) => "it was deleted again".to_string(),
        Err(e) => format!("deleting it failed too ({e}): delete it in the IAM console"),
    };
    Err(format!(
        "the new key {} did not verify ({why}); {cleanup}",
        short(&new.access_key_id)
    ))
}

/// The whole rotation; `store` commits the new key.
pub fn rotate(
    r: &Rotation,
    old: &AwsKey,
    store: &mut dyn FnMut(&AwsKey) -> Result<(), String>,
) -> Result<Rotated, String> {
    let new = create_verified(r, old)?;
    if let Err(e) = store(&new) {
        let cleanup = match iam::delete_access_key(&r.iam, old, &new.access_key_id, (r.now)()) {
            Ok(()) => "the new key was deleted again".to_string(),
            Err(d) => format!(
                "deleting the new key {} failed too ({d}): delete it in the IAM console",
                short(&new.access_key_id)
            ),
        };
        return Err(format!("storing the new key failed ({e}); {cleanup}"));
    }
    let done = Rotated {
        old_id: old.access_key_id.clone(),
        new_id: new.access_key_id.clone(),
    };
    iam::delete_access_key(&r.iam, &new, &old.access_key_id, (r.now)()).map_err(|e| {
        format!(
            "the new key {} is stored and works, but deleting the old key {} failed ({e}): \
             delete it in the IAM console",
            short(&done.new_id),
            short(&done.old_id)
        )
    })?;
    Ok(done)
}

/// `set NAME` with the new key's JSON; the daemon's answer.
fn store_key(name: &str, key: &AwsKey) -> Result<Response, String> {
    let value: ZeroString = key.to_json();
    match crate::client::send_request(&Request::Set {
        name: name.to_string(),
        value: Some(value),
        generate: None,
        ttl_secs: None,
        requires_consent: None,
        requires_fido2: None,
        sealed: None,
        bindings: None,
    }) {
        Ok(r @ Response::SetOk { .. }) => Ok(r),
        Ok(Response::Err { error }) => Err(error),
        Ok(_) => Err("unexpected daemon response".into()),
        Err(e) => Err(format!("daemon unreachable: {e}")),
    }
}

/// Rotate `old` in production (IAM, STS, the daemon's `set NAME`).
/// `Ok` carries the daemon's `SetOk`; `Err` says whether the new key
/// reached the store before the failure.
pub fn run(name: &str, old: &AwsKey) -> Result<(Rotated, Response), (String, bool)> {
    let human = !crate::cli_ui::json_mode();
    let sts_ep = super::sts_endpoint(None).map_err(|e| (e, false))?;
    let pause = |n: u32| {
        if human && n == 2 {
            crate::cli_ui::dim("  waiting for AWS to accept the new key…");
        }
        std::thread::sleep(std::time::Duration::from_secs(u64::from((n * 2).min(6))));
    };
    let r = Rotation {
        iam: Endpoint::iam(),
        sts: sts_ep,
        now: &sts::now_secs,
        pause: &pause,
        attempts: 10,
    };
    let mut stored = None;
    let out = rotate(&r, old, &mut |k| {
        stored = Some(store_key(name, k)?);
        Ok(())
    });
    match (out, stored) {
        (Ok(done), Some(resp)) => Ok((done, resp)),
        (Ok(_), None) => Err(("rotation finished without storing the key".into(), false)),
        (Err(e), s) => Err((e, s.is_some())),
    }
}

pub fn cmd(name: &str) -> Response {
    let name = name.to_uppercase();
    let human = !crate::cli_ui::json_mode();
    let result = super::load_key(&name, &DaemonFetcher)
        .map_err(|e| (e, false))
        .and_then(|old| run(&name, &old));
    match result {
        Ok((done, resp)) => {
            if human {
                crate::cli_ui::ok(&format!(
                    "{name} rotated: new key {} verified and stored; old key {} deleted.",
                    short(&done.new_id),
                    short(&done.old_id)
                ));
            }
            resp
        }
        Err((e, stored)) => {
            let e = if stored {
                e
            } else {
                format!("{e} ({name} keeps its old key)")
            };
            if human {
                crate::cli_ui::err(&e);
            }
            Response::fail(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli_aws::fake;
    use crate::cli_aws::iam::tests::{create_xml, list_xml, DELETE_XML};
    use std::cell::Cell;

    const OLD: &str = "AKIAOLDOLDOLDOLD0001";
    const NEW: &str = "AKIANEWNEWNEWNEW0002";

    fn id_xml(arn: &str) -> String {
        format!(
            "<GetCallerIdentityResult><Arn>{arn}</Arn><UserId>AIDA1</UserId>\
             <Account>123456789012</Account></GetCallerIdentityResult>"
        )
    }

    fn old_key() -> AwsKey {
        AwsKey::parse(&format!(
            r#"{{"access_key_id":"{OLD}","secret_access_key":"OLD/secret"}}"#
        ))
        .unwrap()
    }

    const BOB: &str = "arn:aws:iam::123456789012:user/bob";
    const DENIED: &str = "<ErrorResponse><Error><Code>InvalidClientTokenId</Code>\
        <Message>not yet</Message></Error></ErrorResponse>";

    /// Runs a rotation against `replies`; returns the result, what was
    /// stored, and every request the fake saw (in order).
    fn run(
        replies: Vec<(u16, String)>,
        attempts: u32,
        store_ok: bool,
    ) -> (Result<Rotated, String>, Option<String>, Vec<String>) {
        let n = replies.len();
        let f = fake::serve(replies);
        let ep = |e: Endpoint| Endpoint {
            url: f.url.clone(),
            ..e
        };
        let pauses = Cell::new(0);
        let r = Rotation {
            iam: ep(Endpoint::iam()),
            sts: ep(Endpoint::sts(None).unwrap()),
            now: &|| 1_440_938_160,
            pause: &|_| pauses.set(pauses.get() + 1),
            attempts,
        };
        let mut stored = None;
        let out = rotate(&r, &old_key(), &mut |k| {
            stored = Some(k.to_json().as_str().to_string());
            if store_ok {
                Ok(())
            } else {
                Err("disk full".into())
            }
        });
        let reqs = f.requests.try_iter().take(n).collect();
        (out, stored, reqs)
    }

    fn action(req: &str) -> &str {
        let body = req.rsplit("\r\n\r\n").next().unwrap();
        body.split('&').next().unwrap()
    }

    #[test]
    fn rotates_verifies_stores_then_deletes_the_old_key() {
        let (out, stored, reqs) = run(
            vec![
                (200, id_xml(BOB)),
                (200, list_xml(&[OLD])),
                (200, create_xml(NEW, "NEW/secret")),
                (403, DENIED.into()),
                (200, id_xml(BOB)),
                (200, DELETE_XML.into()),
            ],
            5,
            true,
        );
        assert_eq!(
            out.unwrap(),
            Rotated {
                old_id: OLD.into(),
                new_id: NEW.into()
            }
        );
        let stored: serde_json::Value = serde_json::from_str(&stored.unwrap()).unwrap();
        assert_eq!(stored["access_key_id"], NEW);
        assert_eq!(stored["secret_access_key"], "NEW/secret");
        let acts: Vec<&str> = reqs.iter().map(|r| action(r)).collect();
        assert_eq!(
            acts,
            [
                "Action=GetCallerIdentity",
                "Action=ListAccessKeys",
                "Action=CreateAccessKey",
                "Action=GetCallerIdentity",
                "Action=GetCallerIdentity",
                "Action=DeleteAccessKey"
            ]
        );
        // The old key is deleted, signed with the new one.
        assert!(reqs[5].ends_with(&format!("AccessKeyId={OLD}")));
        assert!(reqs[5].contains(&format!("Credential={NEW}/")));
        assert!(reqs[4].contains(&format!("Credential={NEW}/")));
    }

    #[test]
    fn refuses_when_the_user_already_has_two_keys() {
        let other = "AKIAOTHEROTHEROTH003";
        let (out, stored, reqs) = run(
            vec![(200, id_xml(BOB)), (200, list_xml(&[OLD, other]))],
            3,
            true,
        );
        let e = out.unwrap_err();
        assert!(
            e.contains("2 access keys") && e.contains("AKIA…H003"),
            "{e}"
        );
        assert!(stored.is_none());
        assert_eq!(reqs.len(), 2, "nothing is created");
    }

    #[test]
    fn old_key_kept_and_new_key_deleted_if_verification_fails() {
        let (out, stored, reqs) = run(
            vec![
                (200, id_xml(BOB)),
                (200, list_xml(&[OLD])),
                (200, create_xml(NEW, "NEW/secret")),
                (403, DENIED.into()),
                (403, DENIED.into()),
                (200, DELETE_XML.into()),
            ],
            2,
            true,
        );
        let e = out.unwrap_err();
        assert!(
            e.contains("did not verify") && e.contains("deleted again"),
            "{e}"
        );
        assert!(stored.is_none(), "the store keeps the old key");
        let last = reqs.last().unwrap();
        assert!(last.ends_with(&format!("AccessKeyId={NEW}")) && last.contains(OLD));
        assert!(!e.contains("NEW/secret") && !e.contains("OLD/secret"));
    }

    #[test]
    fn a_key_of_another_principal_is_not_accepted() {
        let (out, stored, _) = run(
            vec![
                (200, id_xml(BOB)),
                (200, list_xml(&[OLD])),
                (200, create_xml(NEW, "NEW/secret")),
                (200, id_xml("arn:aws:iam::123456789012:user/eve")),
                (200, DELETE_XML.into()),
            ],
            5,
            true,
        );
        assert!(out.unwrap_err().contains("user/eve"));
        assert!(stored.is_none());
    }

    #[test]
    fn a_failed_store_deletes_the_new_key() {
        let (out, _, reqs) = run(
            vec![
                (200, id_xml(BOB)),
                (200, list_xml(&[OLD])),
                (200, create_xml(NEW, "NEW/secret")),
                (200, id_xml(BOB)),
                (200, DELETE_XML.into()),
            ],
            1,
            false,
        );
        let e = out.unwrap_err();
        assert!(
            e.contains("disk full") && e.contains("deleted again"),
            "{e}"
        );
        assert!(reqs
            .last()
            .unwrap()
            .ends_with(&format!("AccessKeyId={NEW}")));
    }

    #[test]
    fn temporary_credentials_are_refused_before_any_call() {
        let k = AwsKey::parse(&format!(
            r#"{{"access_key_id":"{OLD}","secret_access_key":"s","session_token":"t"}}"#
        ))
        .unwrap();
        let ep = Endpoint {
            url: "http://127.0.0.1:9/".into(),
            ..Endpoint::iam()
        };
        let r = Rotation {
            iam: ep.clone(),
            sts: ep,
            now: &|| 0,
            pause: &|_| {},
            attempts: 1,
        };
        let e = rotate(&r, &k, &mut |_| Ok(())).unwrap_err();
        assert!(e.contains("session token"));
        assert_eq!(short(OLD), "AKIA…0001");
        assert_eq!(short("x"), "…");
    }
}
