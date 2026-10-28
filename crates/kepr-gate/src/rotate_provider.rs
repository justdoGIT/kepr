//! Provider-side key rotation inside the gate (T13.03).
//!
//! A sealed key is replaced through its provider's own API without the
//! value ever reaching the CLI: the gate of a `rotate:` session (the only
//! process besides the daemon that may hold a sealed value) resolves the
//! old key, asks the provider for a new one, has the daemon store it
//! (`RotateCommit`: seal and bindings kept, gates re-fetch), and only then
//! revokes the old key. Revoking last means a failure anywhere before the
//! commit leaves the old key working and nothing lost; if the commit itself
//! fails the new key is revoked again, so no unrecorded key stays valid.
//!
//! One `Rotate` implementation per provider (GitHub fine-grained tokens,
//! Stripe restricted keys, Anthropic and OpenAI admin keys), each its own
//! ticket; this module is the trait, the order of operations and the
//! harness the implementations are tested with.
//!
//! Errors are fixed strings: never a key, a response body or a header.

// The first provider rotator, and the verb that starts a `rotate:` session,
// land in follow-up tickets; until then only the tests call this.
#![allow(dead_code)]

use kepr_core::generate::ZeroString;

use crate::vault::Resolve;

/// Why a provider call failed. A fixed message, safe to log and to show.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct RotateError(pub &'static str);

pub trait Rotate: Send + Sync {
    /// The host:port the old key is bound to (where it may be resolved).
    fn host(&self) -> (&str, u16);
    /// Ask the provider for a new key, authorised by `old`.
    fn rotate(&self, old: &ZeroString) -> Result<ZeroString, RotateError>;
    /// Revoke `key` at the provider, authorised by `using` (the other key).
    fn revoke(&self, key: &ZeroString, using: &ZeroString) -> Result<(), RotateError>;
}

/// What a rotation did.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// New key stored, old key revoked.
    Done,
    /// New key stored, but the old one is still valid at the provider.
    OldKeyStillValid(RotateError),
}

/// Rotate credential `name` with `rotator`, through `daemon`.
pub fn run(daemon: &dyn Resolve, name: &str, rotator: &dyn Rotate) -> Result<Outcome, String> {
    let (host, port) = rotator.host();
    let (old, _) = daemon
        .resolve(name, host, port)
        .map_err(|_| "credential unavailable".to_string())?;
    let new = rotator
        .rotate(&old)
        .map_err(|e| format!("rotation failed: {}", e.0))?;
    if daemon.rotate_commit(name, &new).is_err() {
        // The new key was never recorded: do not leave it valid.
        let _ = rotator.revoke(&new, &old);
        return Err(
            "rotation failed: the new key could not be stored; the old key is unchanged".into(),
        );
    }
    Ok(match rotator.revoke(&old, &new) {
        Ok(()) => Outcome::Done,
        Err(e) => Outcome::OldKeyStillValid(e),
    })
}

#[cfg(test)]
pub(crate) mod testkit {
    //! A fake provider on loopback and a recording daemon, for rotator tests.

    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    use kepr_core::binding::Inject;

    use super::*;

    /// Serves `replies` in order (`(status, body)`), one connection each;
    /// records `(request head, body)`.
    pub struct FakeProvider {
        pub addr: String,
        pub seen: Arc<Mutex<Vec<(String, String)>>>,
    }

    impl FakeProvider {
        pub fn start(replies: Vec<(u16, &'static str)>) -> Self {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = l.local_addr().unwrap().to_string();
            let seen = Arc::new(Mutex::new(Vec::new()));
            let log = Arc::clone(&seen);
            std::thread::spawn(move || {
                for (status, body) in replies {
                    let Ok((mut s, _)) = l.accept() else { return };
                    // Read to the end of the head: a client may write it in pieces.
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 1024];
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match s.read(&mut chunk) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let text = String::from_utf8_lossy(&buf).into_owned();
                    let (head, b) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
                    log.lock().unwrap().push((head.to_string(), b.to_string()));
                    let _ = write!(
                        s,
                        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                }
            });
            Self { addr, seen }
        }

        /// POST `path` with `bearer` over plain HTTP; `(status, body)`.
        pub fn post(&self, path: &str, bearer: &str) -> Result<(u16, String), RotateError> {
            let mut s = std::net::TcpStream::connect(&self.addr)
                .map_err(|_| RotateError("provider unreachable"))?;
            write!(
                s,
                "POST {path} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {bearer}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .map_err(|_| RotateError("provider unreachable"))?;
            let mut out = String::new();
            s.read_to_string(&mut out)
                .map_err(|_| RotateError("provider unreachable"))?;
            let status = out
                .split_whitespace()
                .nth(1)
                .and_then(|c| c.parse().ok())
                .unwrap_or(0);
            let body = out
                .split_once("\r\n\r\n")
                .map_or("", |(_, b)| b)
                .to_string();
            Ok((status, body))
        }
    }

    /// A daemon that serves one key and records what the gate commits.
    pub struct FakeDaemon {
        pub committed: Mutex<Vec<(String, String)>>,
        pub refuse_commit: bool,
        pub key: &'static str,
    }

    impl FakeDaemon {
        pub fn new(key: &'static str) -> Self {
            Self {
                committed: Mutex::new(Vec::new()),
                refuse_commit: false,
                key,
            }
        }
    }

    impl Resolve for FakeDaemon {
        fn resolve(&self, _: &str, _: &str, _: u16) -> Result<(ZeroString, Inject), String> {
            Ok((ZeroString::from(self.key), Inject::Bearer))
        }
        fn generation(&self) -> Result<u64, String> {
            Ok(1)
        }
        fn rotate_commit(&self, name: &str, value: &ZeroString) -> Result<(), String> {
            if self.refuse_commit {
                return Err("credential unavailable".into());
            }
            self.committed
                .lock()
                .unwrap()
                .push((name.into(), value.as_str().into()));
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::{FakeDaemon, FakeProvider};
    use super::*;

    /// A rotator speaking to the fake provider: POST /keys issues, POST /revoke revokes.
    struct Fake<'a>(&'a FakeProvider);

    impl Rotate for Fake<'_> {
        fn host(&self) -> (&str, u16) {
            ("api.example.com", 443)
        }
        fn rotate(&self, old: &ZeroString) -> Result<ZeroString, RotateError> {
            match self.0.post("/keys", old.as_str())? {
                (200, body) => body
                    .split("\"key\":\"")
                    .nth(1)
                    .and_then(|r| r.split('"').next())
                    .map(ZeroString::from)
                    .ok_or(RotateError("provider reply not understood")),
                _ => Err(RotateError("provider refused")),
            }
        }
        fn revoke(&self, key: &ZeroString, using: &ZeroString) -> Result<(), RotateError> {
            // The revoke call names the key in the path, authorised by `using`.
            match self
                .0
                .post(&format!("/revoke/{}", key.as_str()), using.as_str())?
            {
                (200, _) => Ok(()),
                _ => Err(RotateError("provider refused to revoke")),
            }
        }
    }

    #[test]
    fn issue_then_commit_then_revoke_the_old_key() {
        let p = FakeProvider::start(vec![(200, "{\"key\":\"NEW-KEY\"}"), (200, "{}")]);
        let d = FakeDaemon::new("OLD-KEY");
        assert_eq!(run(&d, "GH", &Fake(&p)), Ok(Outcome::Done));
        assert_eq!(
            *d.committed.lock().unwrap(),
            [("GH".to_string(), "NEW-KEY".to_string())]
        );
        let seen = p.seen.lock().unwrap();
        assert!(seen[0].0.starts_with("POST /keys") && seen[0].0.contains("Bearer OLD-KEY"));
        assert!(
            seen[1].0.starts_with("POST /revoke/OLD-KEY") && seen[1].0.contains("Bearer NEW-KEY")
        );
    }

    #[test]
    fn a_provider_failure_before_the_commit_changes_nothing() {
        let p = FakeProvider::start(vec![(403, "{}")]);
        let d = FakeDaemon::new("OLD-KEY");
        let e = run(&d, "GH", &Fake(&p)).unwrap_err();
        assert_eq!(e, "rotation failed: provider refused");
        assert!(d.committed.lock().unwrap().is_empty());
        assert_eq!(p.seen.lock().unwrap().len(), 1, "no revoke was attempted");
    }

    #[test]
    fn a_refused_commit_revokes_the_new_key_and_keeps_the_old() {
        let p = FakeProvider::start(vec![(200, "{\"key\":\"NEW-KEY\"}"), (200, "{}")]);
        let mut d = FakeDaemon::new("OLD-KEY");
        d.refuse_commit = true;
        let e = run(&d, "GH", &Fake(&p)).unwrap_err();
        assert!(e.contains("old key is unchanged"), "{e}");
        let seen = p.seen.lock().unwrap();
        assert!(
            seen[1].0.starts_with("POST /revoke/NEW-KEY") && seen[1].0.contains("Bearer OLD-KEY")
        );
    }

    #[test]
    fn a_failed_revoke_is_reported_not_hidden() {
        let p = FakeProvider::start(vec![(200, "{\"key\":\"NEW-KEY\"}"), (500, "{}")]);
        let d = FakeDaemon::new("OLD-KEY");
        assert_eq!(
            run(&d, "GH", &Fake(&p)),
            Ok(Outcome::OldKeyStillValid(RotateError(
                "provider refused to revoke"
            )))
        );
        assert_eq!(
            d.committed.lock().unwrap().len(),
            1,
            "the new key is stored regardless"
        );
    }

    #[test]
    fn errors_never_carry_a_key() {
        let p = FakeProvider::start(vec![(500, "{\"key\":\"LEAKY-BODY\"}")]);
        let d = FakeDaemon::new("OLD-KEY");
        let e = run(&d, "GH", &Fake(&p)).unwrap_err();
        assert!(!e.contains("OLD-KEY") && !e.contains("LEAKY-BODY"), "{e}");
    }
}
