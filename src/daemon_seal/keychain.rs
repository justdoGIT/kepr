// daemon_seal/keychain.rs — the macOS keychain holds the master key
// (T10.04).
//
//   KEPR_MASTER_KEY_SEAL=keychain
//
// The key is a generic password (service `kepr-master-key`) in the user's
// default (login) keychain, added with `-U` and an access list (`-T`) that
// names only the daemon binary. `security -i` reads its commands from
// stdin, so the key travels there as hex, never in argv; it is read back
// with `find-generic-password -w` (stdout, kept in `Zeroizing`).
//
// The master-key file keeps only a marker naming the item, no key material:
//
//     "kepr-keychain-v1\n" | service "\n" | account "\n"
//
// The account is a fingerprint of the key (SHA-256, 96 bits): a new master
// key never overwrites an older item, and unseal checks that the item it
// read is the key the marker names.
//
// T10.12: on macOS the daemon reads the item itself through
// Security.framework (`security-framework`, SecItemCopyMatching), so the
// item's access list (`-T` the daemon binary) applies and the keychain does
// not prompt on each start. `/usr/bin/security` is used only to add the item
// (the access list needs it). A failed read (item gone, keychain locked, no
// login session, or a rebuilt daemon binary the list no longer matches)
// fails the unseal; it never falls back to a prompting read.
//
// macOS only at run time (`from_env`); built on every target so the command
// lines and the read path are tested on Linux with fakes.

use std::path::Path;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::runner::{Cmd, Runner, SystemRunner};
use crate::master_key::Sealer;

/// Absolute: never whichever `security` is first on PATH.
const TOOL: &str = "/usr/bin/security";
const SERVICE: &str = "kepr-master-key";
const MAGIC: &str = "kepr-keychain-v1\n";
const SEAL_FAILED: &str = "master-key seal failed";
const UNSEAL_FAILED: &str = "master-key unseal failed";

/// Reads an item's password by (service, account).
pub type Reader = fn(&str, &str) -> Result<Zeroizing<Vec<u8>>, ()>;

pub struct KeychainSealer<R: Runner> {
    /// The daemon binary: the one application the item trusts.
    exe: String,
    runner: R,
    /// T10.12: read in this process (Security.framework on macOS); `None`
    /// reads through `security find-generic-password -w`.
    native: Option<Reader>,
}

/// T10.12: the item's password, read by the daemon itself.
#[cfg(target_os = "macos")]
fn native_read(service: &str, account: &str) -> Result<Zeroizing<Vec<u8>>, ()> {
    use security_framework::passwords::{generic_password, PasswordOptions};
    generic_password(PasswordOptions::new_generic_password(service, account))
        .map(Zeroizing::new)
        .map_err(|_| ())
}

#[cfg(target_os = "macos")]
const NATIVE: Option<Reader> = Some(native_read);
#[cfg(not(target_os = "macos"))]
const NATIVE: Option<Reader> = None;

impl KeychainSealer<SystemRunner> {
    pub fn from_env() -> Result<Self, String> {
        if !cfg!(target_os = "macos") {
            return Err("KEPR_MASTER_KEY_SEAL=keychain is only available on macOS".into());
        }
        let exe = std::env::current_exe()
            .map_err(|_| "KEPR_MASTER_KEY_SEAL=keychain: cannot find the daemon's path")?;
        Ok(Self {
            native: NATIVE,
            ..Self::new(&exe, SystemRunner)?
        })
    }
}

impl<R: Runner> KeychainSealer<R> {
    pub fn new(exe: &Path, runner: R) -> Result<Self, String> {
        let exe = exe.to_str().filter(|p| plain_path(p)).ok_or(
            "KEPR_MASTER_KEY_SEAL=keychain: install the daemon under an absolute path of \
             letters, digits and / . _ + - only",
        )?;
        Ok(Self {
            exe: exe.to_string(),
            runner,
            native: None,
        })
    }
}

/// `security -i` splits its input on spaces: the path must need no quoting.
fn plain_path(p: &str) -> bool {
    p.starts_with('/')
        && p.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'+' | b'-'))
}

/// The item's account: a fingerprint of the key it holds.
fn account(key: &[u8; 32]) -> String {
    let d = Sha256::new()
        .chain_update(b"kepr-keychain-v1")
        .chain_update(key)
        .finalize();
    format!("kepr-{}", hex::encode(&d[..12]))
}

fn valid_account(a: &str) -> bool {
    a.strip_prefix("kepr-")
        .is_some_and(|h| h.len() == 24 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

/// `find-generic-password` for the item; attributes only unless `-w` is
/// added.
fn find_args(account: &str) -> Vec<&str> {
    vec!["find-generic-password", "-a", account, "-s", SERVICE]
}

/// The account a marker names.
fn parse_marker(blob: &[u8]) -> Result<String, String> {
    let rest = std::str::from_utf8(blob)
        .ok()
        .and_then(|t| t.strip_prefix(MAGIC))
        .ok_or(
            "the master key was sealed another way; KEPR_MASTER_KEY_SEAL=keychain \
             applies to new master keys only",
        )?;
    match rest.split('\n').collect::<Vec<_>>()[..] {
        [s, a, ""] if s == SERVICE && valid_account(a) => Ok(a.to_string()),
        _ => Err("invalid sealed master-key file".into()),
    }
}

impl<R: Runner> Sealer for KeychainSealer<R> {
    fn seal(&self, key: &[u8; 32]) -> Result<Vec<u8>, String> {
        let account = account(key);
        let hex_key = Zeroizing::new(hex::encode(key));
        // Sized up front so the line holding the key is never reallocated.
        let mut script = Zeroizing::new(String::with_capacity(160 + self.exe.len()));
        for part in [
            "add-generic-password -U -a ",
            account.as_str(),
            " -s ",
            SERVICE,
            " -T ",
            self.exe.as_str(),
            " -w ",
            hex_key.as_str(),
            "\n",
        ] {
            script.push_str(part);
        }
        let stdin = Cmd::new(TOOL, &["-i"]).stdin(script.as_bytes());
        self.runner.run(&stdin).map_err(|_| SEAL_FAILED)?;
        // `security -i` need not report a failed command in its exit status:
        // check the item is there (attributes only, no secret, no prompt).
        self.runner
            .run(&Cmd::new(TOOL, &find_args(&account)))
            .map_err(|_| SEAL_FAILED)?;
        Ok(format!("{MAGIC}{SERVICE}\n{account}\n").into_bytes())
    }

    fn unseal(&self, blob: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
        let account = parse_marker(blob)?;
        let out = match self.native {
            Some(read) => read(SERVICE, &account).map_err(|_| UNSEAL_FAILED)?,
            None => {
                let mut args = find_args(&account);
                args.push("-w");
                self.runner
                    .run(&Cmd::new(TOOL, &args))
                    .map_err(|_| UNSEAL_FAILED)?
            }
        };
        let text = std::str::from_utf8(&out).map_err(|_| UNSEAL_FAILED)?;
        let mut key = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(text.trim_end(), &mut key[..]).map_err(|_| UNSEAL_FAILED)?;
        if self::account(&key) != account {
            return Err(UNSEAL_FAILED.into());
        }
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::super::runner::fake::{arg, FakeRunner};
    use super::super::runner::RunError;
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    const EXE: &str = "/usr/local/sbin/kepr-daemon";
    const KEY: [u8; 32] = [0xa7; 32];

    type Items = Arc<Mutex<HashMap<String, String>>>;

    /// A pretend keychain: `-i` runs one add-generic-password line from
    /// stdin; find-generic-password answers from what was added.
    fn keychain(items: Items) -> FakeRunner {
        FakeRunner::new(move |c| {
            assert_eq!(c.tool, TOOL);
            let mut items = items.lock().unwrap();
            if c.args == ["-i"] {
                let line = std::str::from_utf8(c.stdin).unwrap();
                let words: Vec<String> = line.split_whitespace().map(String::from).collect();
                assert_eq!(words[..2], ["add-generic-password", "-U"]);
                let a = arg(&words, "-a").unwrap().to_string();
                items.insert(a, arg(&words, "-w").unwrap().to_string());
                return Ok(Vec::new());
            }
            let a = arg(&c.args, "-a").unwrap();
            let v = items.get(a).ok_or(RunError::Failed)?;
            Ok(if c.args.last().unwrap() == "-w" {
                format!("{v}\n").into_bytes()
            } else {
                b"keychain: \"login.keychain-db\"\n".to_vec()
            })
        })
    }

    fn sealer(items: &Items) -> KeychainSealer<FakeRunner> {
        KeychainSealer::new(Path::new(EXE), keychain(items.clone())).unwrap()
    }

    #[test]
    fn the_key_goes_on_stdin_and_never_in_argv_or_the_file() {
        let items = Items::default();
        let s = sealer(&items);
        let blob = s.seal(&KEY).unwrap();
        let acct = account(&KEY);
        assert_eq!(
            blob,
            format!("kepr-keychain-v1\nkepr-master-key\n{acct}\n").as_bytes()
        );
        assert_eq!(*s.unseal(&blob).unwrap(), KEY);

        let hex_key = hex::encode(KEY);
        let calls = s.runner.calls();
        let argv: Vec<Vec<String>> = calls.iter().map(|c| c.1.clone()).collect();
        let find = |extra: &[&str]| -> Vec<String> {
            let mut v = vec!["find-generic-password", "-a", acct.as_str(), "-s", SERVICE];
            v.extend(extra);
            v.into_iter().map(String::from).collect()
        };
        assert_eq!(argv, [vec!["-i".to_string()], find(&[]), find(&["-w"])]);
        assert_eq!(
            String::from_utf8(calls[0].2.clone()).unwrap(),
            format!("add-generic-password -U -a {acct} -s kepr-master-key -T {EXE} -w {hex_key}\n")
        );
        for (tool, args, stdin, env) in &calls[1..] {
            assert_eq!(tool, TOOL);
            assert!(stdin.is_empty() && env.is_empty());
            assert!(args.iter().all(|a| !a.contains(&hex_key[..16])));
        }
        assert!(!blob.windows(32).any(|w| w == KEY));
        assert!(!String::from_utf8_lossy(&blob).contains(&hex_key[..16]));
        // Each key gets its own item: a second key leaves the first alone.
        let other = s.seal(&[0x11; 32]).unwrap();
        assert_ne!(other, blob);
        assert_eq!(items.lock().unwrap().len(), 2);
        assert_eq!(*s.unseal(&blob).unwrap(), KEY);
    }

    #[test]
    fn a_wrong_item_or_marker_fails_quietly() {
        let items = Items::default();
        let s = sealer(&items);
        let blob = s.seal(&KEY).unwrap();
        // The item was changed behind kepr's back.
        for v in items.lock().unwrap().values_mut() {
            *v = hex::encode([0x22u8; 32]);
        }
        assert_eq!(s.unseal(&blob).unwrap_err(), UNSEAL_FAILED);
        let gone = format!("{MAGIC}{SERVICE}\n{}\n", account(&[3; 32]));
        assert_eq!(s.unseal(gone.as_bytes()).unwrap_err(), UNSEAL_FAILED);
        let e = s.unseal(b"kepr-local-v1\n0123").unwrap_err();
        assert!(e.contains("new master keys only"), "{e}");
        for bad in [
            format!("{MAGIC}other\n{}\n", account(&KEY)),
            format!("{MAGIC}{SERVICE}\n-A\n"),
            format!("{MAGIC}{SERVICE}\n{}", account(&KEY)),
        ] {
            assert_eq!(
                s.unseal(bad.as_bytes()).unwrap_err(),
                "invalid sealed master-key file"
            );
        }
    }

    #[test]
    fn a_failed_add_is_a_failed_seal() {
        // `-i` exits 0 but the item never appears.
        let quiet = KeychainSealer::new(
            Path::new(EXE),
            FakeRunner::new(|c| {
                if c.args == ["-i"] {
                    Ok(Vec::new())
                } else {
                    Err(RunError::Failed)
                }
            }),
        )
        .unwrap();
        assert_eq!(quiet.seal(&KEY).unwrap_err(), SEAL_FAILED);
        let missing =
            KeychainSealer::new(Path::new(EXE), FakeRunner::new(|_| Err(RunError::Missing)))
                .unwrap();
        assert_eq!(missing.seal(&KEY).unwrap_err(), SEAL_FAILED);
    }

    #[test]
    fn the_daemon_path_must_need_no_quoting() {
        let runner = || FakeRunner::new(|_| Ok(Vec::new()));
        assert!(KeychainSealer::new(Path::new("/opt/homebrew/bin/kepr-daemon"), runner()).is_ok());
        for bad in [
            "kepr-daemon",
            "/Applications/My App/kepr-daemon",
            "/x -A",
            "/x\n-A",
            "/x\"y",
        ] {
            assert!(
                KeychainSealer::new(Path::new(bad), runner()).is_err(),
                "{bad}"
            );
        }
    }

    thread_local! {
        static NATIVE_ITEMS: std::cell::RefCell<HashMap<String, String>> = Default::default();
    }

    /// Stands in for Security.framework, reading the same pretend keychain.
    fn fake_native(service: &str, account: &str) -> Result<Zeroizing<Vec<u8>>, ()> {
        assert_eq!(service, SERVICE);
        NATIVE_ITEMS.with(|i| {
            i.borrow()
                .get(account)
                .map(|v| Zeroizing::new(v.as_bytes().to_vec()))
                .ok_or(())
        })
    }

    #[test]
    fn native_unseal_reads_in_process_and_never_runs_security_w() {
        let items = Items::default();
        let mut s = sealer(&items);
        s.native = Some(fake_native);
        let blob = s.seal(&KEY).unwrap();
        NATIVE_ITEMS.with(|n| *n.borrow_mut() = items.lock().unwrap().clone());
        assert_eq!(*s.unseal(&blob).unwrap(), KEY);
        // Only the add and its attribute check went through `security`.
        let argv: Vec<Vec<String>> = s.runner.calls().iter().map(|c| c.1.clone()).collect();
        assert_eq!(argv.len(), 2);
        assert!(argv.iter().all(|a| !a.contains(&"-w".to_string())));
        // A failed native read fails the unseal (no prompting fallback).
        NATIVE_ITEMS.with(|n| n.borrow_mut().clear());
        assert_eq!(s.unseal(&blob).unwrap_err(), UNSEAL_FAILED);
        assert_eq!(s.runner.calls().len(), 2);
        // A wrong value behind the right account is refused too.
        let acct = account(&KEY);
        NATIVE_ITEMS.with(|n| n.borrow_mut().insert(acct, hex::encode([5u8; 32])));
        assert_eq!(s.unseal(&blob).unwrap_err(), UNSEAL_FAILED);
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn other_systems_are_told_it_is_macos_only() {
        let e = KeychainSealer::from_env().err().unwrap();
        assert!(e.contains("only available on macOS"), "{e}");
    }
}
