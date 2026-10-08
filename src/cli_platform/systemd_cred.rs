// cli_platform/systemd_cred.rs — `kepr systemd-cred KEY [--name CRED]
// [--tpm2]` (T10.06).
//
// Prints a `SetCredentialEncrypted=` line for a unit file: the value is
// fetched like `kepr get` (sealed, SSH and share-key credentials are
// refused by the daemon with the generic error) and piped to
// `systemd-creds encrypt --pretty` on stdin, never argv. Only the
// encrypted line is printed; the plaintext never reaches stdout.

use std::io::Write;
use std::process::{Command, Stdio};

use kepr_core::protocol::Response;
use kepr_core::protocol_platform::PlatformResponse;
use zeroize::Zeroizing;

use super::args;
use crate::cli_exec::{CredFetcher, DaemonFetcher};

pub struct Opts {
    /// The kepr credential (uppercased).
    pub name: String,
    /// The systemd credential name in the unit (`--name`, default NAME).
    pub cred: String,
    pub tpm2: bool,
}

pub fn parse(argv: &[String]) -> Result<Opts, String> {
    let a = args::parse(argv, &["--name"], &["--tpm2"])?;
    let [name] = a.positional.as_slice() else {
        return Err("usage: kepr systemd-cred KEY [--name CRED] [--tpm2]".into());
    };
    let name = name.to_uppercase();
    let cred = a
        .value("--name")
        .map(str::to_string)
        .unwrap_or(name.clone());
    validate_cred_name(&cred)?;
    Ok(Opts {
        name,
        cred,
        tpm2: a.has("--tpm2"),
    })
}

/// systemd's rule (a valid file name and fd name) minus whitespace, which
/// would make the unit line ambiguous.
pub fn validate_cred_name(cred: &str) -> Result<(), String> {
    let ok = !cred.is_empty()
        && cred.len() <= 255
        && cred != "."
        && cred != ".."
        && cred
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'/' && b != b':');
    if ok {
        Ok(())
    } else {
        Err("--name: use 1-255 printable characters without '/', ':' or spaces".into())
    }
}

/// `systemd-creds` arguments: plaintext on stdin, the pretty unit line on
/// stdout.
pub fn encrypt_args(cred: &str, tpm2: bool) -> Vec<String> {
    let mut a = vec![
        "encrypt".to_string(),
        format!("--name={cred}"),
        "--pretty".to_string(),
    ];
    if tpm2 {
        a.push("--with-key=tpm2".to_string());
    }
    a.extend(["-".to_string(), "-".to_string()]);
    a
}

/// Accept only a `SetCredentialEncrypted=CRED:` line followed by base64
/// continuation lines; anything else is not printed.
pub fn check_line(out: &str, cred: &str) -> Result<String, String> {
    let out = out.trim_end();
    let head = format!("SetCredentialEncrypted={cred}:");
    let body = out
        .strip_prefix(&head)
        .ok_or("unexpected output from systemd-creds")?;
    let base64ish = |c: char| c.is_ascii_alphanumeric() || "+/= \\\n\t".contains(c);
    if body.trim().is_empty() || !body.chars().all(base64ish) {
        return Err("unexpected output from systemd-creds".into());
    }
    Ok(out.to_string())
}

/// Runs `systemd-creds` (a trait so tests need no systemd).
pub trait Encrypter {
    fn encrypt(&self, args: &[String], plaintext: &[u8]) -> Result<Vec<u8>, String>;
}

pub struct SystemdCreds;

impl Encrypter for SystemdCreds {
    fn encrypt(&self, args: &[String], plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let mut child = Command::new("systemd-creds")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // Its own diagnostics (no host key, no TPM) go to the terminal.
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|_| "systemd-creds not found (systemd 250 or newer)".to_string())?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(plaintext)
                .map_err(|_| "systemd-creds encrypt failed".to_string())?;
        }
        let out = child
            .wait_with_output()
            .map_err(|_| "systemd-creds encrypt failed".to_string())?;
        if !out.status.success() {
            return Err("systemd-creds encrypt failed (see its message above)".into());
        }
        Ok(out.stdout)
    }
}

pub fn run(opts: &Opts, fetcher: &dyn CredFetcher, enc: &dyn Encrypter) -> Result<String, String> {
    let value = fetcher.fetch(&opts.name)?;
    let plaintext = Zeroizing::new(value.as_bytes().to_vec());
    drop(value);
    let out = enc.encrypt(&encrypt_args(&opts.cred, opts.tpm2), &plaintext)?;
    check_line(&String::from_utf8_lossy(&out), &opts.cred)
}

pub fn cmd_systemd_cred(argv: &[String]) -> Response {
    let opts = match parse(argv) {
        Ok(o) => o,
        Err(e) => return Response::fail(e),
    };
    match run(&opts, &DaemonFetcher, &SystemdCreds) {
        Ok(line) => {
            if !crate::cli_ui::json_mode() {
                println!("{line}");
            }
            Response::Platform(PlatformResponse::SystemdCredOk {
                name: opts.name,
                line,
            })
        }
        Err(e) => Response::fail(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kepr_core::generate::ZeroString;
    use std::cell::RefCell;

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    struct Fetch(Result<&'static str, &'static str>);
    impl CredFetcher for Fetch {
        fn fetch(&self, _name: &str) -> Result<ZeroString, String> {
            self.0.map(ZeroString::from).map_err(str::to_string)
        }
    }

    #[derive(Default)]
    struct Fake {
        seen: RefCell<Vec<(Vec<String>, Vec<u8>)>>,
    }
    impl Encrypter for Fake {
        fn encrypt(&self, args: &[String], plaintext: &[u8]) -> Result<Vec<u8>, String> {
            self.seen
                .borrow_mut()
                .push((args.to_vec(), plaintext.to_vec()));
            let cred = args[1].trim_start_matches("--name=");
            Ok(
                format!("SetCredentialEncrypted={cred}: \\\n        QUJD+/ \\\n        RA==\n")
                    .into_bytes(),
            )
        }
    }

    #[test]
    fn argument_building() {
        assert_eq!(
            encrypt_args("db", false),
            ["encrypt", "--name=db", "--pretty", "-", "-"]
        );
        assert_eq!(
            encrypt_args("db", true),
            [
                "encrypt",
                "--name=db",
                "--pretty",
                "--with-key=tpm2",
                "-",
                "-"
            ]
        );
        let o = parse(&v(&["db_pass", "--tpm2"])).unwrap();
        assert_eq!(
            (o.name.as_str(), o.cred.as_str(), o.tpm2),
            ("DB_PASS", "DB_PASS", true)
        );
        let o = parse(&v(&["db_pass", "--name", "db.password"])).unwrap();
        assert_eq!((o.cred.as_str(), o.tpm2), ("db.password", false));
        for bad in ["", ".", "..", "a/b", "a:b", "a b"] {
            assert!(parse(&v(&["X", "--name", bad])).is_err(), "{bad:?}");
        }
        assert!(parse(&v(&[])).is_err());
        assert!(parse(&v(&["A", "B"])).is_err());
    }

    #[test]
    fn value_goes_on_stdin_and_only_the_unit_line_is_returned() {
        let fake = Fake::default();
        let opts = parse(&v(&["db", "--name", "pg"])).unwrap();
        let line = run(&opts, &Fetch(Ok("hunter2")), &fake).unwrap();
        assert_eq!(
            line,
            "SetCredentialEncrypted=pg: \\\n        QUJD+/ \\\n        RA=="
        );
        let seen = fake.seen.borrow();
        assert_eq!(seen[0].1, b"hunter2");
        assert!(!seen[0].0.iter().any(|a| a.contains("hunter2")));
    }

    #[test]
    fn output_line_format_is_checked() {
        assert!(check_line("SetCredentialEncrypted=x: \\\n  QUJD\n", "x").is_ok());
        // Wrong name, no body, or something that isn't base64 is refused.
        assert!(check_line("SetCredentialEncrypted=y: QUJD", "x").is_err());
        assert!(check_line("SetCredentialEncrypted=x:", "x").is_err());
        assert!(check_line("SetCredentialEncrypted=x: hunter2!", "x").is_err());
        assert!(check_line("hunter2", "x").is_err());
    }

    #[test]
    fn refuses_sealed_credentials() {
        // The daemon's `Get` refuses sealed / ssh / share-key values with
        // the generic error; nothing reaches systemd-creds.
        let fake = Fake::default();
        let opts = parse(&v(&["SEALED"])).unwrap();
        let e = run(&opts, &Fetch(Err("credential unavailable")), &fake).unwrap_err();
        assert_eq!(e, "credential unavailable");
        assert!(fake.seen.borrow().is_empty());
    }
}
