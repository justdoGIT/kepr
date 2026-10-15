// cli_seal/fido2.rs — the security-key side of T4.09 (`kepr lock --fido2`,
// `kepr unlock` on a FIDO2-protected store), through libfido2's tools.
//
//   lock --fido2   `fido2-cred -M -h` makes a credential with the
//                  `hmac-secret` extension, then `fido2-assert -G -h` reads
//                  its output for a fresh random salt; the passphrase and
//                  that output go to the daemon together (Request::Lock),
//                  which stores the credential id and salt in the envelope.
//   unlock         asks the daemon for the stored id and salt
//                  (`Fido2UnlockParams`), runs `fido2-assert -G -h` again
//                  and sends both factors.
//
// The device is `KEPR_FIDO2_DEVICE`, or the first one `fido2-token -L`
// lists. Parameters go to the tools on stdin, never argv; their stderr
// stays on the terminal for the device's PIN prompt. Tool access goes
// through `Fido2Tool` so tests run without a device.

use std::io::Write;
use std::process::{Command, Stdio};

use base64::Engine;
use zeroize::Zeroizing;

use kepr_core::generate::ZeroString;
use kepr_core::protocol::{Request, Response};
use kepr_core::protocol_seal::{SealRequest, SealResponse};
use kepr_core::seal_factor::{compose_factor, Fido2Factor, FIDO2_RP_ID};

use crate::cli_args::Args;
use crate::cli_input::read_masked;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Runs a libfido2 tool: `stdin` in, stdout back.
pub trait Fido2Tool {
    fn run(&self, tool: &str, args: &[&str], stdin: &[u8]) -> Result<Zeroizing<String>, String>;
}

pub struct SystemTool;

impl Fido2Tool for SystemTool {
    fn run(&self, tool: &str, args: &[&str], stdin: &[u8]) -> Result<Zeroizing<String>, String> {
        let mut child = Command::new(tool)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => {
                    format!("{tool} not found: install libfido2's tools (package fido2-tools)")
                }
                _ => format!("{tool}: {e}"),
            })?;
        if let Some(mut i) = child.stdin.take() {
            i.write_all(stdin).map_err(|e| format!("{tool}: {e}"))?;
        }
        let out = child
            .wait_with_output()
            .map_err(|e| format!("{tool}: {e}"))?;
        let text = Zeroizing::new(String::from_utf8_lossy(&out.stdout).into_owned());
        let _ = Zeroizing::new(out.stdout);
        if !out.status.success() {
            return Err(format!("{tool} failed (is the security key plugged in?)"));
        }
        Ok(text)
    }
}

fn random<const N: usize>() -> Result<[u8; N], String> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|e| format!("CSPRNG failure: {e}"))?;
    Ok(b)
}

/// `KEPR_FIDO2_DEVICE`, or the first device `fido2-token -L` lists
/// (`/dev/hidraw4: vendor=0x1050, …`).
pub fn device(tool: &dyn Fido2Tool) -> Result<String, String> {
    if let Some(d) = std::env::var("KEPR_FIDO2_DEVICE")
        .ok()
        .filter(|d| !d.is_empty())
    {
        return Ok(d);
    }
    let list = tool.run("fido2-token", &["-L"], b"")?;
    list.lines()
        .find_map(|l| l.split_once(':').map(|(p, _)| p.trim().to_string()))
        .filter(|p| !p.is_empty())
        .ok_or_else(|| "no security key found (plug one in, or set KEPR_FIDO2_DEVICE)".into())
}

/// The credential id from `fido2-cred -M` output: client data hash, RP
/// id, format, authenticator data, credential id, signature, ….
pub fn parse_cred_output(out: &str) -> Result<Vec<u8>, String> {
    let line = out.lines().nth(4).ok_or("unexpected fido2-cred output")?;
    let id = B64
        .decode(line.trim())
        .map_err(|_| "unexpected fido2-cred output")?;
    if id.is_empty() || id.len() > 1024 {
        return Err("unexpected fido2-cred output".into());
    }
    Ok(id)
}

/// The `hmac-secret` output from `fido2-assert -G -h` output: client data
/// hash, RP id, authenticator data, signature, [user id], hmac secret.
pub fn parse_assert_output(out: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    let lines: Vec<&str> = out.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.len() < 5 {
        return Err("the security key returned no hmac-secret (does it support it?)".into());
    }
    let raw = Zeroizing::new(
        B64.decode(lines[lines.len() - 1].trim())
            .map_err(|_| "unexpected fido2-assert output")?,
    );
    let secret: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| "unexpected fido2-assert output")?;
    Ok(Zeroizing::new(secret))
}

/// Make a new `hmac-secret` credential on `dev`; returns its id.
pub fn make_credential(tool: &dyn Fido2Tool, dev: &str) -> Result<Vec<u8>, String> {
    let input = format!(
        "{}\n{FIDO2_RP_ID}\nkepr\n{}\n",
        B64.encode(random::<32>()?),
        B64.encode(random::<16>()?)
    );
    eprintln!("  Touch your security key to register it…");
    parse_cred_output(&tool.run("fido2-cred", &["-M", "-h", dev], input.as_bytes())?)
}

/// The key's `hmac-secret` output for `salt`.
pub fn hmac_secret(
    tool: &dyn Fido2Tool,
    dev: &str,
    cred_id: &[u8],
    salt: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, String> {
    let input = format!(
        "{}\n{FIDO2_RP_ID}\n{}\n{}\n",
        B64.encode(random::<32>()?),
        B64.encode(cred_id),
        B64.encode(salt)
    );
    eprintln!("  Touch your security key…");
    parse_assert_output(&tool.run("fido2-assert", &["-G", "-h", dev], input.as_bytes())?)
}

/// A new factor for `kepr lock --fido2`: register, then read the output.
pub fn new_factor(tool: &dyn Fido2Tool) -> Result<Fido2Factor, String> {
    let dev = device(tool)?;
    let credential_id = make_credential(tool, &dev)?;
    let salt = random::<32>()?;
    let hmac = hmac_secret(tool, &dev, &credential_id, &salt)?;
    Ok(Fido2Factor {
        credential_id,
        salt,
        hmac,
    })
}

/// The stored factor parameters, when the store has a security key.
fn stored_params() -> Option<(Vec<u8>, [u8; 32])> {
    let r = crate::client::send_request(&Request::Seal(SealRequest::Fido2UnlockParams)).ok()?;
    let Response::Seal(SealResponse::Fido2UnlockParamsOk {
        credential_id: Some(id),
        salt: Some(salt),
        ..
    }) = r
    else {
        return None;
    };
    let salt: [u8; 32] = B64.decode(salt).ok()?.try_into().ok()?;
    Some((B64.decode(id).ok()?, salt))
}

/// Read the store passphrase; on a FIDO2-protected store also run the
/// assertion and return both factors in one secret (`compose_factor`).
pub fn store_passphrase(prompt: &str) -> Result<ZeroString, String> {
    let params = stored_params();
    let pass = read_masked(prompt);
    if pass.is_empty() {
        return Err("password cannot be empty".into());
    }
    let Some((credential_id, salt)) = params else {
        return Ok(pass);
    };
    let tool = SystemTool;
    let dev = device(&tool)?;
    let hmac = hmac_secret(&tool, &dev, &credential_id, &salt)?;
    let factor = Fido2Factor {
        credential_id,
        salt,
        hmac,
    };
    Ok(compose_factor(pass.as_str(), &factor))
}

fn lock_secret() -> Result<ZeroString, String> {
    let first = read_masked("  Lock password: ");
    if first.is_empty() {
        return Err("password cannot be empty".into());
    }
    let second = read_masked("  Confirm password: ");
    if first.as_str() != second.as_str() {
        return Err("passwords do not match".into());
    }
    let factor = new_factor(&SystemTool)?;
    Ok(compose_factor(first.as_str(), &factor))
}

/// A failed core verb: printed unless `--json` (main prints that).
pub fn failed(a: &Args, e: String) -> Response {
    if !a.json {
        crate::cli_ui::err(&e);
    }
    Response::fail(e)
}

/// `kepr lock --fido2`: the passphrase twice, register a security key,
/// lock the store under both.
pub fn cmd_lock_fido2(a: &Args) -> Response {
    let password = match lock_secret() {
        Ok(p) => p,
        Err(e) => return failed(a, e),
    };
    let resp = crate::cli_cmds::dispatch(a, &Request::Lock { password });
    if !a.json {
        match &resp {
            Response::LockedOk => crate::cli_ui::ok(
                "Credential store locked; unlocking needs the passphrase and this security key.",
            ),
            Response::Err { error } => crate::cli_ui::err(error),
            _ => crate::cli_ui::err("unexpected response"),
        }
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// libfido2 output captured from `fido2-assert -G -h` (no user id).
    const ASSERT_FIXTURE: &str = "\
lv4h3pS4ZwkYEeyhEU1PIdnZ+R4SUgmPKFbeaMnpEoU=
kepr
WCVJpCpVg7m0Ufq5AN3TxwYKOAc/7qh3vO3T2eJnQ9oFAAAAKA==
MEUCIQDA3W2tIMHJbqI5pqXHbZpNYszBGkaZBozTaVQhK0WKRQIgLxQWSvX7a+DBxXWm6KgzJm+XxRDHy0Wu3HZh8pnrqQA=
qBmmEvRrEtn9e14gzAd1fWNDhpU1Tb8V+lfsgIZqEpo=
";

    /// `fido2-cred -M -h` output (packed attestation, no x5c line).
    const CRED_FIXTURE: &str = "\
lv4h3pS4ZwkYEeyhEU1PIdnZ+R4SUgmPKFbeaMnpEoU=
kepr
packed
WCVJpCpVg7m0Ufq5AN3TxwYKOAc/7qh3vO3T2eJnQ9pBAAAAKg==
3q2+796tvu/erb7v3q2+796tvu/erb7v3q2+796tvu8=
MEUCIQDA3W2tIMHJbqI5pqXHbZpNYszBGkaZBozTaVQhK0WKRQIgLxQWSvX7a+DBxXWm6KgzJm+XxRDHy0Wu3HZh8pnrqQA=
";

    struct Fake {
        calls: RefCell<Vec<(String, Vec<String>, String)>>,
    }

    impl Fido2Tool for Fake {
        fn run(
            &self,
            tool: &str,
            args: &[&str],
            stdin: &[u8],
        ) -> Result<Zeroizing<String>, String> {
            self.calls.borrow_mut().push((
                tool.to_string(),
                args.iter().map(|a| a.to_string()).collect(),
                String::from_utf8_lossy(stdin).into_owned(),
            ));
            Ok(Zeroizing::new(
                match tool {
                    "fido2-token" => "/dev/hidraw7: vendor=0x1050, product=0x0407 (Yubico)\n",
                    "fido2-cred" => CRED_FIXTURE,
                    _ => ASSERT_FIXTURE,
                }
                .to_string(),
            ))
        }
    }

    #[test]
    fn parses_fido2_assert_output() {
        let s = parse_assert_output(ASSERT_FIXTURE).unwrap();
        assert_eq!(s[..4], [0xa8, 0x19, 0xa6, 0x12]);
        // With a resident credential the user id comes first; still last line.
        let with_user = ASSERT_FIXTURE.replace("\nqBmm", "\nAAEC\nqBmm");
        assert_eq!(*parse_assert_output(&with_user).unwrap(), *s);
        // No hmac-secret line, or one of the wrong size.
        let lines: Vec<&str> = ASSERT_FIXTURE.lines().collect();
        assert!(parse_assert_output(&lines[..4].join("\n")).is_err());
        let short = ASSERT_FIXTURE.replace("qBmmEvRrEtn9e14gzAd1fWNDhpU1Tb8V+lfsgIZqEpo=", "AAAA");
        assert!(parse_assert_output(&short).is_err());
    }

    #[test]
    fn parses_fido2_cred_output() {
        assert_eq!(
            parse_cred_output(CRED_FIXTURE).unwrap(),
            [0xde, 0xad, 0xbe, 0xef].repeat(8)
        );
        assert!(parse_cred_output("a\nb\nc\n").is_err());
    }

    #[test]
    fn new_factor_registers_then_asserts_with_the_salt_on_stdin() {
        std::env::remove_var("KEPR_FIDO2_DEVICE");
        let fake = Fake {
            calls: RefCell::new(Vec::new()),
        };
        let f = new_factor(&fake).unwrap();
        let calls = fake.calls.borrow();
        assert_eq!(calls[0].0, "fido2-token");
        assert_eq!(
            (calls[1].0.as_str(), &calls[1].1[..]),
            (
                "fido2-cred",
                &["-M", "-h", "/dev/hidraw7"].map(String::from)[..]
            )
        );
        assert_eq!(calls[2].1, ["-G", "-h", "/dev/hidraw7"]);
        // Input: client data hash, RP id, credential id, salt — on stdin.
        let input: Vec<&str> = calls[2].2.lines().collect();
        assert_eq!(input[1], FIDO2_RP_ID);
        assert_eq!(B64.decode(input[2]).unwrap(), f.credential_id);
        assert_eq!(B64.decode(input[3]).unwrap(), f.salt);
        assert_eq!(*f.hmac, *parse_assert_output(ASSERT_FIXTURE).unwrap());
        // Nothing secret on any command line.
        assert!(calls
            .iter()
            .all(|(_, a, _)| a.iter().all(|a| !a.contains(input[3]))));
    }
}
