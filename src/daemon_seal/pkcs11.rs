// daemon_seal/pkcs11.rs — a PKCS#11 token or HSM as the master key's KEK
// (T4.13): YubiHSM 2, YubiKey PIV, smart cards, SoftHSM.
//
//   KEPR_MASTER_KEY_SEAL=pkcs11:<module path>:<key label>
//   KEPR_PKCS11_PIN_FILE=<file holding the user PIN>
//
// The master key is wrapped with the token's RSA key pair labelled
// <key label>, RSA-OAEP (SHA-256, MGF1-SHA-256), through OpenSC's
// `pkcs11-tool --encrypt | --decrypt` (OpenSC 0.23 or newer). Data goes in
// on stdin and comes back on stdout. The PIN is read from the file here and
// handed to the tool in its own environment (`--pin env:KEPR_PKCS11_PIN`):
// never argv, never this daemon's environment, never a log line.
// Unwrapping needs the PIN (the private key); wrapping logs in only when a
// PIN file is set (an HSM such as the YubiHSM needs a session for any use).

use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use super::kms::KekSealer;
use super::runner::{Cmd, RunError, Runner, SystemRunner};

const TOOL: &str = "pkcs11-tool";
const PIN_VAR: &str = "KEPR_PKCS11_PIN";
const SEAL_FAILED: &str = "master-key seal failed";
const UNSEAL_FAILED: &str = "master-key unseal failed";
const MECHANISM: [&str; 6] = [
    "--mechanism",
    "RSA-PKCS-OAEP",
    "--hash-algorithm",
    "SHA256",
    "--mgf",
    "MGF1-SHA256",
];

pub struct Pkcs11<R: Runner> {
    spec: String,
    module: String,
    label: String,
    pin_file: Option<PathBuf>,
    runner: R,
}

/// `(module, label)` from `<module path>:<key label>`.
pub fn parse_spec(spec: &str) -> Result<(String, String), String> {
    let bad = || {
        format!(
            "KEPR_MASTER_KEY_SEAL=pkcs11:{spec}: use pkcs11:/path/to/module.so:LABEL \
             (label: letters, digits, space, . _ -)"
        )
    };
    let (module, label) = spec.rsplit_once(':').ok_or_else(bad)?;
    let module_ok = Path::new(module).is_absolute()
        && !module.bytes().any(|b| b.is_ascii_control() || b == b':');
    let label_ok = !label.is_empty()
        && label.len() <= 64
        && !label.starts_with('-')
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b' ' | b'.' | b'_' | b'-'));
    if !module_ok || !label_ok {
        return Err(bad());
    }
    Ok((module.to_string(), label.to_string()))
}

impl Pkcs11<SystemRunner> {
    pub fn from_env(spec: &str) -> Result<Self, String> {
        let pin_file = std::env::var_os("KEPR_PKCS11_PIN_FILE")
            .filter(|p| !p.is_empty())
            .map(PathBuf::from);
        Self::new(spec, pin_file, SystemRunner)
    }
}

impl<R: Runner> Pkcs11<R> {
    pub fn new(spec: &str, pin_file: Option<PathBuf>, runner: R) -> Result<Self, String> {
        let (module, label) = parse_spec(spec)?;
        Ok(Self {
            spec: spec.to_string(),
            module,
            label,
            pin_file,
            runner,
        })
    }

    /// The PIN from `KEPR_PKCS11_PIN_FILE`, without a trailing newline.
    fn pin(&self) -> Result<Option<Zeroizing<String>>, String> {
        let Some(path) = &self.pin_file else {
            return Ok(None);
        };
        let raw = Zeroizing::new(
            std::fs::read(path).map_err(|_| "cannot read KEPR_PKCS11_PIN_FILE".to_string())?,
        );
        let text = std::str::from_utf8(&raw).map_err(|_| "KEPR_PKCS11_PIN_FILE is not text")?;
        let pin = text.trim_end_matches(['\r', '\n']);
        if pin.is_empty() {
            return Err("KEPR_PKCS11_PIN_FILE is empty".into());
        }
        Ok(Some(Zeroizing::new(pin.to_string())))
    }

    fn run(
        &self,
        op: &str,
        data: &[u8],
        pin: Option<&str>,
        failed: &str,
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        let mut cmd = Cmd::new(TOOL, &["--module", &self.module]);
        if let Some(p) = pin {
            cmd.args
                .extend(["--login", "--pin", "env:KEPR_PKCS11_PIN"].map(String::from));
            cmd.env.push((PIN_VAR, p));
        }
        cmd.args.push(op.to_string());
        cmd.args.extend(MECHANISM.map(String::from));
        cmd.args.extend(["--label".to_string(), self.label.clone()]);
        self.runner.run(&cmd.stdin(data)).map_err(|e| match e {
            RunError::Missing => {
                "PKCS#11 sealing needs OpenSC's pkcs11-tool (package opensc) installed".into()
            }
            RunError::Failed => failed.to_string(),
        })
    }
}

impl<R: Runner> KekSealer for Pkcs11<R> {
    fn kind(&self) -> &'static str {
        "pkcs11"
    }

    fn key_ref(&self) -> &str {
        &self.spec
    }

    fn seal(&self, key: &[u8; 32]) -> Result<Vec<u8>, String> {
        let pin = self.pin()?;
        let out = self.run(
            "--encrypt",
            key,
            pin.as_ref().map(|p| p.as_str()),
            SEAL_FAILED,
        )?;
        if out.is_empty() || out.windows(32).any(|w| w == key) {
            return Err(SEAL_FAILED.into());
        }
        Ok(out.to_vec())
    }

    fn unseal(&self, ciphertext: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
        let pin = self
            .pin()?
            .ok_or("unsealing through PKCS#11 needs the token PIN: set KEPR_PKCS11_PIN_FILE")?;
        let out = self.run("--decrypt", ciphertext, Some(&pin), UNSEAL_FAILED)?;
        let key: [u8; 32] = out[..].try_into().map_err(|_| UNSEAL_FAILED)?;
        Ok(Zeroizing::new(key))
    }
}

#[cfg(test)]
mod tests {
    use super::super::kms::KmsSealer;
    use super::super::runner::fake::FakeRunner;
    use super::*;
    use crate::master_key::Sealer;

    const MODULE: &str = "/usr/lib/x86_64-linux-gnu/pkcs11/yubihsm_pkcs11.so";

    /// A pretend token: "encrypts" by reversing; checks the PIN on login.
    fn token() -> FakeRunner {
        FakeRunner::new(|c| {
            let logged_in = c
                .env
                .iter()
                .any(|(k, v)| *k == PIN_VAR && *v == "0001password");
            if c.args.contains(&"--login".to_string()) && !logged_in {
                return Err(RunError::Failed);
            }
            let mut out = c.stdin.to_vec();
            out.reverse();
            if c.args.contains(&"--decrypt".to_string()) && !logged_in {
                return Err(RunError::Failed);
            }
            Ok(out)
        })
    }

    /// Not a palindrome: the fake token's "ciphertext" must differ from it.
    const KEY: [u8; 32] = {
        let mut k = [0u8; 32];
        let mut i = 0;
        while i < 32 {
            k[i] = i as u8;
            i += 1;
        }
        k
    };

    fn pin_file(dir: &tempfile::TempDir) -> PathBuf {
        let p = dir.path().join("pin");
        std::fs::write(&p, "0001password\n").unwrap();
        p
    }

    #[test]
    fn command_lines_are_built_and_the_pin_stays_off_argv() {
        let dir = tempfile::tempdir().unwrap();
        let spec = format!("{MODULE}:kepr master");
        let s = KmsSealer(Pkcs11::new(&spec, Some(pin_file(&dir)), token()).unwrap());
        let blob = s.seal(&KEY).unwrap();
        assert!(blob.starts_with(format!("kepr-kek1\npkcs11\n{spec}\n").as_bytes()));
        assert_eq!(*s.unseal(&blob).unwrap(), KEY);
        let calls = s.0.runner.calls();
        let expect = |op: &str| -> Vec<String> {
            [
                "--module",
                MODULE,
                "--login",
                "--pin",
                "env:KEPR_PKCS11_PIN",
                op,
                "--mechanism",
                "RSA-PKCS-OAEP",
                "--hash-algorithm",
                "SHA256",
                "--mgf",
                "MGF1-SHA256",
                "--label",
                "kepr master",
            ]
            .map(String::from)
            .to_vec()
        };
        assert_eq!(calls[0].0, "pkcs11-tool");
        assert_eq!(calls[0].1, expect("--encrypt"));
        assert_eq!(calls[0].2, KEY);
        assert_eq!(calls[1].1, expect("--decrypt"));
        for (_, args, _, env) in &calls {
            assert!(args.iter().all(|a| !a.contains("password")));
            assert_eq!(env, &[(PIN_VAR.to_string(), "0001password".to_string())]);
        }
    }

    #[test]
    fn without_a_pin_file_only_wrapping_works() {
        let s = Pkcs11::new(&format!("{MODULE}:k1"), None, token()).unwrap();
        let ct = KekSealer::seal(&s, &KEY).unwrap();
        assert!(!s.runner.calls()[0].1.contains(&"--login".to_string()));
        assert!(s.runner.calls()[0].3.is_empty());
        let e = KekSealer::unseal(&s, &ct).unwrap_err();
        assert!(e.contains("KEPR_PKCS11_PIN_FILE"), "{e}");
    }

    #[test]
    fn a_wrong_pin_or_short_output_fails_quietly() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("pin");
        std::fs::write(&p, "9999").unwrap();
        let s = Pkcs11::new(&format!("{MODULE}:k1"), Some(p), token()).unwrap();
        assert_eq!(
            KekSealer::unseal(&s, &[0u8; 256]).unwrap_err(),
            UNSEAL_FAILED
        );
        let s = Pkcs11::new(&format!("{MODULE}:k1"), Some(pin_file(&dir)), token()).unwrap();
        assert_eq!(
            KekSealer::unseal(&s, &[0u8; 31]).unwrap_err(),
            UNSEAL_FAILED
        );
        // A "token" that echoes the key back is not wrapping anything.
        let echo = Pkcs11::new(
            &format!("{MODULE}:k1"),
            None,
            FakeRunner::new(|c| Ok(c.stdin.to_vec())),
        )
        .unwrap();
        assert_eq!(KekSealer::seal(&echo, &[2u8; 32]).unwrap_err(), SEAL_FAILED);
        let missing = Pkcs11::new(
            &format!("{MODULE}:k1"),
            None,
            FakeRunner::new(|_| Err(RunError::Missing)),
        )
        .unwrap();
        assert!(KekSealer::seal(&missing, &[2u8; 32])
            .unwrap_err()
            .contains("opensc"));
    }

    #[test]
    fn specs_are_checked() {
        assert_eq!(
            parse_spec(&format!("{MODULE}:kepr-master")).unwrap(),
            (MODULE.to_string(), "kepr-master".to_string())
        );
        for bad in [
            "relative.so:k",
            "/m.so:",
            "/m.so:--pin=1",
            "/m.so:k\n",
            "nolabel",
            "/m.so:a$b",
        ] {
            assert!(parse_spec(bad).is_err(), "{bad}");
        }
    }
}
