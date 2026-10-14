// cli_platform/svid.rs — SPIFFE SVIDs from the local CA (T10.11).
//
//   kepr pki svid SPIFFE_ID [--ttl 1h] [--out DIR] [--force] [--ak HANDLE|CTX]
//       svid.pem, svid_key.pem (0600) and svid_bundle.pem (the CA), the
//       file names spiffe-helper uses. With a TPM enrolled, --ak is needed:
//       `tpm2_quote` signs PCR 7 over a daemon nonce first.
//   kepr pki tpm-enroll --ak-pub ak.pem --ak HANDLE|CTX
//       tie SVIDs to this attestation key and the current PCR 7 value.
//
// The tpm2-tools binaries do the TPM work; nothing here talks to the TPM.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use base64::Engine;
use kepr_core::pki::{self, TpmQuote};
use kepr_core::protocol::Response;
use kepr_core::protocol_platform::{PlatformRequest, PlatformResponse};

use super::args;
use super::pki::{leaf_key, send, write_new};

/// DER prefix of a P-256 SubjectPublicKeyInfo with an uncompressed point.
const P256_SPKI_PREFIX: &str = "3059301306072a8648ce3d020106082a8648ce3d030107034200";

const AK_HINT: &str = "create a persistent attestation key once:\n  \
     tpm2_createek -c ek.ctx -G ecc -u ek.pub\n  \
     tpm2_createak -C ek.ctx -c ak.ctx -G ecc -g sha256 -s ecdsa -u ak.pem -f pem\n  \
     tpm2_evictcontrol -c ak.ctx 0x81010002\n\
     then: kepr pki tpm-enroll --ak-pub ak.pem --ak 0x81010002";

/// Runs a tpm2-tools program (a fake in tests).
pub trait Tpm {
    fn run(&self, prog: &str, args: &[String]) -> Result<(), String>;
}

struct Tools;

impl Tpm for Tools {
    fn run(&self, prog: &str, args: &[String]) -> Result<(), String> {
        let out = Command::new(prog)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => format!("{prog} not found: install tpm2-tools"),
                _ => format!("{prog}: {e}"),
            })?;
        if out.status.success() {
            return Ok(());
        }
        let err = String::from_utf8_lossy(&out.stderr);
        let first = err.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
        Err(format!("{prog} failed: {}", first.trim()))
    }
}

/// A private scratch directory, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Result<Self, String> {
        use std::os::unix::fs::DirBuilderExt;
        let mut id = [0u8; 8];
        getrandom::fill(&mut id).map_err(|e| format!("CSPRNG failure: {e}"))?;
        let p = std::env::temp_dir().join(format!("kepr-tpm-{}", hex::encode(id)));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&p)
            .map_err(|e| format!("{}: {e}", p.display()))?;
        Ok(Self(p))
    }
    fn read(&self, name: &str) -> Result<Vec<u8>, String> {
        std::fs::read(self.0.join(name)).map_err(|e| format!("{name}: {e}"))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn quote_args(ak: &str, nonce: &str, msg: &Path, sig: &Path) -> Vec<String> {
    let p = |p: &Path| p.display().to_string();
    [
        "-c",
        ak,
        "-l",
        "sha256:7",
        "-q",
        nonce,
        "-g",
        "sha256",
        "-m",
        &p(msg),
        "-s",
        &p(sig),
    ]
    .map(str::to_string)
    .to_vec()
}

/// A quote over PCR 7 with `nonce` (TSS-format message and signature).
pub fn quote_with(t: &dyn Tpm, ak: &str, nonce: String) -> Result<TpmQuote, String> {
    let dir = Scratch::new()?;
    let (m, s) = (dir.0.join("quote.msg"), dir.0.join("quote.sig"));
    t.run("tpm2_quote", &quote_args(ak, &nonce, &m, &s))?;
    Ok(TpmQuote {
        attest: hex::encode(dir.read("quote.msg")?),
        signature: hex::encode(dir.read("quote.sig")?),
        nonce,
    })
}

fn quote(t: &dyn Tpm, ak: &str) -> Result<TpmQuote, String> {
    match send(PlatformRequest::PkiNonce) {
        Response::Platform(PlatformResponse::PkiNonceOk { nonce }) => quote_with(t, ak, nonce),
        Response::Err { error } => Err(error),
        _ => Err("unexpected daemon response".into()),
    }
}

/// PCR 7 of the SHA-256 bank (hex).
pub fn read_pcr7(t: &dyn Tpm) -> Result<String, String> {
    let dir = Scratch::new()?;
    let out = dir.0.join("pcr7.bin");
    t.run(
        "tpm2_pcrread",
        &[
            "sha256:7".to_string(),
            "-o".into(),
            out.display().to_string(),
        ],
    )?;
    let v = dir.read("pcr7.bin")?;
    if v.len() != 32 {
        return Err("tpm2_pcrread: expected one SHA-256 value".into());
    }
    Ok(hex::encode(v))
}

/// The uncompressed point (hex) of a P-256 public key in PEM.
pub fn ak_point(pem: &str) -> Result<String, String> {
    let b64: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .map(str::trim)
        .collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| "--ak-pub: not a PEM public key".to_string())?;
    let h = hex::encode(der);
    match h.strip_prefix(P256_SPKI_PREFIX) {
        Some(point) if point.len() == 130 && point.starts_with("04") => Ok(point.to_string()),
        _ => Err("--ak-pub: expected an ECC P-256 key (tpm2_createak -G ecc -f pem)".into()),
    }
}

/// svid.pem, svid_key.pem (0600), svid_bundle.pem in `out`.
pub fn write_svid(
    out: &Path,
    cert_pem: &str,
    ca_pem: &str,
    key_pem: &str,
    force: bool,
) -> Result<[PathBuf; 3], String> {
    let paths = ["svid.pem", "svid_key.pem", "svid_bundle.pem"].map(|n| out.join(n));
    if !force {
        if let Some(p) = paths.iter().find(|p| p.exists()) {
            return Err(format!("{} exists (--force to replace it)", p.display()));
        }
    }
    write_new(&paths[1], key_pem.as_bytes(), 0o600, force)?;
    write_new(&paths[0], cert_pem.as_bytes(), 0o644, force)?;
    write_new(&paths[2], ca_pem.as_bytes(), 0o644, force)?;
    Ok(paths)
}

/// `YYYY-MM-DD HH:MM UTC`.
fn when(unix: u64) -> String {
    let s = unix % 86_400;
    format!(
        "{} {:02}:{:02} UTC",
        pki::date(unix),
        s / 3600,
        s % 3600 / 60
    )
}

pub fn svid(argv: &[String]) -> Result<Response, String> {
    let a = args::parse(argv, &["--ttl", "--out", "--ak"], &["--force"])?;
    let [id] = a.positional.as_slice() else {
        return Err(
            "usage: kepr pki svid spiffe://TRUST-DOMAIN/PATH [--ttl 1h] [--out DIR] \
                    [--force] [--ak HANDLE|CTX]"
                .into(),
        );
    };
    pki::validate_spiffe_id(id)?;
    let ttl = pki::parse_svid_ttl(a.value("--ttl"))?;
    let out = PathBuf::from(a.value("--out").unwrap_or("."));
    let quote = a.value("--ak").map(|ak| quote(&Tools, ak)).transpose()?;
    let (key_pem, public_key) = leaf_key()?;
    let resp = send(PlatformRequest::PkiSvid {
        spiffe_id: id.clone(),
        ttl_secs: Some(ttl),
        public_key,
        quote,
    });
    let Response::Platform(PlatformResponse::PkiIssued {
        cert_pem,
        ca_pem,
        cert,
    }) = &resp
    else {
        return Ok(resp);
    };
    let files = write_svid(&out, cert_pem, ca_pem, &key_pem, a.has("--force"))?;
    if !crate::cli_ui::json_mode() {
        crate::cli_ui::ok(&format!("Issued {id} until {}", when(cert.not_after)));
        for f in files {
            crate::cli_ui::dim(&format!("  {}", f.display()));
        }
    }
    Ok(resp)
}

pub fn tpm_enroll(argv: &[String]) -> Result<Response, String> {
    let a = args::parse(argv, &["--ak-pub", "--ak"], &[])?;
    let (Some(ak_pub), Some(ak), true) = (
        a.value("--ak-pub"),
        a.value("--ak"),
        a.positional.is_empty(),
    ) else {
        return Err(format!(
            "usage: kepr pki tpm-enroll --ak-pub ak.pem --ak HANDLE|CTX\n{AK_HINT}"
        ));
    };
    let pem = std::fs::read_to_string(ak_pub).map_err(|e| format!("{ak_pub}: {e}"))?;
    let ak_public = ak_point(&pem)?;
    let pcr7 = read_pcr7(&Tools)?;
    let quote = quote(&Tools, ak)?;
    let resp = send(PlatformRequest::PkiTpmEnroll {
        ak_public,
        pcr7,
        quote,
    });
    if let (Response::Platform(PlatformResponse::PkiTpmEnrolled { policy }), false) =
        (&resp, crate::cli_ui::json_mode())
    {
        crate::cli_ui::ok("TPM enrolled: SVIDs now need a quote from this attestation key");
        crate::cli_ui::dim(&format!(
            "  PCR 7 (sha256) = {}\n  a Secure Boot change stops issuance; kepr pki init --force starts over",
            policy.pcr7
        ));
    }
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Writes fixed bytes where tpm2-tools would, and records the calls.
    struct Fake(RefCell<Vec<String>>);

    impl Tpm for Fake {
        fn run(&self, prog: &str, args: &[String]) -> Result<(), String> {
            self.0
                .borrow_mut()
                .push(format!("{prog} {}", args.join(" ")));
            let after = |flag: &str| args.iter().position(|a| a == flag).map(|i| &args[i + 1]);
            for (flag, data) in [("-m", &b"MSG"[..]), ("-s", b"SIG"), ("-o", &[7u8; 32])] {
                if let Some(p) = after(flag) {
                    std::fs::write(p, data).unwrap();
                }
            }
            Ok(())
        }
    }

    #[test]
    fn quote_runs_tpm2_quote_over_pcr7_with_the_nonce() {
        let fake = Fake(RefCell::new(Vec::new()));
        let q = quote_with(&fake, "0x81010002", "ab12".into()).unwrap();
        assert_eq!(q.nonce, "ab12");
        assert_eq!(q.attest, hex::encode("MSG"));
        assert_eq!(q.signature, hex::encode("SIG"));
        let call = fake.0.borrow()[0].clone();
        assert!(
            call.starts_with("tpm2_quote -c 0x81010002 -l sha256:7 -q ab12 -g sha256 -m "),
            "{call}"
        );
        assert_eq!(read_pcr7(&fake).unwrap(), "07".repeat(32));
        assert!(fake.0.borrow()[1].starts_with("tpm2_pcrread sha256:7 -o "));
        // The scratch directories are gone.
        let dir = call
            .split(" -m ")
            .nth(1)
            .unwrap()
            .split(' ')
            .next()
            .unwrap();
        assert!(!Path::new(dir).parent().unwrap().exists());
    }

    #[test]
    fn attestation_key_pem() {
        let point = format!("04{}", "11".repeat(64));
        let der = hex::decode(format!("{P256_SPKI_PREFIX}{point}")).unwrap();
        let pem = kepr_core::x509_build::pem("PUBLIC KEY", &der);
        assert_eq!(ak_point(&pem).unwrap(), point);
        assert!(ak_point("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n").is_err());
        // An openssl-made key, where openssl is installed.
        let Ok(out) = Command::new("sh")
            .args([
                "-c",
                "openssl ecparam -name prime256v1 -genkey -noout | openssl ec -pubout 2>/dev/null",
            ])
            .output()
        else {
            return;
        };
        if out.status.success() && !out.stdout.is_empty() {
            let p = ak_point(&String::from_utf8_lossy(&out.stdout)).unwrap();
            assert_eq!(p.len(), 130);
        }
    }

    #[test]
    fn svid_files_and_arguments() {
        let dir = tempfile::tempdir().unwrap();
        let [crt, key, bundle] = write_svid(dir.path(), "LEAF", "CA", "KEY", false).unwrap();
        assert_eq!(std::fs::read_to_string(&crt).unwrap(), "LEAF");
        assert_eq!(std::fs::read_to_string(&bundle).unwrap(), "CA");
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(write_svid(dir.path(), "L", "C", "K", false).is_err());
        assert!(write_svid(dir.path(), "L", "C", "K", true).is_ok());
        assert_eq!(when(1_791_462_896), "2026-10-08 12:34 UTC");
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert!(svid(&s(&["https://x/y"])).unwrap_err().contains("SPIFFE"));
        assert!(svid(&s(&["spiffe://td/w", "--ttl", "48h"]))
            .unwrap_err()
            .contains("--ttl"));
        assert!(svid(&s(&[])).unwrap_err().contains("usage"));
        assert!(tpm_enroll(&s(&["--ak", "0x81010002"]))
            .unwrap_err()
            .contains("tpm2_createak"));
    }
}
