// cli_platform/pki.rs — `kepr pki` (T10.10).
//
//   kepr pki init [--days N] [--force]         local CA; its key stays sealed in the store
//   kepr pki ca                                print the CA certificate (to trust it)
//   kepr pki issue NAME... [--days 30] [--out DIR] [--force]
//                                              NAME.crt (leaf + CA) and NAME.key (0600)
//   kepr pki ls                                CA and issued certificates with expiry
//
// The leaf key is generated here and written straight to NAME.key; the
// daemon only sees its public key.

use std::io::Write;
use std::path::{Path, PathBuf};

use kepr_core::pki::{self, PkiCert, PkiState};
use kepr_core::protocol::{Request, Response};
use kepr_core::protocol_platform::{PlatformRequest, PlatformResponse};
use zeroize::Zeroizing;

use super::args;

const USAGE: &str = "usage: kepr pki init [--days N] [--force] | ca | issue NAME... [--days N] [--out DIR] [--force] | ls";

pub fn send(r: PlatformRequest) -> Response {
    crate::client::send_request(&Request::Platform(r)).unwrap_or_else(Response::fail)
}

fn json() -> bool {
    crate::cli_ui::json_mode()
}

pub fn parse_days(v: Option<&str>) -> Result<Option<u32>, String> {
    v.map(|d| {
        d.trim_end_matches('d')
            .parse::<u32>()
            .map_err(|_| format!("--days: not a number: {d}"))
    })
    .transpose()
}

pub fn cmd_pki(argv: &[String]) -> Response {
    let Some((sub, rest)) = argv.split_first() else {
        return Response::fail(USAGE);
    };
    let r = match sub.as_str() {
        "init" => init(rest),
        "ca" => ca(),
        "issue" => issue(rest),
        "ls" | "list" => ls(),
        _ => Err(USAGE.into()),
    };
    r.unwrap_or_else(Response::fail)
}

fn init(argv: &[String]) -> Result<Response, String> {
    let a = args::parse(argv, &["--days"], &["--force"])?;
    if !a.positional.is_empty() {
        return Err(USAGE.into());
    }
    let resp = send(PlatformRequest::PkiInit {
        days: parse_days(a.value("--days"))?,
        force: a.has("--force"),
    });
    if let (Response::Platform(PlatformResponse::PkiCaOk { ca }), false) = (&resp, json()) {
        crate::cli_ui::ok(&format!(
            "Created \"{}\", valid until {}.",
            ca.cn,
            date(ca.not_after)
        ));
        crate::cli_ui::dim(
            "  Trust it: kepr pki ca > kepr-ca.crt, then add it to your system or browser store",
        );
        crate::cli_ui::dim("  (Debian/Ubuntu: sudo cp kepr-ca.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates)");
    }
    Ok(resp)
}

fn list() -> Result<PkiState, String> {
    match send(PlatformRequest::PkiList) {
        Response::Platform(PlatformResponse::PkiListOk { state }) => Ok(state),
        Response::Err { error } => Err(error),
        _ => Err("unexpected daemon response".into()),
    }
}

fn ca() -> Result<Response, String> {
    let state = list()?;
    if !json() {
        print!("{}", state.ca.cert_pem);
    }
    Ok(Response::Platform(PlatformResponse::PkiCaOk {
        ca: state.ca,
    }))
}

/// A file name for a certificate named `san` (`*.x` → `_wildcard.x`).
pub fn file_stem(san: &str) -> String {
    san.replace("*.", "_wildcard.").replace(':', "_")
}

/// Write `data` to a new file (or over an old one with `force`).
pub fn write_new(path: &Path, data: &[u8], mode: u32, force: bool) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).mode(mode);
    if force {
        o.create(true).truncate(true);
    } else {
        o.create_new(true);
    }
    let mut f = o.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            format!("{} exists (--force to replace it)", path.display())
        } else {
            format!("{}: {e}", path.display())
        }
    })?;
    f.write_all(data)
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// A new P-256 leaf key: (PKCS#8 PEM, hex public point).
pub fn leaf_key() -> Result<(Zeroizing<String>, String), String> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let sk = loop {
        let mut b = Zeroizing::new([0u8; 32]);
        getrandom::fill(b.as_mut()).map_err(|e| format!("CSPRNG failure: {e}"))?;
        if let Ok(sk) = p256::SecretKey::from_slice(b.as_ref()) {
            break sk;
        }
    };
    let point = sk.public_key().to_encoded_point(false);
    let scalar: Zeroizing<[u8; 32]> = Zeroizing::new(sk.to_bytes().into());
    let der = Zeroizing::new(kepr_core::x509_build::pkcs8_p256(&scalar, point.as_bytes()));
    Ok((
        Zeroizing::new(kepr_core::x509_build::pem("PRIVATE KEY", &der)),
        hex::encode(point.as_bytes()),
    ))
}

/// Write NAME.crt (leaf then CA) and NAME.key into `out`.
pub fn write_pair(
    out: &Path,
    stem: &str,
    cert_pem: &str,
    ca_pem: &str,
    key_pem: &str,
    force: bool,
) -> Result<(PathBuf, PathBuf), String> {
    let (crt, key) = (
        out.join(format!("{stem}.crt")),
        out.join(format!("{stem}.key")),
    );
    if !force {
        for p in [&crt, &key] {
            if p.exists() {
                return Err(format!("{} exists (--force to replace it)", p.display()));
            }
        }
    }
    write_new(&key, key_pem.as_bytes(), 0o600, force)?;
    write_new(&crt, format!("{cert_pem}{ca_pem}").as_bytes(), 0o644, force)?;
    Ok((crt, key))
}

fn issue(argv: &[String]) -> Result<Response, String> {
    let a = args::parse(argv, &["--days", "--out"], &["--force"])?;
    let sans = pki::normalize_sans(&a.positional)?;
    let out = PathBuf::from(a.value("--out").unwrap_or("."));
    let (key_pem, public_key) = leaf_key()?;
    let resp = send(PlatformRequest::PkiIssue {
        sans: sans.clone(),
        days: parse_days(a.value("--days"))?,
        public_key,
    });
    let Response::Platform(PlatformResponse::PkiIssued {
        cert_pem,
        ca_pem,
        cert,
    }) = &resp
    else {
        return Ok(resp);
    };
    let (crt, key) = write_pair(
        &out,
        &file_stem(&sans[0]),
        cert_pem,
        ca_pem,
        &key_pem,
        a.has("--force"),
    )?;
    if !json() {
        crate::cli_ui::ok(&format!(
            "Issued {} until {}",
            sans.join(", "),
            date(cert.not_after)
        ));
        crate::cli_ui::dim(&format!("  {}\n  {}", crt.display(), key.display()));
    }
    Ok(resp)
}

/// `YYYY-MM-DD` (UTC).
pub fn date(unix: u64) -> String {
    kepr_core::pki::date(unix)
}

pub fn render(state: &PkiState, now: u64) -> String {
    let left = |t: u64| {
        if t <= now {
            "expired".to_string()
        } else {
            format!("{} d", (t - now).div_ceil(86_400))
        }
    };
    let mut s = format!(
        "CA  {}  until {} ({})\n",
        state.ca.cn,
        date(state.ca.not_after),
        left(state.ca.not_after)
    );
    let row = |c: &PkiCert| {
        let who = c.spiffe_id.clone().unwrap_or_else(|| c.sans.join(", "));
        format!(
            "    {who}  until {} ({})  serial {}\n",
            date(c.not_after),
            left(c.not_after),
            c.serial
        )
    };
    s.extend(state.issued.iter().map(row));
    s
}

fn ls() -> Result<Response, String> {
    let state = list()?;
    if !json() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        print!("{}", render(&state, now));
        for line in pki::expiry_issues(&state, now) {
            crate::cli_ui::warn(&line);
        }
    }
    Ok(Response::Platform(PlatformResponse::PkiListOk { state }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kepr_core::pki::PkiCa;

    #[test]
    fn names_days_and_files() {
        assert_eq!(file_stem("*.dev.test"), "_wildcard.dev.test");
        assert_eq!(file_stem("::1"), "__1");
        assert_eq!(parse_days(Some("30d")), Ok(Some(30)));
        assert_eq!(parse_days(None), Ok(None));
        assert!(parse_days(Some("soon")).is_err());
        let dir = tempfile::tempdir().unwrap();
        let (crt, key) =
            write_pair(dir.path(), "a.test", "LEAF\n", "CA\n", "KEY\n", false).unwrap();
        assert_eq!(std::fs::read_to_string(&crt).unwrap(), "LEAF\nCA\n");
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(write_pair(dir.path(), "a.test", "L", "C", "K", false).is_err());
        assert!(write_pair(dir.path(), "a.test", "L2", "C", "K", true).is_ok());
        assert_eq!(std::fs::read_to_string(&crt).unwrap(), "L2C");
    }

    #[test]
    fn leaf_keys_are_p256() {
        let (pem, public) = leaf_key().unwrap();
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert_eq!(public.len(), 130);
        assert!(public.starts_with("04"));
        // ring (already a dependency) accepts the PKCS#8 encoding.
        use base64::Engine;
        let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let der = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .unwrap();
        let rng = ring::rand::SystemRandom::new();
        let kp = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &der,
            &rng,
        )
        .expect("PKCS#8 parses");
        use ring::signature::KeyPair;
        assert_eq!(hex::encode(kp.public_key().as_ref()), public);
    }

    #[test]
    fn listing() {
        let day = 86_400;
        let now = 100 * day;
        let st = PkiState {
            ca: PkiCa {
                cn: "kepr local CA (u) 01".into(),
                cert_pem: String::new(),
                not_after: now + 365 * day,
            },
            issued: vec![PkiCert {
                serial: "ab".into(),
                sans: vec!["a.test".into(), "b.test".into()],
                not_after: now + 3 * day,
                issued_at: now,
                spiffe_id: None,
            }],
        };
        let r = render(&st, now);
        assert!(r.contains("(365 d)"));
        assert!(r.contains("a.test, b.test  until 1970-04-14 (3 d)  serial ab"));
        assert!(cmd_pki(&[]).err_msg().is_some());
        assert!(cmd_pki(&["bogus".to_string()]).err_msg().is_some());
        assert!(
            cmd_pki(&["issue".to_string()]).err_msg().is_some(),
            "no names"
        );
    }
}
