// daemon_platform/pki.rs — `kepr pki init | issue | ls` (T10.10); svid.rs
// signs SPIFFE SVIDs through `issue_leaf` (T10.11).
//
// The CA key is the credential `KEPR_PKI_CA`, stored sealed with no
// bindings: `Get` refuses it, no gate can resolve it (no host), history
// restores it only into a sealed credential, and every "never revealed"
// check in the daemon already covers sealed values. It is decrypted only
// here, to sign. Its certificate and the issued certificates (serial,
// names, expiry; no keys) are kept in the `.meta` `pki` record, written
// before the key like any sealed credential's sidecar.
//
// `kepr health` reports certificates expiring within 14 days on that
// credential (`health_issues`); the CA key's age is ignored there
// (`health_ignore: ["old"]`), since a CA key is not rotated like a secret.

use base64::Engine;
use kepr_core::pki::{self, PkiCert, PkiState, CA_NAME};
use kepr_core::protocol::Response;
use kepr_core::protocol_platform::PlatformResponse;
use zeroize::Zeroizing;

use super::pki_sign::{self, Leaf, P256Public};
use crate::crypto;
use crate::expiry::{self, CredMeta};
use crate::store::cred_path;

/// Issued certificates kept for `kepr pki ls` (oldest dropped first).
const MAX_TRACKED: usize = 200;
const DAY: u64 = 86_400;

fn meta_path(uid: u32) -> std::path::PathBuf {
    expiry::meta_path_for(&cred_path(uid, CA_NAME))
}

/// The CA's meta and PKI record, or "no local CA".
pub fn read_state(uid: u32) -> Result<(CredMeta, PkiState), String> {
    let none = || "no local CA here; create one with: kepr pki init".to_string();
    if !crate::store::cred_exists(uid, CA_NAME) {
        return Err(none());
    }
    let meta = match expiry::read_meta(&meta_path(uid)) {
        Some(Ok(m)) => m,
        _ => return Err(none()),
    };
    match (&meta.pki, meta.sealed) {
        (Some(p), Some(true)) => {
            let p = p.clone();
            Ok((meta, p))
        }
        _ => Err(none()),
    }
}

/// Decrypt the CA key (a P-256 scalar) for one signature.
pub fn ca_key(uid: u32) -> Result<Zeroizing<Vec<u8>>, String> {
    let b64 = crypto::default_backend()
        .decrypt(uid, CA_NAME)
        .map_err(|e| crypto::sanitize_lookup_error(&e))?;
    base64::engine::general_purpose::STANDARD
        .decode(b64.as_str())
        .map(Zeroizing::new)
        .map_err(|_| "the CA key is damaged".to_string())
}

pub fn handle_init(uid: u32, username: &str, days: Option<u32>, force: bool) -> Response {
    let r = (|| {
        let days = days.unwrap_or(pki::DEFAULT_CA_DAYS);
        if !(1..=36_500).contains(&days) {
            return Err("--days: 1 to 36500".to_string());
        }
        let _lock = crate::daemon_credlock::lock(uid, CA_NAME);
        let existed = crate::store::cred_exists(uid, CA_NAME);
        if existed && !force {
            return Err("a local CA exists (kepr pki ls); --force replaces it, and \
                        certificates it issued stop chaining"
                .into());
        }
        let mut id = [0u8; 4];
        getrandom::fill(&mut id).map_err(|e| format!("CSPRNG failure: {e}"))?;
        let cn = format!("kepr local CA ({username}) {}", hex::encode(id));
        let new = pki_sign::new_ca(&cn, expiry::now_unix(), days)?;
        let meta = CredMeta {
            sealed: Some(true),
            pki: Some(PkiState {
                ca: new.ca.clone(),
                issued: Vec::new(),
                tpm: None,
            }),
            health_ignore: Some(vec!["old".into()]),
            ..Default::default()
        };
        let b64 =
            Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(new.key.as_slice()));
        install_ca(&meta_path(uid), &meta, || {
            crypto::default_backend().encrypt(uid, CA_NAME, b64.as_bytes())
        })?;
        crate::daemon_cache::invalidate(uid);
        crate::daemon_gate::bump_generation();
        Ok(new.ca)
    })();
    audit("pki-init", uid, username, &r);
    match r {
        Ok(ca) => Response::Platform(PlatformResponse::PkiCaOk { ca }),
        Err(e) => Response::fail(e),
    }
}

/// Write the CA's meta, then its key through `store_key`. Sealed before
/// the key exists, as for any sealed credential. When the key can't be
/// stored the earlier state comes back: no meta at all for a first CA, and
/// the old meta for `--force` (the old key is still there, and a new
/// certificate over it would sign certificates that don't verify).
fn install_ca(
    meta_file: &std::path::Path,
    meta: &CredMeta,
    store_key: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    let old = expiry::read_meta(meta_file).and_then(Result::ok);
    expiry::write_meta(meta_file, meta)?;
    if let Err(e) = store_key() {
        match old {
            Some(old) => {
                let _ = expiry::write_meta(meta_file, &old);
            }
            None => expiry::delete_meta(meta_file),
        }
        return Err(e);
    }
    Ok(())
}

/// Validity of a new leaf: `days`, never past the CA.
pub fn leaf_window(now: u64, days: u32, ca_not_after: u64) -> Result<(u64, u64), String> {
    let not_after = now + u64::from(days) * DAY;
    if not_after > ca_not_after {
        return Err("the CA expires before that; use fewer --days or kepr pki init --force".into());
    }
    Ok((now.saturating_sub(300), not_after))
}

/// Record an issued certificate: drop entries expired over 30 days ago,
/// keep at most `MAX_TRACKED`.
pub fn track(state: &mut PkiState, cert: PkiCert, now: u64) {
    state.issued.retain(|c| c.not_after + 30 * DAY > now);
    state.issued.push(cert);
    let extra = state.issued.len().saturating_sub(MAX_TRACKED);
    state.issued.drain(..extra);
}

/// Who a leaf is for: DNS names / IPs, or (T10.11) a SPIFFE ID.
pub struct Subject<'a> {
    pub sans: &'a [String],
    pub uri: Option<&'a str>,
}

/// Sign and record one leaf (shared by `issue` and T10.11 `svid`).
/// `check` runs on the CA state under the CA's lock before anything is signed.
pub fn issue_leaf(
    uid: u32,
    public_key: &str,
    who: Subject<'_>,
    (not_before, not_after): (u64, u64),
    check: &dyn Fn(&PkiState) -> Result<(), String>,
) -> Result<(String, PkiCert, String), String> {
    let pk = P256Public::from_hex(public_key)?;
    let _lock = crate::daemon_credlock::lock(uid, CA_NAME);
    let (mut meta, mut state) = read_state(uid)?;
    check(&state)?;
    let Subject { sans, uri } = who;
    if not_after > state.ca.not_after {
        return Err("the CA expires before that; use a shorter validity".into());
    }
    let key = ca_key(uid)?;
    let leaf = Leaf {
        sans,
        uri,
        not_before,
        not_after,
    };
    let (pem, serial) = pki_sign::sign_leaf(&state.ca, &key, &pk, &leaf)?;
    drop(key);
    let now = expiry::now_unix();
    let cert = PkiCert {
        serial,
        sans: sans.to_vec(),
        not_after,
        issued_at: now,
        spiffe_id: uri.map(str::to_string),
    };
    track(&mut state, cert.clone(), now);
    let ca_pem = state.ca.cert_pem.clone();
    meta.pki = Some(state);
    expiry::write_meta(&meta_path(uid), &meta)?;
    Ok((pem, cert, ca_pem))
}

/// Change the PKI record under the CA's lock (T10.11 TPM enrolment).
pub fn update_state<T>(
    uid: u32,
    f: impl FnOnce(&mut PkiState) -> Result<T, String>,
) -> Result<T, String> {
    let _lock = crate::daemon_credlock::lock(uid, CA_NAME);
    let (mut meta, mut state) = read_state(uid)?;
    let out = f(&mut state)?;
    meta.pki = Some(state);
    expiry::write_meta(&meta_path(uid), &meta)?;
    Ok(out)
}

pub fn handle_issue(
    uid: u32,
    username: &str,
    sans: &[String],
    days: Option<u32>,
    public_key: &str,
) -> Response {
    let r = (|| {
        let sans = pki::normalize_sans(sans)?;
        let days = days.unwrap_or(pki::DEFAULT_LEAF_DAYS);
        if !(1..=pki::MAX_LEAF_DAYS).contains(&days) {
            return Err(format!("--days: 1 to {}", pki::MAX_LEAF_DAYS));
        }
        let now = expiry::now_unix();
        let window = leaf_window(now, days, u64::MAX)?;
        let who = Subject {
            sans: &sans,
            uri: None,
        };
        issue_leaf(uid, public_key, who, window, &|_| Ok(()))
    })();
    audit("pki-issue", uid, username, &r);
    match r {
        Ok((cert_pem, cert, ca_pem)) => Response::Platform(PlatformResponse::PkiIssued {
            cert_pem,
            ca_pem,
            cert: Box::new(cert),
        }),
        Err(e) => Response::fail(e),
    }
}

pub fn handle_list(uid: u32, username: &str) -> Response {
    let r = read_state(uid).map(|(_, s)| s);
    audit("pki-ls", uid, username, &r);
    match r {
        Ok(state) => Response::Platform(PlatformResponse::PkiListOk {
            state: Box::new(state),
        }),
        Err(e) => Response::fail(e),
    }
}

/// `kepr health` findings for the CA credential (empty for others).
pub fn health_issues(meta: &CredMeta, now: u64) -> Vec<String> {
    match (&meta.pki, meta.sealed) {
        (Some(state), Some(true)) => pki::expiry_issues(state, now),
        _ => Vec::new(),
    }
}

pub fn audit<T>(op: &'static str, uid: u32, username: &str, r: &Result<T, String>) {
    crate::daemon_session::audit_op(
        op,
        Some(CA_NAME),
        uid,
        username,
        r.as_ref().map(drop).map_err(String::as_str),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert(serial: &str, not_after: u64) -> PkiCert {
        PkiCert {
            serial: serial.into(),
            sans: vec!["a.test".into()],
            not_after,
            issued_at: 0,
            spiffe_id: None,
        }
    }

    #[test]
    fn leaf_window_stays_inside_the_ca() {
        let now = 1_000 * DAY;
        assert_eq!(
            leaf_window(now, 30, now + 3650 * DAY),
            Ok((now - 300, now + 30 * DAY))
        );
        assert!(leaf_window(now, 30, now + 29 * DAY).is_err());
    }

    #[test]
    fn tracking_prunes_old_and_caps() {
        let now = 1_000 * DAY;
        let mut st = PkiState {
            ca: kepr_core::pki::PkiCa {
                cn: "x".into(),
                cert_pem: String::new(),
                not_after: now + 10 * DAY,
            },
            issued: vec![cert("old", now - 31 * DAY), cert("recent", now - DAY)],
            tpm: None,
        };
        track(&mut st, cert("new", now + DAY), now);
        let serials: Vec<&str> = st.issued.iter().map(|c| c.serial.as_str()).collect();
        assert_eq!(serials, ["recent", "new"]);
        for i in 0..MAX_TRACKED + 5 {
            track(&mut st, cert(&i.to_string(), now + DAY), now);
        }
        assert_eq!(st.issued.len(), MAX_TRACKED);
        assert_eq!(
            st.issued.last().unwrap().serial,
            (MAX_TRACKED + 4).to_string()
        );
    }

    #[test]
    fn init_issue_list_and_the_key_never_comes_back() {
        let uid = crate::daemon_store::testkit::uid();
        assert!(handle_list(uid, "t")
            .err_msg()
            .unwrap()
            .contains("pki init"));
        let Response::Platform(PlatformResponse::PkiCaOk { ca }) =
            handle_init(uid, "t", Some(20), false)
        else {
            panic!("init failed");
        };
        assert!(ca.cn.starts_with("kepr local CA (t) "));
        assert!(handle_init(uid, "t", None, false)
            .err_msg()
            .unwrap()
            .contains("--force"));
        let (_scalar, pk) = super::super::pki_sign::tests::leaf_key();
        let sans = vec!["App.Test".to_string(), "10.0.0.1".to_string()];
        let Response::Platform(PlatformResponse::PkiIssued {
            cert_pem,
            ca_pem,
            cert,
        }) = handle_issue(uid, "t", &sans, Some(5), &pk)
        else {
            panic!("issue failed");
        };
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        assert_eq!(ca_pem, ca.cert_pem);
        assert_eq!(cert.sans, ["app.test", "10.0.0.1"]);
        // Past the CA's end, or with a bad key: refused.
        assert!(handle_issue(uid, "t", &sans, Some(30), &pk)
            .err_msg()
            .is_some());
        assert!(handle_issue(uid, "t", &sans, None, "04")
            .err_msg()
            .is_some());
        let Response::Platform(PlatformResponse::PkiListOk { state }) = handle_list(uid, "t")
        else {
            panic!("list failed");
        };
        assert_eq!(state.issued, [*cert]);
        // The CA key is a sealed value: `get` never returns it.
        let pid = std::process::id() as i32;
        let got = crate::daemon_handlers_get::handle_get(uid, pid, "t", CA_NAME, None);
        assert_eq!(got.err_msg(), Some("credential unavailable"));
        // `kepr health`: the leaf expires within 14 days; the key's age is ignored.
        let Response::HealthOk { items } =
            crate::daemon_health::handle_health(uid, "t", Some(0), None)
        else {
            panic!("health failed");
        };
        let ca_item = items.iter().find(|i| i.name == CA_NAME).unwrap();
        assert!(ca_item
            .issues
            .iter()
            .any(|i| i.starts_with("certificate app.test")));
        assert_eq!(ca_item.ignore, ["old"]);
        // A plain set never replaces the sealed CA key; deleting it drops the CA.
        let r = crate::daemon_handlers::handle_set(
            uid,
            "t",
            CA_NAME,
            Some("plain"),
            None,
            Default::default(),
        );
        assert!(r.err_msg().unwrap().contains("never unseals"), "{r:?}");
        assert!(handle_list(uid, "t").is_success());
        assert!(crate::daemon_handlers::handle_delete(uid, "t", CA_NAME).is_success());
        assert!(handle_list(uid, "t").err_msg().is_some());
    }

    #[test]
    fn health_only_for_the_sealed_ca_record() {
        let now = 1_000 * DAY;
        let state = PkiState {
            ca: kepr_core::pki::PkiCa {
                cn: "x".into(),
                cert_pem: String::new(),
                not_after: now + 5 * DAY,
            },
            issued: vec![],
            tpm: None,
        };
        let sealed = CredMeta {
            sealed: Some(true),
            pki: Some(state.clone()),
            ..Default::default()
        };
        assert_eq!(health_issues(&sealed, now).len(), 1);
        let plain = CredMeta {
            pki: Some(state),
            ..Default::default()
        };
        assert!(health_issues(&plain, now).is_empty());
        assert!(health_issues(&CredMeta::default(), now).is_empty());
    }

    #[test]
    fn a_failed_key_write_puts_the_previous_ca_record_back() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("ca.meta");
        let old = CredMeta {
            sealed: Some(true),
            tags: Some(vec!["old".into()]),
            ..Default::default()
        };
        let new = CredMeta {
            sealed: Some(true),
            tags: Some(vec!["new".into()]),
            ..Default::default()
        };
        expiry::write_meta(&f, &old).unwrap();
        let err = install_ca(&f, &new, || Err("disk full".into())).unwrap_err();
        assert_eq!(err, "disk full");
        let back = expiry::read_meta(&f).unwrap().unwrap();
        assert_eq!(back.tags, old.tags, "the old CA record is back");
        // A first CA leaves nothing behind.
        let g = d.path().join("first.meta");
        assert!(install_ca(&g, &new, || Err("no".into())).is_err());
        assert!(!g.exists());
        // Success keeps the new record.
        install_ca(&g, &new, || Ok(())).unwrap();
        assert_eq!(expiry::read_meta(&g).unwrap().unwrap().tags, new.tags);
    }
}
