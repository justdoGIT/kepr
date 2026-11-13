// fido2.rs — FIDO2/WebAuthn credential registry + assertion verify (Phase 2 η).
//
// Daemon stores credentials at /var/lib/kepr/fido2/<uid>/<id>.json.
// Registration: CLI talks to hardware key, sends credential ID + COSE_Key.
// Assertion verify is daemon-side (pre-decrypt gate) using ES256 (P-256).
// Challenge model: each Fido2Needed carries a fresh 32-byte challenge
// (in-memory store, 60s TTL, one-time-use). clientDataJSON is parsed,
// base64url challenge extracted, decoded, matched against the store.

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use kepr_core::protocol::{Fido2Assertion, Fido2CredInfo};

/// Root directory for the FIDO2 credential registry.
/// Registry root: `<state dir>/fido2` — /var/lib/kepr/fido2 in system
/// mode, ~/.local/state/kepr/fido2 in user mode (a non-root user-mode
/// daemon cannot write under /var/lib).
fn fido2_dir() -> PathBuf {
    crate::state_dir().join("fido2")
}
const MAX_LABEL: usize = 128;
const MAX_HEX: usize = 2048;

/// RP ID for SHA-256 hashing in authenticator data.
pub const RP_ID: &str = "kepr";

const CHALLENGE_TTL_SECS: u64 = 60;
/// Outstanding challenges across all users; beyond this, new ones are
/// refused until old ones expire (a client asking without answering
/// can't grow the daemon's memory).
const MAX_PENDING: usize = 1024;
/// challenge hex → (issued, uid, credential name): a challenge answers
/// only the request it was issued for.
type Pending = HashMap<String, (std::time::Instant, u32, String)>;
static CHALLENGES: std::sync::OnceLock<std::sync::Mutex<Pending>> = std::sync::OnceLock::new();
fn cs() -> std::sync::MutexGuard<'static, Pending> {
    let m = CHALLENGES.get_or_init(|| std::sync::Mutex::new(HashMap::new()));
    let mut g = m.lock().unwrap_or_else(|p| p.into_inner());
    g.retain(|_, (t, _, _)| t.elapsed().as_secs() < CHALLENGE_TTL_SECS);
    g
}

/// Fresh 32-byte challenge for `uid`'s `name`, hex-encoded.
pub fn generate_challenge(uid: u32, name: &str) -> Result<String, String> {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).map_err(|e| format!("CSPRNG failure: {e}"))?;
    let h = hex::encode(buf);
    let mut store = cs();
    if store.len() >= MAX_PENDING {
        return Err("too many pending FIDO2 challenges; try again shortly".into());
    }
    store.insert(
        h.clone(),
        (std::time::Instant::now(), uid, name.to_string()),
    );
    Ok(h)
}

/// List credential IDs registered for a given uid.
pub fn credential_ids_for_uid(uid: u32) -> Vec<String> {
    let dir = fido2_uid_dir(uid);
    let mut ids = Vec::new();
    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return ids,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "json") {
            if let Some(stem) = path.file_stem() {
                ids.push(stem.to_string_lossy().to_string());
            }
        }
    }
    ids
}

/// List all registered FIDO2 credentials for a given uid.
pub fn list_for_uid(uid: u32) -> Vec<Fido2CredInfo> {
    let dir = fido2_uid_dir(uid);
    let mut creds = Vec::new();
    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return creds,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "json") {
            let bytes = match fs::read(&path) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let stored: StoredCredential = match serde_json::from_slice(&bytes) {
                Ok(c) => c,
                Err(_) => continue,
            };
            creds.push(Fido2CredInfo {
                label: stored.label,
                credential_id: stored.credential_id,
                uid,
            });
        }
    }
    creds
}

/// Reject non-hex input — prevents path traversal via `../`/null bytes in
/// filenames built from `credential_id`.
fn validate_hex(s: &str, field: &str) -> Result<(), String> {
    if s.is_empty() {
        return Err(format!("fido2: {field} must not be empty"));
    }
    if s.len() > MAX_HEX {
        return Err(format!("fido2: {field} is too long"));
    }
    if !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "fido2: {field} must be hex-encoded, got non-hex bytes"
        ));
    }
    Ok(())
}

/// Register a new FIDO2 credential for the given uid.
/// `Fido2Register`. A new key is accepted only after a polkit prompt:
/// without it, any process running as the user (an agent) could
/// register a software key it holds and then answer every FIDO2
/// challenge itself, so `requires_fido2` would protect nothing.
pub fn handle_register(
    (uid, peer_pid, username): (u32, i32, &str),
    label: &str,
    credential_id: &str,
    public_key_cose: &str,
) -> kepr_core::protocol::Response {
    use crate::audit::{self, AuditEvent, AuditResult};
    let r = if crate::daemon_polkit::consent_granted(peer_pid) {
        register(uid, label, credential_id, public_key_cose)
    } else {
        Err(
            "registering a FIDO2 key needs approval (polkit prompt was refused or unavailable)"
                .into(),
        )
    };
    audit::log(&AuditEvent {
        op: "fido2-register",
        name: Some(label),
        uid,
        username,
        result: r
            .clone()
            .map_or_else(AuditResult::Fail, |()| AuditResult::Ok),
    });
    match r {
        Ok(()) => kepr_core::protocol::Response::Fido2RegisterOk {
            credential_id: credential_id.to_string(),
        },
        Err(e) => kepr_core::protocol::Response::fail(e),
    }
}

pub fn register(
    uid: u32,
    label: &str,
    credential_id: &str,
    public_key_cose_hex: &str,
) -> Result<(), String> {
    validate_hex(credential_id, "credential_id")?;
    validate_hex(public_key_cose_hex, "public_key_cose")?;
    if label.is_empty() || label.chars().count() > MAX_LABEL || label.chars().any(char::is_control)
    {
        return Err(format!(
            "fido2: label must be 1-{MAX_LABEL} printable characters"
        ));
    }
    let dir = fido2_uid_dir(uid);
    fs::create_dir_all(&dir).map_err(|e| format!("create fido2 dir: {e}"))?;
    let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    let path = fido2_cred_path(uid, credential_id);
    let stored = StoredCredential {
        label: label.to_string(),
        credential_id: credential_id.to_string(),
        public_key_cose_hex: public_key_cose_hex.to_string(),
    };
    let json = serde_json::to_vec(&stored).map_err(|e| format!("serialise fido2: {e}"))?;
    crate::atomic_file::write(&path, &json, 0o600).map_err(|e| format!("install fido2: {e}"))
}

/// Verify clientDataJSON contains a daemon-issued, unexpired challenge.
/// Parses JSON, extracts base64url challenge, decodes, matches store.
fn verify_challenge(client_data_json: &[u8], uid: u32, name: &str) -> Result<(), String> {
    let v: serde_json::Value = serde_json::from_slice(client_data_json)
        .map_err(|e| format!("fido2: clientDataJSON parse: {e}"))?;
    let b64u = v
        .get("challenge")
        .and_then(|c| c.as_str())
        .ok_or("fido2: clientDataJSON missing challenge")?;
    let decoded = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, b64u)
        .map_err(|e| format!("fido2: challenge base64 decode: {e}"))?;
    let hex_challenge = hex::encode(&decoded);
    cs().remove(&hex_challenge)
        .filter(|(_, u, n)| *u == uid && n == name)
        .map(|_| ())
        .ok_or_else(|| "fido2: challenge not found, expired, or for another request".to_string())
}

/// Verify a FIDO2 assertion against the stored credential.
pub fn verify_assertion(uid: u32, name: &str, assertion: &Fido2Assertion) -> Result<(), String> {
    use p256::ecdsa::{self, signature::Verifier};
    use sha2::Digest;

    let stored = load_credential(uid, &assertion.credential_id)?;

    let client_data_json = hex::decode(&assertion.client_data_json)
        .map_err(|e| format!("fido2: client_data_json hex: {e}"))?;
    let auth_data = hex::decode(&assertion.authenticator_data)
        .map_err(|e| format!("fido2: authenticator_data hex: {e}"))?;
    let sig_bytes =
        hex::decode(&assertion.signature).map_err(|e| format!("fido2: signature hex: {e}"))?;

    // 0. Verify challenge freshness (one-time-use, 60s TTL).
    verify_challenge(&client_data_json, uid, name)?;

    // 1. Verify RP ID hash: first 32 bytes of authenticatorData.
    if auth_data.len() < 32 {
        return Err("fido2: authenticator_data too short for RP ID hash".to_string());
    }
    let expected_rp_hash = sha2::Sha256::digest(RP_ID.as_bytes());
    if auth_data[..32] != expected_rp_hash[..] {
        return Err("fido2: RP ID hash mismatch".to_string());
    }

    // 2. Verify user presence flag (bit 0 of flags byte).
    if auth_data.len() <= 32 {
        return Err("fido2: authenticator_data too short for flags".to_string());
    }
    if auth_data[32] & 0x01 == 0 {
        return Err("fido2: user presence flag not set".to_string());
    }

    // 3. Reconstruct signed payload: auth_data || SHA-256(client_data_json).
    let client_data_hash = sha2::Sha256::digest(&client_data_json);
    let mut signed_payload = Vec::with_capacity(auth_data.len() + 32);
    signed_payload.extend_from_slice(&auth_data);
    signed_payload.extend_from_slice(&client_data_hash);

    // 4. Parse the public key from COSE_Key CBOR bytes.
    let cose_bytes = hex::decode(&stored.public_key_cose_hex)
        .map_err(|e| format!("fido2: public_key hex: {e}"))?;
    let pub_key_bytes = parse_es256_public_key(&cose_bytes)?;

    // 5. Verify the signature.
    let signature = ecdsa::Signature::from_der(&sig_bytes)
        .map_err(|e| format!("fido2: parse DER signature: {e}"))?;
    let verifying_key = ecdsa::VerifyingKey::from_sec1_bytes(&pub_key_bytes)
        .map_err(|e| format!("fido2: parse public key: {e}"))?;
    verifying_key
        .verify(&signed_payload, &signature)
        .map_err(|e| format!("fido2: signature verify: {e}"))
}

// ── Internal helpers ─────────────────────────────────────────────────────────

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct StoredCredential {
    label: String,
    credential_id: String,
    public_key_cose_hex: String,
}

fn fido2_uid_dir(uid: u32) -> PathBuf {
    fido2_dir().join(uid.to_string())
}

fn fido2_cred_path(uid: u32, credential_id: &str) -> PathBuf {
    fido2_uid_dir(uid).join(format!("{credential_id}.json"))
}

fn load_credential(uid: u32, credential_id: &str) -> Result<StoredCredential, String> {
    validate_hex(credential_id, "credential_id")?;
    let path = fido2_cred_path(uid, credential_id);
    let bytes = fs::read(&path).map_err(|e| format!("fido2: read credential: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("fido2: parse credential: {e}"))
}

/// Parse ES256 public key from COSE_Key CBOR. Returns 65-byte
/// uncompressed point (0x04 || x || y). COSE map: kty=2(EC2), alg=-7(ES256),
/// crv=1(P-256), x=bstr(32B), y=bstr(32B).
fn parse_es256_public_key(cose_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let value: ciborium::value::Value = ciborium::from_reader(cose_bytes)
        .map_err(|e| format!("fido2: CBOR parse COSE_Key: {e}"))?;

    let map = match value {
        ciborium::value::Value::Map(m) => m,
        _ => return Err("fido2: COSE_Key not a map".to_string()),
    };

    let mut fields: HashMap<i128, ciborium::value::Value> = HashMap::new();
    for (k, v) in map {
        let key_int = match k {
            ciborium::value::Value::Integer(i) => i128::from(i),
            _ => continue,
        };
        fields.insert(key_int, v);
    }

    let kty: i128 = get_integer(&fields, 1)?;
    if kty != 2 {
        return Err(format!("fido2: COSE_Key kty={kty}, expected 2 (EC2)"));
    }
    let alg: i128 = get_integer(&fields, 3)?;
    if alg != -7 {
        return Err(format!("fido2: COSE_Key alg={alg}, expected -7 (ES256)"));
    }
    let x = get_bstr(&fields, -2)?;
    let y = get_bstr(&fields, -3)?;
    if x.len() != 32 || y.len() != 32 {
        return Err(format!(
            "fido2: COSE_Key coordinates wrong length: x={}, y={}",
            x.len(),
            y.len()
        ));
    }
    let mut point = Vec::with_capacity(65);
    point.push(0x04);
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);
    Ok(point)
}

fn get_integer(fields: &HashMap<i128, ciborium::value::Value>, key: i128) -> Result<i128, String> {
    match fields.get(&key) {
        Some(ciborium::value::Value::Integer(i)) => Ok(i128::from(*i)),
        Some(v) => Err(format!("fido2: COSE_Key field {key} is not integer: {v:?}")),
        None => Err(format!("fido2: COSE_Key missing field {key}")),
    }
}

fn get_bstr(fields: &HashMap<i128, ciborium::value::Value>, key: i128) -> Result<Vec<u8>, String> {
    match fields.get(&key) {
        Some(ciborium::value::Value::Bytes(b)) => Ok(b.clone()),
        Some(v) => Err(format!("fido2: COSE_Key field {key} is not bytes: {v:?}")),
        None => Err(format!("fido2: COSE_Key missing field {key}")),
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_answers_only_its_own_request() {
        let c = generate_challenge(1, "A").unwrap();
        let b64 = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            hex::decode(&c).unwrap(),
        );
        let cdj = format!(r#"{{"challenge":"{b64}"}}"#);
        assert!(verify_challenge(cdj.as_bytes(), 1, "B").is_err());
        // The mismatched attempt used it up; a fresh one for A works.
        let c = generate_challenge(1, "A").unwrap();
        let b64 = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            hex::decode(&c).unwrap(),
        );
        let cdj = format!(r#"{{"challenge":"{b64}"}}"#);
        assert!(verify_challenge(cdj.as_bytes(), 2, "A").is_err());
    }

    #[test]
    fn generate_challenge_is_64_hex_chars() {
        let c = generate_challenge(1, "X").unwrap();
        assert_eq!(c.len(), 64);
        hex::decode(&c).expect("valid hex");
    }

    #[test]
    fn generate_challenge_is_unique() {
        let a = generate_challenge(1, "X").unwrap();
        let b = generate_challenge(1, "X").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn parse_es256_key_from_known_cose() {
        let x_hex = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
        let y_hex = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
        let cose_hex = format!("a5010203262001215820{x_hex}225820{y_hex}");
        let cose_bytes = hex::decode(&cose_hex).unwrap();
        let key = parse_es256_public_key(&cose_bytes).unwrap();
        assert_eq!(key.len(), 65);
        assert_eq!(key[0], 0x04);
        assert_eq!(hex::encode(&key[1..33]), x_hex);
        assert_eq!(hex::encode(&key[33..65]), y_hex);
    }

    #[test]
    fn parse_es256_key_rejects_non_map() {
        let err = parse_es256_public_key(&[0x00]).unwrap_err();
        assert!(err.contains("not a map"), "msg: {err}");
    }

    #[test]
    fn parse_es256_key_rejects_wrong_kty() {
        let cose = hex::decode("a201010302").unwrap();
        let err = parse_es256_public_key(&cose).unwrap_err();
        assert!(err.contains("kty"), "msg: {err}");
    }

    #[test]
    fn parse_es256_key_rejects_wrong_alg() {
        let cose = hex::decode("a201020327").unwrap();
        let err = parse_es256_public_key(&cose).unwrap_err();
        assert!(err.contains("alg"), "msg: {err}");
    }

    #[test]
    fn parse_es256_key_rejects_missing_coordinates() {
        let cose = hex::decode("a3010203262001").unwrap();
        let err = parse_es256_public_key(&cose).unwrap_err();
        assert!(err.contains("missing"), "msg: {err}");
    }

    #[test]
    fn register_and_list_round_trip() {
        // This test writes to the real registry dir (<state dir>/fido2/)
        // and is only runnable as root (or when the dir is user-writable).
        // Skip gracefully when we can't create the directory.
        let uid = 9999u32;
        let dir = fido2_uid_dir(uid);
        if fs::create_dir_all(&dir).is_err() {
            eprintln!("skipping register_and_list_round_trip (cannot write to {dir:?})");
            return;
        }
        let cred_id = "deadbeef00112233445566778899aabbccddeeff";
        let cose_key = concat!(
            "a5010203262001215820",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "225820bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
        let path = fido2_cred_path(uid, cred_id);
        let _ = fs::remove_file(&path);
        register(uid, "test-key", cred_id, cose_key).unwrap();
        let creds = list_for_uid(uid);
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].label, "test-key");
        assert_eq!(creds[0].credential_id, cred_id);
        assert_eq!(creds[0].uid, uid);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn list_returns_empty_for_unknown_uid() {
        let creds = list_for_uid(u32::MAX);
        assert!(creds.is_empty());
    }

    #[test]
    fn validate_hex_accepts_valid() {
        assert!(validate_hex("abcdef0123456789", "test").is_ok());
        assert!(validate_hex("ABCDEF", "test").is_ok());
    }

    #[test]
    fn validate_hex_rejects_empty() {
        let err = validate_hex("", "test").unwrap_err();
        assert!(err.contains("empty"), "msg: {err}");
    }

    #[test]
    fn validate_hex_rejects_non_hex() {
        let err = validate_hex("abc../def", "test").unwrap_err();
        assert!(err.contains("non-hex"), "msg: {err}");
        // Path traversal via dots and slashes.
        let err = validate_hex("../../../etc/passwd", "test").unwrap_err();
        assert!(err.contains("non-hex"), "msg: {err}");
    }

    #[test]
    fn register_rejects_non_hex_credential_id() {
        let err = register(1, "label", "../malicious", "aa").unwrap_err();
        assert!(err.contains("non-hex"), "msg: {err}");
    }

    #[test]
    fn verify_challenge_accepts_valid_client_data_json() {
        let hex_challenge = generate_challenge(1, "X").unwrap();
        // Build clientDataJSON as the CLI would: hex-decode → base64url → JSON → hex
        let challenge_bytes = hex::decode(&hex_challenge).unwrap();
        use base64::Engine;
        let b64u = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&challenge_bytes);
        let cdj = format!(r#"{{"type":"webauthn.get","challenge":"{b64u}","origin":"kepr"}}"#);
        let cdj_hex = hex::encode(cdj.as_bytes());
        let cdj_bytes = hex::decode(&cdj_hex).unwrap();
        // First call succeeds — challenge is known and unexpired.
        verify_challenge(&cdj_bytes, 1, "X").expect("valid challenge should pass");
    }

    #[test]
    fn verify_challenge_is_one_time_use() {
        let hex_challenge = generate_challenge(1, "X").unwrap();
        let challenge_bytes = hex::decode(&hex_challenge).unwrap();
        use base64::Engine;
        let b64u = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&challenge_bytes);
        let cdj = format!(r#"{{"type":"webauthn.get","challenge":"{b64u}","origin":"kepr"}}"#);
        let cdj_hex = hex::encode(cdj.as_bytes());
        let cdj_bytes = hex::decode(&cdj_hex).unwrap();
        verify_challenge(&cdj_bytes, 1, "X").expect("first use should pass");
        let err = verify_challenge(&cdj_bytes, 1, "X").unwrap_err();
        assert!(err.contains("not found"), "second use should fail: {err}");
    }

    #[test]
    fn verify_challenge_rejects_missing_challenge_field() {
        let cdj = r#"{"type":"webauthn.get","origin":"kepr"}"#;
        let cdj_hex = hex::encode(cdj.as_bytes());
        let cdj_bytes = hex::decode(&cdj_hex).unwrap();
        let err = verify_challenge(&cdj_bytes, 1, "X").unwrap_err();
        assert!(err.contains("missing challenge"), "msg: {err}");
    }

    #[test]
    fn verify_challenge_rejects_garbage_json() {
        let cdj = b"not json";
        let err = verify_challenge(cdj, 1, "X").unwrap_err();
        assert!(err.contains("clientDataJSON parse"), "msg: {err}");
    }

    #[test]
    fn verify_challenge_rejects_forged_challenge() {
        // Generate a challenge that was never stored.
        let forged = hex::encode([0xABu8; 32]);
        let challenge_bytes = hex::decode(&forged).unwrap();
        use base64::Engine;
        let b64u = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&challenge_bytes);
        let cdj = format!(r#"{{"type":"webauthn.get","challenge":"{b64u}","origin":"kepr"}}"#);
        let cdj_hex = hex::encode(cdj.as_bytes());
        let cdj_bytes = hex::decode(&cdj_hex).unwrap();
        let err = verify_challenge(&cdj_bytes, 1, "X").unwrap_err();
        assert!(err.contains("not found"), "msg: {err}");
    }

    #[test]
    fn generate_challenge_stores_in_global_store() {
        let c1 = generate_challenge(1, "X").unwrap();
        let c2 = generate_challenge(1, "X").unwrap();
        // Both should be in the store (not the same)
        assert_ne!(c1, c2);
        // Verify c1 is usable
        let challenge_bytes = hex::decode(&c1).unwrap();
        use base64::Engine;
        let b64u = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&challenge_bytes);
        let cdj = format!(r#"{{"type":"webauthn.get","challenge":"{b64u}","origin":"kepr"}}"#);
        let cdj_hex = hex::encode(cdj.as_bytes());
        let cdj_bytes = hex::decode(&cdj_hex).unwrap();
        verify_challenge(&cdj_bytes, 1, "X").expect("c1 should be in store");
        // c2 is still unused
        let challenge_bytes = hex::decode(&c2).unwrap();
        let b64u = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&challenge_bytes);
        let cdj = format!(r#"{{"type":"webauthn.get","challenge":"{b64u}","origin":"kepr"}}"#);
        let cdj_hex = hex::encode(cdj.as_bytes());
        let cdj_bytes = hex::decode(&cdj_hex).unwrap();
        verify_challenge(&cdj_bytes, 1, "X").expect("c2 should be in store");
    }
}
