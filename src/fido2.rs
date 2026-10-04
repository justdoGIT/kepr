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
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
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
static CHALLENGES: std::sync::OnceLock<std::sync::Mutex<HashMap<String, std::time::Instant>>> =
    std::sync::OnceLock::new();
fn cs() -> &'static std::sync::Mutex<HashMap<String, std::time::Instant>> {
    CHALLENGES.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

/// Fresh 32-byte challenge, hex-encoded, stored for later verification.
pub fn generate_challenge() -> Result<String, String> {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).map_err(|e| format!("CSPRNG failure: {e}"))?;
    let h = hex::encode(buf);
    cs().lock()
        .unwrap()
        .insert(h.clone(), std::time::Instant::now());
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
    // Atomic write: temp + rename.
    let tmp = path.with_extension(format!(
        "tmp.{}.{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let mut f = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(&tmp);
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)
                .map_err(|e| format!("open fido2 temp (after stale-cleanup): {e}"))?
        }
        Err(e) => return Err(format!("open fido2 temp: {e}")),
    };
    if let Err(e) = f.write_all(&json) {
        drop(f);
        let _ = fs::remove_file(&tmp);
        return Err(format!("write fido2: {e}"));
    }
    drop(f);
    fs::rename(&tmp, &path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("install fido2: {e}")
    })
}

/// Verify clientDataJSON contains a daemon-issued, unexpired challenge.
/// Parses JSON, extracts base64url challenge, decodes, matches store.
fn verify_challenge(client_data_json: &[u8]) -> Result<(), String> {
    let v: serde_json::Value = serde_json::from_slice(client_data_json)
        .map_err(|e| format!("fido2: clientDataJSON parse: {e}"))?;
    let b64u = v
        .get("challenge")
        .and_then(|c| c.as_str())
        .ok_or("fido2: clientDataJSON missing challenge")?;
    let decoded = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, b64u)
        .map_err(|e| format!("fido2: challenge base64 decode: {e}"))?;
    let hex_challenge = hex::encode(&decoded);
    let mut store = cs().lock().unwrap();
    store.retain(|_, t| t.elapsed().as_secs() < CHALLENGE_TTL_SECS);
    store
        .remove(&hex_challenge)
        .filter(|t| t.elapsed().as_secs() < CHALLENGE_TTL_SECS)
        .map(|_| ())
        .ok_or_else(|| "fido2: challenge not found or expired".to_string())
}

/// Verify a FIDO2 assertion against the stored credential.
pub fn verify_assertion(uid: u32, assertion: &Fido2Assertion) -> Result<(), String> {
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
    verify_challenge(&client_data_json)?;

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
    fn generate_challenge_is_64_hex_chars() {
        let c = generate_challenge().unwrap();
        assert_eq!(c.len(), 64);
        hex::decode(&c).expect("valid hex");
    }

    #[test]
    fn generate_challenge_is_unique() {
        let a = generate_challenge().unwrap();
        let b = generate_challenge().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn parse_es256_key_from_known_cose() {
        let x_hex = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
        let y_hex = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
        let cose_hex = format!("a5010203262001215820{}225820{}", x_hex, y_hex);
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
        let hex_challenge = generate_challenge().unwrap();
        // Build clientDataJSON as the CLI would: hex-decode → base64url → JSON → hex
        let challenge_bytes = hex::decode(&hex_challenge).unwrap();
        use base64::Engine;
        let b64u = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&challenge_bytes);
        let cdj = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"kepr"}}"#,
            b64u
        );
        let cdj_hex = hex::encode(cdj.as_bytes());
        let cdj_bytes = hex::decode(&cdj_hex).unwrap();
        // First call succeeds — challenge is known and unexpired.
        verify_challenge(&cdj_bytes).expect("valid challenge should pass");
    }

    #[test]
    fn verify_challenge_is_one_time_use() {
        let hex_challenge = generate_challenge().unwrap();
        let challenge_bytes = hex::decode(&hex_challenge).unwrap();
        use base64::Engine;
        let b64u = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&challenge_bytes);
        let cdj = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"kepr"}}"#,
            b64u
        );
        let cdj_hex = hex::encode(cdj.as_bytes());
        let cdj_bytes = hex::decode(&cdj_hex).unwrap();
        verify_challenge(&cdj_bytes).expect("first use should pass");
        let err = verify_challenge(&cdj_bytes).unwrap_err();
        assert!(err.contains("not found"), "second use should fail: {err}");
    }

    #[test]
    fn verify_challenge_rejects_missing_challenge_field() {
        let cdj = r#"{"type":"webauthn.get","origin":"kepr"}"#;
        let cdj_hex = hex::encode(cdj.as_bytes());
        let cdj_bytes = hex::decode(&cdj_hex).unwrap();
        let err = verify_challenge(&cdj_bytes).unwrap_err();
        assert!(err.contains("missing challenge"), "msg: {err}");
    }

    #[test]
    fn verify_challenge_rejects_garbage_json() {
        let cdj = b"not json";
        let err = verify_challenge(cdj).unwrap_err();
        assert!(err.contains("clientDataJSON parse"), "msg: {err}");
    }

    #[test]
    fn verify_challenge_rejects_forged_challenge() {
        // Generate a challenge that was never stored.
        let forged = hex::encode([0xABu8; 32]);
        let challenge_bytes = hex::decode(&forged).unwrap();
        use base64::Engine;
        let b64u = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&challenge_bytes);
        let cdj = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"kepr"}}"#,
            b64u
        );
        let cdj_hex = hex::encode(cdj.as_bytes());
        let cdj_bytes = hex::decode(&cdj_hex).unwrap();
        let err = verify_challenge(&cdj_bytes).unwrap_err();
        assert!(err.contains("not found"), "msg: {err}");
    }

    #[test]
    fn generate_challenge_stores_in_global_store() {
        let c1 = generate_challenge().unwrap();
        let c2 = generate_challenge().unwrap();
        // Both should be in the store (not the same)
        assert_ne!(c1, c2);
        // Verify c1 is usable
        let challenge_bytes = hex::decode(&c1).unwrap();
        use base64::Engine;
        let b64u = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&challenge_bytes);
        let cdj = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"kepr"}}"#,
            b64u
        );
        let cdj_hex = hex::encode(cdj.as_bytes());
        let cdj_bytes = hex::decode(&cdj_hex).unwrap();
        verify_challenge(&cdj_bytes).expect("c1 should be in store");
        // c2 is still unused
        let challenge_bytes = hex::decode(&c2).unwrap();
        let b64u = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&challenge_bytes);
        let cdj = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"kepr"}}"#,
            b64u
        );
        let cdj_hex = hex::encode(cdj.as_bytes());
        let cdj_bytes = hex::decode(&cdj_hex).unwrap();
        verify_challenge(&cdj_bytes).expect("c2 should be in store");
    }
}
