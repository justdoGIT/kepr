// daemon_seal/describe.rs — what seals the master key, for `kepr status`
// (T12.33).
//
// Only the key file's prefix is looked at: the TPM2 PIN / counter blob
// (tpm_blob.rs) carries its flags, a key-service blob (kms.rs) its kind
// line, a keychain blob (keychain.rs) only names the item. The default
// system sealer's blob is foreign, so what it was bound to comes from
// `master.key.seal`, written next to the key when it was sealed
// (master_key.rs); keys sealed before that record existed show as
// `host-unrecorded`. Nothing here is secret, and no token names a tool.

const TPM2: &[u8] = b"kepr-tpm2-v1\n";
const KEK: &[u8] = b"kepr-kek1\n";
const KEYCHAIN: &[u8] = b"kepr-keychain-v1\n";
/// The user-mode key file: the key itself follows (never read here).
const LOCAL: &[u8] = b"kepr-local-v1\n";
const FLAG_PIN: u8 = 1;
const FLAG_PCRS: u8 = 2;
const KEK_KINDS: &[&str] = &["aws-kms", "gcp-kms", "azure-kv", "pkcs11"];
const RECORDED: &[&str] = &["host", "tpm2", "host+tpm2"];

/// The status token for a sealed key file `blob` and its seal record.
pub fn describe(blob: &[u8], recorded: Option<&str>) -> String {
    if let Some(rest) = blob.strip_prefix(TPM2) {
        let flags = rest.first().copied().unwrap_or(0);
        let mut t = String::from("tpm2");
        if flags & FLAG_PIN != 0 {
            t.push_str("+pin");
        }
        if flags & FLAG_PCRS != 0 {
            t.push_str("+pcrs");
        }
        t.push_str("+counter");
        return t;
    }
    if let Some(rest) = blob.strip_prefix(KEK) {
        let kind = rest.split(|b| *b == b'\n').next().unwrap_or_default();
        let known = KEK_KINDS.iter().find(|k| k.as_bytes() == kind);
        return known.map_or("key-service", |k| k).to_string();
    }
    if blob.starts_with(KEYCHAIN) {
        return "keychain".into();
    }
    if blob.starts_with(LOCAL) {
        return "file".into();
    }
    let recorded = recorded.map(str::trim);
    match RECORDED.iter().find(|r| Some(**r) == recorded) {
        Some(r) => r.to_string(),
        None => "host-unrecorded".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tpm(flags: u8) -> Vec<u8> {
        let mut b = TPM2.to_vec();
        b.push(flags);
        b.extend_from_slice(&[0; 40]);
        b
    }

    #[test]
    fn tpm2_blobs_name_their_options() {
        assert_eq!(describe(&tpm(0), None), "tpm2+counter");
        assert_eq!(describe(&tpm(FLAG_PIN), None), "tpm2+pin+counter");
        assert_eq!(describe(&tpm(FLAG_PCRS), None), "tpm2+pcrs+counter");
        assert_eq!(
            describe(&tpm(FLAG_PIN | FLAG_PCRS), Some("host")),
            "tpm2+pin+pcrs+counter",
            "the blob wins over a stale record"
        );
        // Cut short after the magic: still the TPM2 sealer's.
        assert_eq!(describe(TPM2, None), "tpm2+counter");
    }

    #[test]
    fn key_service_blobs_give_their_kind() {
        for kind in KEK_KINDS {
            let blob = format!("kepr-kek1\n{kind}\nref\n\x01\x02");
            assert_eq!(describe(blob.as_bytes(), None), *kind);
        }
        let odd = b"kepr-kek1\nsomething-else\nref\n\x01";
        assert_eq!(describe(odd, None), "key-service");
        assert_eq!(describe(b"kepr-kek1\n", None), "key-service");
    }

    #[test]
    fn keychain_and_local_files() {
        let blob = b"kepr-keychain-v1\nkepr-master-key\nacct\n";
        assert_eq!(describe(blob, Some("host")), "keychain");
        let mut local = LOCAL.to_vec();
        local.extend_from_slice(&[7; 32]);
        assert_eq!(describe(&local, None), "file");
    }

    #[test]
    fn a_foreign_blob_uses_the_record() {
        let foreign = b"\x00\x01opaque credential blob";
        assert_eq!(describe(foreign, None), "host-unrecorded");
        for r in RECORDED {
            assert_eq!(describe(foreign, Some(r)), *r);
        }
        assert_eq!(describe(foreign, Some("host+tpm2\n")), "host+tpm2");
        // Only the known values are believed.
        assert_eq!(describe(foreign, Some("auto")), "host-unrecorded");
        assert_eq!(describe(foreign, Some("evil\x1b[2J")), "host-unrecorded");
        assert_eq!(describe(b"", None), "host-unrecorded");
    }
}
