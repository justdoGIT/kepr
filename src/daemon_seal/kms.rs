// daemon_seal/kms.rs — bring your own key (T4.11): the master key is
// wrapped by a key-encryption key that lives in a cloud KMS or an HSM.
//
//   KEPR_MASTER_KEY_SEAL=aws-kms:<key-arn>            kms_aws.rs (T4.11)
//   KEPR_MASTER_KEY_SEAL=gcp-kms:projects/…/cryptoKeys/… kms_cloud.rs (T4.12)
//   KEPR_MASTER_KEY_SEAL=azure-kv:https://…/keys/K/V  kms_cloud.rs (T4.12)
//
// `KekSealer` is one key service (wrap / unwrap 32 bytes); `KmsSealer`
// turns it into the daemon's `master_key::Sealer` by writing which key
// wrapped the master key in front of the ciphertext:
//
//     "kepr-kek1\n" | kind "\n" | key reference "\n" | ciphertext
//
// Unseal refuses a blob made by another kind or key with an error that
// says which one to configure: the setting applies to new master keys,
// and a blob never chooses the key service it is sent to.

use zeroize::Zeroizing;

use crate::master_key::Sealer;

const MAGIC: &[u8] = b"kepr-kek1\n";

/// One key service: wraps and unwraps the 32-byte master key.
pub trait KekSealer: Send + Sync {
    /// `aws-kms`, … — the `KEPR_MASTER_KEY_SEAL` prefix.
    fn kind(&self) -> &'static str;
    /// The key it uses, as configured (an ARN, a resource name, a URL).
    fn key_ref(&self) -> &str;
    fn seal(&self, key: &[u8; 32]) -> Result<Vec<u8>, String>;
    fn unseal(&self, ciphertext: &[u8]) -> Result<Zeroizing<[u8; 32]>, String>;
}

pub struct KmsSealer<K: KekSealer>(pub K);

impl<K: KekSealer> Sealer for KmsSealer<K> {
    fn seal(&self, key: &[u8; 32]) -> Result<Vec<u8>, String> {
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(self.0.kind().as_bytes());
        out.push(b'\n');
        out.extend_from_slice(self.0.key_ref().as_bytes());
        out.push(b'\n');
        out.extend_from_slice(&self.0.seal(key)?);
        Ok(out)
    }

    fn unseal(&self, blob: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
        let want = format!("{}:{}", self.0.kind(), self.0.key_ref());
        let Some(rest) = blob.strip_prefix(MAGIC) else {
            return Err(format!(
                "the master key was sealed another way; KEPR_MASTER_KEY_SEAL={want} \
                 applies to new master keys only"
            ));
        };
        let mut parts = rest.splitn(3, |b| *b == b'\n');
        let (kind, key_ref, ct) = match (parts.next(), parts.next(), parts.next()) {
            (Some(k), Some(r), Some(c)) if !c.is_empty() => (k, r, c),
            _ => return Err("invalid sealed master-key file".into()),
        };
        if kind != self.0.kind().as_bytes() || key_ref != self.0.key_ref().as_bytes() {
            return Err(format!(
                "the master key was sealed with {}:{}; set KEPR_MASTER_KEY_SEAL to that",
                String::from_utf8_lossy(kind),
                String::from_utf8_lossy(key_ref)
            ));
        }
        self.0.unseal(ct)
    }
}

/// A key reference goes into the blob's header line and into URLs:
/// printable ASCII, no spaces, at most 512 bytes.
pub fn check_ref(kind: &str, r: &str) -> Result<(), String> {
    let ok = !r.is_empty() && r.len() <= 512 && r.bytes().all(|b| b.is_ascii_graphic());
    if !ok {
        return Err(format!(
            "KEPR_MASTER_KEY_SEAL={kind}:…: not a key reference"
        ));
    }
    Ok(())
}

/// The 32-byte key from a decrypt reply's (base64) plaintext.
pub fn key_from_b64(
    b64: &str,
    engine: &impl base64::Engine,
    failed: &str,
) -> Result<Zeroizing<[u8; 32]>, String> {
    let raw = Zeroizing::new(engine.decode(b64.trim()).map_err(|_| failed.to_string())?);
    let key: [u8; 32] = raw.as_slice().try_into().map_err(|_| failed.to_string())?;
    Ok(Zeroizing::new(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// XORs with a constant: enough to test the blob framing.
    struct Xor(&'static str, &'static str);

    impl KekSealer for Xor {
        fn kind(&self) -> &'static str {
            self.0
        }
        fn key_ref(&self) -> &str {
            self.1
        }
        fn seal(&self, key: &[u8; 32]) -> Result<Vec<u8>, String> {
            Ok(key.iter().map(|b| b ^ 0x5a).collect())
        }
        fn unseal(&self, ct: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
            let k: [u8; 32] = ct
                .iter()
                .map(|b| b ^ 0x5a)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            Ok(Zeroizing::new(k))
        }
    }

    #[test]
    fn blob_names_its_key_and_refuses_another() {
        let s = KmsSealer(Xor("aws-kms", "arn:aws:kms:eu-west-1:111122223333:key/k1"));
        let blob = s.seal(&[9u8; 32]).unwrap();
        assert!(
            blob.starts_with(b"kepr-kek1\naws-kms\narn:aws:kms:eu-west-1:111122223333:key/k1\n")
        );
        assert!(!blob.windows(32).any(|w| w == [9u8; 32]));
        assert_eq!(*s.unseal(&blob).unwrap(), [9u8; 32]);
        let other = KmsSealer(Xor("aws-kms", "arn:aws:kms:eu-west-1:111122223333:key/k2"));
        let e = other.unseal(&blob).unwrap_err();
        assert!(
            e.contains("sealed with aws-kms:arn:aws:kms:eu-west-1:111122223333:key/k1"),
            "{e}"
        );
        let e = s.unseal(b"kepr-local-v1\n0123").unwrap_err();
        assert!(e.contains("new master keys only"), "{e}");
        assert!(s.unseal(b"kepr-kek1\naws-kms\n").is_err());
    }

    #[test]
    fn key_refs_are_single_printable_lines() {
        assert!(check_ref("aws-kms", "arn:aws:kms:x").is_ok());
        assert!(check_ref("aws-kms", "").is_err());
        assert!(check_ref("aws-kms", "a\nb").is_err());
        assert!(check_ref("aws-kms", "a b").is_err());
    }
}
