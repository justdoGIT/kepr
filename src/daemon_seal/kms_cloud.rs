// daemon_seal/kms_cloud.rs — GCP Cloud KMS and Azure Key Vault as the
// master key's KEK (T4.12). Bearer tokens, like `kepr sync`:
//
//   KEPR_MASTER_KEY_SEAL=gcp-kms:projects/P/locations/L/keyRings/R/cryptoKeys/K
//       GCP_ACCESS_TOKEN (`gcloud auth print-access-token`); POST
//       v1/{name}:encrypt | :decrypt with additionalAuthenticatedData
//       "kepr:master-key" (KEPR_KMS_ENDPOINT overrides the endpoint)
//   KEPR_MASTER_KEY_SEAL=azure-kv:https://NAME.vault.azure.net/keys/KEY/VERSION
//       AZURE_ACCESS_TOKEN (`az account get-access-token --resource
//       https://vault.azure.net`); POST {key}/wrapkey | /unwrapkey with
//       RSA-OAEP-256, values in base64url
//
// Tokens are read at start-up and never logged; errors carry the HTTP
// status and the provider's error code only.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde::Deserialize;
use zeroize::Zeroizing;

use kepr_core::generate::ZeroString;

use super::http::{host_and_path, http_error, Headers, Transport, UreqTransport};
use super::kms::{check_ref, key_from_b64, KekSealer};

const SEAL_FAILED: &str = "master-key seal failed";
const UNSEAL_FAILED: &str = "master-key unseal failed";
const GCP_AAD: &[u8] = b"kepr:master-key";
const AZURE_API: &str = "api-version=7.4";
const AZURE_SUFFIXES: &[&str] = &[
    "vault.azure.net",
    "vault.azure.cn",
    "vault.usgovcloudapi.net",
    "managedhsm.azure.net",
];

fn token(var: &str, kind: &str) -> Result<ZeroString, String> {
    let t = std::env::var(var)
        .ok()
        .filter(|t| !t.is_empty())
        .ok_or_else(|| format!("{kind} sealing needs {var} in the daemon's environment"))?;
    let t = ZeroString::from_string(t);
    if !t.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(format!("{var} is not a bearer token"));
    }
    Ok(t)
}

/// POST JSON with a bearer token; the reply body on HTTP 200.
fn post<T: Transport>(
    t: &T,
    url: &str,
    token: &ZeroString,
    body: &[u8],
    failed: &str,
) -> Result<Zeroizing<String>, String> {
    let headers: Headers = vec![
        ("Authorization".into(), format!("Bearer {}", token.as_str())),
        ("Content-Type".into(), "application/json".into()),
    ];
    let (status, reply) = t
        .post(url, &headers, body)
        .map_err(|e| format!("{failed}: {e}"))?;
    if status != 200 {
        return Err(http_error(failed, status, &reply));
    }
    Ok(reply)
}

fn segment_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

/// `projects/P/locations/L/keyRings/R/cryptoKeys/K`.
pub fn check_gcp_name(name: &str) -> Result<(), String> {
    let p: Vec<&str> = name.split('/').collect();
    let ok = p.len() == 8
        && [p[0], p[2], p[4], p[6]] == ["projects", "locations", "keyRings", "cryptoKeys"]
        && [p[1], p[3], p[5], p[7]].iter().all(|s| segment_ok(s));
    if !ok {
        return Err(format!(
            "KEPR_MASTER_KEY_SEAL=gcp-kms:{name}: use projects/P/locations/L/keyRings/R/cryptoKeys/K"
        ));
    }
    Ok(())
}

/// `https://NAME.<vault suffix>/keys/KEY/VERSION`.
pub fn check_azure_url(url: &str) -> Result<(), String> {
    let bad = || {
        format!("KEPR_MASTER_KEY_SEAL=azure-kv:{url}: use https://NAME.vault.azure.net/keys/KEY/VERSION")
    };
    if !url.starts_with("https://") {
        return Err(bad());
    }
    let (host, path) = host_and_path(url).map_err(|_| bad())?;
    let vault_ok = host.split_once('.').is_some_and(|(name, suffix)| {
        (3..=24).contains(&name.len())
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && AZURE_SUFFIXES.contains(&suffix)
    });
    let p: Vec<&str> = path.split('/').collect();
    let path_ok = p.len() == 4
        && p[0].is_empty()
        && p[1] == "keys"
        && segment_ok(p[2])
        && !p[3].is_empty()
        && p[3].bytes().all(|b| b.is_ascii_alphanumeric());
    if !vault_ok || !path_ok {
        return Err(bad());
    }
    Ok(())
}

/// Base64url with or without padding (Azure), or standard base64.
fn b64_any(s: &str, failed: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let s = s.trim().trim_end_matches('=');
    URL_SAFE_NO_PAD
        .decode(s)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(s))
        .map(Zeroizing::new)
        .map_err(|_| failed.to_string())
}

#[derive(Deserialize)]
struct GcpEncrypted {
    ciphertext: String,
}

#[derive(Deserialize)]
struct GcpDecrypted {
    plaintext: ZeroString,
}

pub struct GcpKms<T: Transport> {
    name: String,
    endpoint: String,
    token: ZeroString,
    transport: T,
}

impl GcpKms<UreqTransport> {
    pub fn from_env(name: &str) -> Result<Self, String> {
        check_gcp_name(name)?;
        let endpoint = std::env::var("KEPR_KMS_ENDPOINT")
            .ok()
            .filter(|e| !e.is_empty());
        let token = token("GCP_ACCESS_TOKEN", "gcp-kms")?;
        Self::new(name, token, endpoint.as_deref(), UreqTransport)
    }
}

impl<T: Transport> GcpKms<T> {
    pub fn new(
        name: &str,
        token: ZeroString,
        endpoint: Option<&str>,
        transport: T,
    ) -> Result<Self, String> {
        check_gcp_name(name)?;
        let mut endpoint = endpoint
            .unwrap_or("https://cloudkms.googleapis.com/")
            .to_string();
        host_and_path(&endpoint)?;
        if !endpoint.ends_with('/') {
            endpoint.push('/');
        }
        Ok(Self {
            name: name.to_string(),
            endpoint,
            token,
            transport,
        })
    }

    fn url(&self, op: &str) -> String {
        format!("{}v1/{}:{op}", self.endpoint, self.name)
    }
}

impl<T: Transport> KekSealer for GcpKms<T> {
    fn kind(&self) -> &'static str {
        "gcp-kms"
    }

    fn key_ref(&self) -> &str {
        &self.name
    }

    fn seal(&self, key: &[u8; 32]) -> Result<Vec<u8>, String> {
        let plaintext = Zeroizing::new(STANDARD.encode(key));
        let body = Zeroizing::new(format!(
            r#"{{"plaintext":"{}","additionalAuthenticatedData":"{}"}}"#,
            plaintext.as_str(),
            STANDARD.encode(GCP_AAD)
        ));
        let reply = post(
            &self.transport,
            &self.url("encrypt"),
            &self.token,
            body.as_bytes(),
            SEAL_FAILED,
        )?;
        let out: GcpEncrypted = serde_json::from_str(&reply).map_err(|_| SEAL_FAILED)?;
        Ok(b64_any(&out.ciphertext, SEAL_FAILED)?.to_vec())
    }

    fn unseal(&self, ciphertext: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
        let body = serde_json::json!({
            "ciphertext": STANDARD.encode(ciphertext),
            "additionalAuthenticatedData": STANDARD.encode(GCP_AAD),
        })
        .to_string();
        let reply = post(
            &self.transport,
            &self.url("decrypt"),
            &self.token,
            body.as_bytes(),
            UNSEAL_FAILED,
        )?;
        let out: GcpDecrypted = serde_json::from_str(&reply).map_err(|_| UNSEAL_FAILED)?;
        key_from_b64(out.plaintext.as_str(), &STANDARD, UNSEAL_FAILED)
    }
}

#[derive(Deserialize)]
struct AzureValue {
    value: ZeroString,
}

pub struct AzureKv<T: Transport> {
    key_url: String,
    token: ZeroString,
    transport: T,
}

impl AzureKv<UreqTransport> {
    pub fn from_env(key_url: &str) -> Result<Self, String> {
        check_azure_url(key_url)?;
        Self::new(
            key_url,
            token("AZURE_ACCESS_TOKEN", "azure-kv")?,
            UreqTransport,
        )
    }
}

impl<T: Transport> AzureKv<T> {
    pub fn new(key_url: &str, token: ZeroString, transport: T) -> Result<Self, String> {
        check_azure_url(key_url)?;
        check_ref("azure-kv", key_url)?;
        Ok(Self {
            key_url: key_url.to_string(),
            token,
            transport,
        })
    }

    fn call(&self, op: &str, value: &str, failed: &str) -> Result<Zeroizing<Vec<u8>>, String> {
        let body = Zeroizing::new(format!(r#"{{"alg":"RSA-OAEP-256","value":"{value}"}}"#));
        let url = format!("{}/{op}?{AZURE_API}", self.key_url);
        let reply = post(&self.transport, &url, &self.token, body.as_bytes(), failed)?;
        let out: AzureValue = serde_json::from_str(&reply).map_err(|_| failed.to_string())?;
        b64_any(out.value.as_str(), failed)
    }
}

impl<T: Transport> KekSealer for AzureKv<T> {
    fn kind(&self) -> &'static str {
        "azure-kv"
    }

    fn key_ref(&self) -> &str {
        &self.key_url
    }

    fn seal(&self, key: &[u8; 32]) -> Result<Vec<u8>, String> {
        let value = Zeroizing::new(URL_SAFE_NO_PAD.encode(key));
        Ok(self.call("wrapkey", &value, SEAL_FAILED)?.to_vec())
    }

    fn unseal(&self, ciphertext: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
        let raw = self.call(
            "unwrapkey",
            &URL_SAFE_NO_PAD.encode(ciphertext),
            UNSEAL_FAILED,
        )?;
        let key: [u8; 32] = raw.as_slice().try_into().map_err(|_| UNSEAL_FAILED)?;
        Ok(Zeroizing::new(key))
    }
}

#[cfg(test)]
mod tests {
    use super::super::http::fake::Recorder;
    use super::super::kms::KmsSealer;
    use super::*;
    use crate::master_key::Sealer;

    const GCP: &str = "projects/acme-prod/locations/europe-west1/keyRings/kepr/cryptoKeys/master";
    const AZURE: &str =
        "https://acme-vault.vault.azure.net/keys/kepr-master/0123456789abcdef0123456789abcdef";

    #[test]
    fn gcp_encrypt_and_decrypt_requests() {
        let ct = STANDARD.encode(b"gcp-ciphertext\xff\xfe");
        let enc = format!(r#"{{"name":"{GCP}/cryptoKeyVersions/1","ciphertext":"{ct}"}}"#);
        let dec = format!(r#"{{"plaintext":"{}"}}"#, STANDARD.encode([5u8; 32]));
        let k = GcpKms::new(
            GCP,
            "ya29.token".into(),
            None,
            Recorder::new(&[(200, &enc), (200, &dec)]),
        )
        .unwrap();
        let s = KmsSealer(k);
        let blob = s.seal(&[5u8; 32]).unwrap();
        assert!(blob.starts_with(format!("kepr-kek1\ngcp-kms\n{GCP}\n").as_bytes()));
        assert_eq!(*s.unseal(&blob).unwrap(), [5u8; 32]);
        let t = &s.0.transport;
        let sent = t.sent();
        assert_eq!(
            sent[0].0,
            format!("https://cloudkms.googleapis.com/v1/{GCP}:encrypt")
        );
        assert_eq!(
            sent[1].0,
            format!("https://cloudkms.googleapis.com/v1/{GCP}:decrypt")
        );
        assert_eq!(t.header(0, "Authorization").unwrap(), "Bearer ya29.token");
        assert_eq!(t.json(0)["plaintext"], STANDARD.encode([5u8; 32]));
        assert_eq!(t.json(1)["ciphertext"], ct);
        for i in 0..2 {
            assert_eq!(
                t.json(i)["additionalAuthenticatedData"],
                STANDARD.encode(GCP_AAD)
            );
        }
    }

    #[test]
    fn azure_wrap_and_unwrap_requests_use_base64url() {
        // Bytes whose base64url differs from standard base64 (`-`, `_`).
        let ct: Vec<u8> = vec![0xfb, 0xff, 0xbf, 0x3e, 0x3f];
        let wrapped = format!(
            r#"{{"kid":"{AZURE}","value":"{}"}}"#,
            URL_SAFE_NO_PAD.encode(&ct)
        );
        let key = [0xfbu8; 32];
        let unwrapped = format!(
            r#"{{"kid":"{AZURE}","value":"{}=="}}"#,
            URL_SAFE_NO_PAD.encode(key)
        );
        let k = AzureKv::new(
            AZURE,
            "eyJ0.tok".into(),
            Recorder::new(&[(200, &wrapped), (200, &unwrapped)]),
        )
        .unwrap();
        assert_eq!(KekSealer::seal(&k, &key).unwrap(), ct);
        assert_eq!(*KekSealer::unseal(&k, &ct).unwrap(), key);
        let t = &k.transport;
        let sent = t.sent();
        assert_eq!(sent[0].0, format!("{AZURE}/wrapkey?api-version=7.4"));
        assert_eq!(sent[1].0, format!("{AZURE}/unwrapkey?api-version=7.4"));
        assert_eq!(t.json(0)["alg"], "RSA-OAEP-256");
        assert_eq!(t.json(1)["alg"], "RSA-OAEP-256");
        let v0 = t.json(0)["value"].as_str().unwrap().to_string();
        assert_eq!(v0, URL_SAFE_NO_PAD.encode(key));
        assert!(v0.contains('_') || v0.contains('-'));
        assert!(!v0.contains('='));
        assert_eq!(t.json(1)["value"], URL_SAFE_NO_PAD.encode(&ct));
        assert_eq!(t.header(1, "Authorization").unwrap(), "Bearer eyJ0.tok");
    }

    #[test]
    fn errors_and_bad_replies() {
        let body = r#"{"error":{"code":"Forbidden","message":"Caller is not authorized"}}"#;
        let k = AzureKv::new(
            AZURE,
            "t".into(),
            Recorder::new(&[(403, body), (200, r#"{"value":"AAAA"}"#)]),
        )
        .unwrap();
        assert_eq!(
            KekSealer::seal(&k, &[0; 32]).unwrap_err(),
            "master-key seal failed (HTTP 403 Forbidden)"
        );
        assert_eq!(KekSealer::unseal(&k, b"x").unwrap_err(), UNSEAL_FAILED);
        let g = GcpKms::new(
            GCP,
            "t".into(),
            None,
            Recorder::new(&[(200, r#"{"plaintext":"!!"}"#)]),
        )
        .unwrap();
        assert_eq!(KekSealer::unseal(&g, b"x").unwrap_err(), UNSEAL_FAILED);
    }

    #[test]
    fn key_references_are_checked() {
        assert!(check_gcp_name(GCP).is_ok());
        for bad in [
            "projects/p/locations/l/keyRings/r",
            "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
            "projects/p?x/locations/l/keyRings/r/cryptoKeys/k",
            "projects/../locations/l/keyRings/r/cryptoKeys/k",
        ] {
            assert!(check_gcp_name(bad).is_err(), "{bad}");
        }
        assert!(check_azure_url(AZURE).is_ok());
        assert!(
            check_azure_url("https://h.managedhsm.azure.net/keys/k/abc").is_err(),
            "name too short"
        );
        for bad in [
            "http://acme-vault.vault.azure.net/keys/k/v1",
            "https://acme-vault.evil.com/keys/k/v1",
            "https://acme-vault.vault.azure.net/keys/k",
            "https://acme-vault.vault.azure.net/secrets/k/v1",
            "https://acme-vault.vault.azure.net/keys/k/v1?x=1",
        ] {
            assert!(check_azure_url(bad).is_err(), "{bad}");
        }
        assert!(GcpKms::new(
            GCP,
            "t".into(),
            Some("http://evil.com/"),
            Recorder::new(&[])
        )
        .is_err());
    }

    #[test]
    fn tokens_come_from_the_environment() {
        if std::env::var_os("GCP_ACCESS_TOKEN").is_none() {
            assert!(GcpKms::from_env(GCP)
                .err()
                .unwrap()
                .contains("GCP_ACCESS_TOKEN"));
        }
        if std::env::var_os("AZURE_ACCESS_TOKEN").is_none() {
            assert!(AzureKv::from_env(AZURE)
                .err()
                .unwrap()
                .contains("AZURE_ACCESS_TOKEN"));
        }
        assert!(GcpKms::from_env("bad")
            .err()
            .unwrap()
            .contains("projects/P"));
    }
}
