// daemon_seal/kms_aws.rs — AWS KMS as the master key's KEK (T4.11).
//
//   KEPR_MASTER_KEY_SEAL=aws-kms:arn:aws:kms:REGION:ACCOUNT:key/ID
//                                (or …:alias/NAME)
//
// Encrypt / Decrypt over the AWS JSON 1.1 protocol (`X-Amz-Target:
// TrentService.Encrypt`), signed with SigV4 (kepr_core::sigv4). Every call
// sends the encryption context {"kepr":"master-key"}, so a ciphertext made
// for anything else won't decrypt as the master key. Credentials come from
// the daemon's environment: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and
// optionally AWS_SESSION_TOKEN (e.g. an EnvironmentFile= in the drop-in).
// The region comes from the ARN; KEPR_KMS_ENDPOINT overrides the endpoint
// (VPC or FIPS endpoints).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::Deserialize;
use zeroize::Zeroizing;

use kepr_core::generate::ZeroString;
use kepr_core::sigv4::{format_amz_date, sign, SigV4Input};

use super::http::{host_and_path, http_error, Headers, Transport, UreqTransport};
use super::kms::{check_ref, key_from_b64, KekSealer};

const SEAL_FAILED: &str = "master-key seal failed";
const UNSEAL_FAILED: &str = "master-key unseal failed";

pub struct AwsCreds {
    pub access_key: String,
    pub secret_key: ZeroString,
    pub session_token: Option<String>,
}

impl AwsCreds {
    pub fn from_env() -> Result<Self, String> {
        let var = |n: &str| std::env::var(n).ok().filter(|v| !v.is_empty());
        let missing = |n: &str| format!("aws-kms sealing needs {n} in the daemon's environment");
        Ok(Self {
            access_key: var("AWS_ACCESS_KEY_ID").ok_or_else(|| missing("AWS_ACCESS_KEY_ID"))?,
            secret_key: ZeroString::from_string(
                var("AWS_SECRET_ACCESS_KEY").ok_or_else(|| missing("AWS_SECRET_ACCESS_KEY"))?,
            ),
            session_token: var("AWS_SESSION_TOKEN"),
        })
    }
}

/// `(partition, region)` of a KMS key or alias ARN.
pub fn parse_arn(arn: &str) -> Result<(String, String), String> {
    let bad = || format!("KEPR_MASTER_KEY_SEAL=aws-kms:{arn}: not a KMS key ARN");
    check_ref("aws-kms", arn).map_err(|_| bad())?;
    let p: Vec<&str> = arn.splitn(6, ':').collect();
    if p.len() != 6 || p[0] != "arn" || p[2] != "kms" {
        return Err(bad());
    }
    let name = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    let account = p[4].len() == 12 && p[4].bytes().all(|b| b.is_ascii_digit());
    let resource = match p[5].split_once('/') {
        Some(("key" | "alias", id)) => {
            !id.is_empty()
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'/'))
        }
        _ => false,
    };
    if !name(p[1]) || !name(p[3]) || !account || !resource {
        return Err(bad());
    }
    Ok((p[1].to_string(), p[3].to_string()))
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub struct AwsKms<T: Transport> {
    arn: String,
    region: String,
    endpoint: String,
    creds: AwsCreds,
    transport: T,
    clock: fn() -> u64,
}

impl AwsKms<UreqTransport> {
    pub fn from_env(arn: &str) -> Result<Self, String> {
        parse_arn(arn)?;
        let endpoint = std::env::var("KEPR_KMS_ENDPOINT")
            .ok()
            .filter(|e| !e.is_empty());
        Self::new(
            arn,
            AwsCreds::from_env()?,
            endpoint.as_deref(),
            UreqTransport,
        )
    }
}

impl<T: Transport> AwsKms<T> {
    pub fn new(
        arn: &str,
        creds: AwsCreds,
        endpoint: Option<&str>,
        transport: T,
    ) -> Result<Self, String> {
        let (partition, region) = parse_arn(arn)?;
        let endpoint = match (endpoint, partition.as_str()) {
            (Some(e), _) => e.to_string(),
            (None, "aws" | "aws-us-gov") => format!("https://kms.{region}.amazonaws.com/"),
            (None, "aws-cn") => format!("https://kms.{region}.amazonaws.com.cn/"),
            (None, p) => return Err(format!("aws-kms: set KEPR_KMS_ENDPOINT for partition {p}")),
        };
        host_and_path(&endpoint)?;
        Ok(Self {
            arn: arn.to_string(),
            region,
            endpoint,
            creds,
            transport,
            clock: now,
        })
    }

    /// One signed KMS call; the reply body on HTTP 200.
    fn call(&self, op: &str, body: &[u8], failed: &str) -> Result<Zeroizing<String>, String> {
        let (host, path) = host_and_path(&self.endpoint)?;
        let target = format!("TrentService.{op}");
        let amz_date = format_amz_date((self.clock)());
        let signed = sign(&SigV4Input {
            access_key: &self.creds.access_key,
            secret_key: &self.creds.secret_key,
            region: &self.region,
            service: "kms",
            session_token: self.creds.session_token.as_deref(),
            method: "POST",
            host: &host,
            path: &path,
            query: "",
            amz_target: &target,
            body,
            amz_date: &amz_date,
        });
        let mut headers: Headers =
            vec![("Content-Type".into(), "application/x-amz-json-1.1".into())];
        headers.extend(signed.headers);
        let (status, reply) = self
            .transport
            .post(&self.endpoint, &headers, body)
            .map_err(|e| format!("{failed}: {e}"))?;
        if status != 200 {
            return Err(http_error(failed, status, &reply));
        }
        Ok(reply)
    }
}

#[derive(Deserialize)]
struct EncryptOut {
    #[serde(rename = "CiphertextBlob")]
    blob: String,
}

#[derive(Deserialize)]
struct DecryptOut {
    #[serde(rename = "Plaintext")]
    plaintext: ZeroString,
}

/// `{"kepr":"master-key"}` on every call.
const CONTEXT: &str = r#""EncryptionContext":{"kepr":"master-key"}"#;

impl<T: Transport> KekSealer for AwsKms<T> {
    fn kind(&self) -> &'static str {
        "aws-kms"
    }

    fn key_ref(&self) -> &str {
        &self.arn
    }

    fn seal(&self, key: &[u8; 32]) -> Result<Vec<u8>, String> {
        let arn = serde_json::to_string(&self.arn).map_err(|_| SEAL_FAILED)?;
        let plaintext = Zeroizing::new(B64.encode(key));
        let body = Zeroizing::new(format!(
            r#"{{"KeyId":{arn},"Plaintext":"{}",{CONTEXT}}}"#,
            plaintext.as_str()
        ));
        let reply = self.call("Encrypt", body.as_bytes(), SEAL_FAILED)?;
        let out: EncryptOut = serde_json::from_str(&reply).map_err(|_| SEAL_FAILED)?;
        B64.decode(out.blob).map_err(|_| SEAL_FAILED.to_string())
    }

    fn unseal(&self, ciphertext: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
        let arn = serde_json::to_string(&self.arn).map_err(|_| UNSEAL_FAILED)?;
        let body = format!(
            r#"{{"KeyId":{arn},"CiphertextBlob":"{}",{CONTEXT}}}"#,
            B64.encode(ciphertext)
        );
        let reply = self.call("Decrypt", body.as_bytes(), UNSEAL_FAILED)?;
        let out: DecryptOut = serde_json::from_str(&reply).map_err(|_| UNSEAL_FAILED)?;
        key_from_b64(out.plaintext.as_str(), &B64, UNSEAL_FAILED)
    }
}

#[cfg(test)]
mod tests {
    use super::super::http::fake::{loopback, Recorder};
    use super::super::kms::KmsSealer;
    use super::*;
    use crate::master_key::Sealer;

    const ARN: &str = "arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";

    fn creds() -> AwsCreds {
        AwsCreds {
            access_key: "AKIDEXAMPLE".into(),
            secret_key: ZeroString::from("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"),
            session_token: None,
        }
    }

    fn kms<T: Transport>(t: T, endpoint: Option<&str>) -> AwsKms<T> {
        let mut k = AwsKms::new(ARN, creds(), endpoint, t).unwrap();
        k.clock = || 1_790_000_000;
        k
    }

    #[test]
    fn encrypt_and_decrypt_use_the_json_1_1_shape() {
        let ct = B64.encode(b"opaque-ciphertext");
        let pt = B64.encode([7u8; 32]);
        let enc = format!(
            r#"{{"CiphertextBlob":"{ct}","KeyId":"{ARN}","EncryptionAlgorithm":"SYMMETRIC_DEFAULT"}}"#
        );
        let dec = format!(r#"{{"Plaintext":"{pt}","KeyId":"{ARN}"}}"#);
        let k = kms(Recorder::new(&[(200, &enc), (200, &dec)]), None);
        assert_eq!(
            KekSealer::seal(&k, &[7u8; 32]).unwrap(),
            b"opaque-ciphertext"
        );
        assert_eq!(
            *KekSealer::unseal(&k, b"opaque-ciphertext").unwrap(),
            [7u8; 32]
        );
        let t = &k.transport;
        assert_eq!(t.sent()[0].0, "https://kms.eu-west-1.amazonaws.com/");
        for (i, op) in [(0, "Encrypt"), (1, "Decrypt")] {
            assert_eq!(
                t.header(i, "X-Amz-Target").unwrap(),
                format!("TrentService.{op}")
            );
            assert_eq!(
                t.header(i, "Content-Type").unwrap(),
                "application/x-amz-json-1.1"
            );
            let auth = t.header(i, "Authorization").unwrap();
            assert!(
                auth.starts_with(
                    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260921/eu-west-1/kms/aws4_request"
                ),
                "{auth}"
            );
            assert_eq!(t.header(i, "Host").unwrap(), "kms.eu-west-1.amazonaws.com");
            let body = t.json(i);
            assert_eq!(body["KeyId"], ARN);
            assert_eq!(
                body["EncryptionContext"],
                serde_json::json!({"kepr": "master-key"})
            );
        }
        assert_eq!(t.json(0)["Plaintext"], B64.encode([7u8; 32]));
        assert_eq!(t.json(1)["CiphertextBlob"], ct);
        // The secret key never travels; only its signature does.
        assert!(t.sent().iter().all(|(_, h, b)| {
            !String::from_utf8_lossy(b).contains("wJalr")
                && h.iter().all(|(_, v)| !v.contains("wJalr"))
        }));
    }

    #[test]
    fn errors_carry_status_and_code_only() {
        let body = r#"{"__type":"AccessDeniedException","message":"User: arn:aws:iam::1:user/x is not authorized"}"#;
        let k = kms(
            Recorder::new(&[(400, body), (200, "{}"), (200, r#"{"Plaintext":"AAAA"}"#)]),
            None,
        );
        let e = KekSealer::seal(&k, &[1u8; 32]).unwrap_err();
        assert_eq!(e, "master-key seal failed (HTTP 400 AccessDeniedException)");
        assert_eq!(KekSealer::seal(&k, &[1u8; 32]).unwrap_err(), SEAL_FAILED);
        assert_eq!(KekSealer::unseal(&k, b"x").unwrap_err(), UNSEAL_FAILED);
        assert!(KekSealer::unseal(&k, b"x")
            .unwrap_err()
            .contains("no reply"));
    }

    #[test]
    fn arns_are_checked_and_pick_the_endpoint() {
        assert_eq!(parse_arn(ARN).unwrap(), ("aws".into(), "eu-west-1".into()));
        let alias = "arn:aws:kms:us-east-1:111122223333:alias/kepr/master";
        assert!(parse_arn(alias).is_ok());
        for bad in [
            "arn:aws:s3:eu-west-1:111122223333:key/x",
            "arn:aws:kms:eu-west-1:1111:key/x",
            "arn:aws:kms:eu-west-1:111122223333:secret/x",
            "arn:aws:kms:eu-west-1@evil.com:111122223333:key/x",
            "arn:aws:kms:EU:111122223333:key/x",
            "key/x",
        ] {
            assert!(parse_arn(bad).is_err(), "{bad}");
        }
        let cn = "arn:aws-cn:kms:cn-north-1:111122223333:key/x";
        let k = AwsKms::new(cn, creds(), None, Recorder::new(&[])).unwrap();
        assert_eq!(k.endpoint, "https://kms.cn-north-1.amazonaws.com.cn/");
        let iso = "arn:aws-iso:kms:us-iso-east-1:111122223333:key/x";
        assert!(AwsKms::new(iso, creds(), None, Recorder::new(&[])).is_err());
        assert!(AwsKms::new(
            ARN,
            creds(),
            Some("http://kms.example.com/"),
            Recorder::new(&[])
        )
        .is_err());
    }

    #[test]
    fn round_trips_through_a_loopback_kms() {
        // A fake KMS: Encrypt returns the plaintext reversed, Decrypt
        // reverses it back; it checks the context on both.
        let (url, seen) = loopback(2, |head, body| {
            let v: serde_json::Value = serde_json::from_slice(body).unwrap();
            assert_eq!(v["EncryptionContext"]["kepr"], "master-key");
            let flip = |s: &str| {
                let mut b = B64.decode(s).unwrap();
                b.reverse();
                B64.encode(b)
            };
            if head.contains("TrentService.Encrypt") {
                (
                    200,
                    format!(
                        r#"{{"CiphertextBlob":"{}"}}"#,
                        flip(v["Plaintext"].as_str().unwrap())
                    ),
                )
            } else {
                (
                    200,
                    format!(
                        r#"{{"Plaintext":"{}"}}"#,
                        flip(v["CiphertextBlob"].as_str().unwrap())
                    ),
                )
            }
        });
        let sealer = KmsSealer(kms(UreqTransport, Some(&url)));
        let mut key = [0u8; 32];
        key.iter_mut().enumerate().for_each(|(i, b)| *b = i as u8);
        let blob = sealer.seal(&key).unwrap();
        assert!(blob.starts_with(format!("kepr-kek1\naws-kms\n{ARN}\n").as_bytes()));
        assert_eq!(*sealer.unseal(&blob).unwrap(), key);
        let (head, _) = seen.recv().unwrap();
        assert!(
            head.to_ascii_lowercase()
                .contains("x-amz-target: trentservice.encrypt"),
            "{head}"
        );
    }

    #[test]
    fn credentials_come_from_the_environment() {
        if std::env::var_os("AWS_ACCESS_KEY_ID").is_none() {
            let e = AwsKms::from_env(ARN).err().unwrap();
            assert!(e.contains("AWS_ACCESS_KEY_ID"), "{e}");
        }
    }
}
