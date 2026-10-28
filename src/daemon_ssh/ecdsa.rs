// daemon_ssh/ecdsa.rs — ECDSA P-256 for sign-only SSH keys (T12.11):
// `ecdsa-sha2-nistp256` signs SHA-256 of the data; the nonce is RFC 6979
// deterministic. The scalar is only borrowed here (the caller holds it
// in a Zeroizing buffer, and p256's SigningKey wipes itself on drop).

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};

fn key(scalar: &[u8; 32]) -> Result<SigningKey, String> {
    SigningKey::from_slice(scalar).map_err(|_| "stored key is malformed".to_string())
}

/// The uncompressed public point `0x04 ‖ x ‖ y` of `scalar`.
pub fn public_q(scalar: &[u8; 32]) -> Result<[u8; 65], String> {
    let point = key(scalar)?.verifying_key().to_sec1_point(false);
    point
        .as_bytes()
        .try_into()
        .map_err(|_| "stored key is malformed".to_string())
}

/// (r, s) of an ECDSA-SHA256 signature over `data`.
pub fn sign(scalar: &[u8; 32], data: &[u8]) -> Result<([u8; 32], [u8; 32]), String> {
    let sig: Signature = key(scalar)?.sign(data);
    let (r, s) = sig.split_bytes();
    Ok((r.into(), s.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_store::testkit;
    use kepr_core::generate::ZeroString;
    use kepr_core::protocol::{Request, Response};
    use kepr_core::ssh_wire::{self, put_string};
    use kepr_core::ssh_wire_ecdsa as wire;
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::VerifyingKey;

    /// `ssh-keygen -t ecdsa -b 256 -N '' -C fixture@kepr`, test-only (also
    /// used by kepr-core's ssh_wire_ecdsa tests).
    const FIXTURE_B64: &str = include_str!("testdata/ecdsa-p256-test-only.b64");
    const FIXTURE_PUB: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzd\
        HAyNTYAAABBBOMNoAg49EaERM72g2AhPFDX2DoGcFAWQLENAmYrxBatdOfAXh5yBrhspI4XCb1tvy5E31k+BVIzbf0Eaq1ZPJo= fixture@kepr";
    /// `ssh-keygen -Y sign -f fixture -n file` of "kepr ecdsa vector".
    const FIXTURE_SSHSIG: &str =
        "U1NIU0lHAAAAAQAAAGgAAAATZWNkc2Etc2hhMi1uaXN0cDI1NgAAAAhuaXN0cDI1NgAAAE\
        EE4w2gCDj0RoREzvaDYCE8UNfYOgZwUBZAsQ0CZivEFq1058BeHnIGuGykjhcJvW2/LkTf\
        WT4FUjNt/QRqrVk8mgAAAARmaWxlAAAAAAAAAAZzaGE1MTIAAABkAAAAE2VjZHNhLXNoYT\
        ItbmlzdHAyNTYAAABJAAAAIQCGa/wAUdqmBXCvenUNVWWgQ/9Q6FdjuGazLqpeVQJcxgAA\
        ACA/QVumj+K4tbtdltA9oO+Ch1ZX3+KmcRfcH3EHci09aQ==";

    fn arr<const N: usize>(h: &str) -> [u8; N] {
        hex::decode(h).unwrap().try_into().unwrap()
    }

    fn pem(b64: &str) -> ZeroString {
        let label = "OPENSSH PRIVATE KEY";
        ZeroString::from_string(format!(
            "-----BEGIN {label}-----\n{b64}\n-----END {label}-----\n"
        ))
    }

    fn ssh(uid: u32, req: Request) -> Response {
        super::super::dispatch(uid, 0, "t", req)
    }

    fn generate(uid: u32, name: &str, key_type: Option<&str>) -> Response {
        ssh(
            uid,
            Request::SshGenerate {
                name: name.into(),
                comment: "c".into(),
                requires_consent: None,
                key_type: key_type.map(str::to_string),
            },
        )
    }

    fn sign_with(uid: u32, name: &str, data: &[u8]) -> Vec<u8> {
        let req = Request::SshSign {
            name: name.into(),
            data_b64: ssh_wire::b64(data),
        };
        match ssh(uid, req) {
            Response::SshSignOk { signature_b64 } => ssh_wire::unb64(&signature_b64).unwrap(),
            other => panic!("{other:?}"),
        }
    }

    fn stored_public(uid: u32, name: &str) -> Vec<u8> {
        ssh_wire::unb64(&testkit::meta(uid, name).ssh.unwrap().public_b64).unwrap()
    }

    /// Q from an `ecdsa-sha2-nistp256` public blob.
    fn blob_q(blob: &[u8]) -> Vec<u8> {
        let mut b = blob;
        assert_eq!(
            ssh_wire::take_string(&mut b),
            Some(wire::ECDSA_P256.as_bytes())
        );
        assert_eq!(ssh_wire::take_string(&mut b), Some(&b"nistp256"[..]));
        ssh_wire::take_string(&mut b).unwrap().to_vec()
    }

    /// What `ssh-keygen -Y` signs for `msg` in namespace "file".
    fn sshsig_signed_data(msg: &[u8]) -> Vec<u8> {
        use sha2::Digest;
        let mut d = b"SSHSIG".to_vec();
        put_string(&mut d, b"file");
        put_string(&mut d, b"");
        put_string(&mut d, b"sha512");
        put_string(&mut d, &sha2::Sha512::digest(msg));
        d
    }

    #[test]
    fn rfc6979_p256_sha256_vector() {
        // RFC 6979 A.2.5, message "sample".
        let x = arr::<32>("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
        let q = public_q(&x).unwrap();
        assert_eq!(
            hex::encode(q),
            "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6\
             7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"
        );
        let (r, s) = sign(&x, b"sample").unwrap();
        assert_eq!(
            hex::encode(r),
            "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
        );
        assert_eq!(
            hex::encode(s),
            "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
        );
        assert!(public_q(&[0; 32]).is_err(), "zero is not a scalar");
        assert!(sign(&[0xff; 32], b"x").is_err(), "nor is anything >= n");
    }

    #[test]
    fn ssh_keygens_signature_verifies_against_the_fixture_key() {
        // Pins the (r, s) order and mpint form to OpenSSH's own output.
        let raw = ssh_wire::unb64(FIXTURE_SSHSIG).unwrap();
        let mut b = raw.strip_prefix(b"SSHSIG").unwrap();
        assert_eq!(ssh_wire::take_u32(&mut b), Some(1));
        let public = ssh_wire::take_string(&mut b).unwrap();
        for _ in 0..3 {
            ssh_wire::take_string(&mut b).unwrap(); // namespace, reserved, hash
        }
        let blob = ssh_wire::take_string(&mut b).unwrap();
        let (r, s) = wire::parse_signature_blob(blob).unwrap();
        let vk = VerifyingKey::from_sec1_bytes(&blob_q(public)).unwrap();
        let sig = Signature::from_scalars(r, s).unwrap();
        let signed = sshsig_signed_data(b"kepr ecdsa vector");
        assert!(vk.verify(&signed, &sig).is_ok());
        assert!(vk.verify(b"other data", &sig).is_err());
    }

    #[test]
    fn signature_blob_verifies_with_the_stored_public_key() {
        let uid = testkit::uid();
        match generate(uid, "SE_KEY", Some("ecdsa")) {
            Response::SshKeyOk { public_line, .. } => {
                assert!(public_line.starts_with("ecdsa-sha2-nistp256 AAAAE2VjZHNh"));
                assert!(public_line.ends_with(" c"));
            }
            other => panic!("{other:?}"),
        }
        let public = stored_public(uid, "SE_KEY");
        assert_eq!(wire::blob_type(&public), Some(wire::ECDSA_P256));
        let blob = sign_with(uid, "SE_KEY", b"data");
        assert_eq!(wire::blob_type(&blob), Some(wire::ECDSA_P256));
        let (r, s) = wire::parse_signature_blob(&blob).unwrap();
        let vk = VerifyingKey::from_sec1_bytes(&blob_q(&public)).unwrap();
        let sig = Signature::from_scalars(r, s).unwrap();
        assert!(vk.verify(b"data", &sig).is_ok());
        assert!(vk.verify(b"datb", &sig).is_err());
    }

    #[test]
    fn get_refuses_an_ecdsa_key_like_any_ssh_key() {
        let uid = testkit::uid();
        assert!(matches!(
            generate(uid, "SE_GET", Some("ecdsa")),
            Response::SshKeyOk { .. }
        ));
        let r = crate::daemon_handlers_get::handle_get(uid, 0, "t", "SE_GET", None);
        assert_eq!(r.err_msg(), Some("credential unavailable"));
        assert_eq!(testkit::meta(uid, "SE_GET").gated(), Some("ssh"));
    }

    #[test]
    fn unknown_key_types_are_refused() {
        let uid = testkit::uid();
        for t in ["rsa", "ECDSA", "ecdsa-sha2-nistp384", ""] {
            let r = generate(uid, "SE_BAD", Some(t));
            assert_eq!(r.err_msg(), Some("unknown key type"), "{t}");
        }
        assert!(!crate::store::cred_exists(uid, "SE_BAD"));
        assert!(matches!(
            generate(uid, "SE_ED", Some("ed25519")),
            Response::SshKeyOk { .. }
        ));
        let blob = stored_public(uid, "SE_ED");
        assert_eq!(wire::blob_type(&blob), Some(ssh_wire::ED25519));
    }

    #[test]
    fn an_existing_ed25519_meta_still_signs() {
        // A key stored before T12.11: the seed, and a meta with the
        // Ed25519 public blob (no new field).
        use ed25519_dalek::{Signature as EdSig, Verifier as _};
        let uid = testkit::uid();
        let seed = [7u8; 32];
        let pk = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
        let flags = crate::daemon_handlers::SetFlags {
            ssh: Some(crate::expiry::SshMeta {
                public_b64: ssh_wire::b64(&ssh_wire::ed25519_public_blob(&pk.to_bytes())),
                comment: "old".into(),
            }),
            ..Default::default()
        };
        let value = ssh_wire::b64(&seed);
        let r = crate::daemon_handlers::handle_set(uid, "t", "SE_OLD", Some(&value), None, flags);
        assert!(r.is_success(), "{r:?}");
        let blob = sign_with(uid, "SE_OLD", b"data");
        let mut b: &[u8] = &blob;
        assert_eq!(ssh_wire::take_string(&mut b), Some(&b"ssh-ed25519"[..]));
        let raw: [u8; 64] = ssh_wire::take_string(&mut b).unwrap().try_into().unwrap();
        assert!(pk.verify(b"data", &EdSig::from_bytes(&raw)).is_ok());
    }

    #[test]
    fn imports_the_ssh_keygen_fixture() {
        let uid = testkit::uid();
        let req = Request::SshImport {
            name: "SE_IMP".into(),
            private_key: pem(FIXTURE_B64),
            requires_consent: None,
        };
        match ssh(uid, req) {
            Response::SshKeyOk { public_line, .. } => assert_eq!(public_line, FIXTURE_PUB),
            other => panic!("{other:?}"),
        }
        let blob = sign_with(uid, "SE_IMP", b"data");
        let (r, s) = wire::parse_signature_blob(&blob).unwrap();
        let vk = VerifyingKey::from_sec1_bytes(&blob_q(&stored_public(uid, "SE_IMP"))).unwrap();
        assert!(vk
            .verify(b"data", &Signature::from_scalars(r, s).unwrap())
            .is_ok());
    }

    #[test]
    fn an_import_whose_point_is_not_the_scalars_is_refused() {
        // Swap Q for another valid point (RFC 6979's) in both the public
        // and private sections, so only the daemon's point check can
        // notice.
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;
        let mut raw = b64.decode(FIXTURE_B64.replace('\n', "")).unwrap();
        let fixture_q = blob_q(&ssh_wire::unb64(FIXTURE_PUB.split(' ').nth(1).unwrap()).unwrap());
        let other = public_q(&arr::<32>(
            "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
        ))
        .unwrap();
        let mut swapped = 0;
        while let Some(p) = raw.windows(65).position(|w| w == fixture_q.as_slice()) {
            raw[p..p + 65].copy_from_slice(&other);
            swapped += 1;
        }
        assert_eq!(swapped, 2);
        let uid = testkit::uid();
        let req = Request::SshImport {
            name: "SE_MISMATCH".into(),
            private_key: pem(&b64.encode(&raw)),
            requires_consent: None,
        };
        let r = ssh(uid, req);
        assert_eq!(
            r.err_msg(),
            Some("malformed OpenSSH key: the public key does not match")
        );
        assert!(!crate::store::cred_exists(uid, "SE_MISMATCH"));
    }

    fn on_path(tool: &str) -> Option<std::path::PathBuf> {
        let path = std::env::var_os("PATH")?;
        std::env::split_paths(&path)
            .map(|d| d.join(tool))
            .find(|p| p.is_file())
    }

    #[test]
    fn ssh_keygen_verifies_an_ecdsa_signature() {
        let Some(keygen) = on_path("ssh-keygen") else {
            eprintln!("SKIP: ssh-keygen is not on PATH");
            return;
        };
        let uid = testkit::uid();
        let line = match generate(uid, "SE_Y", Some("ecdsa")) {
            Response::SshKeyOk { public_line, .. } => public_line,
            other => panic!("{other:?}"),
        };
        let msg = b"kepr: ssh-keygen -Y verify\n";
        let blob = sign_with(uid, "SE_Y", &sshsig_signed_data(msg));
        let mut sig = b"SSHSIG".to_vec();
        sig.extend_from_slice(&1u32.to_be_bytes());
        put_string(&mut sig, &stored_public(uid, "SE_Y"));
        put_string(&mut sig, b"file");
        put_string(&mut sig, b"");
        put_string(&mut sig, b"sha512");
        put_string(&mut sig, &blob);
        let armored = format!(
            "-----BEGIN SSH SIGNATURE-----\n{}\n-----END SSH SIGNATURE-----\n",
            ssh_wire::b64(&sig)
        );
        let dir = std::env::temp_dir().join(format!("kepr-sshsig-{}-{uid}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("allowed"), format!("kepr@test {line}\n")).unwrap();
        std::fs::write(dir.join("msg.sig"), armored).unwrap();
        std::fs::write(dir.join("msg"), msg).unwrap();
        let verify = |file: &str| {
            std::process::Command::new(&keygen)
                .args(["-Y", "verify", "-I", "kepr@test", "-n", "file", "-f"])
                .arg(dir.join("allowed"))
                .arg("-s")
                .arg(dir.join("msg.sig"))
                .stdin(std::fs::File::open(dir.join(file)).unwrap())
                .output()
                .unwrap()
        };
        let ok = verify("msg");
        assert!(
            ok.status.success(),
            "{}",
            String::from_utf8_lossy(&ok.stderr)
        );
        std::fs::write(dir.join("other"), b"tampered").unwrap();
        assert!(!verify("other").status.success());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
