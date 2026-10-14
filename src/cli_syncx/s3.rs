// cli_syncx/s3.rs — T6.10 `s3:BUCKET[/PREFIX]` sync remote: ListObjectsV2,
// GetObject and PutObject, signed with SigV4 (kepr_core::sigv4_req).
//
// Credentials come from AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY
// (+ AWS_SESSION_TOKEN), the region from AWS_REGION or AWS_DEFAULT_REGION.
// KEPR_S3_ENDPOINT (https://host[:port], or http:// on loopback) points at
// an S3-compatible server instead, path-style. Error text carries the
// status and S3's Code / Message only.

use std::io::Read;

use kepr_core::generate::ZeroString;
use kepr_core::protocol_syncx::MAX_BUNDLE_BYTES;
use kepr_core::sigv4::{format_amz_date, hex_sha256};
use kepr_core::sigv4_req::{
    authorization, aws_encode, canonical_query, signature, valid_region, AwsKey, Canonical, Scope,
};

use super::transport::{bundle_name, Remote};
use crate::cli_aws::sts::{error_summary, now_secs, xml_text};

const MAX_PAGES: usize = 20;

pub struct S3 {
    key: AwsKey,
    region: String,
    /// `scheme://host[:port]` dialled, and the host signed.
    base: String,
    host: String,
    /// Path of the bucket's root: `""` (virtual-hosted) or `/BUCKET`.
    root: String,
    prefix: String,
}

impl S3 {
    /// `BUCKET[/PREFIX]` → `(bucket, prefix)`.
    pub fn parse(spec: &str) -> Result<(String, String), String> {
        let (bucket, prefix) = spec.split_once('/').unwrap_or((spec, ""));
        let edge = |b: Option<&u8>| b.is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
        let bucket_ok = (3..=63).contains(&bucket.len())
            && bucket
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'.' || c == b'-')
            && edge(bucket.as_bytes().first())
            && edge(bucket.as_bytes().last());
        if !bucket_ok {
            return Err(format!("s3:{spec}: {bucket:?} is not a bucket name"));
        }
        let prefix = prefix.trim_matches('/');
        let prefix_ok = prefix.len() <= 512
            && prefix.split('/').all(|seg| seg != ".." && seg != ".")
            && prefix
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._/-".contains(&c));
        if !prefix_ok {
            return Err(format!(
                "s3:{spec}: the prefix may hold A-Z a-z 0-9 . _ / - only"
            ));
        }
        Ok((bucket.to_string(), prefix.to_string()))
    }

    pub fn new(
        spec: &str,
        key: AwsKey,
        region: &str,
        endpoint: Option<&str>,
    ) -> Result<Self, String> {
        let (bucket, prefix) = Self::parse(spec)?;
        if !valid_region(region) {
            return Err(format!("AWS_REGION {region:?} is not a region name"));
        }
        let (base, host, root) = match endpoint {
            Some(e) => {
                let host = e
                    .strip_prefix("https://")
                    .or_else(|| {
                        e.strip_prefix("http://")
                            .filter(|h| h.starts_with("127.0.0.1:") || h.starts_with("localhost:"))
                    })
                    .filter(|h| !h.is_empty() && !h.contains(['/', '@', '?', '#']))
                    .ok_or(
                        "KEPR_S3_ENDPOINT must be https://HOST[:PORT] (http:// only on loopback)",
                    )?;
                (e.to_string(), host.to_string(), format!("/{bucket}"))
            }
            None if bucket.contains('.') => {
                let host = format!("s3.{region}.amazonaws.com");
                (format!("https://{host}"), host, format!("/{bucket}"))
            }
            None => {
                let host = format!("{bucket}.s3.{region}.amazonaws.com");
                (format!("https://{host}"), host, String::new())
            }
        };
        Ok(Self {
            key,
            region: region.to_string(),
            base,
            host,
            root,
            prefix,
        })
    }

    pub fn from_env(spec: &str) -> Result<Self, String> {
        let var = |n: &str| std::env::var(n).ok().filter(|v| !v.is_empty());
        let key = AwsKey {
            access_key_id: var("AWS_ACCESS_KEY_ID").ok_or("AWS_ACCESS_KEY_ID not set")?,
            secret_access_key: ZeroString::from_string(
                var("AWS_SECRET_ACCESS_KEY").ok_or("AWS_SECRET_ACCESS_KEY not set")?,
            ),
            session_token: var("AWS_SESSION_TOKEN").map(ZeroString::from_string),
        };
        let region = var("AWS_REGION")
            .or_else(|| var("AWS_DEFAULT_REGION"))
            .ok_or("AWS_REGION (or AWS_DEFAULT_REGION) not set")?;
        Self::new(spec, key, &region, var("KEPR_S3_ENDPOINT").as_deref())
    }

    fn object_path(&self, name: &str) -> String {
        match self.prefix.as_str() {
            "" => format!("{}/{name}", self.root),
            p => format!("{}/{p}/{name}", self.root),
        }
    }

    /// One signed request: `(status, body)` (the body capped at the
    /// bundle limit).
    fn send(
        &self,
        method: &str,
        path: &str,
        query: &str,
        body: &[u8],
    ) -> Result<(u16, Vec<u8>), String> {
        let amz_date = format_amz_date(now_secs());
        let hash = hex_sha256(body);
        let mut headers = vec![
            ("host".to_string(), self.host.clone()),
            ("x-amz-content-sha256".to_string(), hash.clone()),
            ("x-amz-date".to_string(), amz_date.clone()),
        ];
        if let Some(t) = &self.key.session_token {
            headers.push(("x-amz-security-token".into(), t.as_str().to_string()));
        }
        let path = if path.is_empty() { "/" } else { path };
        let (text, signed) = Canonical {
            method,
            uri: path,
            query,
            headers: &headers,
            payload_hash: &hash,
        }
        .build();
        let scope = Scope {
            date: amz_date[..8].to_string(),
            region: self.region.clone(),
            service: "s3".into(),
        };
        let sig = signature(
            self.key.secret_access_key.as_str(),
            &amz_date,
            &scope,
            &text,
        );
        headers.retain(|(n, _)| n != "host");
        headers.push((
            "authorization".into(),
            authorization(&self.key.access_key_id, &scope, &signed, &sig),
        ));
        let url = match query {
            "" => format!("{}{path}", self.base),
            q => format!("{}{path}?{q}", self.base),
        };
        let mut req = crate::sync_http::agent().request(method, &url);
        for (n, v) in &headers {
            req = req.set(n, v);
        }
        let r = match method {
            "PUT" => req.send_bytes(body),
            _ => req.call(),
        };
        let r = match r {
            Ok(r) | Err(ureq::Error::Status(_, r)) => r,
            Err(e) => return Err(format!("s3: {e}")),
        };
        let status = r.status();
        let mut out = Vec::new();
        r.into_reader()
            .take(MAX_BUNDLE_BYTES as u64 + 1)
            .read_to_end(&mut out)
            .map_err(|e| format!("s3: {e}"))?;
        Ok((status, out))
    }

    fn ok(&self, what: &str, (status, body): (u16, Vec<u8>)) -> Result<Vec<u8>, String> {
        if (200..300).contains(&status) {
            return Ok(body);
        }
        let why = error_summary(&String::from_utf8_lossy(&body));
        Err(format!("s3 {what}: HTTP {status} {why}"))
    }
}

impl Remote for S3 {
    fn list(&self) -> Result<Vec<String>, String> {
        let dir = match self.prefix.as_str() {
            "" => String::new(),
            p => format!("{p}/"),
        };
        let (mut out, mut token) = (Vec::new(), None::<String>);
        for _ in 0..MAX_PAGES {
            let mut raw = format!("list-type=2&prefix={}", aws_encode(&dir, false));
            if let Some(t) = &token {
                raw.push_str(&format!("&continuation-token={}", aws_encode(t, false)));
            }
            let root = format!("{}/", self.root);
            let xml = self.ok(
                "list",
                self.send("GET", &root, &canonical_query(&raw), b"")?,
            )?;
            let xml = String::from_utf8_lossy(&xml).into_owned();
            for part in xml.split("<Key>").skip(1) {
                let key = xml_text(&format!("<Key>{part}"), "Key").unwrap_or_default();
                if let Some(name) = key.strip_prefix(&dir).filter(|n| bundle_name(n)) {
                    out.push(name.to_string());
                }
            }
            token = xml_text(&xml, "NextContinuationToken");
            if xml_text(&xml, "IsTruncated").as_deref() != Some("true") || token.is_none() {
                out.sort();
                return Ok(out);
            }
        }
        Err("s3 list: too many pages".into())
    }

    fn get(&self, name: &str) -> Result<Vec<u8>, String> {
        let body = self.ok("get", self.send("GET", &self.object_path(name), "", b"")?)?;
        if body.len() > MAX_BUNDLE_BYTES {
            return Err(format!("s3 get {name}: over 16 MiB"));
        }
        Ok(body)
    }

    fn put(&mut self, name: &str, bytes: &[u8]) -> Result<(), String> {
        self.ok("put", self.send("PUT", &self.object_path(name), "", bytes)?)
            .map(drop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli_syncx::testserver::serve;
    use kepr_core::sigv4_req::signature_matches;

    fn key() -> AwsKey {
        AwsKey {
            access_key_id: "AKIDEXAMPLEEXAMPLE".into(),
            secret_access_key: ZeroString::from("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"),
            session_token: None,
        }
    }

    /// Check a captured request's signature the way S3 would.
    fn verify(raw: &str, body: &[u8]) {
        let mut lines = raw.split("\r\n");
        let first: Vec<&str> = lines.next().unwrap().split(' ').collect();
        let (path, query) = first[1].split_once('?').unwrap_or((first[1], ""));
        let header = |n: &str| {
            raw.split("\r\n")
                .find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case(n)))
                .map(|(_, v)| v.trim().to_string())
                .unwrap_or_default()
        };
        let auth = header("authorization");
        let sig = auth.rsplit("Signature=").next().unwrap();
        let date = header("x-amz-date");
        assert_eq!(header("x-amz-content-sha256"), hex_sha256(body));
        let headers = vec![
            ("host".to_string(), header("host")),
            (
                "x-amz-content-sha256".to_string(),
                header("x-amz-content-sha256"),
            ),
            ("x-amz-date".to_string(), date.clone()),
        ];
        let (text, _) = Canonical {
            method: first[0],
            uri: path,
            query,
            headers: &headers,
            payload_hash: &hex_sha256(body),
        }
        .build();
        let scope = Scope {
            date: date[..8].to_string(),
            region: "eu-west-1".into(),
            service: "s3".into(),
        };
        assert!(auth.contains("Credential=AKIDEXAMPLEEXAMPLE/"), "{auth}");
        assert!(
            signature_matches(key().secret_access_key.as_str(), &date, &scope, &text, sig),
            "{raw}"
        );
    }

    #[test]
    fn names_and_endpoints() {
        assert_eq!(
            S3::parse("my-bucket/kepr/sync/").unwrap(),
            ("my-bucket".into(), "kepr/sync".into())
        );
        for bad in [
            "ab",
            "Bucket",
            "-bucket",
            "bucket/../x",
            "bucket/a b",
            "bucket/a?b",
        ] {
            assert!(S3::parse(bad).is_err(), "{bad}");
        }
        let vhost = S3::new("bk1/p", key(), "eu-west-1", None).unwrap();
        assert_eq!(vhost.host, "bk1.s3.eu-west-1.amazonaws.com");
        assert_eq!(vhost.object_path("0a1b2c3d.bundle"), "/p/0a1b2c3d.bundle");
        let dotted = S3::new("a.b.c", key(), "eu-west-1", None).unwrap();
        assert_eq!(dotted.object_path("x"), "/a.b.c/x");
        assert!(S3::new("bk1", key(), "eu-west-1", Some("http://evil.example")).is_err());
        assert!(S3::new("bk1", key(), "eu-west-1", Some("https://u@evil")).is_err());
        assert!(S3::new("bk1", key(), "EU", None).is_err());
    }

    #[test]
    fn list_get_put_are_signed_s3_requests() {
        let listing = "<ListBucketResult><IsTruncated>true</IsTruncated>\
            <Contents><Key>p/0a1b2c3d.bundle</Key></Contents>\
            <Contents><Key>p/notes.txt</Key></Contents>\
            <NextContinuationToken>t/1=</NextContinuationToken></ListBucketResult>";
        let page2 = "<ListBucketResult><IsTruncated>false</IsTruncated>\
            <Contents><Key>p/ffffffff.bundle</Key></Contents></ListBucketResult>";
        let (base, seen) = serve(vec![
            (200, listing.into()),
            (200, page2.into()),
            (200, "bundle-bytes".into()),
            (200, String::new()),
            (
                403,
                "<Error><Code>AccessDenied</Code><Message>no</Message></Error>".into(),
            ),
        ]);
        let mut s3 = S3::new("bkt/p", key(), "eu-west-1", Some(&base)).unwrap();
        assert_eq!(s3.list().unwrap(), ["0a1b2c3d.bundle", "ffffffff.bundle"]);
        assert_eq!(s3.get("0a1b2c3d.bundle").unwrap(), b"bundle-bytes");
        s3.put("11111111.bundle", b"new").unwrap();
        let e = s3.put("11111111.bundle", b"new").unwrap_err();
        assert_eq!(e, "s3 put: HTTP 403 AccessDenied: no");
        let seen = seen.join().unwrap();
        assert!(
            seen[0].starts_with("GET /bkt/?list-type=2&prefix=p%2F HTTP/1.1"),
            "{}",
            seen[0]
        );
        assert!(
            seen[1].contains("continuation-token=t%2F1%3D"),
            "{}",
            seen[1]
        );
        assert!(
            seen[2].starts_with("GET /bkt/p/0a1b2c3d.bundle "),
            "{}",
            seen[2]
        );
        assert!(
            seen[3].starts_with("PUT /bkt/p/11111111.bundle "),
            "{}",
            seen[3]
        );
        assert!(seen[3].ends_with("new"));
        for (raw, body) in [
            (&seen[0], &b""[..]),
            (&seen[1], b""),
            (&seen[2], b""),
            (&seen[3], b"new"),
        ] {
            verify(raw, body);
        }
    }
}
