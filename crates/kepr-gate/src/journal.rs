//! Metadata-only request journal (T1.11). One JSON line per request on
//! stderr. Never headers, query strings or bodies.

pub struct Entry<'a> {
    pub session: &'a str,
    pub provider: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    pub status: u16,
    pub bytes_out: usize,
    pub ms: u128,
    pub blocked: Option<&'a str>,
}

pub fn format(e: &Entry) -> String {
    let path = e.path.split('?').next().unwrap_or_default();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut v = serde_json::json!({
        "ts": ts,
        "session": e.session,
        "provider": e.provider,
        "method": e.method,
        "path": path,
        "status": e.status,
        "bytes_out": e.bytes_out,
        "ms": e.ms,
    });
    if let Some(b) = e.blocked {
        v["blocked"] = serde_json::Value::from(b);
    }
    v.to_string()
}

pub fn emit(e: &Entry) {
    eprintln!("{}", format(e));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_is_stripped_and_keys_present() {
        let line = format(&Entry {
            session: "s",
            provider: "google",
            method: "POST",
            path: "/v1/x?key=secret",
            status: 200,
            bytes_out: 5,
            ms: 1,
            blocked: None,
        });
        assert!(!line.contains("secret"));
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        for k in [
            "ts",
            "session",
            "provider",
            "method",
            "path",
            "status",
            "bytes_out",
            "ms",
        ] {
            assert!(v.get(k).is_some(), "{k}");
        }
        assert_eq!(v["path"], "/v1/x");
        assert!(v.get("blocked").is_none());
    }
}
