//! Provider routing (T1.08). The provider table itself lives in
//! `kepr_core::providers` (shared with the CLI). Base URLs handed to
//! harnesses look like `http://127.0.0.1:PORT/<name>/...`.
//! How the key is injected is not decided here: it comes from the
//! credential's binding, which the daemon returns with the value.

pub use kepr_core::providers::lookup;

/// `"/anthropic/v1/messages"` → `Some(("anthropic", "/v1/messages"))`.
pub fn split_path(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix('/')?;
    if rest.is_empty() {
        return None;
    }
    match rest.find('/') {
        Some(i) => Some((&rest[..i], &rest[i..])),
        None => Some((rest, "/")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_path_cases() {
        assert_eq!(split_path("/xai/v1/chat"), Some(("xai", "/v1/chat")));
        assert_eq!(split_path("/openai"), Some(("openai", "/")));
        assert_eq!(split_path("/"), None);
        assert!(lookup(split_path("/unknown/x").unwrap().0).is_none());
    }
}
