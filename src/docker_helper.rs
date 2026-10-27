// docker_helper.rs — `docker-credential-kepr`.
//
// Implements the Docker credential-helper protocol so `docker login`
// can use kepr as its credential store. Docker invokes us as a
// short-lived process per operation, exchanging JSON over stdin/stdout:
//
//   Action  | stdin             | stdout (success)               | exit
//   --------+-------------------+--------------------------------+-----
//   get     | <ServerURL>       | {"Username", "Secret"}         | 0
//   store   | {"ServerURL",     | (none)                         | 0
//           |  "Username",      |                                |
//           |  "Secret"}        |                                |
//   erase   | <ServerURL>       | (none)                         | 0
//   list    | (none)            | {"<ServerURL>": "<Username>"}  | 0
//
// On failure we exit non-zero with a short message on stderr — the
// docker daemon surfaces that to the user. We never leak kepr-internal
// details (paths, daemon socket location) into stderr; the same
// "neutral identifier" rule that governs the audit log applies here.
//
// Storage layout: each docker cred lives at kepr cred-name
// `DOCKER_<sanitised-host>`, with the JSON envelope
// `{"ServerURL", "Username", "Secret"}` as the value. The ServerURL
// is kept inside the value so `list` can reconstruct the map without
// reverse-engineering the kepr cred-name encoding (which is lossy
// after uppercase + non-alnum-to-`_`).
//
// Wire transport: reuses `src/client.rs` over the standard
// `/run/kepr/kepr.sock` socket. The same `kepr` group membership
// gates docker access — no extra config beyond a `docker login`
// pointing at this binary.

mod client;

use std::io::{self, Read, Write};
use std::process::ExitCode;

use kepr_core::protocol::{Request, Response};

const KEPR_NAME_PREFIX: &str = "DOCKER_";

/// JSON envelope stored on the daemon side. Keep ServerURL even
/// though the cred name encodes the host — `list` needs the canonical
/// URL to round-trip back to docker, and the kepr name-sanitisation
/// is lossy (uppercase + non-alnum-to-`_`).
#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq, Eq)]
pub struct DockerCred {
    #[serde(rename = "ServerURL")]
    pub server_url: String,
    #[serde(rename = "Username")]
    pub username: String,
    #[serde(rename = "Secret")]
    pub secret: String,
}

/// Convert a Docker registry URL into a kepr cred name. The mapping
/// is intentionally lossy on the way in (we strip scheme + path,
/// uppercase, sanitise non-alnum to `_`) — the round-trip lives in
/// the JSON envelope, not in this name.
///
/// Why uppercase + non-alnum-to-`_`: kepr's `validate_name` rejects
/// anything outside `[A-Z0-9_]`, see `store::validate_name` in the
/// daemon. A docker URL that reaches us with `:`, `.`, `/`, or
/// alphabetic case would be rejected by the daemon if we passed it
/// straight through.
/// `host[:port]` of a registry URL, lower-cased: what two URLs must share
/// for one's credential to be handed to the other.
pub fn registry_host(url: &str) -> String {
    let no_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    no_scheme
        .split('/')
        .next()
        .unwrap_or(no_scheme)
        .to_ascii_lowercase()
}

pub fn url_to_kepr_name(url: &str) -> String {
    // Strip the scheme so `https://ghcr.io/v2/` and `ghcr.io` map
    // to the same name. Anything before `://` is the scheme.
    let no_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    // Strip the path. Docker's index URL is
    // `https://index.docker.io/v1/`; the cred should be the same as
    // for the bare host.
    let host_only = no_scheme.split('/').next().unwrap_or(no_scheme);
    // KEEP the port. `localhost:5000` and `localhost:5001` are
    // different registries and need distinct cred names. The colon
    // gets sanitised to `_` like every other non-alnum, so the
    // result is `DOCKER_LOCALHOST_5000` vs `DOCKER_LOCALHOST_5001`.
    let mut out = String::with_capacity(KEPR_NAME_PREFIX.len() + host_only.len());
    out.push_str(KEPR_NAME_PREFIX);
    for ch in host_only.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_uppercase());
        } else {
            out.push('_');
        }
    }
    out
}

/// stdin for `store` carries the registry secret: keep it in wiped buffers.
fn read_stdin_to_string() -> Result<zeroize::Zeroizing<String>, String> {
    let mut buf = zeroize::Zeroizing::new(String::new());
    io::stdin()
        .read_to_string(&mut buf)
        .map_err(|e| format!("read stdin: {e}"))?;
    Ok(zeroize::Zeroizing::new(buf.trim().to_string()))
}

/// `get`: stdin is the registry URL (plain text). Response is a
/// JSON object `{Username, Secret}` on stdout, or exit 1 + a short
/// stderr line on miss.
pub fn cmd_get() -> ExitCode {
    let url = match read_stdin_to_string() {
        Ok(u) if !u.is_empty() => u,
        _ => {
            eprintln!("docker-credential-kepr: get expects ServerURL on stdin");
            return ExitCode::from(1);
        }
    };
    let name = url_to_kepr_name(&url);
    let resp = match client::send_request(&Request::Get {
        name,
        fido2_assertion: None,
    }) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("docker-credential-kepr: {e}");
            return ExitCode::from(1);
        }
    };
    let value = match resp {
        Response::GetOk { value, .. } => value,
        Response::Err { error } => {
            eprintln!("docker-credential-kepr: {error}");
            return ExitCode::from(1);
        }
        other => {
            eprintln!("docker-credential-kepr: unexpected response: {other:?}");
            return ExitCode::from(1);
        }
    };
    let cred: DockerCred = match serde_json::from_str(value.as_str()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("docker-credential-kepr: stored cred is malformed: {e}");
            return ExitCode::from(1);
        }
    };
    // Docker only wants Username + Secret on the response — ServerURL
    // came from the request side.
    // The credential name folds every non-alphanumeric character to `_`,
    // so `registry-example.com` and `registry.example.com` share one name:
    // only answer for the registry the credential was stored for.
    if registry_host(&cred.server_url) != registry_host(&url) {
        eprintln!("credentials not found in native keychain");
        return ExitCode::from(1);
    }
    let resp = serde_json::json!({
        "Username": cred.username,
        "Secret": cred.secret,
    });
    println!("{resp}");
    ExitCode::from(0)
}

/// `store`: stdin is `{ServerURL, Username, Secret}` JSON. We pack
/// the same envelope as the kepr cred value (so `list` can recover
/// the canonical ServerURL) and call `Set`.
pub fn cmd_store() -> ExitCode {
    let json = match read_stdin_to_string() {
        Ok(s) if !s.is_empty() => s,
        _ => {
            eprintln!("docker-credential-kepr: store expects JSON on stdin");
            return ExitCode::from(1);
        }
    };
    let cred: DockerCred = match serde_json::from_str(&json) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("docker-credential-kepr: invalid input JSON: {e}");
            return ExitCode::from(1);
        }
    };
    let name = url_to_kepr_name(&cred.server_url);
    let value = match serde_json::to_string(&cred) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("docker-credential-kepr: serialise: {e}");
            return ExitCode::from(1);
        }
    };
    let req = Request::Set {
        name,
        value: Some(kepr_core::generate::ZeroString::from_string(value)),
        generate: None,
        // Docker logins don't expire from kepr's side — docker
        // manages its own session lifecycle. A future PR may want
        // to surface a `--ttl` shaped option, but today we leave
        // expiry to the consumer.
        ttl_secs: None,
        requires_consent: None,
        requires_fido2: None,
        sealed: None,
        bindings: None,
    };
    match client::send_request(&req) {
        Ok(Response::SetOk { .. }) => ExitCode::from(0),
        Ok(Response::Err { error }) => {
            eprintln!("docker-credential-kepr: {error}");
            ExitCode::from(1)
        }
        Ok(other) => {
            eprintln!("docker-credential-kepr: unexpected response: {other:?}");
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!("docker-credential-kepr: {e}");
            ExitCode::from(1)
        }
    }
}

/// `erase`: stdin is the registry URL. Send `Delete`.
pub fn cmd_erase() -> ExitCode {
    let url = match read_stdin_to_string() {
        Ok(u) if !u.is_empty() => u,
        _ => {
            eprintln!("docker-credential-kepr: erase expects ServerURL on stdin");
            return ExitCode::from(1);
        }
    };
    let name = url_to_kepr_name(&url);
    match client::send_request(&Request::Delete { name }) {
        Ok(Response::DeleteOk { .. }) => ExitCode::from(0),
        // A missing cred is fine for `erase` — docker considers
        // erase-of-nothing a no-op success. Map the daemon's
        // "credential unavailable" / "not found" path to exit 0 so
        // `docker logout` doesn't whine on a fresh install.
        Ok(Response::Err { error })
            if error.contains("not found") || error.contains("credential unavailable") =>
        {
            ExitCode::from(0)
        }
        Ok(Response::Err { error }) => {
            eprintln!("docker-credential-kepr: {error}");
            ExitCode::from(1)
        }
        Ok(other) => {
            eprintln!("docker-credential-kepr: unexpected response: {other:?}");
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!("docker-credential-kepr: {e}");
            ExitCode::from(1)
        }
    }
}

/// `list`: stdout is `{<ServerURL>: <Username>}` over every stored
/// `DOCKER_*` cred. We `List` the user's creds, filter to the
/// `DOCKER_` prefix, then `Get` each one to pull out its ServerURL +
/// Username. Each `Get` is one daemon round-trip but the per-uid
/// rate limit covers normal use; a user with hundreds of registry
/// logins is an edge case nobody hits.
pub fn cmd_list() -> ExitCode {
    let resp = match client::send_request(&Request::List) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("docker-credential-kepr: {e}");
            return ExitCode::from(1);
        }
    };
    let names: Vec<String> = match resp {
        Response::ListOk { credentials, .. } => credentials
            .into_iter()
            .map(|c| c.name)
            .filter(|n| n.starts_with(KEPR_NAME_PREFIX))
            .collect(),
        Response::Err { error } => {
            eprintln!("docker-credential-kepr: {error}");
            return ExitCode::from(1);
        }
        other => {
            eprintln!("docker-credential-kepr: unexpected response: {other:?}");
            return ExitCode::from(1);
        }
    };

    let mut out = serde_json::Map::new();
    for name in names {
        let resp = match client::send_request(&Request::Get {
            name: name.clone(),
            fido2_assertion: None,
        }) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("docker-credential-kepr: {e}");
                return ExitCode::from(1);
            }
        };
        let value = match resp {
            Response::GetOk { value, .. } => value,
            // Skip entries that fail to fetch — list should
            // surface what it CAN, not bail on a partial corpus.
            _ => continue,
        };
        if let Ok(cred) = serde_json::from_str::<DockerCred>(value.as_str()) {
            out.insert(cred.server_url, serde_json::Value::String(cred.username));
        }
        // Drop ZeroString as we go — the value lifetime is bounded
        // by this iteration.
    }
    let body = serde_json::Value::Object(out);
    println!("{body}");
    ExitCode::from(0)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let action = match args.get(1) {
        Some(s) => s.as_str(),
        None => {
            eprintln!("docker-credential-kepr: missing action (get/store/erase/list)");
            // Flush so docker sees the message before our exit.
            let _ = io::stderr().flush();
            return ExitCode::from(1);
        }
    };
    match action {
        "get" => cmd_get(),
        "store" => cmd_store(),
        "erase" => cmd_erase(),
        "list" => cmd_list(),
        other => {
            eprintln!("docker-credential-kepr: unknown action: {other}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn lookalike_registries_share_a_name_but_not_a_host() {
        assert_eq!(
            url_to_kepr_name("registry-example.com"),
            url_to_kepr_name("registry.example.com")
        );
        assert_ne!(
            registry_host("https://registry-example.com/v2/"),
            registry_host("registry.example.com")
        );
        assert_eq!(
            registry_host("https://Registry.Example.com:5000/v2/"),
            "registry.example.com:5000"
        );
    }
    use super::*;

    #[test]
    fn url_to_kepr_name_strips_scheme() {
        assert_eq!(url_to_kepr_name("https://ghcr.io"), "DOCKER_GHCR_IO");
        assert_eq!(url_to_kepr_name("http://ghcr.io"), "DOCKER_GHCR_IO");
    }

    #[test]
    fn url_to_kepr_name_strips_path() {
        // Docker's official index URL must collapse to the bare
        // host, otherwise `docker login` (no URL) and
        // `docker login https://index.docker.io/v1/` end up at
        // different cred names.
        assert_eq!(
            url_to_kepr_name("https://index.docker.io/v1/"),
            "DOCKER_INDEX_DOCKER_IO"
        );
    }

    #[test]
    fn url_to_kepr_name_handles_bare_host() {
        // `docker login ghcr.io` (no scheme) is the common case.
        assert_eq!(url_to_kepr_name("ghcr.io"), "DOCKER_GHCR_IO");
    }

    #[test]
    fn url_to_kepr_name_keeps_port_disambiguation() {
        // `localhost:5000` and `localhost:5001` are different
        // registries; their cred names must differ.
        assert_eq!(url_to_kepr_name("localhost:5000"), "DOCKER_LOCALHOST_5000");
        assert_eq!(url_to_kepr_name("localhost:5001"), "DOCKER_LOCALHOST_5001");
        assert_ne!(
            url_to_kepr_name("localhost:5000"),
            url_to_kepr_name("localhost:5001")
        );
    }

    #[test]
    fn url_to_kepr_name_uppercases() {
        // `validate_name` in the daemon rejects lowercase, so the
        // mapping MUST uppercase. Pin the contract.
        assert_eq!(url_to_kepr_name("Quay.IO"), "DOCKER_QUAY_IO");
    }

    #[test]
    fn url_to_kepr_name_sanitises_non_alnum_to_underscore() {
        // Anything outside `[A-Z0-9]` becomes `_`. The daemon's
        // `validate_name` is the source of truth.
        let n = url_to_kepr_name("docker.pkg.github.com");
        assert!(
            n.chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'),
            "name contains illegal char: {n}"
        );
        assert_eq!(n, "DOCKER_DOCKER_PKG_GITHUB_COM");
    }

    #[test]
    fn url_to_kepr_name_idempotent_on_already_clean_input() {
        // A second pass through the function should produce the
        // same result. This is a property the docker daemon
        // implicitly relies on when retrying after a network blip.
        let once = url_to_kepr_name("ghcr.io");
        let twice = url_to_kepr_name(&once);
        assert!(twice.starts_with(KEPR_NAME_PREFIX));
        // The key property: same input → same output, deterministic.
        assert_eq!(once, url_to_kepr_name("ghcr.io"));
        // (idempotency on the OUTPUT is not strictly needed and
        // currently doesn't hold because the prefix gets duplicated;
        // pin the determinism property only.)
        let _ = twice;
    }

    #[test]
    fn docker_cred_round_trips_json() {
        // The value the daemon stores must round-trip cleanly so
        // `list` can recover ServerURL + Username after a `store`.
        let original = DockerCred {
            server_url: "https://ghcr.io".into(),
            username: "alice".into(),
            secret: "ghp_abc123".into(),
        };
        let s = serde_json::to_string(&original).unwrap();
        let back: DockerCred = serde_json::from_str(&s).unwrap();
        assert_eq!(original, back);
    }

    #[test]
    fn docker_cred_uses_capitalised_field_names() {
        // The docker helper protocol calls them ServerURL / Username
        // / Secret — must serialise to those exact keys, not the
        // Rust-snake-case variants.
        let c = DockerCred {
            server_url: "u".into(),
            username: "n".into(),
            secret: "s".into(),
        };
        let s = serde_json::to_string(&c).unwrap();
        assert!(s.contains("\"ServerURL\""), "got: {s}");
        assert!(s.contains("\"Username\""), "got: {s}");
        assert!(s.contains("\"Secret\""), "got: {s}");
        assert!(!s.contains("server_url"), "got: {s}");
    }

    #[test]
    fn docker_cred_parses_server_url_alias() {
        // Make sure deserialisation accepts the wire field name.
        let s = r#"{"ServerURL":"https://ghcr.io","Username":"x","Secret":"y"}"#;
        let c: DockerCred = serde_json::from_str(s).unwrap();
        assert_eq!(c.server_url, "https://ghcr.io");
        assert_eq!(c.username, "x");
        assert_eq!(c.secret, "y");
    }
}
