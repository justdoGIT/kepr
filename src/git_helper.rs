// git_helper.rs — `git-credential-kepr`.
//
// Implements the Git credential helper protocol (get/store/erase over key-value stdin/stdout lines).
//
//   Action | stdin                                | stdout (success)
//   -------+--------------------------------------+-------------------------------------
//   get    | protocol=https\nhost=github.com\n\n  | username=...\npassword=...\n\n
//   store  | protocol=https\nhost=...\npassword=  | (none)
//   erase  | protocol=https\nhost=...\n           | (none)
//
// T12.06: inside `kepr agent run` (KEPR_SESSION set) the helper never
// contacts the daemon. `get` answers an https host with the session
// placeholder from KEPR_PH_GIT_<HOST> (the gate swaps it for the sealed
// token on the wire); `store` and `erase` do nothing.

mod client;

use std::collections::HashMap;
use std::io::{self, BufRead};
use std::process::ExitCode;

use kepr_core::generate::ZeroString;
use kepr_core::protocol::{Request, Response};

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct GitCred {
    pub host: String,
    /// `https`, `http`, … (empty in credentials stored before it was kept).
    #[serde(default)]
    pub protocol: String,
    pub username: String,
    pub password: ZeroString,
}

pub fn host_to_kepr_name(host: &str) -> String {
    kepr_core::providers::git_cred_name(host)
}

type Env<'a> = &'a dyn Fn(&str) -> Option<String>;

fn in_session(env: Env) -> bool {
    env("KEPR_SESSION").is_some()
}

/// T12.06: the `(username, password)` to give git inside an agent
/// session: the placeholder for an https host this session routes, from
/// the environment only. `None` outside a session or for any other host.
pub fn session_answer(env: Env, input: &HashMap<String, String>) -> Option<(String, String)> {
    if !in_session(env) || input.get("protocol").map(String::as_str) != Some("https") {
        return None;
    }
    let host = input.get("host")?.to_ascii_lowercase();
    // Dotted legacy names stay stable; other punctuation receives an exact suffix.
    kepr_core::binding::validate_host(&host).ok()?;
    let var = format!(
        "{}{}",
        kepr_core::providers::GIT_PH_PREFIX,
        host_to_kepr_name(&host)
    );
    let ph = env(&var).filter(|p| p.starts_with("kepr-ph-"))?;
    Some(("x-access-token".to_string(), ph))
}

pub fn parse_git_input<R: BufRead>(reader: R) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in reader.lines().map_while(Result::ok) {
        // A `password=` line is a secret: wipe the raw line after parsing.
        let line = zeroize::Zeroizing::new(line);
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once('=') {
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    map
}

fn process_env(k: &str) -> Option<String> {
    std::env::var(k).ok()
}

pub fn cmd_get() -> ExitCode {
    let input = parse_git_input(io::stdin().lock());
    if in_session(&process_env) {
        if let Some((user, ph)) = session_answer(&process_env, &input) {
            println!("username={user}");
            println!("password={ph}");
        }
        return ExitCode::SUCCESS;
    }
    let host = match input.get("host") {
        Some(h) if !h.is_empty() => h,
        _ => return ExitCode::SUCCESS,
    };
    let kepr_name = host_to_kepr_name(host);
    match client::send_request(&Request::Get {
        name: kepr_name,
        fido2_assertion: None,
    }) {
        Ok(Response::GetOk { value, .. }) => {
            let protocol = input.get("protocol").map(String::as_str).unwrap_or("");
            if let Ok(cred) = serde_json::from_str::<GitCred>(value.as_str()) {
                // The name folds `.` and `-` alike: answer only for the
                // exact host, and never send an https password over http.
                let same_host = cred.host.eq_ignore_ascii_case(host);
                let same_proto = cred.protocol.is_empty() || cred.protocol == protocol;
                if !same_host || !same_proto || (cred.protocol.is_empty() && protocol == "http") {
                    return ExitCode::SUCCESS;
                }
                println!("username={}", cred.username);
                println!("password={}", cred.password.as_str());
            } else if protocol != "http" {
                let username = input
                    .get("username")
                    .cloned()
                    .unwrap_or_else(|| "git".to_string());
                println!("username={username}");
                println!("password={}", value.as_str());
            }
            ExitCode::SUCCESS
        }
        _ => ExitCode::SUCCESS,
    }
}

/// The `Set` that `store` sends: none in a session (T12.06) or with
/// nothing to store; a session placeholder is never stored.
fn store_request(
    env: Env,
    mut input: HashMap<String, String>,
) -> Result<Option<Request>, &'static str> {
    if in_session(env) {
        return Ok(None);
    }
    // Move (not clone) the password out of the map, straight into a
    // ZeroString, so no plain copy is left behind.
    let password = match input.remove("password") {
        Some(p) if !p.is_empty() => ZeroString::from_string(p),
        _ => return Ok(None),
    };
    if password.as_str().starts_with("kepr-ph-") {
        return Err("refusing to store a kepr session placeholder");
    }
    let host = match input.get("host") {
        Some(h) if !h.is_empty() => h,
        _ => return Ok(None),
    };
    let username = input
        .get("username")
        .cloned()
        .unwrap_or_else(|| "git".to_string());
    let cred = GitCred {
        host: host.to_string(),
        protocol: input.get("protocol").cloned().unwrap_or_default(),
        username,
        password,
    };
    let payload = serde_json::to_string(&cred)
        .map(ZeroString::from_string)
        .map_err(|_| "cannot encode the login")?;
    Ok(Some(Request::Set {
        name: host_to_kepr_name(host),
        value: Some(payload),
        generate: None,
        ttl_secs: None,
        requires_consent: None,
        requires_fido2: None,
        sealed: None,
        bindings: None,
    }))
}

pub fn cmd_store() -> ExitCode {
    let req = match store_request(&process_env, parse_git_input(io::stdin().lock())) {
        Ok(Some(req)) => req,
        Ok(None) => return ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("git-credential-kepr: {e}");
            return ExitCode::FAILURE;
        }
    };
    match client::send_request(&req) {
        Ok(Response::SetOk { .. }) => ExitCode::SUCCESS,
        _ => ExitCode::FAILURE,
    }
}

pub fn cmd_erase() -> ExitCode {
    let input = parse_git_input(io::stdin().lock());
    if in_session(&process_env) {
        return ExitCode::SUCCESS;
    }
    let host = match input.get("host") {
        Some(h) if !h.is_empty() => h,
        _ => return ExitCode::SUCCESS,
    };
    let kepr_name = host_to_kepr_name(host);
    let _ = client::send_request(&Request::Delete { name: kepr_name });
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let action = match std::env::args().nth(1) {
        Some(a) => a,
        None => return ExitCode::FAILURE,
    };
    match action.as_str() {
        "get" => cmd_get(),
        "store" => cmd_store(),
        "erase" => cmd_erase(),
        _ => ExitCode::FAILURE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_host_to_kepr_name() {
        assert_eq!(host_to_kepr_name("github.com"), "GIT_GITHUB_COM");
        assert_eq!(
            host_to_kepr_name("gitlab.internal.net:8443"),
            "GIT_GITLAB_INTERNAL_NET_8443_HOST_6769746C61622E696E7465726E616C2E6E65743A38343433"
        );
    }

    const PH: &str = "kepr-ph-0123456789abcdef-0003-0011223344556677";

    fn session_env(k: &str) -> Option<String> {
        match k {
            "KEPR_SESSION" => Some("0123456789abcdef".into()),
            "KEPR_PH_GIT_GITHUB_COM" => Some(PH.into()),
            _ => None,
        }
    }

    fn no_session(k: &str) -> Option<String> {
        (k != "KEPR_SESSION").then(|| session_env(k)).flatten()
    }

    fn input(s: &str) -> HashMap<String, String> {
        parse_git_input(Cursor::new(s))
    }

    #[test]
    fn a_session_answers_with_the_placeholder_from_the_environment() {
        let gh = input("protocol=https\nhost=github.com\n\n");
        assert_eq!(
            session_answer(&session_env, &gh),
            Some(("x-access-token".to_string(), PH.to_string()))
        );
        let other = input("protocol=https\nhost=gitlab.com\n\n");
        assert_eq!(session_answer(&session_env, &other), None);
        let http = input("protocol=http\nhost=github.com\n\n");
        assert_eq!(session_answer(&session_env, &http), None);
        assert_eq!(session_answer(&no_session, &gh), None);
        let folded = input("protocol=https\nhost=github-com\n\n");
        assert_eq!(session_answer(&session_env, &folded), None);
    }

    #[test]
    fn store_does_nothing_in_a_session_and_refuses_placeholders_outside() {
        let login = "protocol=https\nhost=github.com\nusername=me\npassword=hunter22\n\n";
        assert!(matches!(
            store_request(&session_env, input(login)),
            Ok(None)
        ));
        assert!(matches!(
            store_request(&no_session, input(login)),
            Ok(Some(Request::Set { .. }))
        ));
        let ph = format!("protocol=https\nhost=github.com\npassword={PH}\n\n");
        let err = store_request(&no_session, input(&ph)).unwrap_err();
        assert!(!err.contains(PH), "{err}");
        assert!(matches!(store_request(&session_env, input(&ph)), Ok(None)));
    }

    #[test]
    fn test_parse_git_input() {
        let input = "protocol=https\nhost=github.com\nusername=alice\n\n";
        let map = parse_git_input(Cursor::new(input));
        assert_eq!(map.get("protocol").map(String::as_str), Some("https"));
        assert_eq!(map.get("host").map(String::as_str), Some("github.com"));
        assert_eq!(map.get("username").map(String::as_str), Some("alice"));
    }
}
