// git_helper.rs — `git-credential-kepr`.
//
// Implements the Git credential helper protocol (get/store/erase over key-value stdin/stdout lines).
//
//   Action | stdin                                | stdout (success)
//   -------+--------------------------------------+-------------------------------------
//   get    | protocol=https\nhost=github.com\n\n  | username=...\npassword=...\n\n
//   store  | protocol=https\nhost=...\npassword=  | (none)
//   erase  | protocol=https\nhost=...\n           | (none)

mod client;

use std::collections::HashMap;
use std::io::{self, BufRead};
use std::process::ExitCode;

use kepr_core::generate::ZeroString;
use kepr_core::protocol::{Request, Response};

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct GitCred {
    pub host: String,
    pub username: String,
    pub password: ZeroString,
}

pub fn host_to_kepr_name(host: &str) -> String {
    let clean: String = host
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    format!("GIT_{clean}")
}

pub fn parse_git_input<R: BufRead>(reader: R) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in reader.lines().map_while(Result::ok) {
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

pub fn cmd_get() -> ExitCode {
    let input = parse_git_input(io::stdin().lock());
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
            if let Ok(cred) = serde_json::from_str::<GitCred>(value.as_str()) {
                println!("username={}", cred.username);
                println!("password={}", cred.password.as_str());
            } else {
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

pub fn cmd_store() -> ExitCode {
    let input = parse_git_input(io::stdin().lock());
    let host = match input.get("host") {
        Some(h) if !h.is_empty() => h,
        _ => return ExitCode::SUCCESS,
    };
    let username = input
        .get("username")
        .cloned()
        .unwrap_or_else(|| "git".to_string());
    let password = match input.get("password") {
        Some(p) if !p.is_empty() => p.clone(),
        _ => return ExitCode::SUCCESS,
    };
    let cred = GitCred {
        host: host.to_string(),
        username,
        password: ZeroString::from_string(password),
    };
    let payload = match serde_json::to_string(&cred) {
        Ok(json) => json,
        Err(_) => return ExitCode::FAILURE,
    };
    let kepr_name = host_to_kepr_name(host);
    match client::send_request(&Request::Set {
        name: kepr_name,
        value: Some(ZeroString::from_string(payload)),
        generate: None,
        ttl_secs: None,
        requires_consent: None,
        requires_fido2: None,
    }) {
        Ok(Response::SetOk { .. }) => ExitCode::SUCCESS,
        _ => ExitCode::FAILURE,
    }
}

pub fn cmd_erase() -> ExitCode {
    let input = parse_git_input(io::stdin().lock());
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
            "GIT_GITLAB_INTERNAL_NET_8443"
        );
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
