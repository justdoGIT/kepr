// github_app.rs — `kepr github-app add NAME --app-id N --installation-id M
// [--key-file PEM]` (T7.08).
//
// Stores a GitHub App private key sealed, bound to api.github.com with
// `Inject::GithubApp`. `kepr agent run` then routes the session's `gh` /
// GH_TOKEN traffic through the gate, which signs an app JWT with the key
// and mints a 1-hour installation token per session (kepr-gate
// github_app.rs). The key, the JWT and the token never reach the agent,
// and nothing here prints them.

use std::io::{IsTerminal, Read};

use kepr_core::binding::{validate_binding, Binding, Inject};
use kepr_core::generate::ZeroString;
use kepr_core::github_app::{pem_der, KeyDer, API_HOST};
use kepr_core::protocol::{Request, Response};
use ring::signature::RsaKeyPair;

const USAGE: &str =
    "usage: kepr github-app add KEY --app-id N --installation-id N [--key-file PEM]";
/// A 4096-bit PEM is ~3.3 KB.
const MAX_PEM: u64 = 16 * 1024;

/// Is `pem` an RSA private key ring can sign with? Never quotes it.
pub fn check_key(pem: &str) -> Result<(), String> {
    let ok = match pem_der(pem)? {
        KeyDer::Pkcs1(der) => RsaKeyPair::from_der(&der).is_ok(),
        KeyDer::Pkcs8(der) => RsaKeyPair::from_pkcs8(&der).is_ok(),
    };
    if ok {
        Ok(())
    } else {
        Err("not a usable RSA private key".into())
    }
}

fn id(args: &[&str], flag: &str) -> Result<u64, String> {
    super::flag(args, flag)
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .ok_or_else(|| format!("{flag} takes the numeric id from the App's settings\n{USAGE}"))
}

pub struct Opts {
    pub name: String,
    pub binding: Binding,
    pub key_file: Option<String>,
}

pub fn parse(args: &[&str]) -> Result<Opts, String> {
    let valued = ["--app-id", "--installation-id", "--key-file"];
    let name = super::positional(args, &valued).ok_or(USAGE)?;
    let binding = Binding {
        host: API_HOST.into(),
        port: 443,
        inject: Inject::GithubApp {
            app_id: id(args, "--app-id")?,
            installation_id: id(args, "--installation-id")?,
        },
    };
    validate_binding(&binding)?;
    Ok(Opts {
        name: name.to_uppercase(),
        binding,
        key_file: super::flag(args, "--key-file").map(str::to_string),
    })
}

fn read_key(path: Option<&str>) -> Result<ZeroString, String> {
    let mut text = zeroize::Zeroizing::new(String::new());
    let read = match path {
        Some(p) => std::fs::File::open(p)
            .and_then(|f| f.take(MAX_PEM).read_to_string(&mut text))
            .map_err(|e| format!("{p}: {e}")),
        None if std::io::stdin().is_terminal() => Err(format!(
            "pass --key-file (the .pem GitHub gave you) or pipe it in\n{USAGE}"
        )),
        None => (std::io::stdin().take(MAX_PEM).read_to_string(&mut text))
            .map_err(|e| format!("cannot read the key from stdin: {e}")),
    };
    read.map(|_| ZeroString::from_string(text.trim().to_string()))
}

fn store(o: &Opts, pem: ZeroString) -> Response {
    let req = Request::Set {
        name: o.name.clone(),
        value: Some(pem),
        generate: None,
        ttl_secs: None,
        requires_consent: None,
        requires_fido2: None,
        sealed: Some(true),
        bindings: Some(vec![o.binding.clone()]),
    };
    crate::client::send_request(&req).unwrap_or_else(Response::fail)
}

fn add(args: &[&str]) -> Response {
    let o = match parse(args) {
        Ok(o) => o,
        Err(e) => return Response::fail(e),
    };
    let pem = match read_key(o.key_file.as_deref()) {
        Ok(p) => p,
        Err(e) => return Response::fail(e),
    };
    if let Err(e) = check_key(pem.as_str()) {
        return Response::fail(e);
    }
    let r = store(&o, pem);
    if matches!(r, Response::SetOk { .. }) && !crate::cli_ui::json_mode() {
        crate::cli_ui::ok(&format!(
            "{} stored sealed. `kepr agent run` sessions get 1-hour installation tokens for \
             {API_HOST} (gh, GH_TOKEN); the key never leaves the gate",
            o.name
        ));
        if let Some(p) = &o.key_file {
            crate::cli_ui::info(&format!("you can delete {p} now"));
        }
    }
    r
}

pub fn cmd(args: &[&str]) -> Response {
    match args.first() {
        Some(&"add") => add(&args[1..]),
        _ => Response::fail(USAGE),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_pem() -> String {
        let b64 = include_str!("../cli_sharing/testdata/rsa2048-test-only.der.b64").trim();
        format!("-----BEGIN RSA PRIVATE KEY-----\n{b64}\n-----END RSA PRIVATE KEY-----\n")
    }

    #[test]
    fn parses_the_ids_into_a_github_app_binding() {
        let o = parse(&["my_app", "--app-id", "42", "--installation-id", "7"]).unwrap();
        assert_eq!(o.name, "MY_APP");
        assert_eq!(o.binding.host, "api.github.com");
        assert_eq!(
            o.binding.inject,
            Inject::GithubApp {
                app_id: 42,
                installation_id: 7
            }
        );
        assert!(o.key_file.is_none());
        for bad in [
            &["K", "--installation-id", "7"][..],
            &["K", "--app-id", "0", "--installation-id", "7"],
            &["K", "--app-id", "x", "--installation-id", "7"],
            &["--app-id", "1", "--installation-id", "7"],
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
        assert!(matches!(cmd(&["list"]), Response::Err { .. }));
    }

    #[test]
    fn only_an_rsa_private_key_is_accepted() {
        assert!(check_key(&fixture_pem()).is_ok());
        let e = check_key("ghp_abcdefghijklmnopqrstuvwxyz0123456789").unwrap_err();
        assert!(!e.contains("ghp_"));
        let garbage = "-----BEGIN RSA PRIVATE KEY-----\nMAEC\n-----END RSA PRIVATE KEY-----";
        assert_eq!(
            check_key(garbage).unwrap_err(),
            "not a usable RSA private key"
        );
    }
}
