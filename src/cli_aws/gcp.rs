// gcp.rs — `kepr gcp add NAME [--key-file FILE] [--impersonate SA_EMAIL]
// [--scope URL]...` (T12.10, batch: gate-providers).
//
// Stores a Google service-account key or an `authorized_user` file (what
// `gcloud auth application-default login` writes) sealed, bound to the
// gcloud hosts (`www.googleapis.com` and `providers::GCLOUD_HOSTS`) with
// `Inject::GcpToken`. `kepr agent run` then gives gcloud the
// CLOUDSDK_AUTH_ACCESS_TOKEN placeholder, and the gate swaps it for a
// 1-hour access token it mints per session (kepr-gate gcp_token.rs). The
// credential goes only to the daemon; nothing here prints it or quotes
// the file.

use std::io::{IsTerminal, Read};

use kepr_core::binding::{validate_binding, Binding, Inject};
use kepr_core::gcp_token::{self as gcp, Source};
use kepr_core::generate::ZeroString;
use kepr_core::protocol::{Request, Response};
use kepr_core::providers;

const USAGE: &str =
    "usage: kepr gcp add KEY [--key-file FILE] [--impersonate SA_EMAIL] [--scope URL]...";
/// A service-account key file is ~2.4 KB.
const MAX_FILE: u64 = 16 * 1024;
const VALUED: [&str; 3] = ["--key-file", "--impersonate", "--scope"];

pub struct Opts {
    pub name: String,
    pub bindings: Vec<Binding>,
    pub key_file: Option<String>,
}

/// Every `--scope` value, in order, without repeats; the default when none.
fn scopes(args: &[&str]) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for (i, a) in args.iter().enumerate() {
        if *a != "--scope" {
            continue;
        }
        let v = args.get(i + 1).ok_or(USAGE)?;
        if !out.iter().any(|s| s == v) {
            out.push(v.to_string());
        }
    }
    if out.is_empty() {
        out.push(gcp::DEFAULT_SCOPE.to_string());
    }
    Ok(out)
}

pub fn parse(args: &[&str]) -> Result<Opts, String> {
    let mut i = 0;
    while i < args.len() {
        match args[i] {
            f if VALUED.contains(&f) => i += 2,
            f if f.starts_with('-') => return Err(format!("unknown flag {f}\n{USAGE}")),
            _ => i += 1,
        }
    }
    let name = super::positional(args, &VALUED).ok_or(USAGE)?;
    let impersonate = super::flag(args, "--impersonate").map(str::to_string);
    if args.contains(&"--impersonate") && impersonate.is_none() {
        return Err(USAGE.into());
    }
    if let Some(t) = impersonate
        .as_deref()
        .filter(|t| !gcp::valid_service_account(t))
    {
        return Err(format!(
            "--impersonate {t}: not a service account email (NAME@PROJECT.iam.gserviceaccount.com)"
        ));
    }
    let inject = Inject::GcpToken {
        scopes: scopes(args)?,
        impersonate,
    };
    let hosts =
        std::iter::once("www.googleapis.com").chain(providers::GCLOUD_HOSTS.iter().copied());
    let bindings = hosts
        .map(|h| Binding {
            host: h.to_string(),
            port: 443,
            inject: inject.clone(),
        })
        .collect::<Vec<_>>();
    bindings.iter().try_for_each(validate_binding)?;
    Ok(Opts {
        name: name.to_uppercase(),
        bindings,
        key_file: super::flag(args, "--key-file").map(str::to_string),
    })
}

fn read_file(path: Option<&str>) -> Result<ZeroString, String> {
    let mut text = zeroize::Zeroizing::new(String::new());
    let read = match path {
        Some(p) => std::fs::File::open(p)
            .and_then(|f| f.take(MAX_FILE + 1).read_to_string(&mut text))
            .map_err(|e| format!("{p}: {e}")),
        None if std::io::stdin().is_terminal() => Err(format!(
            "pass --key-file (the JSON key or credential file) or pipe it in\n{USAGE}"
        )),
        None => (std::io::stdin()
            .take(MAX_FILE + 1)
            .read_to_string(&mut text))
        .map_err(|_| "cannot read the credential from stdin".to_string()),
    };
    let n = read?;
    if n as u64 > MAX_FILE {
        return Err("the credential file is larger than 16 KiB".into());
    }
    Ok(ZeroString::from_string(text.trim().to_string()))
}

/// Check the credential and build the sealed `Set`; nothing is sent
/// unless this succeeds. Errors never quote the file.
pub fn request(o: &Opts, json: ZeroString) -> Result<Request, String> {
    if let Source::ServiceAccount { private_key, .. } = gcp::parse_source(json.as_str())? {
        super::github_app::check_key(private_key.as_str())?;
    }
    Ok(Request::Set {
        name: o.name.clone(),
        value: Some(json),
        generate: None,
        ttl_secs: None,
        requires_consent: None,
        requires_fido2: None,
        sealed: Some(true),
        bindings: Some(o.bindings.clone()),
    })
}

fn add(args: &[&str]) -> Response {
    let o = match parse(args) {
        Ok(o) => o,
        Err(e) => return Response::fail(e),
    };
    let req = match read_file(o.key_file.as_deref()).and_then(|j| request(&o, j)) {
        Ok(r) => r,
        Err(e) => return Response::fail(e),
    };
    let r = crate::client::send_request(&req).unwrap_or_else(Response::fail);
    if matches!(r, Response::SetOk { .. }) && !crate::cli_ui::json_mode() {
        crate::cli_ui::ok(&format!(
            "{} stored sealed. `kepr agent run` sessions get 1-hour Google access tokens \
             (gcloud, CLOUDSDK_AUTH_ACCESS_TOKEN); the credential never leaves the gate",
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

    const SA_EMAIL: &str = "deploy@proj-1.iam.gserviceaccount.com";

    fn fixture_pem() -> String {
        let b64 = include_str!("../cli_sharing/testdata/rsa2048-test-only.der.b64").trim();
        format!("-----BEGIN RSA PRIVATE KEY-----\n{b64}\n-----END RSA PRIVATE KEY-----\n")
    }

    fn sa_json(key: &str) -> ZeroString {
        let j = serde_json::json!({
            "type": "service_account", "project_id": "proj-1",
            "client_email": "bot@proj-1.iam.gserviceaccount.com", "private_key": key,
        });
        ZeroString::from(j.to_string())
    }

    #[test]
    fn arguments() {
        let o = parse(&["gcp_ci", "--key-file", "k.json"]).unwrap();
        assert_eq!(o.name, "GCP_CI");
        assert_eq!(o.key_file.as_deref(), Some("k.json"));
        let want = Inject::GcpToken {
            scopes: vec![gcp::DEFAULT_SCOPE.to_string()],
            impersonate: None,
        };
        assert!(o.bindings.iter().all(|b| b.inject == want && b.port == 443));
        for bad in [
            &["--key-file", "k.json"][..],
            &[],
            &["K", "--impersonate", "me@example.com"],
            &["K", "--impersonate"],
            &["K", "--scope"],
            &["K", "--scope", "https://evil.example/x"],
            &["K", "--scopes", "x"],
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
        let a = [
            "K",
            "--scope",
            "https://www.googleapis.com/auth/devstorage.read_only",
            "--impersonate",
            SA_EMAIL,
            "--scope",
            "https://www.googleapis.com/auth/cloud-platform",
            "--scope",
            "https://www.googleapis.com/auth/cloud-platform",
        ];
        let o = parse(&a).unwrap();
        let Inject::GcpToken {
            scopes,
            impersonate,
        } = &o.bindings[0].inject
        else {
            panic!("gcp_token expected");
        };
        assert_eq!(
            scopes,
            &[
                "https://www.googleapis.com/auth/devstorage.read_only",
                "https://www.googleapis.com/auth/cloud-platform"
            ]
        );
        assert_eq!(impersonate.as_deref(), Some(SA_EMAIL));
        assert!(matches!(cmd(&["list"]), Response::Err { .. }));
    }

    #[test]
    fn a_service_account_gets_the_gcloud_bindings_sealed() {
        let o = parse(&["GCP"]).unwrap();
        let hosts: Vec<&str> = o.bindings.iter().map(|b| b.host.as_str()).collect();
        assert_eq!(hosts.len(), 1 + providers::GCLOUD_HOSTS.len());
        assert_eq!(hosts[0], "www.googleapis.com");
        assert!(providers::GCLOUD_HOSTS.iter().all(|h| hosts.contains(h)));
        let Request::Set {
            name,
            sealed,
            bindings,
            value,
            ..
        } = request(&o, sa_json(&fixture_pem())).unwrap()
        else {
            panic!("a Set");
        };
        assert_eq!((name.as_str(), sealed), ("GCP", Some(true)));
        assert_eq!(bindings.unwrap(), o.bindings);
        assert!(value.unwrap().as_str().contains("service_account"));
    }

    #[test]
    fn what_is_not_a_credential_is_refused_before_any_request() {
        let o = parse(&["GCP"]).unwrap();
        for bad in [
            r#"{"foo":1}"#.to_string(),
            "ghp_abcdefghijklmnopqrstuvwxyz0123456789".to_string(),
            r#"{"type":"external_account","audience":"x"}"#.to_string(),
            sa_json("-----BEGIN PRIVATE KEY-----\nMAEC\n-----END PRIVATE KEY-----")
                .to_owned_string(),
        ] {
            let e = request(&o, ZeroString::from(bad.as_str())).err().unwrap();
            assert!(!e.contains("ghp_") && !e.contains("MAEC"), "{e}");
        }
        let user =
            r#"{"type":"authorized_user","client_id":"c","client_secret":"s","refresh_token":"r"}"#;
        assert!(request(&o, ZeroString::from(user)).is_ok());
    }
}
