// cli_discover.rs — `kepr discover [--seal] [--yes]` (agent vault P10.7):
// find credentials that CLI tools keep in plain-text config files and
// import them with the `kepr import` pipeline (plan first, names only).
// Source files are never modified; the report says how to switch each
// tool to kepr (credential helpers, `kepr exec`, `kepr inject`).
// `~/.config/kepr/discover.toml` rules (T11.20) add, ignore or ask per
// entry: cli_session/discover_rules.rs.

use std::path::{Path, PathBuf};

use base64::Engine;
use kepr_core::protocol::Response;
use zeroize::Zeroizing;

use crate::cli_import_parse::{kepr_name, Entry};
use crate::cli_ui;

fn entry(name: String, value: &str) -> Option<Entry> {
    let value = value.trim().trim_matches('"').trim_matches('\'');
    (!value.is_empty() && !name.is_empty()).then(|| Entry {
        name,
        value: kepr_core::generate::ZeroString::from_string(value.to_string()),
    })
}

/// `~/.aws/credentials`: `[profile]` sections with `key = value`.
pub fn aws(text: &str) -> Vec<Entry> {
    let mut profile = String::from("default");
    let mut out = Vec::new();
    for line in text.lines().map(str::trim) {
        if let Some(p) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            profile = p.trim().to_string();
        } else if let Some((k, v)) = line.split_once('=') {
            let k = k.trim().to_ascii_lowercase();
            if matches!(
                k.as_str(),
                "aws_access_key_id" | "aws_secret_access_key" | "aws_session_token"
            ) {
                let name = if profile == "default" {
                    k.to_ascii_uppercase()
                } else {
                    format!(
                        "AWS_{}_{}",
                        kepr_name(&profile),
                        &k.to_ascii_uppercase()[4..]
                    )
                };
                out.extend(entry(name, v));
            }
        }
    }
    out
}

/// Same mapping as the git and docker credential helpers' names
/// (every non-alphanumeric byte becomes `_`, port kept).
fn helper_name(prefix: &str, host: &str) -> String {
    let mapped: String = host
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    format!("{prefix}{mapped}")
}

/// A JSON record in the helper's own format, so switching the tool to
/// the kepr helper finds it.
fn helper_entry(name: String, record: serde_json::Value) -> Option<Entry> {
    let json = Zeroizing::new(record.to_string());
    entry(name, &json)
}

/// `~/.git-credentials`: `https://user:token@host` per line, stored as
/// `GIT_<HOST>` in git-credential-kepr's format.
pub fn git_credentials(text: &str) -> Vec<Entry> {
    text.lines()
        .filter_map(|l| {
            let rest = l.trim().split_once("://")?.1;
            let (userinfo, host) = rest.rsplit_once('@')?;
            let (user, token) = userinfo.split_once(':')?;
            let host = host.split('/').next()?;
            if token.is_empty() {
                return None;
            }
            let record = serde_json::json!({"host": host, "username": user, "password": token});
            helper_entry(helper_name("GIT_", host), record)
        })
        .collect()
}

/// `~/.netrc`: `machine H login U password P` tokens.
pub fn netrc(text: &str) -> Vec<Entry> {
    let words: Vec<&str> = text.split_whitespace().collect();
    let mut out = Vec::new();
    let mut host = None;
    for w in words.windows(2) {
        match w[0] {
            "machine" => host = Some(kepr_name(w[1])),
            "password" => {
                if let Some(h) = &host {
                    out.extend(entry(format!("NETRC_{h}_PASSWORD"), w[1]));
                }
            }
            _ => {}
        }
    }
    out
}

/// `~/.npmrc`: `//registry/:_authToken=TOKEN`.
pub fn npmrc(text: &str) -> Vec<Entry> {
    text.lines()
        .filter_map(|l| {
            let (left, v) = l.trim().split_once(":_authToken=")?;
            let host = left.trim_start_matches('/').split('/').next()?;
            let name = if host == "registry.npmjs.org" {
                "NPM_TOKEN".to_string()
            } else {
                format!("NPM_{}_TOKEN", kepr_name(host))
            };
            entry(name, v)
        })
        .collect()
}

/// `~/.pypirc`: `[repo]` sections with `password = …`.
pub fn pypirc(text: &str) -> Vec<Entry> {
    let mut section = String::new();
    let mut out = Vec::new();
    for line in text.lines().map(str::trim) {
        if let Some(s) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = kepr_name(s);
        } else if let Some((k, v)) = line.split_once(['=', ':']) {
            if k.trim() == "password" && section != "DISTUTILS" {
                out.extend(entry(format!("PYPI_{section}_TOKEN"), v));
            }
        }
    }
    out
}

/// `oauth_token: …` (gh `hosts.yml`) and `token: …` (kubeconfig users).
pub fn yaml_tokens(text: &str, prefix: &str) -> Vec<Entry> {
    let mut scope = String::new();
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim().trim_start_matches("- ");
        if !line.starts_with(' ') && t.ends_with(':') {
            scope = kepr_name(t.trim_end_matches(':')); // gh: host key
        } else if let Some(n) = t.strip_prefix("name:") {
            scope = kepr_name(n); // kubeconfig: user name
        }
        for key in ["oauth_token:", "token:"] {
            if let Some(v) = t.strip_prefix(key) {
                out.extend(entry(format!("{prefix}_{scope}_TOKEN"), v));
            }
        }
    }
    out
}

/// `~/.docker/config.json`: base64 `user:password` per registry, stored
/// as `DOCKER_<HOST>` in docker-credential-kepr's format.
pub fn docker(text: &str) -> Vec<Entry> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let b64 = base64::engine::general_purpose::STANDARD;
    v["auths"]
        .as_object()
        .into_iter()
        .flatten()
        .filter_map(|(url, a)| {
            let raw = Zeroizing::new(b64.decode(a["auth"].as_str()?).ok()?);
            let (user, pass) = std::str::from_utf8(&raw).ok()?.split_once(':')?;
            let host = url.split_once("://").map_or(url.as_str(), |(_, r)| r);
            let host = host.split('/').next()?;
            let record = serde_json::json!({"ServerURL": url, "Username": user, "Secret": pass});
            helper_entry(helper_name("DOCKER_", host), record)
        })
        .collect()
}

/// (rule key (T11.20), path, reader, how to stop keeping it in plain text)
type Source = (&'static str, PathBuf, fn(&str) -> Vec<Entry>, &'static str);

fn sources(home: &Path) -> Vec<Source> {
    let cfg = std::env::var_os("XDG_CONFIG_HOME").map_or(home.join(".config"), PathBuf::from);
    let kube = std::env::var_os("KUBECONFIG").map_or(home.join(".kube/config"), PathBuf::from);
    vec![
        (
            "aws",
            home.join(".aws/credentials"),
            aws,
            "use `kepr exec --env AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY -- aws …`",
        ),
        (
            "git",
            home.join(".git-credentials"),
            git_credentials,
            "git config --global credential.helper kepr",
        ),
        (
            "netrc",
            home.join(".netrc"),
            netrc,
            "remove the password lines; use `kepr exec`",
        ),
        (
            "npm",
            home.join(".npmrc"),
            npmrc,
            "write `_authToken=${NPM_TOKEN}` and run npm under `kepr exec --env NPM_TOKEN`",
        ),
        (
            "pypi",
            home.join(".pypirc"),
            pypirc,
            "drop the password; run twine under `kepr exec` (TWINE_PASSWORD)",
        ),
        (
            "docker",
            home.join(".docker/config.json"),
            docker,
            "set \"credsStore\": \"kepr\" and run `docker login` again",
        ),
        (
            "gh",
            cfg.join("gh/hosts.yml"),
            |t| yaml_tokens(t, "GH"),
            "`gh auth login` with the system keyring, or `kepr exec --env GH_TOKEN`",
        ),
        (
            "kube",
            kube,
            |t| yaml_tokens(t, "KUBE"),
            "use an exec credential plugin or `kepr inject` for the kubeconfig",
        ),
    ]
}

pub fn cmd_discover(o: &crate::cli_import::Opts) -> Response {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return Response::fail("HOME is not set");
    };
    let mut all = Vec::new();
    for (key, path, read, advice) in sources(&home) {
        let Ok(text) = std::fs::read_to_string(&path).map(Zeroizing::new) else {
            continue;
        };
        let found = read(&text);
        if !found.is_empty() {
            cli_ui::info(&format!(
                "{}: {} credential(s) — then {advice}",
                path.display(),
                found.len()
            ));
            all.extend(found.into_iter().map(|e| (key, e)));
        }
    }
    if all.is_empty() {
        cli_ui::ok("no plain-text credentials found in the usual CLI config files");
        return Response::Pong;
    }
    crate::cli_session::discover_rules::import(all, o) // T11.20: discover.toml
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(e: Vec<Entry>) -> Vec<(String, String)> {
        e.into_iter()
            .map(|e| (e.name, e.value.as_str().to_string()))
            .collect()
    }
    fn p(a: &str, b: &str) -> (String, String) {
        (a.into(), b.into())
    }

    #[test]
    fn aws_profiles() {
        let t = "[default]\naws_access_key_id = AK\naws_secret_access_key=SK\nregion=x\n[prod]\naws_access_key_id = PK\n";
        assert_eq!(
            n(aws(t)),
            [
                p("AWS_ACCESS_KEY_ID", "AK"),
                p("AWS_SECRET_ACCESS_KEY", "SK"),
                p("AWS_PROD_ACCESS_KEY_ID", "PK")
            ]
        );
    }

    #[test]
    fn git_netrc_npm_pypi() {
        assert_eq!(
            n(git_credentials("https://me:ghp_x@github.com\n")),
            [p(
                "GIT_GITHUB_COM",
                r#"{"host":"github.com","password":"ghp_x","username":"me"}"#
            )]
        );
        assert_eq!(
            n(netrc("machine api.x.io login me password pw\n")),
            [p("NETRC_API_X_IO_PASSWORD", "pw")]
        );
        assert_eq!(
            n(npmrc(
                "//registry.npmjs.org/:_authToken=npm_1\n//npm.pkg.github.com/:_authToken=g\n"
            )),
            [
                p("NPM_TOKEN", "npm_1"),
                p("NPM_NPM_PKG_GITHUB_COM_TOKEN", "g")
            ]
        );
        assert_eq!(n(pypirc("[distutils]\nindex-servers=pypi\n[pypi]\nusername = __token__\npassword = pypi-AB\n")), [p("PYPI_PYPI_TOKEN", "pypi-AB")]);
    }

    #[test]
    fn yaml_and_docker() {
        assert_eq!(
            n(yaml_tokens(
                "github.com:\n    oauth_token: gho_1\n    user: me\n",
                "GH"
            )),
            [p("GH_GITHUB_COM_TOKEN", "gho_1")]
        );
        let kube = "users:\n- name: admin\n  user:\n    token: kt\n";
        assert_eq!(n(yaml_tokens(kube, "KUBE")), [p("KUBE_ADMIN_TOKEN", "kt")]);
        let d = r#"{"auths":{"ghcr.io":{"auth":"bWU6c2VjcmV0"}},"credsStore":"x"}"#;
        assert_eq!(
            n(docker(d)),
            [p(
                "DOCKER_GHCR_IO",
                r#"{"Secret":"secret","ServerURL":"ghcr.io","Username":"me"}"#
            )]
        );
    }
}
