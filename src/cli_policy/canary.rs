// cli_policy/canary.rs — honeytokens (T9.08), CLI side:
//
//   kepr canary plant [--for PROVIDER] [--name NAME] [--in FILE|DIR]
//   kepr canary ls | kepr canary rm NAME
//   kepr canary listen --listen ADDR:PORT
//
// `plant` has the daemon store a decoy key (in the provider's real
// format) and writes it where a thief looks: a `.env` file (`NAME=…`),
// a shell rc file (`export NAME='…'`) or DIR/.env. `rm` deletes it and
// its line. `listen` receives provider-side canary webhooks at
// `/kepr-canary/<trip id>` (`kepr canary ls --json` lists the ids) and
// tells the daemon, which raises the alarm. Alerts come from the audit
// log: a `kepr alerts` rule with `ops = ["canary-tripped"]` posts them.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use kepr_core::protocol::Response;
use kepr_core::protocol_policy::{CanaryEntry, PolicyRequest, PolicyResponse};

use super::approvals_cmd::{reply, request_line};

const USAGE: &str = "usage: kepr canary plant [--for PROVIDER] [--name NAME] [--in FILE|DIR] | canary ls | canary rm NAME | canary listen --listen ADDR:PORT";

pub fn cmd_canary(args: &[String]) -> Response {
    let a = super::plain_args(args);
    match a.as_slice() {
        ["plant", ..] => plant(args),
        ["ls"] | ["list"] => ls(),
        ["rm", name] => rm(name),
        ["listen", ..] => match listen(args) {
            Ok(()) => super::done("canary listener stopped".into()),
            Err(e) => Response::fail(format!("canary listen: {e}")),
        },
        _ => Response::fail(USAGE),
    }
}

/// `~/x` against `$HOME`, relative paths against the working directory;
/// a directory gets `.env` inside it.
fn target(spec: &str) -> Result<PathBuf, String> {
    let home = || {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or("HOME is not set")
    };
    let p = match spec.strip_prefix("~/") {
        Some(rest) => home()?.join(rest),
        None if spec == "~" => home()?,
        None => PathBuf::from(spec),
    };
    let p = if p.is_absolute() {
        p
    } else {
        std::env::current_dir().map_err(|e| e.to_string())?.join(p)
    };
    Ok(if p.is_dir() { p.join(".env") } else { p })
}

/// The line that plants `name`: shell syntax in rc / profile files.
pub fn line_for(path: &Path, name: &str, value: &str) -> String {
    let base = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    let shell = base.ends_with("rc")
        || matches!(
            base,
            ".profile" | ".bash_profile" | ".bash_login" | ".zprofile" | ".zshenv"
        );
    match shell {
        true => format!("export {name}='{value}'"),
        false => format!("{name}={value}"),
    }
}

fn append(path: &Path, line: &str) -> Result<(), String> {
    let existing = std::fs::read(path).unwrap_or_default();
    let sep = if existing.is_empty() || existing.ends_with(b"\n") {
        ""
    } else {
        "\n"
    };
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    writeln!(f, "{sep}{line}").map_err(|e| format!("{}: {e}", path.display()))
}

/// Drop the lines that assign `name` (as `plant` wrote them); how many.
pub fn remove_lines(path: &Path, name: &str) -> Result<usize, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let assigns = |l: &str| {
        let l = l.trim_start();
        let l = l.strip_prefix("export ").unwrap_or(l);
        l.strip_prefix(name)
            .is_some_and(|rest| rest.starts_with('='))
    };
    let kept: Vec<&str> = text.lines().filter(|l| !assigns(l)).collect();
    let removed = text.lines().count() - kept.len();
    if removed > 0 {
        let mut out = kept.join("\n");
        if !out.is_empty() {
            out.push('\n');
        }
        std::fs::write(path, out).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    Ok(removed)
}

fn plant(args: &[String]) -> Response {
    let provider = crate::cli_extra::flag(args, "--for").unwrap_or("openai");
    let Some(shape) = kepr_core::canary::shape(provider) else {
        let all = kepr_core::canary::supported().join(", ");
        return Response::fail(format!("no decoy format for `{provider}` (one of: {all})"));
    };
    let name = crate::cli_extra::flag(args, "--name")
        .unwrap_or(shape.var)
        .to_uppercase();
    let path = match crate::cli_extra::flag(args, "--in").map(target).transpose() {
        Ok(p) => p,
        Err(e) => return Response::fail(e),
    };
    let r = super::send(PolicyRequest::CanaryPlant {
        name: name.clone(),
        provider: provider.to_string(),
        planted_in: path.as_ref().map(|p| p.display().to_string()),
    });
    let Response::Policy(PolicyResponse::CanaryPlanted { value, trip_id, .. }) = r else {
        return r;
    };
    let mut msg = format!("{name}: a decoy {provider} key is stored");
    if let Some(p) = &path {
        if let Err(e) = append(p, &line_for(p, &name, &value)) {
            let _ = super::send(PolicyRequest::CanaryRemove { name });
            return Response::fail(format!("could not plant it: {e} (canary removed)"));
        }
        msg = format!(
            "{name}: a decoy {provider} key is planted in {}",
            p.display()
        );
    }
    super::done(format!(
        "{msg}; reading it, using it through an agent gate or its webhook (/kepr-canary/{trip_id}) logs `canary-tripped` (alert on it: kepr alerts)"
    ))
}

fn table(rows: &[CanaryEntry]) -> Vec<String> {
    let wn = rows.iter().map(|r| r.name.len()).max().unwrap_or(0).max(4);
    let mut out = vec![format!(
        "{:wn$}  {:10}  {:>7}  {:16}  PLANTED IN",
        "NAME", "PROVIDER", "TRIPPED", "LAST TRIPPED"
    )];
    for r in rows {
        out.push(format!(
            "{:wn$}  {:10}  {:>7}  {:16}  {}",
            r.name,
            r.provider,
            r.tripped,
            r.last_tripped.as_deref().unwrap_or("never"),
            r.planted_in.as_deref().unwrap_or("(vault only)")
        ));
    }
    out
}

fn ls() -> Response {
    let r = super::send(PolicyRequest::CanaryList);
    if let (false, Response::Policy(PolicyResponse::CanaryListing { canaries })) =
        (crate::cli_mode::json_mode(), &r)
    {
        if canaries.is_empty() {
            crate::cli_ui::info("no canaries; plant one with kepr canary plant --in .env");
        }
        for line in table(canaries).iter().filter(|_| !canaries.is_empty()) {
            println!("{line}");
        }
    }
    r
}

fn rm(name: &str) -> Response {
    let r = super::send(PolicyRequest::CanaryRemove {
        name: name.to_uppercase(),
    });
    let Response::Policy(PolicyResponse::CanaryRemoved { name, planted_in }) = r else {
        return r;
    };
    let Some(p) = planted_in.map(PathBuf::from) else {
        return super::done(format!("{name}: canary removed"));
    };
    match remove_lines(&p, &name) {
        Ok(n) if n > 0 => super::done(format!(
            "{name}: canary removed, and its line in {}",
            p.display()
        )),
        Ok(_) => super::done(format!(
            "{name}: canary removed ({} no longer has it)",
            p.display()
        )),
        Err(e) => super::done(format!(
            "{name}: canary removed; remove its line yourself ({e})"
        )),
    }
}

/// The answer to one webhook call; `trip` reports a trip id to the daemon.
pub fn webhook(method: &str, path: &str, trip: &dyn Fn(&str) -> bool) -> (u16, &'static str) {
    if method != "POST" && method != "GET" {
        return (405, "method not allowed");
    }
    let id = path.strip_prefix("/kepr-canary/").unwrap_or_default();
    let id = id.split(['?', '#']).next().unwrap_or_default();
    let valid = id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit());
    match valid && trip(id) {
        true => (200, "ok"),
        false => (404, "not found"),
    }
}

fn listen(args: &[String]) -> Result<(), String> {
    let addr = crate::cli_extra::flag(args, "--listen").ok_or("needs --listen ADDR:PORT")?;
    let l = std::net::TcpListener::bind(addr).map_err(|e| format!("listen {addr}: {e}"))?;
    if !crate::cli_mode::json_mode() {
        crate::cli_ui::info(&format!(
            "canary webhooks: http://{addr}/kepr-canary/<trip id> (Ctrl-C stops)"
        ));
    }
    let trip = |id: &str| {
        let r = super::send(PolicyRequest::CanaryTrip {
            trip_id: id.to_string(),
        });
        r.is_success()
    };
    for mut s in l.incoming().flatten() {
        let (method, path) = request_line(&mut s);
        let (status, text) = webhook(&method, &path, &trip);
        reply(&mut s, status, text);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("kepr-canary-cli-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d.join(name)
    }

    #[test]
    fn planted_lines_match_the_file_and_come_out_again() {
        let env = tmp(".env");
        std::fs::write(&env, "DEBUG=1").unwrap();
        append(&env, &line_for(&env, "OPENAI_API_KEY", "sk-proj-x")).unwrap();
        assert_eq!(
            std::fs::read_to_string(&env).unwrap(),
            "DEBUG=1\nOPENAI_API_KEY=sk-proj-x\n"
        );
        let rc = tmp(".bashrc");
        let _ = std::fs::remove_file(&rc);
        append(&rc, &line_for(&rc, "XAI_API_KEY", "xai-y")).unwrap();
        assert_eq!(
            std::fs::read_to_string(&rc).unwrap(),
            "export XAI_API_KEY='xai-y'\n"
        );
        assert_eq!(remove_lines(&env, "OPENAI_API_KEY").unwrap(), 1);
        assert_eq!(std::fs::read_to_string(&env).unwrap(), "DEBUG=1\n");
        assert_eq!(remove_lines(&rc, "XAI_API_KEY").unwrap(), 1);
        assert_eq!(remove_lines(&rc, "XAI_API_KEY").unwrap(), 0);
        // Only the exact name: XAI_API_KEY_2 stays.
        std::fs::write(&env, "XAI_API_KEY_2=a\n").unwrap();
        assert_eq!(remove_lines(&env, "XAI_API_KEY").unwrap(), 0);
        let dir = tmp("");
        assert_eq!(target(dir.to_str().unwrap()).unwrap(), dir.join(".env"));
    }

    #[test]
    fn webhooks_trip_only_known_ids() {
        let id = "0123456789abcdef0123456789abcdef";
        let trip = |t: &str| t == id;
        assert_eq!(
            webhook("POST", &format!("/kepr-canary/{id}"), &trip),
            (200, "ok")
        );
        assert_eq!(
            webhook("GET", &format!("/kepr-canary/{id}?x=1"), &trip).0,
            200
        );
        assert_eq!(
            webhook(
                "POST",
                "/kepr-canary/ffffffffffffffffffffffffffffffff",
                &trip
            )
            .0,
            404
        );
        assert_eq!(webhook("POST", "/kepr-canary/../etc", &trip).0, 404);
        assert_eq!(
            webhook("DELETE", &format!("/kepr-canary/{id}"), &trip).0,
            405
        );
    }

    #[test]
    fn the_table_shows_trips() {
        let e = CanaryEntry {
            name: "OPENAI_API_KEY".into(),
            provider: "openai".into(),
            planted_in: Some("/home/a/.env".into()),
            created: "2026-10-08 00:00".into(),
            trip_id: "ab".into(),
            fingerprint: String::new(),
            tripped: 2,
            last_tripped: Some("2026-10-08 01:00".into()),
        };
        let t = table(&[e]);
        assert!(
            t[1].contains("openai")
                && t[1].contains("2026-10-08 01:00")
                && t[1].ends_with("/home/a/.env"),
            "{}",
            t[1]
        );
        assert!(matches!(
            cmd_canary(&["plant".into(), "--for".into(), "nope".into()]),
            Response::Err { .. }
        ));
    }
}
