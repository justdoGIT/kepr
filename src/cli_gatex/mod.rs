// cli_gatex/ — the gate batch's CLI pieces (P7 PAM-lite, P11.22): flags
// `kepr agent run` passes on to the gate session, and the `kepr agent`
// subcommands added by the batch. No top-level verbs of its own; the help
// lines below are appended to `kepr --help`.

pub mod grant;
pub mod logs;
pub mod mysql_login;
pub mod pg_script;
pub mod replay;
pub mod tunnel;

use kepr_core::protocol::Response;

pub const VERBS: &[&str] = &[];

pub const HELP: &str = concat!(
    "  agent run HARNESS --tunnel NAME=HOST:PORT  loopback port piped to an internal host (no credential)\n",
    "  agent run HARNESS --grant NAME=ROLE:ADMIN  PostgreSQL role held only for the session (ADMIN grants it)\n",
    "  agent run HARNESS --record      keep what the agent sends and receives, encrypted (never keys)\n",
    "  agent replay [SESSION]          list recorded sessions, or print one\n",
    "  agent replay SESSION --typescript FILE --timing FILE  its PostgreSQL traffic for scriptreplay\n",
    "  agent logs [SESSION] [-n N] [--follow]  the gate's request journal (method, host, path, status)\n",
);

pub fn dispatch(verb: &str, _args: &[String]) -> Response {
    Response::fail(format!("unknown command: {verb}"))
}

/// The batch's own `kepr agent` subcommands, or `None` for the others.
pub fn agent_verb(raw: &[String]) -> Option<Response> {
    match raw.first()?.as_str() {
        "replay" => Some(replay::main(&raw[1..])),
        "logs" => Some(logs::main(&raw[1..])),
        _ => None,
    }
}

/// `kepr agent run` flags handled here (kept out of cli_agent_cmd.rs,
/// which is near its size limit).
#[derive(Debug, Default, PartialEq)]
pub struct SessionOpts {
    /// `--tunnel NAME=host:port` (T7.03), as given.
    pub tunnels: Vec<String>,
    /// `--grant NAME=ROLE:ADMIN` (T7.18), as given.
    pub grants: Vec<String>,
    /// `--record` (T7.09).
    pub record: bool,
}

impl SessionOpts {
    pub const FLAGS: &'static [&'static str] = &["--tunnel", "--grant", "--record"];

    /// Take the flag at `raw[i]` (one of FLAGS); returns the index of
    /// the last argument consumed.
    pub fn take(&mut self, raw: &[String], i: usize) -> Result<usize, String> {
        let value = |what: &str| {
            raw.get(i + 1)
                .cloned()
                .ok_or_else(|| format!("{} needs {what}", raw[i]))
        };
        match raw[i].as_str() {
            "--tunnel" => self.tunnels.push(value("NAME=HOST:PORT")?),
            "--grant" => self.grants.push(value("NAME=ROLE:ADMIN")?),
            "--record" => {
                self.record = true;
                return Ok(i);
            }
            other => return Err(format!("unexpected argument: {other}")),
        }
        Ok(i + 1)
    }

    /// Tell the user, on stderr, what `kepr agent run` set up for them.
    pub fn announce(&self, session: Option<&str>) {
        if let (true, Some(id)) = (self.record, session) {
            crate::cli_ui::einfo(&format!(
                "recording this session (encrypted); replay it with: kepr agent replay {id}"
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn takes_session_flags() {
        let raw: Vec<String> = ["--tunnel", "WIKI=wiki.example.com:80"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let mut o = SessionOpts::default();
        assert_eq!(o.take(&raw, 0), Ok(1));
        assert_eq!(o.tunnels, vec!["WIKI=wiki.example.com:80"]);
        assert!(o.take(&raw[..1], 0).is_err());
        let raw: Vec<String> = vec!["--grant".into(), "APP_DB=analyst:APP_ADMIN".into()];
        assert_eq!(o.take(&raw, 0), Ok(1));
        assert_eq!(o.grants, vec!["APP_DB=analyst:APP_ADMIN"]);
        let raw: Vec<String> = vec!["--record".into(), "--tunnel".into()];
        assert_eq!(o.take(&raw, 0), Ok(0), "--record takes no value");
        assert!(o.record);
        assert!(HELP.lines().all(|l| l.starts_with("  ")));
    }
}
