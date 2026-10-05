// cli_gatex/ — the gate batch's CLI pieces (P7 PAM-lite, P11.22): flags
// `kepr agent run` passes on to the gate session, and the `kepr agent`
// subcommands added by the batch. No top-level verbs of its own; the help
// lines below are appended to `kepr --help`.

pub mod tunnel;

use kepr_core::protocol::Response;

pub const VERBS: &[&str] = &[];

pub const HELP: &str =
    "  agent run HARNESS --tunnel NAME=HOST:PORT  loopback port piped to an internal host (no credential)\n";

pub fn dispatch(verb: &str, _args: &[String]) -> Response {
    Response::fail(format!("unknown command: {verb}"))
}

/// `kepr agent run` flags handled here (kept out of cli_agent_cmd.rs,
/// which is near its size limit).
#[derive(Debug, Default, PartialEq)]
pub struct SessionOpts {
    /// `--tunnel NAME=host:port` (T7.03), as given.
    pub tunnels: Vec<String>,
}

impl SessionOpts {
    pub const FLAGS: &'static [&'static str] = &["--tunnel"];

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
            other => return Err(format!("unexpected argument: {other}")),
        }
        Ok(i + 1)
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
        assert!(HELP.lines().all(|l| l.starts_with("  ")));
        assert!(VERBS.is_empty());
    }
}
