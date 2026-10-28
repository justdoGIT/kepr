// cli_agent_doctor.rs — `kepr agent doctor [--port N] [--json]` (T12.16).
// For the harnesses `kepr agent install` configures through a file (omp,
// Grok Build): does the config still route through the gate on PORT, and
// is kepr's plugin installed and current? Every problem names its fix,
// and any problem makes the exit code non-zero (Response::CheckOk, as
// `kepr doctor`). Config files are only read, and only their paths are
// printed: a harness config can hold a key. Harnesses configured through
// the environment alone (claude, codex, grok-cli, aider) have no file.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use kepr_core::protocol::Response;

use crate::cli_agent_adapters::INSTALL_PORT;
use crate::cli_agent_install::{upsert_grok, upsert_omp};
use crate::cli_agent_plugin::{plugin_for, plugin_state, PluginState};
use crate::cli_ui;

const USAGE: &str = "usage: kepr agent doctor [--port N] [--json]";

type Upsert = fn(&str, u16) -> String;

/// (harness, config file under HOME, kepr's edit of it)
const HARNESSES: &[(&str, &str, Upsert)] = &[
    ("omp", ".omp/agent/models.yml", upsert_omp),
    ("grok", ".grok/config.toml", upsert_grok),
];

pub enum Check {
    Ok(String),
    Problem(String),
    NotInstalled,
}

/// Configured iff kepr's own edit would leave the file as it is (the
/// edits end a file with one newline, so a missing one isn't drift).
fn check_config(text: Option<&str>, port: u16, upsert: Upsert) -> Check {
    let Some(text) = text else {
        return Check::NotInstalled;
    };
    if upsert(text, port).trim_end() == text.trim_end() {
        Check::Ok(format!("routes through the gate on port {port}"))
    } else {
        Check::Problem(format!("does not route through the gate on port {port}"))
    }
}

fn read_config(path: &Path, port: u16, upsert: Upsert) -> Check {
    match std::fs::read_to_string(path) {
        Ok(t) => check_config(Some(&t), port, upsert),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Check::NotInstalled,
        Err(e) => Check::Problem(format!("cannot be read ({})", e.kind())),
    }
}

pub struct Report {
    pub harness: &'static str,
    port: u16,
    config_path: PathBuf,
    config: Check,
    plugin_dir: PathBuf,
    plugin: PluginState,
    /// grok only: whether `grok plugin list` shows kepr; None when grok
    /// isn't on PATH (a note, not a problem).
    registered: Option<bool>,
}

impl Report {
    fn installed(&self) -> bool {
        !matches!(self.config, Check::NotInstalled) || self.plugin != PluginState::Missing
    }

    fn fix(&self) -> String {
        match self.port {
            INSTALL_PORT => format!("kepr agent install {}", self.harness),
            p => format!("kepr agent install {} --port {p}", self.harness),
        }
    }

    /// What's wrong, each with its fix; nothing for a harness not set up.
    pub fn problems(&self) -> Vec<String> {
        if !self.installed() {
            return Vec::new();
        }
        let mut p = Vec::new();
        let (cfg, dir) = (self.config_path.display(), self.plugin_dir.display());
        match &self.config {
            Check::Problem(m) => p.push(format!("{cfg} {m}")),
            Check::NotInstalled => p.push(format!("{cfg} is missing")),
            Check::Ok(_) => {}
        }
        match self.plugin {
            PluginState::Missing => p.push(format!("kepr plugin missing ({dir})")),
            PluginState::Stale => p.push(format!("kepr plugin out of date ({dir})")),
            PluginState::Current => {}
        }
        if self.registered == Some(false) {
            p.push("grok does not list the kepr plugin (grok plugin list)".into());
        }
        let fix = self.fix();
        p.into_iter().map(|m| format!("{m} — fix: {fix}")).collect()
    }

    fn render(&self) {
        let h = self.harness;
        if !self.installed() {
            return cli_ui::info(&format!("{h}: not installed"));
        }
        if let Check::Ok(m) = &self.config {
            cli_ui::ok(&format!("{h}: {} {m}", self.config_path.display()));
        }
        if self.plugin == PluginState::Current {
            let dir = self.plugin_dir.display();
            cli_ui::ok(&format!("{h}: kepr plugin current ({dir})"));
        }
        match (h, self.registered) {
            ("grok", Some(true)) => cli_ui::ok("grok: kepr plugin registered"),
            ("grok", None) => cli_ui::info("grok: grok not on PATH; registration not checked"),
            _ => {}
        }
        for p in self.problems() {
            cli_ui::err(&format!("{h}: {p}"));
        }
    }
}

pub fn reports(home: &Path, port: u16, grok_lists: &dyn Fn() -> Option<bool>) -> Vec<Report> {
    HARNESSES
        .iter()
        .filter_map(|&(harness, rel, upsert)| {
            let (dir, files) = plugin_for(harness)?;
            let mut r = Report {
                harness,
                port,
                config_path: home.join(rel),
                config: read_config(&home.join(rel), port, upsert),
                plugin_dir: home.join(dir),
                plugin: plugin_state(&home.join(dir), files),
                registered: None,
            };
            if harness == "grok" && r.installed() {
                r.registered = grok_lists();
            }
            Some(r)
        })
        .collect()
}

/// One entry per harness: "ok", "not installed" or "problem: …".
pub fn results(reports: &[Report]) -> HashMap<String, String> {
    reports
        .iter()
        .map(|r| {
            let p = r.problems();
            let v = match (r.installed(), p.is_empty()) {
                (false, _) => "not installed".to_string(),
                (true, true) => "ok".to_string(),
                (true, false) => format!("problem: {}", p.join("; ")),
            };
            (r.harness.to_string(), v)
        })
        .collect()
}

fn parse(raw: &[String]) -> Result<(u16, bool), String> {
    let (mut port, mut json) = (INSTALL_PORT, false);
    let mut it = raw.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--port" => {
                port = it
                    .next()
                    .and_then(|p| p.parse().ok())
                    .filter(|p| *p > 0)
                    .ok_or("--port must be 1-65535")?;
            }
            "--json" => json = true,
            other => return Err(format!("unexpected argument: {other}\n{USAGE}")),
        }
    }
    Ok((port, json))
}

pub fn cmd_doctor(raw: &[String]) -> Response {
    let (port, json) = match parse(raw) {
        Ok(v) => v,
        Err(e) => return Response::fail(e),
    };
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return Response::fail("HOME is not set");
    };
    let reports = reports(&home, port, &crate::cli_agent_plugin::grok_lists_kepr);
    if !(json || cli_ui::json_mode()) {
        reports.iter().for_each(Report::render);
    }
    let results = results(&reports);
    Response::CheckOk {
        count: results.len(),
        all_ok: reports.iter().all(|r| r.problems().is_empty()),
        results,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli_agent_install::{upsert_grok, upsert_omp};

    fn is_ok(c: &Check) -> bool {
        matches!(c, Check::Ok(_))
    }
    fn is_problem(c: &Check) -> bool {
        matches!(c, Check::Problem(_))
    }

    #[test]
    fn configs_route_through_the_gate_or_not() {
        for upsert in [upsert_omp as fn(&str, u16) -> String, upsert_grok] {
            let good = upsert("", 7878);
            assert!(is_ok(&check_config(Some(&good), 7878, upsert)));
            assert!(is_problem(&check_config(Some(&good), 9000, upsert)));
            let moved = good.replace("127.0.0.1:7878", "127.0.0.1:7879");
            assert!(is_problem(&check_config(Some(&moved), 7878, upsert)));
            let elsewhere = good.replace("http://127.0.0.1:7878", "https://api.example");
            assert!(is_problem(&check_config(Some(&elsewhere), 7878, upsert)));
            assert!(is_problem(&check_config(Some("other = 1\n"), 7878, upsert)));
            assert!(matches!(
                check_config(None, 7878, upsert),
                Check::NotInstalled
            ));
        }
    }

    #[test]
    fn problems_carry_the_fix_and_never_file_contents() {
        let home = std::env::temp_dir().join(format!("kepr-adoc-{}", std::process::id()));
        let omp = home.join(".omp/agent/models.yml");
        std::fs::create_dir_all(omp.parent().unwrap()).unwrap();
        std::fs::write(
            &omp,
            "providers:\n  mine:\n    apiKey: sk-ant-api03-SECRET\n",
        )
        .unwrap();
        let r = reports(&home, 7878, &|| None);
        let omp_r = r.iter().find(|r| r.harness == "omp").unwrap();
        let p = omp_r.problems();
        assert!(
            p.iter().any(|m| m.contains("kepr agent install omp")),
            "{p:?}"
        );
        assert!(p.iter().all(|m| !m.contains("SECRET")));
        assert!(p.iter().any(|m| m.contains("plugin")), "{p:?}");
        let grok_r = r.iter().find(|r| r.harness == "grok").unwrap();
        assert!(grok_r.problems().is_empty(), "grok isn't installed here");
        std::fs::remove_dir_all(&home).unwrap();
    }

    #[test]
    fn healthy_harness_and_one_json_entry_each() {
        let home = std::env::temp_dir().join(format!("kepr-adoc2-{}", std::process::id()));
        let omp = home.join(".omp/agent/models.yml");
        crate::cli_agent_install::apply(&omp, |t| upsert_omp(t, 7878)).unwrap();
        crate::cli_agent_plugin::install("omp", &home).unwrap();
        let grok = home.join(".grok/config.toml");
        crate::cli_agent_install::apply(&grok, |t| upsert_grok(t, 7878)).unwrap();
        let (dir, files) = crate::cli_agent_plugin::plugin_for("grok").unwrap();
        crate::cli_agent_plugin::write_plugin(&home.join(dir), files).unwrap();
        // grok lists no kepr plugin: a problem; grok not on PATH: a note.
        let r = reports(&home, 7878, &|| Some(false));
        let res = results(&r);
        assert_eq!(res.len(), 2);
        assert_eq!(res["omp"], "ok");
        assert!(res["grok"].starts_with("problem: ") && res["grok"].contains("grok plugin"));
        let r = reports(&home, 7878, &|| None);
        assert_eq!(results(&r)["grok"], "ok");
        assert!(r.iter().all(|r| r.problems().is_empty()));
        let none = reports(&home.join("nobody"), 7878, &|| None);
        let res = results(&none);
        assert_eq!(
            (res["omp"].as_str(), res["grok"].as_str()),
            ("not installed", "not installed")
        );
        std::fs::remove_dir_all(&home).unwrap();
    }

    #[test]
    fn parses_port_and_json() {
        assert_eq!(parse(&[]).unwrap(), (7878, false));
        let a: Vec<String> = ["--port", "9000", "--json"].map(String::from).into();
        assert_eq!(parse(&a).unwrap(), (9000, true));
        assert!(parse(&["--port".to_string()]).is_err());
        assert!(parse(&["x".to_string()]).is_err());
    }
}
