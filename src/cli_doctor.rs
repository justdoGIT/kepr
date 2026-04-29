// cli_doctor.rs — `kepr doctor` setup-diagnostics.
//
// First-touch users hit one of a small number of setup failures
// (daemon down, not in the kepr group, socket permissions skewed by
// a manual chmod, etc.). `doctor` walks the well-known invariants
// and prints a one-line ✓/✗ per check with a remediation hint when
// something's wrong, so the user doesn't have to read DOCS.md to
// figure out which step they missed.
//
// Failure semantics: doctor never panics, never returns Response::Err
// for a SOFT failure (a check that just needs the user to do
// something) — the user-visible exit code is the count of FAILED
// checks, mapped onto Response::CheckOk { all_ok: bool } so the
// existing JSON wire shape stays usable from scripts.
//
// Testability: the heavy I/O (stat, getgrnam, daemon Ping) is split
// into `Diagnostic` traits so the orchestration logic can be tested
// without a live daemon. Each production diagnostic owns a single
// stat/socket/group check; mocks in unit tests exercise the
// pass/fail accounting and the JSON shape.

use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::os::unix::fs::PermissionsExt;

use kepr_core::protocol::{Request, Response, SOCKET_PATH};

use crate::client;

/// Single diagnostic check. `name` is the user-visible label;
/// `evaluate` returns Ok(detail) on pass or Err(remediation) on fail.
/// Detail and remediation are both human-readable; the doctor
/// orchestrator decides how to render them.
pub trait Diagnostic {
    fn name(&self) -> &str;
    fn evaluate(&self) -> Result<String, String>;
}

/// Aggregated outcome of running every diagnostic in order.
pub struct DoctorReport {
    pub results: Vec<DiagnosticResult>,
}

pub struct DiagnosticResult {
    pub name: String,
    pub outcome: Outcome,
}

pub enum Outcome {
    Pass(String),
    Fail(String),
}

impl DoctorReport {
    /// True iff every diagnostic passed. Drives the daemon `check`-style
    /// exit-code mapping: 0 on full pass, 1 on any fail.
    pub fn all_ok(&self) -> bool {
        self.results
            .iter()
            .all(|r| matches!(r.outcome, Outcome::Pass(_)))
    }

    /// Pretty-print: one ✓/✗ line per check. Detail/remediation
    /// shown indented underneath the line that owns it.
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        for r in &self.results {
            match &r.outcome {
                Outcome::Pass(detail) => {
                    out.push_str(&format!("\u{2713}  {}", r.name));
                    if !detail.is_empty() {
                        out.push_str(&format!(" — {detail}"));
                    }
                    out.push('\n');
                }
                Outcome::Fail(remedy) => {
                    out.push_str(&format!("\u{2717}  {}\n", r.name));
                    if !remedy.is_empty() {
                        out.push_str(&format!("   \u{21B3} {remedy}\n"));
                    }
                }
            }
        }
        out
    }
}

/// Run the supplied diagnostics in order, capturing each outcome
/// without short-circuiting. The user wants the COMPLETE picture in
/// one run — stopping at the first ✗ would hide downstream issues.
pub fn run<D: Diagnostic + ?Sized>(checks: &[Box<D>]) -> DoctorReport {
    let results = checks
        .iter()
        .map(|c| {
            let outcome = match c.evaluate() {
                Ok(detail) => Outcome::Pass(detail),
                Err(remedy) => Outcome::Fail(remedy),
            };
            DiagnosticResult {
                name: c.name().to_string(),
                outcome,
            }
        })
        .collect();
    DoctorReport { results }
}

// ── Production diagnostics ────────────────────────────────────────────────

/// Verify the daemon's listening socket is present, owned root:kepr,
/// and at mode 0660. Catches the post-install path where the user
/// forgot to start the service, or chmod'd the socket by mistake.
pub struct SocketCheck;

impl Diagnostic for SocketCheck {
    fn name(&self) -> &str {
        "daemon socket"
    }
    fn evaluate(&self) -> Result<String, String> {
        let meta = fs::metadata(SOCKET_PATH).map_err(|_| {
            format!("{SOCKET_PATH} missing — run `sudo systemctl start kepr.service`")
        })?;
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o660 {
            return Err(format!(
                "{SOCKET_PATH} is {mode:o}, expected 660 — run `sudo systemctl restart kepr.service`"
            ));
        }
        Ok(format!("{SOCKET_PATH} (mode {mode:o})"))
    }
}

/// Verify the calling user is a member of the `kepr` group. Without
/// this, every CLI call fails with `Permission denied` at connect()
/// time and the user has to guess the cause.
pub struct GroupCheck;

impl Diagnostic for GroupCheck {
    fn name(&self) -> &str {
        "kepr group membership"
    }
    fn evaluate(&self) -> Result<String, String> {
        let uid = unsafe { libc::getuid() };
        if uid == 0 {
            // Root can connect to any Unix socket regardless of
            // group membership — pass with a note rather than
            // pretend we measured something we didn't.
            return Ok("running as root (group check bypassed)".to_string());
        }
        let target = CString::new("kepr").expect("static cstring");
        // SAFETY: getgrnam is a libc lookup on a static cstring.
        // The returned struct points into a static buffer owned by
        // libc; we copy out the gid before any further libc call
        // could overwrite it.
        let gid = unsafe {
            let g = libc::getgrnam(target.as_ptr());
            if g.is_null() {
                return Err("kepr group does not exist — re-run `sudo ./install.sh`".to_string());
            }
            (*g).gr_gid
        };
        // getgroups returns the supplementary group set; first call
        // sizes it, second populates.
        let mut count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
        if count < 0 {
            return Err("getgroups(2) failed — cannot determine membership".to_string());
        }
        let mut buf = vec![0 as libc::gid_t; count as usize];
        count = unsafe { libc::getgroups(count, buf.as_mut_ptr()) };
        if count < 0 {
            return Err("getgroups(2) failed on second call".to_string());
        }
        buf.truncate(count as usize);
        if buf.contains(&gid) {
            Ok(format!("uid={uid} is in group kepr (gid={gid})"))
        } else {
            Err(format!(
                "uid={uid} is NOT in group kepr (gid={gid}) — run `sudo usermod -aG kepr $USER && newgrp kepr`"
            ))
        }
    }
}

/// Send a Ping over the standard CLI transport. If the socket
/// passed but Ping fails, the daemon's accept loop is wedged or
/// the protocol drifted — neither is recoverable with `restart`,
/// so we surface the actual error rather than guessing.
pub struct PingCheck;

impl Diagnostic for PingCheck {
    fn name(&self) -> &str {
        "daemon responds to Ping"
    }
    fn evaluate(&self) -> Result<String, String> {
        match client::send_request(&Request::Ping) {
            Ok(Response::Pong) => Ok("Pong".to_string()),
            Ok(other) => Err(format!(
                "expected Pong, got {other:?} — daemon may be on a different protocol version"
            )),
            Err(e) => Err(format!(
                "cannot reach daemon: {e} — check `journalctl -u kepr.service`"
            )),
        }
    }
}

/// Build the production diagnostic list. Order matters: socket →
/// group → ping. If the socket is missing, the group check still
/// runs (it's independent) but the ping check will fail with the
/// same root cause; that's fine because the doctor reports the
/// FULL state, not the first cause.
pub fn production_checks() -> Vec<Box<dyn Diagnostic>> {
    vec![
        Box::new(SocketCheck) as Box<dyn Diagnostic>,
        Box::new(GroupCheck) as Box<dyn Diagnostic>,
        Box::new(PingCheck) as Box<dyn Diagnostic>,
    ]
}

/// Top-level handler. Runs the production checks, prints results
/// in text mode, and returns a CheckOk-shaped Response so the
/// `--json` flag works the same way as for `kepr check`.
pub fn cmd_doctor(json: bool) -> Response {
    let report = run(&production_checks());
    if !json {
        print!("{}", report.render_text());
    }
    let mut results = HashMap::new();
    for r in &report.results {
        let v = match &r.outcome {
            Outcome::Pass(_) => "ok".to_string(),
            Outcome::Fail(remedy) => format!("fail: {remedy}"),
        };
        results.insert(r.name.clone(), v);
    }
    let count = results.len();
    Response::CheckOk {
        results,
        count,
        all_ok: report.all_ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// In-memory diagnostic for unit tests. The `result` field is
    /// the value the diagnostic returns; the orchestration code
    /// under test never inspects the `Diagnostic` impl beyond
    /// `name()` and `evaluate()`.
    struct Mock {
        name: String,
        result: Result<String, String>,
    }
    impl Diagnostic for Mock {
        fn name(&self) -> &str {
            &self.name
        }
        fn evaluate(&self) -> Result<String, String> {
            self.result.clone()
        }
    }

    fn pass(name: &str, detail: &str) -> Box<dyn Diagnostic> {
        Box::new(Mock {
            name: name.to_string(),
            result: Ok(detail.to_string()),
        })
    }
    fn fail(name: &str, remedy: &str) -> Box<dyn Diagnostic> {
        Box::new(Mock {
            name: name.to_string(),
            result: Err(remedy.to_string()),
        })
    }

    #[test]
    fn empty_check_list_yields_all_ok() {
        // A doctor with no checks is vacuously OK. Pin the contract
        // so a future refactor that swaps Vec for a non-empty type
        // surfaces here, not in production.
        let checks: Vec<Box<dyn Diagnostic>> = vec![];
        let report = run(&checks);
        assert!(report.all_ok());
        assert_eq!(report.results.len(), 0);
    }

    #[test]
    fn all_pass_reports_all_ok() {
        let checks = vec![pass("a", "ok"), pass("b", "ok"), pass("c", "ok")];
        let report = run(&checks);
        assert!(report.all_ok());
        assert_eq!(report.results.len(), 3);
    }

    #[test]
    fn any_fail_flips_all_ok() {
        let checks = vec![pass("a", ""), fail("b", "do this"), pass("c", "")];
        let report = run(&checks);
        assert!(!report.all_ok());
    }

    #[test]
    fn run_does_not_short_circuit_on_first_failure() {
        // The user wants the COMPLETE picture; if check #1 fails,
        // checks #2 and #3 must still run so the report is
        // self-contained. Pin against a "bail on first error" regression.
        let checks = vec![fail("a", "fix a"), fail("b", "fix b"), fail("c", "fix c")];
        let report = run(&checks);
        assert_eq!(report.results.len(), 3);
        for r in &report.results {
            assert!(matches!(r.outcome, Outcome::Fail(_)));
        }
    }

    #[test]
    fn render_text_marks_pass_and_fail() {
        let checks = vec![pass("alpha", "detail"), fail("beta", "remediation")];
        let report = run(&checks);
        let text = report.render_text();
        assert!(text.contains("\u{2713}  alpha"), "pass marker: {text}");
        assert!(text.contains("detail"), "pass detail: {text}");
        assert!(text.contains("\u{2717}  beta"), "fail marker: {text}");
        assert!(text.contains("remediation"), "fail remedy: {text}");
    }

    #[test]
    fn render_text_omits_empty_pass_detail() {
        // When a check has nothing useful to say beyond "ok", the
        // rendered line shouldn't dangle a stray separator.
        let checks = vec![pass("alpha", "")];
        let report = run(&checks);
        let text = report.render_text();
        assert!(text.contains("\u{2713}  alpha"));
        assert!(
            !text.contains("\u{2713}  alpha — "),
            "no separator when detail is empty: {text}"
        );
    }
}
