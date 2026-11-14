//! Operator-side snapshots, review, and one-use approved export.

mod capture;
mod export;
mod files;
pub(crate) mod io;
pub(crate) mod launch;
mod paths;
mod review;
mod runtime_config;
mod screen;
pub(crate) mod session;

use kepr_core::protocol::Response;
use kepr_core::workspace::WorkspaceResponse;
use std::path::Path;

pub const VERBS: &[&str] = &["workspace"];
pub const HELP: &str = "  workspace prepare SOURCE [--file PATH ...]  copy a safe source tree or explicit inputs to a private session\n  workspace review SESSION                       create a local patch and approval digest\n  workspace export SESSION --approve DIGEST --output NEW_DIRECTORY\n";
const USAGE: &str = "usage: kepr workspace prepare SOURCE [--file PATH ...] | review SESSION | export SESSION --approve DIGEST --output NEW_DIRECTORY";

pub(crate) fn validate_session(id: &str) -> Result<(), &'static str> {
    paths::session_id(id)
}

pub(crate) fn prepare_source(raw: &str) -> Result<String, String> {
    let requested = Path::new(raw);
    let source = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| "workspace current directory unavailable".to_string())?
            .join(requested)
    };
    match session::prepare(&source, &[]).map_err(str::to_owned)? {
        WorkspaceResponse::WorkspacePreparedOk { session, .. } => Ok(session),
        _ => Err("workspace preparation returned an unexpected response".into()),
    }
}

fn execute(args: &[&str]) -> Result<WorkspaceResponse, &'static str> {
    if std::env::var_os("KEPR_AGENT_HARNESS").is_some() {
        return Err("workspace prepare, review and export require an operator terminal");
    }
    match args {
        ["prepare", source, rest @ ..] => {
            if rest.len() % 2 != 0 {
                return Err(USAGE);
            }
            let mut files = Vec::new();
            for pair in rest.as_chunks::<2>().0 {
                if pair[0] != "--file" {
                    return Err(USAGE);
                }
                files.push(pair[1]);
            }
            session::prepare(Path::new(source), &files)
        }
        ["review", id] => review::review(id),
        ["export", id, "--approve", digest, "--output", output] => {
            export::export(id, digest, Path::new(output))
        }
        _ => Err(USAGE),
    }
}

pub fn dispatch(_verb: &str, args: &[String]) -> Response {
    let args: Vec<_> = args
        .iter()
        .map(String::as_str)
        .filter(|s| !matches!(*s, "--json" | "--color" | "--no-color"))
        .collect();
    match execute(&args) {
        Ok(report) => {
            if !crate::cli_ui::json_mode() {
                show(&report);
            }
            Response::Workspace(Box::new(report))
        }
        Err(error) => Response::fail(error),
    }
}

fn show(report: &WorkspaceResponse) {
    match report {
        WorkspaceResponse::WorkspacePreparedOk {
            session,
            workspace,
            files,
            skipped,
        } => {
            println!("workspace session: {session}; copied files: {files}; skipped uninspectable files: {skipped}\nworkspace: {workspace}");
        }
        WorkspaceResponse::WorkspaceReviewOk { report } => {
            for change in &report.changes {
                println!("{:?} {}", change.action, change.path);
            }
            println!(
                "review patch: {}\napproval digest: {}\nexpires at Unix time: {}",
                report.patch_file, report.digest, report.expires_at
            );
        }
        WorkspaceResponse::WorkspaceExportedOk { output, digest, .. } => {
            println!("workspace bundle: {output}\napproved digest: {digest}");
        }
    }
}
