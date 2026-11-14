//! Host-side lifecycle owns export authority while the namespace tree runs.

use super::{
    capture, runtime_config,
    session::{Phase, Session},
};
use crate::cli_agent_sandbox;
use crate::cli_sandbox_workspace::WorkspaceMounts;

pub(crate) struct PreparedLaunch {
    session: Session,
    mounts: WorkspaceMounts,
    pub(crate) argv: Vec<String>,
}

fn empty(dir: &super::io::Dir) -> Result<(), &'static str> {
    let mut entries = std::fs::read_dir(dir.descriptor_path())
        .map_err(|_| "private workspace runtime cannot be inspected")?;
    if entries.next().is_some() {
        return Err("private workspace home, tmp and config must be fresh");
    }
    Ok(())
}

pub(crate) fn prepare(id: &str, argv: &[String]) -> Result<PreparedLaunch, String> {
    crate::cli_sandbox_stdio::validate()?;
    let session = Session::load(id)?;
    if session.manifest.phase != Phase::Prepared {
        return Err("private workspace launch requires a new prepared session".into());
    }
    session.baseline()?;
    capture::tree(&session.workspace()?)?;
    for name in ["home", "tmp", "config"] {
        empty(&session.root.child(name, false, true)?)?;
    }
    cli_agent_sandbox::probe_namespaces()
        .map_err(|e| format!("private workspace isolation unavailable: {e}"))?;
    let stage = session.path.join("sandbox");
    super::io::Dir::absolute(&session.path, false, true)?.child("sandbox", true, true)?;
    let mounts = WorkspaceMounts::new(&session.root_path(), stage)?;
    cli_agent_sandbox::probe_workspace(&mounts)
        .map_err(|e| format!("private workspace isolation unavailable: {e}"))?;
    let argv = crate::cli_sandbox_runtime::program(argv)?;
    Ok(PreparedLaunch {
        session,
        mounts,
        argv,
    })
}

impl PreparedLaunch {
    pub(crate) fn stage(
        &self,
        harness: &str,
        port: u16,
        ca: Option<&str>,
        env: &mut Vec<(String, String)>,
    ) -> Result<(), &'static str> {
        runtime_config::stage(&self.session, harness, port, ca, env)
    }

    pub(crate) fn run(mut self, argv: &[String], env: Vec<(String, String)>, port: u16) -> ! {
        let plan = cli_agent_sandbox::Plan::private(argv, env, port, self.mounts);
        let plan = match plan {
            Ok(plan) => plan,
            Err(e) => {
                eprintln!("kepr: {e}");
                std::process::exit(125);
            }
        };
        self.session.manifest.phase = Phase::Running;
        if let Err(e) = self.session.save() {
            eprintln!("kepr: {e}");
            std::process::exit(125);
        }
        let code = cli_agent_sandbox::run_status(plan);
        self.session.manifest.phase = Phase::Finished;
        self.session.manifest.exit_code = Some(code);
        if let Err(e) = self.session.save() {
            eprintln!("kepr: {e}");
            std::process::exit(125);
        }
        eprintln!(
            "kepr: workspace session {} finished ({code}); review with kepr workspace review {}",
            self.session.manifest.session, self.session.manifest.session
        );
        std::process::exit(code)
    }
}
