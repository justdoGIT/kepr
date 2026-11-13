//! Parse and validate protected launch options before any daemon access.

use kepr_core::protocol::Response;

use super::AgentArgs;

pub(super) const FLAGS: &[&str] = &[
    "--compatibility",
    "--security-preset",
    "--no-sandbox",
    "--strict-sandbox",
    "--isolate-net",
    "--workspace",
    "--workspace-session",
    "--window",
];

pub(super) fn take(a: &mut AgentArgs, raw: &[String], mut i: usize) -> Result<usize, String> {
    match raw[i].as_str() {
        "--compatibility" => a.compatibility = true,
        "--window" => a.open_window = true,
        "--workspace" => {
            i += 1;
            let path = raw.get(i).ok_or("--workspace needs a directory")?;
            if path.starts_with('-') {
                return Err("--workspace needs a directory".into());
            }
            if a.session.workspace_source.replace(path.clone()).is_some() {
                return Err("--workspace may be supplied only once".into());
            }
        }
        "--no-sandbox" => a.no_sandbox = true,
        "--strict-sandbox" => a.strict_sandbox = true,
        "--isolate-net" => a.isolate_net = true,
        "--workspace-session" => {
            i += 1;
            let id = raw
                .get(i)
                .ok_or("--workspace-session needs its identifier")?;
            crate::cli_workspace::validate_session(id)?;
            if a.session.workspace_session.replace(id.clone()).is_some() {
                return Err("--workspace-session may be supplied only once".into());
            }
        }
        "--security-preset" => {
            i += 1;
            let preset = raw
                .get(i)
                .ok_or("--security-preset needs private-cloud or local-only")?;
            if !matches!(preset.as_str(), "private-cloud" | "local-only") {
                return Err("--security-preset needs private-cloud or local-only".into());
            }
            a.security_preset = Some(preset.clone());
        }
        _ => return Err("unsupported launch option".into()),
    }
    Ok(i)
}

pub(super) fn defaults(a: &mut AgentArgs) -> Result<(), String> {
    if a.verb != "run" {
        return if a.compatibility
            || a.security_preset.is_some()
            || a.open_window
            || a.session.workspace_session.is_some()
            || a.session.workspace_source.is_some()
        {
            Err("launch security options require agent run".into())
        } else {
            Ok(())
        };
    }
    if a.session.workspace_session.is_some() && a.session.workspace_source.is_some() {
        return Err("--workspace conflicts with --workspace-session".into());
    }
    if a.compatibility && a.session.workspace_session.is_some() {
        return Err(
            "--workspace-session requires protected isolation; remove --compatibility".into(),
        );
    }
    if a.compatibility && a.session.workspace_source.is_some() {
        return Err("--workspace requires protected isolation; remove --compatibility".into());
    }
    if a.compatibility && (a.strict_sandbox || a.security_preset.is_some()) {
        return Err("--compatibility conflicts with --strict-sandbox and --security-preset".into());
    }
    if a.no_sandbox && !a.compatibility {
        return Err("--no-sandbox requires explicit --compatibility".into());
    }
    if a.no_sandbox && (a.isolate_net || a.target.as_deref() == Some("codex")) {
        return Err("network isolation and Codex protection require the sandbox".into());
    }
    if !a.compatibility {
        a.strict_sandbox = true;
        a.isolate_net = true;
    }
    Ok(())
}

pub(super) fn sandbox_mode(a: &AgentArgs) -> crate::cli_agent_run::SandboxMode {
    use crate::cli_agent_run::SandboxMode;
    if a.no_sandbox {
        SandboxMode::Off
    } else if a.strict_sandbox {
        SandboxMode::Required
    } else {
        SandboxMode::Auto
    }
}

pub(super) fn preflight(a: &AgentArgs) -> Option<Response> {
    if a.security_preset.as_deref() == Some("local-only") {
        return Some(Response::fail(
            "local-only launch unavailable: local inference routing is not implemented",
        ));
    }
    if !a.compatibility && a.session.workspace_session.is_none() {
        return Some(Response::fail("protected launch requires a workspace snapshot; use --workspace PATH or --workspace-session SESSION"));
    }
    if a.compatibility {
        crate::cli_ui::warn(
            "compatibility mode: privacy filtering and required isolation are disabled",
        );
    }
    None
}
