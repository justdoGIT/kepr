//! Generate session configuration; never copy host auth, history or credentials.

use super::{
    io::{self, Dir},
    session::Session,
};
use crate::cli_sandbox_workspace::{VIRTUAL_ROOT, WORKSPACE};
use std::io::Read;

const MAX_HOOK_BINARY_BYTES: usize = 128 * 1024 * 1024;
const OMP: &[(&str, &str)] = &[
    (
        "package.json",
        include_str!("../../plugins/omp/kepr/package.json"),
    ),
    ("index.ts", include_str!("../../plugins/omp/kepr/index.ts")),
    (
        "providers.ts",
        include_str!("../../plugins/omp/kepr/providers.ts"),
    ),
];

fn replace(env: &mut Vec<(String, String)>, key: &str, value: String) {
    env.retain(|(name, _)| name != key);
    env.push((key.into(), value));
}

fn private_env(harness: &str, port: u16, prefix: &str, ca: bool, env: &mut Vec<(String, String)>) {
    for (key, value) in [
        ("PATH", crate::cli_sandbox_runtime::SEARCH_PATH.to_string()),
        ("SHELL", "/bin/sh".into()),
        ("HOME", format!("{VIRTUAL_ROOT}/home")),
        ("PWD", WORKSPACE.into()),
        ("TMPDIR", format!("{VIRTUAL_ROOT}/tmp")),
        ("XDG_CONFIG_HOME", format!("{VIRTUAL_ROOT}/home/.config")),
        ("XDG_CACHE_HOME", format!("{VIRTUAL_ROOT}/home/.cache")),
        ("XDG_DATA_HOME", format!("{VIRTUAL_ROOT}/home/.local/share")),
        (
            "XDG_STATE_HOME",
            format!("{VIRTUAL_ROOT}/home/.local/state"),
        ),
        ("XDG_RUNTIME_DIR", format!("{VIRTUAL_ROOT}/tmp/runtime")),
    ] {
        replace(env, key, value);
    }
    env.retain(|(key, _)| {
        !matches!(
            key.as_str(),
            "CODEX_HOME" | "PI_CODING_AGENT_DIR" | "KEPR_BIN"
        )
    });
    match harness {
        "omp" => {
            replace(
                env,
                "PI_CODING_AGENT_DIR",
                format!("{VIRTUAL_ROOT}/home/omp"),
            );
            replace(env, "KEPR_BIN", format!("{prefix}/bin/kepr"));
        }
        "codex" => replace(env, "CODEX_HOME", format!("{VIRTUAL_ROOT}/home/codex")),
        _ => {}
    }
    if ca {
        for key in [
            "HTTPS_PROXY",
            "https_proxy",
            "HTTP_PROXY",
            "http_proxy",
            "ALL_PROXY",
            "all_proxy",
        ] {
            replace(env, key, format!("http://127.0.0.1:{port}"));
        }
        for key in ["NO_PROXY", "no_proxy"] {
            replace(env, key, "127.0.0.1,localhost".into());
        }
        for key in [
            "NODE_EXTRA_CA_CERTS",
            "SSL_CERT_FILE",
            "REQUESTS_CA_BUNDLE",
            "CURL_CA_BUNDLE",
            "GIT_SSL_CAINFO",
        ] {
            replace(env, key, format!("{prefix}/gate-ca.crt"));
        }
    }
}

fn hook_binary(dir: &Dir) -> Result<(), &'static str> {
    // proc supplies the currently executing, trusted kepr image, not its memory.
    let file = std::fs::File::open("/proc/self/exe")
        .map_err(|_| "private workspace hook image unavailable")?;
    let mut bytes = Vec::new();
    file.take(MAX_HOOK_BINARY_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "private workspace hook image unreadable")?;
    if bytes.len() > MAX_HOOK_BINARY_BYTES {
        return Err("private workspace hook image byte limit reached");
    }
    dir.write_named("kepr", &bytes, 0o500)
}

pub(super) fn stage(
    session: &Session,
    harness: &str,
    port: u16,
    ca: Option<&str>,
    env: &mut Vec<(String, String)>,
) -> Result<(), &'static str> {
    let name = format!("launch-{}", io::random_id()?);
    let config = session
        .root
        .child("config", false, true)?
        .new_child(&name)?;
    let prefix = format!("{VIRTUAL_ROOT}/config/{name}");
    let home = session.root.child("home", false, true)?;
    session
        .root
        .child("tmp", false, true)?
        .new_child("runtime")?;
    if let Some(ca) = ca {
        if ca.len() > 64 * 1024
            || !ca.starts_with("-----BEGIN CERTIFICATE-----")
            || kepr_core::leak::looks_like_key(ca.as_bytes())
        {
            return Err("private workspace gate certificate invalid");
        }
        config.write_named("gate-ca.crt", ca.as_bytes(), 0o400)?;
    }
    if harness == "omp" {
        hook_binary(&config.new_child("bin")?)?;
        let plugin = config.new_child("omp")?;
        for (name, text) in OMP {
            plugin.write_named(name, text.as_bytes(), 0o400)?;
        }
        let agent = home.new_child("omp")?;
        agent.write_named("models.yml", b"providers: {}\n", 0o600)?;
        let extensions = agent.new_child("extensions")?;
        let target = std::ffi::CString::new(format!("{prefix}/omp"))
            .map_err(|_| "private workspace hook path invalid")?;
        // SAFETY: a trusted generated target and constant name under our owned FD.
        if unsafe { libc::symlinkat(target.as_ptr(), extensions.fd(), c"kepr".as_ptr()) } != 0 {
            return Err("private workspace hook registration failed");
        }
        extensions.sync()?;
    } else if harness == "codex" {
        home.new_child("codex")?.write_named(
            "AGENTS.md",
            crate::cli_agent_plugin::SKILL.as_bytes(),
            0o600,
        )?;
    }
    private_env(harness, port, &prefix, ca.is_some(), env);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn private_environment_keeps_only_private_home_config_and_certificate_paths() {
        let mut env = vec![
            ("HOME".into(), "/home/operator/original".into()),
            ("PATH".into(), "/home/operator/bin".into()),
            ("CODEX_HOME".into(), "/home/operator/auth".into()),
            ("PI_CODING_AGENT_DIR".into(), "/home/operator/omp".into()),
            ("SSL_CERT_FILE".into(), "/tmp/host-ca.crt".into()),
            ("KEPR_GATE_URL".into(), "http://127.0.0.1:7000".into()),
        ];
        private_env(
            "omp",
            7000,
            "/session/private/config/launch-example",
            true,
            &mut env,
        );
        let env: HashMap<_, _> = env.into_iter().collect();
        assert_eq!(env["HOME"], "/session/private/home");
        assert_eq!(env["PWD"], WORKSPACE);
        assert_eq!(env["KEPR_GATE_URL"], "http://127.0.0.1:7000");
        assert_eq!(env["PI_CODING_AGENT_DIR"], "/session/private/home/omp");
        assert!(!env.contains_key("CODEX_HOME"));
        assert_eq!(
            env["SSL_CERT_FILE"],
            "/session/private/config/launch-example/gate-ca.crt"
        );
        assert_eq!(env["PATH"], crate::cli_sandbox_runtime::SEARCH_PATH);
        assert!(!env
            .values()
            .any(|v| v.contains("/home/operator") || v.contains("/tmp/host-ca")));
    }
}
