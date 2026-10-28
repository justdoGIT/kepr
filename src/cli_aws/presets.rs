// presets.rs — per-tool files for the CLI presets (T2.04), written into
// the session's private directory next to the egress CA by
// `cli_agent_egress::env`:
//
//   npm     .npmrc `//registry.npmjs.org/:_authToken=${NPM_TOKEN}`
//           (NPM_TOKEN holds the placeholder), NPM_CONFIG_USERCONFIG
//   docker  docker/config.json with a placeholder `auth`, DOCKER_CONFIG
//           and REGISTRY_AUTH_FILE (podman, skopeo, buildah)
//   gcloud  CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE (gcloud reads its own CA
//           setting, not SSL_CERT_FILE)
//   git     T12.06: git-credential-kepr as the only github.com helper
//           (GIT_CONFIG_*), the placeholder in KEPR_PH_GIT_GITHUB_COM
//
// Only placeholders are written; the gate swaps them for the real key.
// The Docker Engine pulls from its own daemon, outside the session, so
// the docker preset serves clients that make registry calls themselves.

use std::collections::HashMap;
use std::path::Path;

use base64::Engine;
use kepr_core::providers::Provider;

/// Does a sealed key for `p` get an egress route? Providers with
/// variables, plus those configured through a file here.
pub fn routed(p: &Provider) -> bool {
    !p.egress_env.is_empty() || p.name == "docker" || p.name == "git"
}

/// T12.06: where git-credential-kepr finds the github.com placeholder
/// (`GIT_PH_PREFIX` + `git_cred_name("github.com")`).
pub const GIT_PH_VAR: &str = "KEPR_PH_GIT_GITHUB_COM";

/// The variables the `git` preset sets.
const GIT_VARS: [&str; 7] = [
    GIT_PH_VAR,
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_KEY_0",
    "GIT_CONFIG_VALUE_0",
    "GIT_CONFIG_KEY_1",
    "GIT_CONFIG_VALUE_1",
    "GIT_TERMINAL_PROMPT",
];

/// Inherited variables the session's own files replace.
pub fn shadowed(placeholders: &HashMap<String, String>) -> Vec<&'static str> {
    let mut out = Vec::new();
    if placeholders.contains_key("npm") {
        out.extend(["NPM_CONFIG_USERCONFIG", "npm_config_userconfig"]);
    }
    if placeholders.contains_key("docker") {
        out.extend(["DOCKER_CONFIG", "REGISTRY_AUTH_FILE"]);
    }
    if placeholders.contains_key("gcloud") {
        out.push("CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE");
    }
    if placeholders.contains_key("git") {
        out.extend(GIT_VARS);
    }
    out
}

/// `git-credential-kepr` next to this binary, else `kepr` (git then runs
/// `git-credential-kepr` from PATH). git runs a helper path through the
/// shell, so only a path of plain characters is used.
fn git_helper() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|e| Some(e.parent()?.join("git-credential-kepr")))
        .filter(|p| p.is_file())
        .map(|p| p.display().to_string())
        .filter(|s| {
            s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/._+-".contains(&b))
        })
        .unwrap_or_else(|| "kepr".to_string())
}

/// T12.06: the empty helper resets the user's own github.com helpers, so
/// git asks only git-credential-kepr, which answers with the placeholder.
fn git_env(placeholder: &str) -> Vec<(String, String)> {
    let key = "credential.https://github.com.helper";
    let values = [placeholder, "2", key, "", key, &git_helper(), "0"];
    GIT_VARS
        .iter()
        .zip(values)
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

pub const NPMRC: &str = "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n";

/// A Docker Hub login whose password is the session placeholder.
pub fn docker_config(placeholder: &str) -> String {
    let auth = base64::engine::general_purpose::STANDARD.encode(format!("kepr:{placeholder}"));
    serde_json::json!({ "auths": { "https://index.docker.io/v1/": { "auth": auth } } }).to_string()
}

/// Write the files the session's placeholders call for into `dir` (the
/// private per-session directory, `bundle` its CA bundle); the variables
/// pointing at them.
pub fn write(
    dir: &Path,
    bundle: &Path,
    placeholders: &HashMap<String, String>,
) -> Result<Vec<(String, String)>, String> {
    let mut env = Vec::new();
    if placeholders.contains_key("gcloud") {
        let b = bundle.display().to_string();
        env.push(("CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE".into(), b));
    }
    if placeholders.contains_key("npm") {
        let rc = dir.join("npmrc");
        crate::cli_agent_egress::write_private(&rc, NPMRC.as_bytes())?;
        env.push(("NPM_CONFIG_USERCONFIG".into(), rc.display().to_string()));
    }
    if let Some(ph) = placeholders.get("docker") {
        let d = dir.join("docker");
        std::fs::create_dir(&d).map_err(|e| format!("{}: {e}", d.display()))?;
        let cfg = d.join("config.json");
        crate::cli_agent_egress::write_private(&cfg, docker_config(ph).as_bytes())?;
        env.push(("DOCKER_CONFIG".into(), d.display().to_string()));
        env.push(("REGISTRY_AUTH_FILE".into(), cfg.display().to_string()));
    }
    if let Some(ph) = placeholders.get("git") {
        env.extend(git_env(ph));
    }
    Ok(env)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PH: &str = "kepr-ph-0123456789abcdef-0002-0011223344556677";

    #[test]
    fn writes_only_placeholders_and_points_the_tools_at_them() {
        let dir = std::env::temp_dir().join(format!("kepr-presets-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let ph: HashMap<String, String> = [
            ("npm".to_string(), PH.to_string()),
            ("docker".to_string(), PH.to_string()),
            ("gcloud".to_string(), PH.to_string()),
        ]
        .into();
        let bundle = dir.join("ca-bundle.pem");
        let env = write(&dir, &bundle, &ph).unwrap();
        let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        let rc = std::fs::read_to_string(get("NPM_CONFIG_USERCONFIG").unwrap()).unwrap();
        assert_eq!(rc, "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n");
        assert_eq!(
            get("CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE"),
            Some(bundle.display().to_string())
        );
        let cfg_path = get("REGISTRY_AUTH_FILE").unwrap();
        assert_eq!(
            Path::new(&cfg_path).parent().unwrap(),
            Path::new(&get("DOCKER_CONFIG").unwrap())
        );
        let cfg: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&cfg_path).unwrap()).unwrap();
        let auth = cfg["auths"]["https://index.docker.io/v1/"]["auth"]
            .as_str()
            .unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(auth)
            .unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), format!("kepr:{PH}"));
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&cfg_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let mut s = shadowed(&ph);
        s.sort_unstable();
        assert_eq!(
            s,
            [
                "CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE",
                "DOCKER_CONFIG",
                "NPM_CONFIG_USERCONFIG",
                "REGISTRY_AUTH_FILE",
                "npm_config_userconfig"
            ]
        );
        let none: HashMap<String, String> = HashMap::new();
        assert!(write(&dir, &bundle, &none).unwrap().is_empty() && shadowed(&none).is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn git_gets_the_placeholder_through_the_credential_helper_only() {
        let dir = std::env::temp_dir().join(format!("kepr-presets-git-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let ph: HashMap<String, String> = [("git".to_string(), PH.to_string())].into();
        let env = write(&dir, &dir.join("ca-bundle.pem"), &ph).unwrap();
        let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        let with_ph: Vec<&str> = env
            .iter()
            .filter(|(_, v)| v.contains(PH))
            .map(|(k, _)| k.as_str())
            .collect();
        assert_eq!(with_ph, ["KEPR_PH_GIT_GITHUB_COM"]);
        assert_eq!(get("KEPR_PH_GIT_GITHUB_COM").as_deref(), Some(PH));
        assert_eq!(get("GIT_CONFIG_COUNT").as_deref(), Some("2"));
        let key = "credential.https://github.com.helper";
        assert_eq!(get("GIT_CONFIG_KEY_0").as_deref(), Some(key));
        assert_eq!(get("GIT_CONFIG_KEY_1").as_deref(), Some(key));
        assert_eq!(get("GIT_CONFIG_VALUE_0").as_deref(), Some(""));
        let helper = get("GIT_CONFIG_VALUE_1").unwrap();
        assert!(
            helper == "kepr" || helper.ends_with("/git-credential-kepr"),
            "{helper}"
        );
        assert_eq!(get("GIT_TERMINAL_PROMPT").as_deref(), Some("0"));
        let mut s = shadowed(&ph);
        s.sort_unstable();
        let mut names: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
        names.sort_unstable();
        assert_eq!(s.len(), 7);
        assert_eq!(s, names);
        assert_eq!(
            GIT_PH_VAR,
            format!(
                "{}{}",
                kepr_core::providers::GIT_PH_PREFIX,
                kepr_core::providers::git_cred_name("github.com")
            )
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
