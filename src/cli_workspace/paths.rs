//! Explicit, bounded text inputs; credential/configuration paths are excluded.

use std::path::{Component, Path};

pub(super) const MAX_FILES: usize = 1024;
pub(super) const MAX_FILE_BYTES: usize = 1024 * 1024;
pub(super) const MAX_TOTAL_BYTES: usize = 32 * 1024 * 1024;

pub(super) const MAX_SNAPSHOT_FILES: usize = 4096;
pub(super) const MAX_SNAPSHOT_BYTES: usize = 128 * 1024 * 1024;
pub(super) const MAX_SNAPSHOT_ENTRIES: usize = 16_384;

pub(super) fn absolute(path: &Path) -> Result<(), &'static str> {
    if !path.is_absolute()
        || path.as_os_str().as_encoded_bytes().len() > 4096
        || path.components().count() < 2
        || path
            .components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
    {
        return Err("workspace root must be a scoped absolute path without traversal");
    }
    Ok(())
}

pub(super) fn source_root(path: &Path) -> Result<(), &'static str> {
    absolute(path)?;
    if ["/etc", "/proc", "/sys", "/dev", "/run", "/var/lib/kepr"]
        .iter()
        .any(|root| path.starts_with(root))
    {
        return Err("workspace credential and system-data roots are excluded");
    }
    for part in path.components() {
        if let Component::Normal(name) = part {
            relative(
                name.to_str()
                    .ok_or("workspace source requires plain names")?,
            )?;
            if name == "credstore.encrypted" {
                return Err("workspace credential roots are excluded");
            }
        }
    }
    Ok(())
}

pub(super) fn component(name: &str) -> Result<(), &'static str> {
    if name.is_empty()
        || name.len() > 255
        || matches!(name, "." | "..")
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err("workspace paths require bounded plain relative names");
    }
    Ok(())
}

fn excluded_component(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | ".ssh"
            | ".gnupg"
            | ".aws"
            | ".azure"
            | ".kube"
            | ".config"
            | ".local"
            | ".cargo"
            | ".codex"
            | ".claude"
            | ".omp"
            | ".grok"
            | ".kepr.toml"
            | ".netrc"
            | ".npmrc"
            | ".pypirc"
            | ".pgpass"
            | "auth.json"
            | "credentials"
            | "credentials.json"
            | "credentials.toml"
            | "secrets.json"
            | "secrets.toml"
            | "config.json"
            | "models.json"
            | "master.key"
            | "vault.img"
            | "id_rsa"
            | "id_ed25519"
    )
}

fn generated_component(name: &str) -> bool {
    matches!(
        name,
        "target"
            | ".venv"
            | "node_modules"
            | "__pycache__"
            | ".pytest_cache"
            | ".mypy_cache"
            | ".ruff_cache"
            | "build"
            | "dist"
    )
}

pub(super) fn source_tree_path(path: &str) -> Result<bool, &'static str> {
    if path.len() > 1024 || path.split('/').count() > 16 {
        return Ok(false);
    }
    for name in path.split('/') {
        if component(name).is_err() {
            return Ok(false);
        }
        let lower = name.to_ascii_lowercase();
        if lower.starts_with(".env")
            || excluded_component(&lower)
            || generated_component(&lower)
            || lower.ends_with(".pem")
            || lower.ends_with(".p12")
            || lower.ends_with(".pfx")
            || lower.ends_with(".key")
            || lower.starts_with("kepr-ph-")
        {
            return Ok(false);
        }
    }
    if super::screen::check(path.as_bytes()).is_err() {
        return Ok(false);
    }
    Ok(true)
}

pub(super) fn relative(path: &str) -> Result<(), &'static str> {
    if path.len() > 1024 || path.split('/').count() > 16 {
        return Err("workspace path limit reached");
    }
    for name in path.split('/') {
        component(name)?;
        let lower = name.to_ascii_lowercase();
        if lower.starts_with(".env")
            || excluded_component(&lower)
            || lower.ends_with(".pem")
            || lower.ends_with(".p12")
            || lower.ends_with(".pfx")
            || lower.ends_with(".key")
            || lower.starts_with("kepr-ph-")
        {
            return Err("workspace credential and host-configuration paths are excluded");
        }
    }
    super::screen::check(path.as_bytes())
}

pub(super) fn session_id(id: &str) -> Result<(), &'static str> {
    if id.len() != 32
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("workspace session requires its 32-character identifier");
    }
    Ok(())
}
