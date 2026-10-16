// cli_session/ssh_rotate.rs — `kepr ssh rotate NAME --host [USER@]HOST
// [--port N]` (T11.21):
//
//   1. generate the new key as NAME_NEXT (or resume with an existing one);
//   2. log in with the OLD key and add the new public key to the host's
//      ~/.ssh/authorized_keys;
//   3. log in with the NEW key (proves it works) and remove the old key's
//      line(s);
//   4. `SshRotateCommit`: the daemon makes NAME the new key, drops NEXT.
//
// ssh runs with a private `kepr ssh-agent` (signing stays in the daemon),
// `-i FILE.pub` + IdentitiesOnly to pick the key and BatchMode (no
// password or host-key prompts). The authorized_keys file is edited here
// (`add_line` / `remove_key`) and written back whole; the remote commands
// are fixed strings, the key lines travel on stdin. A failure before
// step 4 leaves the old key working; re-running resumes.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use kepr_core::protocol::{Request, Response, SshKeyInfo};
use kepr_core::protocol_session::SessionRequest;
use kepr_core::ssh_wire_ecdsa::type_of_b64;

const USAGE: &str = "usage: kepr ssh rotate NAME --host [USER@]HOST [--port N]";
const READ: &str = "cat ~/.ssh/authorized_keys 2>/dev/null || true";
const WRITE: &str = "umask 077 && mkdir -p ~/.ssh && cat > ~/.ssh/.authorized_keys.kepr \
                     && mv -f ~/.ssh/.authorized_keys.kepr ~/.ssh/authorized_keys";

#[derive(Debug, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: Option<u16>,
}

/// Does `line` carry the key `b64` (Ed25519 or ECDSA; any options or comment)?
fn line_has(line: &str, b64: &str) -> bool {
    let words: Vec<&str> = line.split_whitespace().collect();
    words
        .windows(2)
        .any(|w| w[0] == type_of_b64(b64) && w[1] == b64)
}

pub fn has_key(text: &str, b64: &str) -> bool {
    text.lines().any(|l| line_has(l, b64))
}

/// `text` with `line` appended (unless its key is there already).
pub fn add_line(text: &str, line: &str, b64: &str) -> String {
    if has_key(text, b64) {
        return text.to_string();
    }
    let mut out = text.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(line);
    out.push('\n');
    out
}

/// `text` without the lines carrying key `b64`; every other line is kept
/// exactly (other keys, options, comments, blank lines).
pub fn remove_key(text: &str, b64: &str) -> String {
    text.split_inclusive('\n')
        .filter(|l| !line_has(l, b64))
        .collect()
}

pub fn parse(args: &[String]) -> Result<(String, Target), String> {
    let (mut name, mut host, mut port) = (None, None, None);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--host" => host = it.next().cloned(),
            "--port" => {
                let p = it.next().ok_or(USAGE)?;
                port = Some(p.parse::<u16>().map_err(|_| format!("bad port {p:?}"))?);
            }
            s if s.starts_with('-') => return Err(format!("unknown flag {s}\n{USAGE}")),
            s if name.is_none() => name = Some(s.to_uppercase()),
            _ => return Err(USAGE.into()),
        }
    }
    let (Some(name), Some(host)) = (name, host) else {
        return Err(USAGE.into());
    };
    let ok = |c: char| c.is_ascii_alphanumeric() || "._-@:[]".contains(c);
    if host.is_empty() || host.len() > 255 || host.starts_with('-') || !host.chars().all(ok) {
        return Err(format!("bad host {host:?}: use [USER@]HOST"));
    }
    Ok((name, Target { host, port }))
}

/// The ssh command line for `remote`, logging in with the key in `pubkey`.
pub fn ssh_argv(t: &Target, pubkey: &Path, remote: &str) -> Vec<String> {
    let mut v: Vec<String> = ["-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-i"]
        .map(String::from)
        .to_vec();
    v.push(pubkey.display().to_string());
    if let Some(p) = t.port {
        v.extend(["-p".to_string(), p.to_string()]);
    }
    v.extend(["--".to_string(), t.host.clone(), remote.to_string()]);
    v
}

/// A private `kepr ssh-agent` in a fresh 0700 directory, stopped on drop.
struct Agent {
    child: std::process::Child,
    dir: PathBuf,
}

impl Agent {
    fn start() -> Result<Self, String> {
        let base =
            std::env::var_os("XDG_RUNTIME_DIR").map_or_else(std::env::temp_dir, PathBuf::from);
        let mut rnd = [0u8; 8];
        getrandom::fill(&mut rnd).map_err(|e| format!("CSPRNG failure: {e}"))?;
        let dir = base.join(format!("kepr-rotate-{}", hex::encode(rnd)));
        std::os::unix::fs::DirBuilderExt::mode(&mut std::fs::DirBuilder::new(), 0o700)
            .create(&dir)
            .map_err(|e| format!("{}: {e}", dir.display()))?;
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let child = Command::new(exe)
            .args(["ssh-agent", "--foreground", "--socket"])
            .arg(dir.join("agent.sock"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .spawn()
            .map_err(|e| format!("cannot start the agent: {e}"))?;
        let agent = Agent { child, dir };
        for _ in 0..100 {
            if agent.sock().exists() {
                return Ok(agent);
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        Err("the agent did not start".into())
    }
    fn sock(&self) -> PathBuf {
        self.dir.join("agent.sock")
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn line(k: &SshKeyInfo) -> String {
    format!(
        "{} {} {}",
        type_of_b64(&k.public_b64),
        k.public_b64,
        k.comment
    )
    .trim_end()
    .to_string()
}

/// Run `remote` on the host as `key`, with `input` on stdin.
fn ssh(
    a: &Agent,
    t: &Target,
    key: &SshKeyInfo,
    remote: &str,
    input: &str,
) -> Result<String, String> {
    let pubkey = a.dir.join(format!("{}.pub", key.name));
    std::fs::write(&pubkey, format!("{}\n", line(key))).map_err(|e| e.to_string())?;
    let mut child = Command::new("ssh")
        .args(ssh_argv(t, &pubkey, remote))
        .env("SSH_AUTH_SOCK", a.sock())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run ssh: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(input.as_bytes())
            .map_err(|e| e.to_string())?;
    }
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!(
            "ssh to {} as {} failed ({})",
            t.host, key.name, out.status
        ));
    }
    String::from_utf8(out.stdout).map_err(|_| "authorized_keys is not UTF-8".into())
}

fn send(req: Request) -> Result<Response, String> {
    match crate::client::send_request(&req)? {
        Response::Err { error } => Err(error),
        r => Ok(r),
    }
}

fn keys() -> Result<Vec<SshKeyInfo>, String> {
    match send(Request::SshList)? {
        Response::SshListOk { keys } => Ok(keys),
        _ => Err("unexpected daemon response".into()),
    }
}

/// NAME's key and the NEXT key (generated now, or left by an earlier run).
fn old_and_next(name: &str) -> Result<(SshKeyInfo, SshKeyInfo), String> {
    let next = format!("{name}_NEXT");
    let ks = keys()?;
    let find = |n: &str| ks.iter().find(|k| k.name == n).cloned();
    let old = find(name).ok_or_else(|| format!("{name} is not an SSH key (kepr ssh list)"))?;
    if let Some(k) = find(&next) {
        crate::cli_ui::info(&format!("resuming with the key in {next}"));
        return Ok((old, k));
    }
    if let Ok(Response::ListOk { credentials, .. }) = send(Request::List) {
        if credentials.iter().any(|c| c.name == next) {
            return Err(format!(
                "{next} exists and is not an SSH key; rename it first"
            ));
        }
    }
    send(Request::SshGenerate {
        name: next.clone(),
        comment: old.comment.clone(),
        requires_consent: None,
        key_type: None,
    })?;
    let k = keys()?.into_iter().find(|k| k.name == next);
    Ok((old, k.ok_or("the new key was not stored")?))
}

fn rotate(name: &str, t: &Target) -> Result<Response, String> {
    let (old, new) = old_and_next(name)?;
    if old.public_b64 != new.public_b64 {
        let agent = Agent::start()?;
        let text = ssh(&agent, t, &old, READ, "")?;
        if !has_key(&text, &new.public_b64) {
            ssh(
                &agent,
                t,
                &old,
                WRITE,
                &add_line(&text, &line(&new), &new.public_b64),
            )?;
        }
        let text = ssh(&agent, t, &new, READ, "").map_err(|e| {
            format!(
                "{e}: the new key was added but logging in with it failed; the old key still works"
            )
        })?;
        if has_key(&text, &old.public_b64) {
            let edited = remove_key(&text, &old.public_b64);
            if !has_key(&edited, &new.public_b64) {
                return Err("refusing to write an authorized_keys without the new key".into());
            }
            ssh(&agent, t, &new, WRITE, &edited)?;
        }
    }
    send(Request::Session(SessionRequest::SshRotateCommit {
        name: name.to_string(),
        next: new.name,
    }))
}

/// `kepr ssh rotate …` (`args` after `rotate`).
pub fn cmd(args: &[String]) -> Response {
    let r = parse(args).and_then(|(name, t)| rotate(&name, &t));
    match r {
        Ok(r @ Response::SshKeyOk { .. }) => {
            if let (false, Response::SshKeyOk { name, public_line }) =
                (crate::cli_mode::json_mode(), &r)
            {
                crate::cli_ui::ok(&format!(
                    "{name} rotated; the host now accepts only the new key"
                ));
                println!("{public_line}");
            }
            r
        }
        Ok(other) => other,
        Err(e) => Response::fail(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OLD: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIOLD";
    const NEW: &str = "AAAAC3NzaC1lZDI1NTE5AAAAINEW";

    #[test]
    fn add_appends_once_and_fixes_a_missing_newline() {
        let line = format!("ssh-ed25519 {NEW} kepr:K");
        assert_eq!(add_line("", &line, NEW), format!("{line}\n"));
        let text = format!("ssh-ed25519 {OLD} me");
        let added = add_line(&text, &line, NEW);
        assert_eq!(added, format!("{text}\n{line}\n"));
        assert_eq!(add_line(&added, &line, NEW), added, "idempotent");
    }

    #[test]
    fn remove_drops_only_the_old_key_and_keeps_the_rest_exactly() {
        let text = format!(
            "# keys\nssh-ed25519 {OLD} kepr:K\n\nssh-rsa AAAAB3Nza other\n\
             from=\"10.0.0.0/8\" ssh-ed25519 {OLD} copy\nssh-ed25519 {NEW} kepr:K\n\
             ssh-ed25519 {OLD}X longer"
        );
        let out = remove_key(&text, OLD);
        assert_eq!(
            out,
            format!(
                "# keys\n\nssh-rsa AAAAB3Nza other\nssh-ed25519 {NEW} kepr:K\n\
                 ssh-ed25519 {OLD}X longer"
            )
        );
        assert!(has_key(&out, NEW) && !has_key(&out, OLD));
    }

    #[test]
    fn an_ecdsa_key_is_found_by_its_own_type() {
        // T12.11: rotating an ECDSA key removes its ecdsa-sha2-nistp256 line.
        let old = kepr_core::ssh_wire::b64(&kepr_core::ssh_wire_ecdsa::public_blob(&[4; 65]));
        let key = SshKeyInfo {
            name: "K".into(),
            public_b64: old.clone(),
            comment: "me".into(),
        };
        assert_eq!(line(&key), format!("ecdsa-sha2-nistp256 {old} me"));
        let text = format!("{}\nssh-ed25519 {NEW} kepr:K\n", line(&key));
        assert!(has_key(&text, &old));
        assert!(!has_key(&format!("ssh-ed25519 {old} me"), &old));
        assert_eq!(
            remove_key(&text, &old),
            format!("ssh-ed25519 {NEW} kepr:K\n")
        );
    }

    #[test]
    fn command_construction() {
        let t = Target {
            host: "deploy@db1".into(),
            port: Some(2222),
        };
        assert_eq!(
            ssh_argv(&t, Path::new("/r/K.pub"), READ),
            [
                "-o",
                "BatchMode=yes",
                "-o",
                "IdentitiesOnly=yes",
                "-i",
                "/r/K.pub",
                "-p",
                "2222",
                "--",
                "deploy@db1",
                READ
            ]
        );
        let t = Target {
            host: "h".into(),
            port: None,
        };
        assert_eq!(
            ssh_argv(&t, Path::new("k"), "true")[5..],
            ["k", "--", "h", "true"]
        );
    }

    #[test]
    fn parses_and_refuses_odd_hosts() {
        let a = |v: &[&str]| parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert_eq!(
            a(&["k", "--host", "me@h.example", "--port", "22"]).unwrap(),
            (
                "K".into(),
                Target {
                    host: "me@h.example".into(),
                    port: Some(22)
                }
            )
        );
        for bad in ["-oProxyCommand=x", "a b", "h;rm", "h`x`", ""] {
            assert!(a(&["k", "--host", bad]).is_err(), "{bad}");
        }
        assert_eq!(a(&["k"]).unwrap_err(), USAGE);
        assert!(a(&["k", "--host", "h", "--port", "x"]).is_err());
    }
}
