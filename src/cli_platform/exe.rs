// cli_platform/exe.rs — binary-identity bindings, client side (T10.09).
//
//   kepr set KEY … --exe PATH [--exe PATH2]   store, then allow only these programs
//   kepr exe KEY                              show the recorded identities
//   kepr exe KEY --allow PATH [--allow …]     replace them
//   kepr exe KEY --clear                      drop the binding
//
// The CLI hashes the files (SHA-256, plus the fs-verity digest when the
// file has one) with the user's own rights and sends only the hashes; the
// daemon checks the connecting process's /proc/<pid>/exe against them on
// every `get`. Only a program the binding allows may change or clear it.

use std::fs::File;
use std::path::PathBuf;

use kepr_core::exe_digest;
use kepr_core::protocol::{Request, Response};
use kepr_core::protocol_platform::{PlatformRequest, PlatformResponse};

use super::args;
use crate::cli_args::Args;

const USAGE: &str = "usage: kepr exe KEY [--allow PATH]... [--clear]";

/// `PATH` as given, or looked up on $PATH when it has no `/`.
pub fn resolve(path: &str) -> Result<PathBuf, String> {
    if path.contains('/') {
        return Ok(PathBuf::from(path));
    }
    std::env::var_os("PATH")
        .and_then(|p| {
            std::env::split_paths(&p)
                .map(|d| d.join(path))
                .find(|c| c.is_file())
        })
        .ok_or_else(|| format!("--exe {path}: not found on PATH"))
}

/// The identities for one program file.
pub fn identities(path: &str) -> Result<Vec<String>, String> {
    let p = resolve(path)?;
    let p = std::fs::canonicalize(&p).unwrap_or(p);
    let bad = |what: &str| format!("{}: {what}", p.display());
    let f = File::open(&p).map_err(|e| bad(&e.to_string()))?;
    if !f.metadata().map(|m| m.is_file()).unwrap_or(false) {
        return Err(bad("not a regular file"));
    }
    exe_digest::entries_of(&f).map_err(|e| bad(&e.to_string()))
}

/// Identities of several programs, deduplicated, in order.
pub fn identities_of(paths: &[&str]) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for p in paths {
        for id in identities(p)? {
            if !out.contains(&id) {
                out.push(id);
            }
        }
    }
    Ok(out)
}

fn send(r: PlatformRequest) -> Response {
    crate::client::send_request(&Request::Platform(r)).unwrap_or_else(Response::fail)
}

/// `kepr set KEY --exe PATH`: bind the value just stored.
pub fn after_set(a: &Args, resp: Response) -> Response {
    let (Response::SetOk { name, .. }, false) = (&resp, a.platform.exe.is_empty()) else {
        return resp;
    };
    match send(PlatformRequest::ExeBind {
        name: name.clone(),
        digests: a.platform.exe.clone(),
    }) {
        Response::Platform(PlatformResponse::ExeBindings { .. }) => resp,
        Response::Err { error } => Response::fail(format!("{name} was stored, but {error}")),
        _ => Response::fail("unexpected daemon response"),
    }
}

pub fn cmd_exe(argv: &[String]) -> Response {
    let a = match args::parse(argv, &["--allow"], &["--clear"]) {
        Ok(a) => a,
        Err(e) => return Response::fail(e),
    };
    let [name] = a.positional.as_slice() else {
        return Response::fail(USAGE);
    };
    let name = name.to_uppercase();
    let allow = a.values("--allow");
    let req = match (allow.is_empty(), a.has("--clear")) {
        (true, false) => PlatformRequest::ExeShow { name },
        (true, true) => PlatformRequest::ExeBind {
            name,
            digests: Vec::new(),
        },
        (false, false) => match identities_of(&allow) {
            Ok(digests) => PlatformRequest::ExeBind { name, digests },
            Err(e) => return Response::fail(e),
        },
        (false, true) => return Response::fail("use either --allow or --clear"),
    };
    let resp = send(req);
    if let Response::Platform(PlatformResponse::ExeBindings { name, digests }) = &resp {
        if !crate::cli_ui::json_mode() {
            print!("{}", render(name, digests));
        }
    }
    resp
}

pub fn render(name: &str, digests: &[String]) -> String {
    if digests.is_empty() {
        return format!("{name}: any program may read it (no executable binding)\n");
    }
    let mut s = format!("{name}: readable only by programs with these identities\n");
    for d in digests {
        s.push_str(&format!("  {d}\n"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identities_hash_the_file_and_follow_path() {
        let dir = std::env::temp_dir().join(format!("kepr-cli-exe-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("tool");
        std::fs::write(&p, b"abc").unwrap();
        let ids = identities(p.to_str().unwrap()).unwrap();
        assert_eq!(
            ids[0],
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let both = identities_of(&[p.to_str().unwrap(), p.to_str().unwrap()]).unwrap();
        assert_eq!(both, ids, "deduplicated");
        assert!(identities(dir.to_str().unwrap()).is_err(), "a directory");
        assert!(identities(dir.join("missing").to_str().unwrap()).is_err());
        // A bare name is looked up on PATH.
        assert!(resolve("sh").unwrap().is_absolute());
        assert!(resolve("no-such-program-kepr-test").is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn render_lists_identities() {
        assert!(render("K", &[]).contains("any program"));
        let r = render("K", &["sha256:ab".into()]);
        assert!(r.contains("  sha256:ab\n"));
    }

    #[test]
    fn usage_errors() {
        let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(cmd_exe(&v(&[])).is_err_resp());
        assert!(cmd_exe(&v(&["K", "--allow", "/bin/sh", "--clear"])).is_err_resp());
        assert!(cmd_exe(&v(&["K", "--allow", "/no/such/file"])).is_err_resp());
    }

    trait IsErr {
        fn is_err_resp(&self) -> bool;
    }
    impl IsErr for Response {
        fn is_err_resp(&self) -> bool {
            matches!(self, Response::Err { .. })
        }
    }
}
