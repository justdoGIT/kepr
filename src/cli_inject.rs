// cli_inject.rs — `kepr inject -i TEMPLATE [-o OUT]` (agent vault P5.7).
// Replaces every `kepr://NAME` reference in a template with the stored
// value (like Vault's `ksm interpolate`). Output goes to stdout or to a
// new 0600 file; a warning is printed when that file is not on tmpfs,
// because rendered secrets on persistent disk outlive the process.
// Sealed credentials cannot be injected (the daemon refuses them).

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

use kepr_core::generate::ZeroString;
use kepr_core::protocol::Response;
use zeroize::Zeroizing;

use crate::cli_exec::{CredFetcher, DaemonFetcher};

pub const PREFIX: &str = "kepr://";

/// (start, end, NAME) for every reference in `tpl`.
pub fn references(tpl: &str) -> Vec<(usize, usize, String)> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(pos) = tpl[from..].find(PREFIX) {
        let start = from + pos;
        let name_start = start + PREFIX.len();
        let len = tpl[name_start..]
            .bytes()
            .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
            .count();
        if len > 0 {
            out.push((
                start,
                name_start + len,
                tpl[name_start..name_start + len].to_uppercase(),
            ));
        }
        from = name_start + len;
    }
    out
}

pub fn render(
    tpl: &str,
    fetch: &dyn Fn(&str) -> Result<ZeroString, String>,
) -> Result<Zeroizing<String>, String> {
    let refs = references(tpl);
    // One fetch per distinct name: a repeated consent/FIDO2-gated
    // credential prompts once, not once per occurrence.
    let mut values: std::collections::HashMap<&str, ZeroString> = std::collections::HashMap::new();
    for (_, _, name) in &refs {
        if !values.contains_key(name.as_str()) {
            let v = fetch(name).map_err(|e| format!("kepr://{name}: {e}"))?;
            values.insert(name, v);
        }
    }
    // Exact capacity up front: a reallocation would leave freed, unwiped
    // copies of the secrets rendered so far.
    let extra: usize = refs
        .iter()
        .map(|(_, _, n)| values[n.as_str()].as_str().len())
        .sum();
    let mut out = Zeroizing::new(String::with_capacity(tpl.len() + extra));
    let mut last = 0;
    for (start, end, name) in &refs {
        out.push_str(&tpl[last..*start]);
        out.push_str(values[name.as_str()].as_str());
        last = *end;
    }
    out.push_str(&tpl[last..]);
    Ok(out)
}

fn on_tmpfs(path: &std::path::Path) -> bool {
    const TMPFS_MAGIC: i64 = 0x0102_1994;
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let Ok(c) = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()) else {
        return false;
    };
    // SAFETY: statfs writes into a zeroed, stack-local struct.
    unsafe {
        let mut s: libc::statfs = std::mem::zeroed();
        if libc::statfs(c.as_ptr(), &mut s) != 0 {
            return false;
        }
        // f_type is i64 on x86_64 but i32 / u32 on other targets.
        #[allow(clippy::unnecessary_cast)]
        let fs_type = s.f_type as i64;
        fs_type == TMPFS_MAGIC
    }
}

pub fn cmd_inject(input: &str, output: Option<&str>) -> Response {
    let tpl = match std::fs::read_to_string(input) {
        Ok(t) => t,
        Err(e) => return Response::fail(format!("{input}: {e}")),
    };
    let rendered = match render(&tpl, &|n| DaemonFetcher.fetch(n)) {
        Ok(r) => r,
        Err(e) => return Response::fail(e),
    };
    let result = match output {
        None => std::io::stdout().write_all(rendered.as_bytes()),
        Some(path) => {
            if !on_tmpfs(std::path::Path::new(path)) {
                crate::cli_ui::warn(&format!(
                    "{path} is not on tmpfs: the rendered secrets persist on disk"
                ));
            }
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .and_then(|mut f| f.write_all(rendered.as_bytes()))
        }
    };
    match result {
        Ok(()) => Response::Pong,
        Err(e) => Response::fail(format!("write: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake(n: &str) -> Result<ZeroString, String> {
        match n {
            "DB_PASS" => Ok(ZeroString::from_string("p@ss".into())),
            "API" => Ok(ZeroString::from_string("k".into())),
            _ => Err("credential unavailable".into()),
        }
    }

    #[test]
    fn renders_references() {
        let out = render(
            "url=postgres://u:kepr://DB_PASS@h/db\nkey: kepr://api\n",
            &fake,
        )
        .unwrap();
        assert_eq!(out.as_str(), "url=postgres://u:p@ss@h/db\nkey: k\n");
        assert_eq!(
            render("no refs here", &fake).unwrap().as_str(),
            "no refs here"
        );
        assert_eq!(
            render("dangling kepr://", &fake).unwrap().as_str(),
            "dangling kepr://"
        );
    }

    #[test]
    fn repeated_reference_fetched_once() {
        let n = std::cell::Cell::new(0);
        let counting = |name: &str| {
            n.set(n.get() + 1);
            fake(name)
        };
        let out = render("kepr://API kepr://API kepr://API", &counting).unwrap();
        assert_eq!(out.as_str(), "k k k");
        assert_eq!(n.get(), 1);
    }

    #[test]
    fn missing_reference_names_it() {
        let e = render("x=kepr://NOPE", &fake).unwrap_err();
        assert!(e.contains("kepr://NOPE"));
    }
}
