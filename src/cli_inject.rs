// cli_inject.rs — `kepr inject -i TEMPLATE [-o OUT]` (agent vault P5.7).
// Replaces every `kepr://` reference in a template with what it stands
// for (like Vault's `ksm interpolate`): `kepr://NAME` the stored value,
// `kepr://NAME/field[i][sub]`, `/custom_field/LABEL` and `/file/FILE`
// parts of a record (T5.05, cli_recordsx/notation.rs). Output goes to
// stdout or to a new 0600 file; a warning is printed when that file is
// not on tmpfs, because rendered secrets on persistent disk outlive the
// process. Sealed credentials cannot be injected (the daemon refuses them).

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

use kepr_core::generate::ZeroString;
use kepr_core::protocol::Response;
use zeroize::Zeroizing;

use crate::cli_recordsx::notation::{self, PREFIX};
use crate::cli_recordsx::resolve::{self, Cached, Source};

/// (start, end, the reference after `kepr://` with NAME upper-cased)
/// for every reference in `tpl`.
pub fn references(tpl: &str) -> Vec<(usize, usize, String)> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(pos) = tpl[from..].find(PREFIX) {
        let start = from + pos;
        let body = start + PREFIX.len();
        match notation::scan(&tpl[body..]) {
            Some((len, key)) => {
                out.push((start, body + len, key));
                from = body + len;
            }
            None => from = body,
        }
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

/// Resolve reference texts with one fetch per credential and attachment,
/// so a consent- or FIDO2-gated record prompts once however many of its
/// fields the template uses. `NAME/rest` on a value that is not a record
/// renders as the value followed by `/rest`, as before records existed.
pub fn resolver(src: &dyn Source) -> impl Fn(&str) -> Result<ZeroString, String> + '_ {
    let cached = Cached::new(src);
    move |key: &str| {
        let n = notation::parse(&format!("{PREFIX}{key}"))?;
        match resolve::resolve(&n, &cached) {
            Err(e) if e == resolve::NOT_A_RECORD => {
                let v = cached.value(&n.name)?;
                let rest = &key[n.name.len()..];
                Ok(ZeroString::from_string(format!("{}{rest}", v.as_str())))
            }
            r => r,
        }
    }
}

pub fn cmd_inject(input: &str, output: Option<&str>) -> Response {
    let tpl = match std::fs::read_to_string(input) {
        Ok(t) => t,
        Err(e) => return Response::fail(format!("{input}: {e}")),
    };
    let rendered = match render(&tpl, &resolver(&resolve::Daemon)) {
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

    struct Counting(std::cell::Cell<u32>);
    impl Source for Counting {
        fn file(&self, _: &str, _: &str) -> Result<Zeroizing<Vec<u8>>, String> {
            Err("no attachment".into())
        }
        fn value(&self, name: &str) -> Result<ZeroString, String> {
            self.0.set(self.0.get() + 1);
            match name {
                "DB" => Ok(ZeroString::from_string(
                    r#"{"user":"u","password":"p"}"#.into(),
                )),
                "API_BASE" => Ok(ZeroString::from_string("https://x".into())),
                _ => Err("credential unavailable".into()),
            }
        }
    }

    #[test]
    fn one_fetch_per_record_and_old_path_templates_still_render() {
        let src = Counting(std::cell::Cell::new(0));
        let tpl = "kepr://DB/user:kepr://DB/password@h kepr://DB/user kepr://API_BASE/v1";
        let out = render(tpl, &resolver(&src)).unwrap();
        assert_eq!(out.as_str(), "u:p@h u https://x/v1");
        assert_eq!(src.0.get(), 2);
        assert!(render("kepr://DB/nope", &resolver(&src)).is_err());
    }

    #[test]
    fn templates_use_indexes_custom_fields_and_files() {
        let src = crate::cli_recordsx::resolve::tests::fixture();
        let tpl = "a=kepr://r/url[1] b=kepr://R/phone[0][number]\n\
                   c=kepr://R/custom_field/Q\\/A\\ \\[1\\] d=\"kepr://R/file/notes.txt\" e=kepr://R/url[x y]";
        let out = render(tpl, &resolver(&src)).unwrap();
        assert_eq!(
            out.as_str(),
            "a=https://b.example b=111\nc=answer d=\"line one\n\" e=https://a.example[x y]"
        );
        assert_eq!(src.fetches.get(), 1);
        let e = render("x=kepr://R/file/key.bin", &resolver(&src)).unwrap_err();
        assert!(
            e.contains("kepr://R/file/key.bin") && e.contains("not text"),
            "{e}"
        );
    }

    #[test]
    fn field_references_keep_the_field_and_stop_at_upper_case() {
        let refs = references("u=kepr://DB/user p=kepr://DB/password x=kepr://DB/Up kepr://DB/");
        let keys: Vec<&str> = refs.iter().map(|r| r.2.as_str()).collect();
        assert_eq!(keys, ["DB/user", "DB/password", "DB", "DB"]);
        // `/Up` is not a field: the reference ends at the name.
        assert_eq!(
            &"u=kepr://DB/user p=kepr://DB/password x=kepr://DB/Up kepr://DB/"
                [refs[2].0..refs[2].1],
            "kepr://DB"
        );
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
