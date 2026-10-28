// cli_inject.rs — `kepr inject -i TEMPLATE [-o OUT [--allow-disk]]` (P5.7).
// Replaces every `kepr://` reference in a template with what it stands
// for (like Vault's `ksm interpolate`): `kepr://NAME` the stored value,
// `kepr://NAME/field[i][sub]`, `/custom_field/LABEL` and `/file/FILE`
// parts of a record (T5.05, cli_recordsx/notation.rs). Output goes to
// stdout or to a new 0600 file, which must be on a memory-backed file
// system (tmpfs, ramfs; T12.45) unless `--allow-disk` is given, because
// rendered secrets on persistent disk outlive the process. Sealed
// credentials cannot be injected (the daemon refuses them).

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

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

pub fn cmd_inject(input: &str, output: Option<&str>, allow_disk: bool) -> Response {
    let tpl = match std::fs::read_to_string(input) {
        Ok(t) => t,
        Err(e) => return Response::fail(format!("{input}: {e}")),
    };
    let fill = || render(&tpl, &resolver(&resolve::Daemon));
    let result = match output {
        None => fill().and_then(|r| {
            std::io::stdout()
                .write_all(r.as_bytes())
                .map_err(|e| format!("write: {e}"))
        }),
        Some(path) => write_out(Path::new(path), allow_disk, fill),
    };
    match result {
        Ok(()) => Response::Pong,
        Err(e) => Response::fail(e),
    }
}

/// Create OUT (new, 0600), check that file's own file system, and only
/// then render: a refused OUT costs no `get` and no consent, FIDO2 or
/// re-auth prompt. A refused, failed or half-written OUT is removed.
fn write_out(
    out: &Path,
    allow_disk: bool,
    render: impl FnOnce() -> Result<Zeroizing<String>, String>,
) -> Result<(), String> {
    let shown = out.display();
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(out)
        .map_err(|e| format!("{shown}: {e}"))?;
    let discard = |f: std::fs::File| {
        drop(f);
        let _ = std::fs::remove_file(out);
    };
    if !crate::cli_memfs::on_memory_fs(&f) {
        if !allow_disk {
            discard(f);
            return Err(format!(
                "{shown} is on disk: rendered secrets would outlive the process; write under \
                 $XDG_RUNTIME_DIR or /dev/shm, use stdout, or pass --allow-disk"
            ));
        }
        crate::cli_ui::warn(&format!(
            "{shown} is not on tmpfs: the rendered secrets persist on disk"
        ));
    }
    let rendered = match render() {
        Ok(r) => r,
        Err(e) => {
            discard(f);
            return Err(e);
        }
    };
    match f.write_all(rendered.as_bytes()) {
        Ok(()) => Ok(()),
        Err(e) => {
            discard(f);
            Err(format!("write: {e}"))
        }
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

    fn scratch(tag: &str) -> std::path::PathBuf {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("kepr-inject-{tag}-{}-{n}", std::process::id()))
    }

    fn ok(s: &str) -> Result<Zeroizing<String>, String> {
        Ok(Zeroizing::new(s.to_string()))
    }

    #[test]
    fn disk_out_refused_before_render() {
        let out = scratch("disk");
        let dir = out.parent().unwrap();
        if crate::cli_memfs::path_on_memory_fs(dir) {
            eprintln!("skip: target/ is on a memory file system here");
            return;
        }
        let e = write_out(&out, false, || -> Result<Zeroizing<String>, String> {
            panic!("rendered before the file system check")
        })
        .unwrap_err();
        assert!(
            e.contains("is on disk") && e.contains("--allow-disk"),
            "{e}"
        );
        assert!(e.contains(&out.display().to_string()), "{e}");
        assert!(!out.exists());
    }

    #[test]
    fn allow_disk_writes_0600() {
        use std::os::unix::fs::PermissionsExt;
        let out = scratch("allow");
        write_out(&out, true, || ok("v=1\n")).unwrap();
        let mode = std::fs::metadata(&out).unwrap().permissions().mode();
        let body = std::fs::read_to_string(&out).unwrap();
        std::fs::remove_file(&out).unwrap();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(body, "v=1\n");
    }

    #[test]
    fn render_error_leaves_no_file() {
        let out = scratch("err");
        let e = write_out(
            &out,
            true,
            || Err("kepr://X: credential unavailable".into()),
        );
        assert_eq!(e.unwrap_err(), "kepr://X: credential unavailable");
        assert!(!out.exists());
    }

    #[test]
    fn existing_out_refused() {
        let out = scratch("exists");
        std::fs::write(&out, "keep me").unwrap();
        let e = write_out(&out, true, || -> Result<Zeroizing<String>, String> {
            panic!("rendered over an existing file")
        });
        let body = std::fs::read_to_string(&out).unwrap();
        std::fs::remove_file(&out).unwrap();
        assert!(e.is_err());
        assert_eq!(body, "keep me");
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
