// cli_recordsx/types.rs — T11.7 record types: the built-ins
// (kepr_core::record_types) plus user types from
// `~/.config/kepr/types/*.toml` ($XDG_CONFIG_HOME respected).
//
//   kepr record types [--export DIR]    list them; --export writes each
//                                       as DIR/<type>.toml to start from
//   kepr record convert KEY TYPE        re-type a record (daemon side:
//                                       daemon_recordsx/convert.rs)
//
// A user type may not reuse a built-in's name; a file that does not
// parse is reported and skipped, so one bad file never blocks the rest.

use std::path::{Path, PathBuf};

use kepr_core::protocol::Response;
use kepr_core::protocol_records::{RecordsRequest, RecordsResponse};
use kepr_core::record_types::{self, RecordType};

use crate::{cli_mode, cli_ui};

/// `$XDG_CONFIG_HOME/kepr` or `~/.config/kepr`.
pub fn config_dir() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".config")
        })
        .join("kepr")
}

fn parse(text: &str, taken: &[RecordType]) -> Result<RecordType, String> {
    let t: RecordType = toml::from_str(text).map_err(|e| e.to_string())?;
    t.validate()?;
    if record_types::is_builtin(&t.name) {
        return Err(format!("{} is a built-in type; pick another name", t.name));
    }
    if taken.iter().any(|o| o.name == t.name) {
        return Err(format!("type {} is defined twice", t.name));
    }
    Ok(t)
}

/// The user types in `dir` (`*.toml`, by file name), and one error line
/// per file that was skipped.
pub fn load_dir(dir: &Path) -> (Vec<RecordType>, Vec<String>) {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|rd| rd.filter_map(|e| e.ok().map(|e| e.path())).collect())
        .unwrap_or_default();
    files.retain(|p| p.extension().is_some_and(|e| e == "toml") && p.is_file());
    files.sort();
    let (mut types, mut errors) = (Vec::new(), Vec::new());
    for p in files {
        let r = std::fs::read_to_string(&p)
            .map_err(|e| e.to_string())
            .and_then(|text| parse(&text, &types));
        match r {
            Ok(t) => types.push(t),
            Err(e) => errors.push(format!("{}: {e}", p.display())),
        }
    }
    (types, errors)
}

/// Built-in and user types; skipped files are warned about.
pub fn all() -> Vec<RecordType> {
    let (user, errors) = load_dir(&config_dir().join("types"));
    errors
        .iter()
        .for_each(|e| cli_ui::warn(&format!("record type skipped: {e}")));
    let mut out = record_types::builtins();
    out.extend(user);
    out
}

/// The type called `name`, or an error listing the known ones.
pub fn find(name: &str) -> Result<RecordType, String> {
    let all = all();
    let names: Vec<String> = all.iter().map(|t| t.name.clone()).collect();
    all.into_iter().find(|t| t.name == name).ok_or_else(|| {
        format!(
            "unknown record type {name:?}; use one of: {} (see: kepr record types)",
            names.join(", ")
        )
    })
}

fn quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// `t` as a type file `load_dir` reads back.
pub fn to_toml(t: &RecordType) -> String {
    let mut out = format!(
        "# kepr record type. Save under ~/.config/kepr/types/ with a new name\n\
         # to define your own (field types: {}).\nname = {}\n",
        record_types::KINDS.join(", "),
        quote(&t.name)
    );
    if t.fields.is_empty() {
        out.push_str("fields = []  # any fields\n");
        return out;
    }
    out.push_str("fields = [\n");
    for f in &t.fields {
        out.push_str(&format!(
            "  {{ name = {}, type = {}",
            quote(&f.name),
            quote(&f.kind)
        ));
        if f.required {
            out.push_str(", required = true");
        }
        if let Some(m) = f.masked {
            out.push_str(&format!(", masked = {m}"));
        }
        out.push_str(" },\n");
    }
    out.push_str("]\n");
    out
}

/// `username, password*, ssid!`: `*` masked, `!` required.
fn summary(t: &RecordType) -> String {
    if t.fields.is_empty() {
        return "(any fields)".into();
    }
    let marks = |f: &record_types::FieldSpec| {
        format!(
            "{}{}{}",
            f.name,
            if f.required { "!" } else { "" },
            if f.masked() { "*" } else { "" }
        )
    };
    t.fields.iter().map(marks).collect::<Vec<_>>().join(", ")
}

fn export(dir: &Path, types: &[RecordType]) -> Result<usize, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let path = |t: &RecordType| dir.join(format!("{}.toml", t.name));
    if let Some(p) = types.iter().map(path).find(|p| p.exists()) {
        return Err(format!(
            "{} exists; export into an empty directory",
            p.display()
        ));
    }
    for t in types {
        std::fs::write(path(t), to_toml(t)).map_err(|e| format!("{}: {e}", path(t).display()))?;
    }
    Ok(types.len())
}

pub fn cmd_types(args: &[String]) -> Response {
    let types = all();
    match args {
        [] => {}
        [flag, dir] if flag == "--export" => {
            return match export(Path::new(dir), &types) {
                Ok(n) => {
                    cli_ui::ok(&format!("{n} type file(s) written to {dir}"));
                    Response::Pong
                }
                Err(e) => Response::fail(e),
            };
        }
        _ => return Response::fail("usage: kepr record types [--export DIR]"),
    }
    if cli_mode::json_mode() {
        println!("{}", serde_json::to_string(&types).unwrap_or_default());
        return Response::Pong;
    }
    for t in &types {
        println!("{:<9} {}", t.name, summary(t));
    }
    cli_ui::dim(&format!(
        "* masked in `record show`, ! required; your own types: {}/types/*.toml",
        config_dir().display()
    ));
    Response::Pong
}

pub fn cmd_convert(args: &[String]) -> Response {
    let [name, rtype] = args else {
        return Response::fail("usage: kepr record convert KEY TYPE");
    };
    let t = match find(rtype) {
        Ok(t) => t,
        Err(e) => return Response::fail(e),
    };
    let r = super::send(RecordsRequest::RecordConvert {
        name: name.to_uppercase(),
        record_type: t.name.clone(),
        fields: t.fields.iter().map(|f| f.name.clone()).collect(),
    });
    if let Response::Records(RecordsResponse::RecordConvertOk {
        name,
        record_type,
        moved,
        promoted,
        gated,
    }) = &r
    {
        cli_ui::ok(&format!("{name}: now a {record_type} record"));
        if !moved.is_empty() {
            cli_ui::info(&format!("kept as custom fields: {}", moved.join(", ")));
        }
        if !promoted.is_empty() {
            cli_ui::info(&format!(
                "custom fields now fields: {}",
                promoted.join(", ")
            ));
        }
        if *gated {
            cli_ui::dim("field names not shown: the record is consent / FIDO2 protected");
        }
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_types_load_next_to_the_builtins() {
        let dir = tempfile::tempdir().unwrap();
        let w = |f: &str, text: &str| std::fs::write(dir.path().join(f), text).unwrap();
        w(
            "a-wifi.toml",
            "name = \"wifi\"\nfields = [\n  { name = \"ssid\", required = true },\n  \
             { name = \"password\", type = \"secret\" },\n  { name = \"router\", type = \"ref\" },\n]\n",
        );
        w("b-login.toml", "name = \"login\"\nfields = []\n");
        w("c-again.toml", "name = \"wifi\"\n");
        w(
            "d-bad.toml",
            "name = \"x\"\nfields = [{ name = \"a\", type = \"blob\" }]\n",
        );
        w("e-extra.toml", "name = \"y\"\ncolour = \"red\"\n");
        w("notes.txt", "name = \"ignored\"\n");
        let (types, errors) = load_dir(dir.path());
        assert_eq!(types.len(), 1);
        let wifi = &types[0];
        assert_eq!(wifi.name, "wifi");
        assert!(wifi.field("ssid").unwrap().required);
        assert_eq!(wifi.field("ssid").unwrap().kind, "text");
        assert!(wifi.field("password").unwrap().masked());
        assert!(!wifi.field("router").unwrap().masked());
        assert_eq!(errors.len(), 4, "{errors:?}");
        for (e, what) in errors.iter().zip([
            "login is a built-in type",
            "type wifi is defined twice",
            "unknown type \"blob\"",
            "colour",
        ]) {
            assert!(e.contains(what), "{e}");
        }
        assert_eq!(load_dir(&dir.path().join("none")).0, vec![]);
    }

    #[test]
    fn exported_types_load_back_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let mut types = record_types::builtins();
        let (mut user, _) = {
            let src = tempfile::tempdir().unwrap();
            std::fs::write(
                src.path().join("w.toml"),
                "name = \"wifi\"\nfields = [{ name = \"ssid\", required = true, masked = true }]\n",
            )
            .unwrap();
            load_dir(src.path())
        };
        types.append(&mut user);
        assert_eq!(export(dir.path(), &types).unwrap(), types.len());
        // Exported built-ins are refused as user types (same names) but
        // parse as types; the user type loads back as it was.
        for t in &types {
            let text =
                std::fs::read_to_string(dir.path().join(format!("{}.toml", t.name))).unwrap();
            let back: RecordType = toml::from_str(&text).unwrap();
            assert_eq!(&back, t);
        }
        let (loaded, errors) = load_dir(dir.path());
        assert_eq!(loaded.len(), 1);
        assert_eq!(errors.len(), record_types::builtins().len());
        assert!(export(dir.path(), &types).unwrap_err().contains("exists"));
    }

    #[test]
    fn summary_marks_masked_and_required_fields() {
        let t = record_types::builtins().remove(0);
        assert_eq!(summary(&t), "username, password*, url, totp*");
        let custom = record_types::builtins().pop().unwrap();
        assert_eq!(summary(&custom), "(any fields)");
    }
}
