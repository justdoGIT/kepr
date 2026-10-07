// cli_recordsx/generate.rs — T5.04 generator profiles and `kepr strength`.
//
//   kepr set KEY --generate --profile P     a value from profile P of
//                                           ~/.config/kepr/generate.toml
//                                           (P may also name a host or a
//                                           record type there)
//   kepr record add KEY ... --generate FIELD [--profile P]
//                                           FIELD from P, else the profile
//                                           for the record's url / host,
//                                           else for its type, else [default]
//   kepr strength                           estimate the bits of a typed
//                                           value (hidden prompt, or stdin)
//
// The file format is in kepr_core::generate_profile; the estimate in
// kepr_core::strength. The value checked is never printed or sent.

use std::io::{IsTerminal, Read};
use std::path::PathBuf;

use kepr_core::generate::{generate_secret, GenKind, ZeroString};
use kepr_core::generate_profile::ProfileFile;
use kepr_core::protocol::Response;
use kepr_core::protocol_records::RecordsResponse;
use kepr_core::strength;

use crate::{cli_input, cli_mode, cli_ui};

pub fn profiles_path() -> PathBuf {
    super::types::config_dir().join("generate.toml")
}

pub fn parse(text: &str) -> Result<ProfileFile, String> {
    let f: ProfileFile = toml::from_str(text).map_err(|e| e.to_string())?;
    f.validate()?;
    Ok(f)
}

/// The profile file; an absent file is empty (built-in defaults).
pub fn load() -> Result<ProfileFile, String> {
    let path = profiles_path();
    match std::fs::read_to_string(&path) {
        Ok(text) => parse(&text).map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ProfileFile::default()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// `kepr set --generate`: profile `profile` if named, else `kind`.
/// `kepr set` prints no error text of its own, so a failure is shown here.
pub fn generate(kind: GenKind, profile: Option<&str>) -> Result<ZeroString, String> {
    let r = match profile {
        Some(p) => load().and_then(|f| f.pick(Some(p), None, None)?.generate()),
        None => generate_secret(kind),
    };
    if let (Err(e), false) = (&r, cli_mode::json_mode()) {
        cli_ui::err(e);
    }
    r
}

/// The host of a URL-ish string: `https://user@a.example.com:8443/x` →
/// `a.example.com`; a bare host stays as it is.
pub fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?;
    let host = host.split(':').next()?.trim().to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

fn read_value() -> Result<ZeroString, String> {
    if std::io::stdin().is_terminal() {
        return Ok(cli_input::read_masked("Value to check (hidden): "));
    }
    let mut buf = Vec::new();
    std::io::stdin()
        .read_to_end(&mut buf)
        .map_err(|e| format!("read stdin: {e}"))?;
    let mut s = String::from_utf8(buf).map_err(|_| "the value must be UTF-8")?;
    while s.ends_with(['\n', '\r']) {
        s.pop();
    }
    Ok(ZeroString::from_string(s))
}

pub fn cmd_strength(args: &[String]) -> Response {
    if !args.is_empty() {
        return Response::fail(
            "usage: kepr strength   (type the value at the prompt, or pipe it on stdin)",
        );
    }
    let value = match read_value() {
        Ok(v) => v,
        Err(e) => return Response::fail(e),
    };
    let s = strength::estimate(value.as_str());
    let bits = s.bits.round() as u32;
    if !cli_mode::json_mode() {
        cli_ui::info(&format!("~{bits} bits: {}", s.rating()));
        if !s.notes.is_empty() {
            cli_ui::dim(&format!("  guessable parts: {}", s.notes.join(", ")));
        }
    }
    Response::Records(RecordsResponse::StrengthOk {
        bits,
        rating: s.rating().to_string(),
        notes: s.notes.iter().map(|n| n.to_string()).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_file_parses_every_table() {
        let f = parse(
            r#"
[default]
length = 20
[profile.bank]
length = 16
classes = ["lower", "upper", "digit", "symbol"]
symbols = "!#$%"
[profile.memorable]
words = 5
separator = "."
[host."example.com"]
symbols = ""
[type.wifi]
words = 4
"#,
        )
        .unwrap();
        let bank = f.pick(Some("bank"), None, None).unwrap();
        assert_eq!(
            (bank.length, bank.symbols.as_deref()),
            (Some(16), Some("!#$%"))
        );
        let v = bank.generate().unwrap();
        assert_eq!(v.len(), 16);
        assert!(v
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%".contains(&b)));
        let site = f
            .pick(None, Some("www.example.com"), Some("login"))
            .unwrap();
        assert!(site
            .generate()
            .unwrap()
            .bytes()
            .all(|b| b.is_ascii_alphanumeric()));
        assert_eq!(f.pick(None, None, Some("wifi")).unwrap().words, Some(4));
        assert_eq!(f.pick(None, None, None).unwrap().length, Some(20));
        for (bad, what) in [
            ("[profile.x]\nlenght = 3\n", "lenght"),
            ("[profile.x]\nlength = 3\n", "[profile.\"x\"] length"),
            ("[colours]\n", "colours"),
        ] {
            let e = parse(bad).unwrap_err();
            assert!(e.contains(what), "{bad}: {e}");
        }
    }

    #[test]
    fn hosts_come_from_urls_or_bare_names() {
        for (url, host) in [
            ("https://Login.Bank.example/x?y", Some("login.bank.example")),
            ("https://me:pw@a.example.com:8443/", Some("a.example.com")),
            ("db.internal", Some("db.internal")),
            ("10.0.0.1:5432", Some("10.0.0.1")),
            ("https://", None),
        ] {
            assert_eq!(host_of(url).as_deref(), host, "{url}");
        }
    }
}
