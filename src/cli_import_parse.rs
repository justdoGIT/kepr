// cli_import_parse.rs — readers for other secret managers' exports
// (agent vault P10.2). Pure functions: text in, `Entry`s out. Every
// value lands in a `ZeroString`; `cli_import.rs` does the storing.
//
// Formats: password-manager CSV (1Password, Bitwarden, KeePassXC,
// LastPass, Chrome/Edge/Firefox — columns found by header name),
// Bitwarden JSON, vault records JSON, flat JSON objects (Doppler) and
// key/value arrays (Infisical), and `.env` files.

use kepr_core::generate::ZeroString;
use serde_json::Value;
use zeroize::Zeroizing;

pub struct Entry {
    pub name: String,
    pub value: ZeroString,
}

/// `My GitHub (work)` → `MY_GITHUB_WORK`; empty if nothing usable.
pub fn kepr_name(raw: &str) -> String {
    let mut out = String::new();
    for c in raw.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_uppercase());
        } else if !out.ends_with('_') && !out.is_empty() {
            out.push('_');
        }
    }
    let out = out.trim_end_matches('_').to_string();
    match out.chars().next() {
        Some(c) if c.is_ascii_digit() => format!("K_{out}"),
        _ => out.chars().take(100).collect(),
    }
}

/// RFC 4180 CSV: quoted fields, doubled quotes, newlines inside quotes.
pub fn parse_csv(text: &str) -> Zeroizing<Vec<Vec<String>>> {
    let mut rows = Zeroizing::new(Vec::new());
    let (mut row, mut field) = (Vec::new(), String::new());
    let (mut quoted, mut chars) = (
        false,
        text.trim_start_matches('\u{feff}').chars().peekable(),
    );
    while let Some(c) = chars.next() {
        match (quoted, c) {
            (true, '"') if chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            (true, '"') => quoted = false,
            (true, c) => field.push(c),
            (false, '"') => quoted = true,
            (false, ',') => row.push(std::mem::take(&mut field)),
            (false, '\r') => {}
            (false, '\n') => {
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
            }
            (false, c) => field.push(c),
        }
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    rows
}

fn push(out: &mut Vec<Entry>, base: &str, suffix: &str, value: &str) {
    let base = kepr_name(base);
    if base.is_empty() || value.trim().is_empty() {
        return;
    }
    let name = if suffix.is_empty() {
        base
    } else {
        format!("{base}_{}", kepr_name(suffix))
    };
    out.push(Entry {
        name,
        value: ZeroString::from_string(value.to_string()),
    });
}

/// Password-manager CSV with a header row. The title becomes NAME (the
/// password), NAME_USERNAME and NAME_TOTP.
pub fn from_csv(text: &str) -> Result<Vec<Entry>, String> {
    let rows = parse_csv(text);
    let header: Vec<String> = rows
        .first()
        .ok_or("empty CSV")?
        .iter()
        .map(|h| h.trim().to_ascii_lowercase())
        .collect();
    let col = |names: &[&str]| header.iter().position(|h| names.contains(&h.as_str()));
    let title = col(&["title", "name", "account"]).ok_or("CSV has no title/name column")?;
    let password = col(&["password", "login_password"]).ok_or("CSV has no password column")?;
    let username = col(&["username", "login_username", "user name", "login"]);
    let totp = col(&["totp", "otpauth", "login_totp", "one-time password"]);
    let mut out = Vec::new();
    for r in rows.iter().skip(1) {
        let get = |i: Option<usize>| i.and_then(|i| r.get(i)).map_or("", |s| s.as_str());
        let t = get(Some(title));
        push(&mut out, t, "", get(Some(password)));
        push(&mut out, t, "username", get(username));
        push(&mut out, t, "totp", get(totp));
    }
    Ok(out)
}

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

fn from_bitwarden(v: &Value) -> Vec<Entry> {
    let mut out = Vec::new();
    for item in v["items"].as_array().into_iter().flatten() {
        let title = s(item, "name");
        let login = &item["login"];
        push(&mut out, title, "", s(login, "password"));
        push(&mut out, title, "username", s(login, "username"));
        push(&mut out, title, "totp", s(login, "totp"));
        if item["type"] == 2 {
            push(&mut out, title, "", s(item, "notes")); // secure note
        }
        for f in item["fields"].as_array().into_iter().flatten() {
            push(&mut out, title, s(f, "name"), s(f, "value"));
        }
    }
    out
}

fn from_vault_records(v: &Value) -> Vec<Entry> {
    let mut out = Vec::new();
    for r in v["records"].as_array().into_iter().flatten() {
        let title = s(r, "title");
        push(&mut out, title, "", s(r, "password"));
        push(&mut out, title, "username", s(r, "login"));
        if let Some(fields) = r["custom_fields"].as_object() {
            for (k, val) in fields {
                push(&mut out, title, k, val.as_str().unwrap_or(""));
            }
        }
    }
    out
}

/// `{"KEY": "value"}` (Doppler) or `[{"key": …, "value": …}]` (Infisical).
fn from_flat(v: &Value) -> Vec<Entry> {
    let mut out = Vec::new();
    if let Some(obj) = v.as_object() {
        for (k, val) in obj {
            push(&mut out, k, "", val.as_str().unwrap_or(""));
        }
    } else if let Some(arr) = v.as_array() {
        for e in arr {
            push(&mut out, s(e, "key"), "", s(e, "value"));
        }
    }
    out
}

pub fn from_json(text: &str) -> Result<Vec<Entry>, String> {
    let v: Value = serde_json::from_str(text).map_err(|e| format!("not valid JSON: {e}"))?;
    if v.get("encrypted") == Some(&Value::Bool(true)) {
        return Err(
            "this export is encrypted; export it unencrypted (then delete the file)".into(),
        );
    }
    Ok(if v.get("items").is_some() {
        from_bitwarden(&v)
    } else if v.get("records").is_some() {
        from_vault_records(&v)
    } else {
        from_flat(&v)
    })
}

pub fn from_env(text: &str) -> Vec<Entry> {
    text.lines()
        .filter_map(crate::cli_agent_adopt::parse_line)
        .map(|(name, value)| Entry {
            name,
            value: ZeroString::from_string(value),
        })
        .collect()
}

/// Pick a reader from `--format` or the file's name and contents.
pub fn parse(format: &str, file_name: &str, text: &str) -> Result<Vec<Entry>, String> {
    let lower = file_name.to_ascii_lowercase();
    let fmt = match format {
        "auto" if lower.ends_with(".kdbx") || lower.ends_with(".1pux") => {
            return Err("binary vault files aren't supported; export to CSV or JSON first".into())
        }
        "auto" if lower.ends_with(".json") || text.trim_start().starts_with(['{', '[']) => "json",
        "auto" if lower.ends_with(".csv") => "csv",
        "auto" => "env",
        f => f,
    };
    match fmt {
        "csv" => from_csv(text),
        "json" => from_json(text),
        "env" => Ok(from_env(text)),
        other => Err(format!(
            "unknown format {other}: use auto, csv, json or env"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(e: &[Entry]) -> Vec<(&str, &str)> {
        e.iter()
            .map(|e| (e.name.as_str(), e.value.as_str()))
            .collect()
    }

    #[test]
    fn names_are_sanitised() {
        assert_eq!(kepr_name("My GitHub (work)"), "MY_GITHUB_WORK");
        assert_eq!(kepr_name("1password"), "K_1PASSWORD");
        assert_eq!(kepr_name("  --  "), "");
    }

    #[test]
    fn csv_with_quotes_and_newlines() {
        let t = "\u{feff}Title,Username,Password,OTPAuth\r\n\
                 \"Git, Hub\",me,\"p\"\"w\nx\",otpauth://totp/a?secret=AB\r\nEmpty,,,\r\n";
        let e = from_csv(t).unwrap();
        assert_eq!(
            names(&e),
            vec![
                ("GIT_HUB", "p\"w\nx"),
                ("GIT_HUB_USERNAME", "me"),
                ("GIT_HUB_TOTP", "otpauth://totp/a?secret=AB")
            ]
        );
        assert!(from_csv("a,b\n1,2").is_err());
    }

    #[test]
    fn bitwarden_records_and_flat_json() {
        let bw = r#"{"encrypted":false,"items":[{"type":1,"name":"AWS","login":{"username":"u","password":"p"},"fields":[{"name":"Access Key","value":"AK"}]}]}"#;
        assert_eq!(
            names(&from_json(bw).unwrap()),
            vec![
                ("AWS", "p"),
                ("AWS_USERNAME", "u"),
                ("AWS_ACCESS_KEY", "AK")
            ]
        );
        let k = r#"{"records":[{"title":"DB","login":"root","password":"pw","custom_fields":{"port":"5432"}}]}"#;
        assert_eq!(
            names(&from_json(k).unwrap()),
            vec![("DB", "pw"), ("DB_USERNAME", "root"), ("DB_PORT", "5432")]
        );
        assert_eq!(
            names(&from_json(r#"{"API_KEY":"x"}"#).unwrap()),
            vec![("API_KEY", "x")]
        );
        assert_eq!(
            names(&from_json(r#"[{"key":"T","value":"v"}]"#).unwrap()),
            vec![("T", "v")]
        );
        assert!(from_json(r#"{"encrypted":true,"data":"x"}"#).is_err());
    }

    #[test]
    fn format_detection() {
        assert_eq!(parse("auto", "x.env", "A=1\n").unwrap().len(), 1);
        assert!(parse("auto", "v.kdbx", "").is_err());
        assert!(parse("xml", "a", "").is_err());
    }
}
