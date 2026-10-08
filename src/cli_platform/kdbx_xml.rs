// cli_platform/kdbx_xml.rs — the XML inside a KDBX 4 payload (T10.02).
//
// A small pull tokenizer (no DTDs, no custom entities, so nothing expands)
// and a walk that keeps one record per current entry. Protected values
// (`<Value Protected="True">`, base64) are XORed with one ChaCha20 stream
// (key and nonce from SHA-512 of the inner-header key) in document order,
// so every protected value is decoded, including history entries and the
// recycle bin, which are then left out.
//
// Mapping, as for CSV imports: Title → NAME (the password), NAME_USERNAME,
// NAME_TOTP (`otp` / `TOTP Seed`), plus NAME_<FIELD> for other protected
// custom fields. URLs, notes and unprotected custom fields are not imported.

use base64::Engine;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use kepr_core::generate::ZeroString;
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

use crate::cli_import_parse::{kepr_name, Entry};

#[derive(Debug, PartialEq)]
pub enum Tok<'a> {
    /// Element name and whether it is `Protected="True"`.
    Start(&'a str, bool),
    End(&'a str),
    Text(String),
}

fn unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let Some(end) = rest.find(';') else { break };
        let ent = &rest[1..end];
        let c = match ent {
            "lt" => Some('<'),
            "gt" => Some('>'),
            "amp" => Some('&'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => ent
                .strip_prefix("#x")
                .map(|h| u32::from_str_radix(h, 16).ok())
                .unwrap_or_else(|| ent.strip_prefix('#').and_then(|d| d.parse().ok()))
                .and_then(char::from_u32),
        };
        match c {
            Some(c) => {
                out.push(c);
                rest = &rest[end + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// `open…close` at the start of `r` → (inside, after).
fn skip<'a>(r: &'a str, open: &str, close: &str) -> Option<(&'a str, &'a str)> {
    r.strip_prefix(open)
        .and_then(|r| r.find(close).map(|i| (&r[..i], &r[i + close.len()..])))
}

/// Tokenize `xml`; malformed markup is an error.
pub fn tokens(xml: &str) -> Result<Vec<Tok<'_>>, String> {
    let bad = || "the database XML is malformed".to_string();
    let (mut out, mut rest) = (Vec::new(), xml);
    while !rest.is_empty() {
        let Some(lt) = rest.find('<') else {
            out.push(Tok::Text(unescape(rest)));
            break;
        };
        if lt > 0 {
            out.push(Tok::Text(unescape(&rest[..lt])));
        }
        rest = &rest[lt..];
        if let Some((_, r)) = skip(rest, "<?", "?>").or_else(|| skip(rest, "<!--", "-->")) {
            rest = r;
        } else if let Some((text, r)) = skip(rest, "<![CDATA[", "]]>") {
            out.push(Tok::Text(text.to_string()));
            rest = r;
        } else if rest.starts_with("<!") {
            return Err("the database XML has a DTD; refusing it".into());
        } else {
            let gt = rest.find('>').ok_or_else(bad)?;
            let tag = &rest[1..gt];
            rest = &rest[gt + 1..];
            if let Some(name) = tag.strip_prefix('/') {
                out.push(Tok::End(name.trim()));
                continue;
            }
            let (tag, empty) = match tag.strip_suffix('/') {
                Some(t) => (t, true),
                None => (tag, false),
            };
            let name = tag.split_whitespace().next().ok_or_else(bad)?;
            let protected = tag.contains("Protected=\"True\"") || tag.contains("Protected='True'");
            out.push(Tok::Start(name, protected));
            if empty {
                out.push(Tok::End(name));
            }
        }
    }
    Ok(out)
}

/// The protected-value stream: ChaCha20 keyed from SHA-512 of the key.
pub struct Stream(chacha20::ChaCha20);

impl Stream {
    pub fn new(inner_key: &[u8]) -> Self {
        let mut h = Zeroizing::new([0u8; 64]);
        h.copy_from_slice(&Sha512::digest(inner_key));
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&h[..32]);
        let nonce: [u8; 12] = h[32..44].try_into().expect("64-byte hash");
        Self(chacha20::ChaCha20::new(&(*key).into(), &nonce.into()))
    }

    pub fn reveal(&mut self, b64: &str) -> Result<ZeroString, String> {
        let mut b = Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(b64.trim())
                .map_err(|_| "the database XML has a damaged protected value".to_string())?,
        );
        self.0.apply_keystream(&mut b);
        let s = std::str::from_utf8(&b).map_err(|_| WRONG_STREAM.to_string())?;
        Ok(ZeroString::from_string(s.to_string()))
    }
}

const WRONG_STREAM: &str = "the database XML has a protected value that does not decode";

#[derive(Default)]
struct Rec {
    fields: Vec<(String, ZeroString, bool)>,
}

impl Rec {
    fn get(&self, k: &str) -> Option<&ZeroString> {
        self.fields.iter().find(|f| f.0 == k).map(|f| &f.1)
    }
}

fn add(out: &mut Vec<Entry>, title: &str, suffix: &str, v: Option<&ZeroString>) {
    let (base, Some(v)) = (kepr_name(title), v) else {
        return;
    };
    if base.is_empty() || v.as_str().trim().is_empty() {
        return;
    }
    let name = match suffix {
        "" => base,
        s => format!("{base}_{}", kepr_name(s)),
    };
    out.push(Entry {
        name,
        value: ZeroString::from_string(v.as_str().to_string()),
    });
}

fn emit(out: &mut Vec<Entry>, r: &Rec) {
    let title = r
        .get("Title")
        .map(|t| t.as_str().to_string())
        .unwrap_or_default();
    add(out, &title, "", r.get("Password"));
    add(out, &title, "username", r.get("UserName"));
    add(out, &title, "totp", r.get("otp").or(r.get("TOTP Seed")));
    const KNOWN: &[&str] = &[
        "Title",
        "Password",
        "UserName",
        "otp",
        "TOTP Seed",
        "URL",
        "Notes",
    ];
    for (k, v, protected) in &r.fields {
        if *protected && !KNOWN.contains(&k.as_str()) {
            add(out, &title, k, Some(v));
        }
    }
}

/// Entries outside history and the recycle bin.
pub fn entries(xml: &[u8], inner_key: &[u8]) -> Result<Vec<Entry>, String> {
    let xml = std::str::from_utf8(xml).map_err(|_| "the database XML is not UTF-8")?;
    let toks = tokens(xml)?;
    let mut stream = Stream::new(inner_key);
    let (mut stack, mut text) = (Vec::<&str>::new(), String::new());
    let (mut bin, mut bin_on) = (String::new(), true);
    // Per open group: is it (or an ancestor) the recycle bin?
    let mut groups: Vec<bool> = Vec::new();
    let (mut rec, mut key, mut protected) = (None::<Rec>, String::new(), false);
    let mut out = Vec::new();
    for t in toks {
        match t {
            Tok::Text(s) => text.push_str(&s),
            Tok::Start(name, p) => {
                text.clear();
                protected = p;
                match name {
                    "Group" => groups.push(groups.last().copied().unwrap_or(false)),
                    "Entry" if stack.last() == Some(&"Group") => rec = Some(Rec::default()),
                    _ => {}
                }
                stack.push(name);
            }
            Tok::End(name) => {
                if stack.pop() != Some(name) {
                    return Err("the database XML is malformed".into());
                }
                let parent = stack.last().copied();
                match (name, parent) {
                    ("RecycleBinUUID", Some("Meta")) => bin = text.trim().to_string(),
                    ("RecycleBinEnabled", Some("Meta")) => bin_on = text.trim() == "True",
                    ("UUID", Some("Group")) => {
                        if bin_on && !bin.is_empty() && text.trim() == bin {
                            if let Some(g) = groups.last_mut() {
                                *g = true;
                            }
                        }
                    }
                    ("Group", _) => {
                        groups.pop();
                    }
                    ("Key", Some("String")) => key = text.clone(),
                    ("Value", Some("String")) => {
                        let v = if protected {
                            stream.reveal(&text)?
                        } else {
                            ZeroString::from_string(std::mem::take(&mut text))
                        };
                        let in_history = stack.contains(&"History");
                        if let (Some(r), false) = (rec.as_mut(), in_history) {
                            r.fields.push((std::mem::take(&mut key), v, protected));
                        }
                    }
                    ("Entry", Some("Group")) => {
                        if let (Some(r), false) = (rec.take(), *groups.last().unwrap_or(&false)) {
                            emit(&mut out, &r);
                        }
                    }
                    _ => {}
                }
                text.clear();
                protected = false;
            }
        }
    }
    if !stack.is_empty() {
        return Err("the database XML is truncated".into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenizer() {
        let t = tokens(
            "<?xml version=\"1.0\"?><!-- c --><A x='1'><B Protected=\"True\">q&amp;&#65;&#x42;&bogus</B><C/><![CDATA[<raw>]]></A>",
        )
        .unwrap();
        assert_eq!(
            t,
            [
                Tok::Start("A", false),
                Tok::Start("B", true),
                Tok::Text("q&AB&bogus".into()),
                Tok::End("B"),
                Tok::Start("C", false),
                Tok::End("C"),
                Tok::Text("<raw>".into()),
                Tok::End("A"),
            ]
        );
        assert!(tokens("<!DOCTYPE x [<!ENTITY a 'b'>]><x/>").is_err());
        assert!(tokens("<a").is_err());
    }

    /// Protected values XORed with the stream in document order.
    fn protect(stream: &mut chacha20::ChaCha20, v: &str) -> String {
        let mut b = v.as_bytes().to_vec();
        stream.apply_keystream(&mut b);
        base64::engine::general_purpose::STANDARD.encode(b)
    }

    #[test]
    fn entries_skip_history_and_the_recycle_bin() {
        let key = [9u8; 64];
        let h = Sha512::digest(key);
        let mut s = chacha20::ChaCha20::new(
            &<[u8; 32]>::try_from(&h[..32]).unwrap().into(),
            &<[u8; 12]>::try_from(&h[32..44]).unwrap().into(),
        );
        // `pw` is already protected; values are protected in document order.
        let entry = |title: &str, pw: &str, extra: &str| {
            format!(
                "<Entry><String><Key>Title</Key><Value>{title}</Value></String>\
                 <String><Key>UserName</Key><Value>u&amp;1</Value></String>\
                 <String><Key>Password</Key><Value Protected=\"True\">{pw}</Value></String>{extra}</Entry>"
            )
        };
        let mail_pw = protect(&mut s, "new-pw");
        let hist = format!(
            "<History>{}</History>",
            entry("Mail", &protect(&mut s, "old-pw"), "")
        );
        let mail = entry("Mail", &mail_pw, &hist);
        let ci_pw = protect(&mut s, "ci-pw");
        let api = format!(
            "<String><Key>API Key</Key><Value Protected=\"True\">{}</Value></String>",
            protect(&mut s, "k-123")
        );
        let ci = entry("CI bot", &ci_pw, &api);
        let trashed = entry("Gone", &protect(&mut s, "gone-pw"), "");
        let xml = format!(
            "<KeePassFile><Meta><RecycleBinEnabled>True</RecycleBinEnabled>\
             <RecycleBinUUID>BIN=</RecycleBinUUID></Meta><Root><Group><UUID>ROOT=</UUID>{mail}\
             <Group><UUID>SUB=</UUID>{ci}</Group><Group><UUID>BIN=</UUID>{trashed}</Group>\
             </Group></Root></KeePassFile>"
        );
        let got = entries(xml.as_bytes(), &key).unwrap();
        let pairs: Vec<(&str, &str)> = got
            .iter()
            .map(|e| (e.name.as_str(), e.value.as_str()))
            .collect();
        assert_eq!(
            pairs,
            [
                ("MAIL", "new-pw"),
                ("MAIL_USERNAME", "u&1"),
                ("CI_BOT", "ci-pw"),
                ("CI_BOT_USERNAME", "u&1"),
                ("CI_BOT_API_KEY", "k-123"),
            ]
        );
        // A wrong stream key leaves protected values undecodable or wrong.
        if let Ok(e) = entries(xml.as_bytes(), &[8u8; 64]) {
            assert!(e.iter().all(|e| e.value.as_str() != "new-pw"));
        }
        assert!(entries(b"<KeePassFile><Root>", &key).is_err());
    }
}
