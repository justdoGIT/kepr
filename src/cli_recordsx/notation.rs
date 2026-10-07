// cli_recordsx/notation.rs — T5.05 `kepr://` notation: parser and the
// template scanner `kepr inject` uses.
//
//   kepr://NAME                     the whole value
//   kepr://NAME/field               one record field (an array: its first item)
//   kepr://NAME/field[i]            item i;  [] = every item, as a JSON array
//   kepr://NAME/field[i][sub]       a property of a structured item;
//   kepr://NAME/field[sub]          [sub] alone = item 0's; [][sub] = all of them
//   kepr://NAME/custom_field/LABEL  a custom field (`custom` object), same [..]
//   kepr://NAME/file/FILENAME       an attachment's contents (T5.03)
//
// Labels and file names may contain anything but control characters;
// `\/`, `\[`, `\]` and `\\` escape those characters (`\ ` a space, in
// templates). Errors name the 1-based column of the whole notation.

pub const PREFIX: &str = "kepr://";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Index {
    None,
    At(usize),
    All,
    Prop(String),
    AtProp(usize, String),
    AllProp(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sel {
    Whole,
    Field { field: String, index: Index },
    Custom { label: String, index: Index },
    File(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notation {
    /// Upper-case credential name.
    pub name: String,
    pub sel: Sel,
}

fn field_char(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'
}

fn name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn prop_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

/// Ends a reference inside a template.
fn stop(c: char) -> bool {
    c.is_whitespace() || matches!(c, '"' | '\'' | '`' | '<' | '>') || c.is_control()
}

struct P<'a> {
    s: &'a str,
    i: usize,
}

impl P<'_> {
    fn peek(&self) -> Option<char> {
        self.s[self.i..].chars().next()
    }
    fn col(&self) -> usize {
        self.s[..self.i].chars().count() + 1
    }
    fn err<T>(&self, what: &str) -> Result<T, String> {
        Err(format!("{}: {what} at column {}", self.s, self.col()))
    }
    fn take_while(&mut self, f: fn(char) -> bool) -> &str {
        let start = self.i;
        while self.peek().is_some_and(f) {
            self.i += self.peek().map_or(0, char::len_utf8);
        }
        &self.s[start..self.i]
    }
    fn eat(&mut self, c: char) -> bool {
        if self.peek() == Some(c) {
            self.i += c.len_utf8();
            true
        } else {
            false
        }
    }
    /// A label or file name up to `/`, `[` (labels only) or the end.
    fn label(&mut self, brackets: bool) -> Result<String, String> {
        let mut out = String::new();
        while let Some(c) = self.peek() {
            if c == '\\' {
                self.i += 1;
                match self.peek() {
                    Some(e) if !e.is_control() => {
                        out.push(e);
                        self.i += e.len_utf8();
                    }
                    _ => return self.err("dangling \\"),
                }
            } else if c == '/' || (brackets && c == '[') || c.is_control() {
                break;
            } else {
                out.push(c);
                self.i += c.len_utf8();
            }
        }
        if out.is_empty() {
            return self.err("empty label");
        }
        Ok(out)
    }
    /// Up to two `[..]` groups.
    fn index(&mut self) -> Result<Index, String> {
        let mut parts: Vec<Option<String>> = Vec::new();
        while self.peek() == Some('[') {
            let open = self.col();
            self.i += 1;
            let inner = self.take_while(|c| c != ']' && c != '[' && !c.is_control());
            let inner = inner.to_string();
            if !self.eat(']') {
                return Err(format!("{}: unclosed [ at column {open}", self.s));
            }
            if parts.len() == 2 {
                return Err(format!("{}: too many [..] at column {open}", self.s));
            }
            parts.push((!inner.is_empty()).then_some(inner));
        }
        let num = |s: &str| s.parse::<usize>().ok();
        let prop_ok = |s: &str| s.chars().all(prop_char) && num(s).is_none();
        Ok(match parts.as_slice() {
            [] => Index::None,
            [None] => Index::All,
            [Some(a)] if num(a).is_some() => Index::At(num(a).unwrap_or(0)),
            [Some(a)] if prop_ok(a) => Index::Prop(a.clone()),
            [Some(a), Some(b)] if num(a).is_some() && prop_ok(b) => {
                Index::AtProp(num(a).unwrap_or(0), b.clone())
            }
            [None, Some(b)] if prop_ok(b) => Index::AllProp(b.clone()),
            _ => return self.err("bad index"),
        })
    }
}

/// Parse a whole notation (`kepr resolve`, `--env VAR=…`, manifest maps).
pub fn parse(s: &str) -> Result<Notation, String> {
    if !s.starts_with(PREFIX) {
        return Err(format!("{s}: a reference starts with {PREFIX}"));
    }
    let mut p = P { s, i: PREFIX.len() };
    let name = p.take_while(name_char).to_uppercase();
    if name.is_empty() {
        return p.err("expected a credential name");
    }
    let sel = if !p.eat('/') {
        Sel::Whole
    } else {
        let field = p.take_while(field_char).to_string();
        if field.is_empty() {
            return p.err("expected a field name (a-z, 0-9, _)");
        }
        match (field.as_str(), p.peek()) {
            ("custom_field", Some('/')) => {
                p.i += 1;
                let label = p.label(true)?;
                Sel::Custom {
                    label,
                    index: p.index()?,
                }
            }
            ("file", Some('/')) => {
                p.i += 1;
                Sel::File(p.label(false)?)
            }
            _ => Sel::Field {
                field,
                index: p.index()?,
            },
        }
    };
    if p.i < s.len() {
        return p.err("unexpected character");
    }
    Ok(Notation { name, sel })
}

/// In a template, the reference after a `kepr://` at the start of
/// `rest`: `(bytes it spans, text with NAME upper-cased)`. `None` when no
/// name follows. Lenient: it stops before anything that would not parse,
/// so `kepr://DB/Up` is `kepr://DB` followed by `/Up`.
pub fn scan(rest: &str) -> Option<(usize, String)> {
    let mut p = P { s: rest, i: 0 };
    let name_len = p.take_while(name_char).len();
    if name_len == 0 {
        return None;
    }
    let mut end = p.i;
    if p.eat('/') && p.peek().is_some_and(field_char) {
        let field = p.take_while(field_char).to_string();
        end = p.i;
        if matches!(field.as_str(), "custom_field" | "file") && p.peek() == Some('/') {
            let save = p.i;
            p.i += 1;
            if template_label(&mut p, field == "custom_field") {
                end = p.i;
            } else {
                p.i = save;
            }
        }
        if p.i == end && field != "file" {
            end = bracket_groups(&mut p, end);
        }
    }
    let text = format!(
        "{}{}",
        rest[..name_len].to_uppercase(),
        &rest[name_len..end]
    );
    Some((end, text))
}

/// A label in a template: runs to a stop character; true if non-empty.
fn template_label(p: &mut P, brackets: bool) -> bool {
    let start = p.i;
    while let Some(c) = p.peek() {
        if c == '\\' {
            p.i += 1;
            match p.peek() {
                Some(e) if !e.is_control() => p.i += e.len_utf8(),
                _ => {
                    p.i -= 1;
                    break;
                }
            }
        } else if stop(c) || c == '/' || (brackets && c == '[') {
            break;
        } else {
            p.i += c.len_utf8();
        }
    }
    p.i > start
}

/// The most whole `[..]` groups (up to two) that parse; returns the new end.
fn bracket_groups(p: &mut P, end: usize) -> usize {
    let mut ends = vec![end];
    for _ in 0..2 {
        if p.peek() != Some('[') {
            break;
        }
        let Some(close) = p.s[p.i..].find(']') else {
            break;
        };
        let inner = &p.s[p.i + 1..p.i + close];
        if inner.chars().any(|c| stop(c) || c == '[') {
            break;
        }
        p.i += close + 1;
        ends.push(p.i);
    }
    let parses = |e: &usize| parse(&format!("{PREFIX}X/x{}", &p.s[end..*e])).is_ok();
    ends.into_iter().rev().find(parses).unwrap_or(end)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(f: &str, index: Index) -> Sel {
        Sel::Field {
            field: f.into(),
            index,
        }
    }

    #[test]
    fn notations_parse_to_their_forms() {
        let table: Vec<(&str, &str, Sel)> = vec![
            ("kepr://db", "DB", Sel::Whole),
            ("kepr://DB/password", "DB", field("password", Index::None)),
            ("kepr://L/url[1]", "L", field("url", Index::At(1))),
            ("kepr://L/url[]", "L", field("url", Index::All)),
            (
                "kepr://P/phone[0][number]",
                "P",
                field("phone", Index::AtProp(0, "number".into())),
            ),
            (
                "kepr://P/name[first]",
                "P",
                field("name", Index::Prop("first".into())),
            ),
            (
                "kepr://P/phone[][type]",
                "P",
                field("phone", Index::AllProp("type".into())),
            ),
            (
                r"kepr://R/custom_field/Q\/A\[1\]",
                "R",
                Sel::Custom {
                    label: "Q/A[1]".into(),
                    index: Index::None,
                },
            ),
            (
                "kepr://R/custom_field/Pins[2]",
                "R",
                Sel::Custom {
                    label: "Pins".into(),
                    index: Index::At(2),
                },
            ),
            (
                "kepr://R/custom_field/two words",
                "R",
                Sel::Custom {
                    label: "two words".into(),
                    index: Index::None,
                },
            ),
            (
                "kepr://R/file/id card.pdf",
                "R",
                Sel::File("id card.pdf".into()),
            ),
        ];
        for (text, name, sel) in table {
            let n = parse(text).unwrap_or_else(|e| panic!("{text}: {e}"));
            assert_eq!(n.name, name, "{text}");
            assert_eq!(n.sel, sel, "{text}");
        }
    }

    #[test]
    fn malformed_notation_names_the_column() {
        for (text, col, what) in [
            ("kepr://", 8, "credential name"),
            ("kepr://DB/", 11, "field name"),
            ("kepr://DB/Up", 11, "field name"),
            ("kepr://DB/url[x", 14, "unclosed"),
            ("kepr://DB/url[a b]", 19, "bad index"),
            ("kepr://DB/url[1][2]", 20, "bad index"),
            ("kepr://DB/url[0][a][b]", 20, "too many"),
            ("kepr://DB/url/x", 14, "unexpected"),
            ("kepr://DB/custom_field/", 24, "empty label"),
            (r"kepr://DB/custom_field/a\", 26, "dangling"),
        ] {
            let e = parse(text).unwrap_err();
            assert!(
                e.contains(&format!("column {col}")) && e.contains(what),
                "{text}: {e}"
            );
        }
        assert!(parse("http://x").unwrap_err().contains("kepr://"));
    }

    #[test]
    fn scanning_templates_stops_where_the_reference_ends() {
        let s = |t: &str| scan(t).map(|(n, k)| (t[..n].to_string(), k));
        assert_eq!(s("db/user:x"), Some(("db/user".into(), "DB/user".into())));
        assert_eq!(s("DB/Up"), Some(("DB".into(), "DB".into())));
        assert_eq!(s("DB/"), Some(("DB".into(), "DB".into())));
        assert_eq!(s("L/url[0] tail").unwrap().1, "L/url[0]");
        assert_eq!(s("L/url[0][host]").unwrap().1, "L/url[0][host]");
        assert_eq!(s("L/url[x y]").unwrap().1, "L/url");
        assert_eq!(s("L/url[0").unwrap().1, "L/url");
        assert_eq!(s("L/url[1][2]").unwrap().1, "L/url[1]");
        assert_eq!(s("L/url[a][b]").unwrap().1, "L/url[a]");
        assert_eq!(
            s(r"R/custom_field/a\ b\/c rest").unwrap().1,
            r"R/custom_field/a\ b\/c"
        );
        assert_eq!(
            s("R/custom_field/Pin[1]\"").unwrap().1,
            "R/custom_field/Pin[1]"
        );
        assert_eq!(s("R/file/notes.txt\n").unwrap().1, "R/file/notes.txt");
        assert_eq!(s("R/file/ x").unwrap().1, "R/file");
        assert_eq!(s("/x"), None);
        // Whatever the scanner keeps parses.
        for t in [
            "L/url[0][host]",
            r"R/custom_field/a\ b",
            "R/file/x.y",
            "DB/user",
        ] {
            let k = scan(t).unwrap().1;
            assert!(parse(&format!("{PREFIX}{k}")).is_ok(), "{k}");
        }
    }
}
