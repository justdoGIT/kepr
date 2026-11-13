//! Conservative SQL classification for MCP's one-statement database tool.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementClass {
    Query,
    Write,
    Admin,
}

impl StatementClass {
    pub fn action(self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::Write => "write",
            Self::Admin => "admin",
        }
    }
}

fn skip_quote(bytes: &[u8], i: &mut usize, quote: u8) -> Result<(), String> {
    *i += 1;
    while *i < bytes.len() {
        if bytes[*i] == quote {
            if bytes.get(*i + 1) == Some(&quote) {
                *i += 2;
            } else {
                *i += 1;
                return Ok(());
            }
        } else if quote == b'\'' && bytes[*i] == b'\\' {
            return Err("SQL backslash escapes are refused".into());
        } else {
            *i += 1;
        }
    }
    Err("SQL contains an unterminated quoted value".into())
}

fn skip_block_comment(bytes: &[u8], i: &mut usize) -> Result<(), String> {
    let mut depth = 1usize;
    *i += 2;
    while *i < bytes.len() {
        if bytes.get(*i..*i + 2) == Some(b"/*") {
            depth += 1;
            *i += 2;
        } else if bytes.get(*i..*i + 2) == Some(b"*/") {
            depth -= 1;
            *i += 2;
            if depth == 0 {
                return Ok(());
            }
        } else {
            *i += 1;
        }
    }
    Err("SQL contains an unterminated comment".into())
}

fn dollar_delimiter(bytes: &[u8], start: usize) -> Option<&[u8]> {
    if bytes.get(start) != Some(&b'$') {
        return None;
    }
    let mut end = start + 1;
    if bytes.get(end) == Some(&b'$') {
        return Some(&bytes[start..=end]);
    }
    if !bytes
        .get(end)
        .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
    {
        return None;
    }
    end += 1;
    while bytes
        .get(end)
        .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
    {
        end += 1;
    }
    (bytes.get(end) == Some(&b'$')).then(|| &bytes[start..=end])
}

fn skip_dollar_quote(bytes: &[u8], i: &mut usize) -> Result<(), String> {
    let delimiter = dollar_delimiter(bytes, *i).ok_or("invalid SQL dollar quote")?;
    let body = &bytes[*i + delimiter.len()..];
    let end = body
        .windows(delimiter.len())
        .position(|w| w == delimiter)
        .ok_or("SQL contains an unterminated dollar-quoted value")?;
    *i += delimiter.len() + end + delimiter.len();
    Ok(())
}

fn word(bytes: &[u8], i: &mut usize) -> Option<String> {
    if !bytes
        .get(*i)
        .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
    {
        return None;
    }
    let start = *i;
    *i += 1;
    while bytes
        .get(*i)
        .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
    {
        *i += 1;
    }
    Some(String::from_utf8_lossy(&bytes[start..*i]).to_ascii_uppercase())
}

/// Refuse every semicolon outside quoted values and comments, even when trailing.
pub fn classify(sql: &str) -> Result<StatementClass, String> {
    let bytes = sql.as_bytes();
    let (mut i, mut first) = (0, None);
    while i < bytes.len() {
        match bytes[i] {
            b if b.is_ascii_whitespace() => i += 1,
            b'-' if bytes.get(i + 1) == Some(&b'-') => {
                i += 2;
                while bytes.get(i).is_some_and(|b| *b != b'\n') {
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => skip_block_comment(bytes, &mut i)?,
            b';' => {
                return Err("SQL must contain exactly one statement; semicolons are refused".into())
            }
            b'\'' | b'"' => {
                let quote = bytes[i];
                skip_quote(bytes, &mut i, quote)?;
            }
            b'$' if dollar_delimiter(bytes, i).is_some() => skip_dollar_quote(bytes, &mut i)?,
            _ => {
                if first.is_none() {
                    first = word(bytes, &mut i);
                } else {
                    i += 1;
                }
            }
        }
    }
    match first.as_deref().ok_or("SQL statement is empty")? {
        "SELECT" | "SHOW" | "EXPLAIN" | "TABLE" | "VALUES" | "FETCH" => Ok(StatementClass::Query),
        "INSERT" | "UPDATE" | "DELETE" | "MERGE" => Ok(StatementClass::Write),
        _ => Ok(StatementClass::Admin),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_one_statement_and_refuses_chaining() {
        use StatementClass::*;
        for (sql, expect) in [
            ("select 1", Query),
            ("  -- note\n SELECT * FROM t", Query),
            ("/* a /* nested */ b */ show time zone", Query),
            ("EXPLAIN select 1", Query),
            ("insert into t values ('a;b')", Write),
            ("update t set a = 'it''s' where b = 1", Write),
            ("delete from t where a = $$x; y$$", Write),
            ("drop table t", Admin),
            ("create table t (a int)", Admin),
            ("truncate t", Admin),
            ("grant select on t to r", Admin),
        ] {
            assert_eq!(classify(sql), Ok(expect), "{sql}");
        }
        for bad in [
            "select 1;",
            "select 1; select 2",
            "select 1; -- trailing",
            "select 'unterminated",
            "select 'a\\\\'; drop table t; select 'x'",
            "select /* unterminated",
            "select $tag$ unterminated",
            "   ",
            ";",
        ] {
            assert!(classify(bad).is_err(), "{bad}");
        }
    }
}
