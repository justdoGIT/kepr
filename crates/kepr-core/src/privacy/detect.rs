//! Deterministic detectors with bounded matches; no network or model calls.

pub(super) struct Span {
    pub start: usize,
    pub end: usize,
    pub kind: &'static str,
}

pub(super) fn has_url_userinfo(text: &str) -> bool {
    text.match_indices("://").any(|(i, _)| {
        text[i + 3..]
            .split(|c: char| c == '/' || c == '?' || c == '#' || c.is_whitespace())
            .next()
            .is_some_and(|s| s.contains('@'))
    })
}

fn local(c: char) -> bool {
    c.is_alphanumeric() || "._%+-".contains(c)
}

fn domain(c: char) -> bool {
    c.is_alphanumeric() || c == '.' || c == '-'
}

pub(super) fn spans(text: &str, identifiers: &[String]) -> Result<Vec<Span>, &'static str> {
    let mut out = Vec::new();
    let mut add = |start, end, kind| -> Result<(), &'static str> {
        if out.len() >= 4096 {
            return Err("too many personal data matches");
        }
        out.push(Span { start, end, kind });
        Ok(())
    };
    for literal in identifiers {
        for (start, _) in text.match_indices(literal) {
            add(start, start + literal.len(), "identifier")?;
        }
    }
    for (at, _) in text.match_indices('@') {
        let start = text[..at]
            .char_indices()
            .rev()
            .take_while(|(_, c)| local(*c))
            .last()
            .map_or(at, |(i, _)| i);
        let end = text[at + 1..]
            .char_indices()
            .take_while(|(_, c)| domain(*c))
            .last()
            .map_or(at + 1, |(i, c)| at + 1 + i + c.len_utf8());
        let end = end - text[at + 1..end].len() + text[at + 1..end].trim_end_matches('.').len();
        if start < at && end > at + 1 && end - start <= 320 {
            add(start, end, "email")?;
        }
    }
    for prefix in ["/home/", "/Users/", "/root/", "C:\\Users\\", "C:/Users/"] {
        for (start, _) in text.match_indices(prefix) {
            let tail = text[start..]
                .split(|c: char| c.is_whitespace() || "\"'<>),;".contains(c))
                .next()
                .unwrap_or("")
                .trim_end_matches('.');
            add(start, start + tail.len(), "path")?;
        }
    }
    let mut offset = 0;
    while offset < text.len() {
        let c = text[offset..].chars().next().unwrap();
        if c == '+' {
            let candidate: String = text[offset..]
                .chars()
                .take(48)
                .take_while(|c| c.is_ascii_digit() || "+-(). ".contains(*c))
                .collect();
            let candidate = candidate.trim_end_matches(|c: char| !c.is_ascii_digit());
            let digits = candidate.bytes().filter(u8::is_ascii_digit).count();
            if (7..=15).contains(&digits) {
                add(offset, offset + candidate.len(), "phone")?;
                offset += candidate.len();
                continue;
            }
        }
        if c.is_ascii_hexdigit() || c == ':' {
            let candidate: String = text[offset..]
                .chars()
                .take_while(|c| c.is_ascii_hexdigit() || ".:".contains(*c))
                .collect();
            let candidate = candidate.trim_end_matches('.');
            if candidate.parse::<std::net::IpAddr>().is_ok() {
                add(offset, offset + candidate.len(), "ip")?;
            }
            if !candidate.is_empty() {
                offset += candidate.len();
                continue;
            }
        }
        offset += c.len_utf8();
    }
    out.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
    let mut merged: Vec<Span> = Vec::new();
    for span in out {
        if let Some(previous) = merged.last_mut() {
            if span.start < previous.end {
                previous.end = previous.end.max(span.end);
                continue;
            }
        }
        merged.push(span);
    }
    Ok(merged)
}
