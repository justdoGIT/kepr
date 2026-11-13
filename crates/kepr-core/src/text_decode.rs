//! Shared decoding for screening only; outputs never exceed input size.
//! Buffers are wiped on drop. This is not a wire-format rewriter.

pub fn unescape_percent(body: &[u8]) -> Option<zeroize::Zeroizing<Vec<u8>>> {
    let mut i = memchr::memchr(b'%', body)?;
    let mut out = zeroize::Zeroizing::new(Vec::with_capacity(body.len()));
    out.extend_from_slice(&body[..i]);
    while i < body.len() {
        let decoded = (body[i] == b'%')
            .then(|| body.get(i + 1..i + 3))
            .flatten()
            .and_then(|h| std::str::from_utf8(h).ok())
            .and_then(|h| u8::from_str_radix(h, 16).ok());
        if let Some(b) = decoded {
            out.push(b);
            i += 3;
        } else {
            out.push(body[i]);
            i += 1;
        }
    }
    Some(out)
}

fn unicode_escape(body: &[u8], i: usize) -> Option<(char, usize)> {
    let hex = |at| {
        body.get(at..at + 4)
            .and_then(|h| std::str::from_utf8(h).ok())
            .and_then(|h| u32::from_str_radix(h, 16).ok())
    };
    let mut cp = hex(i)?;
    let mut consumed = 4;
    if (0xd800..=0xdbff).contains(&cp) && body.get(i + 4..i + 6) == Some(&b"\\u"[..]) {
        if let Some(low) = hex(i + 6).filter(|n| (0xdc00..=0xdfff).contains(n)) {
            cp = 0x10000 + ((cp - 0xd800) << 10) + (low - 0xdc00);
            consumed = 10;
        }
    }
    Some((char::from_u32(cp).unwrap_or('\u{fffd}'), consumed))
}

/// JSON string escapes decoded in place (`\\uXXXX`, `\\"`, `\\n`, …);
/// `None` when there are none. Not a JSON parser: it decodes escapes
/// wherever they are, which is what a scan wants.
pub fn unescape_json(body: &[u8]) -> Option<zeroize::Zeroizing<Vec<u8>>> {
    memchr::memchr(b'\\', body)?;
    let mut out = zeroize::Zeroizing::new(Vec::with_capacity(body.len()));
    let mut i = 0;
    while i < body.len() {
        if body[i] != b'\\' || i + 1 >= body.len() {
            out.push(body[i]);
            i += 1;
            continue;
        }
        let e = body[i + 1];
        i += 2;
        match e {
            b'n' => out.push(b'\n'),
            b't' => out.push(b'\t'),
            b'r' => out.push(b'\r'),
            b'b' => out.push(8),
            b'f' => out.push(12),
            b'u' => match unicode_escape(body, i) {
                Some((c, consumed)) => {
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                    i += consumed;
                }
                None => out.extend_from_slice(b"\\u"),
            },
            other => out.push(other), // \" \\ \/ and anything else
        }
    }
    Some(out)
}
