// cli_policy/compliance_html.rs — `kepr report compliance --framework F
// --html FILE` (T13.10): the report as one self-contained page. All text is
// escaped, there is no script and no external request, and the file is
// written 0600 without replacing an existing one.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

use kepr_core::protocol_policy::AccessRow;

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c => o.push(c),
        }
    }
    o
}

/// `kind` is `ID  status` (see `compliance::build`).
fn split(kind: &str) -> (&str, &str) {
    kind.rsplit_once("  ").unwrap_or((kind, ""))
}

pub fn render(framework: &str, rows: &[AccessRow]) -> String {
    let count = |s: &str| rows.iter().filter(|r| split(&r.kind).1 == s).count();
    let mut h = String::new();
    h.push_str("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n");
    h.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    h.push_str(&format!(
        "<title>kepr compliance: {}</title>\n",
        esc(framework)
    ));
    h.push_str(
        "<style>body{font:16px/1.5 system-ui,sans-serif;margin:0 auto;max-width:60rem;padding:1rem;\
         color:#1a1a1a;background:#fff}@media(prefers-color-scheme:dark){body{color:#e8e8e8;background:#161616}}\
         .wrap{overflow-x:auto}table{border-collapse:collapse;width:100%}th,td{text-align:left;\
         padding:.5rem;border-bottom:1px solid #8884;vertical-align:top}.pass{color:#1a7f37}.fail{color:#cf222e;\
         font-weight:600}.manual{color:#9a6700}</style>\n</head><body>\n",
    );
    h.push_str(&format!(
        "<h1>Compliance evidence: {}</h1>\n<p>{} pass, {} fail, {} manual. This is evidence for an \
         assessor, not a certification.</p>\n",
        esc(&framework.to_uppercase()),
        count("pass"),
        count("fail"),
        count("manual"),
    ));
    h.push_str("<div class=\"wrap\"><table><thead><tr><th>Control</th><th>Status</th><th>Evidence</th></tr></thead><tbody>\n");
    for r in rows {
        let (id, status) = split(&r.kind);
        let class = match status {
            "pass" | "fail" | "manual" => status,
            _ => "manual",
        };
        h.push_str(&format!(
            "<tr><td>{}</td><td class=\"{class}\">{}</td><td>{}</td></tr>\n",
            esc(id),
            esc(status),
            esc(&r.detail)
        ));
    }
    h.push_str("</tbody></table></div>\n</body></html>\n");
    h
}

pub fn write(path: &str, framework: &str, rows: &[AccessRow]) -> Result<(), String> {
    let html = render(framework, rows);
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut f| f.write_all(html.as_bytes()).and_then(|()| f.sync_all()))
        .map_err(|e| format!("{path}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(kind: &str, detail: &str) -> AccessRow {
        AccessRow {
            kind: kind.into(),
            detail: detail.into(),
        }
    }

    #[test]
    fn everything_from_the_report_is_escaped() {
        let rows = vec![row(
            "<script>x</script>  pass",
            "t\"itle\" & <img src=x onerror=alert(1)>: ok",
        )];
        let h = render("sox<b>", &rows);
        assert!(!h.contains("<script"), "{h}");
        assert!(!h.contains("<img"), "{h}");
        assert!(!h.contains("<b>"), "{h}");
        assert!(h.contains("&lt;script&gt;x&lt;/script&gt;"));
        assert!(h.contains("t&quot;itle&quot; &amp; &lt;img"));
    }

    #[test]
    fn the_page_makes_no_external_request_and_runs_no_script() {
        let h = render("pci", &[row("A1  pass", "fine"), row("A2  fail", "bad")]);
        for banned in [
            "http:", "https:", "<script", "<link", "src=", "@import", "url(",
        ] {
            assert!(!h.contains(banned), "{banned} in page");
        }
        assert!(h.contains("1 pass, 1 fail, 0 manual"));
        assert!(h.contains("class=\"fail\">fail"));
    }

    #[test]
    fn an_unknown_status_is_shown_as_manual_and_the_file_is_private_and_not_replaced() {
        let h = render("nist", &[row("X  weird", "d")]);
        assert!(h.contains("class=\"manual\">weird"));
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("r.html");
        let ps = p.to_str().unwrap();
        write(ps, "nist", &[row("X  pass", "d")]).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(
            write(ps, "nist", &[]).is_err(),
            "an existing file is not replaced"
        );
    }
}
