// audit.rs — structured audit logging to systemd journal
//
// Every credential operation is logged with:
//   - timestamp (from journal)
//   - operation type
//   - credential name (never the value)
//   - requesting uid + username
//   - result (ok/fail)
//   - error message if failed
//
// View logs:
//   journalctl -t credman-daemon
//   journalctl -t credman-daemon CREDMAN_UID=1000
//   journalctl -t credman-daemon CREDMAN_OP=get

use std::os::unix::net::UnixDatagram;
use std::sync::OnceLock;

// systemd journal socket
const JOURNAL_SOCKET: &str = "/run/systemd/journal/socket";

// Persistent datagram socket. `UnixDatagram::unbound()` per-call churned a
// socket fd on every audit event; cache it once for the life of the daemon
// and fall back to stderr (in `log`) if creation fails.
static JOURNAL_SOCK: OnceLock<Option<UnixDatagram>> = OnceLock::new();

fn journal_sock() -> Option<&'static UnixDatagram> {
    JOURNAL_SOCK
        .get_or_init(|| UnixDatagram::unbound().ok())
        .as_ref()
}

// ── Public API ────────────────────────────────────────────────────────────────

pub struct AuditEvent<'a> {
    pub op: &'a str,           // set|get|delete|list|check|ping
    pub name: Option<&'a str>, // credential name (None for list/check)
    pub uid: u32,
    pub username: &'a str,
    pub result: AuditResult,
}

pub enum AuditResult {
    Ok,
    Fail(String),
}

pub fn log(event: &AuditEvent) {
    // Sanitise both fields at the audit boundary. handle_set (and any
    // future handler) calls audit::log with the caller-supplied name
    // *before* validate_name runs, so a malicious name containing CR/LF
    // would otherwise forge extra journald KEY=value pairs or fake log
    // lines in the stderr fallback.
    let result_str = escape_log_field(&match &event.result {
        AuditResult::Ok => "ok".to_string(),
        AuditResult::Fail(msg) => format!("fail: {msg}"),
    });

    let name_str = escape_log_field(event.name.unwrap_or("-"));

    // Try systemd journal first (structured logging)
    if log_to_journal(event, &name_str, &result_str) {
        return;
    }

    // Fallback to stderr (journald not available). The structured journal
    // entry is the audit record; this fallback is purely a dev-time hint
    // that something happened. Omit uid/username so the stderr path never
    // becomes an unstructured PII sink if a sysadmin redirects the daemon
    // output to a shared log file.
    eprintln!(
        "[credman] op={} name={} result={}",
        event.op, name_str, result_str
    );
}

// Replace control characters that would break the journald KEY=value
// framing or let an attacker forge log lines. Cap length so an oversize
// name can't flood the journal. Kept intentionally minimal — valid
// credential names are already [A-Z0-9_]; we only see anything else on
// the validate_name-rejection path.
fn escape_log_field(s: &str) -> String {
    // Cap by char (not byte) count so multi-byte UTF-8 can't panic on a
    // slice boundary. 256 is generous given valid names are <= 128 ASCII
    // chars — this only trims oversize values that reached audit::log
    // from a validate_name-rejection path.
    const MAX_CHARS: usize = 256;
    let mut out = String::with_capacity(s.len());
    for c in s.chars().take(MAX_CHARS) {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() => out.push('?'),
            c => out.push(c),
        }
    }
    out
}

// ── Journal logging ───────────────────────────────────────────────────────────

fn log_to_journal(event: &AuditEvent, name_str: &str, result_str: &str) -> bool {
    // systemd journal protocol: newline-separated KEY=value pairs
    // sent as a datagram to /run/systemd/journal/socket
    //
    // Fields prefixed with CREDMAN_ become indexed journal fields
    // allowing: journalctl CREDMAN_UID=1000

    let mut msg = String::new();

    // Syslog identifier — shows up in journalctl -t
    msg.push_str("SYSLOG_IDENTIFIER=credman-daemon\n");

    // Priority: 6 = informational, 3 = error
    let priority = match &event.result {
        AuditResult::Ok => "6",
        AuditResult::Fail(_) => "3",
    };
    msg.push_str(&format!("PRIORITY={priority}\n"));

    // Human-readable message
    msg.push_str(&format!(
        "MESSAGE=credman: op={} name={} uid={} user={} result={}\n",
        event.op, name_str, event.uid, event.username, result_str
    ));

    // Structured fields — indexed by journal
    msg.push_str(&format!("CREDMAN_OP={}\n", event.op));
    msg.push_str(&format!("CREDMAN_NAME={}\n", name_str));
    msg.push_str(&format!("CREDMAN_UID={}\n", event.uid));
    msg.push_str(&format!("CREDMAN_USER={}\n", event.username));
    msg.push_str(&format!("CREDMAN_RESULT={}\n", result_str));

    // Send to journal socket via the cached datagram fd.
    match journal_sock() {
        Some(sock) => sock.send_to(msg.as_bytes(), JOURNAL_SOCKET).is_ok(),
        None => false,
    }
}

// ── Username lookup ───────────────────────────────────────────────────────────

/// Look up username from uid via /etc/passwd.
/// Returns "uid=N" if not found — never fails.
pub fn username_for_uid(uid: u32) -> String {
    // Read /etc/passwd directly — no libc getpwuid needed
    if let Ok(content) = std::fs::read_to_string("/etc/passwd") {
        for line in content.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() >= 3 {
                if let Ok(u) = fields[2].parse::<u32>() {
                    if u == uid {
                        return fields[0].to_string();
                    }
                }
            }
        }
    }
    format!("uid={uid}")
}

#[cfg(test)]
mod tests {
    use super::escape_log_field;

    #[test]
    fn escapes_newline_and_carriage_return() {
        let forged = "FOO\nCREDMAN_OP=admin\r\nCREDMAN_UID=0";
        let out = escape_log_field(forged);
        assert!(!out.contains('\n'), "raw LF leaked: {out}");
        assert!(!out.contains('\r'), "raw CR leaked: {out}");
        assert!(out.contains("\\n") && out.contains("\\r"));
    }

    #[test]
    fn strips_other_controls() {
        // BEL, NUL, ESC would let an attacker smuggle terminal escape
        // sequences through a log viewer; replace them all.
        let s = "A\x07B\x00C\x1bD";
        let out = escape_log_field(s);
        assert_eq!(out, "A?B?C?D");
    }

    #[test]
    fn passes_valid_ascii_unchanged() {
        assert_eq!(escape_log_field("OPENAI_API_KEY"), "OPENAI_API_KEY");
        assert_eq!(escape_log_field("-"), "-");
    }

    #[test]
    fn caps_oversize_input_without_utf8_panic() {
        // Repeat a 3-byte UTF-8 char past the 256-char cap. The previous
        // byte-slice trim would have panicked on a codepoint boundary.
        let s: String = "ñ".repeat(300);
        let out = escape_log_field(&s);
        assert_eq!(out.chars().count(), 256);
    }
}
