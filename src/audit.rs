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
//   journalctl -t kepr-daemon
//   journalctl -t kepr-daemon KEPR_UID=1000
//   journalctl -t kepr-daemon KEPR_OP=get

use std::os::unix::net::UnixDatagram;
use std::sync::{Arc, OnceLock};

use crate::audit_chain::AuditChain;

// systemd journal socket
const JOURNAL_SOCKET: &str = "/run/systemd/journal/socket";

// Persistent datagram socket. `UnixDatagram::unbound()` per-call churned a
// socket fd on every audit event; cache it once for the life of the daemon
// and fall back to stderr (in `log`) if creation fails.
static JOURNAL_SOCK: OnceLock<Option<UnixDatagram>> = OnceLock::new();

// Phase 2 δ.2 — tamper-evident hash chain. journald is the primary
// audit channel (operators grep it, structured fields, log rotation
// works); the chain is the SECONDARY channel that adds tamper-
// evidence on top. `audit::log` fans out to both. If the chain
// append fails (disk full, permissions glitch), the operation is
// still recorded in journald — soft-fail to keep cred-store
// availability — but the soft failure is itself logged to stderr
// and to journald so an operator notices.
static AUDIT_CHAIN: OnceLock<Arc<AuditChain>> = OnceLock::new();

/// Install the chain handle. Called once at daemon startup, after
/// the StateDirectory is ready. Subsequent calls return Err so a
/// misconfigured restart can't silently swap chains mid-process.
pub fn install_chain(chain: Arc<AuditChain>) -> Result<(), String> {
    AUDIT_CHAIN
        .set(chain)
        .map_err(|_| "audit chain already installed".to_string())
}

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

    // Tee to the hash chain BEFORE journald so a chain-write
    // failure can be reported via the journald path itself (the
    // operator's primary alerting channel). The chain failure is
    // never fatal — cred-store availability outranks tamper-
    // evidence completeness — but it IS visible.
    if let Some(chain) = AUDIT_CHAIN.get() {
        if let Err(e) = chain.append(event.op, event.name, event.uid, event.username, &result_str) {
            // Chain failure is itself an audit-worthy event. Log
            // to stderr (journald sink) with a distinctive marker
            // so an operator's `journalctl -t kepr-daemon` grep
            // finds the gap.
            eprintln!(
                "[kepr-daemon] AUDIT_CHAIN_APPEND_FAILED op={} uid={} reason={}",
                event.op, event.uid, e
            );
        }
    }

    // Try systemd journal first (structured logging) unless forced to stderr
    // by KEPR_AUDIT_STDERR / KEPR_LOG_STDERR (e.g. during integration tests).
    let force_stderr = std::env::var_os("KEPR_AUDIT_STDERR").is_some()
        || std::env::var_os("KEPR_LOG_STDERR").is_some();
    if !force_stderr && log_to_journal(event, &name_str, &result_str) {
        return;
    }

    // Fallback to stderr (journald not available). The structured journal
    // entry is the audit record; this fallback is purely a dev-time hint
    // that something happened. Omit uid/username so the stderr path never
    // becomes an unstructured PII sink if a sysadmin redirects the daemon
    // output to a shared log file.
    eprintln!(
        "[kepr] op={} name={} result={}",
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
    // Fields prefixed with KEPR_ become indexed journal fields
    // allowing: journalctl KEPR_UID=1000

    let mut msg = String::new();

    // Syslog identifier — shows up in journalctl -t
    msg.push_str("SYSLOG_IDENTIFIER=kepr-daemon\n");

    // Priority: 6 = informational, 3 = error
    let priority = match &event.result {
        AuditResult::Ok => "6",
        AuditResult::Fail(_) => "3",
    };
    msg.push_str(&format!("PRIORITY={priority}\n"));

    // Human-readable message
    msg.push_str(&format!(
        "MESSAGE=kepr: op={} name={} uid={} user={} result={}\n",
        event.op, name_str, event.uid, event.username, result_str
    ));

    // Structured fields — indexed by journal
    msg.push_str(&format!("KEPR_OP={}\n", event.op));
    msg.push_str(&format!("KEPR_NAME={name_str}\n"));
    msg.push_str(&format!("KEPR_UID={}\n", event.uid));
    msg.push_str(&format!("KEPR_USER={}\n", event.username));
    msg.push_str(&format!("KEPR_RESULT={result_str}\n"));

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
        let forged = "FOO\nKEPR_OP=admin\r\nKEPR_UID=0";
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
