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
    let result_str = match &event.result {
        AuditResult::Ok => "ok".to_string(),
        AuditResult::Fail(msg) => format!("fail: {msg}"),
    };

    let name_str = event.name.unwrap_or("-");

    // Try systemd journal first (structured logging)
    if log_to_journal(event, &result_str) {
        return;
    }

    // Fallback to stderr (journald not available)
    eprintln!(
        "[credman] op={} name={} uid={} user={} result={}",
        event.op, name_str, "[redacted]", "[redacted]", result_str
    );
}

// ── Journal logging ───────────────────────────────────────────────────────────

fn log_to_journal(event: &AuditEvent, result_str: &str) -> bool {
    // systemd journal protocol: newline-separated KEY=value pairs
    // sent as a datagram to /run/systemd/journal/socket
    //
    // Fields prefixed with CREDMAN_ become indexed journal fields
    // allowing: journalctl CREDMAN_UID=1000

    let name_str = event.name.unwrap_or("-");

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
        event.op, name_str, "[redacted]", "[redacted]", result_str
    ));

    // Structured fields — indexed by journal
    msg.push_str(&format!("CREDMAN_OP={}\n", event.op));
    msg.push_str(&format!("CREDMAN_NAME={}\n", name_str));
    msg.push_str("CREDMAN_UID=[redacted]\n");
    msg.push_str("CREDMAN_USER=[redacted]\n");
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
