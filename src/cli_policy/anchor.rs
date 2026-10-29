// cli_policy/anchor.rs — `kepr audit anchor` and `kepr audit verify
// --anchor FILE` (T13.22).
//
// The audit chain detects an edited or dropped entry, not a whole-file
// replacement by someone who can write it. An anchor is the chain head
// (`seq`, `hash`, time) published where the daemon's account cannot
// rewrite it: a remote syslog host, or a JSON-lines file on another
// machine or an append-only mount. `verify --anchor` asks the daemon to
// check the log against every anchor in a file.

use std::io::Write;
use std::net::UdpSocket;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use kepr_core::protocol::{Request, Response};
use kepr_core::protocol_policy::{AnchorPoint, PolicyRequest};

use super::forward::Target;
use super::tail;
use crate::cli_extra::flag;
use crate::{cli_mode, cli_ui};

const USAGE: &str = "usage: kepr audit anchor --to jsonl:PATH|syslog:udp://HOST[:PORT]|s3:BUCKET[/PREFIX] [--once] [--interval SECS] [--state FILE]\n       kepr audit verify --anchor FILE";

/// Anchors one `verify` run sends (the daemon accepts 500); the newest.
const MAX_SENT: usize = 500;

/// The anchor as one JSON line.
pub fn line(seq: u64, hash: &str, at: u64) -> String {
    serde_json::json!({"seq": seq, "hash": hash, "at": at}).to_string()
}

/// Anchors from a JSON-lines file (syslog-wrapped lines are accepted: the
/// JSON object is whatever follows the first `{`). Blank lines are
/// skipped; any other line must parse. The newest `MAX_SENT` are kept.
pub fn parse_anchors(text: &str) -> Result<Vec<AnchorPoint>, String> {
    let mut out = Vec::new();
    for (i, l) in text.lines().enumerate() {
        if l.trim().is_empty() {
            continue;
        }
        let json = l.find('{').map_or(l, |p| &l[p..]);
        let v: serde_json::Value = serde_json::from_str(json)
            .map_err(|_| format!("anchor file line {}: not JSON", i + 1))?;
        match (v["seq"].as_u64(), v["hash"].as_str()) {
            (Some(seq), Some(hash)) if seq > 0 && !hash.is_empty() => out.push(AnchorPoint {
                seq,
                hash: hash.to_string(),
            }),
            _ => return Err(format!("anchor file line {}: needs seq and hash", i + 1)),
        }
    }
    if out.len() > MAX_SENT {
        out.drain(..out.len() - MAX_SENT);
    }
    Ok(out)
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct State {
    /// The `seq` last published: the resume cursor.
    seq: u64,
}

trait Sink {
    fn send(&mut self, line: &str) -> Result<(), String>;
}

struct Jsonl(PathBuf);

impl Sink for Jsonl {
    fn send(&mut self, line: &str) -> Result<(), String> {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(&self.0)
            .map_err(|e| format!("{}: {e}", self.0.display()))?;
        f.write_all(format!("{line}\n").as_bytes())
            .and_then(|()| f.sync_data())
            .map_err(|e| format!("{}: {e}", self.0.display()))
    }
}

struct Syslog {
    sock: UdpSocket,
    to: String,
    host: String,
}

impl Sink for Syslog {
    fn send(&mut self, line: &str) -> Result<(), String> {
        // RFC 5424: facility 13 (log audit), severity notice.
        let msg = format!("<109>1 - {} kepr-anchor - - - {line}", self.host);
        self.sock
            .send_to(msg.as_bytes(), &self.to)
            .map(|_| ())
            .map_err(|e| format!("syslog send: {e}"))
    }
}

/// `s3:BUCKET[/PREFIX]`: one object per anchor, `anchor-<seq>.json`, so
/// a bucket with versioning or object lock keeps every head (T13.22).
struct S3Sink(crate::cli_syncx::s3::S3);

impl Sink for S3Sink {
    fn send(&mut self, line: &str) -> Result<(), String> {
        use crate::cli_syncx::transport::Remote;
        let seq = serde_json::from_str::<serde_json::Value>(line)
            .ok()
            .and_then(|v| v["seq"].as_u64())
            .ok_or("anchor without a seq")?;
        self.0.put(
            &format!("anchor-{seq:020}.json"),
            format!("{line}\n").as_bytes(),
        )
    }
}

fn open(spec: &str) -> Result<Box<dyn Sink>, String> {
    if let Some(bucket) = spec.strip_prefix("s3:") {
        return Ok(Box::new(S3Sink(crate::cli_syncx::s3::S3::from_env(
            bucket,
        )?)));
    }
    match Target::parse(spec)? {
        Target::Jsonl(p) => Ok(Box::new(Jsonl(p))),
        Target::Syslog(to) => Ok(Box::new(Syslog {
            sock: UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("syslog socket: {e}"))?,
            to,
            host: super::siem::hostname(),
        })),
        Target::Otlp(_) => Err("anchors go to jsonl: or syslog:udp:// targets".into()),
    }
}

/// The chain head as `(entries, hash)`.
fn head() -> Result<(u64, String), String> {
    match crate::client::send_request(&Request::AuditVerify)? {
        Response::AuditOk { entries, last_hash } => Ok((entries as u64, last_hash)),
        Response::Err { error } => Err(error),
        _ => Err("unexpected daemon response".into()),
    }
}

/// Publish the head if it moved past the last anchor; true when sent.
fn publish_once(
    sink: &mut dyn Sink,
    state_file: &Path,
    head: (u64, String),
) -> Result<bool, String> {
    let (seq, hash) = head;
    let mut st: State = tail::load(state_file);
    if seq == 0 || seq <= st.seq {
        return Ok(false);
    }
    sink.send(&line(seq, &hash, tail::now_unix()))?;
    st.seq = seq;
    tail::save(state_file, &st)?;
    Ok(true)
}

fn cmd_anchor(args: &[String]) -> Response {
    let Some(spec) = flag(args, "--to") else {
        return Response::fail(USAGE);
    };
    let interval = match flag(args, "--interval").map(str::parse::<u64>) {
        None => 3600,
        Some(Ok(n)) if n > 0 => n,
        Some(_) => return Response::fail("--interval needs a number of seconds"),
    };
    let state = flag(args, "--state")
        .map(PathBuf::from)
        .unwrap_or_else(|| tail::state_file("anchor", spec));
    let mut sink = match open(spec) {
        Ok(s) => s,
        Err(e) => return Response::fail(e),
    };
    let once = args.iter().any(|a| a == "--once");
    if !once && !cli_mode::json_mode() {
        cli_ui::info(&format!(
            "anchoring the audit chain head every {interval}s (Ctrl-C stops)"
        ));
    }
    loop {
        match head().and_then(|h| publish_once(sink.as_mut(), &state, h)) {
            Ok(sent) if once => {
                return super::done(
                    if sent {
                        "anchor published"
                    } else {
                        "no new entries since the last anchor"
                    }
                    .into(),
                )
            }
            Ok(_) => {}
            Err(e) if once => return Response::fail(format!("audit anchor: {e}")),
            Err(e) => cli_ui::warn(&format!("audit anchor: {e}; retrying")),
        }
        std::thread::sleep(Duration::from_secs(interval));
    }
}

fn cmd_verify(args: &[String]) -> Response {
    let Some(file) = flag(args, "--anchor") else {
        return Response::fail(USAGE);
    };
    let text = match std::fs::read_to_string(file) {
        Ok(t) => t,
        Err(e) => return Response::fail(format!("{file}: {e}")),
    };
    let anchors = match parse_anchors(&text) {
        Ok(a) if !a.is_empty() => a,
        Ok(_) => return Response::fail(format!("{file}: no anchors")),
        Err(e) => return Response::fail(e),
    };
    let r = super::send(PolicyRequest::AuditAnchorCheck { anchors });
    if let Response::Policy(kepr_core::protocol_policy::PolicyResponse::PolicyDone { message }) = &r
    {
        if !cli_mode::json_mode() {
            cli_ui::ok(message);
        }
    }
    r
}

/// `kepr audit anchor|verify …`; `None` for any other subcommand.
pub fn dispatch(sub: &str, args: &[String]) -> Option<Response> {
    match sub {
        "anchor" => Some(cmd_anchor(args)),
        "verify" => Some(cmd_verify(args)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_round_trip_through_the_parser() {
        let text = format!("{}\n\n{}\n", line(5, "aa", 10), line(9, "bb", 20));
        let a = parse_anchors(&text).unwrap();
        assert_eq!(a.len(), 2);
        assert_eq!((a[1].seq, a[1].hash.as_str()), (9, "bb"));
    }

    #[test]
    fn syslog_wrapped_lines_parse() {
        let text = format!("<109>1 - host kepr-anchor - - - {}", line(3, "cc", 1));
        assert_eq!(parse_anchors(&text).unwrap()[0].seq, 3);
    }

    #[test]
    fn bad_lines_are_errors() {
        assert!(parse_anchors("not json").is_err());
        assert!(parse_anchors(r#"{"seq":0,"hash":"a"}"#).is_err());
        assert!(parse_anchors(r#"{"seq":1}"#).is_err());
    }

    #[test]
    fn only_the_newest_anchors_are_sent() {
        let text: String = (1..=600).map(|i| line(i, "h", i) + "\n").collect();
        let a = parse_anchors(&text).unwrap();
        assert_eq!((a.len(), a[0].seq), (MAX_SENT, 101));
    }

    struct Mem(Vec<String>);
    impl Sink for Mem {
        fn send(&mut self, l: &str) -> Result<(), String> {
            self.0.push(l.into());
            Ok(())
        }
    }

    #[test]
    fn the_head_is_published_once_per_advance() {
        let d = std::env::temp_dir().join(format!("kepr-anchor-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let st = d.join("s.json");
        let mut m = Mem(Vec::new());
        assert!(!publish_once(&mut m, &st, (0, "z".into())).unwrap());
        assert!(publish_once(&mut m, &st, (4, "h4".into())).unwrap());
        assert!(!publish_once(&mut m, &st, (4, "h4".into())).unwrap());
        assert!(publish_once(&mut m, &st, (7, "h7".into())).unwrap());
        assert_eq!(m.0.len(), 2);
        assert!(m.0[1].contains("\"seq\":7"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn an_s3_anchor_is_one_signed_object_named_by_its_seq() {
        use crate::cli_syncx::testserver::serve;
        use kepr_core::sigv4_req::AwsKey;
        let key = AwsKey {
            access_key_id: "AKIDEXAMPLEEXAMPLE".into(),
            secret_access_key: kepr_core::generate::ZeroString::from("secret-key-for-the-test"),
            session_token: None,
        };
        let (base, seen) = serve(vec![(200, String::new())]);
        let s3 =
            crate::cli_syncx::s3::S3::new("bkt/anchors", key, "eu-west-1", Some(&base)).unwrap();
        let mut sink = S3Sink(s3);
        sink.send(&line(7, "abcd", 99)).unwrap();
        let seen = seen.join().unwrap();
        assert!(
            seen[0].starts_with("PUT /bkt/anchors/anchor-00000000000000000007.json HTTP/1.1"),
            "{}",
            seen[0]
        );
        assert!(seen[0].contains("\"seq\":7") && seen[0].contains("\"hash\":\"abcd\""));
        assert!(seen[0]
            .to_ascii_lowercase()
            .contains("authorization: aws4-hmac-sha256"));
        assert!(sink.send("{\"no\":1}").is_err(), "an anchor needs a seq");
    }

    #[test]
    fn an_s3_target_needs_credentials_and_a_bucket() {
        // No AWS credentials in the test environment: a clear error, no panic.
        for var in ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"] {
            std::env::remove_var(var);
        }
        let e = open("s3:my-bucket/anchors").err().unwrap();
        assert!(e.contains("AWS_ACCESS_KEY_ID"), "{e}");
    }

    #[test]
    fn targets_other_than_jsonl_and_syslog_are_refused() {
        assert!(open("otlp:https://x.example").is_err());
        assert!(open("kafka:x").is_err());
    }
}
