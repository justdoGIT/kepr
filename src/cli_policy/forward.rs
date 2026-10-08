// cli_policy/forward.rs — `kepr audit forward --to TARGET` (T7.14):
// stream audit-chain entries to a SIEM. Targets:
//
//   jsonl:PATH                 one JSON object per line, appended (0600)
//   syslog:udp://HOST[:PORT]   RFC 5424 datagrams (port 514 by default)
//   otlp:URL                   OTLP/HTTP JSON logs (`…/v1/logs`); URL may
//                              be kepr:NAME when it carries a token
//
// Runs as the user (the daemon has no network). Delivery is at least
// once: the resume point (the last forwarded entry's hash) is saved after
// each page is accepted, so a restart continues where it stopped.

use std::io::Write;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use kepr_core::generate::ZeroString;
use kepr_core::protocol::Response;
use kepr_core::protocol_policy::AuditRecord;

use super::{siem, tail};
use crate::{cli_mode, cli_ui};

const USAGE: &str =
    "usage: kepr audit forward --to jsonl:PATH|syslog:udp://HOST[:PORT]|otlp:URL [--once] [--interval SECS] [--state FILE]";

#[derive(Debug, PartialEq, Eq)]
pub enum Target {
    Jsonl(PathBuf),
    Syslog(String),
    Otlp(String),
}

impl Target {
    pub fn parse(spec: &str) -> Result<Self, String> {
        if let Some(p) = spec.strip_prefix("jsonl:").filter(|p| !p.is_empty()) {
            return Ok(Self::Jsonl(PathBuf::from(p)));
        }
        if let Some(hp) = spec.strip_prefix("syslog:udp://") {
            let hp = hp.trim_end_matches('/');
            if hp.is_empty() {
                return Err("syslog:udp:// needs a host".into());
            }
            let has_port = hp.rsplit_once(':').is_some_and(|(h, p)| {
                !h.is_empty() && (!h.contains(':') || h.ends_with(']')) && p.parse::<u16>().is_ok()
            });
            return Ok(Self::Syslog(if has_port {
                hp.to_string()
            } else {
                format!("{hp}:514")
            }));
        }
        if let Some(u) = spec.strip_prefix("otlp:") {
            if u.starts_with("https://") || u.starts_with("http://") || u.starts_with("kepr:") {
                return Ok(Self::Otlp(u.to_string()));
            }
            return Err("otlp: needs an http(s):// URL or kepr:NAME".into());
        }
        Err(format!(
            "unknown target `{spec}` (jsonl:PATH, syslog:udp://HOST[:PORT] or otlp:URL)"
        ))
    }
}

pub trait Sink {
    fn send(&mut self, records: &[AuditRecord]) -> Result<(), String>;
}

struct JsonlSink(PathBuf);

impl Sink for JsonlSink {
    fn send(&mut self, records: &[AuditRecord]) -> Result<(), String> {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(&self.0)
            .map_err(|e| format!("{}: {e}", self.0.display()))?;
        let mut out = String::new();
        for r in records {
            out.push_str(&siem::jsonl(r));
            out.push('\n');
        }
        f.write_all(out.as_bytes())
            .and_then(|()| f.sync_data())
            .map_err(|e| format!("{}: {e}", self.0.display()))
    }
}

struct SyslogSink {
    sock: UdpSocket,
    to: SocketAddr,
    host: String,
}

impl Sink for SyslogSink {
    fn send(&mut self, records: &[AuditRecord]) -> Result<(), String> {
        for r in records {
            let line = siem::rfc5424(r, &self.host);
            self.sock
                .send_to(line.as_bytes(), self.to)
                .map_err(|e| format!("syslog send: {e}"))?;
        }
        Ok(())
    }
}

struct OtlpSink {
    url: ZeroString,
    host: String,
}

impl Sink for OtlpSink {
    fn send(&mut self, records: &[AuditRecord]) -> Result<(), String> {
        let body = siem::otlp_body(records, &self.host);
        let req = crate::sync_http::agent()
            .post(self.url.as_str())
            .set("Content-Type", "application/json")
            .set("User-Agent", "kepr");
        match crate::sync_http::send(req, Some(body.as_bytes())) {
            Ok((code, _)) if (200..300).contains(&code) => Ok(()),
            Ok((code, _)) => Err(format!("OTLP collector answered HTTP {code}")),
            Err(_) => Err("OTLP collector unreachable".into()),
        }
    }
}

pub fn open(target: &Target) -> Result<Box<dyn Sink>, String> {
    let host = siem::hostname();
    Ok(match target {
        Target::Jsonl(p) => Box::new(JsonlSink(p.clone())),
        Target::Syslog(hp) => {
            let to = hp
                .to_socket_addrs()
                .map_err(|e| format!("syslog host {hp}: {e}"))?
                .next()
                .ok_or_else(|| format!("syslog host {hp}: no address"))?;
            let any: SocketAddr = if to.is_ipv4() {
                "0.0.0.0:0".parse().unwrap_or(to)
            } else {
                "[::]:0".parse().unwrap_or(to)
            };
            let sock = UdpSocket::bind(any).map_err(|e| format!("syslog socket: {e}"))?;
            Box::new(SyslogSink { sock, to, host })
        }
        Target::Otlp(u) => Box::new(OtlpSink {
            url: super::notify::resolve_url(u)?,
            host,
        }),
    })
}

/// Forward everything after the saved resume point; returns the count.
pub fn pump(src: &dyn tail::Source, sink: &mut dyn Sink, state: &Path) -> Result<usize, String> {
    let mut after: Option<String> = tail::load(state);
    tail::drain(
        src,
        &mut after,
        &mut |recs, reset| {
            if reset {
                cli_ui::warn(
                    "the audit log no longer has the resume point; forwarding it from the start",
                );
            }
            sink.send(recs)
        },
        &mut |a| tail::save(state, a),
    )
}

pub fn cmd_audit(args: &[String]) -> Response {
    let a = super::plain_args(args);
    if a.first() != Some(&"forward") {
        return Response::fail(USAGE);
    }
    let Some(spec) = crate::cli_extra::flag(args, "--to") else {
        return Response::fail(USAGE);
    };
    let target = match Target::parse(spec) {
        Ok(t) => t,
        Err(e) => return Response::fail(e),
    };
    let interval = match crate::cli_extra::flag(args, "--interval").map(str::parse::<u64>) {
        None => 5,
        Some(Ok(n)) if n > 0 => n,
        Some(_) => return Response::fail("--interval needs a number of seconds"),
    };
    let state = crate::cli_extra::flag(args, "--state")
        .map(PathBuf::from)
        .unwrap_or_else(|| tail::state_file("forward", spec));
    let mut sink = match open(&target) {
        Ok(s) => s,
        Err(e) => return Response::fail(e),
    };
    if args.iter().any(|a| a == "--once") {
        return match pump(&tail::Daemon, sink.as_mut(), &state) {
            Ok(n) => super::done(format!("forwarded {n} audit event(s)")),
            Err(e) => Response::fail(format!("audit forward: {e}")),
        };
    }
    if !cli_mode::json_mode() {
        cli_ui::info(&format!(
            "forwarding audit events every {interval}s (Ctrl-C stops; the next run resumes)"
        ));
    }
    loop {
        match pump(&tail::Daemon, sink.as_mut(), &state) {
            Ok(0) => {}
            Ok(n) => cli_ui::dim(&format!("forwarded {n} audit event(s)")),
            Err(e) => cli_ui::warn(&format!("audit forward: {e}; retrying")),
        }
        std::thread::sleep(Duration::from_secs(interval));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli_policy::siem::record;
    use crate::cli_policy::tail::fixture;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("kepr-fwd-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn parses_targets() {
        assert_eq!(
            Target::parse("jsonl:/var/log/kepr.jsonl").unwrap(),
            Target::Jsonl("/var/log/kepr.jsonl".into())
        );
        assert_eq!(
            Target::parse("syslog:udp://siem.local").unwrap(),
            Target::Syslog("siem.local:514".into())
        );
        assert_eq!(
            Target::parse("syslog:udp://10.0.0.5:1514").unwrap(),
            Target::Syslog("10.0.0.5:1514".into())
        );
        assert_eq!(
            Target::parse("syslog:udp://[::1]:514").unwrap(),
            Target::Syslog("[::1]:514".into())
        );
        assert_eq!(
            Target::parse("otlp:kepr:OTLP_URL").unwrap(),
            Target::Otlp("kepr:OTLP_URL".into())
        );
        for bad in ["jsonl:", "syslog:udp://", "otlp:ftp://x", "kafka:x"] {
            assert!(Target::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn resumes_from_the_last_forwarded_hash_after_restart() {
        let d = tmp("resume");
        let (out, state) = (d.join("out.jsonl"), d.join("state.json"));
        let log = fixture::Log::new((0..3).map(|i| record(i, "get", Some("K"), "ok")).collect());
        let mut sink = open(&Target::Jsonl(out.clone())).unwrap();
        assert_eq!(pump(&log, sink.as_mut(), &state).unwrap(), 3);
        assert_eq!(pump(&log, sink.as_mut(), &state).unwrap(), 0);
        // "Restart": new events, a fresh sink, the cursor from disk only.
        log.records
            .borrow_mut()
            .extend((3..5).map(|i| record(i, "set", Some("K"), "ok")));
        let mut sink = open(&Target::Jsonl(out.clone())).unwrap();
        assert_eq!(pump(&log, sink.as_mut(), &state).unwrap(), 2);
        let lines: Vec<serde_json::Value> = std::fs::read_to_string(&out)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let seqs: Vec<u64> = lines.iter().map(|v| v["seq"].as_u64().unwrap()).collect();
        assert_eq!(seqs, [0, 1, 2, 3, 4]);
        assert_eq!(tail::load::<Option<String>>(&state).as_deref(), Some("h4"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn syslog_datagrams_reach_the_collector() {
        let collector = UdpSocket::bind("127.0.0.1:0").unwrap();
        collector
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let spec = format!("syslog:udp://{}", collector.local_addr().unwrap());
        let mut sink = open(&Target::parse(&spec).unwrap()).unwrap();
        sink.send(&[record(1, "get", Some("K"), "ok")]).unwrap();
        let mut buf = [0u8; 2048];
        let n = collector.recv(&mut buf).unwrap();
        let line = String::from_utf8_lossy(&buf[..n]);
        assert!(line.starts_with("<86>1 "), "{line}");
        assert!(line.ends_with("get K ok"));
    }

    #[test]
    fn otlp_posts_and_a_refusal_keeps_the_cursor() {
        let d = tmp("otlp");
        let state = d.join("state.json");
        let log = fixture::Log::new(vec![record(1, "get", Some("K"), "ok")]);
        let (url, h) = crate::cli_policy::notify::testserver::once(503);
        let mut sink = open(&Target::Otlp(url)).unwrap();
        assert_eq!(
            pump(&log, sink.as_mut(), &state).unwrap_err(),
            "OTLP collector answered HTTP 503"
        );
        assert_eq!(tail::load::<Option<String>>(&state), None);
        assert!(h.join().unwrap().contains("\"resourceLogs\""));
        let (url, h) = crate::cli_policy::notify::testserver::once(200);
        let mut sink = open(&Target::Otlp(url)).unwrap();
        assert_eq!(pump(&log, sink.as_mut(), &state).unwrap(), 1);
        assert!(h.join().unwrap().starts_with("POST /hook "));
        let _ = std::fs::remove_dir_all(&d);
    }
}
