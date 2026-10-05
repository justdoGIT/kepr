// cli_sharing/once.rs — one-time share links (T6.04).
//
//   kepr share send NAME --once [--ttl 1h] [--relay URL | -o FILE] [--qr]
//       → kepr://share/<id>[?relay=URL]#<key>
//   kepr share open LINK [--from FILE] [--as NAME]
//
// The daemon makes the blob and its key. With --relay the blob is PUT to
// `<relay>/b/<id>`; without, it goes to a file to pass on some other way
// (the recipient opens it with --from). The key goes only into the
// link's #fragment: it is never sent to the relay.

use kepr_core::generate::ZeroString;
use kepr_core::protocol::Response;
use kepr_core::protocol_sharing::{SharingRequest, SharingResponse};

use super::{parse_duration, qr, read_input, send, write_new};
use crate::cli_extra::{flag, positionals};
use crate::sync_http::{agent, send as http};
use crate::{cli_mode, cli_ui};

const SCHEME: &str = "kepr://share/";
const USAGE: &str = "usage: kepr share send NAME --once [--ttl 1h] [--relay URL | -o FILE] [--qr] \
                     | kepr share open LINK [--from FILE] [--as NAME]";

pub struct Link {
    pub id: String,
    pub relay: Option<String>,
    pub key: ZeroString,
}

fn pct(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn unpct(s: &str) -> Option<String> {
    let mut out = Vec::new();
    let mut b = s.bytes();
    while let Some(c) = b.next() {
        if c == b'%' {
            let h = [b.next()?, b.next()?];
            out.push(u8::from_str_radix(std::str::from_utf8(&h).ok()?, 16).ok()?);
        } else {
            out.push(c);
        }
    }
    String::from_utf8(out).ok()
}

/// A relay base URL: http(s), no fragment, no trailing slash.
pub fn relay_base(url: &str) -> Result<String, String> {
    let u = url.trim().trim_end_matches('/');
    let ok = (u.starts_with("https://") || u.starts_with("http://"))
        && !u.contains(['#', '?', ' '])
        && u.len() > "http://".len();
    ok.then(|| u.to_string())
        .ok_or_else(|| format!("{url}: not a relay URL (http(s)://host[:port])"))
}

pub fn format_link(id: &str, relay: Option<&str>, key: &str) -> String {
    match relay {
        Some(r) => format!("{SCHEME}{id}?relay={}#{key}", pct(r)),
        None => format!("{SCHEME}{id}#{key}"),
    }
}

pub fn parse_link(text: &str) -> Result<Link, String> {
    let bad = || "not a kepr share link (kepr://share/…#…)".to_string();
    let rest = text.trim().strip_prefix(SCHEME).ok_or_else(bad)?;
    let (head, key) = rest.split_once('#').ok_or_else(bad)?;
    let (id, query) = head.split_once('?').unwrap_or((head, ""));
    let relay = match query.strip_prefix("relay=") {
        Some(r) => Some(relay_base(&unpct(r).ok_or_else(bad)?)?),
        None if query.is_empty() => None,
        None => return Err(bad()),
    };
    let id_ok = id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit());
    if !id_ok || key.is_empty() {
        return Err(bad());
    }
    Ok(Link {
        id: id.to_string(),
        relay,
        key: key.into(),
    })
}

/// PUT the blob; the key is not an argument, so it can't be sent.
pub fn put_blob(relay: &str, id: &str, blob: &str, ttl: u64) -> Result<(), String> {
    let req = agent()
        .put(&format!("{relay}/b/{id}"))
        .set("X-Kepr-Ttl", &ttl.to_string())
        .set("Content-Type", "application/octet-stream");
    match http(req, Some(blob.as_bytes()))? {
        (201, _) => Ok(()),
        // The relay's reason, printable ASCII only (it is remote text).
        (s, body) => Err(format!(
            "the relay refused the blob: HTTP {s} {}",
            body.chars()
                .filter(|c| c.is_ascii_graphic() || *c == ' ')
                .take(80)
                .collect::<String>()
        )),
    }
}

/// GET = fetch-and-delete on the relay.
pub fn fetch_blob(relay: &str, id: &str) -> Result<String, String> {
    match http(agent().get(&format!("{relay}/b/{id}")), None)? {
        (200, body) => Ok(body),
        (404 | 410, _) => Err("this link was already opened, or it has expired".into()),
        (s, _) => Err(format!("the relay answered HTTP {s}")),
    }
}

fn ttl_arg(args: &[String]) -> Result<Option<u64>, Response> {
    flag(args, "--ttl")
        .map(parse_duration)
        .transpose()
        .map_err(Response::fail)
}

pub fn send_once(args: &[String]) -> Response {
    let r = (|| -> Result<Response, Response> {
        let pos = positionals(args, &["--ttl", "--relay", "-o"]);
        let name = pos.first().ok_or_else(|| Response::fail(USAGE))?;
        let relay = flag(args, "--relay").map(relay_base).transpose();
        let relay = relay.map_err(Response::fail)?;
        if relay.is_some() && flag(args, "-o").is_some() {
            return Err(Response::fail("--relay and -o don't go together"));
        }
        let r = send(SharingRequest::ShareLinkCreate {
            name: name.to_uppercase(),
            ttl_secs: ttl_arg(args)?,
        });
        let Response::Sharing(SharingResponse::ShareLink {
            id,
            key,
            blob,
            expires_at,
            ttl_secs,
        }) = &r
        else {
            return Ok(r);
        };
        let where_ = match &relay {
            Some(base) => {
                put_blob(base, id, blob, *ttl_secs).map_err(Response::fail)?;
                format!("the blob is on {base} until it is opened")
            }
            None => {
                let path = flag(args, "-o")
                    .map(str::to_string)
                    .unwrap_or_else(|| format!("kepr-share-{}.txt", &id[..8]));
                write_new(&path, blob)?;
                format!("send {path} and the link by different channels; open with --from FILE")
            }
        };
        let link = format_link(id, relay.as_deref(), key.as_str());
        if cli_mode::json_mode() {
            return Ok(SharingResponse::ShareLinkReady {
                link: link.into(),
                expires_at: expires_at.clone(),
            }
            .into());
        }
        println!("{link}");
        if args.iter().any(|a| a == "--qr") {
            qr::print(&link).map_err(Response::fail)?;
        }
        cli_ui::einfo(&format!(
            "single use, expires {expires_at} UTC; {where_}. Anyone with the link can open it once."
        ));
        Ok(Response::Pong)
    })();
    r.unwrap_or_else(|e| e)
}

pub fn open(args: &[String]) -> Response {
    let r = (|| -> Result<Response, Response> {
        let pos = positionals(args, &["--from", "--as", "--relay"]);
        let text = match pos.first() {
            Some(l) => l.clone(),
            None => qr::join(&read_input(None)?).map_err(Response::fail)?,
        };
        let link = parse_link(&text).map_err(Response::fail)?;
        let blob = match (flag(args, "--from"), flag(args, "--relay"), &link.relay) {
            (Some(path), _, _) => read_input(Some(path))?.trim().to_string(),
            (None, Some(r), _) => fetch_blob(&relay_base(r).map_err(Response::fail)?, &link.id)
                .map_err(Response::fail)?,
            (None, None, Some(r)) => fetch_blob(r, &link.id).map_err(Response::fail)?,
            (None, None, None) => return Err(Response::fail(
                "this link has no relay: open it with --from FILE (the blob file you were sent)",
            )),
        };
        let r = send(SharingRequest::ShareLinkOpen {
            blob,
            key: link.key,
            name: flag(args, "--as").map(str::to_uppercase),
        });
        if let (Response::SetOk { name, .. }, false) = (&r, cli_mode::json_mode()) {
            cli_ui::ok(&format!("opened and stored as {name}"));
        }
        Ok(r)
    })();
    r.unwrap_or_else(|e| e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};

    const ID: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn links_round_trip() {
        let l = format_link(ID, Some("https://relay.example:8443/x"), "S3cr3tKey_-");
        assert!(l.starts_with("kepr://share/0123") && l.ends_with("#S3cr3tKey_-"));
        let p = parse_link(&l).unwrap();
        assert_eq!(p.id, ID);
        assert_eq!(p.relay.as_deref(), Some("https://relay.example:8443/x"));
        assert_eq!(p.key.as_str(), "S3cr3tKey_-");
        let local = parse_link(&format_link(ID, None, "k")).unwrap();
        assert!(local.relay.is_none());
        for bad in [
            "https://x",
            "kepr://share/abc#k",
            "kepr://share/0123456789abcdef0123456789abcdef",
            "kepr://share/0123456789abcdef0123456789abcdef?x=1#k",
            "kepr://share/0123456789abcdef0123456789abcdef?relay=ftp%3A%2F%2Fx#k",
        ] {
            assert!(parse_link(bad).is_err(), "{bad}");
        }
    }

    /// A TCP pass-through that records every byte sent to the relay.
    fn tap(relay: SocketAddr) -> (SocketAddr, Arc<Mutex<Vec<u8>>>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        std::thread::spawn(move || {
            for c in l.incoming().flatten() {
                let mut up = TcpStream::connect(relay).unwrap();
                let (mut down, mut back) = (c.try_clone().unwrap(), up.try_clone().unwrap());
                std::thread::spawn(move || std::io::copy(&mut back, &mut down));
                let log = Arc::clone(&log);
                std::thread::spawn(move || {
                    let (mut c, mut buf) = (c, [0u8; 4096]);
                    while let Ok(n) = c.read(&mut buf) {
                        if n == 0 || up.write_all(&buf[..n]).is_err() {
                            break;
                        }
                        log.lock().unwrap().extend_from_slice(&buf[..n]);
                    }
                    let _ = up.shutdown(std::net::Shutdown::Write);
                });
            }
        });
        (addr, seen)
    }

    #[test]
    fn a_link_round_trips_through_a_relay_that_never_sees_the_key() {
        use kepr_relay::{store::Limits, Relay};
        let relay = kepr_relay::spawn("127.0.0.1:0", Relay::new(Limits::default(), 100)).unwrap();
        let (addr, seen) = tap(relay);
        let base = relay_base(&format!("http://{addr}")).unwrap();
        let key = "mYv3ryS3cr3tLinkKey0123456789abcdefghijklm";
        let blob = "kepr-link1-AAAABBBBCCCC";
        put_blob(&base, ID, blob, 60).unwrap();
        let link = parse_link(&format_link(ID, Some(&base), key)).unwrap();
        assert_eq!(
            fetch_blob(link.relay.as_deref().unwrap(), &link.id).unwrap(),
            blob
        );
        let again = fetch_blob(&base, ID).unwrap_err();
        assert!(again.contains("already opened"), "{again}");
        // Everything that crossed the wire to the relay, both requests:
        let wire = String::from_utf8_lossy(&seen.lock().unwrap()).to_string();
        assert!(wire.contains(&format!("PUT /b/{ID}")) && wire.contains(blob));
        assert!(!wire.contains(key) && !wire.contains("mYv3ry"), "{wire}");
        // A too-long ttl is refused by the relay, not silently cut.
        let e = put_blob(&base, "fedcba9876543210fedcba9876543210", blob, 10 * 86_400);
        assert!(e.unwrap_err().contains("HTTP 400"));
    }

    #[test]
    fn usage_errors_need_no_daemon() {
        let v = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert!(matches!(send_once(&v(&["--once"])), Response::Err { .. }));
        let r = send_once(&v(&["A", "--once", "--relay", "ftp://x"]));
        assert!(matches!(r, Response::Err { error } if error.contains("relay URL")));
        let r = open(&v(&["kepr://share/nope#k"]));
        assert!(matches!(r, Response::Err { error } if error.contains("not a kepr share link")));
        let r = open(&v(&[&format_link(ID, None, "k")]));
        assert!(matches!(r, Response::Err { error } if error.contains("--from")));
    }
}
