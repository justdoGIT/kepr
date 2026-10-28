// cli_desktop/dbus/addr.rs — D-Bus bus addresses.
//
//   unix:path=/run/user/1000/bus        a filesystem socket
//   unix:abstract=/tmp/dbus-XXXX        an abstract socket
//   unix:runtime=yes                    $XDG_RUNTIME_DIR/bus
//
// Several may be given, separated by `;`, and `,guid=…` is ignored. Other
// transports (tcp, systemd, …) are skipped: the session bus of a desktop
// login is a Unix socket.

use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixStream};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    Path(PathBuf),
    Abstract(Vec<u8>),
}

/// `%xx` escapes of an address value.
fn unescape(v: &str) -> Result<Vec<u8>, String> {
    let b = v.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = v.get(i + 1..i + 3).ok_or("bad escape in bus address")?;
            out.push(u8::from_str_radix(h, 16).map_err(|_| "bad escape in bus address")?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Ok(out)
}

/// The usable endpoints of `addr`; `runtime` is `$XDG_RUNTIME_DIR`.
pub fn parse(addr: &str, runtime: Option<&str>) -> Result<Vec<Endpoint>, String> {
    let mut out = Vec::new();
    for one in addr.split(';').filter(|a| !a.is_empty()) {
        let Some(rest) = one.strip_prefix("unix:") else {
            continue;
        };
        let mut path = None;
        for kv in rest.split(',') {
            let Some((k, v)) = kv.split_once('=') else {
                continue;
            };
            match k {
                "path" => {
                    path = Some(Endpoint::Path(PathBuf::from(
                        String::from_utf8(unescape(v)?).map_err(|_| "bus address is not UTF-8")?,
                    )))
                }
                "abstract" => path = Some(Endpoint::Abstract(unescape(v)?)),
                "runtime" if v == "yes" => {
                    let dir = runtime.ok_or("unix:runtime=yes without XDG_RUNTIME_DIR")?;
                    path = Some(Endpoint::Path(PathBuf::from(dir).join("bus")));
                }
                _ => {}
            }
        }
        out.extend(path);
    }
    if out.is_empty() {
        return Err(format!("no usable unix endpoint in bus address {addr:?}"));
    }
    Ok(out)
}

/// `DBUS_SESSION_BUS_ADDRESS`, else the per-user default.
pub fn session_bus() -> Result<Vec<Endpoint>, String> {
    let runtime = std::env::var("XDG_RUNTIME_DIR").ok();
    match std::env::var("DBUS_SESSION_BUS_ADDRESS") {
        Ok(a) if !a.is_empty() => parse(&a, runtime.as_deref()),
        _ => {
            let dir = runtime
                .ok_or("no session bus: DBUS_SESSION_BUS_ADDRESS and XDG_RUNTIME_DIR are unset")?;
            Ok(vec![Endpoint::Path(PathBuf::from(dir).join("bus"))])
        }
    }
}

/// Connect to the first endpoint that answers.
pub fn connect(eps: &[Endpoint]) -> Result<UnixStream, String> {
    let mut last = String::from("no endpoints");
    for ep in eps {
        let r = match ep {
            Endpoint::Path(p) => {
                UnixStream::connect(p).map_err(|e| format!("{}: {e}", p.display()))
            }
            Endpoint::Abstract(n) => SocketAddr::from_abstract_name(n)
                .and_then(|a| UnixStream::connect_addr(&a))
                .map_err(|e| format!("abstract socket: {e}")),
        };
        match r {
            Ok(s) => return Ok(s),
            Err(e) => last = e,
        }
    }
    Err(format!("cannot connect to the session bus: {last}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses() {
        assert_eq!(
            parse("unix:path=/run/user/1000/bus", None).unwrap(),
            [Endpoint::Path("/run/user/1000/bus".into())]
        );
        assert_eq!(
            parse("unix:abstract=/tmp/dbus-AbC,guid=0123", None).unwrap(),
            [Endpoint::Abstract(b"/tmp/dbus-AbC".to_vec())]
        );
        assert_eq!(
            parse("unix:runtime=yes", Some("/run/user/7")).unwrap(),
            [Endpoint::Path("/run/user/7/bus".into())]
        );
        // Several, with an unusable one between.
        let many = parse("tcp:host=h,port=1;unix:path=/a;unix:path=/b%20c", None).unwrap();
        assert_eq!(
            many,
            [Endpoint::Path("/a".into()), Endpoint::Path("/b c".into())]
        );
        assert!(parse("unix:runtime=yes", None).is_err());
        assert!(parse("tcp:host=h", None).is_err());
        assert!(parse("unix:path=/a%2", None).is_err());
        assert!(parse("", None).is_err());
    }

    #[test]
    fn connects_to_a_path_and_an_abstract_socket() {
        let dir = std::env::temp_dir().join(format!("kepr-addr-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("bus");
        let _l = std::os::unix::net::UnixListener::bind(&p).unwrap();
        assert!(connect(&[Endpoint::Path(p.clone())]).is_ok());
        let name = format!("kepr-addr-test-{}", std::process::id()).into_bytes();
        let a = SocketAddr::from_abstract_name(&name).unwrap();
        let _l2 = std::os::unix::net::UnixListener::bind_addr(&a).unwrap();
        assert!(connect(&[
            Endpoint::Path(dir.join("missing")),
            Endpoint::Abstract(name)
        ])
        .is_ok());
        assert!(connect(&[Endpoint::Path(dir.join("missing"))])
            .unwrap_err()
            .contains("session bus"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
