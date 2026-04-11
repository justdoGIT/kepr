#![allow(unused_unsafe)]
#![allow(dead_code)]

// daemon.rs — credman-daemon
//
// Root systemd service. Listens on Unix socket.
// Handles all encryption/decryption operations.
// Never exposes internal tooling to clients.
//
// Socket: /run/credman/credman.sock  (root:credman 660)
// Credstore: /etc/credstore.encrypted/ (standard systemd location)
//
// Each connection:
//   1. Read peer uid via SO_PEERCRED
//   2. Validate request JSON
//   3. Perform crypto operation
//   4. Write audit log entry
//   5. Send JSON response
//   6. Close connection

mod protocol;
mod crypto;
mod generate;
mod store;
mod audit;

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::thread;

use audit::{AuditEvent, AuditResult, username_for_uid};
use generate::{generate_secret, GenKind};
use protocol::{
    CredInfo, Request, Response,
    SOCKET_PATH, SOCKET_DIR, MAX_MSG_BYTES,
};
use store::{list_for_uid, validate_name, file_mtime_str, file_size};

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    if unsafe { libc_geteuid() } != 0 {
        eprintln!("[credman-daemon] must run as root");
        std::process::exit(1);
    }

    setup_socket_dir();

    // Remove stale socket if present
    let _ = fs::remove_file(SOCKET_PATH);

    let listener = UnixListener::bind(SOCKET_PATH)
        .expect("cannot bind socket");

    // Socket permissions: root:credman 660
    // Members of 'credman' group can connect — no world access
    set_socket_permissions();

    eprintln!("[credman-daemon] listening on {SOCKET_PATH}");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(move || handle_client(stream));
            }
            Err(e) => {
                eprintln!("[credman-daemon] accept error: {e}");
            }
        }
    }
}

// ── Socket setup ──────────────────────────────────────────────────────────────

fn setup_socket_dir() {
    fs::create_dir_all(SOCKET_DIR)
        .expect("cannot create socket dir");
    fs::set_permissions(SOCKET_DIR, fs::Permissions::from_mode(0o755))
        .expect("cannot chmod socket dir");
}

fn set_socket_permissions() {
    // Get gid of 'credman' group
    let gid = group_gid("credman").unwrap_or(0);

    unsafe {
        libc_chown(
            std::ffi::CString::new(SOCKET_PATH).unwrap().as_ptr(),
            0,      // root
            gid,
        );
    }

    fs::set_permissions(SOCKET_PATH, fs::Permissions::from_mode(0o660))
        .expect("cannot chmod socket");
}

// ── Client handler ────────────────────────────────────────────────────────────

fn handle_client(mut stream: UnixStream) {
    // Set timeout
    let timeout = std::time::Duration::from_secs(protocol::TIMEOUT_SECS);
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    // Get peer uid via SO_PEERCRED — this is the requesting user's real uid
    let peer_uid = match get_peer_uid(&stream) {
        Some(uid) => uid,
        None => {
            send_error(&mut stream, "cannot verify caller identity");
            return;
        }
    };

    // Read request
    let mut buf = vec![0u8; MAX_MSG_BYTES];
    let n = match stream.read(&mut buf) {
        Ok(n) if n > 0 => n,
        _ => return,
    };

    let request: Request = match serde_json::from_slice(&buf[..n]) {
        Ok(r) => r,
        Err(e) => {
            send_error(&mut stream, &format!("invalid request: {e}"));
            return;
        }
    };

    let username = username_for_uid(peer_uid);
    let response = dispatch(peer_uid, &username, request, &mut stream);
    send_response(&mut stream, &response);
}

// ── Request dispatcher ────────────────────────────────────────────────────────

fn dispatch(
    uid: u32,
    username: &str,
    request: Request,
    _stream: &mut UnixStream,
) -> Response {

    match request {
        Request::Ping => {
            audit::log(&AuditEvent {
                op: "ping", name: None, uid, username,
                result: AuditResult::Ok,
            });
            Response { ok: true, pong: Some(true), ..Response::empty() }
        }

        Request::Set { name, value, generate } => {
            handle_set(uid, username, &name, value.as_deref(), generate.as_deref())
        }

        Request::Get { name } => {
            handle_get(uid, username, &name)
        }

        Request::List => {
            handle_list(uid, username)
        }

        Request::Delete { name } => {
            handle_delete(uid, username, &name)
        }

        Request::Check => {
            handle_check(uid, username)
        }
    }
}

// ── Handlers ──────────────────────────────────────────────────────────────────

fn handle_set(
    uid:      u32,
    username: &str,
    name:     &str,
    value:    Option<&str>,
    generate: Option<&str>,
) -> Response {

    // Validate name
    if let Err(e) = validate_name(name) {
        audit::log(&AuditEvent {
            op: "set", name: Some(name), uid, username,
            result: AuditResult::Fail(e.clone()),
        });
        return Response::fail(&e);
    }

    let upper = name.to_uppercase();

    // Determine secret value
    let secret = if let Some(v) = value {
        generate::ZeroString::from_string(v.to_string())
    } else {
        let kind = generate.and_then(GenKind::from_str).unwrap_or(GenKind::Hex);
        generate_secret(kind)
    };

    // Encrypt
    match crypto::encrypt(uid, &upper, secret.as_bytes()) {
        Ok(()) => {
            let cred_name = store::to_cred_name(uid, &upper);
            audit::log(&AuditEvent {
                op: "set", name: Some(&upper), uid, username,
                result: AuditResult::Ok,
            });
            Response {
                ok: true,
                name: Some(upper),
                cred_name: Some(cred_name),
                ..Response::empty()
            }
        }
        Err(e) => {
            audit::log(&AuditEvent {
                op: "set", name: Some(&upper), uid, username,
                result: AuditResult::Fail(e.clone()),
            });
            Response::fail(&e)
        }
    }
}

fn handle_get(uid: u32, username: &str, name: &str) -> Response {
    if let Err(e) = validate_name(name) {
        return Response::fail(&e);
    }

    let upper = name.to_uppercase();

    match crypto::decrypt(uid, &upper) {
        Ok(secret) => {
            audit::log(&AuditEvent {
                op: "get", name: Some(&upper), uid, username,
                result: AuditResult::Ok,
            });
            Response {
                ok:    true,
                name:  Some(upper),
                value: Some(secret.to_owned_string()),
                ..Response::empty()
            }
        }
        Err(e) => {
            audit::log(&AuditEvent {
                op: "get", name: Some(&upper), uid, username,
                result: AuditResult::Fail(e.clone()),
            });
            Response::fail(&e)
        }
    }
}

fn handle_list(uid: u32, username: &str) -> Response {
    let entries = list_for_uid(uid);
    let creds: Vec<CredInfo> = entries.iter().map(|(name, path)| {
        CredInfo {
            name:      name.clone(),
            cred_name: store::to_cred_name(uid, name),
            size:      file_size(path),
            modified:  file_mtime_str(path),
        }
    }).collect();

    let count = creds.len();
    audit::log(&AuditEvent {
        op: "list", name: None, uid, username,
        result: AuditResult::Ok,
    });

    Response {
        ok: true,
        credentials: Some(creds),
        count: Some(count),
        ..Response::empty()
    }
}

fn handle_delete(uid: u32, username: &str, name: &str) -> Response {
    if let Err(e) = validate_name(name) {
        return Response::fail(&e);
    }

    let upper = name.to_uppercase();

    match crypto::delete(uid, &upper) {
        Ok(()) => {
            audit::log(&AuditEvent {
                op: "delete", name: Some(&upper), uid, username,
                result: AuditResult::Ok,
            });
            Response { ok: true, name: Some(upper), ..Response::empty() }
        }
        Err(e) => {
            audit::log(&AuditEvent {
                op: "delete", name: Some(&upper), uid, username,
                result: AuditResult::Fail(e.clone()),
            });
            Response::fail(&e)
        }
    }
}

fn handle_check(uid: u32, username: &str) -> Response {
    let entries = list_for_uid(uid);
    let mut results = HashMap::new();
    let mut all_ok = true;

    for (name, _) in &entries {
        let ok = crypto::verify(uid, name);
        results.insert(name.clone(), if ok { "ok" } else { "failed" }.to_string());
        if !ok { all_ok = false; }
    }

    audit::log(&AuditEvent {
        op: "check", name: None, uid, username,
        result: if all_ok {
            AuditResult::Ok
        } else {
            AuditResult::Fail("some credentials failed".to_string())
        },
    });

    Response {
        ok: all_ok,
        results: Some(results),
        count: Some(entries.len()),
        ..Response::empty()
    }
}

// ── I/O helpers ───────────────────────────────────────────────────────────────

fn send_response(stream: &mut UnixStream, resp: &Response) {
    if let Ok(json) = serde_json::to_vec(resp) {
        let _ = stream.write_all(&json);
    }
}

fn send_error(stream: &mut UnixStream, msg: &str) {
    let resp = Response::fail(msg);
    send_response(stream, &resp);
}

// ── Unix helpers (minimal FFI) ────────────────────────────────────────────────

extern "C" { fn geteuid() -> u32; }
fn libc_geteuid() -> u32 { unsafe { geteuid() } }

#[repr(C)]
struct UCred { pid: i32, uid: u32, gid: u32 }

fn get_peer_uid(stream: &UnixStream) -> Option<u32> {
    use std::os::unix::io::AsRawFd;
    let mut cred = UCred { pid: 0, uid: 0, gid: 0 };
    let mut len  = std::mem::size_of::<UCred>() as u32;
    unsafe {
        // SOL_SOCKET=1, SO_PEERCRED=17
        let ret = libc_getsockopt(
            stream.as_raw_fd(), 1, 17,
            &mut cred as *mut _ as *mut _,
            &mut len,
        );
        if ret == 0 { Some(cred.uid) } else { None }
    }
}

extern "C" {
    fn getsockopt(fd: i32, level: i32, optname: i32,
                  optval: *mut std::ffi::c_void,
                  optlen: *mut u32) -> i32;
    fn chown(path: *const i8, owner: u32, group: u32) -> i32;
}

fn libc_getsockopt(fd: i32, level: i32, optname: i32,
                   optval: *mut std::ffi::c_void, optlen: *mut u32) -> i32 {
    unsafe { getsockopt(fd, level, optname, optval, optlen) }
}

fn libc_chown(path: *const i8, owner: u32, group: u32) -> i32 {
    unsafe { chown(path, owner, group) }
}

fn group_gid(name: &str) -> Option<u32> {
    let content = fs::read_to_string("/etc/group").ok()?;
    for line in content.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 3 && fields[0] == name {
            return fields[2].parse().ok();
        }
    }
    None
}
