#![allow(unused_unsafe)]
#![allow(dead_code)]

// daemon.rs — credman-daemon entry, accept loop, and request dispatcher.
//
// Root systemd service. Owns all encryption/decryption operations and audit
// logging. Per-connection: read peer uid via SO_PEERCRED, parse framed JSON,
// dispatch, emit framed JSON response.

mod protocol;
mod crypto;
mod generate;
mod store;
mod audit;
mod framing;
mod daemon_socket;
mod daemon_peer;
mod daemon_handlers;

use std::fs;
use std::os::unix::net::{UnixListener, UnixStream};
use std::thread;

use audit::{username_for_uid, AuditEvent, AuditResult};
use daemon_handlers::{handle_check, handle_delete, handle_get, handle_list, handle_set};
use daemon_peer::get_peer_uid;
use daemon_socket::{effective_uid, set_socket_permissions, setup_socket_dir};
use framing::{read_frame, write_frame};
use protocol::{Request, Response, MAX_MSG_BYTES, SOCKET_PATH, TIMEOUT_SECS};

fn main() {
    if effective_uid() != 0 {
        eprintln!("[credman-daemon] must run as root");
        std::process::exit(1);
    }

    setup_socket_dir();
    let _ = fs::remove_file(SOCKET_PATH);

    let listener = UnixListener::bind(SOCKET_PATH)
        .expect("cannot bind socket");
    set_socket_permissions();

    eprintln!("[credman-daemon] listening on {SOCKET_PATH}");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => { thread::spawn(move || handle_client(stream)); }
            Err(e)     => eprintln!("[credman-daemon] accept error: {e}"),
        }
    }
}

fn handle_client(mut stream: UnixStream) {
    let timeout = std::time::Duration::from_secs(TIMEOUT_SECS);
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let peer_uid = match get_peer_uid(&stream) {
        Some(uid) => uid,
        None => {
            send_error(&mut stream, "cannot verify caller identity");
            return;
        }
    };

    let buf = match read_frame(&mut stream, MAX_MSG_BYTES) {
        Ok(b)  => b,
        Err(_) => return,
    };

    let request: Request = match serde_json::from_slice(&buf) {
        Ok(r) => r,
        Err(e) => {
            send_error(&mut stream, &format!("invalid request: {e}"));
            return;
        }
    };

    let username = username_for_uid(peer_uid);
    let response = dispatch(peer_uid, &username, request);
    send_response(&mut stream, &response);
}

fn dispatch(uid: u32, username: &str, request: Request) -> Response {
    match request {
        Request::Ping => {
            audit::log(&AuditEvent {
                op: "ping", name: None, uid, username,
                result: AuditResult::Ok,
            });
            Response { ok: true, pong: Some(true), ..Response::empty() }
        }
        Request::Set { name, value, generate } =>
            handle_set(uid, username, &name, value.as_deref(), generate.as_deref()),
        Request::Get { name }    => handle_get(uid, username, &name),
        Request::List            => handle_list(uid, username),
        Request::Delete { name } => handle_delete(uid, username, &name),
        Request::Check           => handle_check(uid, username),
    }
}

fn send_response(stream: &mut UnixStream, resp: &Response) {
    if let Ok(json) = serde_json::to_vec(resp) {
        let _ = write_frame(stream, &json);
    }
}

fn send_error(stream: &mut UnixStream, msg: &str) {
    send_response(stream, &Response::fail(msg));
}
