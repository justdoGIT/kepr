use std::env;
use std::net::{TcpListener, TcpStream};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

mod client;
mod http;
mod server;

const READ_TIMEOUT_SECS: u64 = 30;
const WORKERS: usize = 8;

fn main() {
    let listen = env::var("KEPR_ESO_LISTEN").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let auth_token = Arc::new(
        env::var("KEPR_ESO_AUTH_TOKEN")
            .ok()
            .filter(|token| !token.trim().is_empty()),
    );
    let externally_reachable = !listen.starts_with("127.0.0.1:")
        && !listen.starts_with("localhost:")
        && !listen.starts_with("[::1]:");
    if externally_reachable && auth_token.is_none() {
        eprintln!(
            "kepr-eso-provider: KEPR_ESO_AUTH_TOKEN is required when \
             listening outside loopback"
        );
        std::process::exit(1);
    }
    // A loopback TCP port is reachable by every local user, so serving
    // without a token hands this user's secrets to anyone logged in.
    if auth_token.is_none() && env::var("KEPR_ESO_INSECURE_NO_AUTH").as_deref() != Ok("1") {
        eprintln!(
            "kepr-eso-provider: set KEPR_ESO_AUTH_TOKEN (any local user can reach \
             a loopback port); KEPR_ESO_INSECURE_NO_AUTH=1 overrides on single-user hosts"
        );
        std::process::exit(1);
    }
    let listener = match TcpListener::bind(&listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("kepr-eso-provider: cannot bind {listen}: {e}");
            std::process::exit(1);
        }
    };
    let (tx, rx) = mpsc::sync_channel::<TcpStream>(WORKERS * 2);
    let rx = Arc::new(Mutex::new(rx));
    for _ in 0..WORKERS {
        let rx = Arc::clone(&rx);
        let token = Arc::clone(&auth_token);
        thread::spawn(move || loop {
            let Ok(stream) = rx.lock().expect("worker queue poisoned").recv() else {
                break;
            };
            server::handle_connection(stream, token.as_deref());
        });
    }
    eprintln!("kepr-eso-provider: listening on {listen} with {WORKERS} workers");
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let t = Some(Duration::from_secs(READ_TIMEOUT_SECS));
                if s.set_read_timeout(t)
                    .and_then(|_| s.set_write_timeout(t))
                    .is_err()
                {
                    continue;
                }
                // Shed load instead of blocking accept: with every worker
                // busy and the queue full, new clients get a 503.
                match tx.try_send(s) {
                    Ok(()) => {}
                    Err(mpsc::TrySendError::Full(mut s)) => {
                        use std::io::Write;
                        let _ = s.write_all(b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
                    }
                    Err(mpsc::TrySendError::Disconnected(_)) => {
                        eprintln!("kepr-eso-provider: worker queue closed");
                        break;
                    }
                }
            }
            Err(e) => eprintln!("kepr-eso-provider: accept error: {e}"),
        }
    }
}
