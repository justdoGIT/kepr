use std::env;
use std::net::{TcpListener, TcpStream};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

mod client;
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
                if let Err(e) = s.set_read_timeout(Some(Duration::from_secs(READ_TIMEOUT_SECS))) {
                    eprintln!("kepr-eso-provider: set_read_timeout failed: {e}");
                }
                if tx.send(s).is_err() {
                    eprintln!("kepr-eso-provider: worker queue closed");
                    break;
                }
            }
            Err(e) => eprintln!("kepr-eso-provider: accept error: {e}"),
        }
    }
}
