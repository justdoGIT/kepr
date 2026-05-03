use std::env;
use std::net::TcpListener;
use std::time::Duration;

mod client;
mod server;

const READ_TIMEOUT_SECS: u64 = 30;

fn main() {
    let listen = env::var("KEPR_ESO_LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let listener = match TcpListener::bind(&listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("kepr-eso-provider: cannot bind {listen}: {e}");
            std::process::exit(1);
        }
    };
    eprintln!("kepr-eso-provider: listening on {listen}");
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let _ = s.set_read_timeout(Some(Duration::from_secs(READ_TIMEOUT_SECS)));
                server::handle_connection(s);
            }
            Err(e) => eprintln!("kepr-eso-provider: accept error: {e}"),
        }
    }
}
