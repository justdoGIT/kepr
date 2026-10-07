// kepr-relay — serve one-time share-link blobs (T6.04).
//
//   kepr-relay [--listen ADDR] [--max-ttl SECS] [--rate PER_MINUTE]
//
// Defaults: 127.0.0.1:8737, 7 days, 60 requests per minute per address.
// Put it behind a TLS reverse proxy to reach it from other machines.

use std::sync::Arc;

use kepr_relay::store::Limits;
use kepr_relay::Relay;

const USAGE: &str = "usage: kepr-relay [--listen ADDR] [--max-ttl SECS] [--rate PER_MINUTE]";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut listen = "127.0.0.1:8737".to_string();
    let mut limits = Limits::default();
    let mut rate = 60u32;
    let mut i = 0;
    while i < args.len() {
        let value = args.get(i + 1).cloned().unwrap_or_default();
        let ok = match args[i].as_str() {
            "--listen" => {
                listen = value;
                true
            }
            "--max-ttl" => value.parse().map(|v| limits.max_ttl = v).is_ok(),
            "--rate" => value.parse().map(|v| rate = v).is_ok(),
            _ => false,
        };
        if !ok {
            eprintln!("{USAGE}");
            std::process::exit(2);
        }
        i += 2;
    }
    let listener = match std::net::TcpListener::bind(&listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("kepr-relay: cannot listen on {listen}: {e}");
            std::process::exit(1);
        }
    };
    eprintln!("kepr-relay: listening on {listen}");
    kepr_relay::serve(listener, Arc::new(Relay::new(limits, rate)));
}
