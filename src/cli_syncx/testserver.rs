// cli_syncx/testserver.rs — test-only loopback HTTP fake for the sync
// targets: serves canned `(status, body)` replies in order, one request
// per connection, and hands back each raw request it saw.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::{Duration, Instant};

/// Base URL (`http://127.0.0.1:PORT`) and a thread returning the raw
/// requests. Panics if a request doesn't arrive within 10 s.
pub fn serve(replies: Vec<(u16, String)>) -> (String, std::thread::JoinHandle<Vec<String>>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.set_nonblocking(true).unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    let h = std::thread::spawn(move || {
        let mut seen = Vec::new();
        for (status, body) in replies {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut s = loop {
                match l.accept() {
                    Ok((s, _)) => break s,
                    Err(_) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(5))
                    }
                    Err(e) => panic!("no request arrived: {e}"),
                }
            };
            s.set_nonblocking(false).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            seen.push(read_request(&mut s));
            let _ = write!(
                s,
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
        seen
    });
    (base, h)
}

fn read_request(s: &mut std::net::TcpStream) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = s.read(&mut chunk).unwrap_or(0);
        buf.extend_from_slice(&chunk[..n]);
        let text = String::from_utf8_lossy(&buf).to_string();
        if let Some(end) = text.find("\r\n\r\n") {
            let len = text
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                })
                .unwrap_or(0);
            if buf.len() >= end + 4 + len {
                return text;
            }
        }
        if n == 0 {
            return text;
        }
    }
}
