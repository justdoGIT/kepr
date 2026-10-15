// fake.rs — a loopback HTTP server for the batch's tests (STS, IAM and
// GitHub fakes). Answers each connection with the next canned reply and
// hands the raw request (head + body) to the test. No real cloud calls.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;

pub struct Fake {
    pub url: String,
    pub requests: mpsc::Receiver<String>,
}

/// Serve `replies` (status, body) in order, one per connection.
pub fn serve(replies: Vec<(u16, String)>) -> Fake {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for (status, body) in replies {
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            let mut r = BufReader::new(stream.try_clone().unwrap());
            let (mut head, mut len) = (String::new(), 0usize);
            loop {
                let mut line = String::new();
                if r.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap_or(0);
                }
                head.push_str(&line);
            }
            let mut b = vec![0u8; len];
            let _ = r.read_exact(&mut b);
            let _ = tx.send(format!("{head}\r\n{}", String::from_utf8_lossy(&b)));
            let mut s = stream;
            let _ = write!(
                s,
                "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    Fake { url, requests: rx }
}
