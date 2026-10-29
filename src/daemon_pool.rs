// daemon_pool.rs — bounded worker pool for incoming connections.
//
// Replaces `thread::spawn` per connection. Cap concurrency so a flood of
// connects can't spawn unbounded pthread stacks (OOM) or exhaust fds.
//
// Backpressure model: the accept loop calls `dispatch(stream)` which blocks
// on `SyncSender::send` when the queue is full. That parks the accept
// thread, and the kernel's listen backlog absorbs the overflow; once a
// worker returns, the queue drains and accept resumes.

use std::os::unix::net::UnixStream;
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread;

pub struct Pool {
    tx: SyncSender<UnixStream>,
}

impl Pool {
    pub fn new(workers: usize, queue: usize, handler: fn(UnixStream)) -> Self {
        let (tx, rx) = sync_channel::<UnixStream>(queue);
        let rx = Arc::new(Mutex::new(rx));

        for _ in 0..workers {
            let rx = Arc::clone(&rx);
            thread::spawn(move || loop {
                // Lock held only across recv — never while handling a request.
                let stream = {
                    let guard = rx.lock().expect("worker rx poisoned");
                    match guard.recv() {
                        Ok(s) => s,
                        Err(_) => return, // sender dropped — shutdown
                    }
                };
                // A panic in one request (a poisoned lock, an unexpected
                // input) must cost that connection, not the worker: with 16
                // workers, 16 panics would otherwise leave a daemon that
                // accepts connections and answers none.
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handler(stream)));
                if r.is_err() {
                    eprintln!("[kepr-daemon] a request handler panicked; the worker continues");
                }
            });
        }

        Self { tx }
    }

    pub fn dispatch(&self, stream: UnixStream) {
        // Blocks on full queue → natural backpressure to accept().
        let _ = self.tx.send(stream);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    static SEEN: AtomicUsize = AtomicUsize::new(0);

    fn flaky(_: UnixStream) {
        if SEEN.fetch_add(1, Ordering::SeqCst) & 1 == 0 {
            panic!("boom");
        }
    }

    #[test]
    fn a_panicking_handler_does_not_kill_its_worker() {
        // One worker: if it died on the first panic, nothing below runs.
        let pool = Pool::new(1, 8, flaky);
        for _ in 0..6 {
            let (a, _b) = UnixStream::pair().unwrap();
            pool.dispatch(a);
        }
        let until = std::time::Instant::now() + Duration::from_secs(5);
        while SEEN.load(Ordering::SeqCst) < 6 && std::time::Instant::now() < until {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(SEEN.load(Ordering::SeqCst), 6);
    }
}
