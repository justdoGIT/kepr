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
                        Ok(s)  => s,
                        Err(_) => return, // sender dropped — shutdown
                    }
                };
                handler(stream);
            });
        }

        Self { tx }
    }

    pub fn dispatch(&self, stream: UnixStream) {
        // Blocks on full queue → natural backpressure to accept().
        let _ = self.tx.send(stream);
    }
}
