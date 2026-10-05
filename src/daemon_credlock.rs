// daemon_credlock.rs — one lock per (uid, credential name), so the
// multi-step operations on a credential can't interleave:
//   set     meta write → value write → history (sealed meta first)
//   get     policy check on .meta → decrypt
//   delete  / expiry sweep / restore / share send
// Without it, a `Get` racing a sealed `set` could pass the check on the
// old (unsealed) meta and then decrypt the new sealed value, and two
// concurrent sets could leave a sealed value with no .meta at all.
//
// 64 striped mutexes (two names may share a stripe, which only costs
// waiting). Re-entrant per thread: handlers call each other (restore →
// set, records → set), and a thread already holding a stripe just
// proceeds.

use std::cell::RefCell;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::{Mutex, MutexGuard};

const STRIPES: usize = 64;
static LOCKS: [Mutex<()>; STRIPES] = [const { Mutex::new(()) }; STRIPES];

thread_local! {
    static HELD: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
}

fn stripe(uid: u32, name: &str) -> usize {
    let mut h = DefaultHasher::new();
    (uid, name.to_uppercase()).hash(&mut h);
    (h.finish() as usize) % STRIPES
}

/// Held for the life of a credential operation.
pub struct Guard {
    stripe: usize,
    _inner: Option<MutexGuard<'static, ()>>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        if self._inner.is_some() {
            HELD.with(|h| h.borrow_mut().retain(|s| *s != self.stripe));
        }
    }
}

/// Lock `(uid, name)` for this thread (a no-op if it already holds it).
pub fn lock(uid: u32, name: &str) -> Guard {
    let stripe = stripe(uid, name);
    if HELD.with(|h| h.borrow().contains(&stripe)) {
        return Guard {
            stripe,
            _inner: None,
        };
    }
    // A poisoned stripe only means another handler panicked mid-way;
    // the files themselves are the state, so carry on.
    let g = LOCKS[stripe].lock().unwrap_or_else(|p| p.into_inner());
    HELD.with(|h| h.borrow_mut().push(stripe));
    Guard {
        stripe,
        _inner: Some(g),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    #[test]
    fn reentrant_on_one_thread() {
        let _a = lock(1000, "FOO");
        let _b = lock(1000, "foo"); // same credential, same thread: no deadlock
    }

    #[test]
    fn excludes_other_threads_until_released() {
        let busy = Arc::new(AtomicBool::new(true));
        let g = lock(1001, "BAR");
        let b = busy.clone();
        let t = std::thread::spawn(move || {
            let _g = lock(1001, "BAR");
            assert!(!b.load(Ordering::SeqCst), "entered while held");
        });
        std::thread::sleep(std::time::Duration::from_millis(50));
        busy.store(false, Ordering::SeqCst);
        drop(g);
        t.join().unwrap();
    }
}
