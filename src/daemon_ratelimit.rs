// daemon_ratelimit.rs — per-uid token-bucket rate limiter
//
// Bounds the request rate any single peer-uid can drive against the
// daemon. A misbehaving or hostile client in the `kepr` group could
// otherwise hammer the daemon into a denial-of-service for other
// users; the daemon_pool already caps total concurrency but does not
// differentiate between callers.
//
// Defaults: capacity 30 (burst), refill 10 tokens/sec. A peer that
// stays below ~10 ops/sec sees no impact; a peer bursting above 30
// outstanding tokens is throttled until the bucket refills. Values
// are compile-time constants for now; a follow-up will move them
// to `/etc/kepr/daemon.toml`.
//
// Thread-safety: a single `Mutex<HashMap>` covers all per-uid buckets.
// The lock is held for microseconds (a HashMap lookup plus a few
// floating-point operations), and contention is bounded by the
// daemon_pool worker count.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// Per-uid token bucket. One bucket per peer; created on first request.
pub struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
    capacity: f64,
    refill_per_sec: f64,
}

impl TokenBucket {
    pub fn new(capacity: f64, refill_per_sec: f64) -> Self {
        Self {
            tokens: capacity,
            last_refill: Instant::now(),
            capacity,
            refill_per_sec,
        }
    }

    /// Try to consume one token. Returns true on success, false if the
    /// bucket is empty. Refills based on elapsed time before consuming,
    /// so a caller arriving after a long idle period sees the full
    /// capacity, capped at `capacity`.
    pub fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

pub struct RateLimiter {
    buckets: Mutex<HashMap<u32, TokenBucket>>,
    capacity: f64,
    refill_per_sec: f64,
}

impl RateLimiter {
    pub fn new(capacity: f64, refill_per_sec: f64) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            capacity,
            refill_per_sec,
        }
    }

    /// Returns `true` if the call is allowed (a token was consumed),
    /// `false` if the peer is over budget. Call before dispatch.
    ///
    /// Periodically evicts idle buckets to bound memory. Buckets with
    /// zero tokens (exhausted and not refilling) are candidates for
    /// removal; buckets with positive tokens are kept — their capacity
    /// serves as a burst window that a legitimate caller may return to.
    pub fn check(&self, uid: u32) -> bool {
        let mut buckets = self.buckets.lock().unwrap();
        // Periodic cleanup: sweep every ~1000 checks, remove buckets
        // that are exhausted and have been idle for >60s. This bounds
        // the HashMap to active UIDs plus a small stale tail.
        if buckets.len() > 0 && buckets.len() % 1024 == 0 {
            buckets.retain(|_uid, b| {
                b.last_refill.elapsed().as_secs() < 60 || b.tokens > 0.0
            });
        }
        let bucket = buckets
            .entry(uid)
            .or_insert_with(|| TokenBucket::new(self.capacity, self.refill_per_sec));
        bucket.try_consume()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn fresh_bucket_allows_capacity_burst() {
        let mut b = TokenBucket::new(5.0, 1.0);
        for _ in 0..5 {
            assert!(b.try_consume(), "burst within capacity must succeed");
        }
        assert!(!b.try_consume(), "after capacity is exhausted, must reject");
    }

    #[test]
    fn refills_over_elapsed_time() {
        // 100 tokens/sec refill so a short sleep deterministically
        // re-fills the bucket. With 60 ms sleep we expect ~6 tokens earned,
        // capped at the 5-token capacity.
        let mut b = TokenBucket::new(5.0, 100.0);
        for _ in 0..5 {
            assert!(b.try_consume());
        }
        assert!(!b.try_consume());
        std::thread::sleep(Duration::from_millis(60));
        for _ in 0..5 {
            assert!(b.try_consume(), "post-refill must allow up to capacity");
        }
    }

    #[test]
    fn refill_caps_at_capacity() {
        let mut b = TokenBucket::new(3.0, 100.0);
        // 100 ms of idle would notionally earn 10 tokens at this refill
        // rate; the cap must keep the bucket at 3. Consuming 4 in a row
        // proves it never over-filled.
        std::thread::sleep(Duration::from_millis(100));
        assert!(b.try_consume());
        assert!(b.try_consume());
        assert!(b.try_consume());
        assert!(!b.try_consume(), "must not overfill above capacity");
    }

    #[test]
    fn rate_limiter_isolates_per_uid() {
        // refill = 0 disables time-based refill so each uid's budget is
        // exactly its capacity for the duration of the test.
        let r = RateLimiter::new(2.0, 0.0);
        assert!(r.check(1000));
        assert!(r.check(1000));
        assert!(!r.check(1000));
        // A different uid still has a fresh bucket.
        assert!(r.check(1001));
        assert!(r.check(1001));
        assert!(!r.check(1001));
    }

    #[test]
    fn unknown_uid_starts_with_full_capacity() {
        let r = RateLimiter::new(1.0, 0.0);
        assert!(r.check(42), "first check for a new uid must succeed");
    }
}
