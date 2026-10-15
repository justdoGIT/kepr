// limit.rs — per-IP request limit: at most `per_minute` requests in each
// 60-second window. The table is bounded: when it is full, windows that
// have ended are dropped first, then the new address is refused.

use std::collections::HashMap;
use std::net::IpAddr;

const MAX_TRACKED: usize = 65_536;

pub struct RateLimit {
    per_minute: u32,
    seen: HashMap<IpAddr, (u64, u32)>,
}

impl RateLimit {
    pub fn new(per_minute: u32) -> Self {
        Self {
            per_minute,
            seen: HashMap::new(),
        }
    }

    /// Count one request from `ip` at `now`; false when over the limit.
    pub fn allow(&mut self, ip: IpAddr, now: u64) -> bool {
        let window = now / 60;
        if self.seen.len() >= MAX_TRACKED && !self.seen.contains_key(&ip) {
            self.seen.retain(|_, (w, _)| *w == window);
            if self.seen.len() >= MAX_TRACKED {
                return false;
            }
        }
        let e = self.seen.entry(ip).or_insert((window, 0));
        if e.0 != window {
            *e = (window, 0);
        }
        e.1 += 1;
        e.1 <= self.per_minute
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_address_gets_its_own_window() {
        let mut r = RateLimit::new(2);
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        assert!(r.allow(a, 60) && r.allow(a, 61));
        assert!(!r.allow(a, 62));
        assert!(r.allow(b, 62));
        assert!(r.allow(a, 120), "a new minute resets the count");
    }
}
