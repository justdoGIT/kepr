//! Spend and rate guard (agent vault P9.5): per-session caps on
//! requests, tokens and requests per minute.
//!
//! Requests are counted when admitted. Tokens are counted from the
//! providers' own `usage` fields as responses stream back (Anthropic
//! `input_tokens`/`output_tokens`, OpenAI `prompt_tokens`/
//! `completion_tokens`/`total_tokens`, Gemini `promptTokenCount`/
//! `candidatesTokenCount`/`totalTokenCount`), so the token cap stops
//! the *next* request once a response has pushed the total over it.
//!
//! T9.06: the per-day caps are per credential and shared by every session
//! of the user: each request is reported to the daemon, which answers
//! with today's totals; tokens are reported when a response ends.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use kepr_core::gate_protocol::GateLimits;

use crate::vault::Cache;

/// Why a request was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// A session cap: the agent should stop, not retry.
    Cap(String),
    /// The per-minute rate: retry after this many seconds.
    Rate(u64),
}

pub struct Limiter {
    cfg: GateLimits,
    requests: AtomicU64,
    tokens: AtomicU64,
    window: Mutex<VecDeque<Instant>>,
}

impl Limiter {
    pub fn new(cfg: GateLimits) -> Self {
        Self {
            cfg,
            requests: AtomicU64::new(0),
            tokens: AtomicU64::new(0),
            window: Mutex::new(VecDeque::new()),
        }
    }

    /// Admit one request at `now`, or say why not.
    pub fn admit(&self, now: Instant) -> Result<(), Refusal> {
        if let Some(max) = self.cfg.max_tokens {
            let used = self.tokens.load(Ordering::Relaxed);
            if used >= max {
                return Err(Refusal::Cap(format!(
                    "this session used {used} tokens, over its limit of {max} (kepr agent run --max-tokens)"
                )));
            }
        }
        if let Some(per_min) = self.cfg.per_minute {
            let mut w = self.window.lock().unwrap_or_else(|e| e.into_inner());
            while w
                .front()
                .is_some_and(|t| now.duration_since(*t) >= Duration::from_secs(60))
            {
                w.pop_front();
            }
            if w.len() >= per_min as usize {
                let wait = w.front().map_or(60, |t| {
                    60u64
                        .saturating_sub(now.duration_since(*t).as_secs())
                        .max(1)
                });
                return Err(Refusal::Rate(wait));
            }
            w.push_back(now);
        }
        if let Some(max) = self.cfg.max_requests {
            let n = self.requests.fetch_add(1, Ordering::Relaxed);
            if n >= max {
                return Err(Refusal::Cap(format!(
                    "this session reached its limit of {max} requests (kepr agent run --max-requests)"
                )));
            }
        }
        Ok(())
    }

    pub fn config(&self) -> GateLimits {
        self.cfg
    }

    /// Only sessions with a token cap pay for scanning responses.
    pub fn meters_tokens(&self) -> bool {
        self.cfg.max_tokens.is_some() || self.cfg.max_tokens_day.is_some()
    }

    /// T9.06: count one request of `cred` with the daemon and check the
    /// day's totals. A total the daemon can't give refuses (fail closed).
    pub async fn admit_today(&self, cache: Arc<Cache>, cred: String) -> Result<(), Refusal> {
        if self.cfg.max_requests_day.is_none() && self.cfg.max_tokens_day.is_none() {
            return Ok(());
        }
        let today = tokio::task::spawn_blocking(move || cache.day_usage(&cred, 1, 0)).await;
        self.check_today(today.unwrap_or_else(|_| Err(String::new())))
    }

    pub fn check_today(&self, today: Result<(u64, u64), String>) -> Result<(), Refusal> {
        let (requests, tokens) =
            today.map_err(|_| Refusal::Cap("kepr could not check today's usage".into()))?;
        if let Some(max) = self.cfg.max_tokens_day.filter(|m| tokens >= *m) {
            return Err(Refusal::Cap(format!(
                "this key used {tokens} tokens today, over its daily limit of {max} (kepr agent run --max-tokens-day)"
            )));
        }
        if let Some(max) = self.cfg.max_requests_day.filter(|m| requests > *m) {
            return Err(Refusal::Cap(format!(
                "this key reached its daily limit of {max} requests (kepr agent run --max-requests-day)"
            )));
        }
        Ok(())
    }

    pub fn add_tokens(&self, n: u64) {
        self.tokens.fetch_add(n, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub fn tokens(&self) -> u64 {
        self.tokens.load(Ordering::Relaxed)
    }
}

const IN_KEYS: &[&[u8]] = &[
    b"\"input_tokens\"",
    b"\"prompt_tokens\"",
    b"\"promptTokenCount\"",
];
const OUT_KEYS: &[&[u8]] = &[
    b"\"output_tokens\"",
    b"\"completion_tokens\"",
    b"\"candidatesTokenCount\"",
];
const TOTAL_KEYS: &[&[u8]] = &[b"\"total_tokens\"", b"\"totalTokenCount\""];
const CARRY: usize = 64;

/// Largest number following any of `keys` (as `"key": N`) in `buf`.
fn max_after(buf: &[u8], keys: &[&[u8]]) -> u64 {
    let mut best = 0;
    for key in keys {
        for (i, _) in buf.windows(key.len()).enumerate().filter(|(_, w)| w == key) {
            let rest = &buf[i + key.len()..];
            let rest = rest
                .iter()
                .position(|b| !matches!(b, b' ' | b':'))
                .map_or(&[][..], |p| &rest[p..]);
            let digits: Vec<u8> = rest
                .iter()
                .take_while(|b| b.is_ascii_digit())
                .copied()
                .collect();
            if let Some(n) = std::str::from_utf8(&digits)
                .ok()
                .and_then(|s| s.parse().ok())
            {
                best = best.max(n);
            }
        }
    }
    best
}

/// Follows one response body and adds its token usage to the session.
/// Usage counts are cumulative within a response, so it keeps the
/// largest value per kind and adds only the growth.
pub struct UsageMeter {
    limiter: Arc<Limiter>,
    /// T9.06: where the response's tokens go when it ends.
    report: Option<Box<dyn FnOnce(u64) + Send + Sync>>,
    carry: Vec<u8>,
    input: u64,
    output: u64,
    total: u64,
    counted: u64,
}

impl UsageMeter {
    pub fn new(limiter: Arc<Limiter>) -> Self {
        Self {
            limiter,
            report: None,
            carry: Vec::new(),
            input: 0,
            output: 0,
            total: 0,
            counted: 0,
        }
    }

    /// T9.06: with a daily token cap, report this response's tokens for
    /// `cred` to the daemon when the response is done.
    pub fn daily(mut self, cache: &Arc<Cache>, cred: &str) -> Self {
        if self.limiter.cfg.max_tokens_day.is_some() {
            let (cache, cred) = (cache.clone(), cred.to_string());
            self.report = Some(Box::new(move |n| {
                if let Ok(h) = tokio::runtime::Handle::try_current() {
                    h.spawn_blocking(move || cache.day_usage(&cred, 0, n));
                }
            }));
        }
        self
    }

    pub fn observe(&mut self, chunk: &Bytes) {
        let mut buf = std::mem::take(&mut self.carry);
        buf.extend_from_slice(chunk);
        self.input = self.input.max(max_after(&buf, IN_KEYS));
        self.output = self.output.max(max_after(&buf, OUT_KEYS));
        self.total = self.total.max(max_after(&buf, TOTAL_KEYS));
        let now = self.total.max(self.input + self.output);
        if now > self.counted {
            self.limiter.add_tokens(now - self.counted);
            self.counted = now;
        }
        let keep = buf.len().saturating_sub(CARRY);
        self.carry = buf.split_off(keep);
    }
}

impl Drop for UsageMeter {
    fn drop(&mut self) {
        if let Some(report) = self.report.take().filter(|_| self.counted > 0) {
            report(self.counted);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lim(r: Option<u64>, t: Option<u64>, m: Option<u32>) -> Arc<Limiter> {
        Arc::new(Limiter::new(GateLimits {
            max_requests: r,
            max_tokens: t,
            per_minute: m,
            ..Default::default()
        }))
    }

    #[test]
    fn daily_caps_refuse_with_the_days_totals() {
        let l = Limiter::new(GateLimits {
            max_requests_day: Some(2),
            max_tokens_day: Some(1_000),
            ..Default::default()
        });
        assert!(l.check_today(Ok((2, 999))).is_ok());
        assert!(
            matches!(l.check_today(Ok((3, 0))), Err(Refusal::Cap(m)) if m.contains("daily limit of 2 requests"))
        );
        assert!(
            matches!(l.check_today(Ok((1, 1_000))), Err(Refusal::Cap(m)) if m.contains("daily limit of 1000"))
        );
        assert!(matches!(
            l.check_today(Err("gone".into())),
            Err(Refusal::Cap(_))
        ));
        assert!(l.meters_tokens());
        assert!(Limiter::new(GateLimits::default())
            .check_today(Ok((9, 9)))
            .is_ok());
    }

    #[test]
    fn a_metered_response_reports_its_tokens_once() {
        let l = Arc::new(Limiter::new(GateLimits::default()));
        let got = Arc::new(Mutex::new(Vec::new()));
        let mut m = UsageMeter::new(l);
        let g = got.clone();
        m.report = Some(Box::new(move |n| g.lock().unwrap().push(n)));
        m.observe(&Bytes::from_static(
            br#"{"usage":{"input_tokens":30,"output_tokens":12}}"#,
        ));
        drop(m);
        assert_eq!(*got.lock().unwrap(), [42]);
    }

    #[test]
    fn request_cap() {
        let l = lim(Some(2), None, None);
        let t = Instant::now();
        assert!(l.admit(t).is_ok() && l.admit(t).is_ok());
        assert!(matches!(l.admit(t), Err(Refusal::Cap(m)) if m.contains("limit of 2 requests")));
    }

    #[test]
    fn rate_window_slides() {
        let l = lim(None, None, Some(2));
        let t = Instant::now();
        assert!(l.admit(t).is_ok() && l.admit(t).is_ok());
        assert!(matches!(
            l.admit(t + Duration::from_secs(10)),
            Err(Refusal::Rate(50))
        ));
        assert!(l.admit(t + Duration::from_secs(61)).is_ok());
    }

    #[test]
    fn meters_anthropic_stream_split_across_chunks() {
        let l = lim(None, Some(100), None);
        let mut m = UsageMeter::new(l.clone());
        m.observe(&Bytes::from_static(
            br#"event: message_start
data: {"message":{"usage":{"input_tokens":40,"cache_read_input_tokens":999,"output_tokens":1}}}"#,
        ));
        m.observe(&Bytes::from_static(br#"data: {"usage":{"output_to"#));
        m.observe(&Bytes::from_static(br#"kens": 70}}"#));
        assert_eq!(l.tokens(), 110);
        assert!(matches!(l.admit(Instant::now()), Err(Refusal::Cap(_))));
    }

    #[test]
    fn meters_openai_and_gemini_totals() {
        let l = lim(None, None, None);
        UsageMeter::new(l.clone()).observe(&Bytes::from_static(
            br#"{"usage":{"prompt_tokens":5,"completion_tokens":7,"total_tokens":12}}"#,
        ));
        UsageMeter::new(l.clone()).observe(&Bytes::from_static(
            br#"{"usageMetadata":{"promptTokenCount":3,"candidatesTokenCount":4,"totalTokenCount":9}}"#,
        ));
        assert_eq!(l.tokens(), 21);
    }
}
