// Credential caching, invalidation and resolver isolation regressions.
use super::*;
use std::sync::Arc;

#[derive(Default)]
struct Counting {
    resolves: AtomicU64,
    generation: AtomicU64,
}
impl Resolve for Arc<Counting> {
    fn resolve(&self, _: &str, _: &str, _: u16) -> Result<(ZeroString, Inject), String> {
        self.resolves.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(20));
        Ok((
            ZeroString::from_string("secret-value".into()),
            Inject::Bearer,
        ))
    }
    fn generation(&self) -> Result<u64, String> {
        Ok(self.generation.load(Ordering::SeqCst))
    }
}

#[test]
fn caches_then_refetches_after_ttl() {
    let n = Arc::new(Counting::default());
    let c = Cache::new(Box::new(n.clone()), Duration::from_secs(60));
    c.get("A", "h.example.com", 443).unwrap();
    c.get("A", "h.example.com", 443).unwrap();
    assert_eq!(n.resolves.load(Ordering::SeqCst), 1);
    let c0 = Cache::new(Box::new(n.clone()), Duration::ZERO);
    c0.get("A", "h.example.com", 443).unwrap();
    c0.get("A", "h.example.com", 443).unwrap();
    assert_eq!(n.resolves.load(Ordering::SeqCst), 3);
}

#[test]
fn generation_change_drops_cache() {
    let n = Arc::new(Counting::default());
    let c = Cache::new(Box::new(n.clone()), DEFAULT_TTL);
    c.get("A", "h.example.com", 443).unwrap();
    n.generation.store(5, Ordering::SeqCst); // e.g. `kepr agent revoke`
                                             // Within the check interval the cached value may still serve...
    c.get("A", "h.example.com", 443).unwrap();
    assert_eq!(n.resolves.load(Ordering::SeqCst), 1);
    // ...and once it has passed, the change drops the cache.
    std::thread::sleep(Duration::from_millis(300));
    c.get("A", "h.example.com", 443).unwrap();
    assert_eq!(n.resolves.load(Ordering::SeqCst), 2);
}

#[test]
fn concurrent_misses_resolve_once() {
    let n = Arc::new(Counting::default());
    let c = Arc::new(Cache::new(Box::new(n.clone()), DEFAULT_TTL));
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let c = c.clone();
            std::thread::spawn(move || c.get("A", "h.example.com", 443).unwrap())
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    assert_eq!(n.resolves.load(Ordering::SeqCst), 1);
}

#[test]
fn values_and_clear() {
    let c = Cache::new(Box::new(Arc::new(Counting::default())), DEFAULT_TTL);
    c.get("A", "h.example.com", 443).unwrap();
    assert_eq!(c.values().len(), 1);
    c.clear();
    assert!(c.values().is_empty());
}

#[test]
fn cached_values_and_tokens_live_in_secret_cells() {
    let c = Cache::new(Box::new(Arc::new(Counting::default())), DEFAULT_TTL);
    c.get("A", "h.example.com", 443).unwrap();
    c.mint([1; 32], &ZeroString::from("ghs_minted-token-1"), 100, 0);
    let secret = kepr_core::secmem::memfd_secret_available();
    let e = c.entries.lock().unwrap();
    assert!(e
        .values()
        .all(|(cell, _, _)| cell.is_secret_backed() == secret));
    drop(e);
    let m = c.minted.lock().unwrap();
    assert!(m
        .values()
        .all(|(cell, _)| cell.is_secret_backed() == secret));
    drop(m);
    assert_eq!(c.values()[0].1.as_str(), "secret-value");
    assert_eq!(c.minted(&[1; 32]).unwrap().0.as_str(), "ghs_minted-token-1");
    let (v, _) = c.get("A", "h.example.com", 443).unwrap();
    assert_eq!(v.as_str(), "secret-value", "a hit reveals the cell");
}

#[test]
fn a_generation_change_empties_values_and_tokens() {
    let n = Arc::new(Counting::default());
    let c = Cache::new(Box::new(n.clone()), DEFAULT_TTL);
    c.get("A", "h.example.com", 443).unwrap();
    c.mint([1; 32], &ZeroString::from("ghs_minted-token-1"), 100, 0);
    c.check_generation().unwrap();
    assert_eq!(c.values().len(), 2, "resolved value and derived token");
    n.generation.store(7, Ordering::SeqCst);
    std::thread::sleep(Duration::from_millis(300));
    c.check_generation().unwrap();
    assert!(c.values().is_empty());
    assert!(c.minted(&[1; 32]).is_none());
}

struct Record(&'static str);
impl Resolve for Record {
    fn resolve(&self, _: &str, _: &str, _: u16) -> Result<(ZeroString, Inject), String> {
        Ok((ZeroString::from(self.0), Inject::Postgres))
    }
    fn generation(&self) -> Result<u64, String> {
        Ok(1)
    }
}

#[test]
fn needles_of_a_database_record_are_its_password_not_user_or_database() {
    let rec = r#"{"user":"app-user-long","password":"s3cret-PW-only","database":"main-database"}"#;
    let c = Cache::new(Box::new(Record(rec)), DEFAULT_TTL);
    c.get("DB", "db.example.com", 5432).unwrap();
    let got: Vec<String> = c.needles().iter().map(|z| z.to_owned_string()).collect();
    // The password and its Base64 spellings; never the user or database.
    assert!(got.contains(&"s3cret-PW-only".to_string()));
    assert!(!got
        .iter()
        .any(|g| g.contains("app-user") || g.contains("main-")));
    assert_eq!(got.len(), 3, "{got:?}");
}

#[test]
fn needles_cover_minted_tokens_and_skip_short_values() {
    let c = Cache::new(Box::new(Record("short")), DEFAULT_TTL);
    c.get("A", "h.example.com", 443).unwrap();
    assert!(c.needles().is_empty(), "under MIN_SECRET_LEN");
    c.mint([1; 32], &ZeroString::from("ghs_minted-token-1"), 100, 0);
    let got: Vec<String> = c.needles().iter().map(|z| z.to_owned_string()).collect();
    assert!(got.contains(&"ghs_minted-token-1".to_string()));
    assert_eq!(got.len(), 2, "the token and its Base64 form: {got:?}");
}

#[test]
fn stale_replies_are_skipped_by_id() {
    let (gate_end, mut daemon_end) = UnixStream::pair().unwrap();
    let r = FdResolver {
        stream: Mutex::new(gate_end),
        next_id: AtomicU64::new(10),
    };
    let t = std::thread::spawn(move || {
        let _ = read_frame(&mut daemon_end, MAX_MSG_BYTES).unwrap();
        // A late reply for an older request (id 9), then the real one.
        for (id, v) in [(9, "WRONG"), (10, "right")] {
            let resp = GateResponse::ResolveOk {
                id,
                value: ZeroString::from_string(v.into()),
                inject: Inject::Bearer,
            };
            write_frame(&mut daemon_end, &serde_json::to_vec(&resp).unwrap()).unwrap();
        }
    });
    let (v, _) = r.resolve("A", "h.example.com", 443).unwrap();
    assert_eq!(v.as_str(), "right");
    t.join().unwrap();
}

fn poison<T>(lock: &Mutex<T>) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = lock.lock().unwrap();
        panic!("intentional screening regression fixture");
    }));
}

#[test]
fn poisoned_cache_keeps_existing_values_in_outbound_screening() {
    let c = Cache::new(Box::new(Arc::new(Counting::default())), DEFAULT_TTL);
    let (value, _) = c.get("A", "h.example.com", 443).unwrap();
    poison(&c.entries);
    assert!(matches!(
        crate::dlp::scan(value.as_bytes(), &c.values()),
        crate::dlp::Verdict::StoredSecret(_)
    ));
}

#[test]
fn values_resolved_after_cache_poisoning_are_still_screened() {
    let c = Cache::new(Box::new(Arc::new(Counting::default())), DEFAULT_TTL);
    poison(&c.entries);
    let (value, _) = c.get("A", "h.example.com", 443).unwrap();
    assert!(matches!(
        crate::dlp::scan(value.as_bytes(), &c.values()),
        crate::dlp::Verdict::StoredSecret(_)
    ));
}

#[test]
fn minted_session_tokens_are_screened_even_after_lock_poisoning() {
    let c = Cache::new(Box::new(Arc::new(Counting::default())), DEFAULT_TTL);
    let token = ZeroString::from_string(["derived-", "session-token-fixture"].concat());
    c.mint([1; 32], &token, 100, 0);
    assert!(matches!(
        crate::dlp::scan(token.as_bytes(), &c.values()),
        crate::dlp::Verdict::StoredSecret(_)
    ));
    poison(&c.minted);
    assert!(matches!(
        crate::dlp::scan(token.as_bytes(), &c.values()),
        crate::dlp::Verdict::StoredSecret(_)
    ));
    let later = ZeroString::from_string(["later-", "session-token-fixture"].concat());
    c.mint([2; 32], &later, 100, 0);
    assert!(matches!(
        crate::dlp::scan(later.as_bytes(), &c.values()),
        crate::dlp::Verdict::StoredSecret(_)
    ));
    let other = Cache::new(Box::new(Arc::new(Counting::default())), DEFAULT_TTL);
    assert_eq!(
        crate::dlp::scan(token.as_bytes(), &other.values()),
        crate::dlp::Verdict::Clean
    );
    c.clear();
    assert_eq!(
        crate::dlp::scan(token.as_bytes(), &c.values()),
        crate::dlp::Verdict::Clean
    );
}

#[test]
fn cloudflare_whole_record_encoding_cannot_hide_its_session_token() {
    use base64::Engine;
    let value = kepr_core::cloudflare::GatewayCredential::new(
        ZeroString::from_string(["cloudflare-", "opaque-fixture-token"].concat()),
        "a".repeat(32),
        "fixture-gateway".into(),
    )
    .unwrap()
    .encode();
    let c = Cache::new(Box::new(Arc::new(Counting::default())), DEFAULT_TTL);
    c.entries.lock().unwrap().insert(
        ("CF".into(), kepr_core::cloudflare::HOST.into(), 443),
        (
            SecretCell::new(&value),
            Inject::CloudflareGateway,
            Instant::now(),
        ),
    );
    let encoded = base64::engine::general_purpose::STANDARD.encode(value.as_bytes());
    assert!(matches!(
        crate::dlp::scan(encoded.as_bytes(), &c.values()),
        crate::dlp::Verdict::StoredSecret(_)
    ));
}
