// daemon_store/testkit.rs — test-only: a real in-process backend over a
// temp store, shared by the daemon test binary (the backend is a
// process-wide OnceLock). Every test takes a fresh uid, so tests never
// see each other's credentials. Only XDG_DATA_HOME is set, once, before
// the backend is created (store_dir() reads it; nothing else in the
// daemon's tests depends on it).

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Once};

use kepr_core::binding::{Binding, Inject};

use crate::daemon_handlers::{handle_set, SetFlags};
use crate::expiry::{self, CredMeta};
use crate::store::cred_path;

static INIT: Once = Once::new();
static NEXT_UID: AtomicU32 = AtomicU32::new(4_100_000);

/// A uid no other test uses, with the shared test store ready.
pub fn uid() -> u32 {
    INIT.call_once(|| {
        let root = std::env::temp_dir().join(format!("kepr-store-tests-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create test store root");
        std::env::remove_var("KEPR_SYSTEM_MODE");
        std::env::set_var("XDG_DATA_HOME", root.join("data"));
        let versions = Arc::new(
            crate::version_state::VersionState::load(root.join("cred-versions.json"))
                .expect("version state"),
        );
        let _ = crate::crypto::initialize_inproc_backend(&[0x5a; 32], versions);
    });
    NEXT_UID.fetch_add(1, Ordering::SeqCst)
}

/// `kepr set NAME VALUE` with no flags.
pub fn set(uid: u32, name: &str, value: &str) {
    let r = handle_set(uid, "t", name, Some(value), None, SetFlags::default());
    assert!(r.is_success(), "set {name}: {r:?}");
}

/// A sealed credential bound to api.example.com.
pub fn set_sealed(uid: u32, name: &str, value: &str) {
    let flags = SetFlags {
        sealed: Some(true),
        bindings: Some(vec![Binding {
            host: "api.example.com".into(),
            port: 443,
            inject: Inject::Bearer,
        }]),
        ..Default::default()
    };
    let r = handle_set(uid, "t", name, Some(value), None, flags);
    assert!(r.is_success(), "sealed set {name}: {r:?}");
}

pub fn meta(uid: u32, name: &str) -> CredMeta {
    expiry::read_meta(&expiry::meta_path_for(&cred_path(uid, name)))
        .and_then(Result::ok)
        .unwrap_or_default()
}

/// The decrypted value (test assertions only).
pub fn value(uid: u32, name: &str) -> Option<String> {
    crate::crypto::default_backend()
        .decrypt(uid, name)
        .ok()
        .map(|z| z.as_str().to_string())
}
