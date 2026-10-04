// expiry.rs — sidecar metadata for `--ttl`-bearing credentials.
//
// Phase 2 α: the simplest expiry primitive. Each cred file in
// /etc/credstore.encrypted/ may have a sibling `<cred>.meta` file
// holding a JSON record with the absolute unix expiry timestamp.
//
//   /etc/credstore.encrypted/kepr-1000-foo
//   /etc/credstore.encrypted/kepr-1000-foo.meta   ← {"expires_at_unix":1740000000}
//
// `handle_get` consults the meta on every read and returns
// "credential unavailable" if `now >= expires_at_unix`. This means
// expiry is enforced at access time even if no GC has run; the
// (deferred to Phase 2 β) sweeper thread is a disk-hygiene win, not
// a security boundary.
//
// Threat model: the meta file lives at root:kepr 0640 alongside the
// cred. An attacker with filesystem write to /etc/credstore.encrypted/
// can already read or delete the cred itself, so making the meta
// resistant to tampering wouldn't add anything — expiry is treated
// as a UX feature, not an authz boundary. The cred-content authz
// (per-uid namespacing, AEAD AAD binding, rollback counter) stays
// the source of truth for confidentiality and integrity.
//
// Why a sidecar and not the AEAD plaintext: the AEAD format is
// versioned (`kepr_v1` / `kepr_v2`); shoehorning expiry into the
// plaintext would require `kepr_v3` and a sweep/migration step.
// Sidecar lets the feature ship without touching the crypto path
// or the on-disk format.

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Suffix for the metadata file. A separate suffix (rather than a
/// hidden file or a different directory) keeps every per-cred
/// artefact discoverable by `ls /etc/credstore.encrypted/`, which
/// is how operators audit the store today.
const META_SUFFIX: &str = ".meta";

/// On-disk record. Every field is `Option<…>` with `#[serde(default)]`
/// so meta files written by older daemons parse cleanly under newer
/// ones. Empty `CredMeta` is equivalent to "no flags" (callers should
/// skip writing the meta file in that case).
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct CredMeta {
    /// Absolute unix timestamp (seconds since epoch) at which this
    /// credential expires. The daemon refuses to decrypt past this
    /// instant. Phase 2 α.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub expires_at_unix: Option<u64>,
    /// True iff `kepr get` requires a polkit consent prompt before
    /// the daemon decrypts. Phase 2 ε.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub requires_consent: Option<bool>,
    /// True iff `kepr get` requires a FIDO2 hardware-key assertion
    /// before the daemon decrypts. Phase 2 η.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub requires_fido2: Option<bool>,
    /// True iff the value is write-only: `Get` is refused and only a
    /// daemon-spawned kepr-gate may resolve it, for a host listed in
    /// `bindings`. Agent vault plan §4.3.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sealed: Option<bool>,
    /// Destinations a sealed value may be sent to.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub bindings: Option<Vec<kepr_core::binding::Binding>>,
    /// P2.4: the value is an Ed25519 SSH key seed. Like `sealed`, `Get`
    /// refuses it; the daemon only signs with it (`SshSign`).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ssh: Option<SshMeta>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct SshMeta {
    /// Public key blob, base64 (not secret).
    pub public_b64: String,
    pub comment: String,
}

impl CredMeta {
    /// True iff the meta has no flags set. Callers use this to
    /// decide whether to bother writing the file at all — an empty
    /// meta is identical to no meta from the read path's perspective.
    pub fn is_empty(&self) -> bool {
        self.expires_at_unix.is_none()
            && self.requires_consent.is_none()
            && self.requires_fido2.is_none()
            && self.sealed.is_none()
            && self.bindings.is_none()
            && self.ssh.is_none()
    }

    /// Build a `CredMeta` from per-flag CLI inputs. Returns `Err`
    /// if `ttl_secs` would overflow `now + ttl` past `u64::MAX`
    /// — the caller treats that as a fail-and-rollback condition
    /// in `handle_set`. Pure: no I/O, no SystemTime.
    pub fn from_flags(
        now_unix: u64,
        ttl_secs: Option<u64>,
        requires_consent: Option<bool>,
        requires_fido2: Option<bool>,
    ) -> Result<Self, String> {
        let mut meta = Self::default();
        if let Some(ttl) = ttl_secs {
            meta.expires_at_unix = Some(
                compute_expires_at(now_unix, ttl)
                    .ok_or_else(|| "ttl too large to fit in u64".to_string())?,
            );
        }
        if matches!(requires_consent, Some(true)) {
            meta.requires_consent = Some(true);
        }
        if matches!(requires_fido2, Some(true)) {
            meta.requires_fido2 = Some(true);
        }
        Ok(meta)
    }

    /// Apply the sealed flag and bindings after validating them.
    /// Sealed requires at least one valid binding; bindings without
    /// sealed are rejected so nobody believes a readable credential is
    /// destination-restricted.
    pub fn with_seal(
        mut self,
        sealed: Option<bool>,
        bindings: Option<Vec<kepr_core::binding::Binding>>,
    ) -> Result<Self, String> {
        const MSG: &str = "sealed credentials need at least one valid binding";
        match (sealed, bindings) {
            (None | Some(false), None) => Ok(self),
            (Some(true), _) if self.requires_fido2 == Some(true) => Err(
                "sealed credentials can't require FIDO2 yet (the gate can't ask for a touch); \
                 use --requires-consent"
                    .to_string(),
            ),
            (Some(true), Some(bs)) if !bs.is_empty() => {
                for b in &bs {
                    kepr_core::binding::validate_binding(b).map_err(|e| format!("{MSG}: {e}"))?;
                }
                self.sealed = Some(true);
                self.bindings = Some(bs);
                Ok(self)
            }
            _ => Err(MSG.to_string()),
        }
    }
}

/// Compute the expected meta-file path for a given cred path.
/// Pure function; no I/O. The caller decides whether to read or write.
pub fn meta_path_for(cred_path: &Path) -> PathBuf {
    // Append <cred>.meta by converting to a string and pushing the
    // suffix. Using PathBuf methods avoids the raw OsStr manipulation
    // the previous implementation relied on.
    let mut s = cred_path.to_path_buf().into_os_string();
    s.push(META_SUFFIX);
    PathBuf::from(s)
}

/// Current wall-clock time as a unix timestamp. Wraps the
/// `SystemTime` API to keep the unwrap-on-time-before-epoch case in
/// one place. A clock skew this catastrophic would break much more
/// than expiry; we surface 0 and let `is_expired` handle the
/// degenerate case (every cred would fail-closed).
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Compute an expiry instant from a TTL. Returns `None` if the
/// addition would overflow u64 (which would require `now + ttl >
/// 2^64`, i.e. ~584 billion years in the future — practically
/// impossible, but pinned anyway against a future logic bug that
/// passes a junk u64).
pub fn compute_expires_at(now_unix: u64, ttl_secs: u64) -> Option<u64> {
    now_unix.checked_add(ttl_secs)
}

/// Atomically write a meta file at `meta_path` with the given
/// expiry timestamp. The temp+rename dance mirrors the cred-write
/// path in `crypto_inproc::write_atomic` so a crashed daemon
/// doesn't leave half-written meta files; the per-(pid, thread-id)
/// suffix keeps two concurrent writers from racing on the same temp.
pub fn write_meta(meta_path: &Path, meta: &CredMeta) -> Result<(), String> {
    let parent = meta_path.parent().ok_or("invalid meta path (no parent)")?;
    if !parent.exists() {
        fs::create_dir_all(parent).map_err(|e| format!("create meta dir: {e}"))?;
    }
    let tmp = meta_path.with_extension(format!(
        "tmp.{}.{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let bytes = serde_json::to_vec(meta).map_err(|e| format!("serialise meta: {e}"))?;

    let mut f = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Stale tempfile from a crashed run; retry once.
            let _ = fs::remove_file(&tmp);
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)
                .map_err(|e| format!("open meta temp (after stale-cleanup): {e}"))?
        }
        Err(e) => return Err(format!("open meta temp: {e}")),
    };
    if let Err(e) = f.write_all(&bytes) {
        drop(f);
        let _ = fs::remove_file(&tmp);
        return Err(format!("write meta: {e}"));
    }
    drop(f);
    fs::rename(&tmp, meta_path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("install meta: {e}")
    })
}

/// Read a meta file. `None` if the file is absent (the no-TTL case);
/// `Some(Err)` if the file exists but is malformed (a future-format
/// meta written by a newer daemon). Treat the malformed-but-present
/// branch as fail-closed at the call site: refuse to decrypt rather
/// than silently dropping the expiry constraint.
pub fn read_meta(meta_path: &Path) -> Option<Result<CredMeta, String>> {
    let bytes = match fs::read(meta_path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => return Some(Err(format!("read meta: {e}"))),
    };
    Some(serde_json::from_slice(&bytes).map_err(|e| format!("parse meta: {e}")))
}

/// Best-effort delete of a meta file. The cred-delete path calls
/// this AFTER the cred file is removed, since (a) we want the
/// AEAD-rooted state mutation to land first, and (b) a missing
/// meta on a present cred is harmless (decrypt just no-ops the
/// expiry check), while a present meta on a missing cred is also
/// harmless (the cred is gone, no decrypt can succeed).
pub fn delete_meta(meta_path: &Path) {
    let _ = fs::remove_file(meta_path);
}

/// Format a unix timestamp as `YYYY-MM-DD HH:MM` (UTC), matching
/// the `modified` field's format in `CredInfo`. Used to render
/// `expires_at` in `kepr list` output.
pub fn format_expires_at(unix: u64) -> String {
    // No chrono dep — hand-roll the UTC conversion. The math is
    // standard "days since epoch" → "civil date" via Howard Hinnant's
    // algorithm, plus a hh:mm split from the seconds-of-day remainder.
    let secs_per_day: u64 = 86_400;
    let days = unix / secs_per_day;
    let seconds_of_day = unix % secs_per_day;
    let hh = seconds_of_day / 3600;
    let mm = (seconds_of_day % 3600) / 60;

    // Hinnant: civil_from_days. Returns (year, month, day) where
    // month is 1..=12 and day is 1..=31.
    let z = days as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02}")
}

#[cfg(test)]
mod tests {
    use kepr_core::binding::{Binding, Inject};

    fn binding() -> Binding {
        Binding {
            host: "api.anthropic.com".into(),
            port: 443,
            inject: Inject::Header {
                name: "x-api-key".into(),
            },
        }
    }

    #[test]
    fn old_meta_without_seal_fields_parses() {
        let m: CredMeta = serde_json::from_str(r#"{"requires_consent":true}"#).unwrap();
        assert_eq!(m.sealed, None);
        assert_eq!(m.bindings, None);
    }

    #[test]
    fn sealed_meta_round_trips_and_default_omits_fields() {
        let m = CredMeta::default()
            .with_seal(Some(true), Some(vec![binding()]))
            .unwrap();
        let json = serde_json::to_string(&m).unwrap();
        let back: CredMeta = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
        assert!(!m.is_empty());
        let empty = serde_json::to_string(&CredMeta::default()).unwrap();
        assert!(!empty.contains("sealed") && !empty.contains("bindings"));
    }

    #[test]
    fn with_seal_validation() {
        let d = CredMeta::default;
        assert!(d().with_seal(Some(true), None).is_err());
        assert!(d().with_seal(Some(true), Some(vec![])).is_err());
        assert!(d().with_seal(None, Some(vec![binding()])).is_err());
        let mut bad = binding();
        bad.host = "localhost".into();
        assert!(d().with_seal(Some(true), Some(vec![bad])).is_err());
        assert_eq!(d().with_seal(None, None).unwrap(), d());
        let fido = CredMeta {
            requires_fido2: Some(true),
            ..Default::default()
        };
        assert!(fido.with_seal(Some(true), Some(vec![binding()])).is_err());
    }

    use super::*;

    #[test]
    fn meta_path_appends_suffix() {
        assert_eq!(
            meta_path_for(Path::new("/etc/credstore.encrypted/kepr-1000-foo")),
            PathBuf::from("/etc/credstore.encrypted/kepr-1000-foo.meta")
        );
    }

    #[test]
    fn meta_path_handles_path_with_dots() {
        // `foo.bar` with the suffix becomes `foo.bar.meta` — never
        // `foo.meta`. Pin against a Path::set_extension regression.
        assert_eq!(
            meta_path_for(Path::new("/x/foo.bar")),
            PathBuf::from("/x/foo.bar.meta")
        );
    }

    #[test]
    fn compute_expires_at_normal_case() {
        assert_eq!(compute_expires_at(1_000_000_000, 60), Some(1_000_000_060));
    }

    #[test]
    fn compute_expires_at_overflow_yields_none() {
        // Defensive: a junk TTL near u64::MAX must not silently wrap
        // around to a near-past timestamp.
        assert_eq!(compute_expires_at(u64::MAX - 5, 100), None);
    }

    #[test]
    fn write_then_read_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("foo.meta");
        write_meta(
            &path,
            &CredMeta {
                expires_at_unix: Some(1_777_500_000),
                requires_consent: None,
                requires_fido2: None,
                sealed: None,
                bindings: None,
                ssh: None,
            },
        )
        .unwrap();
        let meta = read_meta(&path).expect("file present").expect("parses");
        assert_eq!(meta.expires_at_unix, Some(1_777_500_000));
    }

    #[test]
    fn read_meta_returns_none_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.meta");
        assert!(read_meta(&path).is_none());
    }

    #[test]
    fn read_meta_surfaces_parse_error() {
        // A meta file written by a future daemon variant might not
        // parse under today's deserializer. Distinguishable from
        // "no meta" so the caller can fail-closed.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.meta");
        fs::write(&path, b"this is not json").unwrap();
        match read_meta(&path) {
            Some(Err(e)) => assert!(e.contains("parse meta"), "got: {e}"),
            other => panic!("expected Some(Err), got: {other:?}"),
        }
    }

    #[test]
    fn write_meta_uses_0600_mode() {
        // Self-review fix: meta must match the cred file's 0o600
        // (see crypto_inproc::write_atomic). The earlier 0o640 was
        // functionally equivalent under root:root ownership today
        // but would leak group-readability if a future PR moves
        // /etc/credstore.encrypted/ to root:kepr ownership as part
        // of dropping User=root in the unit.
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("perm.meta");
        write_meta(
            &path,
            &CredMeta {
                expires_at_unix: Some(42),
                requires_consent: None,
                requires_fido2: None,
                sealed: None,
                bindings: None,
                ssh: None,
            },
        )
        .unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "meta must be 0o600, got {mode:o}");
    }

    #[test]
    fn delete_meta_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gone.meta");
        delete_meta(&path); // missing - no panic
        write_meta(
            &path,
            &CredMeta {
                expires_at_unix: Some(1),
                requires_consent: None,
                requires_fido2: None,
                sealed: None,
                bindings: None,
                ssh: None,
            },
        )
        .unwrap();
        delete_meta(&path); // present - removed
        assert!(!path.exists());
        delete_meta(&path); // missing again - still no panic
    }

    #[test]
    fn format_expires_at_renders_utc_yyyymmdd_hhmm() {
        // Pin against a known epoch second. 1_700_000_000 is
        // 2023-11-14 22:13:20 UTC — verified with `date -u -d @1700000000`.
        assert_eq!(format_expires_at(1_700_000_000), "2023-11-14 22:13");
        // A round midnight to pin the time-of-day path too.
        assert_eq!(format_expires_at(0), "1970-01-01 00:00");
    }
}
