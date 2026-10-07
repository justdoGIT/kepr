// daemon_seal/tpm.rs — TPM2 sealing with a PIN and an anti-rollback
// counter, through tpm2-tools (T4.08; settings in tpm_config.rs).
//
// With a PIN the sealed object's policy is PolicyAuthValue (plus
// PolicyPCR with KEPR_TPM2_PCRS), so wrong PINs count towards the TPM's
// dictionary-attack lockout. The tools read the PIN themselves
// (`-p file:PATH`); the key goes in on stdin and comes back on stdout.
//
// The NV counter is defined (`nt=counter`) on the first seal and
// incremented on every seal, i.e. every new master key. Its value is
// sealed in the TPM object with the key and the index (key ‖ counter ‖
// index) and written in the blob's header; unseal refuses a blob whose
// sealed counter is lower than the TPM's: an older copy of the key.
//
// Blob: "kepr-tpm2-v1\n" | flags (1: PIN, 2: PCRs) | counter u64 | index
// u32 | pcrs (u8 len, `7,11`) | public (u16 len) | private (u16 len).

use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use super::runner::{Cmd, RunError, Runner};
use super::tpm_config::TpmConfig;
use crate::master_key::Sealer;

const MAGIC: &[u8] = b"kepr-tpm2-v1\n";
const FLAG_PIN: u8 = 1;
const FLAG_PCRS: u8 = 2;
const PAYLOAD: usize = 32 + 8 + 4;
const SEAL_FAILED: &str = "master-key seal failed";
const UNSEAL_FAILED: &str = "master-key unseal failed";
const COUNTER_FAILED: &str = "cannot use the TPM2 anti-rollback counter";
const MISSING: &str = "TPM2 sealing needs the tpm2-tools package installed";

/// A private scratch directory for the tools' context files, removed on
/// drop. Nothing secret is written there.
struct WorkDir(PathBuf);

impl WorkDir {
    fn new(base: &Path) -> Result<Self, String> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let p = base.join(format!(".tpm2-{}-{nanos}", std::process::id()));
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&p)
            .map_err(|e| format!("TPM2 work directory: {e}"))?;
        Ok(Self(p))
    }

    fn file(&self, name: &str) -> String {
        self.0.join(name).to_string_lossy().into_owned()
    }
}

impl Drop for WorkDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Blob {
    flags: u8,
    counter: u64,
    index: u32,
    pcrs: String,
    public: Vec<u8>,
    private: Vec<u8>,
}

fn put16(out: &mut Vec<u8>, b: &[u8]) -> Result<(), String> {
    let n = u16::try_from(b.len()).map_err(|_| SEAL_FAILED)?;
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(b);
    Ok(())
}

impl Blob {
    fn encode(&self) -> Result<Vec<u8>, String> {
        let mut out = MAGIC.to_vec();
        out.push(self.flags);
        out.extend_from_slice(&self.counter.to_be_bytes());
        out.extend_from_slice(&self.index.to_be_bytes());
        out.push(self.pcrs.len() as u8);
        out.extend_from_slice(self.pcrs.as_bytes());
        put16(&mut out, &self.public)?;
        put16(&mut out, &self.private)?;
        Ok(out)
    }

    fn decode(blob: &[u8]) -> Result<Self, String> {
        let bad =
            || "the master key was not sealed with the TPM2 PIN / counter options".to_string();
        let mut r = blob.strip_prefix(MAGIC).ok_or_else(bad)?;
        let mut take = |n: usize| -> Result<Vec<u8>, String> {
            if r.len() < n {
                return Err(bad());
            }
            let (a, b) = r.split_at(n);
            r = b;
            Ok(a.to_vec())
        };
        let flags = take(1)?[0];
        let counter = u64::from_be_bytes(take(8)?.try_into().map_err(|_| bad())?);
        let index = u32::from_be_bytes(take(4)?.try_into().map_err(|_| bad())?);
        let n = take(1)?[0];
        let pcrs = String::from_utf8(take(n.into())?).map_err(|_| bad())?;
        let n = u16::from_be_bytes(take(2)?.try_into().map_err(|_| bad())?);
        let public = take(n.into())?;
        let n = u16::from_be_bytes(take(2)?.try_into().map_err(|_| bad())?);
        let private = take(n.into())?;
        let pcrs_ok = pcrs.bytes().all(|b| b.is_ascii_digit() || b == b',');
        if !r.is_empty() || !pcrs_ok || (flags & FLAG_PCRS != 0) == pcrs.is_empty() {
            return Err(bad());
        }
        Ok(Self {
            flags,
            counter,
            index,
            pcrs,
            public,
            private,
        })
    }
}

pub struct TpmSealer<R: Runner> {
    pub cfg: TpmConfig,
    pub runner: R,
    /// Where scratch directories go (the master key's directory).
    pub work: PathBuf,
}

impl<R: Runner> TpmSealer<R> {
    fn run(&self, cmd: Cmd, failed: &str) -> Result<Zeroizing<Vec<u8>>, String> {
        self.runner.run(&cmd).map_err(|e| match e {
            RunError::Missing => MISSING.into(),
            RunError::Failed => failed.to_string(),
        })
    }

    fn read_counter(&self, index: u32) -> Result<u64, String> {
        let i = format!("{index:#010x}");
        let out = self.run(
            Cmd::new("tpm2_nvread", &["-C", "o", "-s", "8", &i]),
            COUNTER_FAILED,
        )?;
        let b: [u8; 8] = out[..].try_into().map_err(|_| COUNTER_FAILED)?;
        Ok(u64::from_be_bytes(b))
    }

    /// Define the counter on first use, increment it, return the value.
    fn bump_counter(&self) -> Result<u64, String> {
        let i = format!("{:#010x}", self.cfg.nv_index);
        if let Err(e) = self.runner.run(&Cmd::new("tpm2_nvreadpublic", &[&i])) {
            if e == RunError::Missing {
                return Err(MISSING.into());
            }
            let attrs = "nt=counter|ownerread|ownerwrite";
            let define = ["-C", "o", "-s", "8", "-a", attrs, &i];
            self.run(Cmd::new("tpm2_nvdefine", &define), COUNTER_FAILED)?;
        }
        self.run(
            Cmd::new("tpm2_nvincrement", &["-C", "o", &i]),
            COUNTER_FAILED,
        )?;
        self.read_counter(self.cfg.nv_index)
    }

    fn primary(&self, w: &WorkDir, failed: &str) -> Result<String, String> {
        let ctx = w.file("primary.ctx");
        let args = ["-C", "o", "-g", "sha256", "-G", "ecc", "-c", &ctx];
        self.run(Cmd::new("tpm2_createprimary", &args), failed)?;
        Ok(ctx)
    }

    /// Start a session, run the policy commands `flags` asks for (the
    /// last one writes `digest` on a trial session) and hand the session
    /// to `then`; the session is flushed afterwards either way.
    fn with_policy<T>(
        &self,
        w: &WorkDir,
        (flags, pcrs): (u8, &str),
        digest: Option<&str>,
        then: impl FnOnce(&str) -> Result<T, String>,
    ) -> Result<T, String> {
        let failed = if digest.is_some() {
            SEAL_FAILED
        } else {
            UNSEAL_FAILED
        };
        let s = w.file("session.ctx");
        // A trial session computes the digest; a policy session satisfies it.
        let mut start = vec!["-S", s.as_str()];
        if digest.is_none() {
            start.insert(0, "--policy-session");
        }
        self.run(Cmd::new("tpm2_startauthsession", &start), failed)?;
        let r = (|| {
            let pcr = format!("sha256:{pcrs}");
            let mut steps: Vec<(&str, Vec<&str>)> = Vec::new();
            if flags & FLAG_PCRS != 0 {
                steps.push(("tpm2_policypcr", vec!["-S", &s, "-l", &pcr]));
            }
            if flags & FLAG_PIN != 0 {
                steps.push(("tpm2_policyauthvalue", vec!["-S", &s]));
            }
            if let (Some(d), Some(last)) = (digest, steps.last_mut()) {
                last.1.extend(["-L", d]);
            }
            for (tool, args) in steps {
                self.run(Cmd::new(tool, &args), failed)?;
            }
            then(&s)
        })();
        let _ = self.runner.run(&Cmd::new("tpm2_flushcontext", &[&s]));
        r
    }

    fn pin_auth(&self) -> Result<String, String> {
        let f = self.cfg.pin_file.as_ref().ok_or(
            "this master key needs its TPM2 PIN: set KEPR_TPM2_PIN=1 and KEPR_TPM2_PIN_FILE",
        )?;
        Ok(format!("file:{}", f.display()))
    }
}

impl<R: Runner> Sealer for TpmSealer<R> {
    fn seal(&self, key: &[u8; 32]) -> Result<Vec<u8>, String> {
        let w = WorkDir::new(&self.work)?;
        let counter = self.bump_counter()?;
        let primary = self.primary(&w, SEAL_FAILED)?;
        let pcrs = self.cfg.pcrs.clone().unwrap_or_default();
        let flags = if self.cfg.pin_file.is_some() {
            FLAG_PIN
        } else {
            0
        } | if pcrs.is_empty() { 0 } else { FLAG_PCRS };
        let (public, private) = (w.file("key.pub"), w.file("key.priv"));
        let mut create = Cmd::new(
            "tpm2_create",
            &[
                "-C", &primary, "-g", "sha256", "-u", &public, "-r", &private, "-i", "-",
            ],
        );
        if flags != 0 {
            let digest = w.file("policy.digest");
            self.with_policy(&w, (flags, &pcrs), Some(&digest), |_| Ok(()))?;
            create
                .args
                .extend(["-L", &digest, "-a", "fixedtpm|fixedparent"].map(String::from));
        }
        if flags & FLAG_PIN != 0 {
            create.args.extend(["-p".to_string(), self.pin_auth()?]);
        }
        let mut payload = Zeroizing::new(Vec::with_capacity(PAYLOAD));
        payload.extend_from_slice(key);
        payload.extend_from_slice(&counter.to_be_bytes());
        payload.extend_from_slice(&self.cfg.nv_index.to_be_bytes());
        self.run(create.stdin(&payload), SEAL_FAILED)?;
        let read = |p: &str| fs::read(p).map_err(|_| SEAL_FAILED.to_string());
        Blob {
            flags,
            counter,
            index: self.cfg.nv_index,
            pcrs,
            public: read(&public)?,
            private: read(&private)?,
        }
        .encode()
    }

    fn unseal(&self, blob: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
        let b = Blob::decode(blob)?;
        let w = WorkDir::new(&self.work)?;
        let (public, private, ctx) = (w.file("key.pub"), w.file("key.priv"), w.file("key.ctx"));
        fs::write(&public, &b.public).map_err(|_| UNSEAL_FAILED)?;
        fs::write(&private, &b.private).map_err(|_| UNSEAL_FAILED)?;
        let primary = self.primary(&w, UNSEAL_FAILED)?;
        let load = ["-C", &primary, "-u", &public, "-r", &private, "-c", &ctx];
        self.run(Cmd::new("tpm2_load", &load), UNSEAL_FAILED)?;
        let unseal = |auth: Option<String>| {
            let mut c = Cmd::new("tpm2_unseal", &["-c", &ctx]);
            c.args
                .extend(auth.into_iter().flat_map(|a| ["-p".to_string(), a]));
            self.run(c, UNSEAL_FAILED)
        };
        let out = if b.flags == 0 {
            unseal(None)?
        } else {
            let pin = match b.flags & FLAG_PIN {
                0 => String::new(),
                _ => format!("+{}", self.pin_auth()?),
            };
            self.with_policy(&w, (b.flags, &b.pcrs), None, |s| {
                unseal(Some(format!("session:{s}{pin}")))
            })?
        };
        if out.len() != PAYLOAD {
            return Err(UNSEAL_FAILED.into());
        }
        let counter = u64::from_be_bytes(out[32..40].try_into().map_err(|_| UNSEAL_FAILED)?);
        let index = u32::from_be_bytes(out[40..].try_into().map_err(|_| UNSEAL_FAILED)?);
        if counter != b.counter || index != b.index {
            return Err("the sealed master key's header was altered".into());
        }
        if counter < self.read_counter(index)? {
            return Err(
                "this sealed master key is older than the TPM2 anti-rollback counter: \
                        refusing a rolled-back copy"
                    .into(),
            );
        }
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&out[..32]);
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::super::runner::fake::{arg, FakeRunner};
    use super::super::tpm_config::DEFAULT_NV_INDEX;
    use super::*;
    use std::sync::{Arc, Mutex};

    /// A pretend TPM: one NV counter, and "sealing" that keeps the payload
    /// in the private blob (enough to test the orchestration).
    #[derive(Default)]
    struct Tpm {
        counter: Option<u64>,
        loaded: Vec<u8>,
    }

    fn fake(tpm: Arc<Mutex<Tpm>>) -> FakeRunner {
        FakeRunner::new(move |c| {
            let mut t = tpm.lock().unwrap();
            match c.tool {
                "tpm2_nvreadpublic" => t.counter.map(|_| Vec::new()).ok_or(RunError::Failed),
                "tpm2_nvdefine" => {
                    t.counter = Some(0);
                    Ok(Vec::new())
                }
                "tpm2_nvincrement" => {
                    *t.counter.as_mut().ok_or(RunError::Failed)? += 1;
                    Ok(Vec::new())
                }
                "tpm2_nvread" => Ok(t.counter.ok_or(RunError::Failed)?.to_be_bytes().to_vec()),
                "tpm2_create" => {
                    fs::write(arg(&c.args, "-u").unwrap(), b"PUBLIC").unwrap();
                    fs::write(arg(&c.args, "-r").unwrap(), c.stdin).unwrap();
                    Ok(Vec::new())
                }
                "tpm2_load" => {
                    t.loaded = fs::read(arg(&c.args, "-r").unwrap()).unwrap();
                    Ok(Vec::new())
                }
                "tpm2_unseal" => Ok(t.loaded.clone()),
                _ => Ok(Vec::new()),
            }
        })
    }

    fn sealer(cfg: TpmConfig, tpm: &Arc<Mutex<Tpm>>, dir: &Path) -> TpmSealer<FakeRunner> {
        TpmSealer {
            cfg,
            runner: fake(Arc::clone(tpm)),
            work: dir.to_path_buf(),
        }
    }

    fn counter_only() -> TpmConfig {
        TpmConfig {
            pin_file: None,
            nv_index: DEFAULT_NV_INDEX,
            pcrs: None,
        }
    }

    #[test]
    fn first_seal_defines_the_counter_and_rotation_increments_it() {
        let dir = tempfile::tempdir().unwrap();
        let tpm = Arc::new(Mutex::new(Tpm::default()));
        let s = sealer(counter_only(), &tpm, dir.path());
        let blob = s.seal(&[7u8; 32]).unwrap();
        let define: Vec<_> = s
            .runner
            .calls()
            .into_iter()
            .filter(|c| c.0 == "tpm2_nvdefine")
            .collect();
        assert_eq!(define.len(), 1);
        assert!(define[0]
            .1
            .contains(&"nt=counter|ownerread|ownerwrite".to_string()));
        assert!(define[0].1.contains(&"0x01800a11".to_string()));
        assert_eq!(*s.unseal(&blob).unwrap(), [7u8; 32]);
        // A second master key: no new definition, counter 2.
        let s2 = sealer(counter_only(), &tpm, dir.path());
        s2.seal(&[8u8; 32]).unwrap();
        assert!(!s2.runner.tools().contains(&"tpm2_nvdefine".to_string()));
        assert_eq!(tpm.lock().unwrap().counter, Some(2));
        // Scratch directories are gone.
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn an_older_blob_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let tpm = Arc::new(Mutex::new(Tpm::default()));
        let s = sealer(counter_only(), &tpm, dir.path());
        let old = s.seal(&[1u8; 32]).unwrap();
        let new = s.seal(&[2u8; 32]).unwrap();
        assert_eq!(*s.unseal(&new).unwrap(), [2u8; 32]);
        let e = s.unseal(&old).unwrap_err();
        assert!(e.contains("rolled-back"), "{e}");
        // Raising the header's counter doesn't help: the sealed one counts.
        let mut forged = old.clone();
        forged[MAGIC.len() + 8] = 2;
        assert!(s.unseal(&forged).unwrap_err().contains("altered"));
    }

    #[test]
    fn pin_uses_policy_auth_value_and_never_argv() {
        let dir = tempfile::tempdir().unwrap();
        let pin = dir.path().join("pin");
        fs::write(&pin, b"123456").unwrap();
        let tpm = Arc::new(Mutex::new(Tpm::default()));
        let cfg = TpmConfig {
            pin_file: Some(pin.clone()),
            nv_index: DEFAULT_NV_INDEX,
            pcrs: Some("7,11".into()),
        };
        let work = dir.path().join("w");
        let s = sealer(cfg, &tpm, &work);
        let blob = s.seal(&[3u8; 32]).unwrap();
        let calls = s.runner.calls();
        let create = calls.iter().find(|c| c.0 == "tpm2_create").unwrap();
        assert_eq!(
            arg(&create.1, "-p"),
            Some(format!("file:{}", pin.display()).as_str())
        );
        assert_eq!(arg(&create.1, "-a"), Some("fixedtpm|fixedparent"));
        assert_eq!(arg(&create.1, "-i"), Some("-"));
        assert_eq!(&create.2[..32], &[3u8; 32]);
        let policy = calls
            .iter()
            .find(|c| c.0 == "tpm2_policyauthvalue")
            .unwrap();
        assert!(
            arg(&policy.1, "-L").is_some(),
            "trial policy writes the digest"
        );
        assert!(calls
            .iter()
            .any(|c| c.0 == "tpm2_policypcr" && c.1.contains(&"sha256:7,11".into())));
        assert!(calls
            .iter()
            .all(|c| c.1.iter().all(|a| !a.contains("123456"))));
        // Unseal replays the policy and passes the session plus the PIN file.
        assert_eq!(*s.unseal(&blob).unwrap(), [3u8; 32]);
        let calls = s.runner.calls();
        let unseal = calls.iter().rev().find(|c| c.0 == "tpm2_unseal").unwrap();
        let auth = arg(&unseal.1, "-p").unwrap();
        assert!(
            auth.starts_with("session:") && auth.ends_with(&format!("+file:{}", pin.display()))
        );
        assert!(calls
            .iter()
            .any(|c| c.1.contains(&"--policy-session".to_string())));
        // Without the PIN file the key stays sealed.
        let nopin = sealer(counter_only(), &tpm, &work);
        assert!(nopin.unseal(&blob).unwrap_err().contains("PIN"));
    }

    #[test]
    fn a_missing_tool_names_the_package() {
        let dir = tempfile::tempdir().unwrap();
        let s = TpmSealer {
            cfg: counter_only(),
            runner: FakeRunner::new(|_| Err(RunError::Missing)),
            work: dir.path().to_path_buf(),
        };
        assert!(s
            .seal(&[0u8; 32])
            .unwrap_err()
            .contains("tpm2-tools package"));
        let s = TpmSealer {
            cfg: counter_only(),
            runner: FakeRunner::new(|c| match c.tool {
                "tpm2_createprimary" => Err(RunError::Missing),
                "tpm2_nvread" => Ok(1u64.to_be_bytes().to_vec()),
                _ => Ok(Vec::new()),
            }),
            work: dir.path().to_path_buf(),
        };
        assert!(s
            .seal(&[0u8; 32])
            .unwrap_err()
            .contains("tpm2-tools package"));
    }

    #[test]
    fn foreign_blobs_are_rejected_clearly() {
        let dir = tempfile::tempdir().unwrap();
        let tpm = Arc::new(Mutex::new(Tpm::default()));
        let s = sealer(counter_only(), &tpm, dir.path());
        let e = s.unseal(b"kepr-local-v1\nxxxx").unwrap_err();
        assert!(e.contains("not sealed with the TPM2"), "{e}");
        let mut blob = s.seal(&[4u8; 32]).unwrap();
        blob.push(0);
        assert!(s.unseal(&blob).is_err());
    }
}
