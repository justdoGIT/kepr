// daemon_seal/tpm.rs — TPM2 sealing with a PIN and an anti-rollback
// counter, through tpm2-tools (T4.08; settings in tpm_config.rs).
//
// With a PIN the sealed object's policy is PolicyAuthValue (plus
// PolicyPCR with KEPR_TPM2_PCRS), so wrong PINs count towards the TPM's
// dictionary-attack lockout. The tools read the PIN themselves
// (`-p file:PATH`); the key goes in on stdin and comes back on stdout.
// Between the tools and the TPM it travels only inside salted sessions
// with parameter encryption (T12.29, tpm_session.rs), so the TPM bus
// carries ciphertext.
//
// The NV counter (tpm_counter.rs) is defined (`nt=counter`) on the first
// seal and incremented on every seal, i.e. every new master key. Its value is
// sealed in the TPM object with the key and the index (key ‖ counter ‖
// index) and written in the blob's header; unseal refuses a blob whose
// sealed counter is lower than the TPM's: an older copy of the key. The
// blob format is in tpm_blob.rs.

use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use super::runner::{Cmd, RunError, Runner};
use super::tpm_blob::{Blob, FLAG_PCRS, FLAG_PIN};
use super::tpm_config::TpmConfig;
use super::tpm_counter::{bump_counter, read_counter, COUNTER_FAILED};
use super::tpm_session::Session;
use crate::master_key::Sealer;

const PAYLOAD: usize = 32 + 8 + 4;
pub(super) const SEAL_FAILED: &str = "master-key seal failed";
const UNSEAL_FAILED: &str = "master-key unseal failed";
const MISSING: &str = "TPM2 sealing needs the tpm2-tools package installed";
/// tpm2_sessionconfig came with tpm2-tools 5.0.
const MISSING_SESSIONS: &str =
    "TPM2 sealing needs the tpm2-tools package installed (tpm2-tools 5.0 or newer)";

/// A tool's failure as the user sees it: never its stderr.
pub(super) fn tool_err(e: RunError, missing: &str, failed: &str) -> String {
    match e {
        RunError::Missing => missing.into(),
        RunError::Failed => failed.into(),
    }
}

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

pub struct TpmSealer<R: Runner> {
    pub cfg: TpmConfig,
    pub runner: R,
    /// Where scratch directories go (the master key's directory).
    pub work: PathBuf,
}

impl<R: Runner> TpmSealer<R> {
    fn run(&self, cmd: Cmd, failed: &str) -> Result<Zeroizing<Vec<u8>>, String> {
        self.runner
            .run(&cmd)
            .map_err(|e| tool_err(e, MISSING, failed))
    }

    /// A salted session with parameter encryption on `primary`, in the
    /// scratch file `name`; flushed when dropped.
    fn salted(
        &self,
        w: &WorkDir,
        (name, policy): (&str, bool),
        primary: &str,
        failed: &str,
    ) -> Result<Session<'_, R>, String> {
        Session::salted(&self.runner, w.file(name), primary, policy)
            .map_err(|e| tool_err(e, MISSING_SESSIONS, failed))
    }

    /// The value of the master key's counter (tpm_counter.rs).
    fn read_counter(&self, index: u32) -> Result<u64, String> {
        read_counter(&self.runner, index).map_err(|e| tool_err(e, MISSING, COUNTER_FAILED))
    }

    /// Define the counter on first use, increment it, return the value.
    fn bump_counter(&self) -> Result<u64, String> {
        bump_counter(&self.runner, self.cfg.nv_index)
            .map_err(|e| tool_err(e, MISSING, COUNTER_FAILED))
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
        (primary, digest): (&str, Option<&str>),
        then: impl FnOnce(&Session<'_, R>) -> Result<T, String>,
    ) -> Result<T, String> {
        let failed = if digest.is_some() {
            SEAL_FAILED
        } else {
            UNSEAL_FAILED
        };
        // A trial session computes the digest (nothing secret crosses the
        // bus); a salted, encrypting policy session satisfies it.
        let session = match digest {
            Some(_) => Session::trial(&self.runner, w.file("session.ctx"))
                .map_err(|e| tool_err(e, MISSING, failed))?,
            None => self.salted(w, ("session.ctx", true), primary, failed)?,
        };
        let s = session.path();
        let pcr = format!("sha256:{pcrs}");
        let mut steps: Vec<(&str, Vec<&str>)> = Vec::new();
        if flags & FLAG_PCRS != 0 {
            steps.push(("tpm2_policypcr", vec!["-S", s, "-l", &pcr]));
        }
        if flags & FLAG_PIN != 0 {
            steps.push(("tpm2_policyauthvalue", vec!["-S", s]));
        }
        if let (Some(d), Some(last)) = (digest, steps.last_mut()) {
            last.1.extend(["-L", d]);
        }
        for (tool, args) in steps {
            self.run(Cmd::new(tool, &args), failed)?;
        }
        then(&session)
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
        // The key (and the PIN) go to the TPM parameter-encrypted.
        let session = self.salted(&w, ("hmac.ctx", false), &primary, SEAL_FAILED)?;
        let auth = session.auth();
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
                "-C", &primary, "-P", &auth, "-g", "sha256", "-u", &public, "-r", &private, "-i",
                "-",
            ],
        );
        if flags != 0 {
            let digest = w.file("policy.digest");
            let trial = (primary.as_str(), Some(digest.as_str()));
            self.with_policy(&w, (flags, &pcrs), trial, |_| Ok(()))?;
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
        let unseal = |auth: &str| {
            let c = Cmd::new("tpm2_unseal", &["-c", &ctx, "-p", auth]);
            self.run(c, UNSEAL_FAILED)
        };
        // The key comes back parameter-encrypted.
        let out = if b.flags == 0 {
            let s = self.salted(&w, ("hmac.ctx", false), &primary, UNSEAL_FAILED)?;
            unseal(&s.auth())?
        } else {
            let pin = match b.flags & FLAG_PIN {
                0 => String::new(),
                _ => format!("+{}", self.pin_auth()?),
            };
            self.with_policy(&w, (b.flags, &b.pcrs), (&primary, None), |s| {
                unseal(&format!("{}{pin}", s.auth()))
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
    use super::super::tpm_blob::MAGIC;
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

    // T12.29: salted, encrypting sessions. The scripts below pin every
    // tpm2-tools call and its argv, in order.

    /// `fake`, except that `tool` fails (or is missing).
    fn fake_failing(tpm: Arc<Mutex<Tpm>>, tool: &'static str, missing: bool) -> FakeRunner {
        let inner = fake(tpm);
        FakeRunner::new(move |c| match c.tool == tool {
            true if missing => Err(RunError::Missing),
            true => Err(RunError::Failed),
            false => inner.run(c).map(|z| z.to_vec()),
        })
    }

    /// The calls since `from`, one line each (tool and argv; stdin not
    /// shown), each scratch directory written `W` and the PIN file `PIN`.
    fn script(r: &FakeRunner, from: usize, pin: Option<&Path>) -> Vec<String> {
        let calls = r.calls().split_off(from);
        let dirs: Vec<String> = calls
            .iter()
            .filter(|c| c.0 == "tpm2_createprimary")
            .map(|c| {
                let ctx = Path::new(arg(&c.1, "-c").unwrap());
                ctx.parent().unwrap().to_string_lossy().into_owned()
            })
            .collect();
        calls
            .iter()
            .map(|c| {
                let mut line = std::iter::once(c.0.as_str())
                    .chain(c.1.iter().map(String::as_str))
                    .collect::<Vec<_>>()
                    .join(" ");
                for d in &dirs {
                    line = line.replace(d.as_str(), "W");
                }
                if let Some(p) = pin {
                    line = line.replace(&p.display().to_string(), "PIN");
                }
                line
            })
            .collect()
    }

    const COUNTER_SEAL: &[&str] = &[
        "tpm2_nvreadpublic 0x01800a11",
        "tpm2_nvdefine -C o -s 8 -a nt=counter|ownerread|ownerwrite 0x01800a11",
        "tpm2_nvincrement -C o 0x01800a11",
        "tpm2_nvread -C o -s 8 0x01800a11",
        "tpm2_createprimary -C o -g sha256 -G ecc -c W/primary.ctx",
    ];

    #[test]
    fn unseal_without_policy_uses_a_salted_encrypting_hmac_session() {
        let dir = tempfile::tempdir().unwrap();
        let tpm = Arc::new(Mutex::new(Tpm::default()));
        let s = sealer(counter_only(), &tpm, dir.path());
        let blob = s.seal(&[5u8; 32]).unwrap();
        let from = s.runner.calls().len();
        assert_eq!(*s.unseal(&blob).unwrap(), [5u8; 32]);
        assert_eq!(
            script(&s.runner, from, None),
            [
                "tpm2_createprimary -C o -g sha256 -G ecc -c W/primary.ctx",
                "tpm2_load -C W/primary.ctx -u W/key.pub -r W/key.priv -c W/key.ctx",
                "tpm2_startauthsession --hmac-session -S W/hmac.ctx -c W/primary.ctx",
                "tpm2_sessionconfig W/hmac.ctx --enable-encrypt --enable-decrypt",
                "tpm2_unseal -c W/key.ctx -p session:W/hmac.ctx",
                "tpm2_flushcontext W/hmac.ctx",
                "tpm2_nvread -C o -s 8 0x01800a11",
            ]
        );
    }

    #[test]
    fn seal_passes_the_key_over_a_decrypting_session() {
        let dir = tempfile::tempdir().unwrap();
        let tpm = Arc::new(Mutex::new(Tpm::default()));
        let s = sealer(counter_only(), &tpm, dir.path());
        s.seal(&[6u8; 32]).unwrap();
        let mut want = COUNTER_SEAL.to_vec();
        want.extend([
            "tpm2_startauthsession --hmac-session -S W/hmac.ctx -c W/primary.ctx",
            "tpm2_sessionconfig W/hmac.ctx --enable-encrypt --enable-decrypt",
            "tpm2_create -C W/primary.ctx -P session:W/hmac.ctx -g sha256 -u W/key.pub \
             -r W/key.priv -i -",
            "tpm2_flushcontext W/hmac.ctx",
        ]);
        assert_eq!(script(&s.runner, 0, None), want);
        // The key goes in on stdin of tpm2_create only.
        let calls = s.runner.calls();
        let with_stdin: Vec<_> = calls.iter().filter(|c| !c.2.is_empty()).collect();
        assert_eq!(with_stdin.len(), 1);
        assert_eq!(with_stdin[0].0, "tpm2_create");
        assert_eq!(&with_stdin[0].2[..32], &[6u8; 32]);

        // With a PIN and PCRs: the trial session stays unsalted.
        let pin = dir.path().join("pin");
        fs::write(&pin, b"246810").unwrap();
        let cfg = TpmConfig {
            pin_file: Some(pin.clone()),
            nv_index: DEFAULT_NV_INDEX,
            pcrs: Some("7".into()),
        };
        let s = sealer(cfg, &tpm, &dir.path().join("w"));
        s.seal(&[7u8; 32]).unwrap();
        assert_eq!(
            script(&s.runner, 0, Some(&pin)),
            [
                "tpm2_nvreadpublic 0x01800a11",
                "tpm2_nvincrement -C o 0x01800a11",
                "tpm2_nvread -C o -s 8 0x01800a11",
                "tpm2_createprimary -C o -g sha256 -G ecc -c W/primary.ctx",
                "tpm2_startauthsession --hmac-session -S W/hmac.ctx -c W/primary.ctx",
                "tpm2_sessionconfig W/hmac.ctx --enable-encrypt --enable-decrypt",
                "tpm2_startauthsession -S W/session.ctx",
                "tpm2_policypcr -S W/session.ctx -l sha256:7",
                "tpm2_policyauthvalue -S W/session.ctx -L W/policy.digest",
                "tpm2_flushcontext W/session.ctx",
                "tpm2_create -C W/primary.ctx -P session:W/hmac.ctx -g sha256 -u W/key.pub \
                 -r W/key.priv -i - -L W/policy.digest -a fixedtpm|fixedparent -p file:PIN",
                "tpm2_flushcontext W/hmac.ctx",
            ]
        );
    }

    #[test]
    fn pin_unseal_runs_its_policy_on_a_salted_session() {
        let dir = tempfile::tempdir().unwrap();
        let pin = dir.path().join("pin");
        fs::write(&pin, b"135790").unwrap();
        let tpm = Arc::new(Mutex::new(Tpm::default()));
        let cfg = TpmConfig {
            pin_file: Some(pin.clone()),
            nv_index: DEFAULT_NV_INDEX,
            pcrs: Some("7,11".into()),
        };
        let s = sealer(cfg, &tpm, &dir.path().join("w"));
        let blob = s.seal(&[8u8; 32]).unwrap();
        let from = s.runner.calls().len();
        assert_eq!(*s.unseal(&blob).unwrap(), [8u8; 32]);
        assert_eq!(
            script(&s.runner, from, Some(&pin)),
            [
                "tpm2_createprimary -C o -g sha256 -G ecc -c W/primary.ctx",
                "tpm2_load -C W/primary.ctx -u W/key.pub -r W/key.priv -c W/key.ctx",
                "tpm2_startauthsession --policy-session -S W/session.ctx -c W/primary.ctx",
                "tpm2_sessionconfig W/session.ctx --enable-encrypt --enable-decrypt",
                "tpm2_policypcr -S W/session.ctx -l sha256:7,11",
                "tpm2_policyauthvalue -S W/session.ctx",
                "tpm2_unseal -c W/key.ctx -p session:W/session.ctx+file:PIN",
                "tpm2_flushcontext W/session.ctx",
                "tpm2_nvread -C o -s 8 0x01800a11",
            ]
        );
        assert!(s
            .runner
            .calls()
            .iter()
            .all(|c| c.1.iter().all(|a| !a.contains("135790"))));
    }

    /// (tpm2_startauthsession calls, tpm2_flushcontext calls)
    fn starts_and_flushes(r: &FakeRunner) -> (usize, usize) {
        let tools = r.tools();
        let n = |t: &str| tools.iter().filter(|x| *x == t).count();
        (n("tpm2_startauthsession"), n("tpm2_flushcontext"))
    }

    #[test]
    fn every_session_is_flushed_even_when_unseal_fails() {
        let dir = tempfile::tempdir().unwrap();
        let pin = dir.path().join("pin");
        fs::write(&pin, b"1234").unwrap();
        let with_pin = TpmConfig {
            pin_file: Some(pin),
            nv_index: DEFAULT_NV_INDEX,
            pcrs: None,
        };
        let session_steps = ["tpm2_unseal", "tpm2_sessionconfig"];
        let policy_steps = ["tpm2_unseal", "tpm2_sessionconfig", "tpm2_policyauthvalue"];
        for (cfg, tools) in [
            (counter_only(), &session_steps[..]),
            (with_pin, &policy_steps),
        ] {
            let tpm = Arc::new(Mutex::new(Tpm::default()));
            let blob = sealer(cfg.clone(), &tpm, dir.path())
                .seal(&[9u8; 32])
                .unwrap();
            for &tool in tools {
                let s = TpmSealer {
                    cfg: cfg.clone(),
                    runner: fake_failing(Arc::clone(&tpm), tool, false),
                    work: dir.path().to_path_buf(),
                };
                let e = s.unseal(&blob).unwrap_err();
                assert_eq!(e, "master-key unseal failed", "{tool}");
                let (starts, flushes) = starts_and_flushes(&s.runner);
                assert_eq!(starts, 1, "{tool}");
                assert_eq!(flushes, starts, "{tool}");
            }
        }
        // Seal too: a failing create still flushes the HMAC session.
        let tpm = Arc::new(Mutex::new(Tpm::default()));
        let s = TpmSealer {
            cfg: counter_only(),
            runner: fake_failing(tpm, "tpm2_create", false),
            work: dir.path().to_path_buf(),
        };
        assert_eq!(s.seal(&[1u8; 32]).unwrap_err(), "master-key seal failed");
        assert_eq!(starts_and_flushes(&s.runner), (1, 1));
        assert_eq!(
            fs::read_dir(dir.path()).unwrap().count(),
            1,
            "only the PIN file"
        );
    }

    #[test]
    fn old_tools_without_sessionconfig_get_a_clear_error() {
        let dir = tempfile::tempdir().unwrap();
        let tpm = Arc::new(Mutex::new(Tpm::default()));
        let blob = sealer(counter_only(), &tpm, dir.path())
            .seal(&[2u8; 32])
            .unwrap();
        let old = TpmSealer {
            cfg: counter_only(),
            runner: fake_failing(Arc::clone(&tpm), "tpm2_sessionconfig", true),
            work: dir.path().to_path_buf(),
        };
        let want = "TPM2 sealing needs the tpm2-tools package installed (tpm2-tools 5.0 or newer)";
        assert_eq!(old.seal(&[3u8; 32]).unwrap_err(), want);
        assert_eq!(old.unseal(&blob).unwrap_err(), want);
        assert_eq!(starts_and_flushes(&old.runner), (2, 2));
        assert!(!old.runner.tools().iter().any(|t| t == "tpm2_create"));
    }
}
