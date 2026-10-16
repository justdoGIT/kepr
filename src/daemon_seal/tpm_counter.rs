// daemon_seal/tpm_counter.rs — TPM2 NV counters through tpm2-tools: the
// master key's anti-rollback counter (T4.08, tpm.rs) and the vault
// image's own (T12.30, KEPR_TPM2_IMAGE_NV_INDEX), which backs the image
// header's anchor (daemon_vault/rollback.rs).
//
// A counter is defined owner-readable and owner-writable (`nt=counter`)
// on its first increment. Its value is no secret, so it is read without
// a session; tampering with it on the bus only makes the daemon refuse
// the image or the key. A counter defined but never incremented (a crash
// between the two) reads as undefined, so the next increment completes it.

use super::runner::{Cmd, RunError, Runner};
use super::tpm::tool_err;
use crate::daemon_vault::rollback::EpochCounter;

pub(super) const COUNTER_FAILED: &str = "cannot use the TPM2 anti-rollback counter";
const COUNTER_MISSING: &str =
    "the TPM2 anti-rollback counter needs the tpm2-tools package installed";

fn hex(index: u32) -> String {
    format!("{index:#010x}")
}

/// The counter's public area, or None when it isn't defined.
fn public<R: Runner + ?Sized>(runner: &R, index: u32) -> Result<Option<Vec<u8>>, RunError> {
    match runner.run(&Cmd::new("tpm2_nvreadpublic", &[&hex(index)])) {
        Ok(out) => Ok(Some(out.to_vec())),
        Err(RunError::Missing) => Err(RunError::Missing),
        Err(RunError::Failed) => Ok(None),
    }
}

/// `tpm2_nvread -C o -s 8 IDX`: the value, big-endian.
pub(super) fn read_counter<R: Runner + ?Sized>(runner: &R, index: u32) -> Result<u64, RunError> {
    let out = runner.run(&Cmd::new(
        "tpm2_nvread",
        &["-C", "o", "-s", "8", &hex(index)],
    ))?;
    let b: [u8; 8] = out[..].try_into().map_err(|_| RunError::Failed)?;
    Ok(u64::from_be_bytes(b))
}

/// Define the counter on first use, increment it, return the value.
pub(super) fn bump_counter<R: Runner + ?Sized>(runner: &R, index: u32) -> Result<u64, RunError> {
    let i = hex(index);
    if public(runner, index)?.is_none() {
        let attrs = "nt=counter|ownerread|ownerwrite";
        runner.run(&Cmd::new(
            "tpm2_nvdefine",
            &["-C", "o", "-s", "8", "-a", attrs, &i],
        ))?;
    }
    runner.run(&Cmd::new("tpm2_nvincrement", &["-C", "o", &i]))?;
    read_counter(runner, index)
}

/// Has the counter been incremented since it was defined? (`written` in
/// tpm2_nvreadpublic's attribute list.)
fn written(public: &[u8]) -> bool {
    String::from_utf8_lossy(public)
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .any(|w| w == "written")
}

/// A TPM2 NV counter as the vault image's `EpochCounter`.
pub struct NvCounter<R: Runner> {
    pub index: u32,
    pub runner: R,
}

impl<R: Runner> NvCounter<R> {
    fn err(e: RunError) -> String {
        tool_err(e, COUNTER_MISSING, COUNTER_FAILED)
    }

    /// None while the counter is undefined (or defined, never incremented).
    pub fn read(&self) -> Result<Option<u64>, String> {
        let Some(public) = public(&self.runner, self.index).map_err(Self::err)? else {
            return Ok(None);
        };
        match read_counter(&self.runner, self.index) {
            Ok(v) => Ok(Some(v)),
            Err(RunError::Failed) if !written(&public) => Ok(None),
            Err(e) => Err(Self::err(e)),
        }
    }

    /// Defines the counter if needed, increments it, returns the value.
    pub fn increment(&self) -> Result<u64, String> {
        bump_counter(&self.runner, self.index).map_err(Self::err)
    }
}

impl<R: Runner> EpochCounter for NvCounter<R> {
    fn index(&self) -> u32 {
        self.index
    }
    fn read(&self) -> Result<Option<u64>, String> {
        NvCounter::read(self)
    }
    fn increment(&self) -> Result<u64, String> {
        NvCounter::increment(self)
    }
}

#[cfg(test)]
mod tests {
    use super::super::runner::fake::FakeRunner;
    use super::*;
    use std::sync::{Arc, Mutex};

    const IMAGE_INDEX: u32 = 0x0180_0A12;

    /// One NV counter: None = undefined; Some((value, written)).
    type Nv = Arc<Mutex<Option<(u64, bool)>>>;

    /// tpm2_nvreadpublic prints the attributes as tpm2-tools 5 does.
    fn fake(nv: &Nv) -> FakeRunner {
        let nv = Arc::clone(nv);
        FakeRunner::new(move |c| {
            let mut n = nv.lock().unwrap();
            match c.tool {
                "tpm2_nvreadpublic" => {
                    let (_, w) = n.ok_or(RunError::Failed)?;
                    let attrs = if w {
                        "ownerwrite|nt=0x1|ownerread|written"
                    } else {
                        "ownerwrite|nt=0x1|ownerread"
                    };
                    Ok(format!("0x1800a12:\n  attributes:\n    friendly: {attrs}\n").into_bytes())
                }
                "tpm2_nvdefine" => {
                    *n = Some((0, false));
                    Ok(Vec::new())
                }
                "tpm2_nvincrement" => {
                    let (v, w) = n.as_mut().ok_or(RunError::Failed)?;
                    // A real counter starts at the highest value any
                    // counter of this TPM has had.
                    *v = if *w { *v + 1 } else { 41 };
                    *w = true;
                    Ok(Vec::new())
                }
                "tpm2_nvread" => match *n {
                    Some((v, true)) => Ok(v.to_be_bytes().to_vec()),
                    _ => Err(RunError::Failed),
                },
                _ => Err(RunError::Failed),
            }
        })
    }

    fn counter(nv: &Nv) -> NvCounter<FakeRunner> {
        NvCounter {
            index: IMAGE_INDEX,
            runner: fake(nv),
        }
    }

    fn argv(r: &FakeRunner) -> Vec<String> {
        r.calls()
            .into_iter()
            .map(|(tool, args, stdin, env)| {
                assert!(stdin.is_empty() && env.is_empty(), "{tool}");
                format!("{tool} {}", args.join(" "))
            })
            .collect()
    }

    #[test]
    fn read_of_an_undefined_counter_is_none() {
        let nv = Nv::default();
        let c = counter(&nv);
        assert_eq!(c.read(), Ok(None));
        assert_eq!(argv(&c.runner), ["tpm2_nvreadpublic 0x01800a12"]);
    }

    #[test]
    fn first_increment_defines_then_increments() {
        let nv = Nv::default();
        let c = counter(&nv);
        assert_eq!(c.increment(), Ok(41));
        assert_eq!(
            argv(&c.runner),
            [
                "tpm2_nvreadpublic 0x01800a12",
                "tpm2_nvdefine -C o -s 8 -a nt=counter|ownerread|ownerwrite 0x01800a12",
                "tpm2_nvincrement -C o 0x01800a12",
                "tpm2_nvread -C o -s 8 0x01800a12",
            ]
        );
        // Defined now: no second definition.
        let c = counter(&nv);
        assert_eq!(c.increment(), Ok(42));
        assert_eq!(
            argv(&c.runner),
            [
                "tpm2_nvreadpublic 0x01800a12",
                "tpm2_nvincrement -C o 0x01800a12",
                "tpm2_nvread -C o -s 8 0x01800a12",
            ]
        );
        let c = counter(&nv);
        assert_eq!(c.read(), Ok(Some(42)));
        assert_eq!(
            argv(&c.runner),
            [
                "tpm2_nvreadpublic 0x01800a12",
                "tpm2_nvread -C o -s 8 0x01800a12"
            ]
        );
    }

    #[test]
    fn read_parses_eight_big_endian_bytes() {
        let reply = |out: Vec<u8>| {
            NvCounter {
                index: IMAGE_INDEX,
                runner: FakeRunner::new(move |c| match c.tool {
                    "tpm2_nvreadpublic" => Ok(b"friendly: ownerread|written".to_vec()),
                    _ => Ok(out.clone()),
                }),
            }
            .read()
        };
        assert_eq!(reply(vec![0, 0, 0, 0, 0, 0, 1, 2]), Ok(Some(258)));
        assert_eq!(reply(u64::MAX.to_be_bytes().to_vec()), Ok(Some(u64::MAX)));
        for bad in [vec![1; 7], vec![1; 9], Vec::new()] {
            assert_eq!(reply(bad), Err(COUNTER_FAILED.to_string()));
        }
        assert_eq!(
            read_counter(&FakeRunner::new(|_| Ok(vec![0, 0, 0, 0, 0, 0, 0, 9])), 1),
            Ok(9)
        );
    }

    #[test]
    fn a_counter_defined_but_never_incremented_reads_as_none() {
        // A crash between tpm2_nvdefine and tpm2_nvincrement.
        let nv: Nv = Arc::new(Mutex::new(Some((0, false))));
        assert_eq!(counter(&nv).read(), Ok(None));
        let c = counter(&nv);
        assert_eq!(c.increment(), Ok(41));
        assert!(!argv(&c.runner)
            .iter()
            .any(|a| a.starts_with("tpm2_nvdefine")));
        // A written counter that can't be read is an error, not "undefined".
        let broken = NvCounter {
            index: IMAGE_INDEX,
            runner: FakeRunner::new(|c| match c.tool {
                "tpm2_nvreadpublic" => Ok(b"friendly: ownerwrite|written".to_vec()),
                _ => Err(RunError::Failed),
            }),
        };
        assert_eq!(broken.read(), Err(COUNTER_FAILED.to_string()));
        assert!(written(
            b"  friendly: ownerwrite|nt=0x1|ownerread|written\n"
        ));
        assert!(!written(b"  friendly: ownerwrite|writelocked|writeall\n"));
    }

    #[test]
    fn missing_tools_name_the_package() {
        let c = NvCounter {
            index: IMAGE_INDEX,
            runner: FakeRunner::new(|_| Err(RunError::Missing)),
        };
        for e in [c.read().unwrap_err(), c.increment().unwrap_err()] {
            assert!(e.contains("tpm2-tools package"), "{e}");
        }
        // Only tpm2_nvread missing (a broken install).
        let c = NvCounter {
            index: IMAGE_INDEX,
            runner: FakeRunner::new(|c| match c.tool {
                "tpm2_nvread" => Err(RunError::Missing),
                _ => Ok(Vec::new()),
            }),
        };
        assert!(c.read().unwrap_err().contains("tpm2-tools package"));
    }

    #[test]
    fn it_is_the_vault_images_epoch_counter() {
        let nv = Nv::default();
        let c: Arc<dyn EpochCounter> = Arc::new(counter(&nv));
        assert_eq!(c.index(), IMAGE_INDEX);
        assert_eq!(c.read(), Ok(None));
        assert_eq!(c.increment(), Ok(41));
        assert_eq!(c.read(), Ok(Some(41)));
    }
}
