// daemon_seal/tpm_session.rs — salted, encrypted TPM2 sessions for the
// PIN / counter sealer (T12.29).
//
// A session started with `-c PRIMARY` is salted with and bound to the
// primary key: its session key comes from a secret only the TPM and this
// process know, never sent in the clear. With parameter encryption on
// (`tpm2_sessionconfig --enable-encrypt --enable-decrypt`), the first
// parameter of each command (the key going in to `tpm2_create`) and of
// each response (the key coming out of `tpm2_unseal`) crosses the TPM bus
// encrypted, so sniffing a discrete TPM's LPC / SPI bus yields
// ciphertext. The session is flushed when dropped, on every path.
//
// A trial session only computes a policy digest and carries no secret,
// so it stays unsalted.

use super::runner::{Cmd, RunError, Runner};

pub(super) struct Session<'a, R: Runner> {
    runner: &'a R,
    path: String,
}

impl<'a, R: Runner> Session<'a, R> {
    /// tpm2_startauthsession (--policy-session | --hmac-session) -S PATH
    /// -c PRIMARY (salted with and bound to the primary), then
    /// tpm2_sessionconfig PATH --enable-encrypt --enable-decrypt
    pub fn salted(
        runner: &'a R,
        path: String,
        primary: &str,
        policy: bool,
    ) -> Result<Self, RunError> {
        let kind = if policy {
            "--policy-session"
        } else {
            "--hmac-session"
        };
        runner.run(&Cmd::new(
            "tpm2_startauthsession",
            &[kind, "-S", &path, "-c", primary],
        ))?;
        // From here on the session exists: dropping `s` flushes it.
        let s = Self { runner, path };
        let config = [s.path.as_str(), "--enable-encrypt", "--enable-decrypt"];
        runner.run(&Cmd::new("tpm2_sessionconfig", &config))?;
        Ok(s)
    }

    /// tpm2_startauthsession -S PATH: a trial session, for computing a
    /// policy digest at seal time.
    pub fn trial(runner: &'a R, path: String) -> Result<Self, RunError> {
        runner.run(&Cmd::new("tpm2_startauthsession", &["-S", &path]))?;
        Ok(Self { runner, path })
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    /// session:PATH, for -p / -P
    pub fn auth(&self) -> String {
        format!("session:{}", self.path)
    }
}

impl<R: Runner> Drop for Session<'_, R> {
    fn drop(&mut self) {
        let _ = self
            .runner
            .run(&Cmd::new("tpm2_flushcontext", &[&self.path]));
    }
}
