// daemon_seal/runner.rs — how the master-key sealers run their helper
// tools (tpm2-tools, pkcs11-tool, `security`). Behind a trait so tests
// script the tools instead of needing a TPM, an HSM or macOS.
//
// Secrets never go in argv: data and PINs travel on stdin, in a file the
// administrator provides, or in the child's own environment. The tools'
// stderr is dropped: it never reaches a log or an error message.

use std::io::Write;
use std::process::{Command, Stdio};

use zeroize::Zeroizing;

/// One tool invocation.
pub struct Cmd<'a> {
    pub tool: &'a str,
    pub args: Vec<String>,
    pub stdin: &'a [u8],
    /// Extra environment for this child only.
    pub env: Vec<(&'static str, &'a str)>,
}

impl<'a> Cmd<'a> {
    pub fn new(tool: &'a str, args: &[&str]) -> Self {
        Self {
            tool,
            args: args.iter().map(|a| a.to_string()).collect(),
            stdin: b"",
            env: Vec::new(),
        }
    }

    pub fn stdin(mut self, data: &'a [u8]) -> Self {
        self.stdin = data;
        self
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum RunError {
    /// The tool isn't installed.
    Missing,
    /// It ran and failed (non-zero exit, I/O error).
    Failed,
}

pub trait Runner: Send + Sync {
    /// stdout of a successful run.
    fn run(&self, cmd: &Cmd) -> Result<Zeroizing<Vec<u8>>, RunError>;
}

pub struct SystemRunner;

impl Runner for SystemRunner {
    fn run(&self, cmd: &Cmd) -> Result<Zeroizing<Vec<u8>>, RunError> {
        let mut c = Command::new(cmd.tool);
        c.args(&cmd.args)
            .stdin(if cmd.stdin.is_empty() {
                Stdio::null()
            } else {
                Stdio::piped()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        for (k, v) in &cmd.env {
            c.env(k, v);
        }
        let mut child = c.spawn().map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => RunError::Missing,
            _ => RunError::Failed,
        })?;
        if let Some(mut i) = child.stdin.take() {
            // Inputs are small (a key, a ciphertext): they fit the pipe.
            i.write_all(cmd.stdin).map_err(|_| RunError::Failed)?;
        }
        let out = child.wait_with_output().map_err(|_| RunError::Failed)?;
        let stdout = Zeroizing::new(out.stdout);
        if !out.status.success() {
            return Err(RunError::Failed);
        }
        Ok(stdout)
    }
}

#[cfg(test)]
pub mod fake {
    use super::*;
    use std::sync::Mutex;

    /// A recorded call: tool, argv, stdin, environment.
    pub type Call = (String, Vec<String>, Vec<u8>, Vec<(String, String)>);
    type Script = Box<dyn Fn(&Cmd) -> Result<Vec<u8>, RunError> + Send + Sync>;

    /// Records every call and answers with `script`.
    pub struct FakeRunner {
        pub calls: Mutex<Vec<Call>>,
        script: Script,
    }

    impl FakeRunner {
        pub fn new(
            script: impl Fn(&Cmd) -> Result<Vec<u8>, RunError> + Send + Sync + 'static,
        ) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                script: Box::new(script),
            }
        }

        pub fn calls(&self) -> Vec<Call> {
            self.calls.lock().unwrap().clone()
        }

        /// The tools called, in order.
        pub fn tools(&self) -> Vec<String> {
            self.calls().into_iter().map(|c| c.0).collect()
        }
    }

    impl Runner for FakeRunner {
        fn run(&self, cmd: &Cmd) -> Result<Zeroizing<Vec<u8>>, RunError> {
            self.calls.lock().unwrap().push((
                cmd.tool.to_string(),
                cmd.args.clone(),
                cmd.stdin.to_vec(),
                cmd.env
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            ));
            (self.script)(cmd).map(Zeroizing::new)
        }
    }

    /// The value after `flag` in `args`.
    pub fn arg<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
        let i = args.iter().position(|a| a == flag)?;
        args.get(i + 1).map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_runner_feeds_stdin_and_reports_missing_tools() {
        let out = SystemRunner
            .run(&Cmd::new("cat", &[]).stdin(b"data"))
            .unwrap();
        assert_eq!(&out[..], b"data");
        let mut env = Cmd::new("sh", &["-c", "printf %s \"$KEPR_TEST_ENV\""]);
        env.env.push(("KEPR_TEST_ENV", "only-here"));
        assert_eq!(&SystemRunner.run(&env).unwrap()[..], b"only-here");
        assert_eq!(
            SystemRunner
                .run(&Cmd::new("kepr-no-such-tool", &[]))
                .unwrap_err(),
            RunError::Missing
        );
        assert_eq!(
            SystemRunner.run(&Cmd::new("false", &[])).unwrap_err(),
            RunError::Failed
        );
    }
}
