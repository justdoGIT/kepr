//! Dialog startup retries only transient executable-write contention.
use std::io::Write;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

pub(super) fn spawn(program: &Path, args: &[&str], stdin: Option<&str>) -> Result<Child, String> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut busy = 0;
    let mut child = loop {
        match cmd.spawn() {
            Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) && busy < 20 => {
                busy += 1;
                std::thread::sleep(Duration::from_millis(10));
            }
            result => break result.map_err(|e| format!("{}: {e}", program.display()))?,
        }
    };
    if let (Some(text), Some(mut pipe)) = (stdin, child.stdin.take()) {
        let _ = pipe.write_all(text.as_bytes());
    }
    Ok(child)
}
