//! Capture bounded engine output without waiting indefinitely on inherited pipes.
use std::io::{ErrorKind, Read};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub struct Captured {
    pub stdout: Zeroizing<Vec<u8>>,
    pub stderr: Zeroizing<Vec<u8>>,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub output_limited: bool,
    pub incomplete: bool,
}

fn nonblocking(fd: i32) -> Result<(), String> {
    // SAFETY: the caller owns this open pipe; fcntl changes only its flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err("scanner output setup failed".into());
    }
    // SAFETY: the same owned pipe descriptor remains open here.
    let changed = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if changed < 0 {
        return Err("scanner output setup failed".into());
    }
    Ok(())
}

fn drain(
    reader: &mut impl Read,
    out: &mut Vec<u8>,
    remaining: usize,
) -> Result<(bool, bool), String> {
    let mut buffer = Zeroizing::new([0u8; 4096]);
    loop {
        match reader.read(&mut buffer[..]) {
            Ok(0) => return Ok((true, false)),
            Ok(n) => {
                let take = n.min(remaining.saturating_sub(out.len()));
                out.extend_from_slice(&buffer[..take]);
                if take < n {
                    return Ok((false, true));
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok((false, false)),
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => return Err("scanner output read failed".into()),
        }
    }
}

pub fn run(command: &mut Command, timeout: Duration, limit: usize) -> Result<Captured, String> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: setpgid is async-signal-safe and only groups this child for cleanup.
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().map_err(|_| "scanner could not start")?;
    let id = child.id() as i32;
    let mut stdout = child.stdout.take().ok_or("scanner output unavailable")?;
    let mut stderr = child.stderr.take().ok_or("scanner output unavailable")?;
    let setup = nonblocking(stdout.as_raw_fd()).and_then(|_| nonblocking(stderr.as_raw_fd()));
    if let Err(error) = setup {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    let mut out = Captured {
        stdout: Zeroizing::new(Vec::new()),
        stderr: Zeroizing::new(Vec::new()),
        exit_code: None,
        timed_out: false,
        output_limited: false,
        incomplete: false,
    };
    let start = Instant::now();
    let mut finished = None;
    loop {
        let a = drain(
            &mut stdout,
            &mut out.stdout,
            limit.saturating_sub(out.stderr.len()),
        );
        let b = drain(
            &mut stderr,
            &mut out.stderr,
            limit.saturating_sub(out.stdout.len()),
        );
        let (a, b) = match (a, b) {
            (Ok(a), Ok(b)) => (a, b),
            _ => {
                out.incomplete = true;
                break;
            }
        };
        if a.1 || b.1 {
            out.output_limited = true;
            break;
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                out.exit_code = status.code();
                finished.get_or_insert_with(Instant::now);
                if a.0 && b.0 {
                    return Ok(out);
                }
            }
            Ok(None) => {}
            Err(_) => {
                out.incomplete = true;
                break;
            }
        }
        if finished.is_some_and(|at: Instant| at.elapsed() >= Duration::from_millis(100)) {
            out.incomplete = true;
            break;
        }
        if start.elapsed() >= timeout {
            out.timed_out = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    // SAFETY: this child created the process group; cleanup also ends pipe-holding
    // descendants while that group is alive. No host service is addressed.
    unsafe {
        libc::kill(-id, libc::SIGKILL);
    }
    let _ = child.kill();
    let _ = child.wait();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn python(script: &str) -> Command {
        let mut command = Command::new("/usr/bin/python3");
        command.args(["-c", script]);
        command
    }
    #[test]
    fn captures_error_codes_and_enforces_output_and_time_bounds() {
        let mut command = python("import sys; print('fixture'); sys.exit(2)");
        let out = run(&mut command, Duration::from_secs(2), 1024).unwrap();
        assert_eq!(out.exit_code, Some(2));
        let mut command = python("print('x' * 10000)");
        let out = run(&mut command, Duration::from_secs(2), 100).unwrap();
        assert!(out.output_limited);
        assert!(out.stdout.len() + out.stderr.len() <= 100);
        let mut command = python("import time; time.sleep(5)");
        let start = std::time::Instant::now();
        let out = run(&mut command, Duration::from_millis(100), 1024).unwrap();
        assert!(out.timed_out);
        assert!(start.elapsed() < Duration::from_secs(2));
    }
    #[test]
    fn a_descendant_holding_output_open_does_not_hang_capture() {
        let mut command = python("import os,time; p=os.fork(); time.sleep(5) if p == 0 else None");
        let start = std::time::Instant::now();
        let out = run(&mut command, Duration::from_secs(2), 1024).unwrap();
        assert!(out.incomplete);
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}
