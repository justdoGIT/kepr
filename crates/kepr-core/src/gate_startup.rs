//! Bounded daemon/service startup IO. No detached reader threads and no raw
//! subprocess output in errors: startup diagnostics cannot disclose a key.

use std::io;
use std::os::fd::AsRawFd;
use std::time::Instant;

use crate::gate_protocol::ReadyLine;

pub const MAX_READY_LINE: usize = 64 * 1024;

fn nonblocking(fd: i32) -> Result<(), String> {
    // SAFETY: callers own this pipe throughout the operation.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err("kepr-gate startup pipe setup failed".into());
    }
    Ok(())
}

fn wait(fd: i32, events: i16, deadline: Instant) -> io::Result<()> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let mut descriptor = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let timeout = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
        // SAFETY: descriptor points at one initialized pollfd.
        let result = unsafe { libc::poll(&mut descriptor, 1, timeout) };
        if result > 0 {
            if descriptor.revents & libc::POLLNVAL != 0 {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            // A closed read pipe must be drained/read to observe EOF, not
            // misclassified as a readiness IO error (POLLHUP without POLLIN).
            if descriptor.revents & events != 0
                || (events == libc::POLLIN && descriptor.revents & libc::POLLHUP != 0)
            {
                return Ok(());
            }
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        if result == 0 {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

pub fn write_config<W: AsRawFd>(writer: W, bytes: &[u8], deadline: Instant) -> Result<(), String> {
    let fd = writer.as_raw_fd();
    nonblocking(fd)?;
    let mut offset = 0;
    while offset < bytes.len() {
        wait(fd, libc::POLLOUT, deadline).map_err(|error| {
            if error.kind() == io::ErrorKind::TimedOut {
                "kepr-gate config write timed out"
            } else {
                "kepr-gate exited before accepting its configuration"
            }
            .to_string()
        })?;
        // SAFETY: bytes remain valid, and writer owns fd throughout.
        let count =
            unsafe { libc::write(fd, bytes[offset..].as_ptr().cast(), bytes.len() - offset) };
        if count > 0 {
            offset += count as usize;
            continue;
        }
        if count < 0
            && matches!(
                io::Error::last_os_error().kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            )
        {
            continue;
        }
        return Err("kepr-gate config write failed".into());
    }
    // Closing stdin is part of the protocol: the child reads config to EOF.
    drop(writer);
    Ok(())
}

/// Only these fixed diagnostics may cross a service or subprocess boundary.
pub fn failure_reason(error: &str) -> &'static str {
    match error {
        "gate port bind failed" => "gate port bind failed",
        "database port bind failed" => "database port bind failed",
        "kepr-gate exited before reporting readiness" => {
            "kepr-gate exited before reporting readiness"
        }
        "kepr-gate ready line exceeded the size limit" => {
            "kepr-gate ready line exceeded the size limit"
        }
        "kepr-gate sent a malformed ready line" => "kepr-gate sent a malformed ready line",
        "kepr-gate readiness timed out" => "kepr-gate readiness timed out",
        "kepr-gate config write timed out" => "kepr-gate config write timed out",
        "kepr-gate exited before accepting its configuration" => {
            "kepr-gate exited before accepting its configuration"
        }
        _ => "gate startup failed",
    }
}

pub fn parse_ready(line: &[u8]) -> Result<ReadyLine, String> {
    if line.is_empty() {
        return Err("kepr-gate exited before reporting readiness".into());
    }
    if line.len() > MAX_READY_LINE {
        return Err("kepr-gate ready line exceeded the size limit".into());
    }
    let ready: ReadyLine =
        serde_json::from_slice(line).map_err(|_| "kepr-gate sent a malformed ready line")?;
    if !ready.ready {
        return Err(failure_reason(ready.error.as_deref().unwrap_or_default()).into());
    }
    if ready.port == 0 {
        return Err("kepr-gate reported an invalid listening port".into());
    }
    Ok(ready)
}

pub fn read_ready<R: AsRawFd>(reader: R, deadline: Instant) -> Result<ReadyLine, String> {
    let fd = reader.as_raw_fd();
    nonblocking(fd)?;
    let mut line = Vec::with_capacity(4096);
    let mut buffer = [0u8; 4096];
    loop {
        wait(fd, libc::POLLIN, deadline).map_err(|error| {
            if error.kind() == io::ErrorKind::TimedOut {
                "kepr-gate readiness timed out"
            } else {
                "kepr-gate readiness read failed"
            }
            .to_string()
        })?;
        // SAFETY: buffer is writable and reader owns fd throughout.
        let count = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
        if count == 0 {
            return parse_ready(&line);
        }
        if count < 0 {
            if matches!(
                io::Error::last_os_error().kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err("kepr-gate readiness read failed".into());
        }
        let chunk = &buffer[..count as usize];
        let newline = chunk.iter().position(|b| *b == b'\n');
        let used = newline.map_or(chunk.len(), |index| index + 1);
        if line.len() + used > MAX_READY_LINE {
            return Err("kepr-gate ready line exceeded the size limit".into());
        }
        line.extend_from_slice(&chunk[..used]);
        if newline.is_some() {
            return parse_ready(&line);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    #[test]
    fn protocol_failures_are_distinct_and_do_not_echo_output() {
        assert!(parse_ready(b"").unwrap_err().contains("exited before"));
        assert!(parse_ready(&vec![b'x'; MAX_READY_LINE + 1])
            .unwrap_err()
            .contains("size limit"));
        let error = parse_ready(b"synthetic-private-output").unwrap_err();
        assert!(error.contains("malformed"));
        assert!(!error.contains("synthetic-private-output"));
        assert!(parse_ready(br#"{"ready":true,"port":0,"placeholders":{}}"#)
            .unwrap_err()
            .contains("invalid listening port"));
        assert_eq!(
            parse_ready(
                br#"{"ready":false,"port":0,"placeholders":{},"error":"gate port bind failed"}"#
            )
            .unwrap_err(),
            "gate port bind failed"
        );
        assert_eq!(
            parse_ready(br#"{"ready":true,"port":7878,"placeholders":{}}"#)
                .unwrap()
                .port,
            7878
        );
    }

    #[test]
    fn exited_child_is_eof_even_when_poll_only_reports_hangup() {
        let mut child = Command::new("sh")
            .args(["-c", "exit 70"])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child.wait().unwrap();
        let error = read_ready(
            child.stdout.take().unwrap(),
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(error.contains("exited before reporting readiness"));
    }

    #[test]
    fn silent_child_times_out_without_a_reader_thread_or_orphan() {
        let mut child = Command::new("sleep")
            .arg("30")
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let error = read_ready(
            child.stdout.take().unwrap(),
            Instant::now() + Duration::from_millis(40),
        )
        .unwrap_err();
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(error.contains("timed out"));
    }

    #[test]
    fn child_that_never_reads_configuration_cannot_block_the_daemon() {
        let mut child = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        let error = write_config(
            child.stdin.take().unwrap(),
            &vec![b'x'; 1024 * 1024],
            Instant::now() + Duration::from_millis(40),
        )
        .unwrap_err();
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(error.contains("config write timed out"));
    }
}
