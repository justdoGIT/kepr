// cli_sandbox_relay.rs — the `--isolate-net` connection relay of the agent
// sandbox (split out of cli_agent_sandbox.rs). Inside the sandbox's network
// namespace an acceptor listens on each session port (the gate's, plus
// database and tunnel ports, T7.03) and passes every connection out over
// a Unix socket (SCM_RIGHTS); outside, the relay connects it to the same
// port on the host's loopback. Only the session's ports are relayed.

use std::net::{TcpListener, TcpStream};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixStream;

use crate::cli_sandbox_sys as sys;

pub fn acceptor(listener: TcpListener, relay: UnixStream) -> ! {
    // SAFETY: prctl with a signal number; die with our parent (pid 1).
    unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) };
    for conn in listener.incoming().flatten() {
        if sys::send_fd(&relay, conn.as_raw_fd()).is_err() {
            break;
        }
    }
    // SAFETY: _exit after fork.
    unsafe { libc::_exit(0) }
}

pub fn relay_loop(relay: UnixStream, ports: Vec<u16>) {
    while let Ok(Some(fd)) = sys::recv_fd(&relay) {
        // SAFETY: recv_fd handed us ownership of a connected TCP socket.
        let inner = unsafe { TcpStream::from_raw_fd(fd) };
        // The sandbox listens on the same port numbers as the host side.
        let Some(port) = inner.local_addr().ok().map(|a| a.port()) else {
            continue;
        };
        if !ports.contains(&port) {
            continue;
        }
        std::thread::spawn(move || {
            let Ok(mut outer) = TcpStream::connect(("127.0.0.1", port)) else {
                return;
            };
            let (Ok(mut from_sandbox), Ok(mut from_gate)) = (inner.try_clone(), outer.try_clone())
            else {
                return;
            };
            let up = std::thread::spawn(move || {
                let _ = std::io::copy(&mut from_sandbox, &mut outer);
                let _ = outer.shutdown(std::net::Shutdown::Write);
            });
            let mut inner = inner;
            let _ = std::io::copy(&mut from_gate, &mut inner);
            let _ = inner.shutdown(std::net::Shutdown::Write);
            let _ = up.join();
        });
    }
}
