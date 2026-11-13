#!/usr/bin/env python3
"""Restart only the Linux user daemon answering the selected Kepr socket."""

import argparse
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import struct
import subprocess
import sys
import time


def paths():
    runtime = Path(os.environ.get("XDG_RUNTIME_DIR", ""))
    if not runtime.is_absolute():
        runtime = Path(f"/run/user/{os.getuid()}")
    state = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state"))
    runtime, state = runtime / "kepr", state / "kepr"
    profile = os.environ.get("KEPR_PROFILE", "default")
    if profile not in ("", "default"):
        if re.fullmatch(r"[a-z0-9_-]{1,32}", profile) is None:
            raise RuntimeError("invalid Kepr profile; refusing to restart a daemon")
        runtime, state = runtime / "profiles" / profile, state / "profiles" / profile
    return runtime / "kepr.sock", state


def read_exact(stream, size):
    data = bytearray()
    while len(data) < size:
        chunk = stream.recv(size - len(data))
        if not chunk:
            raise RuntimeError("selected daemon closed its ping response")
        data.extend(chunk)
    return data


def peer_pid(path):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(1)
        try:
            stream.connect(str(path))
        except (FileNotFoundError, ConnectionRefusedError):
            return None
        pid, uid, _ = struct.unpack(
            "3i", stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )
        if uid != os.getuid() or pid <= 1:
            raise RuntimeError("selected daemon has an unexpected owner; refusing to signal it")
        ping = b'{"cmd":"ping"}'
        stream.sendall(struct.pack("!I", len(ping)) + ping)
        size = struct.unpack("!I", read_exact(stream, 4))[0]
        if size > 4096:
            raise RuntimeError("selected socket did not return a bounded Kepr ping")
        reply = json.loads(read_exact(stream, size))
        if not isinstance(reply, dict) or reply.get("kind") != "pong":
            raise RuntimeError("selected socket did not answer a Kepr ping")
        return pid


def stop(path):
    pid = peer_pid(path)
    if pid is None:
        return
    fd = os.pidfd_open(pid)
    try:
        if peer_pid(path) != pid:
            raise RuntimeError("selected daemon changed during restart; refusing to signal it")
        signal.pidfd_send_signal(fd, signal.SIGTERM)
        waiter = select.poll()
        waiter.register(fd, select.POLLIN)
        if not waiter.poll(5000):
            raise RuntimeError("selected daemon did not stop within five seconds")
    finally:
        os.close(fd)


def restart(daemon, stop_only=False):
    if not daemon.is_absolute() or not daemon.is_file() or not os.access(daemon, os.X_OK):
        raise RuntimeError("installed daemon is missing or not executable; existing daemon left running")
    if not all((hasattr(socket, "SO_PEERCRED"), hasattr(os, "pidfd_open"),
                hasattr(signal, "pidfd_send_signal"))):
        raise RuntimeError("safe user-daemon restart requires Linux and Python 3.9 or newer")
    path, state = paths()
    stop(path)
    if stop_only:
        return
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    log_path = state / "install-daemon.log"
    log = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    env = os.environ.copy()
    env.pop("KEPR_SYSTEM_MODE", None)
    try:
        child = subprocess.Popen(
            [str(daemon), "--user"], env=env, stdin=subprocess.DEVNULL,
            stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
        )
    finally:
        os.close(log)
    ready = False
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if child.poll() is not None:
                raise RuntimeError(f"installed daemon exited; inspect {log_path}")
            pid = peer_pid(path)
            if pid == child.pid:
                ready = True
                print(f"Installed user daemon is responding (pid {pid}).")
                return
            if pid is not None:
                raise RuntimeError("another daemon answered the selected socket; use its service manager")
            time.sleep(0.05)
        raise RuntimeError(f"installed daemon did not become ready; inspect {log_path}")
    finally:
        if not ready and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("daemon", type=Path)
    parser.add_argument("--stop-only", action="store_true")
    args = parser.parse_args()
    try:
        restart(args.daemon, args.stop_only)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"Kepr user-daemon restart failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
