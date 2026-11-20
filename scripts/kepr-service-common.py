#!/usr/bin/env python3
"""Filesystem and socket checks shared by Kepr's runit tools."""
import errno
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import stat
import struct
import time


def absolute(value):
    path = Path(value)
    if not path.is_absolute() or '..' in path.parts:
        raise RuntimeError(f"expected an absolute normalized path: {path}")
    return path


def no_symlinks(path):
    path = absolute(path)
    for part in reversed([path, *path.parents]):
        if part.is_symlink():
            raise RuntimeError(f"refusing symlink: {part}")


def private_directory(path, uid, gid, create=False):
    no_symlinks(path)
    if create and not path.exists():
        path.mkdir(mode=0o700)
        os.chown(path, uid, gid)
    item = path.lstat()
    if not stat.S_ISDIR(item.st_mode) or item.st_uid != uid or stat.S_IMODE(item.st_mode) != 0o700:
        raise RuntimeError(f"expected owner {uid} and directory mode 0700: {path}")
    return item.st_dev, item.st_ino


def profile_name(value):
    if value in ('', 'default'):
        return 'default'
    if not re.fullmatch(r'[a-z0-9_-]{1,32}', value):
        raise RuntimeError('invalid Kepr profile')
    return value


def sockets(runtime, profile):
    profile = profile_name(profile)
    daemon = runtime / 'kepr'
    if profile != 'default':
        daemon = daemon / 'profiles' / profile
    suffix = '' if profile == 'default' else '-' + profile
    return daemon / 'kepr.sock', runtime / f'kepr-ssh-agent{suffix}.sock'


def exact(stream, count):
    result = bytearray()
    while len(result) < count:
        chunk = stream.recv(count - len(result))
        if not chunk:
            raise RuntimeError('socket closed during protocol verification')
        result.extend(chunk)
    return result


def probe(path, uid, executable, kind, verify=True, protocol=True):
    no_symlinks(path)
    try:
        item = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISSOCK(item.st_mode) or item.st_uid != uid:
        raise RuntimeError(f'refusing unsafe socket: {path}')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(2)
        try:
            stream.connect(str(path))
        except ConnectionRefusedError:
            return None
        pid, owner, _ = struct.unpack('3i', stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if owner != uid or pid <= 1:
            raise RuntimeError(f'unexpected socket peer: {path}')
        if verify:
            actual = os.readlink(f'/proc/{pid}/exe').removesuffix(' (deleted)')
            if actual != str(executable.resolve()):
                raise RuntimeError(f'unexpected executable on {path}; left running')
            command = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
            required = b'--user' if kind == 'daemon' else b'ssh-agent'
            if required not in command:
                raise RuntimeError(f'unexpected Kepr command on {path}; left running')
        if not protocol:
            return pid
        if kind == 'daemon':
            request = b'{"cmd":"ping"}'
            stream.sendall(struct.pack('!I', len(request)) + request)
        else:
            stream.sendall(struct.pack('!IB', 1, 11))
        size = struct.unpack('!I', exact(stream, 4))[0]
        if not 1 <= size <= (4096 if kind == 'daemon' else 262144):
            raise RuntimeError('unbounded protocol response; refusing cutover')
        reply = exact(stream, size)
        valid = (isinstance((data := json.loads(reply)), dict) and data.get('kind') == 'pong') if kind == 'daemon' else reply[0] in (5, 12)
        if not valid:
            raise RuntimeError('unexpected protocol response; refusing cutover')
        return pid


def stop_checked(path, uid, executable, kind, pid, protocol=True):
    if pid is None:
        return
    fd = os.pidfd_open(pid)
    try:
        if probe(path, uid, executable, kind, protocol=protocol) != pid:
            raise RuntimeError('socket peer changed; refusing cutover')
        signal.pidfd_send_signal(fd, signal.SIGTERM)
        poll = select.poll()
        poll.register(fd, select.POLLIN)
        if not poll.poll(5000):
            raise RuntimeError('Kepr peer did not stop; refusing forced termination')
    finally:
        os.close(fd)


def drop_identity(uid, gid):
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)


def environment(config):
    return {'HOME': config['home'], 'USER': config['user'], 'LOGNAME': config['user'],
            'PATH': '/usr/local/bin:/usr/bin:/bin', 'XDG_RUNTIME_DIR': config['runtime'],
            'KEPR_PROFILE': config['profile']}


def wait_supervisors(services, timeout=20):
    deadline = time.monotonic() + timeout
    pending = list(services)
    while pending:
        for directory in pending[:]:
            control = directory / 'supervise/control'
            try:
                fd = os.open(control, os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW)
            except OSError as error:
                if error.errno not in (errno.ENOENT, errno.ENXIO):
                    raise
                continue
            try:
                if not stat.S_ISFIFO(os.fstat(fd).st_mode):
                    raise RuntimeError(f'runit control is not a FIFO: {control}')
            finally:
                os.close(fd)
            pending.remove(directory)
        if pending:
            if time.monotonic() >= deadline:
                raise RuntimeError('runsv did not open control pipes; check the active runsvdir: '
                                   + ', '.join(str(path) for path in pending))
            time.sleep(0.05)
