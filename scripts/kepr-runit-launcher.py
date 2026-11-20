#!/usr/bin/env python3
"""Root runit monitor: restrict privileges and follow the login runtime lifetime."""
import importlib.util
import json
import os
from pathlib import Path
import resource
import signal
import sys
import time

spec = importlib.util.spec_from_file_location('kepr_service', Path(__file__).with_name('kepr-service-common.py'))
common = importlib.util.module_from_spec(spec)
spec.loader.exec_module(common)


def secure_config(path):
    common.no_symlinks(path)
    for entry in [path, *path.parents]:
        item = entry.stat()
        if item.st_uid != 0 or item.st_mode & 0o022:
            raise RuntimeError(f'root-owned non-writable service path required: {entry}')
    config = json.loads(path.read_text())
    if config['uid'] <= 0 or config['gid'] < 0:
        raise RuntimeError('refusing a root vault owner')
    for key in ('runtime', 'home', 'daemon', 'kepr'):
        common.absolute(config[key])
    common.profile_name(config['profile'])
    for key in ('daemon', 'kepr'):
        executable = Path(config[key])
        common.no_symlinks(executable)
        for entry in [executable, *executable.parents]:
            item = entry.stat()
            if item.st_uid != 0 or item.st_mode & 0o022:
                raise RuntimeError(f'unsafe privileged executable path: {entry}')
    return config


def child_exec(config, kind):
    os.umask(0o077)
    if kind == 'daemon':
        resource.setrlimit(resource.RLIMIT_MEMLOCK, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
    common.drop_identity(config['uid'], config['gid'])
    daemon_socket, agent_socket = common.sockets(Path(config['runtime']), config['profile'])
    executable = config['daemon'] if kind == 'daemon' else config['kepr']
    # Never let a foreground agent auto-spawn a second unsupervised daemon.
    if kind == 'ssh-agent' and common.probe(daemon_socket, config['uid'], Path(config['daemon']), 'daemon', verify=False) is None:
        raise RuntimeError('supervised daemon is not ready')
    target = daemon_socket if kind == 'daemon' else agent_socket
    if common.probe(target, config['uid'], Path(executable), kind, verify=False) is not None:
        raise RuntimeError('selected socket already has a live peer; refusing duplicate service')
    args = [executable, '--user', '--login'] if kind == 'daemon' else [executable, 'ssh-agent', '--foreground', '--socket', str(agent_socket)]
    env = common.environment(config)
    if kind == 'ssh-agent':
        env['KEPR_NO_AUTOSTART'] = '1'
    os.execve(executable, args, env)

def run(config, kind):
    runtime = Path(config['runtime'])
    # elogind owns /run/user/UID. Never create or retain it outside a login.
    while not runtime.exists():
        common.no_symlinks(runtime)
        time.sleep(1)
    identity = common.private_directory(runtime, config['uid'], config['gid'])
    daemon_socket, agent_socket = common.sockets(runtime, config['profile'])
    target = daemon_socket if kind == 'daemon' else agent_socket
    binary = Path(config['daemon'] if kind == 'daemon' else config['kepr'])
    if common.probe(target, config['uid'], binary, kind, protocol=False) is not None:
        raise RuntimeError('live Kepr peer already owns selected socket; refusing duplicate service')
    if kind == 'ssh-agent' and common.probe(daemon_socket, config['uid'], Path(config['daemon']), 'daemon', protocol=False) is None:
        raise RuntimeError('supervised daemon is not ready')
    pid = os.fork()
    if pid == 0:
        try:
            child_exec(config, kind)
        except Exception as error:
            print(f'kepr runit: {error}', file=sys.stderr, flush=True)
            os._exit(1)
    stopping = False

    def terminate(_number, _frame):
        nonlocal stopping
        if not stopping:
            stopping = True
            os.kill(pid, signal.SIGTERM)

    signal.signal(signal.SIGTERM, terminate)
    signal.signal(signal.SIGINT, terminate)
    while True:
        result, status = os.waitpid(pid, os.WNOHANG)
        if result:
            return os.waitstatus_to_exitcode(status)
        try:
            present = common.private_directory(runtime, config['uid'], config['gid']) == identity
        except (OSError, RuntimeError):
            present = False
        if not present:
            terminate(None, None)
        time.sleep(0.2)


def main():
    if os.geteuid() != 0:
        raise RuntimeError('Kepr runit launcher requires root')
    if len(sys.argv) != 3 or sys.argv[2] not in ('daemon', 'ssh-agent'):
        raise RuntimeError('usage: kepr-runit-launcher.py CONFIG daemon|ssh-agent')
    return max(0, run(secure_config(common.absolute(sys.argv[1])), sys.argv[2]))


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, RuntimeError, ValueError) as error:
        print(f'kepr runit: {error}', file=sys.stderr)
        sys.exit(1)
