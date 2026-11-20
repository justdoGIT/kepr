#!/usr/bin/env python3
"""Install Kepr-owned runit services without building or changing login policy."""
import argparse
import importlib.util
import fcntl
import json
import os
from pathlib import Path
import pwd
import shlex
import shutil
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('kepr_service', HERE / 'kepr-service-common.py')
common = importlib.util.module_from_spec(spec)
spec.loader.exec_module(common)


def executable(value):
    path = common.absolute(value).resolve(strict=True)
    if not path.is_file() or not os.access(path, os.X_OK):
        raise RuntimeError(f'executable required: {path}')
    return path


def configuration(args):
    username = args.user or os.environ.get('SUDO_USER') or pwd.getpwuid(os.getuid()).pw_name
    owner = pwd.getpwnam(username)
    if owner.pw_uid == 0:
        raise RuntimeError('specify a non-root vault owner with --user')
    runtime = common.absolute(args.runtime or f'/run/user/{owner.pw_uid}')
    home = common.absolute(owner.pw_dir)
    binaries = common.absolute(args.bin_dir)
    config = dict(user=username, uid=owner.pw_uid, gid=owner.pw_gid, home=str(home),
                  runtime=str(runtime), profile=common.profile_name(args.profile),
                  daemon=str(executable(binaries / 'kepr-daemon')),
                  kepr=str(executable(binaries / 'kepr')))
    if not args.root:
        for key in ('daemon', 'kepr'):
            for entry in [Path(config[key]), *Path(config[key]).parents]:
                item = entry.stat()
                if item.st_uid != 0 or item.st_mode & 0o022:
                    raise RuntimeError(f'install binaries into a root-owned non-writable path first: {entry}')
    return config


def as_owner(config, operation):
    pid = os.fork()
    if pid == 0:
        try:
            if os.geteuid() == 0:
                common.drop_identity(config['uid'], config['gid'])
            elif os.getuid() != config['uid']:
                raise RuntimeError('staging runtime checks require the selected owner')
            operation()
            os._exit(0)
        except Exception as error:
            print(f'kepr runit: {error}', file=sys.stderr, flush=True)
            os._exit(1)
    if os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]) != 0:
        raise RuntimeError('owner-scoped preflight/cutover failed; no services installed')


def check_runtime(config, create=False):
    runtime = Path(config['runtime'])
    common.no_symlinks(runtime)
    if runtime.exists() or create:
        common.private_directory(runtime, config['uid'], config['gid'], create)
    else:
        raise RuntimeError('runtime missing; log in through elogind first, or approve --create-runtime with a custom --runtime')


def peers(config, args):
    daemon, agent = common.sockets(Path(config['runtime']), config['profile'])
    return [(daemon, Path(args.previous_daemon or config['daemon']), 'daemon'),
            (agent, Path(args.previous_kepr or config['kepr']), 'ssh-agent')]


def cutover(config, args, stop):
    runtime = Path(config['runtime'])
    if args.create_runtime and not runtime.exists():
        common.no_symlinks(runtime)
        if stop:
            as_owner(config, lambda: check_runtime(config, True))
    else:
        check_runtime(config)
    checked = []
    for path, binary, kind in peers(config, args):
        pid = common.probe(path, config['uid'], binary, kind, protocol=False)
        if pid:
            status = Path(f'/proc/{pid}/status').read_text()
            parent = next(line.split()[1] for line in status.splitlines() if line.startswith('PPid:'))
            manager = Path(os.readlink(f'/proc/{parent}/exe')).name
            if manager in ('runsv', 'systemd', 'supervise'):
                raise RuntimeError(f'{kind} is supervised; stop its existing service before cutover')
        checked.append((path, binary, kind, pid))
    def verify_protocols():
        for path, binary, kind, pid in checked:
            if common.probe(path, config['uid'], binary, kind, verify=False) != pid:
                raise RuntimeError('socket peer changed during owner protocol check')
    as_owner(config, verify_protocols)
    if stop:
        # All sockets are proven before either peer is signalled.
        for path, binary, kind, pid in reversed(checked):
            common.stop_checked(path, config['uid'], binary, kind, pid, protocol=False)
        for path, binary, kind, _ in checked:
            if common.probe(path, config['uid'], binary, kind, protocol=False) is not None:
                raise RuntimeError('a supervisor restarted Kepr; refusing duplicate listeners')


def target(root, path):
    result = root / path.lstrip('/')
    common.no_symlinks(result.parent)
    return result


def preflight_destination(path, replace):
    if not path.exists() and not path.is_symlink():
        return
    if not replace:
        raise RuntimeError(f'existing artifact requires explicit --replace-existing (backed up): {path}')
    if path.is_dir() and not path.is_symlink():
        run = path / 'run'
        if not run.is_file():
            raise RuntimeError(f'refusing unrelated service directory: {path}')
        # The option approves only these exact Kepr service names, never arbitrary directories.
        if path.name not in ('kepr-daemon', 'kepr-ssh-agent'):
            raise RuntimeError(f'refusing unrelated directory: {path}')
        lock = path / 'supervise/lock'
        if lock.exists():
            common.no_symlinks(lock)
            with lock.open('rb') as stream:
                try:
                    fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise RuntimeError(f'active runsv owns {path}; disable its link and stop/exit that supervisor first')


def backup(path):
    if path.exists() or path.is_symlink():
        path.rename(path.with_name(path.name + f'.kepr-backup-{time.time_ns()}'))


def service_backup_directory(root):
    directory = target(root, '/etc/kepr/runit-backups')
    common.no_symlinks(directory)
    if directory.exists():
        item = directory.stat()
        if not directory.is_dir() or item.st_uid != os.geteuid() or item.st_mode & 0o777 != 0o700:
            raise RuntimeError(f'unsafe service backup directory: {directory}')
    return directory


def backup_service(root, path):
    if not path.exists() and not path.is_symlink():
        return
    directory = service_backup_directory(root)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    shutil.move(str(path), str(directory / (path.name + f'-{time.time_ns()}')))


def install_file(path, contents, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    backup(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(contents)
    path.chmod(mode)


def user_adapter(config, args, contents=None):
    path = Path(config['home']) / '.local/bin/kepr-ssh-keygen'
    common.no_symlinks(path.parent)
    exists = path.exists() or path.is_symlink()
    if exists and not args.replace_user_adapter:
        raise RuntimeError(f'{path} takes PATH precedence; approve --replace-user-adapter to back it up')
    if exists and path.is_dir() and not path.is_symlink():
        raise RuntimeError(f'refusing adapter directory: {path}')
    if contents is not None and (exists or args.replace_user_adapter):
        install_file(path, contents, 0o755)


def install(args):
    if sys.version_info < (3, 9) or not hasattr(os, 'pidfd_open') or not hasattr(common.signal, 'pidfd_send_signal'):
        raise RuntimeError('safe Kepr runit installation requires Linux and Python 3.9 or newer')
    if not args.root and os.geteuid() != 0:
        raise RuntimeError('root access required; run sudo -n python3 scripts/install-runit.py ...')
    if args.root and args.create_runtime:
        raise RuntimeError('staging never creates live runtime directories')
    root = common.absolute(args.root) if args.root else Path('/')
    common.no_symlinks(root)
    if args.root and root == Path('/'):
        raise RuntimeError('--root must name an isolated staging directory, not /')
    service_backup_directory(root)
    config = configuration(args)
    if args.root and args.cutover:
        raise RuntimeError('--cutover is forbidden with --root staging')
    service_dir = common.absolute(args.service_dir)
    if not args.root:
        service_dir = service_dir.resolve(strict=True)
    libexec = '/usr/local/libexec/kepr'
    config_path = '/etc/kepr/runit.json'
    python = str(executable(sys.executable))
    templates = HERE.parent / 'runit'
    if not templates.is_dir():
        templates = Path('/usr/share/kepr/runit')
    files = {f'{libexec}/{name}': ((HERE / name).read_bytes(), 0o755)
             for name in ('install-runit.py', 'kepr-runit-launcher.py', 'kepr-service-common.py', 'kepr-ssh-keygen')}
    files['/usr/local/bin/kepr-ssh-keygen'] = ((HERE / 'kepr-ssh-keygen').read_bytes(), 0o755)
    files[config_path] = ((json.dumps(config, indent=2) + '\n').encode(), 0o600)
    services = ['/etc/sv/kepr-daemon', '/etc/sv/kepr-ssh-agent']
    for service in services:
        body = (templates / (Path(service).name + '.run')).read_text()
        for token, value in (('@PYTHON@', python), ('@LAUNCHER@', libexec + '/kepr-runit-launcher.py'), ('@CONFIG@', config_path)):
            body = body.replace(token, shlex.quote(value))
        files[service + '/run'] = (body.encode(), 0o755)
        files[service + '/down'] = (b'', 0o644)
    for name in ('kepr-daemon.run', 'kepr-ssh-agent.run'):
        files['/usr/share/kepr/runit/' + name] = ((templates / name).read_bytes(), 0o644)
    # Validate the complete destination set before modifying files or signalling processes.
    for path in [path for path in files if not path.startswith('/etc/sv/')] + services:
        destination = target(root, path)
        if not args.root:
            for entry in destination.parents:
                if entry.exists():
                    item = entry.stat()
                    if item.st_uid != 0 or item.st_mode & 0o022:
                        raise RuntimeError(f'unsafe root installation directory: {entry}')
        preflight_destination(destination, args.replace_existing)
    for service in services:
        link = target(root, str(service_dir / Path(service).name))
        if not args.root:
            for entry in link.parents:
                if entry.exists():
                    item = entry.stat()
                    if item.st_uid != 0 or item.st_mode & 0o022:
                        raise RuntimeError(f'unsafe service enablement directory: {entry}')
        if link.exists() or link.is_symlink():
            if not link.is_symlink() or os.readlink(link) != service:
                raise RuntimeError(f'unrelated enablement path; left untouched: {link}')
    if not args.root:
        as_owner(config, lambda: user_adapter(config, args))
        cutover(config, args, False)
    if args.dry_run:
        print(json.dumps({'config': config, 'root': str(root), 'enable': args.enable, 'cutover': args.cutover}, indent=2))
        return
    if not args.root:
        if not args.cutover:
            raise RuntimeError('live installation requires --cutover after reviewing --dry-run')
    for service in services:
        backup_service(root, target(root, service))
    for path, (body, mode) in files.items():
        install_file(target(root, path), body, mode)
    for service in services:
        target(root, service).chmod(0o755)
    if not args.root:
        contents = files['/usr/local/bin/kepr-ssh-keygen'][0]
        as_owner(config, lambda: user_adapter(config, args, contents))
    if args.enable:
        for service in services:
            directory = target(root, service)
            link = target(root, str(service_dir / Path(service).name))
            link.parent.mkdir(parents=True, exist_ok=True)
            if not link.is_symlink():
                link.symlink_to(service)
        if not args.root:
            common.wait_supervisors([target(root, service) for service in services])
    if not args.root:
        # Leave the existing listener alive until installation and supervision are ready.
        cutover(config, args, True)
    if args.enable:
        for service in services:
            (target(root, service) / 'down').unlink()
        if not args.root:
            subprocess.run(['sv', '-w', '20', 'up',
                            *(str(service_dir / Path(service).name) for service in services)], check=True)
    print('Installed Kepr runit services' + (' and enabled them.' if args.enable else ' (down; enable explicitly).'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--user')
    parser.add_argument('--runtime')
    parser.add_argument('--profile', default='default')
    parser.add_argument('--bin-dir', default='/usr/local/bin')
    parser.add_argument('--root', help='stage files below this directory; never touch live sockets')
    parser.add_argument('--service-dir', default='/var/service', help='active runsvdir directory (resolved explicitly on live installs)')
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--enable', action='store_true')
    parser.add_argument('--cutover', action='store_true', help='stop only socket-proven standalone Kepr peers')
    parser.add_argument('--replace-existing', action='store_true', help='approve backups/replacement of the exact Kepr artifacts')
    parser.add_argument('--replace-user-adapter', action='store_true', help='back up and replace only ~/.local/bin/kepr-ssh-keygen as its owner')
    parser.add_argument('--create-runtime', action='store_true', help='create a custom runtime as the vault owner; not /run/user/UID')
    parser.add_argument('--previous-daemon', type=executable)
    parser.add_argument('--previous-kepr', type=executable)
    args = parser.parse_args()
    if args.create_runtime and (not args.runtime or args.runtime.startswith('/run/user/')):
        parser.error('--create-runtime requires a custom --runtime; elogind owns /run/user/UID')
    install(args)


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, KeyError, ValueError, subprocess.CalledProcessError) as error:
        print(f'kepr runit: {error}', file=sys.stderr)
        sys.exit(1)
