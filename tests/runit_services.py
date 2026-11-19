#!/usr/bin/env python3
"""Hermetic behavior coverage; no root, installed services, or live vault needed."""
import importlib.util
import json
import os
from pathlib import Path
import pwd
import resource
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / 'scripts' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


common = load('kepr-service-common')
installer = load('install-runit')
launcher = load('kepr-runit-launcher')
SERVER = '''import socket,struct,sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.bind(sys.argv[1]); s.listen()
while True:
 c,_=s.accept()
 with c:
  try:
   head=c.recv(4)
   if len(head)!=4: continue
   size=struct.unpack('!I',head)[0]; request=c.recv(size)
   reply=b'{"kind":"pong"}' if sys.argv[2]=='--user' else bytes([5])
   c.sendall(struct.pack('!I',len(reply))+reply)
  except (BrokenPipeError,ConnectionResetError): pass
'''


class Services(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='kepr-runit-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.runtime = self.base / 'runtime'
        self.runtime.mkdir(mode=0o700)
        self.uid, self.gid = os.getuid(), os.getgid()

    def server(self, path, kind='--user'):
        path.parent.mkdir(parents=True, exist_ok=True)
        child = subprocess.Popen([sys.executable, '-c', SERVER, str(path), kind],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 env={'PATH': '/usr/bin:/bin'})
        def close():
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=5)
        self.addCleanup(close)
        deadline = time.monotonic() + 5
        while not path.exists():
            self.assertIsNone(child.poll())
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.01)
        return child

    def test_private_directory_rejects_wrong_owner_mode_and_symlinks(self):
        self.assertEqual(common.private_directory(self.runtime, self.uid, self.gid),
                         (self.runtime.stat().st_dev, self.runtime.stat().st_ino))
        with self.assertRaises(RuntimeError):
            common.private_directory(self.runtime, self.uid + 1, self.gid)
        self.runtime.chmod(0o755)
        with self.assertRaises(RuntimeError):
            common.private_directory(self.runtime, self.uid, self.gid)
        self.runtime.chmod(0o700)
        alias = self.base / 'alias'
        alias.symlink_to(self.runtime)
        with self.assertRaises(RuntimeError):
            common.private_directory(alias, self.uid, self.gid)
        with self.assertRaises(RuntimeError):
            common.probe(alias / 'agent.sock', self.uid, Path(sys.executable), 'ssh-agent')

    def test_socket_paths_are_profile_aware(self):
        daemon, agent = common.sockets(self.runtime, 'work')
        self.assertEqual(daemon, self.runtime / 'kepr/profiles/work/kepr.sock')
        self.assertEqual(agent, self.runtime / 'kepr-ssh-agent-work.sock')
        self.assertEqual(common.sockets(self.runtime, 'default')[1], self.runtime / 'kepr-ssh-agent.sock')
        for invalid in ('../work', 'Work', 'x' * 33):
            with self.assertRaises(RuntimeError):
                common.sockets(self.runtime, invalid)

    def test_active_peer_is_socket_scoped_and_pidfd_stopped(self):
        selected = self.runtime / 'selected.sock'
        other = self.runtime / 'other.sock'
        child = self.server(selected)
        untouched = self.server(other)
        binary = Path(sys.executable).resolve()
        self.assertEqual(common.probe(selected, self.uid, binary, 'daemon'), child.pid)
        common.stop_checked(selected, self.uid, binary, 'daemon', child.pid)
        self.assertEqual(child.wait(timeout=5), -signal.SIGTERM)
        self.assertIsNone(untouched.poll())
        self.assertIsNone(common.probe(selected, self.uid, binary, 'daemon'))
        self.assertTrue(selected.exists(), 'stale socket is not unlinked by cutover')

    def test_unrelated_peer_and_socket_symlink_are_left_untouched(self):
        path = self.runtime / 'agent.sock'
        child = self.server(path, 'ssh-agent')
        with self.assertRaises(RuntimeError):
            common.probe(path, self.uid, Path('/bin/true').resolve(), 'ssh-agent')
        self.assertIsNone(child.poll())
        alias = self.runtime / 'alias.sock'
        alias.symlink_to(path)
        with self.assertRaises(RuntimeError):
            common.probe(alias, self.uid, Path(sys.executable).resolve(), 'ssh-agent')
        self.assertTrue(alias.is_symlink())
        self.assertIsNone(child.poll())

    def test_all_peers_are_preflighted_before_stopping_any(self):
        daemon, agent = common.sockets(self.runtime, 'default')
        child = self.server(daemon)
        unrelated = self.server(agent, 'ssh-agent')
        config = dict(runtime=str(self.runtime), uid=self.uid, gid=self.gid,
                      daemon=str(Path(sys.executable).resolve()), kepr='/bin/true', profile='default')
        args = SimpleNamespace(create_runtime=False, previous_daemon=None, previous_kepr=None)
        with self.assertRaises(RuntimeError):
            installer.cutover(config, args, True)
        self.assertIsNone(child.poll())
        self.assertIsNone(unrelated.poll())

    def test_missing_runtime_is_not_created_by_default(self):
        missing = self.base / 'missing'
        with self.assertRaises(RuntimeError):
            installer.check_runtime(dict(runtime=str(missing), uid=self.uid, gid=self.gid))
        self.assertFalse(missing.exists())

    def test_service_backup_preserves_symlink_outside_active_service_tree(self):
        stage = self.base / 'stage'
        service = stage / 'etc/sv/kepr-daemon'
        service.parent.mkdir(parents=True)
        legacy = self.base / 'legacy-service'
        legacy.mkdir()
        (legacy / 'run').write_text('untouched')
        service.symlink_to(legacy)
        installer.backup_service(stage, service)
        self.assertFalse(service.is_symlink())
        backups = list((stage / 'etc/kepr/runit-backups').iterdir())
        self.assertEqual(len(backups), 1)
        self.assertTrue(backups[0].is_symlink())
        self.assertEqual((legacy / 'run').read_text(), 'untouched')

    def test_staging_cannot_bypass_live_root_or_enable_cutover(self):
        result = self.stage('--root', '/', '--dry-run')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('isolated staging', result.stderr)
        result = self.stage('--cutover')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.base / 'stage').exists())

    def test_runtime_logout_terminates_only_supervised_child(self):
        config = dict(runtime=str(self.runtime), uid=self.uid, gid=self.gid,
                      profile='default', daemon='/opt/kepr-daemon', kepr='/opt/kepr')
        killed = []
        with patch.object(launcher.common, 'private_directory', side_effect=[(1, 2), FileNotFoundError()]), \
             patch.object(launcher.common, 'probe', return_value=None), \
             patch.object(launcher.os, 'fork', return_value=12345), \
             patch.object(launcher.os, 'waitpid', side_effect=[(0, 0), (12345, signal.SIGTERM)]), \
             patch.object(launcher.os, 'kill', side_effect=lambda *v: killed.append(v)), \
             patch.object(launcher.signal, 'signal'), patch.object(launcher.time, 'sleep'):
            launcher.run(config, 'daemon')
        self.assertEqual(killed, [(12345, signal.SIGTERM)])

    def test_memlock_failure_never_drops_or_executes(self):
        with patch.object(launcher.os, 'umask'), \
             patch.object(launcher.resource, 'setrlimit', side_effect=PermissionError('denied')), \
             patch.object(launcher.common, 'drop_identity') as drop, \
             patch.object(launcher.os, 'execve') as execute:
            with self.assertRaises(PermissionError):
                launcher.child_exec({}, 'daemon')
        drop.assert_not_called()
        execute.assert_not_called()

    def test_daemon_memlock_precedes_identity_drop_and_agent_keeps_limit(self):
        config = dict(runtime=str(self.runtime), uid=1234, gid=4321, profile='work',
                      daemon='/opt/kepr-daemon', kepr='/opt/kepr', home='/home/example', user='example')
        for kind in ('daemon', 'ssh-agent'):
            events = []
            def probe(path, *_args, **_kwargs):
                return 42 if kind == 'ssh-agent' and path.name == 'kepr.sock' else None
            with patch.object(launcher.os, 'umask', side_effect=lambda mode: events.append(('umask', mode))), \
                 patch.object(launcher.resource, 'setrlimit', side_effect=lambda *v: events.append(('limit', *v))), \
                 patch.object(launcher.common, 'drop_identity', side_effect=lambda *v: events.append(('drop', *v))), \
                 patch.object(launcher.common, 'probe', side_effect=probe), \
                 patch.object(launcher.os, 'execve', side_effect=lambda *v: events.append(('exec', *v))):
                launcher.child_exec(config, kind)
            self.assertEqual(events[0], ('umask', 0o077))
            self.assertEqual([e[0] for e in events], ['umask', 'limit', 'drop', 'exec'] if kind == 'daemon' else ['umask', 'drop', 'exec'])
            if kind == 'daemon':
                self.assertEqual(events[1], ('limit', resource.RLIMIT_MEMLOCK, (-1, -1)))
                self.assertEqual(events[-1][2], ['/opt/kepr-daemon', '--user', '--login'])
            else:
                self.assertEqual(events[-1][2][-1], str(self.runtime / 'kepr-ssh-agent-work.sock'))
                self.assertEqual(events[-1][3]['KEPR_NO_AUTOSTART'], '1')
            self.assertNotIn('KEPR_SYSTEM_MODE', events[-1][3])

    def test_identity_drop_removes_all_supplementary_groups_first(self):
        calls = []
        with patch.object(common.os, 'setgroups', side_effect=lambda v: calls.append(('groups', v))), \
             patch.object(common.os, 'setgid', side_effect=lambda v: calls.append(('gid', v))), \
             patch.object(common.os, 'setuid', side_effect=lambda v: calls.append(('uid', v))):
            common.drop_identity(1234, 4321)
        self.assertEqual(calls, [('groups', []), ('gid', 4321), ('uid', 1234)])

    def test_user_adapter_backup_does_not_follow_old_symlink(self):
        home = self.base / 'home'
        destination = home / '.local/bin/kepr-ssh-keygen'
        destination.parent.mkdir(parents=True)
        original = self.base / 'old-adapter'
        original.write_text('untouched')
        destination.symlink_to(original)
        config = dict(home=str(home))
        with self.assertRaises(RuntimeError):
            installer.user_adapter(config, SimpleNamespace(replace_user_adapter=False), b'new')
        installer.user_adapter(config, SimpleNamespace(replace_user_adapter=True), b'new')
        self.assertEqual(original.read_text(), 'untouched')
        self.assertEqual(destination.read_bytes(), b'new')
        backups = list(destination.parent.glob('kepr-ssh-keygen.kepr-backup-*'))
        self.assertEqual(len(backups), 1)
        self.assertTrue(backups[0].is_symlink())

    def stage(self, *extra):
        binaries = self.base / 'binaries'
        binaries.mkdir(exist_ok=True)
        for name in ('kepr', 'kepr-daemon'):
            path = binaries / name
            path.write_text('#!/bin/sh\nexit 0\n')
            path.chmod(0o755)
        user = pwd.getpwuid(self.uid).pw_name if self.uid else 'nobody'
        return subprocess.run([sys.executable, str(ROOT / 'scripts/install-runit.py'),
                               '--root', str(self.base / 'stage'), '--user', user,
                               '--bin-dir', str(binaries), '--runtime', str(self.runtime),
                               '--profile', 'work', *extra], capture_output=True, text=True,
                              env={'PATH': '/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE': '1'})

    def test_staging_renders_dynamic_identity_and_absolute_owned_launchers(self):
        result = self.stage('--enable')
        self.assertEqual(result.returncode, 0, result.stderr)
        stage = self.base / 'stage'
        config = json.loads((stage / 'etc/kepr/runit.json').read_text())
        owner = pwd.getpwnam(config['user'])
        self.assertEqual((config['uid'], config['gid'], config['home']), (owner.pw_uid, owner.pw_gid, owner.pw_dir))
        self.assertEqual(config['runtime'], str(self.runtime))
        self.assertEqual(config['profile'], 'work')
        service = stage / 'etc/sv/kepr-daemon'
        self.assertFalse(service.is_symlink())
        self.assertFalse((service / 'down').exists())
        self.assertEqual(os.readlink(stage / 'var/service/kepr-daemon'), '/etc/sv/kepr-daemon')
        body = (service / 'run').read_text()
        self.assertIn('/usr/local/libexec/kepr/kepr-runit-launcher.py', body)
        self.assertNotIn(str(ROOT), body)
        self.assertNotIn('@', body)
        self.assertEqual((stage / 'etc/kepr/runit.json').stat().st_mode & 0o777, 0o600)

    def test_dry_run_writes_nothing_and_existing_artifacts_need_approval(self):
        result = self.stage('--dry-run')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.base / 'stage').exists())
        self.assertEqual(self.stage().returncode, 0)
        original = self.base / 'stage/etc/kepr/runit.json'
        before = original.read_bytes()
        self.assertNotEqual(self.stage().returncode, 0)
        self.assertEqual(original.read_bytes(), before)
        self.assertEqual(self.stage('--replace-existing').returncode, 0)
        self.assertTrue(list(original.parent.glob('runit.json.kepr-backup-*')))

    def test_staging_refuses_symlinked_destination_without_damage(self):
        stage = self.base / 'stage'
        stage.mkdir()
        outside = self.base / 'outside'
        outside.mkdir()
        (stage / 'etc').symlink_to(outside)
        result = self.stage('--replace-existing')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(outside.iterdir()), [])

    def test_signing_adapter_selects_profile_socket_and_forwards_arguments(self):
        fakebin = self.base / 'bin'
        fakebin.mkdir()
        fake = fakebin / 'ssh-keygen'
        fake.write_text('#!/usr/bin/env python3\nimport json,os,sys\nprint(json.dumps([os.environ["SSH_AUTH_SOCK"],sys.argv[1:]]))\n')
        fake.chmod(0o755)
        for profile, suffix in (('default', ''), ('work', '-work')):
            path = self.runtime / f'kepr-ssh-agent{suffix}.sock'
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as agent:
                agent.bind(str(path))
                args = ['-Y', 'sign', '-f', 'public key.pub', '-n', 'git', 'message']
                env = {'PATH': f'{fakebin}:/usr/bin:/bin', 'XDG_RUNTIME_DIR': str(self.runtime),
                       'KEPR_PROFILE': profile, 'SSH_AUTH_SOCK': '/unrelated/agent.sock'}
                result = subprocess.run([sys.executable, str(ROOT / 'scripts/kepr-ssh-keygen'), *args],
                                        env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), [str(path), args])
                env.pop('SSH_AUTH_SOCK')
                result = subprocess.run([sys.executable, str(ROOT / 'scripts/kepr-ssh-keygen'), *args],
                                        env=env, capture_output=True, text=True)
                self.assertEqual(json.loads(result.stdout), [str(path), args])
        env['KEPR_PROFILE'] = '../escape'
        result = subprocess.run([sys.executable, str(ROOT / 'scripts/kepr-ssh-keygen')], env=env, capture_output=True)
        self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
