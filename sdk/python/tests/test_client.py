"""Unit tests against a fake framed server; a live round-trip runs when
KEPR_SDK_LIVE=1 (needs a running kepr daemon)."""

import json
import os
import socket
import struct
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from kepr_client import FETCH_FD_CMD, Client, CredInfo, KeprError, socket_path  # noqa: E402


class FakeDaemon:
    """Answers each connection with ``reply(request_dict)``, then calls
    ``after(conn)`` (e.g. to pass a descriptor)."""

    def __init__(self, reply, after=None):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "s.sock")
        self.reply = reply
        self.after = after
        self.seen = []
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(self.path)
        self.srv.listen(4)
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            with conn:
                (n,) = struct.unpack(">I", conn.recv(4, socket.MSG_WAITALL))
                req = json.loads(conn.recv(n, socket.MSG_WAITALL))
                self.seen.append(req)
                out = json.dumps(self.reply(req)).encode()
                conn.sendall(struct.pack(">I", len(out)) + out)
                if self.after:
                    self.after(conn)

    def close(self):
        self.srv.close()


class ClientTests(unittest.TestCase):
    def test_get_uppercases_and_returns_value(self):
        d = FakeDaemon(lambda r: {"kind": "get_ok", "name": r["name"], "value": "v1"})
        self.addCleanup(d.close)
        self.assertEqual(Client(d.path).get("api_key"), "v1")
        self.assertEqual(d.seen, [{"cmd": "get", "name": "API_KEY"}])

    def test_err_reply_raises(self):
        d = FakeDaemon(lambda r: {"kind": "err", "error": "credential unavailable"})
        self.addCleanup(d.close)
        with self.assertRaisesRegex(KeprError, "credential unavailable"):
            Client(d.path).get("SEALED")

    def test_set_generate_and_flags(self):
        d = FakeDaemon(lambda r: {"kind": "set_ok", "name": r["name"], "cred_name": "x",
                                  "password_protected": False})
        self.addCleanup(d.close)
        Client(d.path).set("k", ttl_secs=60, requires_consent=True)
        self.assertEqual(d.seen[0], {"cmd": "set", "name": "K", "generate": "hex",
                                     "ttl_secs": 60, "requires_consent": True})

    def test_set_value_generate_and_validation(self):
        d = FakeDaemon(lambda r: {"kind": "set_ok", "name": r["name"], "cred_name": "x",
                                  "password_protected": False})
        self.addCleanup(d.close)
        c = Client(d.path)
        c.set("a", "v", requires_fido2=True)
        c.set("b", generate="words")
        self.assertEqual(d.seen[0], {"cmd": "set", "name": "A", "value": "v",
                                     "requires_fido2": True})
        self.assertEqual(d.seen[1], {"cmd": "set", "name": "B", "generate": "words"})
        with self.assertRaisesRegex(KeprError, "generate"):
            c.set("c", generate="rot13")
        with self.assertRaisesRegex(KeprError, "not both"):
            c.set("c", "v", generate="hex")
        with self.assertRaisesRegex(KeprError, "empty"):
            c.set("c", "")
        self.assertEqual(len(d.seen), 2, "invalid calls never reach the daemon")

    def test_delete_and_list_with_metadata(self):
        creds = [
            {"name": "GH", "cred_name": "kepr-1-gh", "size": 40, "modified": "2026-10-01 12:00",
             "expires_at": "2026-12-01 00:00", "requires_consent": True},
            {"name": "OA", "cred_name": "kepr-1-oa", "size": 9, "modified": "2026-10-02 08:00",
             "sealed": True, "bound_hosts": ["api.openai.com"], "tags": ["work"]},
        ]

        def reply(r):
            if r["cmd"] == "delete":
                return {"kind": "delete_ok", "name": r["name"]}
            return {"kind": "list_ok", "credentials": creds, "count": 2}

        d = FakeDaemon(reply)
        self.addCleanup(d.close)
        c = Client(d.path)
        c.delete("gh")
        self.assertEqual(d.seen[0], {"cmd": "delete", "name": "GH"})
        infos = c.credentials()
        self.assertIsInstance(infos[0], CredInfo)
        self.assertEqual(infos[0].expires_at, "2026-12-01 00:00")
        self.assertTrue(infos[0].requires_consent)
        self.assertFalse(infos[0].sealed)
        self.assertTrue(infos[1].sealed)
        self.assertEqual(infos[1].bound_hosts, ["api.openai.com"])
        self.assertEqual(infos[1].tags, ["work"], "fields from newer daemons pass through")
        self.assertEqual(c.info("oa").name, "OA")
        self.assertIsNone(c.info("missing"))
        self.assertNotIn("value", repr(infos[0]))

    def test_fetch_fd_receives_a_descriptor(self):
        r, w = os.pipe()
        os.write(w, b"s3cret")
        os.close(w)
        self.addCleanup(os.close, r)

        def after(conn):
            socket.send_fds(conn, [b"\0"], [r])

        d = FakeDaemon(lambda q: {"kind": "fd_ok", "len": 6}, after=after)
        self.addCleanup(d.close)
        fd, n = Client(d.path).fetch_fd("db_pass")
        try:
            self.assertEqual(d.seen, [{"cmd": FETCH_FD_CMD, "name": "DB_PASS"}])
            self.assertEqual(n, 6)
            self.assertEqual(os.read(fd, 16), b"s3cret")
            self.assertFalse(os.get_inheritable(fd))
        finally:
            os.close(fd)

    def test_fetch_fd_without_descriptor_fails(self):
        d = FakeDaemon(lambda q: {"kind": "fd_ok", "len": 6})
        self.addCleanup(d.close)
        with self.assertRaisesRegex(KeprError, "descriptor"):
            Client(d.path).fetch_fd("X")

    def test_unreachable_socket(self):
        with self.assertRaisesRegex(KeprError, "cannot reach"):
            Client("/nonexistent/kepr.sock", timeout=1).ping()

    def test_socket_served_by_another_user_is_refused(self):
        # System mode expects root; a fake daemon run by anyone else is not it.
        if os.geteuid() == 0 or not hasattr(socket, "SO_PEERCRED"):
            self.skipTest("needs a non-root Linux user")
        d = FakeDaemon(lambda r: {"kind": "get_ok", "value": "x"})
        old = os.environ.get("KEPR_SYSTEM_MODE")
        os.environ["KEPR_SYSTEM_MODE"] = "1"
        try:
            with self.assertRaises(KeprError) as cm:
                Client(d.path).get("A")
            self.assertIn("expected credential daemon", str(cm.exception))
            self.assertEqual(d.seen, [])
        finally:
            d.close()
            if old is None:
                del os.environ["KEPR_SYSTEM_MODE"]
            else:
                os.environ["KEPR_SYSTEM_MODE"] = old

    def test_bad_name(self):
        with self.assertRaises(KeprError):
            Client("/x").get("")

    def test_socket_path_follows_runtime_dir(self):
        old = dict(os.environ)
        try:
            os.environ.pop("KEPR_SYSTEM_MODE", None)
            os.environ["XDG_RUNTIME_DIR"] = "/run/user/1000"
            self.assertEqual(socket_path(), "/run/user/1000/kepr/kepr.sock")
            os.environ["KEPR_SYSTEM_MODE"] = "1"
            self.assertEqual(socket_path(), "/run/kepr/kepr.sock")
        finally:
            os.environ.clear()
            os.environ.update(old)


@unittest.skipUnless(os.environ.get("KEPR_SDK_LIVE"), "set KEPR_SDK_LIVE=1 with a running daemon")
class LiveTests(unittest.TestCase):
    def test_round_trip(self):
        c = Client()
        name = "SDK_TEST_%d" % os.getpid()
        c.set(name, "one")
        c.set(name, "two")
        try:
            self.assertEqual(c.get(name), "two")
            self.assertIn(name, [x["name"] for x in c.list()])
            self.assertEqual(len(c.history(name)), 1)
            c.restore(name, 1)
            self.assertEqual(c.get(name), "one")
            self.assertTrue(any(k["name"] == name for k in c.usage()["keys"]))
        finally:
            c.delete(name)
        with self.assertRaises(KeprError):
            c.get(name)


if __name__ == "__main__":
    unittest.main()
