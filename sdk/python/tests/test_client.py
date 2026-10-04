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
from kepr_client import Client, KeprError, socket_path  # noqa: E402


class FakeDaemon:
    """Answers each connection with ``reply(request_dict)``."""

    def __init__(self, reply):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "s.sock")
        self.reply = reply
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

    def test_unreachable_socket(self):
        with self.assertRaisesRegex(KeprError, "cannot reach"):
            Client("/nonexistent/kepr.sock", timeout=1).ping()

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
