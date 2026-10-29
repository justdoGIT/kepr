"""Thin client for the kepr credential daemon.

Speaks the daemon's own wire format: one JSON request per connection,
framed by a 4-byte big-endian length, over the per-user Unix socket
(``$XDG_RUNTIME_DIR/kepr/kepr.sock``, or ``/run/kepr/kepr.sock`` with
``KEPR_SYSTEM_MODE=1``). The daemon identifies the caller by its
socket credentials, so this client can only reach the calling user's
own credentials, and every call is audited like the CLI's.

Sealed (agent) credentials and SSH keys are never returned by ``get``;
that is enforced by the daemon, not here.

Python strings cannot be wiped from memory. Keep secrets in scope for
as short a time as possible and prefer ``kepr exec`` / ``kepr agent
run`` when a child process only needs the value as configuration.
"""

import base64
import json
import os
import socket
import struct

__all__ = ["Client", "CredInfo", "KeprError", "socket_path", "GENERATE_KINDS"]
__version__ = "0.2.0"

MAX_MSG_BYTES = 65536
_DEFAULT_TIMEOUT = 65.0  # covers the daemon's 60 s consent prompt

GENERATE_KINDS = ("hex", "base62", "pass", "uuid", "words")
# Pull-on-demand fd delivery (plan T3.06): request name and reply kind.
FETCH_FD_CMD = "fetch_fd"
_FD_OK = "fd_ok"


class KeprError(Exception):
    """The daemon refused the request or could not be reached."""


class CredInfo:
    """One credential's metadata as ``list`` reports it. Never a value.

    Known fields are attributes (``None`` / ``False`` when absent); fields
    from newer daemons (e.g. ``tags``) are attributes too.
    """

    _FLAGS = ("requires_consent", "requires_fido2", "sealed")
    _OPTIONAL = ("expires_at", "bound_hosts", "record_type")

    def __init__(self, d):
        self.name = d.get("name", "")
        self.size = d.get("size", 0)
        self.modified = d.get("modified", "")
        for k in self._OPTIONAL:
            setattr(self, k, d.get(k))
        for k in self._FLAGS:
            setattr(self, k, bool(d.get(k)))
        for k, v in d.items():
            if not hasattr(self, k):
                setattr(self, k, v)
        # The on-disk name carries the uid; it is not useful to callers.
        self.__dict__.pop("cred_name", None)

    def __repr__(self):
        return "CredInfo(%r)" % (self.__dict__,)


def socket_path():
    """Same resolution as the kepr CLI."""
    if os.environ.get("KEPR_SYSTEM_MODE"):
        return "/run/kepr/kepr.sock"
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if not runtime:
        home = os.environ.get("HOME", "/tmp")
        runtime = os.path.join(home, ".local/state/kepr/runtime")
    return os.path.join(runtime, "kepr", "kepr.sock")


def _recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise KeprError("connection closed by the credential service")
        buf.extend(chunk)
    return bytes(buf)


def _check_peer(sock):
    """Refuse a socket whose server is not the daemon we expect: root's in
    system mode, otherwise our own user's (SO_PEERCRED, Linux)."""
    opt = getattr(socket, "SO_PEERCRED", None)
    if opt is None:
        return
    cred = sock.getsockopt(socket.SOL_SOCKET, opt, struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", cred)
    want = 0 if os.environ.get("KEPR_SYSTEM_MODE") else os.geteuid()
    if uid != want:
        raise KeprError("the socket is not served by the expected credential daemon")


def _upper(name):
    if not isinstance(name, str) or not name:
        raise KeprError("credential name must be a non-empty string")
    return name.upper()


class Client:
    """``Client().get("OPENAI_API_KEY")`` and friends."""

    def __init__(self, path=None, timeout=_DEFAULT_TIMEOUT):
        self.path = path or socket_path()
        self.timeout = timeout

    def request(self, req):
        """Send one raw request dict (``{"cmd": ...}``); return the reply dict.

        Raises KeprError for an ``err`` reply.
        """
        payload = json.dumps(req).encode()
        if len(payload) > MAX_MSG_BYTES:
            raise KeprError("request too large")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect(self.path)
                _check_peer(s)
                s.sendall(struct.pack(">I", len(payload)) + payload)
                (n,) = struct.unpack(">I", _recv_exact(s, 4))
                if n > MAX_MSG_BYTES:
                    raise KeprError("reply too large")
                resp = json.loads(_recv_exact(s, n))
        except OSError as e:
            raise KeprError(
                "cannot reach the credential service at %s (%s); "
                "start it with `kepr-daemon --user`" % (self.path, e)
            ) from None
        if resp.get("kind") == "err":
            raise KeprError(resp.get("error", "request failed"))
        return resp

    def _expect(self, req, kind):
        resp = self.request(req)
        if resp.get("kind") != kind:
            if resp.get("kind") == "fido2_needed":
                raise KeprError("this credential needs a FIDO2 touch; use `kepr get`")
            raise KeprError("unexpected reply: %s" % resp.get("kind"))
        return resp

    # ── credentials ──────────────────────────────────────────────────

    def get(self, name):
        """The value of ``name`` (str)."""
        return self._expect({"cmd": "get", "name": _upper(name)}, "get_ok")["value"]

    def get_many(self, names):
        """``{NAME: value}`` for each name (one request per name)."""
        return {_upper(n): self.get(n) for n in names}

    def set(self, name, value=None, generate=None, ttl_secs=None, requires_consent=None,
            requires_fido2=None):
        """Store ``value``, or have the daemon generate one (``generate`` =
        ``"hex"|"base62"|"pass"|"uuid"|"words"``, default hex). A generated
        value is never sent back; read it with ``get`` if you need it."""
        req = {"cmd": "set", "name": _upper(name)}
        if value is not None and generate is not None:
            raise KeprError("pass a value or generate, not both")
        if value is not None:
            if not isinstance(value, str) or value == "":
                raise KeprError("value must be a non-empty string")
            req["value"] = value
        else:
            kind = generate or "hex"
            if kind not in GENERATE_KINDS:
                raise KeprError("generate must be one of %s" % ", ".join(GENERATE_KINDS))
            req["generate"] = kind
        if ttl_secs is not None:
            req["ttl_secs"] = int(ttl_secs)
        if requires_consent:
            req["requires_consent"] = True
        if requires_fido2:
            req["requires_fido2"] = True
        return self._expect(req, "set_ok")

    def delete(self, name):
        self._expect({"cmd": "delete", "name": _upper(name)}, "delete_ok")

    def list(self):
        """Credential records (name, size, modified, flags) as dicts — no values."""
        return self._expect({"cmd": "list"}, "list_ok")["credentials"]

    def credentials(self):
        """``list`` as :class:`CredInfo` objects (expiry, consent, sealed, type…)."""
        return [CredInfo(d) for d in self.list()]

    def info(self, name):
        """Metadata for one credential, or ``None`` if there is none by that name."""
        n = _upper(name)
        return next((c for c in self.credentials() if c.name == n), None)

    def fetch_fd(self, name):
        """Fetch ``name`` as a sealed in-memory file descriptor (plan T3.06).

        Returns ``(fd, length)``. The daemon applies the same checks as
        ``get``; the fd is close-on-exec, so children never inherit it.
        The caller owns the fd: read it (``os.pread(fd, length, 0)``) and
        ``os.close`` it. Needs a daemon with pull-on-demand fd delivery.
        """
        req = json.dumps({"cmd": FETCH_FD_CMD, "name": _upper(name)}).encode()
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect(self.path)
                _check_peer(s)
                s.sendall(struct.pack(">I", len(req)) + req)
                (n,) = struct.unpack(">I", _recv_exact(s, 4))
                if n > MAX_MSG_BYTES:
                    raise KeprError("reply too large")
                resp = json.loads(_recv_exact(s, n))
                if resp.get("kind") == "err":
                    raise KeprError(resp.get("error", "request failed"))
                if resp.get("kind") != _FD_OK:
                    raise KeprError("unexpected reply: %s" % resp.get("kind"))
                _, fds, _, _ = socket.recv_fds(s, 1, 1)
        except OSError as e:
            raise KeprError("cannot reach the credential service at %s (%s)" % (self.path, e)) \
                from None
        if len(fds) != 1:
            for fd in fds:
                os.close(fd)
            raise KeprError("the credential service sent no descriptor")
        os.set_inheritable(fds[0], False)
        return fds[0], int(resp.get("len", 0))

    def history(self, name):
        """Saved previous versions of ``name`` (no values)."""
        return self._expect({"cmd": "history", "name": _upper(name)}, "history_ok")["versions"]

    def restore(self, name, version):
        """Make history version ``version`` (1 = newest) current again."""
        self._expect(
            {"cmd": "restore", "name": _upper(name), "version": int(version)}, "restore_ok"
        )

    def usage(self, days=None):
        """Per-credential usage report from the audit log."""
        req = {"cmd": "usage"}
        if days is not None:
            req["days"] = int(days)
        return self._expect(req, "usage_ok")

    def health(self, max_age_days=None):
        """Weak / reused / old findings per credential (no values)."""
        req = {"cmd": "health"}
        if max_age_days is not None:
            req["max_age_days"] = int(max_age_days)
        return self._expect(req, "health_ok")["items"]

    # ── SSH keys (sign-only) ─────────────────────────────────────────

    def ssh_list(self):
        return self._expect({"cmd": "sshlist"}, "ssh_list_ok")["keys"]

    def ssh_sign(self, name, data):
        """OpenSSH signature blob over ``data`` (bytes); the key stays in the daemon."""
        resp = self._expect(
            {"cmd": "sshsign", "name": _upper(name), "data_b64": base64.b64encode(data).decode()},
            "ssh_sign_ok",
        )
        return base64.b64decode(resp["signature_b64"])

    # ── daemon ───────────────────────────────────────────────────────

    def status(self):
        return self._expect({"cmd": "status"}, "status_ok")

    def ping(self):
        self._expect({"cmd": "ping"}, "pong")
        return True
