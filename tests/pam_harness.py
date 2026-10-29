#!/usr/bin/env python3
"""pam_harness.py — drive libpam from tests/pam_e2e.sh.

pamtester can't set PAM items between calls, so it can't play `sudo -u`
(the session is for another user than the one who authenticated) or a
password change (old and new tokens), and it hides the module's messages.

    pam_harness.py SERVICE USER STEP...

Steps, run in order on one PAM handle:
    user=NAME      pam_set_item(PAM_USER)
    authtok=PW     what tests/pam_setitems.so makes PAM_AUTHTOK at the next
                   auth / chauthtok call (libpam lets only modules set it)
    oldtok=PW      the same for PAM_OLDAUTHTOK
    auth | setcred | open | close | chauthtok | silent-chauthtok
Prints `STEP=rc` for each call and `INFO: text` for each message the
modules show the user. Exits 0 whatever the PAM stack answered; the caller
reads the lines.
"""
import ctypes
import os
import sys
from ctypes import (CFUNCTYPE, POINTER, Structure, c_char_p, c_int, c_void_p,
                    cast, sizeof)

PAM_USER = 2
PAM_TEXT_INFO, PAM_ERROR_MSG = 4, 3
PAM_SILENT = 0x8000
PAM_ESTABLISH_CRED = 0x2


class Message(Structure):
    _fields_ = [("msg_style", c_int), ("msg", c_char_p)]


class Response(Structure):
    _fields_ = [("resp", c_char_p), ("resp_retcode", c_int)]


Conv = CFUNCTYPE(c_int, c_int, POINTER(POINTER(Message)), POINTER(POINTER(Response)), c_void_p)


class PamConv(Structure):
    _fields_ = [("conv", Conv), ("appdata", c_void_p)]


libc = ctypes.CDLL(None)
libc.calloc.restype = c_void_p
libc.calloc.argtypes = [ctypes.c_size_t, ctypes.c_size_t]
# Global, like a real PAM client: modules resolve pam_get_item() etc. from it.
pam = ctypes.CDLL("libpam.so.0", mode=ctypes.RTLD_GLOBAL)
pam.pam_start.argtypes = [c_char_p, c_char_p, POINTER(PamConv), POINTER(c_void_p)]
pam.pam_set_item.argtypes = [c_void_p, c_int, c_char_p]
for fn in ("pam_authenticate", "pam_setcred", "pam_open_session",
           "pam_close_session", "pam_chauthtok", "pam_end"):
    getattr(pam, fn).argtypes = [c_void_p, c_int]


def talk(n, msgs, resp, _data):
    arr = libc.calloc(n, sizeof(Response))  # libpam frees it
    resp[0] = cast(arr, POINTER(Response))
    for i in range(n):
        m = msgs[i][0]
        if m.msg_style in (PAM_TEXT_INFO, PAM_ERROR_MSG):
            print("INFO: " + (m.msg or b"").decode(errors="replace"), flush=True)
    return 0


def main(argv):
    if len(argv) < 3:
        sys.exit(__doc__)
    service, user, steps = argv[0], argv[1], argv[2:]
    conv = PamConv(Conv(talk), None)
    h = c_void_p()
    rc = pam.pam_start(service.encode(), user.encode(), ctypes.byref(conv), ctypes.byref(h))
    if rc != 0:
        sys.exit(f"pam_start failed: {rc}")
    calls = {
        "auth": lambda: pam.pam_authenticate(h, 0),
        "setcred": lambda: pam.pam_setcred(h, PAM_ESTABLISH_CRED),
        "open": lambda: pam.pam_open_session(h, 0),
        "close": lambda: pam.pam_close_session(h, 0),
        "chauthtok": lambda: pam.pam_chauthtok(h, 0),
        "silent-chauthtok": lambda: pam.pam_chauthtok(h, PAM_SILENT),
    }
    tokens = {"authtok": "KEPR_TEST_AUTHTOK", "oldtok": "KEPR_TEST_OLDTOK"}
    for step in steps:
        key, _, val = step.partition("=")
        if key == "user":
            print(f"user={pam.pam_set_item(h, PAM_USER, val.encode())}", flush=True)
        elif key in tokens:
            os.environ[tokens[key]] = val  # read by pam_setitems.so
        elif step in calls:
            print(f"{step}={calls[step]()}", flush=True)
        else:
            sys.exit(f"unknown step {step}")
    pam.pam_end(h, 0)


main(sys.argv[1:])
