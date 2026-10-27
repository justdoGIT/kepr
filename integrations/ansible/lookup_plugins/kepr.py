# Ansible lookup plugin for the local kepr credential daemon (plan T8.04).
# Uses the kepr Python client (sdk/python in the kepr repository).
from __future__ import annotations

DOCUMENTATION = r"""
name: kepr
author: kepr contributors
short_description: read credentials from the local kepr daemon
description:
  - Returns the value of each kepr credential named in the terms.
  - A term is C(NAME), C(kepr://NAME), or C(kepr://NAME/field) for one string
    field of a typed record (C(kepr record add)).
  - The daemon decides what the calling user may read; sealed agent keys and
    SSH keys are never returned, and consent-gated credentials prompt.
options:
  _terms:
    description: credential names or kepr:// references
    required: true
  socket_path:
    description: daemon socket (default as for the kepr CLI)
    type: str
    env:
      - name: KEPR_SOCKET
  timeout:
    description: seconds to wait for the daemon (covers a consent prompt)
    type: float
    default: 65
notes:
  - Values are secrets. Use C(no_log: true) on tasks that receive them.
  - Install the client with C(pip install ./sdk/python) on the controller.
"""

EXAMPLES = r"""
- name: Use an API token
  ansible.builtin.uri:
    url: https://api.example.com/v1/items
    headers:
      Authorization: "Bearer {{ lookup('kepr', 'API_TOKEN') }}"
  no_log: true

- name: One field of a database record
  ansible.builtin.set_fact:
    db_password: "{{ lookup('kepr', 'kepr://PROD_DB/password') }}"
  no_log: true
"""

RETURN = r"""
_raw:
  description: one value per term
  type: list
  elements: str
"""

import json
import os
import re
import sys

from ansible.errors import AnsibleLookupError
from ansible.plugins.lookup import LookupBase

try:
    from kepr_client import Client, KeprError
except ImportError:  # running from a kepr checkout: use its SDK
    _sdk = os.path.join(os.path.dirname(__file__), "..", "..", "..", "sdk", "python")
    if os.path.isdir(os.path.join(_sdk, "kepr_client")):
        sys.path.insert(0, os.path.abspath(_sdk))
        from kepr_client import Client, KeprError
    else:
        Client = None

        class KeprError(Exception):
            pass


PREFIX = "kepr://"
_NAME = re.compile(r"^[A-Za-z0-9_]{1,128}$")
_FIELD = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def parse_term(term):
    """``NAME`` / ``kepr://NAME`` / ``kepr://NAME/field`` → (NAME, field or None)."""
    if not isinstance(term, str):
        raise AnsibleLookupError("kepr: each term must be a string")
    body = term[len(PREFIX):] if term.startswith(PREFIX) else term
    name, sep, field = body.partition("/")
    if not _NAME.match(name):
        raise AnsibleLookupError("kepr: invalid credential name %r" % name)
    if sep and not _FIELD.match(field):
        raise AnsibleLookupError("kepr: invalid field in %r" % term)
    return name.upper(), (field if sep else None)


def field_of(name, value, field):
    """One string field of a typed record (same rule as `kepr record get`)."""
    try:
        obj = json.loads(value)
    except ValueError:
        obj = None
    if not isinstance(obj, dict):
        raise AnsibleLookupError("kepr: %s is not a record" % name)
    v = obj.get(field)
    if not isinstance(v, str):
        raise AnsibleLookupError("kepr: %s has no field %r" % (name, field))
    return v


class LookupModule(LookupBase):
    @staticmethod
    def _new_client(path, timeout):
        if Client is None:
            raise AnsibleLookupError(
                "kepr: the kepr Python client is not installed (pip install ./sdk/python)"
            )
        return Client(path=path, timeout=timeout)

    def run(self, terms, variables=None, **kwargs):
        self.set_options(var_options=variables, direct=kwargs)
        timeout = float(self.get_option("timeout") or 65)
        client = self._new_client(self.get_option("socket_path"), timeout)
        out = []
        for term in terms:
            name, field = parse_term(term)
            try:
                value = client.get(name)
            except KeprError as e:
                raise AnsibleLookupError("kepr: %s: %s" % (name, e)) from None
            out.append(value if field is None else field_of(name, value, field))
        return out
