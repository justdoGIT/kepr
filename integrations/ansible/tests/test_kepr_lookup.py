"""Unit tests for the kepr lookup plugin with a fake client and stub
Ansible modules (Ansible itself is not needed to run them)."""

import importlib.util
import os
import sys
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PLUGIN = os.path.join(HERE, "..", "lookup_plugins", "kepr.py")


def _stub_ansible():
    """Minimal stand-ins for the Ansible APIs the plugin uses."""
    if "ansible.plugins.lookup" in sys.modules:
        return
    errors = types.ModuleType("ansible.errors")

    class AnsibleError(Exception):
        pass

    class AnsibleLookupError(AnsibleError):
        pass

    errors.AnsibleError = AnsibleError
    errors.AnsibleLookupError = AnsibleLookupError

    lookup = types.ModuleType("ansible.plugins.lookup")

    class LookupBase:
        def __init__(self, *a, **k):
            self._options = {}

        def set_options(self, var_options=None, direct=None):
            self._options = dict(direct or {})

        def get_option(self, name):
            return self._options.get(name)

    lookup.LookupBase = LookupBase
    sys.modules["ansible"] = types.ModuleType("ansible")
    sys.modules["ansible.errors"] = errors
    sys.modules["ansible.plugins"] = types.ModuleType("ansible.plugins")
    sys.modules["ansible.plugins.lookup"] = lookup


def _load_plugin():
    _stub_ansible()
    spec = importlib.util.spec_from_file_location("kepr_lookup", PLUGIN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


plugin = _load_plugin()


class FakeClient:
    """Stands in for kepr_client.Client."""

    def __init__(self, path=None, timeout=None):
        self.path = path
        self.timeout = timeout
        self.asked = []

    def get(self, name):
        self.asked.append(name)
        values = {
            "API_TOKEN": "t0k",
            "DB": '{"user": "app", "password": "pw", "port": 5432}',
        }
        if name.upper() not in values:
            raise plugin.KeprError("credential unavailable")
        return values[name.upper()]


class LookupTests(unittest.TestCase):
    def run_lookup(self, terms, **kwargs):
        lk = plugin.LookupModule()
        made = []

        def factory(path, timeout):
            c = FakeClient(path, timeout)
            made.append(c)
            return c

        lk._new_client = factory
        return lk.run(terms, variables={}, **kwargs), made

    def test_plain_names_and_references(self):
        out, made = self.run_lookup(["api_token", "kepr://API_TOKEN", "kepr://DB/user"])
        self.assertEqual(out, ["t0k", "t0k", "app"])
        self.assertEqual(made[0].asked, ["API_TOKEN", "API_TOKEN", "DB"])

    def test_record_field_must_be_a_string_field(self):
        out, _ = self.run_lookup(["kepr://DB/password"])
        self.assertEqual(out, ["pw"])
        for bad in ["kepr://DB/port", "kepr://DB/nope", "kepr://API_TOKEN/user"]:
            with self.assertRaises(plugin.AnsibleLookupError) as cm:
                self.run_lookup([bad])
            self.assertNotIn("pw", str(cm.exception))
            self.assertNotIn("t0k", str(cm.exception))

    def test_refusals_are_lookup_errors_without_values(self):
        with self.assertRaisesRegex(plugin.AnsibleLookupError, "MISSING: credential unavailable"):
            self.run_lookup(["missing"])

    def test_bad_terms(self):
        for bad in ["", "kepr://", "../etc/passwd", "kepr://A/b/c", "A B", 42]:
            with self.assertRaises(plugin.AnsibleLookupError, msg=repr(bad)):
                self.run_lookup([bad])

    def test_options_reach_the_client(self):
        _, made = self.run_lookup(["API_TOKEN"], socket_path="/run/kepr/kepr.sock", timeout=5)
        self.assertEqual(made[0].path, "/run/kepr/kepr.sock")
        self.assertEqual(made[0].timeout, 5.0)

    def test_parse_term(self):
        self.assertEqual(plugin.parse_term("db"), ("DB", None))
        self.assertEqual(plugin.parse_term("kepr://db/User"), ("DB", "User"))


@unittest.skipUnless(os.environ.get("KEPR_SDK_LIVE"), "set KEPR_SDK_LIVE=1 with a running daemon")
class LiveTests(unittest.TestCase):
    def test_round_trip(self):
        c = plugin.Client()
        name = "ANSIBLE_LIVE_%d" % os.getpid()
        c.set(name, '{"user": "u1"}')
        try:
            lk = plugin.LookupModule()
            self.assertEqual(lk.run([name, PREFIX_REF % name], variables={}),
                             ['{"user": "u1"}', "u1"])
        finally:
            c.delete(name)


PREFIX_REF = "kepr://%s/user"

if __name__ == "__main__":
    unittest.main()
