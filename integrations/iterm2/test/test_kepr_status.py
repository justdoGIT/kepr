import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import kepr_status as k  # noqa: E402


class StatusTests(unittest.TestCase):
    def test_states(self):
        self.assertEqual(k.parse_status('{"kind":"status_ok","locked":true}')[0], "locked")
        self.assertEqual(
            k.parse_status('{"kind":"status_ok","locked":false,"password_protected":true}'), ("unlocked", "unlocked")
        )
        self.assertIn("no passphrase", k.parse_status('{"kind":"status_ok","locked":false}')[1])
        self.assertEqual(k.parse_status('{"kind":"err","error":"cannot connect"}'), ("offline", "cannot connect"))
        for bad in ["", "garbage", "[]", "null", '{"kind":"pong"}']:
            self.assertEqual(k.parse_status(bad)[0], "offline", bad)

    def test_text(self):
        self.assertEqual(k.status_text("locked"), "kepr: locked")
        self.assertEqual(k.status_text("unlocked"), "kepr: unlocked")
        self.assertEqual(k.status_text("anything else"), "kepr: offline")


class CredentialTests(unittest.TestCase):
    def test_metadata_sorted_and_without_values(self):
        text = json.dumps(
            {
                "kind": "list_ok",
                "credentials": [
                    {"name": "ZED", "modified": "m", "cred_name": "kepr-1-zed"},
                    {"name": "ALPHA", "tags": ["prod"], "sealed": True, "expires_at": "2027-01-01"},
                    None,
                    {"no": "name"},
                ],
            }
        )
        got = k.parse_credentials(text)
        self.assertEqual([c["name"] for c in got], ["ALPHA", "ZED"])
        self.assertTrue(got[0]["sealed"])
        self.assertEqual(got[0]["tags"], ["prod"])
        for c in got:
            self.assertFalse(any("value" in key or "secret" in key for key in c))

    def test_errors(self):
        with self.assertRaises(ValueError):
            k.parse_credentials('{"kind":"err","error":"locked"}')
        with self.assertRaises(ValueError):
            k.parse_credentials('{"kind":"pong"}')
        with self.assertRaises(ValueError):
            k.parse_credentials("[]")

    def test_copy_command_checks_the_name(self):
        self.assertEqual(k.copy_command("DB_PASS"), ["kepr", "copy", "DB_PASS"])
        for bad in ["", None, "a b", "a;b", "../x", "-rf", "A" * 129]:
            self.assertIsNone(k.copy_command(bad), bad)


if __name__ == "__main__":
    unittest.main()
