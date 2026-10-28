"""Lock state and credential metadata from the kepr CLI's JSON output.

Pure functions, no iTerm2 import, so they test anywhere. There is no value in
`kepr status --json` or `kepr ls --json`, so none can be shown.
"""

import json
import re

_NAME = re.compile(r"^[A-Za-z0-9_]{1,128}$")


def parse_status(text):
    """Return (state, detail): state is 'locked', 'unlocked' or 'offline'."""
    try:
        reply = json.loads(text)
    except (ValueError, TypeError):
        return "offline", "kepr gave no JSON"
    if not isinstance(reply, dict):
        return "offline", "unexpected reply from kepr"
    if reply.get("kind") == "err":
        return "offline", str(reply.get("error", "kepr failed"))
    if reply.get("kind") != "status_ok":
        return "offline", "unexpected reply from kepr"
    if reply.get("locked"):
        return "locked", "Run `kepr unlock` in a terminal."
    if reply.get("password_protected"):
        return "unlocked", "unlocked"
    return "unlocked", "open (no passphrase set)"


def status_text(state):
    """The status bar string for a state."""
    return {
        "locked": "kepr: locked",
        "unlocked": "kepr: unlocked",
    }.get(state, "kepr: offline")


def parse_credentials(text):
    """Credential metadata from `kepr ls --json`, sorted by name.

    Raises ValueError on a daemon error or a reply that is not a list.
    """
    reply = json.loads(text)
    if not isinstance(reply, dict):
        raise ValueError("unexpected reply from kepr")
    if reply.get("kind") == "err":
        raise ValueError(str(reply.get("error", "kepr failed")))
    creds = reply.get("credentials")
    if reply.get("kind") != "list_ok" or not isinstance(creds, list):
        raise ValueError("unexpected reply from kepr")
    out = []
    for c in creds:
        if not isinstance(c, dict) or not isinstance(c.get("name"), str):
            continue
        out.append(
            {
                "name": c["name"],
                "modified": str(c.get("modified", "")),
                "expires_at": c.get("expires_at"),
                "record_type": c.get("record_type"),
                "tags": [str(t) for t in c.get("tags", []) if isinstance(c.get("tags"), list)],
                "sealed": c.get("sealed") is True,
            }
        )
    return sorted(out, key=lambda c: c["name"])


def copy_command(name):
    """argv for copying a credential through the CLI, or None for an unsafe name.

    `kepr copy` puts the value on the clipboard and clears it later; the
    script never reads it.
    """
    return ["kepr", "copy", name] if _NAME.match(name or "") else None
