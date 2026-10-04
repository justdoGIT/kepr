# kepr-client (Python)

A thin, dependency-free client for the local kepr daemon. It uses the same
Unix socket and wire format as the `kepr` CLI, so the daemon applies
the same rules: per-user namespacing by socket credentials, auditing,
consent prompts, and refusing to return sealed agent credentials or SSH keys.

```python
from kepr_client import Client, KeprError

kepr = Client()
token = kepr.get("GITHUB_TOKEN")
kepr.set("DB_PASSWORD", generate="pass", ttl_secs=3600)
for v in kepr.history("DB_PASSWORD"):
    print(v["version"], v["saved_at"])
print(kepr.usage(days=30)["keys"])
sig = kepr.ssh_sign("DEPLOY_KEY", b"data")   # key never leaves the daemon
```

Python strings cannot be wiped from memory, so keep values in scope briefly.
For a child process that only needs a key as configuration, `kepr exec` or
`kepr agent run` is the better tool.

Tests: `python3 -m unittest discover -s tests` (add `KEPR_SDK_LIVE=1` to
also run the round trip against a running daemon).
