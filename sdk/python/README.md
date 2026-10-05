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

kepr.set("API_TOKEN", "value-from-elsewhere", requires_consent=True)
for c in kepr.credentials():                  # metadata only, never values
    print(c.name, c.record_type, c.expires_at, c.sealed)
print(kepr.info("API_TOKEN").modified)
kepr.delete("API_TOKEN")

fd, n = kepr.fetch_fd("DB_PASSWORD")          # sealed memfd, close-on-exec
try:
    password = os.pread(fd, n, 0)
finally:
    os.close(fd)
```

`fetch_fd` needs a daemon with pull-on-demand fd delivery (plan T3.06);
older daemons answer it with an error.

Python strings cannot be wiped from memory, so keep values in scope briefly.
For a child process that only needs a key as configuration, `kepr exec` or
`kepr agent run` is the better tool.

Tests: `python3 -m unittest discover -s tests` (add `KEPR_SDK_LIVE=1` to
also run the round trip against a running daemon).
