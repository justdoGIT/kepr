---
name: kepr
description: How to work with API keys and other secrets when kepr manages them. Use when a task needs a credential, an API key, a token, a database password, or a .env file.
---

# Working with secrets under kepr

kepr keeps credentials in an encrypted store. In a session started with
`kepr agent run <harness>`, you never hold a real key:

- API key variables (`XAI_API_KEY`, `ANTHROPIC_API_KEY`, `GH_TOKEN`, …)
  contain **placeholders** that start with `kepr-ph-`. Use them exactly as
  they are. A local gate replaces them with the real key on the way to the
  provider, and only for that provider's host.
- `DATABASE_URL` / `PG*` point at a local gate port. Connect normally; the
  gate logs in to the real database.
- `KEPR_GATE_URL` is set. If it is missing, the session is not protected:
  say so and suggest `kepr agent run <harness>` (for example
  `kepr agent run claude`).

Rules:

1. Never ask the user to paste a key into the chat. Ask them to run
   `kepr agent add NAME` (for agent keys) or `kepr set NAME` in their own
   terminal instead.
2. Never print, echo, base64 or otherwise decode environment variables or
   `.env` files to look at secrets. Placeholders are useless outside the
   gate, and real keys must not reach the transcript.
3. Never write a key into a file, a command line or a commit. Reference the
   environment variable (`$XAI_API_KEY`, `process.env.XAI_API_KEY`).
4. `kepr get`, `kepr env`, `kepr exec`, `kepr totp`, `kepr inject`,
   `kepr copy`, `kepr record get`, `kepr share` and `kepr sync-push` are
   blocked in agent sessions because they reveal or move values. `kepr list`, `kepr agent ls` and `kepr status` are
   fine and show names only.
5. To call a provider API without any key in the environment, use the
   `kepr` MCP server's `call_api` tool; `list_secrets` shows what exists.
6. If you see something that looks like a real key anywhere, stop and tell
   the user to run `kepr leaked NAME`, which stops sessions and deletes it.


## Inspecting source and session history safely

Key-shaped examples in source, test output, diffs, and old conversations can
trigger the gate's 403 even when no live credential was exposed. Before showing
such text to the model, capture it locally and pass it to `kepr hook redact` as
JSON on stdin (`{"text": captured_text}`). Parse its JSON response and emit only
its `text` field after checking the exit status and field type. Never emit the
unfiltered output or redactor stderr on failure. Keep searches focused; the hook
accepts at most 10 MiB of JSON input. Do not use this to inspect credential files.

For example, inspect source with a bounded search:

```python
import json, subprocess
found = subprocess.run(["rg", "-n", "topic", "path/to/source"], capture_output=True, text=True)
checked = subprocess.run(
    ["kepr", "hook", "redact"],
    input=json.dumps({"text": found.stdout + found.stderr}),
    capture_output=True, text=True,
)
if checked.returncode:
    raise SystemExit("Secret check failed; output withheld")
result = json.loads(checked.stdout)
if not isinstance(result.get("text"), str):
    raise SystemExit("Invalid secret-check response; output withheld")
print(result["text"])
```

Use the shared detector, not a token-length-only regex: private-key blocks and
JSON-escaped keys need redaction too. Build synthetic test strings from short
fragments at runtime so tool calls themselves do not contain complete key shapes.
If a real credential is discovered, follow the `kepr leaked NAME` rule above.

An OpenAI Responses "different ... OpenAI resource" error is a separate upstream
conversation-state failure. Preserve item contents, tool-call links, and encrypted
reasoning; never fix it by deleting live history databases or disabling kepr.
Save a sanitized recovery note before a restart. Updated gates take effect for new
agent sessions; leave the current session's gate running while it is in use.
