# Harness plugins

kepr ships a plugin for two agent harnesses. `kepr agent install omp|grok`
installs the copy embedded in the `kepr` binary, so plugin and binary
always match. Both plugins ask `kepr hook` for decisions (`src/cli_hook.rs`).

| Directory | Harness | Format |
| --- | --- | --- |
| `omp/kepr/` | oh-my-pi (`omp`) | TypeScript extension, `package.json` `omp.extensions` |
| `grok/kepr/` | Grok Build (`grok`) | `.grok-plugin/plugin.json`, `hooks/hooks.json`, `.mcp.json`, `skills/` |

What they do, and their limits, is described in
`docs/content/docs/guides/ai-agents.mdx` under "Plugins for omp and Grok
Build". In short: they stop the obvious ways a secret reaches the model
(a pasted key, `kepr get`, a key in a tool call). The boundary is still the
gate and the sandbox of `kepr agent run`.

The omp context hook redacts text in user, assistant, and tool-result messages,
including unsigned thinking text and tool arguments. It preserves tool-call identifiers,
image data, and reasoning signatures. A failed redaction check withholds text;
it does not send unchecked content. Signed thinking that requires redaction is
refused because changing its text would invalidate its signature. Run the tests with Node 24:
`node --test plugins/omp/kepr/index.test.mjs`.

The gate also redacts key-shaped conversation text for Responses, Chat
Completions, and Messages requests. Stored credentials, canaries, unsafe headers,
and key shapes outside supported text fields still block the request. Changed
requests carry replacement markers and the response header `x-kepr-redactions`.
The local saved conversation is not rewritten.

For AgentRouter's specific Responses resource-mismatch 400, the gate retries
once without saved item IDs when every item contains its portable content.
Messages, tool-call links and encrypted reasoning remain intact. Requests using
`previous_response_id`, `conversation`, references, or unsupported items are not
retried. Authentication failures are not retried. The retry counts toward request
limits and is reported by `x-kepr-responses-retry: item-ids`. A persistent mismatch
still requires the upstream provider to use the resource that owns its state.

Install by hand, without `kepr agent install`:

```bash
# omp: copy the directory where omp discovers extensions
cp -r plugins/omp/kepr ~/.omp/agent/extensions/kepr
# Grok Build
grok plugin validate plugins/grok/kepr
grok plugin install ./plugins/grok/kepr --trust
```

Neither plugin makes network calls or has dependencies; both need `kepr`
on `PATH` (the omp extension also honours `KEPR_BIN`).

`grok/kepr/skills/kepr/SKILL.md` is written for any harness and is the one
source of kepr's guidance for the model. `kepr agent install claude` writes
it as a Claude Code skill (`${CLAUDE_CONFIG_DIR:-~/.claude}/skills/kepr/SKILL.md`),
and `kepr agent install codex` puts its body, without the front matter,
between `<!-- kepr:begin -->` and `<!-- kepr:end -->` in
`${CODEX_HOME:-~/.codex}/AGENTS.md`; the rest of that file is left as it is.
