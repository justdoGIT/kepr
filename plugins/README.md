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
