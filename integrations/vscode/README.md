# kepr for VS Code

- **Hover** a `kepr://NAME` or `kepr://NAME/field` reference (the notation
  `kepr inject` fills) to see the credential's type, the field, tags, expiry,
  last change and policy flags (sealed, consent, FIDO2). Unknown names and
  fields on non-records are flagged. Values are never shown.
- **kepr: List credentials** opens a quick pick of your credentials
  (metadata only); picking one inserts its `kepr://NAME` reference, or copies
  it when no editor is open.
- **Status bar**: locked / unlocked / offline, refreshed every 30 s or on
  click (**kepr: Refresh lock state**).

The extension talks to the local daemon through the kepr Node SDK
(`sdk/node`) and only sends `list` and `status` requests; it has no code
path that reads a value. Hovers share one listing per 15 s, since every
request is audited. Setting: `kepr.socketPath` (empty = the CLI's default).

## Build

```bash
cd integrations/vscode
npm test                    # notation matcher, hover text, activation (fake client + API stub)
npm install                 # links kepr-client from ../../sdk/node
npx @vscode/vsce package    # kepr-vscode-0.1.0.vsix
```
