# kepr-client (Node.js)

A thin client for the local kepr daemon with no dependencies. It uses the
same socket and wire format as the `kepr` CLI, so the daemon applies the same
rules (per-user namespacing, audit, consent, sealed keys never returned).

```js
const { Client } = require('kepr-client');
const kepr = new Client();
const token = await kepr.get('GITHUB_TOKEN');
await kepr.set('DB_PASSWORD', null, { generate: 'words', ttlSecs: 3600 });
await kepr.generate('SESSION_KEY', 'base62', { requiresConsent: true });
for (const c of await kepr.credentials()) {   // metadata only, never values
  console.log(c.name, c.recordType, c.expiresAt, c.sealed);
}
await kepr.delete('SESSION_KEY');
```

There is no `fetchFd` here: Node.js cannot receive file descriptors over a
Unix socket without a native addon. Use the Python or Go client, or
`kepr exec`, for fd delivery.

JavaScript strings can't be wiped from memory, so keep values in scope
briefly.

Tests: `npm test` (set `KEPR_SDK_LIVE=1` to also run the live round trip
against a daemon).
