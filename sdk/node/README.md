# kepr-client (Node.js)

A thin client for the local kepr daemon with no dependencies. It uses the
same socket and wire format as the `kepr` CLI, so the daemon applies the same
rules (per-user namespacing, audit, consent, sealed keys never returned).

```js
const { Client } = require('kepr-client');
const kepr = new Client();
const token = await kepr.get('GITHUB_TOKEN');
await kepr.set('DB_PASSWORD', null, { generate: 'words', ttlSecs: 3600 });
```

JavaScript strings can't be wiped from memory, so keep values in scope
briefly.

Tests: `npm test` (set `KEPR_SDK_LIVE=1` to also run the live round trip
against a daemon).
