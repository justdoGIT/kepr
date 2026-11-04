# Browser Integration with Kepr

## Overview

Integrate Kepr credential management with browsers (Firefox, Chrome, Chromium) for secure API access.

## HTTP Proxy Mode

### Firefox Configuration

Create user.js file in Firefox profile:

```javascript
// ~/.mozilla/firefox/*.default/user.js

// Enable manual proxy
user_pref("network.proxy.type", 1);
user_pref("network.proxy.http", "127.0.0.1");
user_pref("network.proxy.http_port", 20128);
user_pref("network.proxy.ssl", "127.0.0.1");
user_pref("network.proxy.ssl_port", 20128);
user_pref("network.proxy.socks", "127.0.0.1");
user_pref("network.proxy.socks_port", 20128);

// Bypass local addresses
user_pref("network.proxy.no_proxies_on", "localhost,127.0.0.1,::1");
```

**Kepr Gate Port:** Default is 20128, but varies based on kepr agent run session.

### Chrome/Chromium Configuration

Launch with proxy arguments:

```bash
google-chrome --proxy-server="http://127.0.0.1:20128" --proxy-bypass-list="localhost,127.0.0.1"
```

Or configure via `chrome://settings/system` > Proxy settings.

## Browser Extension

### Manifest v3 Extension

Create extension to intercept API requests:

**manifest.json:**
```json
{
  "manifest_version": 3,
  "name": "Kepr Secure API Proxy",
  "version": "1.0.0",
  "permissions": ["webRequest", "webRequestBlocking"],
  "host_permissions": [
    "*://api.openai.com/*",
    "*://api.anthropic.com/*",
    "*://api.x.ai/*",
    "*://api.groq.com/*"
  ],
  "background": {
    "service_worker": "background.js"
  }
}
```

**background.js:**
```javascript
const KEPR_GATE_URL = 'http://127.0.0.1:20128';
const PROVIDER_MAP = {
  'api.openai.com': '/openai/v1',
  'api.anthropic.com': '/anthropic',
  'api.x.ai': '/xai/v1'
};

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    const url = new URL(details.url);
    const path = PROVIDER_MAP[url.hostname];
    if (!path) return {};
    
    const newUrl = KEPR_GATE_URL + path + url.pathname + url.search;
    return { redirectUrl: newUrl };
  },
  { urls: ["*://api.*.com/*"] },
  ["blocking"]
);
```

Load unpacked extension in `chrome://extensions` or `about:debugging`.

## Supported Providers

Kepr gate routes for browsers:

| Domain | Kepr Path | Placeholder |
|--------|-----------|-------------|
| api.openai.com | /openai/v1 | KEPR_PH_OPENAI |
| api.anthropic.com | /anthropic | KEPR_PH_ANTHROPIC |
| api.x.ai | /xai/v1 | KEPR_PH_XAI |
| api.groq.com | /openai/v1 | KEPR_PH_GROQ |
| api.qronos.me | /anthropic | KEPR_PH_QRONOS |
| api.omniroute.com | /openai/v1 | KEPR_PH_OMNIROUTE |

## Security Notes

- Never export API keys to browser environment
- Kepr gate injects keys at wire level
- Browser only sees placeholder tokens
- Use HTTPS for all provider connections

## Troubleshooting

**Gate not reachable:**
```bash
curl http://127.0.0.1:20128/health
kepr agent doctor
```

**Keys not injecting:**
- Verify keys sealed: `kepr agent ls`
- Check provider routes configured
- Ensure `kepr agent run` is active
