# Application Integration with Kepr

## Overview

Integrate Kepr credential management with CLI tools, applications, and services.

## Integration Patterns

### 1. Agent Run Pattern

Wrap applications with kepr agent for full protection:

```bash
kepr agent run omp -- omp chat --model claude-opus
kepr agent run codex -- codex --model gpt-4
kepr agent run claude -- claude --model sonnet
```

**Benefits:**
- Secrets never enter process environment
- Keys injected at wire level via gate
- Full audit trail
- Per-request rate limiting

### 2. Exec Pattern

Inject secrets via memfd (anonymous memory files):

```bash
kepr exec --env OPENAI_API_KEY -- my-app
kepr exec --memfd OPENAI_API_KEY,ANTHROPIC_API_KEY -- my-app
```

**Benefits:**
- No environment variable exposure
- Secrets in anonymous memory, not /proc/environ
- Automatic cleanup after process exits

### 3. MCP Server Pattern

Use kepr's MCP server for programmatic access:

```bash
# Start MCP server
kepr mcp

# Client connects via stdio
# API calls routed through gate
# No secrets exposed
```

### 4. Database Connections

Seal database credentials:

```bash
kepr agent add-db DB_PASSWORD --url postgres://user@localhost/db
```

Application receives `DATABASE_URL` pointing to local gate port (e.g., 127.0.0.1:5432).

## Supported Harnesses

Kepr provides native support for:

- **Claude Code**: `kepr agent run claude`
- **Codex**: `kepr agent run codex`
- **OMP**: `kepr agent run omp`
- **Grok**: `kepr agent run grok`
- **Aider**: `kepr agent run aider`
- **Gemini**: `kepr agent run gemini`
- **Opencode**: `kepr agent run opencode`

## Custom Application Integration

### For OpenAI-Compatible APIs

```javascript
// Before: Direct API call
fetch('https://api.openai.com/v1/chat/completions', {
  headers: {
    'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`
  }
});

// After: Kepr-protected
fetch('http://127.0.0.1:20128/openai/v1/chat/completions', {
  headers: {
    'Authorization': 'Bearer KEPR_PH_OPENAI'
  }
});
```

### For Anthropic-Compatible APIs

```javascript
// Before
fetch('https://api.anthropic.com/v1/messages', {
  headers: {
    'x-api-key': process.env.ANTHROPIC_API_KEY
  }
});

// After
fetch('http://127.0.0.1:20128/anthropic/v1/messages', {
  headers: {
    'x-api-key': 'KEPR_PH_ANTHROPIC'
  }
});
```

## Shim Installation

Create PATH shims for automatic kepr protection:

```bash
kepr agent shim omp --dir ~/.local/share/kepr/shims
```

Add to PATH:
```bash
export PATH="$HOME/.local/share/kepr/shims:$PATH"
```

Now `omp` automatically runs through kepr.

## Security Best Practices

### ✅ DO

- Use `kepr agent run` for all agent invocations
- Use placeholders instead of real keys
- Seal keys with `kepr agent add`
- Use memfd for transient secret injection
- Audit with `kepr usage` and `kepr health`

### ❌ DON'T

- Export API keys to environment
- Use `kepr get` to retrieve keys
- Pass keys via CLI arguments
- Store keys in .env files
- Commit keys to git

## Examples

### Example 1: Node.js Application

```javascript
const API_KEY = 'KEPR_PH_OPENAI'; // Placeholder
const BASE_URL = 'http://127.0.0.1:20128/openai/v1';

const client = new OpenAI({
  apiKey: API_KEY,
  baseURL: BASE_URL
});
```

Run with:
```bash
kepr agent run node -- node app.js
```

### Example 2: Python Application

```python
import os
from openai import OpenAI

client = OpenAI(
  api_key='KEPR_PH_OPENAI',
  base_url='http://127.0.0.1:20128/openai/v1'
)
```

Run with:
```bash
kepr agent run python -- python app.py
```

### Example 3: Shell Script

```bash
#!/bin/bash
# Uses placeholder, real key injected by kepr-gate
export OPENAI_API_KEY="KEPR_PH_OPENAI"
curl http://127.0.0.1:20128/openai/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -d '{"model":"gpt-4","messages":[]}'
```

Run with:
```bash
kepr agent run bash -- ./script.sh
```

## Troubleshooting

**Keys not injecting:**
```bash
kepr agent ls  # Check keys sealed
kepr agent doctor  # Verify routing
```

**Gate not reachable:**
```bash
curl http://127.0.0.1:20128/health
```

**Permission errors:**
```bash
kepr status  # Check store locked
kepr unlock  # Unlock if needed
```
