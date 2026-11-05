# Kepr Integration Guides

## Overview

Comprehensive guides for integrating Kepr credential manager with browsers, applications, and services.

## Guides

### [Browser Integration](./BROWSER_INTEGRATION.md)
Integrate Kepr with Firefox, Chrome, and Chromium browsers.

- HTTP Proxy configuration
- Browser extension development
- Request interception
- Provider routing

**Use when:** You want to use Kepr-protected API keys in browser-based tools.

### [Application Integration](./APP_INTEGRATION.md)
Integrate Kepr with CLI tools and applications.

- Agent run pattern
- Exec pattern with memfd
- MCP server pattern
- Custom application integration
- Shim installation

**Use when:** You want to secure credentials for CLI tools, scripts, or custom apps.

### [Quick Reference](./QUICK_REFERENCE.md)
Essential commands and patterns for daily use.

- Common commands
- Provider routes
- Security checklist
- Troubleshooting

**Use when:** You need fast reference for Kepr usage.

## Quick Start

### 1. Seal a key for agents
```bash
kepr agent add OPENAI_API_KEY --for openai
```

### 2. Run protected
```bash
kepr agent run omp -- omp chat --model gpt-4
```

### 3. Browser proxy (optional)
Configure browser to use `http://127.0.0.1:20128` as proxy.

## Security Principles

1. **Never export keys** to environment variables
2. **Always use placeholders** in configs
3. **Run agents through kepr** for protection
4. **Audit regularly** with `kepr health`

## Support

For issues or questions:
- Check Kepr docs: `~/projects/kepr/docs/`
- Run `kepr doctor` for diagnostics
- Review security checklist in Quick Reference
