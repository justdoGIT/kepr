# Kepr Quick Reference

## Essential Commands

### Store Management
```bash
kepr list                    # List stored credentials
kepr get KEY --quiet          # Get key value (avoid!)
kepr set KEY --value "..."    # Store credential
kepr delete KEY               # Delete credential
kepr lock | unlock | status   # Manage store lock
```

### Agent Operations
```bash
kepr agent add KEY [--for PROVIDER]  # Seal key for agents
kepr agent ls                        # List sealed keys
kepr agent run HARNESS -- CMD        # Run with protection
kepr agent shim HARNESS              # Create PATH shim
kepr agent doctor                    # Check setup
```

### Secure Execution
```bash
kepr exec --env KEY1,KEY2 -- CMD    # Inject secrets via env
kepr exec --memfd KEY1,KEY2 -- CMD  # Inject via memfd (safer)
```

## Provider Routes

| Provider | Domain | Kepr Path | Placeholder |
|----------|--------|-----------|-------------|
| OpenAI | api.openai.com | /openai/v1 | KEPR_PH_OPENAI |
| Anthropic | api.anthropic.com | /anthropic | KEPR_PH_ANTHROPIC |
| xAI | api.x.ai | /xai/v1 | KEPR_PH_XAI |
| Groq | api.groq.com | /openai/v1 | KEPR_PH_GROQ |
| Qronos | api.qronos.me | /anthropic | KEPR_PH_QRONOS |
| Omniroute | api.omniroute.com | /openai/v1 | KEPR_PH_OMNIROUTE |
| DLAB | api.dlabkeys.com | /openai/v1 | KEPR_PH_DLAB |

## Shell Integration

### .agentrc
Centralize agent wrappers:
```bash
# ~/.agentrc
omp() { kepr agent run omp "$@"; }
codex() { kepr agent run codex "$@"; }
```

Source from ~/.profile:
```bash
[ -e "$HOME/.agentrc" ] && source "$HOME/.agentrc"
```

## Common Patterns

### ✅ Correct
```bash
kepr agent run omp -- omp chat --model claude
kepr exec --env OPENAI_API_KEY -- my-app
```

### ❌ Wrong
```bash
export OPENAI_API_KEY="$(kepr get OPENAI_API_KEY --quiet)"
my-app  # Key exposed in /proc/environ
```

## Security Checklist

- [ ] No `kepr get` used to export keys
- [ ] All agents use `kepr agent run`
- [ ] Keys sealed with `kepr agent add`
- [ ] Placeholders used in configs
- [ ] Browser proxy configured (if needed)
- [ ] Regular audits with `kepr health`

## Troubleshooting

```bash
kepr status      # Check store
kepr agent doctor  # Check routing
kepr usage       # Check usage
kepr health      # Security audit
```
