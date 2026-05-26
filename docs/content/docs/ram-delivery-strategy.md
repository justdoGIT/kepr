# RAM-Based API Key Delivery — Strategy & Design

**Status:** Draft  
**Date:** 2026-05-26  
**Target:** kepr v0.4.0+

## Problem

Currently `kepr exec` passes secrets as **environment variables**. Environment
variables leak through:

- `/proc/<pid>/environ` (readable by same-UID processes)
- Shell history (`export KEY=...`)
- Process listings (`ps auxww`)
- Debug logs that dump the environment
- Child processes inheriting the full env

The goal: software that needs an API key gets it **directly in RAM**, with no
shell involvement and no environment variable exposure.

## Solution: Three-Tier Delivery

### Tier 1: `kepr exec --memfd` — memfd-backed file descriptors

Instead of environment variables, secrets are placed in sealed memory file
descriptors (memfd). The child process reads from the fd directly.

```
kepr exec --memfd OPENAI_API_KEY,ANTHROPIC_API_KEY -- ./my-app
```

**How it works (per credential):**

1. `memfd_create("kepr_OPENAI_API_KEY", MFD_CLOEXEC)` — creates anonymous
   in-memory file, auto-closed on exec unless we clear CLOEXEC
2. Write secret → `ftruncate` + `write`  
3. `fcntl(F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL)`
   — locks the fd: no writes, no resize, no unsealing. Read-only for the child.
4. Pass fd number via `KEPR_FD_OPENAI_API_KEY=3` env var (fd number only,
   **not** the secret)
5. Child reads from `/dev/fd/3` or `/proc/self/fd/3`

**Security properties:**
- Secret never in `/proc/<pid>/environ` — only an fd number
- memfd is sealed read-only — child can't modify or leak it further
- `MFD_CLOEXEC` can be cleared only for the specific fds we pass
- On process exit, kernel reclaims the memfd
- Defense-in-depth: `prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY)` prevents
  `gdb`/`strace` snooping (optional)

### Tier 2: `kepr serve` — lightweight sidecar socket

For long-running applications, a sidecar that serves secrets on demand.

```
kepr serve --socket /run/user/1000/kepr-sidecar.sock &
```

**Protocol:** Same framed JSON as the main daemon, but:
- Only serves `Get` requests (no Set/Delete/List)
- Can enforce process-level ACLs (check peer PID → binary path)
- Auto-expires after idle timeout

**Client integration (Rust):**
```rust
let key = kepr_sidecar::get("OPENAI_API_KEY")?;
```

**Client integration (Python):**
```python
import kepr
api_key = kepr.get("OPENAI_API_KEY")
```

### Tier 3: Language-specific SDKs

Thin wrappers that know how to reach kepr:

| Language   | Package          | Transport       |
|-----------|------------------|-----------------|
| Rust      | `kepr-client`    | Unix socket     |
| Python    | `kepr-py`        | Sidecar socket  |
| Node.js   | `kepr-js`        | Sidecar socket  |
| Go        | `kepr-go`        | Sidecar socket  |

Each SDK:
1. Checks `KEPR_FD_*` env vars first (memfd mode)
2. Falls back to sidecar socket at well-known path
3. Falls back to `kepr` CLI subprocess as last resort

## LLM Model Integration

### OpenAI

```python
# Before: key in env
client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])

# After: key from kepr memfd
import kepr
client = OpenAI(api_key=kepr.get("OPENAI_API_KEY"))
```

```bash
# CLI mode
kepr exec --memfd OPENAI_API_KEY -- python my_llm_app.py
```

### Anthropic, Google AI, Mistral, Cohere, etc.

Same pattern — all accept API keys as constructor parameters. The kepr SDK
abstracts the transport so the application code is identical whether using
memfd, sidecar, or subprocess fallback.

## Enterprise Software Integration

### Docker / Kubernetes

```
# Sidecar pattern in pod
containers:
  - name: app
    env:
      - name: KEPR_SIDECAR_SOCKET
        value: /run/kepr-sidecar.sock
  - name: kepr-sidecar
    image: kepr-sidecar:latest
    volumeMounts:
      - name: kepr-socket
        mountPath: /run
```

### CI/CD (GitHub Actions, GitLab CI)

```yaml
- name: Provision secrets
  run: |
    kepr exec --memfd NPM_TOKEN,DOCKER_TOKEN -- \
      bash -c 'npm publish --token=$(cat /dev/fd/$KEPR_FD_NPM_TOKEN)'
```

### systemd services

```
[Service]
ExecStart=/usr/local/bin/kepr exec --memfd DB_PASSWORD -- /usr/bin/my-server
PrivateTmp=yes
ProtectSystem=strict
```

## Implementation Phases

### Phase 1 (v0.4.0): `kepr exec --memfd`
- `cli_exec.rs`: Add `--memfd` flag alongside existing `--env` flag
- memfd creation + sealing in `exec` module
- Pass fd numbers as `KEPR_FD_<NAME>` env vars
- Tests: verify fd is sealed, secret not in environ, child can read

### Phase 2 (v0.5.0): `kepr serve` sidecar
- `daemon_sidecar.rs`: Lightweight listener
- Process-level ACL via `/proc/<pid>/exe` resolution
- Idle timeout + auto-shutdown

### Phase 3 (v0.6.0): Language SDKs
- `kepr-py` (Python package, PyPI)
- `kepr-js` (Node.js package, npm)
- `kepr-go` (Go module)

## Comparison with Alternatives

| Approach              | Env leak? | Shell needed? | /proc exposure? | Memory wipe? |
|----------------------|-----------|---------------|-----------------|--------------|
| `export KEY=...`     | Yes       | Yes           | Yes             | No           |
| `kepr exec --env`    | Yes       | No            | Yes             | Yes (ZeroString) |
| `kepr exec --memfd`  | No        | No            | No              | Yes (memfd seal) |
| `kepr serve` sidecar | No        | No            | No              | Yes (in-process) |
| HashiCorp Vault      | Partial   | No            | No              | Depends       |
