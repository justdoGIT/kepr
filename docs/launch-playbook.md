# Kepr Open-Source Launch Playbook & Campaign Strategy

## Launch Overview & Positioning
**Tagline:** *Kepr — The Developer-Native Secret Vault That Kills `.env` Leaks*

Kepr solves the core security flaws of traditional secret management for local developers and AI coding agents:
1. Plaintext `.env` files lying unencrypted in workspace directories.
2. Secret leakage through `/proc/<pid>/environ`, shell history (`export KEY=...`), and child process environment tables.
3. LLM coding agents (Claude Code, Cursor, Windsurf, Aider) capturing raw secret strings in context windows.

---

## Channel 1: Show HN (Hacker News)

**Title:** `Show HN: Kepr – Secret vault for Linux/macOS that kills .env file leaks`

**Body:**
> Hey HN,
>
> We built Kepr (https://github.com/aikepeer/kepr) because storing secrets in `.env` files or standard environment variables (`export API_KEY=...`) leaves them exposed to every same-UID process inspecting `/proc/<pid>/environ`, terminal history, and AI coding agent context logs.
>
> Kepr is a per-user, cross-platform secret manager written in Rust (`kepr` CLI, user/root `kepr-daemon`, `git-credential-kepr`, `docker-credential-kepr`, and `kepr-eso-provider`).
>
> Key technical highlights:
> - **RAM Delivery (`kepr exec --memfd`)**: Pass secrets to child processes as sealed, read-only memory file descriptors (`memfd_create` + `F_ADD_SEALS`). Secrets exist strictly in RAM and never touch environment tables.
> - **AI Agent Protection (`kepr protect-agent`)**: Intercepts Claude Code, Cursor, Windsurf, and Aider invocations to inject API keys via RAM without exposing raw strings to LLM prompts.
> - **Zero `sudo` Required**: Runs as a standalone user-mode daemon over a Unix socket (`0600` permissions) with kernel-attested peer authentication (`SO_PEERCRED` / `LOCAL_PEERCRED`).
> - **Argon2id Key Wrapping**: Option to lock the store at rest (`kepr lock`) with Argon2id + AES-256-GCM.
>
> We'd love feedback on the memory sealing design and multi-platform architecture!
>
> Repo: https://github.com/aikepeer/kepr  
> Docs: https://kepr.dev

---

## Channel 2: Reddit (`r/rust`, `r/linux`, `r/netsec`, `r/devops`, `r/LocalLLaMA`)

### Post Title (`r/rust`):
`Kepr: A Rust credential manager that uses Linux memfd seals to eliminate environment variable secret leaks`

### Key Post Points:
- Pure Rust implementation using `aes-gcm`, `argon2`, `sha2`, `hmac`, and `zeroize`.
- Zero-copy, zeroize-on-drop throughout the crypto pipeline.
- Benchmark: CLI round-trip to user daemon < 1.2 ms.

---

## Channel 3: Product Hunt & X (Twitter)

### X (Twitter) Thread Structure:
1. **Hook**: "Stop putting API keys in `.env` files. Here's why and how we fixed it with Linux `memfd` memory sealing in Rust."
2. **Problem**: Graphic showing `/proc/self/environ` reading secret keys.
3. **Solution**: `kepr exec --memfd OPENAI_API_KEY -- python app.py` -> Clean `/proc` output!
4. **AI Agents**: `kepr protect-agent claude` protecting Claude Code from dumping tokens into prompt logs.
5. **Call to Action**: Star on GitHub -> https://github.com/aikepeer/kepr

---

## Launch Checklist
- [x] All 230+ unit tests passing on release profile.
- [x] Zero clippy warnings across workspace (`-D warnings`).
- [x] `memfd` RAM delivery verified against `/proc/<pid>/environ`.
- [x] `.github/workflows/*.yml` pinned to 40-character commit SHAs.
- [x] Docs site ready at Fumadocs/Next.js (`docs/`).
