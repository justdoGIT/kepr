// cli_hook.rs — `kepr hook pre-tool|prompt|session-start`: the policy
// behind the omp and Grok Build plugins (plugins/). Reads the harness's
// hook JSON on stdin (Claude Code / Grok Build shape: `tool_name`,
// `tool_input` or Grok's `toolInput`, `prompt`) and answers the way those
// hooks expect:
//   exit 0           allow (session-start prints JSON with extra context)
//   exit 2 + stderr  block; stderr is shown to the model or the user
//
//   pre-tool       blocks shell commands that would print stored values
//                  (`kepr get`, `kepr env`, `kepr exec`, …) and any tool
//                  call whose input carries an API-key or private-key shape
//   prompt         blocks a prompt with a key in it before it reaches the
//                  model, and says how to store the key instead
//   session-start  tells the model how credentials work in this session
//   redact         `{"text"}` → `{"text", "found"}` with every key removed
//                  (omp's `context` event: covers non-interactive runs)
//
// This is a guard for unsandboxed runs, not the boundary: under `kepr
// agent run` the sandbox hides the daemon socket and the agent only ever
// holds placeholders. Unreadable input is allowed (exit 0) for that reason.

use std::io::Read;

use serde_json::{json, Value};

/// kepr verbs whose output (or side effect) is a stored value.
const REVEALING: &[&str] = &[
    "get",
    "env",
    "exec",
    "totp",
    "inject",
    "copy",
    "recovery-kit",
    "recovery-key",
    "record",
    // These move a value somewhere the agent may control.
    "share",
    "sync-push",
];

pub enum Verdict {
    Allow,
    Block(String),
    Context(String),
}

/// Words of a shell command, split on whitespace and shell operators.
/// Deliberately rough: over-matching only blocks, it never allows more.
fn words(cmd: &str) -> Vec<&str> {
    cmd.split(|c: char| c.is_whitespace() || ";|&()`$<>\"'{}".contains(c))
        .filter(|w| !w.is_empty())
        .collect()
}

/// The first revealing kepr verb in `cmd`, if any.
pub fn revealing_verb(cmd: &str) -> Option<&str> {
    let w = words(cmd);
    w.iter().enumerate().find_map(|(i, word)| {
        if word.rsplit('/').next() != Some("kepr") {
            return None;
        }
        let verb = w[i + 1..].iter().find(|a| !a.starts_with('-'))?;
        REVEALING.contains(verb).then_some(*verb)
    })
}

fn strings<'a>(v: &'a Value, out: &mut Vec<&'a str>) {
    match v {
        Value::String(s) => out.push(s),
        Value::Array(a) => a.iter().for_each(|x| strings(x, out)),
        Value::Object(o) => o.values().for_each(|x| strings(x, out)),
        _ => {}
    }
}

fn key_kind(text: &str) -> Option<&'static str> {
    kepr_core::leak::find_all(text.as_bytes())
        .first()
        .map(|h| h.kind)
}

/// The first of `keys` present in `v` (Claude Code uses snake_case,
/// Grok Build camelCase).
fn field<'a>(v: &'a Value, keys: &[&str]) -> &'a Value {
    keys.iter()
        .map(|k| &v[*k])
        .find(|x| !x.is_null())
        .unwrap_or(&Value::Null)
}

pub fn pre_tool(input: &Value) -> Verdict {
    let tool_input = field(input, &["tool_input", "toolInput"]);
    if let Some(cmd) = tool_input["command"].as_str() {
        if let Some(verb) = revealing_verb(cmd) {
            return Verdict::Block(format!(
                "kepr: `kepr {verb}` would reveal a stored secret, so it is blocked in agent \
                 sessions. Use the placeholder already in the environment, or ask the user to \
                 run the command themselves."
            ));
        }
    }
    let mut all = Vec::new();
    strings(tool_input, &mut all);
    match all.iter().find_map(|s| key_kind(s)) {
        Some(kind) => Verdict::Block(format!(
            "kepr: this tool call contains what looks like a real {kind}. Secrets must not be \
             written into commands or files; reference the environment variable instead."
        )),
        None => Verdict::Allow,
    }
}

pub fn prompt(input: &Value) -> Verdict {
    match field(input, &["prompt", "userPrompt"])
        .as_str()
        .and_then(key_kind)
    {
        Some(kind) => Verdict::Block(format!(
            "kepr: your message contains a {kind} and was not sent to the model. Store the key \
             once with `kepr agent add NAME` (it asks for the value, hidden) and start the agent \
             with `kepr agent run`. If the key was real, consider rotating it."
        )),
        None => Verdict::Allow,
    }
}

/// `text` with every key-shaped substring replaced, and how many.
pub fn redact(text: &str) -> (String, usize) {
    let hits = kepr_core::leak::find_all(text.as_bytes());
    let (mut out, mut at) = (String::new(), 0);
    for h in &hits {
        if h.offset < at {
            continue; // overlapping shapes
        }
        // Key shapes are ASCII, so these are char boundaries.
        out.push_str(&text[at..h.offset]);
        out.push_str(&format!("[{} removed by kepr]", h.kind));
        at = h.offset + h.len;
    }
    out.push_str(&text[at..]);
    (out, hits.len())
}

pub fn session_start(gate_url: Option<&str>) -> Verdict {
    Verdict::Context(match gate_url {
        Some(_) => "Credentials in this session are managed by kepr. API keys in the \
                    environment are placeholders (kepr-ph-…); a local gate swaps in the real \
                    key on the way to the provider. Use them as they are. Never ask the user to \
                    paste a key, and never try to print or decode secrets: `kepr get`, `kepr env` \
                    and `kepr exec` are blocked here. Never put a key in a file, a command line \
                    or a commit; reference the environment variable instead. The `kepr` MCP \
                    server (`kepr mcp`) offers list_secrets and call_api for provider calls \
                    without a key. If a real key shows up anywhere, stop and tell the user to \
                    run `kepr leaked NAME`."
            .into(),
        None => "kepr is installed but this session was not started with `kepr agent run`, \
                 so real keys may be present in the environment. Do not print environment \
                 variables or .env files. Suggest `kepr agent run <harness>` to the user."
            .into(),
    })
}

/// `kepr hook EVENT`: exit code + output for the harness.
pub fn cmd_hook(args: &[String]) -> i32 {
    let event = args.first().map(String::as_str).unwrap_or_default();
    let mut raw = String::new();
    if event != "session-start" {
        let _ = std::io::stdin().take(10 << 20).read_to_string(&mut raw);
        let _ = std::io::copy(&mut std::io::stdin(), &mut std::io::sink());
    }
    let input: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);
    let verdict = match event {
        "pre-tool" => pre_tool(&input),
        "prompt" => prompt(&input),
        "session-start" => session_start(std::env::var("KEPR_GATE_URL").ok().as_deref()),
        "redact" => {
            let (text, found) = redact(input["text"].as_str().unwrap_or_default());
            println!("{}", json!({"text": text, "found": found}));
            return 0;
        }
        _ => {
            eprintln!("usage: kepr hook pre-tool|prompt|session-start|redact  (JSON on stdin)");
            return 1;
        }
    };
    match verdict {
        Verdict::Allow => 0,
        Verdict::Block(reason) => {
            eprintln!("{reason}");
            2
        }
        Verdict::Context(text) => {
            let out = json!({"hookSpecificOutput": {
                "hookEventName": "SessionStart",
                "additionalContext": text,
            }});
            println!("{out}");
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocked(v: Verdict) -> bool {
        matches!(v, Verdict::Block(_))
    }

    #[test]
    fn revealing_commands() {
        for c in [
            "kepr get OPENAI_API_KEY",
            "/usr/local/bin/kepr env --env A,B",
            "echo $(kepr get X) | base64",
            "FOO=1 kepr --json totp GITHUB",
            "cd x && kepr exec --mask -- sh -c 'echo $K'",
            "kepr record get DB password",
            "kepr share send OPENAI_API_KEY --to kepr-pub1-AAAA",
            "VAULT_ADDR=https://x kepr sync-push K --url vault:a/b",
            "kepr recovery-key enrol",
            "kepr --json recovery-key enrol --replace",
        ] {
            assert!(revealing_verb(c).is_some(), "{c}");
        }
        for c in [
            "kepr list",
            "kepr agent ls",
            "kepr status && kepr history X",
            "keprget foo",
            "cargo build -p kepr",
            "kepr",
        ] {
            assert!(revealing_verb(c).is_none(), "{c}");
        }
    }

    #[test]
    fn pre_tool_blocks_reveals_and_key_literals() {
        let bash = |c: &str| json!({"tool_name": "Bash", "tool_input": {"command": c}});
        assert!(blocked(pre_tool(&bash("kepr get A"))));
        assert!(blocked(pre_tool(&bash("kepr recovery-key enrol"))));
        assert!(!blocked(pre_tool(&bash("ls -la"))));
        assert!(blocked(pre_tool(&bash(
            "curl -H 'x-api-key: sk-ant-api03-abcdefghijklmnopqrstuvwx' https://x"
        ))));
        let write = json!({"tool_name": "Write", "tool_input": {
            "file_path": "a.env", "content": "KEY=ghp_abcdefghijklmnopqrstuvwxyz0123456789"}});
        assert!(blocked(pre_tool(&write)));
        // Grok Build's payload shape.
        let grok =
            json!({"toolName": "run_terminal_command", "toolInput": {"command": "kepr env"}});
        assert!(blocked(pre_tool(&grok)));
        let edit = json!({"tool_name": "edit", "tool_input": {"edits": [{"new": "x = 1"}]}});
        assert!(!blocked(pre_tool(&edit)));
        // A placeholder is not a key.
        assert!(!blocked(pre_tool(&bash(
            "curl -H 'Authorization: Bearer kepr-ph-0123456789abcdef-0000-0123456789abcdef' x"
        ))));
        assert!(!blocked(pre_tool(&Value::Null)));
    }

    #[test]
    fn prompt_with_a_key_is_blocked_with_advice() {
        let p = json!({"prompt": "use this key sk-ant-api03-abcdefghijklmnopqrstuvwx thanks"});
        match prompt(&p) {
            Verdict::Block(m) => assert!(m.contains("kepr agent add") && !m.contains("sk-ant")),
            _ => panic!("not blocked"),
        }
        assert!(!blocked(prompt(&json!({"prompt": "refactor main.rs"}))));
    }

    #[test]
    fn redact_removes_every_key_and_keeps_the_rest() {
        let (t, n) = redact("a sk-ant-api03-abcdefghijklmnopqrstuvwx b AKIAABCDEFGHIJKLMNOP é");
        assert_eq!(n, 2);
        assert!(!t.contains("sk-ant-api03") && !t.contains("AKIA"));
        assert!(t.starts_with("a [") && t.ends_with(" é"));
        assert_eq!(redact("nothing here"), ("nothing here".into(), 0));
    }

    #[test]
    fn session_context_depends_on_the_gate() {
        let Verdict::Context(inside) = session_start(Some("http://127.0.0.1:1")) else {
            panic!()
        };
        let Verdict::Context(outside) = session_start(None) else {
            panic!()
        };
        assert!(inside.contains("placeholders") && outside.contains("kepr agent run"));
        for rule in ["kepr leaked", "call_api", "list_secrets", "commit"] {
            assert!(inside.contains(rule), "{rule}");
        }
    }
}
