//! Reviewed fields for the initial text-only provider adapters.

use kepr_core::privacy::Session;
use serde_json::Value;

pub(super) fn schema(path: &str) -> Option<&'static [&'static str]> {
    match path {
        "/v1/responses" | "/responses" => Some(&[
            "model",
            "input",
            "instructions",
            "tools",
            "tool_choice",
            "temperature",
            "top_p",
            "max_output_tokens",
            "stream",
            "parallel_tool_calls",
            "text",
            "reasoning",
            "truncation",
            "store",
            "metadata",
            "user",
            "prompt_cache_key",
            "safety_identifier",
            "service_tier",
            "previous_response_id",
            "background",
            "conversation",
            "include",
        ]),
        "/v1/messages" => Some(&[
            "model",
            "messages",
            "system",
            "max_tokens",
            "stream",
            "temperature",
            "top_p",
            "top_k",
            "stop_sequences",
            "tools",
            "tool_choice",
            "metadata",
            "thinking",
        ]),
        "/v1/chat/completions"
        | "/chat/completions"
        | "/api/v1/chat/completions"
        | "/openai/v1/chat/completions"
        | "/inference/v1/chat/completions" => Some(&[
            "model",
            "messages",
            "tools",
            "tool_choice",
            "temperature",
            "top_p",
            "max_tokens",
            "max_completion_tokens",
            "stream",
            "stream_options",
            "stop",
            "frequency_penalty",
            "presence_penalty",
            "response_format",
            "parallel_tool_calls",
            "seed",
            "reasoning_effort",
            "store",
            "metadata",
            "user",
            "service_tier",
        ]),
        _ => None,
    }
}

fn protocol_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}

pub(super) fn walk(
    v: &mut Value,
    session: &mut Session,
    depth: usize,
    nodes: &mut usize,
) -> Result<usize, String> {
    walk_in(v, session, depth, nodes, true)
}

fn walk_in(
    v: &mut Value,
    session: &mut Session,
    depth: usize,
    nodes: &mut usize,
    protocol: bool,
) -> Result<usize, String> {
    *nodes += 1;
    if depth > 64 || *nodes > 100_000 {
        return Err("privacy JSON complexity limit reached".into());
    }
    let mut count = 0;
    match v {
        Value::String(s) => {
            let (masked, hits) = session.transform(s).map_err(str::to_owned)?;
            *s = masked;
            count += hits;
        }
        Value::Array(items) => {
            for item in items {
                count += walk_in(item, session, depth + 1, nodes, protocol)?;
            }
        }
        Value::Object(object) => {
            if object.keys().any(|key| {
                matches!(
                    key.as_str(),
                    "encrypted_content"
                        | "signature"
                        | "thinkingSignature"
                        | "thinking_signature"
                        | "previous_response_id"
                        | "conversation"
                        | "image_url"
                        | "file_id"
                        | "file_data"
                        | "audio"
                        | "video"
                )
            }) {
                return Err("opaque provider state or media requires local processing".into());
            }
            if object.get("type").and_then(Value::as_str).is_some_and(|t| {
                matches!(
                    t,
                    "input_image"
                        | "image"
                        | "input_file"
                        | "file"
                        | "input_audio"
                        | "audio"
                        | "video"
                        | "web_search"
                        | "web_search_preview"
                        | "file_search"
                        | "computer_use_preview"
                        | "mcp"
                )
            }) {
                return Err("unsupported privacy content or provider tool".into());
            }
            if object
                .get("include")
                .is_some_and(|v| v.as_array().is_none_or(|a| !a.is_empty()))
            {
                return Err("opaque provider inclusions are unsupported".into());
            }
            let tool_input = object.get("type").and_then(Value::as_str) == Some("tool_use");
            for (key, value) in object {
                if session.transform(key).map_err(str::to_owned)?.1 > 0 {
                    return Err("personal data in a protocol field name".into());
                }
                if protocol
                    && matches!(
                        key.as_str(),
                        "id" | "call_id" | "tool_call_id" | "tool_use_id"
                    )
                {
                    let id = value.as_str().ok_or("invalid conversation reference")?;
                    if !protocol_id(id) || session.transform(id).map_err(str::to_owned)?.1 > 0 {
                        return Err("invalid conversation reference".into());
                    }
                    continue;
                }
                if protocol && key == "arguments" && value.is_string() {
                    let mut args: Value = serde_json::from_str(value.as_str().unwrap())
                        .map_err(|_| "invalid JSON tool arguments")?;
                    count += walk_in(&mut args, session, depth + 1, nodes, false)?;
                    *value = Value::String(
                        serde_json::to_string(&args).map_err(|_| "invalid tool arguments")?,
                    );
                } else if protocol && matches!(key.as_str(), "model" | "name" | "role" | "type") {
                    let s = value.as_str().ok_or("protocol identity must be text")?;
                    if s.len() > 128 || session.transform(s).map_err(str::to_owned)?.1 > 0 {
                        return Err("personal data in protocol identity".into());
                    }
                } else {
                    let child_protocol = protocol
                        && !matches!(key.as_str(), "parameters" | "input_schema" | "schema")
                        && !(tool_input && key == "input");
                    count += walk_in(value, session, depth + 1, nodes, child_protocol)?;
                }
            }
        }
        _ => {}
    }
    Ok(count)
}
