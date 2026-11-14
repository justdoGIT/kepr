//! Explicit text/message/function shapes; unknown nested provider types stop here.

use serde_json::{Map, Value};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Api {
    Responses,
    Messages,
    Chat,
}

type Checked<T> = Result<T, &'static str>;

fn object<'a>(value: &'a Value, fields: &[&str]) -> Checked<&'a Map<String, Value>> {
    let object = value.as_object().ok_or("privacy object required")?;
    if object.keys().any(|key| !fields.contains(&key.as_str())) {
        return Err("unreviewed nested privacy field");
    }
    Ok(object)
}

fn required<'a>(object: &'a Map<String, Value>, name: &str) -> Checked<&'a Value> {
    object.get(name).ok_or("required privacy field missing")
}

fn text(value: &Value) -> Checked<&str> {
    value.as_str().ok_or("privacy text required")
}

fn array(value: &Value) -> Checked<&[Value]> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or("privacy array required")
}

fn content(value: &Value, api: Api, allow_tools: bool) -> Checked<()> {
    if value.is_string() || (api == Api::Chat && value.is_null()) {
        return Ok(());
    }
    for block in array(value)? {
        let kind = text(block.get("type").ok_or("privacy content type required")?)?;
        match (api, kind) {
            (Api::Responses, "input_text" | "output_text")
            | (Api::Messages | Api::Chat, "text") => {
                let fields = if api == Api::Responses && kind == "output_text" {
                    &["type", "text", "annotations"][..]
                } else {
                    &["type", "text"][..]
                };
                let block = object(block, fields)?;
                text(required(block, "text")?)?;
                if let Some(annotations) = block.get("annotations") {
                    if !array(annotations)?.is_empty() {
                        return Err("provider annotations require local processing");
                    }
                }
            }
            (Api::Messages, "tool_use") if allow_tools => {
                let block = object(block, &["type", "id", "name", "input"])?;
                for key in ["id", "name"] {
                    text(required(block, key)?)?;
                }
                if !required(block, "input")?.is_object() {
                    return Err("privacy tool input must be an object");
                }
            }
            (Api::Messages, "tool_result") if allow_tools => {
                let block = object(block, &["type", "tool_use_id", "content", "is_error"])?;
                text(required(block, "tool_use_id")?)?;
                content(required(block, "content")?, api, false)?;
                if block.get("is_error").is_some_and(|v| !v.is_boolean()) {
                    return Err("invalid privacy tool result flag");
                }
            }
            _ => return Err("unreviewed privacy content type"),
        }
    }
    Ok(())
}

fn chat_call(value: &Value) -> Checked<()> {
    let call = object(value, &["name", "arguments"])?;
    text(required(call, "name")?)?;
    text(required(call, "arguments")?)?;
    Ok(())
}

fn message(value: &Value, api: Api) -> Checked<()> {
    let fields = match api {
        Api::Responses => &["type", "id", "role", "content", "status"][..],
        Api::Messages => &["role", "content"][..],
        Api::Chat => &[
            "role",
            "content",
            "name",
            "tool_calls",
            "tool_call_id",
            "function_call",
            "refusal",
        ][..],
    };
    let message = object(value, fields)?;
    let roles = match api {
        Api::Responses => &["system", "developer", "user", "assistant"][..],
        Api::Messages => &["user", "assistant"][..],
        Api::Chat => &[
            "system",
            "developer",
            "user",
            "assistant",
            "tool",
            "function",
        ][..],
    };
    if !roles.contains(&text(required(message, "role")?)?) {
        return Err("unreviewed privacy message role");
    }
    if message
        .get("type")
        .is_some_and(|v| v.as_str() != Some("message"))
    {
        return Err("unreviewed privacy message type");
    }
    content(required(message, "content")?, api, api == Api::Messages)?;
    if let Some(calls) = message.get("tool_calls") {
        for call in array(calls)? {
            let call = object(call, &["type", "id", "function"])?;
            if text(required(call, "type")?)? != "function" {
                return Err("unreviewed privacy tool call");
            }
            text(required(call, "id")?)?;
            chat_call(required(call, "function")?)?;
        }
    }
    if let Some(call) = message.get("function_call") {
        chat_call(call)?;
    }
    Ok(())
}

fn response_input(value: &Value) -> Checked<()> {
    if value.is_string() {
        return Ok(());
    }
    for item in array(value)? {
        match item.get("type").and_then(Value::as_str) {
            Some("function_call") => {
                let call = object(
                    item,
                    &["type", "id", "call_id", "name", "arguments", "status"],
                )?;
                for key in ["call_id", "name", "arguments"] {
                    text(required(call, key)?)?;
                }
            }
            Some("function_call_output") => {
                let call = object(item, &["type", "id", "call_id", "output", "status"])?;
                text(required(call, "call_id")?)?;
                content(required(call, "output")?, Api::Responses, false)?;
            }
            Some("message") | None => message(item, Api::Responses)?,
            _ => return Err("unreviewed privacy input type"),
        }
    }
    Ok(())
}

fn tool(value: &Value, api: Api) -> Checked<()> {
    let definition = match api {
        Api::Messages => {
            let tool = object(value, &["type", "name", "description", "input_schema"])?;
            if tool
                .get("type")
                .is_some_and(|v| v.as_str() != Some("custom"))
            {
                return Err("unreviewed provider tool type");
            }
            if !required(tool, "input_schema")?.is_object() {
                return Err("privacy tool schema must be an object");
            }
            tool
        }
        Api::Responses | Api::Chat => {
            let fields = if api == Api::Chat {
                &["type", "function"][..]
            } else {
                &["type", "name", "description", "parameters", "strict"][..]
            };
            let tool = object(value, fields)?;
            if text(required(tool, "type")?)? != "function" {
                return Err("unreviewed provider tool type");
            }
            if api == Api::Chat {
                object(
                    required(tool, "function")?,
                    &["name", "description", "parameters", "strict"],
                )?
            } else {
                tool
            }
        }
    };
    text(required(definition, "name")?)?;
    if let Some(description) = definition.get("description") {
        text(description)?;
    }
    if definition.get("parameters").is_some_and(|v| !v.is_object())
        || definition.get("strict").is_some_and(|v| !v.is_boolean())
    {
        return Err("invalid privacy function definition");
    }
    Ok(())
}

pub(super) fn validate(path: &str, request: &Value) -> Checked<()> {
    let api = if path.ends_with("responses") {
        Api::Responses
    } else if path.ends_with("messages") {
        Api::Messages
    } else {
        Api::Chat
    };
    if api == Api::Responses {
        if let Some(input) = request.get("input") {
            response_input(input)?;
        }
    } else if let Some(messages) = request.get("messages") {
        for value in array(messages)? {
            message(value, api)?;
        }
    }
    if api == Api::Messages {
        if let Some(system) = request.get("system") {
            content(system, api, false)?;
        }
    }
    if let Some(tools) = request.get("tools") {
        for value in array(tools)? {
            tool(value, api)?;
        }
    }
    Ok(())
}
