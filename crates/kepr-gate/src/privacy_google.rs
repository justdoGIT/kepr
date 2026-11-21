//! Reviewed text-only Generative Language requests; opaque state stays local.

use serde_json::{Map, Value};

type Checked<T> = Result<T, &'static str>;

/// The model is one literal path segment, never an encoded path or resource URI.
pub(super) fn endpoint(path: &str) -> Option<(&str, bool)> {
    let rest = path
        .strip_prefix("/v1beta/models/")
        .or_else(|| path.strip_prefix("/v1/models/"))?;
    let (model, streaming) = rest
        .strip_suffix(":generateContent")
        .map(|model| (model, false))
        .or_else(|| {
            rest.strip_suffix(":streamGenerateContent")
                .map(|model| (model, true))
        })?;
    (!model.is_empty()
        && model.len() <= 128
        && model
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
        && !matches!(model, "." | ".."))
    .then_some((model, streaming))
}

fn object<'a>(value: &'a Value, fields: &[&str]) -> Checked<&'a Map<String, Value>> {
    let object = value.as_object().ok_or("privacy object required")?;
    if object.keys().any(|key| !fields.contains(&key.as_str())) {
        return Err("unreviewed Google privacy field");
    }
    Ok(object)
}

fn required<'a>(object: &'a Map<String, Value>, key: &str) -> Checked<&'a Value> {
    object
        .get(key)
        .ok_or("required Google privacy field missing")
}

fn text(value: &Value) -> Checked<&str> {
    value.as_str().ok_or("Google privacy text required")
}

fn array(value: &Value) -> Checked<&[Value]> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or("Google privacy array required")
}

fn choice(value: &Value, choices: &[&str]) -> Checked<()> {
    if !choices.contains(&text(value)?) {
        return Err("unsupported Google privacy option");
    }
    Ok(())
}

fn data_object(value: &Value) -> Checked<()> {
    if !value.is_object() {
        return Err("Google function data or schema must be an object");
    }
    Ok(())
}

fn function(value: &Value, response: bool) -> Checked<()> {
    let fields = if response {
        &["id", "name", "response"][..]
    } else {
        &["id", "name", "args"][..]
    };
    let function = object(value, fields)?;
    let name = text(required(function, "name")?)?;
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_:.-".contains(&b))
    {
        return Err("invalid Google function name");
    }
    if let Some(id) = function.get("id") {
        text(id)?;
    }
    if response {
        data_object(required(function, "response")?)?;
    } else if let Some(args) = function.get("args") {
        data_object(args)?;
    }
    Ok(())
}

fn content(value: &Value, system: bool) -> Checked<()> {
    let content = object(value, &["role", "parts"])?;
    if let Some(role) = content.get("role") {
        choice(
            role,
            if system {
                &["user", "model", "system"]
            } else {
                &["user", "model"]
            },
        )?;
    }
    let parts = array(required(content, "parts")?)?;
    if parts.is_empty() {
        return Err("Google content parts required");
    }
    for value in parts {
        let part = object(
            value,
            &["text", "thought", "functionCall", "functionResponse"],
        )?;
        if ["text", "functionCall", "functionResponse"]
            .iter()
            .filter(|key| part.contains_key(**key))
            .count()
            != 1
        {
            return Err("Google part requires exactly one supported content field");
        }
        if let Some(thought) = part.get("thought") {
            if !thought.is_boolean() || !part.contains_key("text") {
                return Err("invalid Google thought text");
            }
        }
        if let Some(value) = part.get("text") {
            text(value)?;
        } else if system {
            return Err("Google system instructions must be text");
        } else if let Some(value) = part.get("functionCall") {
            function(value, false)?;
        } else if let Some(value) = part.get("functionResponse") {
            function(value, true)?;
        }
    }
    Ok(())
}

fn tool(value: &Value) -> Checked<()> {
    let tool = object(value, &["functionDeclarations"])?;
    for value in array(required(tool, "functionDeclarations")?)? {
        let definition = object(
            value,
            &[
                "name",
                "description",
                "parameters",
                "parametersJsonSchema",
                "response",
                "responseJsonSchema",
            ],
        )?;
        let name = text(required(definition, "name")?)?;
        if name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_:.-".contains(&b))
        {
            return Err("invalid Google function name");
        }
        if let Some(description) = definition.get("description") {
            text(description)?;
        }
        for (schema, json_schema) in [
            ("parameters", "parametersJsonSchema"),
            ("response", "responseJsonSchema"),
        ] {
            if definition.contains_key(schema) && definition.contains_key(json_schema) {
                return Err("conflicting Google function schemas");
            }
            for key in [schema, json_schema] {
                if let Some(value) = definition.get(key) {
                    data_object(value)?;
                }
            }
        }
    }
    Ok(())
}

fn generation(value: &Value) -> Checked<()> {
    let config = object(
        value,
        &[
            "stopSequences",
            "responseMimeType",
            "responseSchema",
            "responseJsonSchema",
            "responseModalities",
            "candidateCount",
            "maxOutputTokens",
            "temperature",
            "topP",
            "topK",
            "seed",
            "presencePenalty",
            "frequencyPenalty",
            "thinkingConfig",
        ],
    )?;
    for key in [
        "temperature",
        "topP",
        "topK",
        "presencePenalty",
        "frequencyPenalty",
    ] {
        if config.get(key).is_some_and(|v| !v.is_number()) {
            return Err("invalid Google numeric generation option");
        }
    }
    for key in ["candidateCount", "maxOutputTokens", "seed"] {
        if config.get(key).is_some_and(|v| !v.is_i64() && !v.is_u64()) {
            return Err("invalid Google integer generation option");
        }
    }
    if let Some(stops) = config.get("stopSequences") {
        for value in array(stops)? {
            text(value)?;
        }
    }
    if let Some(mime) = config.get("responseMimeType") {
        choice(mime, &["text/plain", "application/json", "text/x.enum"])?;
    }
    if config.contains_key("responseSchema") && config.contains_key("responseJsonSchema") {
        return Err("conflicting Google response schemas");
    }
    for key in ["responseSchema", "responseJsonSchema"] {
        if let Some(schema) = config.get(key) {
            data_object(schema)?;
        }
    }
    if let Some(modalities) = config.get("responseModalities") {
        for value in array(modalities)? {
            choice(value, &["TEXT"])?;
        }
    }
    if let Some(thinking) = config.get("thinkingConfig") {
        let thinking = object(
            thinking,
            &["thinkingBudget", "includeThoughts", "thinkingLevel"],
        )?;
        if thinking.get("thinkingBudget").is_some_and(|v| !v.is_i64())
            || thinking
                .get("includeThoughts")
                .is_some_and(|v| !v.is_boolean())
        {
            return Err("invalid Google thinking option");
        }
        if let Some(level) = thinking.get("thinkingLevel") {
            choice(level, &["MINIMAL", "LOW", "MEDIUM", "HIGH"])?;
        }
    }
    Ok(())
}

pub(super) fn validate(request: &Value) -> Checked<()> {
    let contents = array(request.get("contents").ok_or("Google contents required")?)?;
    if contents.is_empty() {
        return Err("Google contents required");
    }
    for value in contents {
        content(value, false)?;
    }
    if let Some(system) = request.get("systemInstruction") {
        content(system, true)?;
    }
    if let Some(tools) = request.get("tools") {
        for value in array(tools)? {
            tool(value)?;
        }
    }
    if let Some(config) = request.get("toolConfig") {
        let config = object(config, &["functionCallingConfig"])?;
        if let Some(function) = config.get("functionCallingConfig") {
            let function = object(function, &["mode", "allowedFunctionNames"])?;
            if let Some(mode) = function.get("mode") {
                choice(
                    mode,
                    &["AUTO", "ANY", "NONE", "VALIDATED", "MODE_UNSPECIFIED"],
                )?;
            }
            if let Some(names) = function.get("allowedFunctionNames") {
                for value in array(names)? {
                    text(value)?;
                }
            }
        }
    }
    if let Some(config) = request.get("generationConfig") {
        generation(config)?;
    }
    if let Some(settings) = request.get("safetySettings") {
        for value in array(settings)? {
            let setting = object(value, &["category", "threshold"])?;
            choice(
                required(setting, "category")?,
                &[
                    "HARM_CATEGORY_HATE_SPEECH",
                    "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                    "HARM_CATEGORY_DANGEROUS_CONTENT",
                    "HARM_CATEGORY_HARASSMENT",
                    "HARM_CATEGORY_CIVIC_INTEGRITY",
                    "HARM_CATEGORY_JAILBREAK",
                ],
            )?;
            choice(
                required(setting, "threshold")?,
                &[
                    "BLOCK_LOW_AND_ABOVE",
                    "BLOCK_MEDIUM_AND_ABOVE",
                    "BLOCK_ONLY_HIGH",
                    "BLOCK_NONE",
                    "OFF",
                    "HARM_BLOCK_THRESHOLD_UNSPECIFIED",
                ],
            )?;
        }
    }
    Ok(())
}
