//! Retry an AgentRouter resource mismatch once when the request contains
//! portable item contents. Never invent history or drop encrypted reasoning.

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::StatusCode;
use kepr_core::binding::Inject;
use serde_json::Value;

use crate::{
    forward,
    journal::Log,
    proxy::{Body, Route},
};

fn replay(body: &[u8], error: &[u8]) -> Option<Bytes> {
    let error: Value = serde_json::from_slice(error).ok()?;
    let message = error["error"]["message"].as_str()?;
    if !message.contains("The requested item was created under a different")
        || !message.contains("OpenAI resource")
    {
        return None;
    }
    let mut request: Value = serde_json::from_slice(body).ok()?;
    // Chained requests and conversations may omit essential history.
    if !request["previous_response_id"].is_null() || !request["conversation"].is_null() {
        return None;
    }
    let input = request.get_mut("input")?.as_array_mut()?;
    let mut changed = false;
    for item in input {
        let portable = match item["type"].as_str() {
            Some("message") | None => {
                item["role"].is_string()
                    && (item["content"].is_string() || item["content"].is_array())
            }
            Some("function_call") => {
                item["call_id"].is_string()
                    && item["name"].is_string()
                    && item["arguments"].is_string()
            }
            Some("function_call_output" | "custom_tool_call_output") => {
                item["call_id"].is_string() && !item["output"].is_null()
            }
            Some("custom_tool_call") => {
                item["call_id"].is_string() && item["name"].is_string() && item["input"].is_string()
            }
            Some("reasoning") => item["encrypted_content"]
                .as_str()
                .is_some_and(|s| !s.is_empty()),
            // References, compaction and unknown items cannot be reconstructed.
            _ => false,
        };
        if !portable {
            return None;
        }
        changed |= item.as_object_mut()?.remove("id").is_some();
    }
    changed.then(|| Bytes::from(serde_json::to_vec(&request).expect("JSON value serializes")))
}

/// Successful/SSE responses stream immediately. Only the specific 400 error
/// is inspected, after response masking, and at most one extra call is made.
pub async fn send(
    log: &Log<'_>,
    route: &Route,
    parts: &hyper::http::request::Parts,
    inject: &Inject,
    value: &str,
    bytes: Bytes,
) -> Result<(hyper::http::response::Parts, Body), forward::Refusal> {
    let state = log.state;
    let mut body = bytes;
    for attempt in 0..=1 {
        let up = if *inject == Inject::CloudflareGateway {
            crate::cloudflare::upstream_request(log, parts, value, body.clone())
        } else {
            forward::upstream_request(log, parts, inject, value, Full::new(body.clone()))
        }
        .ok_or_else(|| Box::new(forward::cannot_build()))?;
        let resp = state
            .client
            .request(up)
            .await
            .map_err(|_| Box::new(forward::upstream_failed()))?;
        let (mut p, b) = forward::for_agent(state, resp, inject, crate::mask::forms(value));
        if attempt == 1 {
            p.headers
                .insert("x-kepr-responses-retry", "item-ids".parse().unwrap());
        }
        let eligible = attempt == 0
            && log.provider == "agentrouter"
            && matches!(log.path, "/v1/responses" | "/responses")
            && parts.method == hyper::Method::POST
            && p.status == StatusCode::BAD_REQUEST;
        if !eligible {
            return Ok((p, b));
        }
        let error = Limited::new(b, 64 * 1024)
            .collect()
            .await
            .map_err(|_| Box::new(forward::upstream_failed()))?
            .to_bytes();
        let Some(retry) = replay(&body, &error) else {
            return Ok((p, Full::new(error).map_err(|e| match e {}).boxed()));
        };
        if let Err(refusal) = state.limiter.admit(std::time::Instant::now()) {
            return Err(Box::new(crate::proxy::limit_response(refusal)));
        }
        if let Err(refusal) = state
            .limiter
            .admit_today(state.cache.clone(), route.cred.clone())
            .await
        {
            return Err(Box::new(crate::proxy::limit_response(refusal)));
        }
        body = retry;
    }
    unreachable!("the second response is returned without another retry")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn mismatch() -> Vec<u8> {
        serde_json::to_vec(&json!({"error":{"message":"The requested item was created under a different test OpenAI resource. Use the same resource that created the item to access it."}})).unwrap()
    }

    #[test]
    fn replay_only_removes_ids_and_keeps_all_context() {
        let body = json!({"input":[
            {"role":"user", "content":"prior context"},
            {"type":"message", "id":"msg_old", "role":"assistant", "phase":"commentary", "content":[{"type":"output_text","text":"working"}]},
            {"type":"reasoning", "id":"rs_old", "encrypted_content":"opaque", "summary":[]},
            {"type":"function_call", "id":"fc_old", "call_id":"call_saved", "name":"read", "arguments":"{}"},
            {"type":"function_call_output", "call_id":"call_saved", "output":"full result"}
        ]});
        let out = replay(&serde_json::to_vec(&body).unwrap(), &mismatch()).unwrap();
        let out: Value = serde_json::from_slice(&out).unwrap();
        let mut expected = body;
        for item in expected["input"].as_array_mut().unwrap() {
            item.as_object_mut().unwrap().remove("id");
        }
        assert_eq!(out, expected);
        assert!(replay(&serde_json::to_vec(&out).unwrap(), &mismatch()).is_none());
    }

    #[test]
    fn incomplete_history_and_other_errors_are_not_retried() {
        for body in [
            json!(null),
            json!("invalid request"),
            json!(123),
            json!({"previous_response_id":"resp_old", "input":[{"id":"msg_old","role":"user","content":"continue"}]}),
            json!({"conversation":"conv_old", "input":[]}),
            json!({"input":[{"type":"item_reference","id":"msg_old"}]}),
            json!({"input":[{"type":"reasoning","id":"rs_old","summary":[]}]}),
            json!({"input":[{"type":"compaction","id":"cmp_old","encrypted_content":"opaque"}]}),
        ] {
            assert!(replay(&serde_json::to_vec(&body).unwrap(), &mismatch()).is_none());
        }
        let body = serde_json::to_vec(
            &json!({"input":[{"id":"msg_old","role":"user","content":"hello"}]}),
        )
        .unwrap();
        for error in [
            b"not JSON".as_slice(),
            br#"{"error":{"message":"unauthorized client"}}"#,
        ] {
            assert!(replay(&body, error).is_none());
        }
    }
}
