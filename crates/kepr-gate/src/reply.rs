//! The gate's own replies to the agent: JSON errors in the shape the
//! providers' SDKs parse, and the session limits' 403 / 429.

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::HeaderValue;
use hyper::{Response, StatusCode};

use crate::limits::Refusal;
use crate::proxy::Body;

pub(crate) fn json(status: StatusCode, body: String) -> Response<Body> {
    let mut r = Response::new(Full::new(Bytes::from(body)).map_err(|n| match n {}).boxed());
    *r.status_mut() = status;
    r.headers_mut()
        .insert("content-type", HeaderValue::from_static("application/json"));
    r
}

pub fn kepr_error(status: StatusCode, kind: &str, message: &str) -> Response<Body> {
    let body = serde_json::json!({"type": "error", "error": {"type": kind, "message": message}});
    json(status, body.to_string())
}

/// A session cap is final (403, so harnesses don't retry); the rate
/// limit is a 429 with `Retry-After`.
pub(crate) fn limit_response(refusal: Refusal) -> Response<Body> {
    match refusal {
        Refusal::Cap(why) => kepr_error(
            StatusCode::FORBIDDEN,
            "kepr_limit",
            &format!("kepr stopped this request: {why}."),
        ),
        Refusal::Rate(secs) => {
            let mut r = kepr_error(
                StatusCode::TOO_MANY_REQUESTS,
                "kepr_limit",
                &format!("kepr rate limit for this session; retry in {secs}s."),
            );
            r.headers_mut()
                .insert("retry-after", HeaderValue::from(secs));
            r
        }
    }
}
