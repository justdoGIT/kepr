//! Egress proxy (P2.1): `CONNECT host:443` from tools the agent runs.
//!
//! For a host a sealed key of this session is bound to, the gate accepts
//! the TLS itself (session CA, ca.rs) and serves the decrypted requests
//! through the same `proxy_request` path as base-URL traffic: the
//! placeholder must be valid, limits and DLP apply, and the real key is
//! added toward the real host over TLS with the gate's compiled-in roots.
//! Other hosts are tunnelled byte-for-byte when the session allows it,
//! and refused under `--isolate-net` unless they are one of the
//! session's `--tunnel` targets (T7.03).

use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;

use crate::journal;
use crate::proxy::{kepr_error, proxy_request, Body, State};

fn ok() -> Response<Body> {
    Response::new(Empty::<Bytes>::new().map_err(|n| match n {}).boxed())
}

fn log(state: &State, target: &str, status: StatusCode, blocked: Option<&str>, start: Instant) {
    journal::emit(&journal::Entry {
        session: &state.session_id,
        provider: "egress",
        method: "CONNECT",
        path: target,
        status: status.as_u16(),
        bytes_out: 0,
        ms: start.elapsed().as_millis(),
        blocked,
    });
}

/// The provider name if `host:port` is bound in this session.
fn bound_provider(state: &State, host: &str, port: u16) -> Option<&'static str> {
    let ca = state.ca.as_ref()?;
    let p = kepr_core::providers::by_host(host)?;
    (port == 443 && ca.covers(host) && state.routes.contains_key(p.name)).then_some(p.name)
}

pub async fn connect(state: Arc<State>, req: Request<Incoming>) -> Response<Body> {
    let start = Instant::now();
    let Some(auth) = req.uri().authority().cloned() else {
        return kepr_error(StatusCode::BAD_REQUEST, "kepr", "CONNECT needs host:port");
    };
    let host = auth.host().to_ascii_lowercase();
    let port = auth.port_u16().unwrap_or(443);
    let target = format!("{host}:{port}");

    if let Some(pname) = bound_provider(&state, &host, port) {
        let Some(cfg) = state
            .ca
            .as_ref()
            .and_then(|ca| ca.server_config(&host).ok())
        else {
            return kepr_error(StatusCode::BAD_GATEWAY, "kepr", "no certificate for host");
        };
        log(&state, &target, StatusCode::OK, Some("intercepted"), start);
        tokio::spawn(async move {
            let Ok(up) = hyper::upgrade::on(req).await else {
                return;
            };
            let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
            let Ok(tls) = acceptor.accept(TokioIo::new(up)).await else {
                return;
            };
            let svc = hyper::service::service_fn(move |r: Request<Incoming>| {
                let (st, path) = (state.clone(), r.uri().path().to_string());
                async move { proxy_request(st, pname, &path, r).await }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(tls), svc)
                .await;
        });
        return ok();
    }

    if !state.tunnel && !crate::tunnel::allowed(&state, &host, port) {
        log(
            &state,
            &target,
            StatusCode::FORBIDDEN,
            Some("egress"),
            start,
        );
        return kepr_error(
            StatusCode::FORBIDDEN,
            "kepr_blocked",
            &format!(
                "kepr: this session can only reach the hosts its keys are bound to, not {host}"
            ),
        );
    }
    let upstream = match tokio::net::TcpStream::connect((host.as_str(), port)).await {
        Ok(s) => s,
        Err(_) => {
            log(&state, &target, StatusCode::BAD_GATEWAY, None, start);
            return kepr_error(StatusCode::BAD_GATEWAY, "kepr", "cannot reach host");
        }
    };
    log(&state, &target, StatusCode::OK, None, start);
    tokio::spawn(async move {
        if let Ok(up) = hyper::upgrade::on(req).await {
            let mut client = TokioIo::new(up);
            let mut upstream = upstream;
            let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
        }
    });
    ok()
}
