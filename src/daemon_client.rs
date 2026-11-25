use std::os::unix::net::UnixStream;
use std::time::Duration;

use zeroize::Zeroizing;

use kepr_core::protocol::{Request, Response, MAX_MSG_BYTES};

use crate::daemon_peer::get_peer_creds;

pub fn handle_client(mut stream: UnixStream) {
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let Some(response) = receive(&stream) else {
        return;
    };
    let sent = serde_json::to_vec(&response)
        .map(Zeroizing::new)
        .ok()
        .is_some_and(|json| kepr_core::framing::write_frame(&mut stream, &json).is_ok());
    // Close a parked descriptor even when the frame could not be delivered.
    crate::daemon_session::fetchfd::send_pending(
        &stream,
        if sent { &response } else { &Response::Pong },
    );
}

fn receive(stream: &UnixStream) -> Option<Response> {
    let creds = get_peer_creds(stream)?;
    if crate::user_mode() && creds.uid != crate::daemon_socket::effective_uid() {
        return Some(Response::fail("permission denied"));
    }
    // Parse before enforcing the per-uid bucket so interactive and
    // auth-critical calls can be exempted. Checking the limiter before the
    // request was known let a noisy background `Get` client drain a uid's
    // tokens and starve `kepr status` plus the SSH signing agent.
    let mut reader = crate::daemon_socket::Deadline::new(stream, Duration::from_secs(5));
    let bytes = Zeroizing::new(kepr_core::framing::read_frame(&mut reader, MAX_MSG_BYTES).ok()?);
    let request = serde_json::from_slice::<Request>(&bytes).ok()?;
    drop(bytes);
    if !exempt_from_rate_limit(&request) && !crate::rate_limiter().check(creds.uid) {
        return Some(Response::fail("rate limited"));
    }
    crate::daemon_session::idle::touch(&request);
    let username = crate::audit::username_for_uid(creds.uid);
    Some(crate::daemon_dispatch::dispatch(
        creds.uid, creds.pid, &username, request,
    ))
}

/// Status probes and sign-only SSH operations must stay responsive even when
/// a background credential reader has exhausted the uid's token bucket.
/// Credential reads (`Get`, `List`, `Check`, …) remain rate limited.
fn exempt_from_rate_limit(request: &Request) -> bool {
    matches!(
        request,
        Request::Ping | Request::Status | Request::SshList | Request::SshSign { .. }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interactive_ops_bypass_credential_budget() {
        assert!(exempt_from_rate_limit(&Request::Ping));
        assert!(exempt_from_rate_limit(&Request::Status));
        assert!(exempt_from_rate_limit(&Request::SshList));
        assert!(exempt_from_rate_limit(&Request::SshSign {
            name: "id_ed25519".into(),
            data_b64: "dGVzdA==".into(),
        }));
    }

    #[test]
    fn credential_reads_stay_rate_limited() {
        assert!(!exempt_from_rate_limit(&Request::List));
        assert!(!exempt_from_rate_limit(&Request::Check));
        assert!(!exempt_from_rate_limit(&Request::Get {
            name: "SOME_KEY".into(),
            fido2_assertion: None,
        }));
    }
}
