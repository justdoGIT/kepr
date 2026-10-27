//! PostgreSQL password rotation through the gate (P7.2). `kepr agent
//! rotate-db` has the daemon put a new random password into the sealed
//! record as `pending_password`, then logs in through the gate with the
//! `kepr_rotate` startup parameter. The gate logs in with the current
//! password and sets the new one as a SCRAM verifier, so the password
//! itself never appears in SQL text or server logs. The CLI then tells the
//! daemon to commit (or drop) the pending password.
//!
//! Re-runnable: if a previous run changed the server but never committed,
//! the current password fails and the pending one logs in. The gate then
//! reports success without another ALTER, and the CLI commits.

use tokio::io::AsyncWriteExt;

use crate::pg::{error_response, login, message, read_msg, DbRoute, Login};
use crate::pg_tls::Io;
use kepr_core::generate::ZeroString;

/// Read server messages until ReadyForQuery; `Err` with the server's
/// text if an ErrorResponse came first.
async fn until_ready(up: &mut Box<dyn Io>) -> Result<(), String> {
    let mut error = None;
    loop {
        let (kind, body) = read_msg(up).await.map_err(|e| e.to_string())?;
        match kind {
            b'E' => {
                let text = body
                    .split(|b| *b == 0)
                    .find_map(|f| f.strip_prefix(b"M"))
                    .map(|m| String::from_utf8_lossy(m).to_string());
                error = Some(text.unwrap_or_else(|| "server error".into()));
            }
            b'Z' => return error.map_or(Ok(()), Err),
            _ => {}
        }
    }
}

/// Set `pending` as the logged-in role's password. `up` has just
/// received AuthenticationOk.
pub async fn rotate(up: &mut Box<dyn Io>, pending: &str) -> Result<(), String> {
    if !(16..=128).contains(&pending.len()) || !pending.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err("pending password must be 16-128 alphanumeric characters".into());
    }
    until_ready(up).await?;
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|e| format!("CSPRNG failure: {e}"))?;
    let v = crate::scram::verifier(pending, &salt, 4096);
    // The verifier is base64 and `$` / `:` only: safe inside quotes.
    let mut q = format!("ALTER ROLE CURRENT_USER PASSWORD '{v}'").into_bytes();
    q.push(0);
    up.write_all(&message(b'Q', &q))
        .await
        .map_err(|e| e.to_string())?;
    until_ready(up).await
}

/// One `kepr_rotate` login: the reply for the client (AuthenticationOk +
/// ReadyForQuery when the server now has the pending password, else an
/// ErrorResponse). `up` is connected and has not logged in yet.
pub async fn session(
    mut up: Box<dyn Io>,
    route: &DbRoute,
    params: &[(String, String)],
    rec: &Login,
) -> Vec<u8> {
    let fail = |e: &str| error_response("28000", &format!("kepr rotate: {e}"));
    let Some(pending) = rec.pending_password.as_ref() else {
        return fail("no rotation pending (run kepr agent rotate-db)");
    };
    let done = |ok: Vec<u8>| [ok, message(b'Z', b"I")].concat();
    match login(&mut up, params, rec).await {
        Ok(ok) => match rotate(&mut up, pending.as_str()).await {
            Ok(()) => done(ok),
            Err(e) => fail(&e),
        },
        Err(first) => {
            // An earlier run may have set the pending password already.
            let retry = Login {
                user: rec.user.clone(),
                password: ZeroString::from_string(pending.0.clone()),
                database: rec.database.clone(),
                // Same TLS policy as the record: the cleartext-password
                // guard in `login` depends on `sslmode`.
                sslmode: rec.sslmode.clone(),
                ca_pem: rec.ca_pem.clone(),
                pending_password: None,
            };
            let up2 = crate::pg_tls::upstream(&route.target, &rec.sslmode, &rec.ca_pem).await;
            match up2 {
                Ok(mut up2) => match login(&mut up2, params, &retry).await {
                    Ok(ok) => done(ok),
                    Err(_) => first,
                },
                Err(_) => first,
            }
        }
    }
}
