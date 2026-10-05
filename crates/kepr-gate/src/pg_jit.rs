//! Just-in-time role elevation for PostgreSQL routes (T7.18). A `db:`
//! route whose target carries a `grant` holds that role only while the
//! agent session runs: before the route's first client login the gate
//! logs in with the grant's admin record (another sealed `database`
//! record, bound to the same server) and runs `GRANT "role" TO "<login>"`;
//! when the session ends (the agent exits) it runs the matching REVOKE.
//! The grantee is the route record's user rather than CURRENT_USER: the
//! statement runs on the admin's connection.
//!
//! Only what the gate granted is revoked: a login that already had the
//! role keeps it. A failed grant refuses the login. A gate killed outright
//! (`kepr panic`) can't run its REVOKE, so the role stays until an
//! administrator revokes it.

use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use crate::db::{self, DbRoute, Login};
use crate::pg::{login, message, read_msg, Io};
use crate::proxy::State;
use kepr_core::binding::Inject;
use kepr_core::gate_protocol::RoleGrant;

/// How long a GRANT (the login waits) or a REVOKE (the gate's exit
/// waits) may take.
const ADMIN_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Default)]
enum Status {
    #[default]
    Unchecked,
    /// The login had the role before the session: never revoked.
    AlreadyMember,
    /// The gate granted the role to this login.
    Granted(String),
}

/// A route's elevation state for the session.
#[derive(Default)]
pub struct Held(Mutex<Status>);

/// `"name"` with `"` doubled; `None` for a name PostgreSQL would reject
/// or truncate (empty, NUL, over 63 bytes).
pub fn ident(s: &str) -> Option<String> {
    if s.is_empty() || s.len() > 63 || s.contains('\0') {
        return None;
    }
    Some(format!("\"{}\"", s.replace('"', "\"\"")))
}

/// `'text'` with `'` doubled; `None` with a backslash or NUL, whose
/// meaning depends on `standard_conforming_strings`.
pub fn literal(s: &str) -> Option<String> {
    if s.contains(['\\', '\0']) {
        return None;
    }
    Some(format!("'{}'", s.replace('\'', "''")))
}

/// (membership check, GRANT, REVOKE) for `role` and `grantee`.
pub fn statements(role: &str, grantee: &str) -> Option<[String; 3]> {
    let (r, g) = (ident(role)?, ident(grantee)?);
    let (rl, gl) = (literal(role)?, literal(grantee)?);
    Some([
        format!(
            "SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid \
             JOIN pg_roles u ON u.oid = m.member WHERE r.rolname = {rl} AND u.rolname = {gl}"
        ),
        format!("GRANT {r} TO {g}"),
        format!("REVOKE {r} FROM {g}"),
    ])
}

/// The `M` field of an ErrorResponse body.
fn error_text(body: &[u8]) -> String {
    body.split(|b| *b == 0)
        .find_map(|f| f.strip_prefix(b"M"))
        .map(|m| String::from_utf8_lossy(m).into_owned())
        .unwrap_or_else(|| "server error".into())
}

/// Read until ReadyForQuery: the number of DataRows, or the server's error.
async fn until_ready(up: &mut Box<dyn Io>) -> Result<usize, String> {
    let (mut rows, mut error) = (0, None);
    loop {
        let (kind, body) = read_msg(up).await.map_err(|e| e.to_string())?;
        match kind {
            b'D' => rows += 1,
            b'E' => error = Some(error_text(&body)),
            b'Z' => return error.map_or(Ok(rows), Err),
            _ => {}
        }
    }
}

async fn query(up: &mut Box<dyn Io>, sql: &str) -> Result<usize, String> {
    let mut q = sql.as_bytes().to_vec();
    q.push(0);
    up.write_all(&message(b'Q', &q))
        .await
        .map_err(|e| e.to_string())?;
    until_ready(up).await
}

/// A connection logged in with the grant's admin record.
async fn admin(state: &State, route: &DbRoute, g: &RoleGrant) -> Result<Box<dyn Io>, String> {
    let (cache, name, t) = (state.cache.clone(), g.admin.clone(), route.target.clone());
    let got = tokio::task::spawn_blocking(move || cache.get(&name, &t.host, t.port)).await;
    let rec: Login = match got {
        Ok(Ok((v, Inject::Postgres))) => {
            serde_json::from_str(v.as_str()).map_err(|_| "the admin record is damaged")?
        }
        _ => return Err(format!("the admin login {} is unavailable", g.admin)),
    };
    let mut up = crate::pg_tls::upstream(&route.target, &rec.sslmode, &rec.ca_pem).await?;
    let params = [("application_name".to_string(), "kepr-jit".to_string())];
    login(&mut up, &params, &rec)
        .await
        .map_err(|e| error_text(e.get(5..).unwrap_or_default()))?;
    drop(rec);
    until_ready(&mut up).await?;
    Ok(up)
}

/// Before a client login on `route`: make sure `grantee` (the route
/// record's user) has the route's role. `Err` refuses the login.
pub async fn ensure(state: &State, route: &DbRoute, grantee: &str) -> Result<(), String> {
    let Some(g) = route.target.grant.as_ref() else {
        return Ok(());
    };
    let mut held = route.jit.0.lock().await;
    if !matches!(*held, Status::Unchecked) {
        return Ok(());
    }
    let start = Instant::now();
    let [check, grant, _] =
        statements(&g.role, grantee).ok_or("the role or login name cannot be quoted")?;
    let r = tokio::time::timeout(ADMIN_TIMEOUT, async {
        let mut up = admin(state, route, g).await?;
        let status = if query(&mut up, &check).await? > 0 {
            Status::AlreadyMember
        } else {
            query(&mut up, &grant).await?;
            Status::Granted(grantee.to_string())
        };
        let _ = up.write_all(&message(b'X', &[])).await;
        Ok::<_, String>(status)
    })
    .await
    .unwrap_or_else(|_| Err("the database did not answer in time".into()));
    db::log(
        state,
        route,
        "GRANT",
        &r.as_ref().map(drop).map_err(|_| (502, None)),
        start,
    );
    *held = r?;
    Ok(())
}

/// At session end: revoke what `ensure` granted on `route`.
pub async fn revoke(state: &State, route: &DbRoute) -> Result<(), String> {
    let Some(g) = route.target.grant.as_ref() else {
        return Ok(());
    };
    let mut held = route.jit.0.lock().await;
    let Status::Granted(grantee) = std::mem::take(&mut *held) else {
        return Ok(());
    };
    let start = Instant::now();
    let [_, _, sql] = statements(&g.role, &grantee).ok_or("cannot quote")?;
    let r = async {
        let mut up = admin(state, route, g).await?;
        query(&mut up, &sql).await?;
        let _ = up.write_all(&message(b'X', &[])).await;
        Ok(())
    }
    .await;
    db::log(
        state,
        route,
        "REVOKE",
        &r.clone().map_err(|_| (502, None)),
        start,
    );
    r
}

/// Revoke every route's grant (session end), each within a time bound.
pub async fn revoke_all(state: &State, routes: &[std::sync::Arc<DbRoute>]) {
    for r in routes {
        let _ = tokio::time::timeout(ADMIN_TIMEOUT, revoke(state, r)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::testkit;
    use crate::pg::error_response;
    use kepr_core::gate_protocol::DbTarget;
    use std::sync::Arc;
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::mpsc;

    #[test]
    fn identifiers_and_literals_are_quoted() {
        assert_eq!(ident("analyst").unwrap(), "\"analyst\"");
        assert_eq!(ident("Read \"Only\"").unwrap(), "\"Read \"\"Only\"\"\"");
        for bad in ["", "a\0b"] {
            assert_eq!(ident(bad), None, "{bad:?}");
        }
        assert_eq!(ident(&"r".repeat(64)), None);
        assert!(ident(&"r".repeat(63)).is_some());
        assert_eq!(literal("o'k").unwrap(), "'o''k'");
        assert_eq!(literal("a\\b"), None);
        assert_eq!(literal("a\0b"), None);

        let [check, grant, revoke] = statements("x\" TO public; --", "app").unwrap();
        assert_eq!(grant, "GRANT \"x\"\" TO public; --\" TO \"app\"");
        assert_eq!(revoke, "REVOKE \"x\"\" TO public; --\" FROM \"app\"");
        assert!(check.ends_with("r.rolname = 'x\" TO public; --' AND u.rolname = 'app'"));
        assert!(statements("analyst", "we\\ird").is_none());
    }

    #[derive(Debug, PartialEq)]
    enum Ev {
        /// A login, with its application_name.
        Connect(Option<String>),
        Query(String),
    }

    /// A PostgreSQL server (trust auth) on loopback. `member`: the
    /// membership check returns a row; `refuse`: GRANT fails.
    async fn fake_pg(member: bool, refuse: bool) -> (u16, mpsc::UnboundedReceiver<Ev>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                let tx = tx.clone();
                tokio::spawn(async move {
                    let len = s.read_u32().await.unwrap() as usize;
                    let mut body = vec![0u8; len - 4];
                    s.read_exact(&mut body).await.unwrap();
                    let params = crate::pg::parse_params(&body[4..]);
                    let app = params.into_iter().find(|(k, _)| k == "application_name");
                    let _ = tx.send(Ev::Connect(app.map(|(_, v)| v)));
                    let hello = [message(b'R', &0u32.to_be_bytes()), message(b'Z', b"I")];
                    s.write_all(&hello.concat()).await.unwrap();
                    while let Ok((kind, body)) = read_msg(&mut s).await {
                        if kind != b'Q' {
                            break;
                        }
                        let sql = String::from_utf8_lossy(&body[..body.len() - 1]).to_string();
                        let _ = tx.send(Ev::Query(sql.clone()));
                        let mut out = Vec::new();
                        if sql.starts_with("SELECT") && member {
                            out.extend(message(b'D', &[0, 1, 0, 0, 0, 1, b'1']));
                        }
                        if sql.starts_with("GRANT") && refuse {
                            out.extend(error_response("42501", "permission denied to grant role"));
                        } else {
                            out.extend(message(b'C', b"OK\0"));
                        }
                        out.extend(message(b'Z', b"I"));
                        s.write_all(&out).await.unwrap();
                    }
                });
            }
        });
        (port, rx)
    }

    fn route(port: u16) -> Arc<DbRoute> {
        let target = DbTarget {
            host: "127.0.0.1".into(),
            port,
            grant: Some(RoleGrant {
                role: "analyst".into(),
                admin: "TEST_ADMIN".into(),
            }),
            ..Default::default()
        };
        Arc::new(DbRoute::new(
            "db:TEST_DB".into(),
            "TEST_DB".into(),
            0,
            target,
        ))
    }

    fn state() -> Arc<State> {
        let rec = r#"{"user":"app","password":"pw","database":"prod","sslmode":"disable"}"#;
        testkit::state(rec, Inject::Postgres)
    }

    /// A client login through the gate: the gate's first reply after the
    /// placeholder (AuthenticationOk, or an ErrorResponse).
    async fn client_login(gate: u16) -> (u8, Vec<u8>) {
        let mut c = TcpStream::connect(("127.0.0.1", gate)).await.unwrap();
        let mut body = 196_608u32.to_be_bytes().to_vec();
        body.extend_from_slice(b"user\0agent\0\0");
        let mut m = ((body.len() + 4) as u32).to_be_bytes().to_vec();
        m.extend(body);
        c.write_all(&m).await.unwrap();
        assert_eq!(read_msg(&mut c).await.unwrap().0, b'R');
        let mut p = testkit::placeholder(0).into_bytes();
        p.push(0);
        c.write_all(&message(b'p', &p)).await.unwrap();
        read_msg(&mut c).await.unwrap()
    }

    fn jit() -> Option<String> {
        Some("kepr-jit".into())
    }

    async fn drain(rx: &mut mpsc::UnboundedReceiver<Ev>, n: usize) -> Vec<Ev> {
        let mut out = Vec::new();
        for _ in 0..n {
            out.push(rx.recv().await.unwrap());
        }
        out
    }

    #[tokio::test]
    async fn grants_before_the_first_login_and_revokes_at_session_end() {
        let (up, mut seen) = fake_pg(false, false).await;
        let (st, r) = (state(), route(up));
        let gate = testkit::listen(st.clone(), r.clone()).await;
        assert_eq!(client_login(gate).await.0, b'R');
        let ev = drain(&mut seen, 4).await;
        assert_eq!(ev[0], Ev::Connect(jit()));
        assert!(matches!(&ev[1], Ev::Query(q) if q.starts_with("SELECT 1 FROM pg_auth_members")));
        assert_eq!(ev[2], Ev::Query("GRANT \"analyst\" TO \"app\"".into()));
        assert_eq!(ev[3], Ev::Connect(None), "then the agent's own login");
        // A second login: no second grant.
        assert_eq!(client_login(gate).await.0, b'R');
        assert_eq!(seen.recv().await.unwrap(), Ev::Connect(None));
        // Session end.
        revoke_all(&st, std::slice::from_ref(&r)).await;
        let ev = drain(&mut seen, 2).await;
        assert_eq!(ev[0], Ev::Connect(jit()));
        assert_eq!(ev[1], Ev::Query("REVOKE \"analyst\" FROM \"app\"".into()));
        revoke_all(&st, &[r]).await;
        assert!(seen.try_recv().is_err(), "revoked once");
    }

    #[tokio::test]
    async fn a_failed_grant_refuses_the_login() {
        let (up, mut seen) = fake_pg(false, true).await;
        let gate = testkit::listen(state(), route(up)).await;
        let (kind, body) = client_login(gate).await;
        assert_eq!(kind, b'E');
        let msg = error_text(&body);
        assert!(msg.contains("role elevation failed"), "{msg}");
        assert!(msg.contains("permission denied"), "{msg}");
        let ev = drain(&mut seen, 3).await; // login, check, the refused GRANT
        assert!(matches!(&ev[2], Ev::Query(q) if q.starts_with("GRANT")));
        let quiet = tokio::time::timeout(Duration::from_millis(200), seen.recv());
        assert!(
            quiet.await.is_err(),
            "the agent's login never reached the server"
        );
    }

    #[tokio::test]
    async fn an_existing_membership_is_left_alone() {
        let (up, mut seen) = fake_pg(true, false).await;
        let (st, r) = (state(), route(up));
        let gate = testkit::listen(st.clone(), r.clone()).await;
        assert_eq!(client_login(gate).await.0, b'R');
        let ev = drain(&mut seen, 3).await;
        assert_eq!(ev[2], Ev::Connect(None), "no GRANT");
        revoke_all(&st, &[r]).await;
        let quiet = tokio::time::timeout(Duration::from_millis(200), seen.recv());
        assert!(quiet.await.is_err(), "no REVOKE");
    }
}
