//! Dynamic database users for PostgreSQL routes (T13.02). With
//! `--db-user NAME=ROLE[:TTL]` the route's sealed record is an admin login
//! (one that may CREATE ROLE) that the agent never uses and never learns a
//! password for. Before the route's first client login the gate, with that
//! record, creates a login role `kepr_e_<random>` with a random password
//! (sent as a SCRAM verifier, so the password is not in SQL text or server
//! logs), `VALID UNTIL` now + TTL, a member of ROLE; it logs the agent in
//! as that role, and at the end of the session drops it again.
//!
//! A gate that is killed before it can drop the role leaves one that has
//! already stopped logging in (`VALID UNTIL`); the next session on the
//! route drops every expired `kepr_e_` role before it makes its own, so
//! nothing accumulates. Only roles the gate named this way are touched.

use std::num::NonZeroU32;
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::db::{self, DbRoute, Login};
use crate::pg::{login, message, read_msg, Io};
use crate::pg_jit::{error_text, ident, literal, query, until_ready};
use crate::proxy::State;
use kepr_core::generate::ZeroString;

/// Name prefix of every role this module creates.
const PREFIX: &str = "kepr_e_";
const ADMIN_TIMEOUT: Duration = Duration::from_secs(15);
const ITERATIONS: NonZeroU32 = NonZeroU32::new(4096).unwrap();

struct Created {
    user: String,
    password: ZeroString,
}

/// A route's login role for the session.
#[derive(Default)]
pub struct Held(Mutex<Option<Created>>);

/// `YYYY-MM-DD HH:MM:SS+00` for a unix time.
pub fn timestamp(unix: u64) -> String {
    let t = time::OffsetDateTime::from_unix_timestamp(unix as i64)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}+00",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

/// The two statements that create the login: CREATE ROLE and GRANT.
pub fn create_statements(
    name: &str,
    verifier: &str,
    until: &str,
    role: &str,
) -> Option<[String; 2]> {
    let (n, r) = (ident(name)?, ident(role)?);
    let (v, u) = (literal(verifier)?, literal(until)?);
    Some([
        format!("CREATE ROLE {n} LOGIN PASSWORD {v} VALID UNTIL {u} CONNECTION LIMIT 16"),
        format!("GRANT {r} TO {n}"),
    ])
}

/// What it takes to remove a role: end its sessions, keep what it made,
/// drop its privileges, drop it. Only the last must succeed.
pub fn drop_statements(name: &str) -> Option<[String; 4]> {
    let (n, l) = (ident(name)?, literal(name)?);
    Some([
        format!("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = {l}"),
        format!("REASSIGN OWNED BY {n} TO CURRENT_USER"),
        format!("DROP OWNED BY {n}"),
        format!("DROP ROLE {n}"),
    ])
}

/// Expired roles of this module's naming.
const EXPIRED: &str = "SELECT rolname FROM pg_roles WHERE rolname LIKE 'kepr\\_e\\_%' \
                       AND rolvaliduntil IS NOT NULL AND rolvaliduntil < now()";

fn random_hex(n: usize) -> Result<String, String> {
    let mut b = Zeroizing::new(vec![0u8; n]);
    getrandom::fill(&mut b).map_err(|e| format!("CSPRNG failure: {e}"))?;
    Ok(hex::encode(&*b))
}

/// Run `sql` and return the first column of every DataRow.
async fn first_column(up: &mut Box<dyn Io>, sql: &str) -> Result<Vec<String>, String> {
    let mut q = sql.as_bytes().to_vec();
    q.push(0);
    up.write_all(&message(b'Q', &q))
        .await
        .map_err(|e| e.to_string())?;
    let (mut rows, mut error) = (Vec::new(), None);
    loop {
        let (kind, body) = read_msg(up).await.map_err(|e| e.to_string())?;
        match kind {
            b'D' if body.len() >= 6 => {
                let len = u32::from_be_bytes(body[2..6].try_into().expect("4 bytes")) as usize;
                if let Some(v) = body.get(6..6 + len) {
                    rows.push(String::from_utf8_lossy(v).into_owned());
                }
            }
            b'E' => error = Some(error_text(&body)),
            b'Z' => return error.map_or(Ok(rows), Err),
            _ => {}
        }
    }
}

/// A connection logged in with `rec` (the route's admin record).
async fn connect(route: &DbRoute, rec: &Login) -> Result<Box<dyn Io>, String> {
    let mut up = crate::pg_tls::upstream(&route.target, &rec.sslmode, &rec.ca_pem).await?;
    let params = [("application_name".to_string(), "kepr-ephemeral".to_string())];
    login(&mut up, &params, rec)
        .await
        .map_err(|e| error_text(e.get(5..).unwrap_or_default()))?;
    until_ready(&mut up).await?;
    Ok(up)
}

/// Remove `name`: the first three steps are best effort.
async fn remove(up: &mut Box<dyn Io>, name: &str) -> Result<(), String> {
    let [terminate, reassign, owned, drop] = drop_statements(name).ok_or("cannot quote")?;
    for sql in [terminate, reassign, owned] {
        let _ = query(up, &sql).await;
    }
    query(up, &drop).await.map(drop_value)
}

fn drop_value<T>(_: T) {}

/// Make the session's login on `route`, once. `admin` is the route's
/// sealed record. Returns the record the agent's upstream login uses.
async fn create(route: &DbRoute, admin: &Login) -> Result<Created, String> {
    let e = route
        .target
        .ephemeral
        .as_ref()
        .ok_or("not an ephemeral route")?;
    let mut up = connect(route, admin).await?;
    // Drop what earlier sessions left behind.
    if let Ok(old) = first_column(&mut up, EXPIRED).await {
        for name in old.iter().filter(|n| n.starts_with(PREFIX)) {
            let _ = remove(&mut up, name).await;
        }
    }
    let name = format!("{PREFIX}{}", random_hex(8)?);
    let password = ZeroString::from_string(random_hex(24)?);
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|e| format!("CSPRNG failure: {e}"))?;
    let verifier = crate::scram::verifier(password.as_str(), &salt, ITERATIONS);
    let until = timestamp(crate::github_app::now_secs() + e.ttl_secs);
    let [create, grant] = create_statements(&name, &verifier, &until, &e.role)
        .ok_or("the role name cannot be quoted")?;
    query(&mut up, &create).await?;
    if let Err(err) = query(&mut up, &grant).await {
        let _ = remove(&mut up, &name).await;
        return Err(err);
    }
    let _ = up.write_all(&message(b'X', &[])).await;
    Ok(Created {
        user: name,
        password,
    })
}

fn record_for(c: &Created, admin: &Login) -> Login {
    Login {
        user: c.user.clone(),
        password: ZeroString::from(c.password.as_str()),
        database: admin.database.clone(),
        sslmode: admin.sslmode.clone(),
        ca_pem: admin.ca_pem.clone(),
        pending_password: None,
    }
}

/// The login the agent's connection uses on `route`: the route record
/// itself, or (ephemeral routes) the session's own role, made on first
/// use. `Err` is a message for the client.
pub async fn login_for(state: &State, route: &DbRoute, rec: Login) -> Result<Login, String> {
    if route.target.ephemeral.is_none() {
        return Ok(rec);
    }
    let mut held = route.eph.0.lock().await;
    if let Some(c) = held.as_ref() {
        return Ok(record_for(c, &rec));
    }
    let start = Instant::now();
    let r = tokio::time::timeout(ADMIN_TIMEOUT, create(route, &rec))
        .await
        .unwrap_or_else(|_| Err("the database did not answer in time".into()));
    db::log(
        state,
        route,
        "CREATE ROLE",
        &r.as_ref().map(drop_value).map_err(|_| (502, None)),
        start,
    );
    let c = r?;
    let out = record_for(&c, &rec);
    *held = Some(c);
    Ok(out)
}

/// At session end: drop the role `login_for` made on `route`.
pub async fn drop_role(state: &State, route: &DbRoute) -> Result<(), String> {
    let mut held = route.eph.0.lock().await;
    let Some(c) = held.take() else {
        return Ok(());
    };
    let start = Instant::now();
    let r = async {
        let admin = db::resolve_login(state, route)
            .await
            .map_err(|()| "the admin login is unavailable".to_string())?;
        let mut up = connect(route, &admin).await?;
        remove(&mut up, &c.user).await?;
        let _ = up.write_all(&message(b'X', &[])).await;
        Ok(())
    }
    .await;
    db::log(
        state,
        route,
        "DROP ROLE",
        &r.clone().map_err(|_| (502, None)),
        start,
    );
    r
}

/// Drop every route's role (session end), each within a time bound.
pub async fn drop_all(state: &State, routes: &[std::sync::Arc<DbRoute>]) {
    for r in routes {
        let _ = tokio::time::timeout(ADMIN_TIMEOUT, drop_role(state, r)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::testkit;
    use crate::pg::error_response;
    use kepr_core::binding::Inject;
    use kepr_core::gate_protocol::{DbTarget, Ephemeral};
    use std::sync::Arc;
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::mpsc;

    #[derive(Debug, PartialEq, Clone)]
    enum Ev {
        /// A login: (user, application_name).
        Connect(String, Option<String>),
        Query(String),
    }

    /// PostgreSQL on loopback (trust auth). The expired-roles query returns
    /// `kepr_e_old`; `refuse` fails the GRANT.
    async fn fake_pg(refuse: bool) -> (u16, mpsc::UnboundedReceiver<Ev>) {
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
                    let get = |k: &str| params.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
                    let _ = tx.send(Ev::Connect(
                        get("user").unwrap_or_default(),
                        get("application_name"),
                    ));
                    let hello = [message(b'R', &0u32.to_be_bytes()), message(b'Z', b"I")];
                    s.write_all(&hello.concat()).await.unwrap();
                    while let Ok((kind, body)) = read_msg(&mut s).await {
                        if kind != b'Q' {
                            break;
                        }
                        let sql = String::from_utf8_lossy(&body[..body.len() - 1]).to_string();
                        let _ = tx.send(Ev::Query(sql.clone()));
                        let mut out = Vec::new();
                        if sql.starts_with("SELECT rolname") {
                            let name = b"kepr_e_old";
                            let mut row = 1u16.to_be_bytes().to_vec();
                            row.extend((name.len() as u32).to_be_bytes());
                            row.extend(name);
                            out.extend(message(b'D', &row));
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
            ephemeral: Some(Ephemeral {
                role: "analyst".into(),
                ttl_secs: 3600,
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
        let rec = r#"{"user":"admin","password":"admin-pw","database":"prod","sslmode":"disable"}"#;
        testkit::state(rec, Inject::Postgres)
    }

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

    async fn drain(rx: &mut mpsc::UnboundedReceiver<Ev>, n: usize) -> Vec<Ev> {
        let mut out = Vec::new();
        for _ in 0..n {
            out.push(
                tokio::time::timeout(Duration::from_secs(5), rx.recv())
                    .await
                    .unwrap()
                    .unwrap(),
            );
        }
        out
    }

    fn query(ev: &Ev) -> &str {
        match ev {
            Ev::Query(q) => q,
            other => panic!("not a query: {other:?}"),
        }
    }

    #[test]
    fn statements_are_quoted_and_dates_are_utc() {
        let [create, grant] = create_statements(
            "kepr_e_ab",
            "SCRAM-SHA-256$4096:c2FsdA==$x:y",
            "2026-10-28 12:00:00+00",
            "Read \"Only\"",
        )
        .unwrap();
        assert!(create.starts_with("CREATE ROLE \"kepr_e_ab\" LOGIN PASSWORD 'SCRAM-SHA-256$4096:"));
        assert!(create.ends_with("VALID UNTIL '2026-10-28 12:00:00+00' CONNECTION LIMIT 16"));
        assert_eq!(grant, "GRANT \"Read \"\"Only\"\"\" TO \"kepr_e_ab\"");
        assert!(
            create_statements("n", "v\\", "u", "r").is_none(),
            "a backslash cannot be quoted"
        );
        let d = drop_statements("kepr_e_ab").unwrap();
        assert!(d[0].contains("usename = 'kepr_e_ab'") && d[3] == "DROP ROLE \"kepr_e_ab\"");
        assert_eq!(timestamp(0), "1970-01-01 00:00:00+00");
        assert_eq!(timestamp(1_792_000_000), "2026-10-14 17:46:40+00");
    }

    #[tokio::test]
    async fn the_agent_logs_in_as_a_role_made_for_the_session_and_it_is_dropped_at_the_end() {
        let (up, mut seen) = fake_pg(false).await;
        let (st, r) = (state(), route(up));
        let gate = testkit::listen(st.clone(), r.clone()).await;
        assert_eq!(client_login(gate).await.0, b'R');

        // Admin login, expired-role sweep and its drop of kepr_e_old, then CREATE and GRANT.
        let ev = drain(&mut seen, 1 + 1 + 4 + 2).await;
        assert_eq!(
            ev[0],
            Ev::Connect("admin".into(), Some("kepr-ephemeral".into()))
        );
        assert!(query(&ev[1]).starts_with("SELECT rolname FROM pg_roles"));
        assert_eq!(query(&ev[5]), "DROP ROLE \"kepr_e_old\"");
        let create = query(&ev[6]);
        assert!(create.starts_with("CREATE ROLE \"kepr_e_"), "{create}");
        assert!(
            create.contains("PASSWORD 'SCRAM-SHA-256$4096:") && create.contains("VALID UNTIL '"),
            "{create}"
        );
        assert!(!create.contains("admin-pw"));
        let name = create.split('"').nth(1).unwrap().to_string();
        assert_eq!(query(&ev[7]), format!("GRANT \"analyst\" TO \"{name}\""));
        // Then the agent's own login, as the new role (not the admin).
        let login = drain(&mut seen, 1).await;
        assert_eq!(login[0], Ev::Connect(name.clone(), None));

        // A second connection reuses the role: no second CREATE.
        assert_eq!(client_login(gate).await.0, b'R');
        assert_eq!(
            drain(&mut seen, 1).await[0],
            Ev::Connect(name.clone(), None)
        );

        // Session end: terminate, reassign, drop owned, drop role.
        drop_all(&st, std::slice::from_ref(&r)).await;
        let ev = drain(&mut seen, 5).await;
        assert_eq!(
            ev[0],
            Ev::Connect("admin".into(), Some("kepr-ephemeral".into()))
        );
        assert_eq!(query(&ev[4]), format!("DROP ROLE \"{name}\""));
        drop_all(&st, &[r]).await;
        let quiet = tokio::time::timeout(Duration::from_millis(200), seen.recv());
        assert!(quiet.await.is_err(), "dropped once");
    }

    #[tokio::test]
    async fn a_failed_grant_drops_the_new_role_and_refuses_the_login() {
        let (up, mut seen) = fake_pg(true).await;
        let gate = testkit::listen(state(), route(up)).await;
        let (kind, body) = client_login(gate).await;
        assert_eq!(kind, b'E');
        let msg = error_text(&body);
        assert!(msg.contains("could not create the session login"), "{msg}");
        // connect, sweep + 4 for kepr_e_old, CREATE, the refused GRANT, then the cleanup of the new role.
        let ev = drain(&mut seen, 1 + 1 + 4 + 2 + 4).await;
        assert!(query(&ev[7]).starts_with("GRANT"));
        assert!(query(&ev[11]).starts_with("DROP ROLE \"kepr_e_"));
        let quiet = tokio::time::timeout(Duration::from_millis(200), seen.recv());
        assert!(
            quiet.await.is_err(),
            "the agent's login never reached the server"
        );
    }

    #[tokio::test]
    async fn routes_without_the_option_are_untouched() {
        let rec: Login =
            serde_json::from_str(r#"{"user":"u","password":"p","database":"d"}"#).unwrap();
        let t = DbTarget {
            host: "127.0.0.1".into(),
            port: 1,
            ..Default::default()
        };
        let r = DbRoute::new("db:X".into(), "X".into(), 0, t);
        let out = login_for(&state(), &r, rec).await.unwrap();
        assert_eq!(out.user, "u");
        assert!(drop_role(&state(), &r).await.is_ok());
    }
}
