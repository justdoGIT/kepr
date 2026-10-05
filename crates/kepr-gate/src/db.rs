//! Database routes of a session (P7.1): one loopback listener per route;
//! the route's kind picks the protocol handler. Shared here: the sealed
//! login record, resolving it, the session's limits and the journal line.

use std::sync::Arc;
use std::time::Instant;

use tokio::net::TcpStream;

use crate::journal;
use crate::limits::Refusal;
use crate::proxy::State;
use kepr_core::gate_protocol::{DbTarget, TargetKind};
use kepr_core::generate::ZeroString;

/// One database route of the session.
pub struct DbRoute {
    pub key: String,
    pub cred: String,
    pub slot: u16,
    pub target: DbTarget,
}

/// The sealed `database` record.
#[derive(serde::Deserialize)]
pub(crate) struct Login {
    pub(crate) user: String,
    pub(crate) password: ZeroString,
    pub(crate) database: String,
    #[serde(default)]
    pub(crate) sslmode: String,
    #[serde(default)]
    pub(crate) ca_pem: String,
    /// P7.2: set during `kepr agent rotate-db`, until committed.
    #[serde(default)]
    pub(crate) pending_password: Option<ZeroString>,
}

/// Journal status and blocked reason of a failed connection.
pub(crate) type Fail = (u16, Option<&'static str>);

/// Serve one client connection on a route's port.
pub async fn serve_conn(state: Arc<State>, route: Arc<DbRoute>, client: TcpStream) {
    match route.target.kind {
        TargetKind::Postgres => crate::pg::serve_conn(state, route, client).await,
        TargetKind::Redis => crate::redis::serve_conn(state, route, client).await,
        TargetKind::Mysql => crate::mysql::serve_conn(state, route, client).await,
        TargetKind::Tcp => crate::tunnel::serve_conn(state, route, client).await,
    }
}

/// The session's caps and rate; `Err` is the message for the client.
pub(crate) fn admit(state: &State) -> Result<(), String> {
    state.limiter.admit(Instant::now()).map_err(|r| match r {
        Refusal::Cap(m) => format!("kepr stopped this login: {m}"),
        Refusal::Rate(s) => format!("kepr rate limit; retry in {s}s"),
    })
}

/// The placeholder a route's clients must present (for protocols where
/// the gate checks a scramble of it rather than the placeholder itself).
pub(crate) fn expected_placeholder(state: &State, slot: u16) -> zeroize::Zeroizing<String> {
    let make = |k: &[u8; 32]| crate::placeholder::make(k, &state.session_id, slot);
    zeroize::Zeroizing::new(state.session_key.with_key(make))
}

/// Resolve the route's sealed login. It must be a login of the route's
/// kind: a Redis password is never sent to a server speaking another
/// protocol.
pub(crate) async fn resolve_login(state: &State, route: &DbRoute) -> Result<Login, ()> {
    let (cache, cred, t) = (
        state.cache.clone(),
        route.cred.clone(),
        route.target.clone(),
    );
    let want = t.kind.inject().ok_or(())?;
    match tokio::task::spawn_blocking(move || cache.get(&cred, &t.host, t.port)).await {
        Ok(Ok((value, inject))) if inject == want => {
            serde_json::from_str(value.as_str()).map_err(|_| ())
        }
        _ => Err(()),
    }
}

/// One journal line per client connection.
pub(crate) fn log(
    state: &State,
    route: &DbRoute,
    method: &str,
    result: &Result<(), Fail>,
    start: Instant,
) {
    let (status, blocked) = match result {
        Ok(()) => (200, None),
        Err((s, b)) => (*s, *b),
    };
    journal::emit(&journal::Entry {
        session: &state.session_id,
        provider: route.target.kind.name(),
        method,
        path: &route.key,
        status,
        bytes_out: 0,
        ms: start.elapsed().as_millis(),
        blocked,
    });
}

#[cfg(test)]
pub(crate) mod testkit {
    //! Fixtures for the database proxies' tests: a session whose resolver
    //! returns one fixed record, and a loopback listener for a route.
    use super::*;
    use crate::vault::{Cache, Resolve, DEFAULT_TTL};
    use kepr_core::binding::Inject;
    use kepr_core::secmem::SplitKey;

    pub const SID: &str = "0123456789abcdef";
    pub const KEY: [u8; 32] = [7u8; 32];

    struct Fixed(String, Inject);
    impl Resolve for Fixed {
        fn generation(&self) -> Result<u64, String> {
            Ok(1)
        }
        fn resolve(&self, _: &str, _: &str, _: u16) -> Result<(ZeroString, Inject), String> {
            Ok((ZeroString::from_string(self.0.clone()), self.1.clone()))
        }
    }

    pub fn state(record: &str, inject: Inject) -> Arc<State> {
        let cache = Arc::new(Cache::new(
            Box::new(Fixed(record.into(), inject)),
            DEFAULT_TTL,
        ));
        let key = SplitKey::new(&KEY).unwrap();
        Arc::new(State::new(SID.into(), key, Default::default(), cache))
    }

    pub fn placeholder(slot: u16) -> String {
        crate::placeholder::make(&KEY, SID, slot)
    }

    pub fn route(kind: TargetKind, host: &str, port: u16) -> Arc<DbRoute> {
        Arc::new(DbRoute {
            key: "db:TEST_DB".into(),
            cred: "TEST_DB".into(),
            slot: 0,
            target: DbTarget {
                host: host.into(),
                port,
                kind,
                ..Default::default()
            },
        })
    }

    /// Serve `route` on a fresh loopback port; returns the port.
    pub async fn listen(state: Arc<State>, route: Arc<DbRoute>) -> u16 {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((c, _)) = l.accept().await {
                tokio::spawn(serve_conn(state.clone(), route.clone(), c));
            }
        });
        port
    }
}
