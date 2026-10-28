// cli_desktop/ss/session.rs — Secret Service sessions: how secrets are
// carried between a client and this server on the bus.
//
//   plain   the secret travels as it is (the bus is a per-user socket)
//   dh-ietf1024-sha256-aes128-cbc-pkcs7
//           encrypted under a key both sides derive (dh.rs); a bus logger
//           or a process that reads the socket buffer never sees it
//
// A session belongs to the connection that opened it: any other
// connection naming its path gets `NoSession`. Sessions end on `Close`,
// when their owner leaves the bus, and (a bound against clients that never
// close any) when a table is full: a connection past MAX_PER_OWNER loses its
// own oldest session, and when the whole table (MAX_TOTAL) is full the
// oldest session of the connection holding the most goes. A flood of
// connections cannot hold the table, and cannot push out a client that
// keeps few sessions.

use std::collections::HashMap;
use std::sync::Mutex;

use zeroize::Zeroizing;

use super::dh;
use super::names::{self, DErr, DResult};
use crate::cli_desktop::dbus::Value;

pub const MAX_PER_OWNER: usize = 16;
const MAX_TOTAL: usize = 256;

struct Session {
    owner: String,
    key: Option<Zeroizing<[u8; 16]>>,
    /// Opening order, to find the oldest.
    seq: u64,
}

#[derive(Default)]
struct Table {
    by_id: HashMap<String, Session>,
    next: u64,
}

#[derive(Default)]
pub struct Sessions(Mutex<Table>);

impl Table {
    /// Make room for one more session of `owner`.
    fn make_room(&mut self, owner: &str) {
        let mine = self.by_id.values().filter(|s| s.owner == owner).count();
        let victim = if mine >= MAX_PER_OWNER {
            Some(owner.to_string())
        } else if self.by_id.len() >= MAX_TOTAL {
            let mut held: HashMap<&str, usize> = HashMap::new();
            for s in self.by_id.values() {
                *held.entry(&s.owner).or_default() += 1;
            }
            held.into_iter()
                .max_by_key(|&(o, n)| (n, o))
                .map(|(o, _)| o.to_string())
        } else {
            None
        };
        let oldest = victim.and_then(|v| {
            self.by_id
                .iter()
                .filter(|(_, s)| s.owner == v)
                .min_by_key(|(_, s)| s.seq)
                .map(|(id, _)| id.clone())
        });
        if let Some(id) = oldest {
            self.by_id.remove(&id);
        }
    }
}

fn fresh_id() -> String {
    let mut b = [0u8; 8];
    let _ = getrandom::fill(&mut b);
    format!("s{}", hex::encode(b))
}

impl Sessions {
    fn m(&self) -> std::sync::MutexGuard<'_, Table> {
        self.0.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// OpenSession: the new session's id and the `output` variant.
    pub fn open(&self, owner: &str, algorithm: &str, input: &Value) -> DResult<(String, Value)> {
        let (key, output) = match algorithm {
            "plain" => (None, Value::variant(Value::str(""))),
            dh::ALGORITHM => {
                let Value::Bytes(theirs) = input.unwrap_variant() else {
                    return Err(DErr::args("the public key must be an array of bytes"));
                };
                let (private, public) = dh::keypair().map_err(|e| DErr::new(names::E_FAILED, e))?;
                let key = dh::session_key(&private, theirs).map_err(DErr::args)?;
                (Some(key), Value::variant(Value::Bytes(public.to_vec())))
            }
            other => {
                return Err(DErr::new(
                    names::E_NOT_SUPPORTED,
                    format!("the session algorithm {other:?} is not supported"),
                ))
            }
        };
        let mut t = self.m();
        t.make_room(owner);
        let id = fresh_id();
        let seq = t.next;
        t.next += 1;
        t.by_id.insert(
            id.clone(),
            Session {
                owner: owner.into(),
                key,
                seq,
            },
        );
        Ok((id, output))
    }

    pub fn close(&self, id: &str, owner: &str) -> bool {
        let mut t = self.m();
        if t.by_id.get(id).is_some_and(|s| s.owner == owner) {
            t.by_id.remove(id);
            return true;
        }
        false
    }

    pub fn drop_owner(&self, owner: &str) {
        self.m().by_id.retain(|_, s| s.owner != owner);
    }

    pub fn exists(&self, id: &str, owner: &str) -> bool {
        self.m().by_id.get(id).is_some_and(|s| s.owner == owner)
    }

    fn session_id(path: &str) -> Option<String> {
        match names::parse(path)? {
            names::Obj::Session(id) => Some(id),
            _ => None,
        }
    }

    /// The `(oayays)` struct carrying `secret` for the session at `path`.
    pub fn encode(
        &self,
        path: &str,
        owner: &str,
        secret: &[u8],
        content_type: &str,
    ) -> DResult<Value> {
        let no = || DErr::new(names::E_NO_SESSION, "no such session");
        let id = Self::session_id(path).ok_or_else(no)?;
        let key = {
            let t = self.m();
            let s = t
                .by_id
                .get(&id)
                .filter(|s| s.owner == owner)
                .ok_or_else(no)?;
            s.key.clone()
        };
        let (params, value) = match key {
            None => (Vec::new(), secret.to_vec()),
            Some(k) => {
                let (iv, ct) =
                    dh::encrypt(&k, secret).map_err(|e| DErr::new(names::E_FAILED, e))?;
                (iv.to_vec(), ct)
            }
        };
        Ok(Value::Struct(vec![
            Value::path(path),
            Value::Bytes(params),
            Value::Bytes(value),
            Value::str(content_type),
        ]))
    }

    /// The secret and content type inside a `(oayays)` from a client.
    pub fn decode(&self, owner: &str, v: &Value) -> DResult<(Zeroizing<Vec<u8>>, String)> {
        let bad = || DErr::args("malformed secret");
        let [Value::Path(path), Value::Bytes(params), Value::Bytes(value), Value::Str(ct)] =
            v.as_struct().ok_or_else(bad)?
        else {
            return Err(bad());
        };
        let no = || DErr::new(names::E_NO_SESSION, "no such session");
        let id = Self::session_id(path).ok_or_else(no)?;
        let key = {
            let t = self.m();
            t.by_id
                .get(&id)
                .filter(|s| s.owner == owner)
                .ok_or_else(no)?
                .key
                .clone()
        };
        let plain = match key {
            None => Zeroizing::new(value.clone()),
            Some(k) => dh::decrypt(&k, params, value).map_err(DErr::args)?,
        };
        Ok((plain, ct.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dh_open(s: &Sessions, owner: &str) -> (String, Zeroizing<[u8; 16]>) {
        let (private, public) = dh::keypair().unwrap();
        let (id, out) = s
            .open(
                owner,
                dh::ALGORITHM,
                &Value::variant(Value::Bytes(public.to_vec())),
            )
            .unwrap();
        let Value::Variant(inner) = out else { panic!() };
        let Value::Bytes(server_pub) = *inner else {
            panic!()
        };
        (id, dh::session_key(&private, &server_pub).unwrap())
    }

    #[test]
    fn plain_secrets_travel_as_they_are() {
        let s = Sessions::default();
        let (id, out) = s
            .open(":1.1", "plain", &Value::variant(Value::str("")))
            .unwrap();
        assert_eq!(out, Value::variant(Value::str("")));
        let path = names::session_path(&id);
        let v = s.encode(&path, ":1.1", b"pw", "text/plain").unwrap();
        assert_eq!(v.sig(), "(oayays)");
        let f = v.as_struct().unwrap();
        assert_eq!(
            (f[1].as_bytes().unwrap(), f[2].as_bytes().unwrap()),
            (&[][..], &b"pw"[..])
        );
        let (back, ct) = s.decode(":1.1", &v).unwrap();
        assert_eq!((&back[..], ct.as_str()), (&b"pw"[..], "text/plain"));
    }

    #[test]
    fn dh_secrets_are_encrypted_and_the_client_can_read_them() {
        let s = Sessions::default();
        let (id, key) = dh_open(&s, ":1.2");
        let v = s
            .encode(
                &names::session_path(&id),
                ":1.2",
                b"correct horse",
                "text/plain",
            )
            .unwrap();
        let f = v.as_struct().unwrap();
        assert_eq!(f[1].as_bytes().unwrap().len(), 16, "an IV");
        assert_ne!(f[2].as_bytes().unwrap(), b"correct horse");
        let plain = dh::decrypt(&key, f[1].as_bytes().unwrap(), f[2].as_bytes().unwrap()).unwrap();
        assert_eq!(&plain[..], b"correct horse");
        // And the other way: a client sends one.
        let (iv, ct) = dh::encrypt(&key, b"from client").unwrap();
        let sent = Value::Struct(vec![
            Value::path(names::session_path(&id)),
            Value::Bytes(iv.to_vec()),
            Value::Bytes(ct),
            Value::str("text/plain"),
        ]);
        assert_eq!(&s.decode(":1.2", &sent).unwrap().0[..], b"from client");
    }

    #[test]
    fn a_session_belongs_to_its_connection() {
        let s = Sessions::default();
        let (id, _) = s
            .open(":1.1", "plain", &Value::variant(Value::str("")))
            .unwrap();
        let path = names::session_path(&id);
        assert!(s.exists(&id, ":1.1") && !s.exists(&id, ":1.2"));
        assert_eq!(
            s.encode(&path, ":1.2", b"x", "t").unwrap_err().0,
            names::E_NO_SESSION
        );
        assert!(!s.close(&id, ":1.2"));
        assert!(s.close(&id, ":1.1"));
        assert_eq!(
            s.encode(&path, ":1.1", b"x", "t").unwrap_err().0,
            names::E_NO_SESSION
        );
        let (id2, _) = s
            .open(":1.3", "plain", &Value::variant(Value::str("")))
            .unwrap();
        s.drop_owner(":1.3");
        assert!(!s.exists(&id2, ":1.3"));
    }

    #[test]
    fn bad_algorithms_keys_and_floods_are_refused() {
        let s = Sessions::default();
        assert_eq!(
            s.open(":1.1", "rot13", &Value::variant(Value::str("")))
                .unwrap_err()
                .0,
            names::E_NOT_SUPPORTED
        );
        assert_eq!(
            s.open(":1.1", dh::ALGORITHM, &Value::variant(Value::str("x")))
                .unwrap_err()
                .0,
            names::E_INVALID_ARGS
        );
        assert!(
            s.open(
                ":1.1",
                dh::ALGORITHM,
                &Value::variant(Value::Bytes(vec![1]))
            )
            .is_err(),
            "a trivial public key"
        );
        // Garbage structs.
        assert_eq!(
            s.decode(":1.1", &Value::Struct(vec![])).unwrap_err().0,
            names::E_INVALID_ARGS
        );
        let (id, _) = dh_open(&s, ":1.1");
        let junk = Value::Struct(vec![
            Value::path(names::session_path(&id)),
            Value::Bytes(vec![1; 3]),
            Value::Bytes(vec![2; 5]),
            Value::str("t"),
        ]);
        assert!(
            s.decode(":1.1", &junk).is_err(),
            "short IV and ragged ciphertext"
        );
        let not_a_session = Value::Struct(vec![
            Value::path("/org/freedesktop/secrets"),
            Value::Bytes(vec![]),
            Value::Bytes(vec![]),
            Value::str("t"),
        ]);
        assert_eq!(
            s.decode(":1.1", &not_a_session).unwrap_err().0,
            names::E_NO_SESSION
        );
    }

    fn plain(s: &Sessions, owner: &str) -> String {
        s.open(owner, "plain", &Value::variant(Value::str("")))
            .unwrap()
            .0
    }

    #[test]
    fn a_client_past_its_share_loses_its_oldest_session_and_nobody_elses() {
        let s = Sessions::default();
        let other = plain(&s, ":1.10");
        let first = plain(&s, ":1.9");
        let rest: Vec<String> = (1..MAX_PER_OWNER).map(|_| plain(&s, ":1.9")).collect();
        assert!(s.exists(&first, ":1.9"), "at the limit, none lost yet");
        let newest = plain(&s, ":1.9");
        assert!(!s.exists(&first, ":1.9"), "the oldest went");
        assert!(rest.iter().chain([&newest]).all(|i| s.exists(i, ":1.9")));
        assert!(
            s.exists(&other, ":1.10"),
            "other connections are unaffected"
        );
    }

    #[test]
    fn a_full_table_cannot_be_held_by_many_connections() {
        let s = Sessions::default();
        let victim = plain(&s, ":victim");
        // 16 sessions on each of enough connections to fill the table.
        let mut held = Vec::new();
        for c in 0..(MAX_TOTAL / MAX_PER_OWNER + 4) {
            for _ in 0..MAX_PER_OWNER {
                held.push((format!(":flood.{c}"), plain(&s, &format!(":flood.{c}"))));
            }
        }
        assert!(s.0.lock().unwrap().by_id.len() <= MAX_TOTAL, "bounded");
        assert!(
            s.exists(&victim, ":victim"),
            "a connection with one session is not the one that pays for the flood"
        );
        // The service still opens sessions for new clients.
        let fresh = plain(&s, ":late");
        assert!(s.exists(&fresh, ":late"));
        assert!(s.0.lock().unwrap().by_id.len() <= MAX_TOTAL);
    }
}
