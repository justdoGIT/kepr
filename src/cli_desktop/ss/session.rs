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
// when their owner leaves the bus, and (a bound against a client that
// never closes any) at MAX_PER_OWNER per connection.

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
}

#[derive(Default)]
pub struct Sessions(Mutex<HashMap<String, Session>>);

fn fresh_id() -> String {
    let mut b = [0u8; 8];
    let _ = getrandom::fill(&mut b);
    format!("s{}", hex::encode(b))
}

impl Sessions {
    fn m(&self) -> std::sync::MutexGuard<'_, HashMap<String, Session>> {
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
        let mut m = self.m();
        if m.len() >= MAX_TOTAL || m.values().filter(|s| s.owner == owner).count() >= MAX_PER_OWNER
        {
            return Err(DErr::new(names::E_FAILED, "too many open sessions"));
        }
        let id = fresh_id();
        m.insert(
            id.clone(),
            Session {
                owner: owner.into(),
                key,
            },
        );
        Ok((id, output))
    }

    pub fn close(&self, id: &str, owner: &str) -> bool {
        let mut m = self.m();
        if m.get(id).is_some_and(|s| s.owner == owner) {
            m.remove(id);
            return true;
        }
        false
    }

    pub fn drop_owner(&self, owner: &str) {
        self.m().retain(|_, s| s.owner != owner);
    }

    pub fn exists(&self, id: &str, owner: &str) -> bool {
        self.m().get(id).is_some_and(|s| s.owner == owner)
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
            let m = self.m();
            let s = m.get(&id).filter(|s| s.owner == owner).ok_or_else(no)?;
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
            let m = self.m();
            m.get(&id)
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
        for _ in 0..MAX_PER_OWNER {
            s.open(":1.9", "plain", &Value::variant(Value::str("")))
                .unwrap();
        }
        assert!(s
            .open(":1.9", "plain", &Value::variant(Value::str("")))
            .is_err());
        assert!(
            s.open(":1.10", "plain", &Value::variant(Value::str("")))
                .is_ok(),
            "other connections are unaffected"
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
}
