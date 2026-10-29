// cli_desktop/ss_client.rs — a Secret Service client, for `kepr
// secret-service import`: read the items of whatever provider owns
// org.freedesktop.secrets (GNOME Keyring, KWallet, another kepr). Secrets
// come over a DH-encrypted session when the provider offers one, so they
// are not readable on the bus; they land in `Zeroizing` buffers.

use std::collections::BTreeMap;
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use zeroize::Zeroizing;

use super::dbus::conn::{Conn, BUS, BUS_PATH};
use super::dbus::{Message, Value};
use super::ss::dh;
use super::ss::names as n;

const WAIT: Duration = Duration::from_secs(25);
/// How long a person gets to answer the provider's unlock dialog.
const PROMPT_WAIT: Duration = Duration::from_secs(300);

pub struct Client {
    conn: Arc<Conn>,
    session: String,
    key: Option<Zeroizing<[u8; 16]>>,
    prompts: Mutex<Receiver<Message>>,
}

pub struct RemoteItem {
    pub path: String,
    pub label: String,
    pub attributes: BTreeMap<String, String>,
    pub created: u64,
}

fn err<T>(r: Result<T, super::dbus::conn::CallError>, what: &str) -> Result<T, String> {
    r.map_err(|e| format!("{what}: {e}"))
}

impl Client {
    pub fn open() -> Result<Client, String> {
        let (tx, rx) = channel();
        let tx = Mutex::new(tx);
        let conn = super::bus::connect_with(move |m| {
            if m.member.as_deref() == Some("Completed") {
                if let Ok(t) = tx.lock() {
                    let _ = t.send(m);
                }
            }
        })?;
        let rule = "type='signal',interface='org.freedesktop.Secret.Prompt',member='Completed'";
        err(
            conn.call(
                Message::call(BUS, BUS_PATH, BUS, "AddMatch", vec![Value::str(rule)]),
                WAIT,
            ),
            "AddMatch",
        )?;
        let mut c = Client {
            conn,
            session: String::new(),
            key: None,
            prompts: Mutex::new(rx),
        };
        c.open_session()?;
        Ok(c)
    }

    fn call(
        &self,
        path: &str,
        iface: &str,
        member: &str,
        body: Vec<Value>,
    ) -> Result<Vec<Value>, String> {
        let m = Message::call(n::BUS_NAME, path, iface, member, body);
        err(self.conn.call(m, WAIT), member).map(|r| r.body)
    }

    fn open_session(&mut self) -> Result<(), String> {
        let (private, public) = dh::keypair()?;
        let dh_try = self.call(
            n::ROOT,
            n::I_SERVICE,
            "OpenSession",
            vec![
                Value::str(dh::ALGORITHM),
                Value::variant(Value::Bytes(public.to_vec())),
            ],
        );
        if let Ok(b) = dh_try {
            let theirs = b
                .first()
                .map(Value::unwrap_variant)
                .and_then(Value::as_bytes)
                .ok_or("OpenSession returned no key")?;
            self.key = Some(dh::session_key(&private, theirs)?);
            self.session = b
                .get(1)
                .and_then(Value::as_str)
                .ok_or("OpenSession returned no session")?
                .to_string();
            return Ok(());
        }
        let b = self.call(
            n::ROOT,
            n::I_SERVICE,
            "OpenSession",
            vec![Value::str("plain"), Value::variant(Value::str(""))],
        )?;
        self.session = b
            .get(1)
            .and_then(Value::as_str)
            .ok_or("OpenSession returned no session")?
            .to_string();
        Ok(())
    }

    fn prop(&self, path: &str, iface: &str, name: &str) -> Result<Value, String> {
        let b = self.call(
            path,
            n::I_PROPS,
            "Get",
            vec![Value::str(iface), Value::str(name)],
        )?;
        b.into_iter()
            .next()
            .map(|v| v.unwrap_variant().clone())
            .ok_or_else(|| format!("{name}: no value"))
    }

    /// Collection paths, the memory-only `session` one left out.
    pub fn collections(&self) -> Result<Vec<String>, String> {
        let all = self
            .prop(n::ROOT, n::I_SERVICE, "Collections")?
            .strings()
            .ok_or("Collections is not a list of paths")?;
        Ok(all
            .into_iter()
            .filter(|p| p.rsplit('/').next() != Some("session"))
            .collect())
    }

    pub fn read_alias(&self, alias: &str) -> Option<String> {
        let b = self
            .call(n::ROOT, n::I_SERVICE, "ReadAlias", vec![Value::str(alias)])
            .ok()?;
        b.first()
            .and_then(Value::as_str)
            .filter(|p| *p != "/")
            .map(String::from)
    }

    pub fn collection_label(&self, path: &str) -> Result<String, String> {
        Ok(self
            .prop(path, n::I_COLLECTION, "Label")?
            .as_str()
            .unwrap_or("")
            .to_string())
    }

    pub fn is_locked(&self, path: &str, iface: &str) -> Result<bool, String> {
        Ok(self.prop(path, iface, "Locked")?.as_bool().unwrap_or(true))
    }

    /// Unlock `paths`, waiting for the provider's own dialog if it shows one.
    pub fn unlock(&self, paths: Vec<String>) -> Result<(), String> {
        let b = self.call(n::ROOT, n::I_SERVICE, "Unlock", vec![Value::paths(paths)])?;
        let prompt = b.get(1).and_then(Value::as_str).unwrap_or("/");
        if prompt == "/" {
            return Ok(());
        }
        let rx = self.prompts.lock().unwrap_or_else(|p| p.into_inner());
        while rx.try_recv().is_ok() {}
        self.call(prompt, n::I_PROMPT, "Prompt", vec![Value::str("")])?;
        loop {
            let m = rx
                .recv_timeout(PROMPT_WAIT)
                .map_err(|_| "the unlock dialog was not answered in time".to_string())?;
            if m.path.as_deref() == Some(prompt) {
                return match m.body.first().and_then(Value::as_bool) {
                    Some(false) => Ok(()),
                    _ => Err("the unlock was dismissed".into()),
                };
            }
        }
    }

    pub fn items(&self, collection: &str) -> Result<Vec<String>, String> {
        self.prop(collection, n::I_COLLECTION, "Items")?
            .strings()
            .ok_or_else(|| "Items is not a list of paths".into())
    }

    pub fn item(&self, path: &str) -> Result<RemoteItem, String> {
        let b = self.call(path, n::I_PROPS, "GetAll", vec![Value::str(n::I_ITEM)])?;
        let props: BTreeMap<String, Value> = b
            .first()
            .and_then(Value::pairs_sv)
            .ok_or("GetAll returned no properties")?
            .into_iter()
            .map(|(k, v)| (k, v.clone()))
            .collect();
        Ok(RemoteItem {
            path: path.to_string(),
            label: props
                .get("Label")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            attributes: props
                .get("Attributes")
                .and_then(Value::pairs_ss)
                .map(|p| p.into_iter().collect())
                .unwrap_or_default(),
            created: props.get("Created").and_then(Value::as_u64).unwrap_or(0),
        })
    }

    /// The secret and its content type.
    pub fn secret(&self, item: &str) -> Result<(Zeroizing<Vec<u8>>, String), String> {
        let b = self.call(
            item,
            n::I_ITEM,
            "GetSecret",
            vec![Value::path(&self.session)],
        )?;
        let f = b
            .first()
            .and_then(Value::as_struct)
            .filter(|f| f.len() == 4)
            .ok_or("GetSecret returned a malformed secret")?;
        let (iv, value) = (
            f[1].as_bytes().unwrap_or(&[]),
            f[2].as_bytes().unwrap_or(&[]),
        );
        let content_type = f[3].as_str().unwrap_or("text/plain").to_string();
        let plain = match &self.key {
            Some(k) => dh::decrypt(k, iv, value)?,
            None => Zeroizing::new(value.to_vec()),
        };
        Ok((plain, content_type))
    }

    pub fn close(&self) {
        let _ = self.call(&self.session, n::I_SESSION, "Close", vec![]);
        self.conn.close();
    }
}
