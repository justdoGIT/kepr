// cli_desktop/dbus/msg.rs — D-Bus messages.
//
//   byte 0   endianness ('l' or 'B')      byte 1  type
//   byte 2   flags                        byte 3  protocol version (1)
//   4..8     body length                  8..12   serial
//   12..     header fields a(yv), padded to 8, then the body
//
// We always write little endian and read either.

use zeroize::Zeroizing;

use super::marshal::Writer;
use super::sig::{self, Type};
use super::unmarshal::Reader;
use super::value::Value;

pub const METHOD_CALL: u8 = 1;
pub const METHOD_RETURN: u8 = 2;
pub const ERROR: u8 = 3;
pub const SIGNAL: u8 = 4;
pub const NO_REPLY_EXPECTED: u8 = 1;

/// Largest message accepted (the protocol allows 128 MiB; a keyring needs
/// nowhere near that).
pub const MAX_MESSAGE: usize = 4 * 1024 * 1024;
const MAX_FIELDS: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Message {
    pub kind: u8,
    pub flags: u8,
    pub serial: u32,
    pub path: Option<String>,
    pub interface: Option<String>,
    pub member: Option<String>,
    pub error_name: Option<String>,
    pub reply_serial: Option<u32>,
    pub destination: Option<String>,
    pub sender: Option<String>,
    pub body: Vec<Value>,
}

fn name_ok(s: &str, dotted: bool, hyphen: bool) -> bool {
    let part = |p: &str| {
        !p.is_empty()
            && !p.as_bytes()[0].is_ascii_digit()
            && p.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || (hyphen && b == b'-'))
    };
    s.len() <= 255
        && if dotted {
            s.split('.').count() >= 2 && s.split('.').all(part)
        } else {
            part(s)
        }
}

pub fn valid_interface(s: &str) -> bool {
    name_ok(s, true, false)
}

pub fn valid_member(s: &str) -> bool {
    name_ok(s, false, false)
}

/// A unique (`:1.23`) or well-known bus name.
pub fn valid_bus_name(s: &str) -> bool {
    match s.strip_prefix(':') {
        Some(rest) => {
            s.len() <= 255
                && !rest.is_empty()
                && rest.split('.').all(|p| {
                    !p.is_empty()
                        && p.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                })
        }
        None => name_ok(s, true, true),
    }
}

impl Message {
    pub fn call(dest: &str, path: &str, iface: &str, member: &str, body: Vec<Value>) -> Self {
        Message {
            kind: METHOD_CALL,
            destination: Some(dest.into()),
            path: Some(path.into()),
            interface: Some(iface.into()),
            member: Some(member.into()),
            body,
            ..Default::default()
        }
    }

    pub fn signal(path: &str, iface: &str, member: &str, body: Vec<Value>) -> Self {
        Message {
            kind: SIGNAL,
            path: Some(path.into()),
            interface: Some(iface.into()),
            member: Some(member.into()),
            body,
            ..Default::default()
        }
    }

    pub fn reply_to(&self, body: Vec<Value>) -> Self {
        Message {
            kind: METHOD_RETURN,
            flags: NO_REPLY_EXPECTED,
            reply_serial: Some(self.serial),
            destination: self.sender.clone(),
            body,
            ..Default::default()
        }
    }

    pub fn error_to(&self, name: &str, text: &str) -> Self {
        Message {
            kind: ERROR,
            flags: NO_REPLY_EXPECTED,
            error_name: Some(name.into()),
            reply_serial: Some(self.serial),
            destination: self.sender.clone(),
            body: vec![Value::str(text)],
            ..Default::default()
        }
    }

    pub fn wants_reply(&self) -> bool {
        self.kind == METHOD_CALL && self.flags & NO_REPLY_EXPECTED == 0
    }

    pub fn signature(&self) -> String {
        self.body.iter().map(Value::sig).collect()
    }

    fn fields(&self) -> Value {
        let mut f: Vec<(u8, Value)> = Vec::new();
        let mut add = |code: u8, v: Option<Value>| {
            if let Some(v) = v {
                f.push((code, v));
            }
        };
        add(1, self.path.clone().map(Value::Path));
        add(2, self.interface.clone().map(Value::Str));
        add(3, self.member.clone().map(Value::Str));
        add(4, self.error_name.clone().map(Value::Str));
        add(5, self.reply_serial.map(Value::U32));
        add(6, self.destination.clone().map(Value::Str));
        add(7, self.sender.clone().map(Value::Str));
        add(
            8,
            (!self.body.is_empty()).then(|| Value::Sig(self.signature())),
        );
        let entry = Type::Struct(vec![Type::Byte, Type::Variant]);
        let items = f
            .into_iter()
            .map(|(c, v)| Value::Struct(vec![Value::Byte(c), Value::variant(v)]))
            .collect();
        Value::Array(entry, items)
    }

    /// The bytes to send, under `serial`. Wiped when dropped: bodies carry
    /// secrets.
    pub fn encode(&self, serial: u32) -> Result<Zeroizing<Vec<u8>>, String> {
        let mut body = Writer::default();
        for v in &self.body {
            body.write(v)?;
        }
        let body = Zeroizing::new(body.buf);
        let mut w = Writer::default();
        w.buf.extend_from_slice(&[b'l', self.kind, self.flags, 1]);
        w.buf.extend_from_slice(&(body.len() as u32).to_le_bytes());
        w.buf.extend_from_slice(&serial.to_le_bytes());
        w.write(&self.fields())?;
        w.align(8);
        w.buf.extend_from_slice(&body);
        if w.buf.len() > MAX_MESSAGE {
            return Err("message too large".into());
        }
        Ok(Zeroizing::new(w.buf))
    }

    /// Total length of the message whose first 16 bytes these are.
    pub fn total_len(head: &[u8; 16]) -> Result<usize, String> {
        let le = match head[0] {
            b'l' => true,
            b'B' => false,
            _ => return Err("bad endianness byte".into()),
        };
        let word = |i: usize| {
            let a = [head[i], head[i + 1], head[i + 2], head[i + 3]];
            if le {
                u32::from_le_bytes(a)
            } else {
                u32::from_be_bytes(a)
            }
        };
        let (body, fields) = (word(4) as usize, word(12) as usize);
        if fields > MAX_FIELDS || body > MAX_MESSAGE {
            return Err("message too large".into());
        }
        let total = (16 + fields).div_ceil(8) * 8 + body;
        if total > MAX_MESSAGE {
            return Err("message too large".into());
        }
        Ok(total)
    }

    pub fn decode(b: &[u8]) -> Result<Message, String> {
        let head: &[u8; 16] = b
            .get(..16)
            .and_then(|h| h.try_into().ok())
            .ok_or("short message")?;
        if Self::total_len(head)? != b.len() {
            return Err("message length mismatch".into());
        }
        let le = head[0] == b'l';
        if head[3] != 1 {
            return Err("unsupported protocol version".into());
        }
        let body_len = {
            let a = [head[4], head[5], head[6], head[7]];
            if le {
                u32::from_le_bytes(a)
            } else {
                u32::from_be_bytes(a)
            }
        } as usize;
        let serial = {
            let a = [head[8], head[9], head[10], head[11]];
            if le {
                u32::from_le_bytes(a)
            } else {
                u32::from_be_bytes(a)
            }
        };
        let mut m = Message {
            kind: head[1],
            flags: head[2],
            serial,
            ..Default::default()
        };
        if !(METHOD_CALL..=SIGNAL).contains(&m.kind) || serial == 0 {
            return Err("bad message type or serial".into());
        }
        let header_end = b.len() - body_len;
        let mut r = Reader::new(&b[..header_end], 12, le);
        let entry = Type::Struct(vec![Type::Byte, Type::Variant]);
        let fields = r.read(&Type::Array(Box::new(entry)), 0)?;
        let mut signature = String::new();
        for f in fields.as_array().unwrap_or_default() {
            let (code, v) = match f.as_struct() {
                Some([Value::Byte(c), v]) => (*c, v.unwrap_variant()),
                _ => return Err("bad header field".into()),
            };
            let text = |ok: bool| -> Result<Option<String>, String> {
                match (ok, v.as_str()) {
                    (true, Some(s)) => Ok(Some(s.to_string())),
                    _ => Err(format!("header field {code} has the wrong type or value")),
                }
            };
            match (code, v) {
                (1, Value::Path(_)) => m.path = text(true)?,
                (2, Value::Str(s)) => m.interface = text(valid_interface(s))?,
                (3, Value::Str(s)) => m.member = text(valid_member(s))?,
                (4, Value::Str(s)) => m.error_name = text(valid_interface(s))?,
                (5, Value::U32(n)) => m.reply_serial = Some(*n),
                (6, Value::Str(s)) => m.destination = text(valid_bus_name(s))?,
                (7, Value::Str(s)) => m.sender = text(valid_bus_name(s))?,
                (8, Value::Sig(s)) => signature = s.clone(),
                (9, Value::U32(_)) => return Err("file descriptors are not supported".into()),
                (1..=9, _) => return Err(format!("header field {code} has the wrong type")),
                _ => {} // unknown fields are ignored
            }
        }
        r.align(8)?;
        if !r.done() {
            return Err("garbage after the header fields".into());
        }
        let need = |ok: bool| {
            if ok {
                Ok(())
            } else {
                Err("a required header field is missing")
            }
        };
        match m.kind {
            METHOD_CALL => need(m.path.is_some() && m.member.is_some())?,
            SIGNAL => need(m.path.is_some() && m.interface.is_some() && m.member.is_some())?,
            ERROR => need(m.error_name.is_some() && m.reply_serial.is_some())?,
            _ => need(m.reply_serial.is_some())?,
        }
        let types = sig::parse(&signature)?;
        let mut br = Reader::new(&b[header_end..], 0, le);
        m.body = br.read_all(&types)?;
        if !br.done() {
            return Err("bytes left after the body".into());
        }
        Ok(m)
    }
}
