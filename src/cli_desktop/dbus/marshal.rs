// cli_desktop/dbus/marshal.rs — values to D-Bus wire bytes (little endian).
//
// Alignment is measured from the start of the buffer, which is the start
// of the message for the header and (the header being a multiple of 8
// long) equally for the body.

use super::sig::Type;
use super::value::Value;

/// Largest array the wire format allows (64 MiB).
pub const MAX_ARRAY: usize = 64 * 1024 * 1024;

#[derive(Default)]
pub struct Writer {
    pub buf: Vec<u8>,
}

impl Writer {
    pub fn align(&mut self, n: usize) {
        while !self.buf.len().is_multiple_of(n) {
            self.buf.push(0);
        }
    }

    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn u32(&mut self, v: u32) {
        self.align(4);
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn string(&mut self, s: &str) -> Result<(), String> {
        if s.contains('\0') {
            return Err("a string holds a NUL byte".into());
        }
        let n = u32::try_from(s.len()).map_err(|_| "string too long")?;
        self.u32(n);
        self.buf.extend_from_slice(s.as_bytes());
        self.buf.push(0);
        Ok(())
    }

    fn signature(&mut self, s: &str) -> Result<(), String> {
        if s.contains('\0') || s.len() > super::sig::MAX_SIG {
            return Err("bad signature".into());
        }
        self.buf.push(s.len() as u8);
        self.buf.extend_from_slice(s.as_bytes());
        self.buf.push(0);
        Ok(())
    }

    pub fn write(&mut self, v: &Value) -> Result<(), String> {
        match v {
            Value::Byte(b) => self.u8(*b),
            Value::Bool(b) => self.u32(u32::from(*b)),
            Value::I16(n) => {
                self.align(2);
                self.buf.extend_from_slice(&n.to_le_bytes());
            }
            Value::U16(n) => {
                self.align(2);
                self.buf.extend_from_slice(&n.to_le_bytes());
            }
            Value::I32(n) => {
                self.align(4);
                self.buf.extend_from_slice(&n.to_le_bytes());
            }
            Value::U32(n) => self.u32(*n),
            Value::I64(n) => {
                self.align(8);
                self.buf.extend_from_slice(&n.to_le_bytes());
            }
            Value::U64(n) => {
                self.align(8);
                self.buf.extend_from_slice(&n.to_le_bytes());
            }
            Value::F64(n) => {
                self.align(8);
                self.buf.extend_from_slice(&n.to_le_bytes());
            }
            Value::Str(s) => self.string(s)?,
            Value::Path(s) => {
                if !valid_path(s) {
                    return Err(format!("invalid object path {s:?}"));
                }
                self.string(s)?;
            }
            Value::Sig(s) => {
                super::sig::parse(s)?;
                self.signature(s)?;
            }
            Value::Variant(inner) => {
                self.signature(&inner.sig())?;
                self.write(inner)?;
            }
            Value::Bytes(b) => {
                if b.len() > MAX_ARRAY {
                    return Err("array too long".into());
                }
                self.u32(b.len() as u32);
                self.buf.extend_from_slice(b);
            }
            Value::Array(elem, items) => self.array(elem, items)?,
            Value::Struct(fields) => {
                if fields.is_empty() {
                    return Err("empty struct".into());
                }
                self.align(8);
                for f in fields {
                    self.write(f)?;
                }
            }
            Value::Dict(k, val) => {
                self.align(8);
                self.write(k)?;
                self.write(val)?;
            }
        }
        Ok(())
    }

    fn array(&mut self, elem: &Type, items: &[Value]) -> Result<(), String> {
        self.align(4);
        let len_at = self.buf.len();
        self.buf.extend_from_slice(&[0; 4]);
        self.align(elem.align());
        let start = self.buf.len();
        for item in items {
            if item.ty() != *elem {
                return Err(format!("array of {} holds a {}", elem.sig(), item.sig()));
            }
            self.write(item)?;
        }
        let len = self.buf.len() - start;
        if len > MAX_ARRAY {
            return Err("array too long".into());
        }
        self.buf[len_at..len_at + 4].copy_from_slice(&(len as u32).to_le_bytes());
        Ok(())
    }
}

/// D-Bus object path syntax.
pub fn valid_path(p: &str) -> bool {
    if p == "/" {
        return true;
    }
    p.starts_with('/')
        && p[1..]
            .split('/')
            .all(|e| !e.is_empty() && e.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(v: &Value) -> Vec<u8> {
        let mut w = Writer::default();
        w.write(v).unwrap();
        w.buf
    }

    #[test]
    fn basic_types_are_aligned() {
        // "s" then "u": the u32 starts on a 4-byte boundary.
        let mut w = Writer::default();
        w.write(&Value::str("a")).unwrap();
        w.write(&Value::U32(7)).unwrap();
        assert_eq!(w.buf, [1, 0, 0, 0, b'a', 0, 0, 0, 7, 0, 0, 0]);
        assert_eq!(bytes(&Value::Bool(true)), [1, 0, 0, 0]);
        assert_eq!(bytes(&Value::U64(1)), [1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            bytes(&Value::Sig("a{sv}".into())),
            [5, b'a', b'{', b's', b'v', b'}', 0]
        );
    }

    #[test]
    fn arrays_pad_before_the_first_element_not_in_the_length() {
        // ax: length 8, then 4 bytes of padding to 8, then the element.
        let v = Value::Array(Type::I64, vec![Value::I64(1)]);
        let b = bytes(&v);
        assert_eq!(b.len(), 16);
        assert_eq!(&b[0..4], &8u32.to_le_bytes());
        assert_eq!(&b[4..8], &[0; 4]);
        assert_eq!(&b[8..16], &1i64.to_le_bytes());
        // An empty array of 8-aligned elements still pads.
        let e = bytes(&Value::Array(Type::U64, vec![]));
        assert_eq!(e, [0; 8]);
        assert_eq!(bytes(&Value::Bytes(vec![1, 2, 3])), [3, 0, 0, 0, 1, 2, 3]);
    }

    #[test]
    fn variants_carry_their_signature() {
        assert_eq!(
            bytes(&Value::variant(Value::U32(5))),
            [1, b'u', 0, 0, 5, 0, 0, 0]
        );
        assert_eq!(
            bytes(&Value::variant(Value::str("x"))),
            [1, b's', 0, 0, 1, 0, 0, 0, b'x', 0]
        );
    }

    #[test]
    fn mistakes_are_errors_not_garbage() {
        let mut w = Writer::default();
        assert!(w.write(&Value::str("a\0b")).is_err());
        assert!(w.write(&Value::path("relative")).is_err());
        assert!(w.write(&Value::path("/a//b")).is_err());
        assert!(w.write(&Value::Struct(vec![])).is_err());
        assert!(w
            .write(&Value::Array(Type::U32, vec![Value::Byte(1)]))
            .is_err());
        assert!(w.write(&Value::Sig("a".into())).is_err());
        for ok in [
            "/",
            "/a",
            "/org/freedesktop/secrets/collection/login",
            "/a_1/B2",
        ] {
            assert!(valid_path(ok), "{ok}");
        }
        for bad in ["", "a", "/a/", "//", "/a-b", "/a b", "/é"] {
            assert!(!valid_path(bad), "{bad}");
        }
    }
}
