// cli_desktop/dbus/unmarshal.rs — D-Bus wire bytes to values.
//
// The input comes from other programs in the user's session, so every
// length is checked against what is left, padding must be zero, strings
// must be UTF-8 with their NUL, booleans 0 or 1, object paths and
// signatures well formed, and nesting is bounded.

use super::marshal::{valid_path, MAX_ARRAY};
use super::sig::{self, Type};
use super::value::Value;

const MAX_DEPTH: usize = 64;

pub struct Reader<'a> {
    b: &'a [u8],
    pub pos: usize,
    le: bool,
}

impl<'a> Reader<'a> {
    pub fn new(b: &'a [u8], pos: usize, le: bool) -> Self {
        Reader { b, pos, le }
    }

    pub fn done(&self) -> bool {
        self.pos == self.b.len()
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.pos.checked_add(n).filter(|e| *e <= self.b.len());
        let end = end.ok_or("message is shorter than its contents")?;
        let s = &self.b[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    pub fn align(&mut self, n: usize) -> Result<(), String> {
        let pad = (n - self.pos % n) % n;
        if self.take(pad)?.iter().any(|b| *b != 0) {
            return Err("padding is not zero".into());
        }
        Ok(())
    }

    fn num<const N: usize>(&mut self) -> Result<[u8; N], String> {
        self.align(N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(self.take(N)?);
        if !self.le {
            a.reverse();
        }
        Ok(a)
    }

    pub fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.num::<4>()?))
    }

    fn string(&mut self) -> Result<String, String> {
        let n = self.u32()? as usize;
        let s = self.take(n)?;
        if self.take(1)? != [0] {
            return Err("string is not NUL terminated".into());
        }
        let s = std::str::from_utf8(s).map_err(|_| "string is not UTF-8")?;
        if s.contains('\0') {
            return Err("string holds a NUL byte".into());
        }
        Ok(s.to_string())
    }

    fn signature(&mut self) -> Result<String, String> {
        let n = self.take(1)?[0] as usize;
        let s = self.take(n)?;
        if self.take(1)? != [0] {
            return Err("signature is not NUL terminated".into());
        }
        let s = std::str::from_utf8(s).map_err(|_| "signature is not UTF-8")?;
        sig::parse(s)?;
        Ok(s.to_string())
    }

    pub fn read_all(&mut self, types: &[Type]) -> Result<Vec<Value>, String> {
        types.iter().map(|t| self.read(t, 0)).collect()
    }

    pub fn read(&mut self, t: &Type, depth: usize) -> Result<Value, String> {
        if depth > MAX_DEPTH {
            return Err("values nested too deeply".into());
        }
        Ok(match t {
            Type::Byte => Value::Byte(self.take(1)?[0]),
            Type::Bool => match self.u32()? {
                0 => Value::Bool(false),
                1 => Value::Bool(true),
                _ => return Err("boolean is neither 0 nor 1".into()),
            },
            Type::I16 => Value::I16(i16::from_le_bytes(self.num::<2>()?)),
            Type::U16 => Value::U16(u16::from_le_bytes(self.num::<2>()?)),
            Type::I32 => Value::I32(i32::from_le_bytes(self.num::<4>()?)),
            Type::U32 => Value::U32(self.u32()?),
            Type::I64 => Value::I64(i64::from_le_bytes(self.num::<8>()?)),
            Type::U64 => Value::U64(u64::from_le_bytes(self.num::<8>()?)),
            Type::F64 => Value::F64(f64::from_le_bytes(self.num::<8>()?)),
            Type::Str => Value::Str(self.string()?),
            Type::Path => {
                let p = self.string()?;
                if !valid_path(&p) {
                    return Err(format!("invalid object path {p:?}"));
                }
                Value::Path(p)
            }
            Type::Sig => Value::Sig(self.signature()?),
            Type::Fd => return Err("file descriptors are not supported".into()),
            Type::Variant => {
                let inner = sig::parse_one(&self.signature()?)?;
                Value::Variant(Box::new(self.read(&inner, depth + 1)?))
            }
            Type::Array(elem) => self.array(elem, depth)?,
            Type::Struct(fields) => {
                self.align(8)?;
                let mut out = Vec::with_capacity(fields.len());
                for f in fields {
                    out.push(self.read(f, depth + 1)?);
                }
                Value::Struct(out)
            }
            Type::Dict(k, v) => {
                self.align(8)?;
                let key = self.read(k, depth + 1)?;
                Value::Dict(Box::new(key), Box::new(self.read(v, depth + 1)?))
            }
        })
    }

    fn array(&mut self, elem: &Type, depth: usize) -> Result<Value, String> {
        let len = self.u32()? as usize;
        if len > MAX_ARRAY {
            return Err("array too long".into());
        }
        self.align(elem.align())?;
        if *elem == Type::Byte {
            return Ok(Value::Bytes(self.take(len)?.to_vec()));
        }
        let end = self
            .pos
            .checked_add(len)
            .filter(|e| *e <= self.b.len())
            .ok_or("array is longer than the message")?;
        let mut items = Vec::new();
        while self.pos < end {
            items.push(self.read(elem, depth + 1)?);
        }
        if self.pos != end {
            return Err("array elements overrun its length".into());
        }
        Ok(Value::Array(elem.clone(), items))
    }
}

#[cfg(test)]
mod tests {
    use super::super::marshal::Writer;
    use super::*;

    fn round(v: Value) -> Value {
        let mut w = Writer::default();
        w.write(&v).unwrap();
        let mut r = Reader::new(&w.buf, 0, true);
        let out = r.read(&v.ty(), 0).unwrap();
        assert!(r.done(), "{v:?} left bytes");
        out
    }

    #[test]
    fn everything_the_secret_service_sends_round_trips() {
        let secret = Value::Struct(vec![
            Value::path("/org/freedesktop/secrets/session/s1"),
            Value::Bytes((0..16).collect()),
            Value::Bytes(b"correct horse".to_vec()),
            Value::str("text/plain; charset=utf8"),
        ]);
        let all = Value::Array(
            Type::Dict(Box::new(Type::Path), Box::new(secret.ty())),
            vec![Value::Dict(
                Box::new(Value::path("/a/b")),
                Box::new(secret.clone()),
            )],
        );
        for v in [
            Value::Byte(7),
            Value::Bool(true),
            Value::I16(-2),
            Value::U16(9),
            Value::I32(-9),
            Value::U32(77),
            Value::I64(-1),
            Value::U64(u64::MAX),
            Value::F64(1.5),
            Value::str("héllo"),
            Value::Sig("a{sv}".into()),
            secret,
            all,
            Value::paths(vec!["/a".to_string(), "/b".to_string()]),
            Value::paths(vec![]),
            Value::dict_sv(vec![
                ("Label".into(), Value::str("x")),
                (
                    "Attributes".into(),
                    Value::dict_ss(&std::collections::BTreeMap::from([(
                        "k".into(),
                        "v".into(),
                    )])),
                ),
            ]),
            Value::variant(Value::variant(Value::Bytes(vec![1, 2]))),
            Value::Bytes(vec![]),
        ] {
            assert_eq!(round(v.clone()), v);
        }
    }

    #[test]
    fn big_endian_input_is_read() {
        // u32 0x01020304 big endian, then a string "ab".
        let b = [1, 2, 3, 4, 0, 0, 0, 2, b'a', b'b', 0];
        let mut r = Reader::new(&b, 0, false);
        assert_eq!(r.read(&Type::U32, 0).unwrap(), Value::U32(0x0102_0304));
        assert_eq!(r.read(&Type::Str, 0).unwrap(), Value::str("ab"));
        assert!(r.done());
    }

    fn fails(sig: &str, bytes: &[u8]) {
        let mut r = Reader::new(bytes, 0, true);
        let t = sig::parse_one(sig).unwrap();
        assert!(r.read(&t, 0).is_err(), "{sig} accepted {bytes:?}");
    }

    #[test]
    fn hostile_input_is_refused() {
        fails("u", &[1, 2, 3]); // short
        fails("s", &[5, 0, 0, 0, b'a', 0]); // length beyond the data
        fails("s", &[1, 0, 0, 0, b'a', 1]); // no NUL
        fails("s", &[2, 0, 0, 0, b'a', 0, 0]); // NUL inside
        fails("s", &[1, 0, 0, 0, 0xff, 0]); // not UTF-8
        fails("b", &[2, 0, 0, 0]); // boolean 2
        fails("o", &[2, 0, 0, 0, b'a', b'b', 0]); // not a path
        fails("g", &[1, b'z', 0]); // bad signature
        fails("ay", &[255, 255, 255, 255]); // huge array
        fails("ay", &[4, 0, 0, 0, 1]); // longer than the message
        fails("au", &[3, 0, 0, 0, 1, 2, 3]); // not a multiple of the element
        fails("(yu)", &[1, 9, 9, 9, 9, 9, 9, 9, 1, 0, 0, 0]); // padding not zero
        fails("v", &[1, b'u', 0]); // variant value missing
        fails("v", &[2, b'u', b'u', 0]); // two types in a variant
        fails("h", &[0, 0, 0, 0]); // fds
                                   // Nested variants without end.
        let mut deep = Vec::new();
        for _ in 0..200 {
            deep.extend_from_slice(&[1, b'v', 0]);
        }
        fails("v", &deep);
    }
}
