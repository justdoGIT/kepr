// cli_desktop/dbus/value.rs — D-Bus values.
//
// An `ay` is `Bytes` (secrets travel in them; a Vec of a Value per byte
// would be 16x the size). Empty arrays carry their element type, so they
// still marshal. `wipe` zeroes whatever a value holds: secrets pass
// through here on their way to and from the Secret Service clients.

use super::sig::Type;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Byte(u8),
    Bool(bool),
    I16(i16),
    U16(u16),
    I32(i32),
    U32(u32),
    I64(i64),
    U64(u64),
    F64(f64),
    Str(String),
    Path(String),
    Sig(String),
    Variant(Box<Value>),
    Array(Type, Vec<Value>),
    Bytes(Vec<u8>),
    Struct(Vec<Value>),
    /// A dict entry; only inside an `Array`.
    Dict(Box<Value>, Box<Value>),
}

impl Value {
    pub fn ty(&self) -> Type {
        match self {
            Value::Byte(_) => Type::Byte,
            Value::Bool(_) => Type::Bool,
            Value::I16(_) => Type::I16,
            Value::U16(_) => Type::U16,
            Value::I32(_) => Type::I32,
            Value::U32(_) => Type::U32,
            Value::I64(_) => Type::I64,
            Value::U64(_) => Type::U64,
            Value::F64(_) => Type::F64,
            Value::Str(_) => Type::Str,
            Value::Path(_) => Type::Path,
            Value::Sig(_) => Type::Sig,
            Value::Variant(_) => Type::Variant,
            Value::Array(t, _) => Type::Array(Box::new(t.clone())),
            Value::Bytes(_) => Type::Array(Box::new(Type::Byte)),
            Value::Struct(f) => Type::Struct(f.iter().map(Value::ty).collect()),
            Value::Dict(k, v) => Type::Dict(Box::new(k.ty()), Box::new(v.ty())),
        }
    }

    pub fn sig(&self) -> String {
        self.ty().sig()
    }

    pub fn str(s: impl Into<String>) -> Value {
        Value::Str(s.into())
    }

    pub fn path(s: impl Into<String>) -> Value {
        Value::Path(s.into())
    }

    pub fn variant(v: Value) -> Value {
        Value::Variant(Box::new(v))
    }

    /// `ao`.
    pub fn paths<I: IntoIterator<Item = String>>(paths: I) -> Value {
        Value::Array(Type::Path, paths.into_iter().map(Value::Path).collect())
    }

    /// `a{ss}`.
    pub fn dict_ss<'a, I: IntoIterator<Item = (&'a String, &'a String)>>(pairs: I) -> Value {
        let entry = |(k, v): (&String, &String)| {
            Value::Dict(
                Box::new(Value::str(k.as_str())),
                Box::new(Value::str(v.as_str())),
            )
        };
        Value::Array(
            Type::Dict(Box::new(Type::Str), Box::new(Type::Str)),
            pairs.into_iter().map(entry).collect(),
        )
    }

    /// `a{sv}`.
    pub fn dict_sv(pairs: Vec<(String, Value)>) -> Value {
        let entry = |(k, v): (String, Value)| {
            Value::Dict(Box::new(Value::Str(k)), Box::new(Value::variant(v)))
        };
        Value::Array(
            Type::Dict(Box::new(Type::Str), Box::new(Type::Variant)),
            pairs.into_iter().map(entry).collect(),
        )
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) | Value::Path(s) | Value::Sig(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_u32(&self) -> Option<u32> {
        match self {
            Value::U32(n) => Some(*n),
            _ => None,
        }
    }

    /// A `t` (or a `u`, which some services use for times).
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::U64(n) => Some(*n),
            Value::U32(n) => Some(u64::from(*n)),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// The value inside a variant (or the value itself).
    pub fn unwrap_variant(&self) -> &Value {
        match self {
            Value::Variant(v) => v.unwrap_variant(),
            other => other,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(_, items) => Some(items),
            _ => None,
        }
    }

    pub fn as_struct(&self) -> Option<&[Value]> {
        match self {
            Value::Struct(f) => Some(f),
            _ => None,
        }
    }

    /// `ao` / `as` as strings.
    pub fn strings(&self) -> Option<Vec<String>> {
        self.as_array()?
            .iter()
            .map(|v| v.as_str().map(String::from))
            .collect()
    }

    /// `a{ss}` as pairs.
    pub fn pairs_ss(&self) -> Option<Vec<(String, String)>> {
        self.as_array()?
            .iter()
            .map(|e| match e {
                Value::Dict(k, v) => Some((k.as_str()?.to_string(), v.as_str()?.to_string())),
                _ => None,
            })
            .collect()
    }

    /// `a{sv}` as pairs, variants unwrapped.
    pub fn pairs_sv(&self) -> Option<Vec<(String, &Value)>> {
        self.as_array()?
            .iter()
            .map(|e| match e {
                Value::Dict(k, v) => Some((k.as_str()?.to_string(), v.unwrap_variant())),
                _ => None,
            })
            .collect()
    }

    /// Zero every byte and string this value holds.
    pub fn wipe(&mut self) {
        match self {
            Value::Bytes(b) => zeroize::Zeroize::zeroize(b),
            Value::Str(s) | Value::Path(s) | Value::Sig(s) => zeroize::Zeroize::zeroize(s),
            Value::Variant(v) => v.wipe(),
            Value::Array(_, items) | Value::Struct(items) => items.iter_mut().for_each(Value::wipe),
            Value::Dict(k, v) => {
                k.wipe();
                v.wipe();
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers_build_the_types_the_secret_service_uses() {
        assert_eq!(Value::paths(vec!["/a".to_string()]).sig(), "ao");
        assert_eq!(Value::paths(Vec::new()).sig(), "ao");
        let attrs = std::collections::BTreeMap::from([("k".to_string(), "v".to_string())]);
        assert_eq!(Value::dict_ss(&attrs).sig(), "a{ss}");
        assert_eq!(
            Value::dict_sv(vec![("Label".into(), Value::str("x"))]).sig(),
            "a{sv}"
        );
        let secret = Value::Struct(vec![
            Value::path("/s"),
            Value::Bytes(vec![]),
            Value::Bytes(vec![1]),
            Value::str("text/plain"),
        ]);
        assert_eq!(secret.sig(), "(oayays)");
    }

    #[test]
    fn accessors_look_through_variants_and_dicts() {
        let d = Value::dict_sv(vec![
            ("a".into(), Value::U32(7)),
            ("b".into(), Value::Bool(true)),
        ]);
        let pairs = d.pairs_sv().unwrap();
        assert_eq!(pairs[0].0, "a");
        assert_eq!(pairs[0].1.as_u32(), Some(7));
        assert_eq!(pairs[1].1.as_bool(), Some(true));
        let ss = Value::dict_ss(&std::collections::BTreeMap::from([(
            "x".to_string(),
            "y".to_string(),
        )]));
        assert_eq!(ss.pairs_ss().unwrap(), [("x".to_string(), "y".to_string())]);
        assert_eq!(
            Value::variant(Value::variant(Value::U32(1)))
                .unwrap_variant()
                .as_u32(),
            Some(1)
        );
        assert!(Value::U32(1).as_str().is_none());
    }

    #[test]
    fn wipe_zeroes_nested_secrets() {
        let mut v = Value::Struct(vec![
            Value::Bytes(b"hunter2".to_vec()),
            Value::variant(Value::str("pw")),
        ]);
        v.wipe();
        match v {
            Value::Struct(f) => {
                assert!(f[0].as_bytes().unwrap().iter().all(|b| *b == 0));
                assert_eq!(
                    f[1].unwrap_variant()
                        .as_str()
                        .unwrap()
                        .bytes()
                        .filter(|b| *b != 0)
                        .count(),
                    0
                );
            }
            _ => unreachable!(),
        }
    }
}
