// cli_desktop/dbus/sig.rs — D-Bus type signatures.
//
// `parse` turns a signature string into the complete types it lists. The
// limits are the specification's: 255 bytes, at most 32 levels of arrays
// and 32 of structs, dict entries only as array elements with a basic
// key, no empty structs.

#[derive(Debug, Clone, PartialEq)]
pub enum Type {
    Byte,
    Bool,
    I16,
    U16,
    I32,
    U32,
    I64,
    U64,
    F64,
    Str,
    Path,
    Sig,
    Fd,
    Variant,
    Array(Box<Type>),
    Struct(Vec<Type>),
    /// `{kv}`; only inside an array.
    Dict(Box<Type>, Box<Type>),
}

pub const MAX_SIG: usize = 255;
const MAX_DEPTH: usize = 32;

impl Type {
    /// Alignment of a value of this type in the marshalled stream.
    pub fn align(&self) -> usize {
        match self {
            Type::Byte | Type::Sig | Type::Variant => 1,
            Type::I16 | Type::U16 => 2,
            Type::Bool | Type::I32 | Type::U32 | Type::Str | Type::Path | Type::Fd => 4,
            Type::Array(_) => 4,
            Type::I64 | Type::U64 | Type::F64 | Type::Struct(_) | Type::Dict(..) => 8,
        }
    }

    pub fn is_basic(&self) -> bool {
        !matches!(
            self,
            Type::Variant | Type::Array(_) | Type::Struct(_) | Type::Dict(..)
        )
    }

    pub fn write_sig(&self, out: &mut String) {
        match self {
            Type::Byte => out.push('y'),
            Type::Bool => out.push('b'),
            Type::I16 => out.push('n'),
            Type::U16 => out.push('q'),
            Type::I32 => out.push('i'),
            Type::U32 => out.push('u'),
            Type::I64 => out.push('x'),
            Type::U64 => out.push('t'),
            Type::F64 => out.push('d'),
            Type::Str => out.push('s'),
            Type::Path => out.push('o'),
            Type::Sig => out.push('g'),
            Type::Fd => out.push('h'),
            Type::Variant => out.push('v'),
            Type::Array(e) => {
                out.push('a');
                e.write_sig(out);
            }
            Type::Struct(fields) => {
                out.push('(');
                fields.iter().for_each(|f| f.write_sig(out));
                out.push(')');
            }
            Type::Dict(k, v) => {
                out.push('{');
                k.write_sig(out);
                v.write_sig(out);
                out.push('}');
            }
        }
    }

    pub fn sig(&self) -> String {
        let mut s = String::new();
        self.write_sig(&mut s);
        s
    }
}

/// The signature string of a list of types.
pub fn join(types: &[Type]) -> String {
    let mut s = String::new();
    types.iter().for_each(|t| t.write_sig(&mut s));
    s
}

/// All complete types in `sig`.
pub fn parse(sig: &str) -> Result<Vec<Type>, String> {
    if sig.len() > MAX_SIG {
        return Err("signature too long".into());
    }
    let b = sig.as_bytes();
    let mut pos = 0;
    let mut out = Vec::new();
    while pos < b.len() {
        out.push(one(b, &mut pos, (0, 0))?);
    }
    Ok(out)
}

/// Exactly one complete type (a variant's signature).
pub fn parse_one(sig: &str) -> Result<Type, String> {
    let mut t = parse(sig)?;
    if t.len() == 1 {
        Ok(t.remove(0))
    } else {
        Err("a variant holds exactly one value".into())
    }
}

fn one(b: &[u8], pos: &mut usize, (arrays, structs): (usize, usize)) -> Result<Type, String> {
    let c = *b.get(*pos).ok_or("signature ends inside a type")?;
    *pos += 1;
    Ok(match c {
        b'y' => Type::Byte,
        b'b' => Type::Bool,
        b'n' => Type::I16,
        b'q' => Type::U16,
        b'i' => Type::I32,
        b'u' => Type::U32,
        b'x' => Type::I64,
        b't' => Type::U64,
        b'd' => Type::F64,
        b's' => Type::Str,
        b'o' => Type::Path,
        b'g' => Type::Sig,
        b'h' => Type::Fd,
        b'v' => Type::Variant,
        b'a' => {
            if arrays >= MAX_DEPTH {
                return Err("arrays nested too deeply".into());
            }
            if b.get(*pos) == Some(&b'{') {
                *pos += 1;
                let k = one(b, pos, (arrays + 1, structs))?;
                if !k.is_basic() {
                    return Err("dict entry key must be a basic type".into());
                }
                let v = one(b, pos, (arrays + 1, structs))?;
                if b.get(*pos) != Some(&b'}') {
                    return Err("dict entry must have exactly a key and a value".into());
                }
                *pos += 1;
                Type::Array(Box::new(Type::Dict(Box::new(k), Box::new(v))))
            } else {
                Type::Array(Box::new(one(b, pos, (arrays + 1, structs))?))
            }
        }
        b'(' => {
            if structs >= MAX_DEPTH {
                return Err("structs nested too deeply".into());
            }
            let mut fields = Vec::new();
            while b.get(*pos) != Some(&b')') {
                if *pos >= b.len() {
                    return Err("struct is not closed".into());
                }
                fields.push(one(b, pos, (arrays, structs + 1))?);
            }
            *pos += 1;
            if fields.is_empty() {
                return Err("empty struct".into());
            }
            Type::Struct(fields)
        }
        other => return Err(format!("unknown type code '{}'", other as char)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_secret_service_signatures_round_trip() {
        for s in [
            "",
            "s",
            "a{sv}",
            "a{ss}",
            "a{o(oayays)}",
            "(oayays)",
            "ao",
            "oo",
            "sv",
            "ya(yv)",
            "a{sa{sv}}",
            "bv",
        ] {
            assert_eq!(join(&parse(s).unwrap()), s, "{s}");
        }
        assert_eq!(parse("a{sv}").unwrap().len(), 1);
        assert_eq!(parse("oo").unwrap().len(), 2);
    }

    #[test]
    fn alignments() {
        let al = |s: &str| parse(s).unwrap()[0].align();
        assert_eq!(
            [
                al("y"),
                al("n"),
                al("u"),
                al("t"),
                al("s"),
                al("g"),
                al("v")
            ],
            [1, 2, 4, 8, 4, 1, 1]
        );
        assert_eq!(
            [al("ay"), al("a(yy)"), al("(y)"), al("a{ss}")],
            [4, 4, 8, 4]
        );
    }

    #[test]
    fn malformed_signatures_are_refused() {
        for bad in [
            "a", "(", "(s", "()", "{sv}", "a{v}", "a{sv", "a{svv}", "a{(s)s}", "z", "a{vs}", "a{}",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
        assert!(parse(&"a".repeat(33)).is_err(), "arrays 33 deep");
        assert!(parse(&format!("{}y", "a".repeat(32))).is_ok());
        assert!(parse(&format!("{}y{}", "(".repeat(33), ")".repeat(33))).is_err());
        assert!(parse(&"y".repeat(256)).is_err());
        assert!(parse_one("ss").is_err());
        assert!(parse_one("").is_err());
        assert_eq!(parse_one("a{sv}").unwrap().sig(), "a{sv}");
    }
}
