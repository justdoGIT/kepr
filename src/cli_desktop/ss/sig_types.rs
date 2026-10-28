// cli_desktop/ss/sig_types.rs — the one container type the Secret Service
// needs spelled out for empty arrays.

use crate::cli_desktop::dbus::sig::{self, Type};

/// `{o(oayays)}`, the element of GetSecrets' `a{o(oayays)}`.
pub fn secrets_map_type() -> Type {
    match sig::parse_one("a{o(oayays)}") {
        Ok(Type::Array(e)) => *e,
        _ => unreachable!("a constant signature"),
    }
}
