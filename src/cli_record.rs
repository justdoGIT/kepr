// cli_record.rs — typed records (agent vault P5.1).
//
//   kepr record add NAME --type T [--field k=v | --field k=-]... [--requires-consent]
//       `k=-` (or a type's field left out) is prompted for, hidden.
//       `--field k[]=v` appends to a list, `--custom LABEL=v` sets a
//       custom field (T5.05), `--ref k=OTHER` links to the record OTHER
//       (T11.6: `kepr://NAME/k/field` reads OTHER's field); T11.8:
//       `--from-file F` / `--clone OTHER` start from F's or OTHER's fields.
//   kepr record show NAME [--reveal]     fields, the type's masked ones starred
//   kepr record get NAME FIELD           one field's value, raw; FIELD is
//       anything after `kepr://NAME/` (url[1], custom_field/LABEL, ...)
//   kepr record template TYPE            JSON skeleton for --from-file (T11.8)
//   kepr record types [--export DIR]     known types and their fields (T11.7:
//       built-ins plus ~/.config/kepr/types/*.toml; cli_recordsx/types.rs)
//   kepr record convert NAME TYPE        re-type a record, unmatched fields
//       kept as custom fields (T11.7)
//
// add / show / template live in cli_recordsx/record_add.rs.
// `kepr://NAME/field` in `kepr inject` templates reads one field.

use kepr_core::protocol::Response;

use crate::cli_recordsx::notation;
use crate::cli_recordsx::resolve;

const USAGE: &str = "usage: kepr record add NAME --type T [--field k=v | k[]=v]... [--custom LABEL=v]... [--ref k=OTHER]... [--from-file F | --clone OTHER] | show NAME [--reveal] | get NAME FIELD | template TYPE | types [--export DIR] | convert NAME TYPE";

pub fn cmd_record(args: &[String]) -> Response {
    let rest = args.get(1..).unwrap_or_default();
    match (args.first().map(String::as_str), rest) {
        (Some("add"), _) => crate::cli_recordsx::record_add::cmd_add(rest),
        (Some("show"), [name, ..]) => {
            crate::cli_recordsx::record_add::cmd_show(name, rest.iter().any(|a| a == "--reveal"))
        }
        (Some("template"), _) => crate::cli_recordsx::record_add::cmd_template(rest), // T11.8
        (Some("get"), [name, field]) => {
            let n = notation::parse(&format!("{}{name}/{field}", notation::PREFIX));
            match n.and_then(|n| resolve::resolve(&n, &resolve::Daemon)) {
                Ok(v) => {
                    println!("{}", v.as_str());
                    Response::Pong
                }
                Err(e) => Response::fail(e),
            }
        }
        (Some("types"), _) => crate::cli_recordsx::types::cmd_types(rest), // T11.7
        (Some("convert"), _) => crate::cli_recordsx::types::cmd_convert(rest), // T11.7
        _ => Response::fail(USAGE),
    }
}
