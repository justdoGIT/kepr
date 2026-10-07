// cli_recordsx/ — the `records` ticket batch, CLI side: `kepr attach`
// (T5.03), `kepr://` notation (T5.05), references in exec / manifests and
// `kepr resolve` (T5.06), manifest stages (T5.02), linked records (T11.6),
// record types and convert (T11.7). Registered in cli_more.rs.
// (`cli_record.rs` already holds `kepr record`, hence the x.)

mod attach;
pub mod notation;
pub mod refs;
pub mod resolve;
pub mod stages;
pub mod types;

use kepr_core::protocol::{Request, Response};
use kepr_core::protocol_records::RecordsRequest;

pub const VERBS: &[&str] = &["attach", "resolve"];

pub const HELP: &str = "\
  attach add KEY FILE [--as NAME]      attach a file to KEY, encrypted (16 MiB each, 64 MiB per key);
                                       attachments follow KEY into the trash and back
  attach get KEY NAME [-o OUT] [--force]  save one (mode 0600, checked against its SHA-256;
                                       `-o -`: stdout); refused for sealed or consent/FIDO2 keys
  attach ls KEY | attach rm KEY NAME   list / remove attachments
  resolve kepr://KEY/...               print what a reference stands for (sealed keys refused);
                                       exec/env also take --env VAR=kepr://... and [env.map]
  exec|env --stage S                   add the .kepr.toml [env.S] set (default: $KEPR_STAGE)
  record add KEY ... --ref k=OTHER     link field k to the record OTHER: kepr://KEY/k/field reads
                                       OTHER's field (each record read with its own get)
  record types [--export DIR]          built-in types plus yours (~/.config/kepr/types/*.toml:
                                       name, fields = [{name, type, required, masked}])
  record convert KEY TYPE              re-type a record; unmatched fields become custom fields
";

pub fn dispatch(verb: &str, args: &[String]) -> Response {
    match verb {
        "attach" => attach::cmd_attach(args),
        "resolve" => refs::cmd_resolve(args),
        other => Response::fail(format!("unknown command: {other}")),
    }
}

fn send(req: RecordsRequest) -> Response {
    crate::client::send_request(&Request::Records(req)).unwrap_or_else(Response::fail)
}
