// cli_recordsx/ — the `records` ticket batch, CLI side: `kepr attach`
// (T5.03), `kepr://` notation (T5.05), references in exec / manifests and
// `kepr resolve` (T5.06), manifest stages (T5.02), linked records (T11.6),
// record types and convert (T11.7), record add/show/template with field
// options, --from-file and --clone (T11.8), generator profiles and
// `kepr strength` (T5.04), `kepr health --period / --policy` reports
// (T11.11). Registered in cli_more.rs.
// (`cli_record.rs` already holds `kepr record`, hence the x.)

mod attach;
pub mod generate;
pub mod health;
pub mod notation;
pub mod record_add;
mod record_fields;
pub mod refs;
pub mod resolve;
pub mod stages;
pub mod types;

use kepr_core::protocol::{Request, Response};
use kepr_core::protocol_records::RecordsRequest;

pub const VERBS: &[&str] = &["attach", "resolve", "strength"];

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
  record template TYPE                 JSON skeleton; fill it in, then record add KEY --from-file F
  record add KEY --clone OTHER         start from OTHER's fields (not its attachments or history);
                                       a type's required fields must be set, masked ones are starred
  set KEY --generate --profile P       generate from profile P of ~/.config/kepr/generate.toml
                                       ([profile.P], [host.\"example.com\"], [type.T], [default]:
                                       length, classes, symbols, words, separator)
  record add KEY ... --generate FIELD  fill FIELD from --profile P, else the url/host's or type's
  strength                             estimate the bits of a value (typed hidden, or on stdin)
  health --period N[d|w|m|y]           aging report: keys unchanged for longer, oldest first
  health --policy FILE                 check min_length / classes / max_age_days, and [tag.T] rules
";

pub fn dispatch(verb: &str, args: &[String]) -> Response {
    match verb {
        "attach" => attach::cmd_attach(args),
        "resolve" => refs::cmd_resolve(args),
        "strength" => generate::cmd_strength(args),
        other => Response::fail(format!("unknown command: {other}")),
    }
}

fn send(req: RecordsRequest) -> Response {
    crate::client::send_request(&Request::Records(req)).unwrap_or_else(Response::fail)
}
