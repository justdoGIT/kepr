// cli_recordsx/ — the `records` ticket batch, CLI side: `kepr attach`
// (T5.03), `kepr://` notation (T5.05). Registered in cli_more.rs.
// (`cli_record.rs` already holds `kepr record`, hence the x.)

mod attach;
pub mod notation;
pub mod resolve;

use kepr_core::protocol::{Request, Response};
use kepr_core::protocol_records::RecordsRequest;

pub const VERBS: &[&str] = &["attach"];

pub const HELP: &str = "\
  attach add KEY FILE [--as NAME]      attach a file to KEY, encrypted (16 MiB each, 64 MiB per key);
                                       attachments follow KEY into the trash and back
  attach get KEY NAME [-o OUT] [--force]  save one (mode 0600, checked against its SHA-256;
                                       `-o -`: stdout); refused for sealed or consent/FIDO2 keys
  attach ls KEY | attach rm KEY NAME   list / remove attachments
";

pub fn dispatch(verb: &str, args: &[String]) -> Response {
    match verb {
        "attach" => attach::cmd_attach(args),
        other => Response::fail(format!("unknown command: {other}")),
    }
}

fn send(req: RecordsRequest) -> Response {
    crate::client::send_request(&Request::Records(req)).unwrap_or_else(Response::fail)
}
