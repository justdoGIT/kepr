// cli_store/alias.rs — `kepr ln ALIAS NAME` (T11.5) and the warning
// `kepr rm NAME` prints when aliases point at NAME.

use kepr_core::protocol::{CredInfo, Request, Response};
use kepr_core::protocol_store::{StoreRequest, StoreResponse};

use super::{plain_args, send};
use crate::{cli_mode, cli_ui};

pub fn cmd_ln(args: &[String]) -> Response {
    let [alias, target] = plain_args(args)[..] else {
        return Response::fail("usage: kepr ln ALIAS NAME");
    };
    let r = send(StoreRequest::Link {
        alias: alias.to_uppercase(),
        target: target.to_uppercase(),
    });
    if let (false, Response::Store(StoreResponse::LinkOk { alias, target })) =
        (cli_mode::json_mode(), &r)
    {
        cli_ui::ok(&format!("{alias} -> {target}"));
    }
    r
}

/// Aliases among `creds` that point at `name`.
fn aliases_to<'a>(creds: &'a [CredInfo], name: &str) -> Vec<&'a str> {
    creds
        .iter()
        .filter(|c| c.alias_of.as_deref() == Some(name))
        .map(|c| c.name.as_str())
        .collect()
}

/// Before `rm NAME`: say which aliases will stop resolving.
pub fn warn_aliases(name: &str) {
    if let Ok(Response::ListOk { credentials, .. }) = crate::client::send_request(&Request::List) {
        let names = aliases_to(&credentials, name);
        if !names.is_empty() {
            cli_ui::warn(&format!(
                "{} point{} to {name} and will stop resolving",
                names.join(", "),
                if names.len() == 1 { "s" } else { "" }
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_aliases_of_a_name() {
        let c = |n: &str, to: Option<&str>| -> CredInfo {
            let mut c: CredInfo = serde_json::from_value(serde_json::json!({
                "name": n, "cred_name": "", "size": 0, "modified": ""
            }))
            .unwrap();
            c.alias_of = to.map(str::to_string);
            c
        };
        let creds = vec![
            c("A", None),
            c("B", Some("A")),
            c("C", Some("X")),
            c("D", Some("A")),
        ];
        assert_eq!(aliases_to(&creds, "A"), vec!["B", "D"]);
        assert!(aliases_to(&creds, "B").is_empty());
        assert!(matches!(cmd_ln(&["A".to_string()]), Response::Err { .. }));
    }
}
