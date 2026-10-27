// cli_store/diff.rs — `kepr history NAME --diff A B` (T11.3): which
// record fields changed from version A to version B (0 = current).
// Field names only; the daemon never sends values.

use kepr_core::protocol::Response;
use kepr_core::protocol_store::{StoreRequest, StoreResponse};

use super::{plain_args, send};
use crate::{cli_mode, cli_ui};

const USAGE: &str =
    "usage: kepr history NAME --diff A B   (versions from kepr history; 0 = current)";

fn label(v: u32) -> String {
    if v == 0 {
        "current".into()
    } else {
        format!("version {v}")
    }
}

pub fn cmd_history_diff(args: &[String]) -> Response {
    let words: Vec<&str> = plain_args(args)
        .into_iter()
        .filter(|w| *w != "--diff")
        .collect();
    let [name, a, b] = words[..] else {
        return Response::fail(USAGE);
    };
    let (Ok(from), Ok(to)) = (a.parse::<u32>(), b.parse::<u32>()) else {
        return Response::fail(USAGE);
    };
    let r = send(StoreRequest::HistoryDiff {
        name: name.to_uppercase(),
        from,
        to,
    });
    if cli_mode::json_mode() {
        return r;
    }
    if let Response::Store(StoreResponse::HistoryDiffOk {
        name,
        from,
        to,
        changes,
    }) = &r
    {
        println!("  {name}: {} -> {}", label(*from), label(*to));
        if changes.is_empty() {
            cli_ui::info("no differences");
        }
        for c in changes {
            let mark = match c.change.as_str() {
                "added" => "+",
                "removed" => "-",
                _ => "~",
            };
            println!("  {mark} {:<32} {}", c.field, cli_ui::color("2", &c.change));
        }
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_errors() {
        let v = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert!(matches!(
            cmd_history_diff(&v(&["A", "--diff", "1"])),
            Response::Err { .. }
        ));
        assert!(matches!(
            cmd_history_diff(&v(&["A", "--diff", "x", "1"])),
            Response::Err { .. }
        ));
    }
}
