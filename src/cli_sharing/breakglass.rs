// cli_sharing/breakglass.rs — T6.07 `kepr break-glass NAME`: paste k
// recovery-kit shares (masked, blank line to finish); the sealed value is
// printed once on stdout and the credential is marked must-rotate.

use kepr_core::generate::ZeroString;
use kepr_core::protocol::Response;
use kepr_core::protocol_sharing::SharingRequest;

use super::send;
use crate::cli_input::read_masked;
use crate::{cli_mode, cli_ui};

const USAGE: &str = "usage: kepr break-glass NAME";

pub fn cmd_break_glass(args: &[String]) -> Response {
    let [name] = args else {
        return Response::fail(USAGE);
    };
    cli_ui::warn(&format!(
        "break-glass reveals sealed {} and marks it must-rotate; this is audited",
        name.to_uppercase()
    ));
    let mut shares = Vec::new();
    loop {
        let s = read_masked(&format!(
            "  Recovery share {} (blank line when done): ",
            shares.len() + 1
        ));
        if s.as_str().trim().is_empty() {
            break;
        }
        shares.push(ZeroString::from_string(s.as_str().trim().to_string()));
    }
    if shares.len() < 2 {
        return Response::fail("paste at least the kit's threshold number of shares");
    }
    let r = send(SharingRequest::BreakGlass {
        name: name.to_uppercase(),
        shares,
    });
    if let (Response::GetOk { name, value }, false) = (&r, cli_mode::json_mode()) {
        println!("{}", value.as_str());
        cli_ui::einfo(&format!(
            "{name} is now marked must-rotate: replace it at its provider, then store the new \
             value (kepr agent add / kepr set), which clears the mark"
        ));
        return Response::Pong;
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn needs_exactly_one_name() {
        assert!(matches!(cmd_break_glass(&[]), Response::Err { .. }));
        let two = ["A".to_string(), "B".to_string()];
        assert!(matches!(cmd_break_glass(&two), Response::Err { .. }));
    }
}
