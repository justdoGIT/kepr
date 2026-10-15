// cli_session/profile.rs — `kepr --profile NAME …` (T11.16): the same as
// `KEPR_PROFILE=NAME kepr …`. The flag is taken from the global options
// in front of the command; kepr then re-executes itself with the variable
// set and the flag removed, so every parser below sees an ordinary
// command line and the daemon it starts inherits the profile.

use std::os::unix::process::CommandExt;

use kepr_core::protocol::Response;

const USAGE: &str = "usage: kepr --profile NAME COMMAND …";

/// Split `--profile NAME` / `--profile=NAME` out of the leading `--`
/// options of `raw` (argv). `Ok(None)` when there is none.
pub fn take_flag(raw: &[String]) -> Result<Option<(String, Vec<String>)>, String> {
    let mut i = 1;
    while i < raw.len() && raw[i].starts_with("--") && raw[i] != "--" {
        let (name, skip) = match raw[i].as_str() {
            "--profile" => (raw.get(i + 1).cloned().ok_or(USAGE)?, 2),
            s => match s.strip_prefix("--profile=") {
                Some(n) => (n.to_string(), 1),
                None => {
                    i += 1;
                    continue;
                }
            },
        };
        kepr_core::profile::parse(&name, false)?;
        let mut rest = raw.to_vec();
        rest.drain(i..i + skip);
        return Ok(Some((name, rest)));
    }
    Ok(None)
}

fn fail(raw: &[String], e: String) -> ! {
    let resp = Response::fail(e);
    if raw.iter().any(|a| a == "--json") {
        crate::cli_ui::print_json(&resp);
    } else if let Response::Err { error } = &resp {
        crate::cli_ui::err(error);
    }
    std::process::exit(1)
}

/// Called first in `main`: apply `--profile` (re-exec), then refuse an
/// invalid `KEPR_PROFILE` before anything talks to a daemon.
pub fn apply() {
    let raw: Vec<String> = std::env::args().collect();
    match take_flag(&raw) {
        Ok(None) => {}
        Ok(Some((name, rest))) => {
            let exe = std::env::current_exe().unwrap_or_else(|e| fail(&raw, e.to_string()));
            let e = std::process::Command::new(exe)
                .arg0(&rest[0])
                .args(&rest[1..])
                .env(kepr_core::profile::ENV, name)
                .exec();
            fail(&raw, format!("cannot re-run kepr with the profile: {e}"));
        }
        Err(e) => fail(&raw, e),
    }
    if let Err(e) = kepr_core::profile::current() {
        fail(&raw, e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn takes_the_flag_from_the_global_options_only() {
        assert_eq!(
            take_flag(&argv(&["kepr", "--profile", "work", "ls"])),
            Ok(Some(("work".into(), argv(&["kepr", "ls"]))))
        );
        assert_eq!(
            take_flag(&argv(&["kepr", "--json", "--profile=dev", "get", "K"])),
            Ok(Some(("dev".into(), argv(&["kepr", "--json", "get", "K"]))))
        );
        // After the command (or after `--`) it isn't ours.
        assert_eq!(
            take_flag(&argv(&["kepr", "ls", "--profile", "x"])),
            Ok(None)
        );
        assert_eq!(
            take_flag(&argv(&["kepr", "--", "--profile", "x"])),
            Ok(None)
        );
        assert_eq!(take_flag(&argv(&["kepr"])), Ok(None));
    }

    #[test]
    fn refuses_bad_names_and_a_missing_one() {
        assert!(take_flag(&argv(&["kepr", "--profile", "../x", "ls"])).is_err());
        assert!(take_flag(&argv(&["kepr", "--profile=Work", "ls"])).is_err());
        assert_eq!(take_flag(&argv(&["kepr", "--profile"])).unwrap_err(), USAGE);
    }
}
