// cli_extra.rs — verbs with their own small parsers (kept out of
// cli_args.rs, which is near its size limit):
//
//   kepr agent …                       see cli_agent_cmd.rs
//   kepr totp NAME
//   kepr inject -i TEMPLATE [-o OUT [--allow-disk]]
//   kepr scan [PATH...] [--staged]
//   kepr copy NAME [--clear SECS]
//   kepr history NAME
//   kepr restore NAME --version N
//   kepr usage [--days N]
//   kepr health [--max-age DAYS | --period N] [--policy FILE] [--breach]
//               [--notify URL [--format F]]
//   kepr leaked NAME [--yes] [--rotate]
//   kepr record add|show|get|types        see cli_record.rs
//   kepr share key|send|receive           see cli_share.rs
//   kepr recovery-kit create|restore      see cli_recovery.rs
//   kepr discover [--seal] [--overwrite] [--yes]
//   kepr import FILE [--format F] [--prefix P] [--seal] [--overwrite] [--yes]

use kepr_core::protocol::Response;

pub const VERBS: &[&str] = &[
    "agent",
    "totp",
    "inject",
    "scan",
    "copy",
    "ssh",
    "ssh-agent",
    "history",
    "restore",
    "usage",
    "health",
    "import",
    "discover",
    "leaked",
    "record",
    "share",
    "recovery-kit",
    "__clipboard-clear",
    "__private-tmp",
    "__clipboard-serve",
];

fn value_of<'a>(args: &'a [String], flags: &[&str]) -> Result<Option<&'a str>, String> {
    match args.iter().position(|a| flags.contains(&a.as_str())) {
        Some(i) => args
            .get(i + 1)
            .map(|s| Some(s.as_str()))
            .ok_or_else(|| format!("{} needs a value", flags[0])),
        None => Ok(None),
    }
}

/// The value after `f`, if `f` is present (the shared flag lookup for the
/// small parsers in cli_*.rs).
pub fn flag<'a>(args: &'a [String], f: &str) -> Option<&'a str> {
    let i = args.iter().position(|a| a == f)?;
    args.get(i + 1).map(String::as_str)
}

/// Arguments that are neither flags nor flag values (`-` counts: stdin).
pub fn positionals(args: &[String], value_flags: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    let mut skip = false;
    for a in args {
        if skip {
            skip = false;
        } else if value_flags.contains(&a.as_str()) {
            skip = true;
        } else if !a.starts_with('-') || a == "-" {
            out.push(a.clone());
        }
    }
    out
}

const INJECT_USAGE: &str = "usage: kepr inject -i TEMPLATE [-o OUT [--allow-disk]]";

/// `-i TEMPLATE`, `-o OUT` and `--allow-disk` (T12.45), which only
/// means something with `-o`.
fn inject_args(args: &[String]) -> Result<(&str, Option<&str>, bool), String> {
    let input = value_of(args, &["-i", "--input"])?.ok_or(INJECT_USAGE)?;
    let output = value_of(args, &["-o", "--output"])?;
    let allow_disk = args.iter().any(|a| a == "--allow-disk");
    if allow_disk && output.is_none() {
        return Err(INJECT_USAGE.into());
    }
    Ok((input, output, allow_disk))
}

fn one_name(args: &[String], verb: &str, value_flags: &[&str]) -> Result<String, Response> {
    match positionals(args, value_flags).as_slice() {
        [n] => Ok(n.clone()),
        _ => Err(Response::fail(format!("usage: kepr {verb} NAME"))),
    }
}

pub fn dispatch(verb: &str, args: &[String]) -> Response {
    let r = || -> Result<Response, Response> {
        Ok(match verb {
            "agent" => crate::cli_agent_cmd::main(args),
            "totp" => crate::cli_totp::cmd_totp(&one_name(args, verb, &[])?),
            "inject" => {
                let (input, output, allow_disk) = inject_args(args).map_err(Response::fail)?;
                crate::cli_inject::cmd_inject(input, output, allow_disk)
            }
            "scan" => crate::cli_scan::cmd_scan(
                &positionals(args, &[]),
                args.iter().any(|a| a == "--staged"),
            ),
            "copy" => {
                let name = one_name(args, verb, &["--clear"])?;
                let secs = match value_of(args, &["--clear"]).map_err(Response::fail)? {
                    Some(s) => s
                        .parse()
                        .map_err(|_| Response::fail("--clear needs a number of seconds"))?,
                    None => crate::cli_copy::DEFAULT_CLEAR_SECS,
                };
                crate::cli_copy::cmd_copy(&name, secs)
            }
            "history" if args.iter().any(|a| a == "--diff") => {
                crate::cli_store::cmd_history_diff(args) // T11.3
            }
            "history" => crate::cli_history::cmd_history(&one_name(args, verb, &[])?),
            "restore" => {
                let name = one_name(args, verb, &["--version"])?;
                match value_of(args, &["--version"]).map_err(Response::fail)? {
                    Some(v) => match v.parse() {
                        Ok(n) => crate::cli_history::cmd_restore(&name, n),
                        Err(_) => {
                            Response::fail("--version needs a number (see: kepr history NAME)")
                        }
                    },
                    None => Response::fail("usage: kepr restore NAME --version N"),
                }
            }
            "usage" if args.iter().any(|a| a == "--report") => {
                crate::cli_policy::usage_report(args)
            }
            "usage" => match value_of(args, &["--days"]).map_err(Response::fail)? {
                Some(d) => match d.parse() {
                    Ok(n) => crate::cli_usage::cmd_usage(Some(n)),
                    Err(_) => Response::fail("--days needs a number"),
                },
                None => crate::cli_usage::cmd_usage(None),
            },
            "health" => {
                let notify = crate::cli_policy::health_notify(args).map_err(Response::fail)?; // T6.08
                let rest = crate::cli_policy::health_rest(args);
                crate::cli_policy::after_health(notify, crate::cli_health::cmd(&rest))
                // T11.11
            }
            "import" => {
                let file = one_name(args, verb, &["--format", "--prefix"])?;
                let flag = |f: &str| args.iter().any(|a| a == f);
                let opts = crate::cli_import::Opts {
                    format: value_of(args, &["--format"])
                        .map_err(Response::fail)?
                        .unwrap_or("auto"),
                    prefix: value_of(args, &["--prefix"]).map_err(Response::fail)?,
                    seal: flag("--seal"),
                    overwrite: flag("--overwrite"),
                    yes: flag("--yes") || flag("-y"),
                };
                crate::cli_import::cmd_import(&file, &opts)
            }
            "discover" => {
                let flag = |f: &str| args.iter().any(|a| a == f);
                crate::cli_discover::cmd_discover(&crate::cli_import::Opts {
                    format: "auto",
                    prefix: None,
                    seal: flag("--seal"),
                    overwrite: flag("--overwrite"),
                    yes: flag("--yes") || flag("-y"),
                })
            }
            "leaked" => crate::cli_leaked::cmd_leaked(
                &one_name(args, verb, &[])?,
                args.iter().any(|a| a == "--yes" || a == "-y"),
                args.iter().any(|a| a == "--rotate"), // T9.09 (batch: aws)
            ),
            "recovery-kit" => crate::cli_recovery::cmd_recovery_kit(args),
            "record" => crate::cli_record::cmd_record(args),
            "share" => crate::cli_share::cmd_share(args),
            "__clipboard-clear" => crate::cli_copy::cmd_clipboard_clear(),
            "__private-tmp" => crate::cli_memfs::cmd_private_tmp(args), // T12.46
            "__clipboard-serve" => crate::cli_clip::cmd_clipboard_serve(), // T12.47
            "ssh" => crate::cli_ssh::cmd_ssh(args),
            "ssh-agent" => crate::cli_ssh_agent::cmd_ssh_agent(args),
            other => Response::fail(format!("unknown command: {other}")),
        })
    };
    r().unwrap_or_else(|e| e)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn flag_and_positional_helpers() {
        let a = v(&["NAME", "--clear", "5"]);
        assert_eq!(value_of(&a, &["--clear"]).unwrap(), Some("5"));
        assert_eq!(positionals(&a, &["--clear"]), v(&["NAME"]));
        assert!(value_of(&v(&["--clear"]), &["--clear"]).is_err());
        assert_eq!(value_of(&v(&["x"]), &["-i"]).unwrap(), None);
    }

    #[test]
    fn inject_parses_allow_disk() {
        let a = v(&["-i", "t.tpl", "-o", "/dev/shm/o", "--allow-disk"]);
        assert_eq!(
            inject_args(&a).unwrap(),
            ("t.tpl", Some("/dev/shm/o"), true)
        );
        let a = v(&["--input", "t.tpl", "--output", "o"]);
        assert_eq!(inject_args(&a).unwrap(), ("t.tpl", Some("o"), false));
        assert_eq!(inject_args(&v(&["-i", "t"])).unwrap(), ("t", None, false));
        assert!(inject_args(&v(&["-i", "t", "--allow-disk"])).is_err());
        assert!(inject_args(&v(&["-o", "x"])).is_err());
    }

    #[test]
    fn usage_errors() {
        assert!(matches!(dispatch("totp", &[]), Response::Err { .. }));
        assert!(matches!(
            dispatch("inject", &v(&["-o", "x"])),
            Response::Err { .. }
        ));
        assert!(matches!(
            dispatch("copy", &v(&["A", "--clear", "x"])),
            Response::Err { .. }
        ));
        assert!(matches!(
            dispatch("restore", &v(&["A"])),
            Response::Err { .. }
        ));
        assert!(matches!(
            dispatch("restore", &v(&["A", "--version", "one"])),
            Response::Err { .. }
        ));
    }
}
