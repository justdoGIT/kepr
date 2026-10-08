// cli_aws/ — the `aws` ticket batch, CLI side (2026-10-05).
// batch: aws
//
//   sts        STS / Query-API client on kepr_core::sigv4_req (T7.06)
//   session    `aws:<NAME>` gate routes and the placeholder pair (T2.02)
//   credproc   `kepr aws credential-process` (T2.03)
//   iam        IAM Query API: list / create / delete access keys (T7.05)
//   rotate_iam `kepr rotate NAME --aws-iam` (T7.05)
//   rotate_sched `kepr rotate NAME --every 30d ...` / `--scheduled` (T7.07)
//   flags      this batch's flags on the core `rotate` verb
//   leaked     `kepr leaked NAME --rotate`: provider-API rotation (T9.09)
//   github_app `kepr github-app add`: sealed GitHub App keys (T7.08)
//   presets    npm / docker files for agent sessions (T2.04)
//
// Network calls to providers happen here, in the user's CLI process: the
// root daemon's unit has no TCP. Values reach the store only through the
// normal `set` path.

pub mod credproc;
pub mod flags;
pub mod github_app;
pub mod iam;
pub mod leaked;
pub mod presets;
pub mod rotate_iam;
pub mod rotate_sched;
pub mod session;
pub mod sts;

pub use flags::{AwsFlags, FLAGS};
pub use rotate_sched::list_tail;

#[cfg(test)]
pub mod fake;

use kepr_core::generate::ZeroString;
use kepr_core::protocol::Response;
use kepr_core::sigv4_req::AwsKey;

use crate::cli_exec::{CredFetcher, DaemonFetcher};

pub const VERBS: &[&str] = &["aws", "github-app"];

pub const HELP: &str = "\
  aws whoami KEY [--region R]          which AWS account and principal the stored key KEY is
                                       (STS GetCallerIdentity; KEY holds {access_key_id,...})
  aws credential-process KEY [--duration SECS] [--region R] [--role-arn ARN]
                                       for ~/.aws/config `credential_process`: STS temporary
                                       credentials (900-43200 s); inside `kepr agent run` the
                                       session's placeholder pair. Never the long-lived key
  rotate KEY --aws-iam                 new IAM access key for the stored KEY: created, verified
                                       (STS), stored, then the old key deleted (2-key limit)
  rotate KEY --db                      new password for a sealed database login (rotate-db)
  rotate KEY --every 30d --hook CMD | --aws-iam | --db
                                       rotate on a schedule (12h, 30d, 2w; `--every off` stops);
                                       the user-mode daemon runs due ones and `kepr list`
                                       shows the next. `rotate KEY --scheduled` runs it now
  github-app add KEY --app-id N --installation-id N [--key-file PEM]
                                       store a GitHub App private key sealed; agent sessions get
                                       1-hour installation tokens for gh / GH_TOKEN (gate-minted)
";

pub fn dispatch(verb: &str, args: &[String]) -> Response {
    let args: Vec<&str> = args
        .iter()
        .map(String::as_str)
        .filter(|a| !matches!(*a, "--json" | "--color" | "--no-color"))
        .collect();
    match (verb, args.first().copied()) {
        ("aws", Some("whoami")) => cmd_whoami(&args[1..]),
        ("aws", Some("credential-process")) => credproc::cmd(&args[1..]),
        ("github-app", _) => github_app::cmd(&args),
        _ => Response::fail(format!("usage:\n{HELP}")),
    }
}

/// The value of `--flag VALUE`, if given.
pub fn flag<'a>(args: &[&'a str], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| *a == name)
        .and_then(|i| args.get(i + 1).copied())
}

/// The first argument that is neither a flag nor a flag's value.
pub fn positional<'a>(args: &[&'a str], valued: &[&str]) -> Option<&'a str> {
    let mut i = 0;
    while i < args.len() {
        match args[i] {
            f if valued.contains(&f) => i += 2,
            f if f.starts_with('-') => i += 1,
            p => return Some(p),
        }
    }
    None
}

/// Read a stored, unsealed AWS key. A sealed key never leaves the gate,
/// so it is refused here before any `Get`.
pub fn load_key(name: &str, fetcher: &dyn CredFetcher) -> Result<AwsKey, String> {
    let name = name.to_uppercase();
    if crate::cli_agent_run::sealed_creds()?
        .iter()
        .any(|c| c.name == name)
    {
        return Err(format!(
            "{name} is sealed: its key never leaves the agent gate (only `kepr agent run` uses it)"
        ));
    }
    let value: ZeroString = fetcher.fetch(&name)?;
    AwsKey::parse(value.as_str()).map_err(|e| format!("{name}: {e}"))
}

fn cmd_whoami(args: &[&str]) -> Response {
    let Some(name) = positional(args, &["--region"]) else {
        return Response::fail("usage: kepr aws whoami KEY [--region R]");
    };
    let result = sts_endpoint(flag(args, "--region")).and_then(|ep| {
        let key = load_key(name, &DaemonFetcher)?;
        sts::get_caller_identity(&ep, &key, sts::now_secs())
    });
    match result {
        Ok(id) => {
            if !crate::cli_ui::json_mode() {
                println!(
                    "account  {}\narn      {}\nuser id  {}",
                    id.account, id.arn, id.user_id
                );
            }
            Response::Pong
        }
        Err(e) => Response::fail(e),
    }
}

/// STS for `--region`, else `AWS_REGION` / `AWS_DEFAULT_REGION`, else global.
pub fn sts_endpoint(region: Option<&str>) -> Result<sts::Endpoint, String> {
    let env = std::env::var("AWS_REGION")
        .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
        .ok();
    sts::Endpoint::sts(region.or(env.as_deref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argument_helpers() {
        let a = ["--region", "eu-west-1", "PROD_AWS", "--json"];
        assert_eq!(positional(&a, &["--region"]), Some("PROD_AWS"));
        assert_eq!(flag(&a, "--region"), Some("eu-west-1"));
        assert_eq!(flag(&a, "--duration"), None);
        assert!(matches!(dispatch("aws", &[]), Response::Err { .. }));
    }
}
