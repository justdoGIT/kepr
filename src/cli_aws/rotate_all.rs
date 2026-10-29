// cli_aws/rotate_all.rs — `kepr rotate --all [--dry-run]`: rotate every
// credential kepr knows how to rotate, in one run, whatever its provider
// or harness.
//
// What "knows how" means is what is already configured, nothing guessed:
//   - a rotation schedule (`rotate NAME --every DUR --hook CMD|--aws-iam|--db`):
//     the rotator the schedule names;
//   - a sealed AWS key (SigV4 binding): IAM access-key rotation;
//   - a sealed database login: a new random database password.
// Everything else is listed as manual, with the one thing to do, and is
// never touched. Each rotation is atomic on its own (validate upstream,
// then commit), so one failure leaves that credential on its old value and
// the run goes on; it exits non-zero if any failed. `--dry-run` prints the
// plan and changes nothing. Keys internal to kepr (`KEPR_…`) are skipped.

use kepr_core::protocol::{CredInfo, Request, Response};

/// How one credential would be rotated.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Plan {
    /// The rotator its schedule names (`rotate NAME --scheduled`).
    Scheduled(String),
    AwsIam,
    Database,
    /// Not rotatable by kepr; why, and what to do.
    Manual(&'static str),
}

pub fn plan(c: &CredInfo) -> Option<Plan> {
    if c.name.starts_with("KEPR_") || c.alias_of.is_some() {
        return None;
    }
    if let Some(via) = &c.rotate_via {
        return Some(Plan::Scheduled(via.clone()));
    }
    let sealed = c.sealed == Some(true);
    Some(match () {
        _ if sealed && c.aws_sigv4 == Some(true) => Plan::AwsIam,
        _ if sealed && c.record_type.as_deref() == Some("database") => Plan::Database,
        _ => Plan::Manual("no rotator configured: kepr rotate NAME --every 30d --hook CMD"),
    })
}

fn describe(p: &Plan) -> String {
    match p {
        Plan::Scheduled(via) => format!(
            "scheduled rotator ({})",
            via.split(':').next().unwrap_or(via)
        ),
        Plan::AwsIam => "AWS IAM access key".into(),
        Plan::Database => "database password".into(),
        Plan::Manual(m) => format!("manual: {m}"),
    }
}

/// Run the plan for every credential. `send` lists, `run` rotates one.
pub fn run_all(
    send: &dyn Fn(&Request) -> Response,
    run: &dyn Fn(&str, &Plan) -> Response,
    dry_run: bool,
) -> Response {
    let say = |m: &str| {
        if !crate::cli_ui::json_mode() {
            crate::cli_ui::info(m);
        }
    };
    let credentials = match send(&Request::List) {
        Response::ListOk { credentials, .. } => credentials,
        other => return Response::fail(other.err_msg().unwrap_or("unexpected response")),
    };
    let (mut done, mut failed, mut manual) = (0, 0, 0);
    for c in &credentials {
        let Some(p) = plan(c) else { continue };
        if let Plan::Manual(_) = p {
            manual += 1;
            say(&format!("{}: {}", c.name, describe(&p)));
            continue;
        }
        if dry_run {
            say(&format!("{}: would rotate, {}", c.name, describe(&p)));
            continue;
        }
        match run(&c.name, &p).err_msg() {
            None => {
                done += 1;
                say(&format!("{}: rotated ({})", c.name, describe(&p)));
            }
            Some(e) => {
                failed += 1;
                say(&format!("{}: FAILED, unchanged: {e}", c.name));
            }
        }
    }
    say(&if dry_run {
        format!("dry run: nothing changed; {manual} would need doing by hand")
    } else {
        format!("{done} rotated, {failed} failed, {manual} manual")
    });
    if failed > 0 {
        return Response::fail(format!(
            "{failed} rotation(s) failed; those keys are unchanged"
        ));
    }
    Response::Pong
}

/// The real run: one credential through the rotator its plan names.
pub fn rotate_one(name: &str, p: &Plan) -> Response {
    match p {
        Plan::Scheduled(_) => super::rotate_sched::run_scheduled(name),
        Plan::AwsIam => super::rotate_iam::cmd(name),
        Plan::Database => crate::cli_agent_db_rotate::cmd_rotate_db(&[name.to_uppercase()]),
        Plan::Manual(_) => Response::fail("not rotatable by kepr"),
    }
}

pub fn cmd(dry_run: bool) -> Response {
    let send = |r: &Request| crate::client::send_request(r).unwrap_or_else(Response::fail);
    run_all(&send, &rotate_one, dry_run)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn cred(name: &str) -> CredInfo {
        CredInfo {
            name: name.into(),
            ..Default::default()
        }
    }

    fn sealed(name: &str) -> CredInfo {
        CredInfo {
            sealed: Some(true),
            ..cred(name)
        }
    }

    fn fleet() -> Vec<CredInfo> {
        vec![
            CredInfo {
                rotate_via: Some("hook:hex:/bin/true".into()),
                rotate_every_secs: Some(60),
                ..cred("STRIPE")
            },
            CredInfo {
                aws_sigv4: Some(true),
                ..sealed("AWS_PROD")
            },
            CredInfo {
                record_type: Some("database".into()),
                ..sealed("PROD_DB")
            },
            cred("PLAIN_NOTE"),
            cred("KEPR_PKI_CA"),
            CredInfo {
                alias_of: Some("STRIPE".into()),
                ..cred("LINK")
            },
        ]
    }

    #[test]
    fn plans_follow_what_is_configured() {
        let f = fleet();
        assert!(matches!(plan(&f[0]), Some(Plan::Scheduled(_))));
        assert_eq!(plan(&f[1]), Some(Plan::AwsIam));
        assert_eq!(plan(&f[2]), Some(Plan::Database));
        assert!(matches!(plan(&f[3]), Some(Plan::Manual(_))));
        assert_eq!(plan(&f[4]), None, "kepr's own keys");
        assert_eq!(plan(&f[5]), None, "aliases");
        // An unsealed database-looking record is not guessed at.
        let unsealed = CredInfo {
            record_type: Some("database".into()),
            ..cred("D")
        };
        assert!(matches!(plan(&unsealed), Some(Plan::Manual(_))));
    }

    fn lister() -> impl Fn(&Request) -> Response {
        |_| Response::ListOk {
            credentials: fleet(),
            count: 6,
        }
    }

    #[test]
    fn a_dry_run_changes_nothing() {
        let r = run_all(&lister(), &|_, _| panic!("rotated in a dry run"), true);
        assert!(r.is_success());
    }

    #[test]
    fn every_rotatable_key_is_rotated_and_manual_ones_are_left() {
        let ran = RefCell::new(Vec::new());
        let run = |n: &str, p: &Plan| {
            ran.borrow_mut().push((n.to_string(), p.clone()));
            Response::Pong
        };
        let r = run_all(&lister(), &run, false);
        assert!(r.is_success());
        let names: Vec<String> = ran.borrow().iter().map(|(n, _)| n.clone()).collect();
        assert_eq!(names, ["STRIPE", "AWS_PROD", "PROD_DB"]);
    }

    #[test]
    fn a_failure_does_not_stop_the_others_but_fails_the_run() {
        let ran = RefCell::new(Vec::new());
        let run = |n: &str, _: &Plan| {
            ran.borrow_mut().push(n.to_string());
            if n == "AWS_PROD" {
                Response::fail("STS refused")
            } else {
                Response::Pong
            }
        };
        let r = run_all(&lister(), &run, false);
        assert_eq!(
            r.err_msg(),
            Some("1 rotation(s) failed; those keys are unchanged")
        );
        assert_eq!(*ran.borrow(), ["STRIPE", "AWS_PROD", "PROD_DB"]);
    }

    #[test]
    fn a_list_error_is_reported() {
        let r = run_all(&|_| Response::fail("locked"), &|_, _| Response::Pong, false);
        assert_eq!(r.err_msg(), Some("locked"));
    }
}
