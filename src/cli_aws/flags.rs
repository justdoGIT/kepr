// flags.rs — this batch's flags on the core `rotate` verb, parsed by
// `cli_args.rs` (`FLAGS` / `AwsFlags::take`) and routed from
// `cli_activity.rs` when any is given.
//
//   kepr rotate NAME --provider P --bootstrap ADMIN_KEY
//                               provider key replacement with a separate
//                               management credential
//   kepr rotate NAME --every DUR --provider P --bootstrap ADMIN_KEY
//                               scheduled provider rotation

use kepr_core::protocol::Response;

use crate::cli_args::Args;

pub const FLAGS: &[&str] = &[
    "--aws-iam",
    "--db",
    "--provider",
    "--bootstrap",
    "--every",
    "--scheduled",
    "--due",
    // `--all` is the store batch's flag (`delete --all`); `rotate --all`
    // reads it from there.
    "--dry-run",
];

#[derive(Debug, Default)]
pub struct AwsFlags {
    /// `rotate --aws-iam` (T7.05).
    pub aws_iam: bool,
    /// `rotate --db`: a sealed database login (T7.07).
    pub db: bool,
    /// `rotate --provider [NAME]`: rotate API key through provider API.
    pub provider: Option<String>,
    /// Separate provider-management credential used for key creation.
    pub bootstrap: Option<String>,
    /// `rotate --every DUR|off` (T7.07).
    pub every: Option<String>,
    /// `rotate --scheduled`: what the daemon spawns (T7.07).
    pub scheduled: bool,
    /// `rotate --due`: every due schedule of the caller (T12.50).
    pub due: bool,
    /// `rotate --all --dry-run`: the plan only (`--all` itself is the store batch's flag).
    pub dry_run: bool,
}

impl AwsFlags {
    /// Take the flag at `raw[i]`; returns the next index.
    pub fn take(&mut self, raw: &[String], i: usize) -> Result<usize, String> {
        match raw[i].as_str() {
            "--aws-iam" => self.aws_iam = true,
            "--db" => self.db = true,
            "--scheduled" => self.scheduled = true,
            "--due" => self.due = true,
            "--dry-run" => self.dry_run = true,
            "--provider" | "--bootstrap" => {
                let flag = raw[i].as_str();
                if let Some(v) = raw.get(i + 1) {
                    if !v.starts_with("--") && !FLAGS.contains(&v.as_str()) {
                        if flag == "--provider" {
                            self.provider = Some(v.clone());
                        } else {
                            self.bootstrap = Some(v.to_uppercase());
                        }
                        return Ok(i + 2);
                    }
                }
                if flag == "--provider" {
                    self.provider = Some("auto".to_string());
                } else {
                    return Err("--bootstrap needs a credential name".into());
                }
                return Ok(i + 1);
            }
            "--every" => {
                let v = raw.get(i + 1).ok_or("--every needs a duration, e.g. 30d")?;
                self.every = Some(v.clone());
                return Ok(i + 2);
            }
            other => return Err(format!("unknown flag: {other}")),
        }
        Ok(i + 1)
    }

    /// Does `kepr rotate` belong to this batch?
    pub fn any(&self) -> bool {
        self.aws_iam
            || self.db
            || self.provider.is_some()
            || self.bootstrap.is_some()
            || self.scheduled
            || self.due
            || self.dry_run
            || self.every.is_some()
    }
}

/// `--due` runs every due schedule: it takes no NAME and no other
/// rotate flag (`hook`: whether `--hook` was given).
fn due_alone(name: Option<&str>, f: &AwsFlags, hook: bool) -> Result<(), &'static str> {
    let other = hook
        || f.aws_iam
        || f.db
        || f.provider.is_some()
        || f.bootstrap.is_some()
        || f.scheduled
        || f.every.is_some();
    if name.is_some() || other {
        return Err("--due takes no NAME or other flag");
    }
    Ok(())
}

/// `kepr rotate NAME` with one of this batch's flags.
pub fn cmd_rotate(a: &Args) -> Response {
    let fail = |m: &str| {
        if !crate::cli_ui::json_mode() {
            crate::cli_ui::err(m);
        }
        Response::fail(m)
    };
    let f = &a.aws;
    if a.store.all {
        let other = a.name.is_some()
            || a.hook_path.is_some()
            || f.aws_iam
            || f.db
            || f.bootstrap.is_some()
            || f.scheduled
            || f.due
            || f.every.is_some();
        if other {
            return fail(
                "--all takes no NAME or other rotate flag (except --dry-run or --provider)",
            );
        }
        let only_providers = f.provider.is_some();
        return super::rotate_sched::shout(super::rotate_all::cmd(f.dry_run, only_providers));
    }
    if f.dry_run {
        return fail("--dry-run goes with --all");
    }
    if f.due {
        // --gen-kind only means something with --hook.
        let hook = a.hook_path.is_some() || a.gen_kind.as_str() != "hex";
        return match due_alone(a.name.as_deref(), f, hook) {
            Ok(()) => super::rotate_sched::shout(super::rotate_sched::run_due()),
            Err(m) => fail(m),
        };
    }
    let Some(name) = a.name.as_deref() else {
        return fail("rotate requires NAME");
    };
    if let Some(every) = &f.every {
        if f.scheduled {
            return fail("--scheduled runs an existing schedule; it takes no --every");
        }
        return super::rotate_sched::shout(super::rotate_sched::schedule(a, name, every));
    }
    if f.scheduled {
        if f.aws_iam
            || f.db
            || f.provider.is_some()
            || f.bootstrap.is_some()
            || a.hook_path.is_some()
        {
            return fail("--scheduled runs the rotator the schedule names; pass no other");
        }
        let r = super::rotate_sched::run_scheduled(name);
        return super::rotate_sched::shout(r);
    }
    let count = (a.hook_path.is_some() as u8)
        + (f.aws_iam as u8)
        + (f.db as u8)
        + (f.provider.is_some() as u8);
    if count > 1 {
        return fail("pick one rotator: --hook CMD, --aws-iam, --db or --provider");
    }
    if let Some(prov) = &f.provider {
        let p = if prov == "auto" {
            None
        } else {
            Some(prov.as_str())
        };
        let r = super::rotate_provider::cmd(name, p, f.bootstrap.as_deref());
        return super::rotate_sched::shout(r);
    }
    if f.bootstrap.is_some() {
        return fail("--bootstrap only applies to --provider");
    }
    if f.db {
        let db = crate::cli_agent_db_rotate::cmd_rotate_db(&[name.to_uppercase()]);
        return super::rotate_sched::shout(db);
    }
    super::rotate_iam::cmd(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(args: &[&str]) -> AwsFlags {
        let raw: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let mut f = AwsFlags::default();
        let mut i = 2;
        while i < raw.len() {
            i = if FLAGS.contains(&raw[i].as_str()) {
                f.take(&raw, i).unwrap()
            } else {
                i + 1
            };
        }
        f
    }

    #[test]
    fn due_stands_alone() {
        let f = parsed(&["kepr", "rotate", "--due"]);
        assert!(f.due && f.any(), "--due routes to this batch");
        assert_eq!(due_alone(None, &f, false), Ok(()));
        let msg = Err("--due takes no NAME or other flag");
        assert_eq!(due_alone(Some("K"), &f, false), msg);
        let f = parsed(&["kepr", "rotate", "--due", "--every", "30d"]);
        assert_eq!(due_alone(None, &f, false), msg);
        let f = parsed(&["kepr", "rotate", "--due", "--scheduled"]);
        assert_eq!(due_alone(None, &f, false), msg);
        let f = parsed(&["kepr", "rotate", "--due"]);
        assert_eq!(due_alone(None, &f, true), msg, "--hook");
    }

    #[test]
    fn takes_only_its_own_flags() {
        let raw: Vec<String> = [
            "kepr",
            "rotate",
            "K",
            "--aws-iam",
            "--x",
            "--every",
            "30d",
            "--provider",
            "openai",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let mut f = AwsFlags::default();
        assert!(!f.any());
        assert_eq!(f.take(&raw, 3), Ok(4));
        assert!(f.aws_iam && f.any());
        assert!(f.take(&raw, 4).is_err());
        assert_eq!(f.take(&raw, 5), Ok(7));
        assert_eq!(f.every.as_deref(), Some("30d"));
        assert_eq!(f.take(&raw, 7), Ok(9));
        assert_eq!(f.provider.as_deref(), Some("openai"));
        let last = ["kepr".to_string(), "--every".to_string()];
        assert!(f.take(&last, 1).is_err(), "--every at the end has no value");
        assert!(FLAGS.iter().all(
            |f| !crate::cli_store::FLAGS.contains(f) && !crate::cli_session::FLAGS.contains(f)
        ));
    }
    #[test]
    fn parses_a_separate_bootstrap_credential() {
        let f = parsed(&[
            "kepr",
            "rotate",
            "TARGET",
            "--provider",
            "openrouter",
            "--bootstrap",
            "ADMIN",
        ]);
        assert_eq!(f.provider.as_deref(), Some("openrouter"));
        assert_eq!(f.bootstrap.as_deref(), Some("ADMIN"));
        assert!(f.any());

        let raw = [
            "kepr".to_string(),
            "rotate".to_string(),
            "--bootstrap".to_string(),
        ];
        let mut f = AwsFlags::default();
        assert!(f.take(&raw, 2).is_err());
    }
}
