// flags.rs — this batch's flags on the core `rotate` verb, parsed by
// `cli_args.rs` (`FLAGS` / `AwsFlags::take`) and routed from
// `cli_activity.rs` when any is given.
//
//   kepr rotate NAME --aws-iam     IAM access-key rotation (T7.05)

use kepr_core::protocol::Response;

use crate::cli_args::Args;

pub const FLAGS: &[&str] = &["--aws-iam"];

#[derive(Debug, Default)]
pub struct AwsFlags {
    /// `rotate --aws-iam` (T7.05).
    pub aws_iam: bool,
}

impl AwsFlags {
    /// Take the flag at `raw[i]`; returns the next index.
    pub fn take(&mut self, raw: &[String], i: usize) -> Result<usize, String> {
        match raw[i].as_str() {
            "--aws-iam" => self.aws_iam = true,
            other => return Err(format!("unknown flag: {other}")),
        }
        Ok(i + 1)
    }

    /// Does `kepr rotate` belong to this batch?
    pub fn any(&self) -> bool {
        self.aws_iam
    }
}

/// `kepr rotate NAME` with one of this batch's flags.
pub fn cmd_rotate(a: &Args) -> Response {
    let fail = |m: &str| {
        if !crate::cli_ui::json_mode() {
            crate::cli_ui::err(m);
        }
        Response::fail(m)
    };
    let Some(name) = a.name.as_deref() else {
        return fail("rotate requires NAME");
    };
    if a.hook_path.is_some() {
        return fail("--aws-iam rotates through the IAM API; it takes no --hook");
    }
    super::rotate_iam::cmd(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn takes_only_its_own_flags() {
        let raw: Vec<String> = ["kepr", "rotate", "K", "--aws-iam", "--x"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let mut f = AwsFlags::default();
        assert!(!f.any());
        assert_eq!(f.take(&raw, 3), Ok(4));
        assert!(f.aws_iam && f.any());
        assert!(f.take(&raw, 4).is_err());
        assert!(FLAGS.iter().all(
            |f| !crate::cli_store::FLAGS.contains(f) && !crate::cli_session::FLAGS.contains(f)
        ));
    }
}
