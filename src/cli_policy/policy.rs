// cli_policy/policy.rs — `kepr policy test|status|reload` (T6.11).
//
// `test FILE` parses the file exactly like the daemon does and runs its
// `[[test]]` cases locally (no daemon needed), so a policy can be
// checked in CI before it is installed.

use kepr_core::policy::PolicyFile;
use kepr_core::protocol::Response;
use kepr_core::protocol_policy::{PolicyRequest, PolicyResponse};

use crate::{cli_mode, cli_ui};

const USAGE: &str = "usage: kepr policy test FILE | policy status | policy reload";

pub fn parse(text: &str) -> Result<PolicyFile, String> {
    let file: PolicyFile = toml::from_str(text).map_err(|e| e.to_string())?;
    file.validate()?;
    Ok(file)
}

/// Run the cases in `text`: `Ok(lines)` when all pass, `Err(message)` else.
pub fn run(text: &str) -> Result<Vec<String>, String> {
    let file = parse(text).map_err(|e| format!("invalid policy: {e}"))?;
    if file.tests.is_empty() {
        return Err("the policy has no [[test]] cases".into());
    }
    let (passed, lines) = file.run_tests();
    if passed {
        return Ok(lines);
    }
    let failed: Vec<&String> = lines.iter().filter(|l| l.starts_with("FAIL")).collect();
    Err(format!(
        "{} of {} policy tests failed:\n{}",
        failed.len(),
        lines.len(),
        failed
            .iter()
            .map(|l| l.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    ))
}

fn cmd_test(path: &str) -> Response {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => return Response::fail(format!("{path}: {e}")),
    };
    match run(&text) {
        Ok(lines) => {
            if !cli_mode::json_mode() {
                lines.iter().for_each(|l| println!("{l}"));
                cli_ui::ok(&format!("{} policy test(s) passed", lines.len()));
            }
            Response::Policy(PolicyResponse::PolicyTestOk { lines })
        }
        Err(e) => Response::fail(e),
    }
}

fn cmd_status(reload: bool) -> Response {
    let r = super::send(PolicyRequest::PolicyStatus { reload });
    if cli_mode::json_mode() {
        return r;
    }
    if let Response::Policy(PolicyResponse::PolicyStatusOk {
        path,
        active,
        rules,
        error,
    }) = &r
    {
        match (active, error) {
            (false, _) => {
                cli_ui::info(&format!("no policy ({path} absent): nothing is restricted"))
            }
            (true, Some(e)) => cli_ui::warn(&format!(
                "{path} has errors, so get / exec / export / share / set / seal are all denied: {e}"
            )),
            (true, None) => cli_ui::ok(&format!("{path}: {rules} rule(s), deny by default")),
        }
    }
    r
}

pub fn cmd_policy(args: &[String]) -> Response {
    let a = super::plain_args(args);
    match a.as_slice() {
        ["test", file] => cmd_test(file),
        ["status"] | [] => cmd_status(false),
        ["reload"] => cmd_status(true),
        _ => Response::fail(USAGE),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = r#"
[[rule]]
effect = "deny"
ops = ["*"]
names = ["PROD_*"]
agent = true

[[rule]]
effect = "allow"
ops = ["get", "exec"]
names = ["GITHUB_*", "PROD_*"]
parent = ["/usr/bin/git"]

[[test]]
op = "get"
name = "github_token"
parent = "/usr/bin/git"
expect = "allow"

[[test]]
op = "exec"
name = "PROD_DB"
parent = "/usr/bin/git"
harness = "claude"
expect = "deny"
"#;

    #[test]
    fn passing_cases_print_one_line_each() {
        let lines = run(POLICY).unwrap();
        assert_eq!(
            lines,
            vec![
                "ok    test 1: get GITHUB_TOKEN parent=/usr/bin/git -> allow (rule 2)",
                "ok    test 2: exec PROD_DB parent=/usr/bin/git harness=claude -> deny (denied by rule 1)",
            ]
        );
    }

    #[test]
    fn failing_cases_are_named() {
        let text = POLICY.replace("expect = \"deny\"", "expect = \"allow\"");
        let e = run(&text).unwrap_err();
        assert!(e.starts_with("1 of 2 policy tests failed:\nFAIL  test 2: exec PROD_DB"));
        assert!(e.ends_with("expected allow"));
    }

    #[test]
    fn bad_files_are_reported() {
        assert!(run("[[rule]]\neffect = \"allow\"\nops = [\"get\"]\n")
            .unwrap_err()
            .contains("no [[test]] cases"));
        assert!(
            run("[[rule]]\neffect = \"allow\"\nops = [\"get\"]\nexes = [\"x\"]\n")
                .unwrap_err()
                .starts_with("invalid policy:")
        );
        assert!(matches!(
            cmd_policy(&["frob".to_string()]),
            Response::Err { .. }
        ));
    }
}
