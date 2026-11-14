// Agent command argument parsing and refusal regressions.
use super::*;

fn v(s: &[&str]) -> Vec<String> {
    s.iter().map(|x| x.to_string()).collect()
}

#[test]
fn parses_each_form() {
    let a = parse(&v(&[
        "add",
        "k",
        "--for",
        "xai",
        "--for",
        "h.example.com:bearer",
        "--stdin",
    ]))
    .unwrap();
    assert_eq!(
        (a.target.as_deref(), a.fors.len(), a.stdin),
        (Some("k"), 2, true)
    );
    let r = parse(&v(&[
        "run", "claude", "--port", "9000", "--", "claude", "-p", "hi",
    ]))
    .unwrap();
    assert_eq!(r.port, Some(9000));
    assert_eq!(r.argv, v(&["claude", "-p", "hi"]));
    assert!(parse(&v(&["run", "claude", "--port", "0"])).is_err());
    assert!(parse(&v(&["add", "a", "b"])).is_err());
    assert!(parse(&[]).is_err());
}

#[test]
fn parses_workspace_source_for_protected_runs() {
    let args = parse(&v(&["run", "omp", "--workspace", "."])).unwrap();
    assert_eq!(args.session.workspace_source.as_deref(), Some("."));
    assert!(parse(&v(&[
        "run",
        "omp",
        "--workspace",
        ".",
        "--workspace-session",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ]))
    .is_err());
}

#[test]
fn from_clipboard_parses_and_excludes_stdin() {
    let a = parse(&v(&["add", "K", "--from-clipboard"])).unwrap();
    assert!(a.from_clipboard && !a.stdin);
    let e = parse(&v(&["add", "K", "--from-clipboard", "--stdin"])).unwrap_err();
    assert_eq!(e, "use one of --stdin or --from-clipboard");
}

#[test]
fn daily_caps_parse() {
    let r = parse(&v(&[
        "run",
        "claude",
        "--max-requests-day",
        "500",
        "--max-tokens-day",
        "200000",
    ]))
    .unwrap();
    assert_eq!(
        (r.limits.max_requests_day, r.limits.max_tokens_day),
        (Some(500), Some(200_000))
    );
    assert!(parse(&v(&["run", "claude", "--max-tokens-day", "lots"])).is_err());
}

#[test]
fn protected_launch_requires_sandbox_and_network_isolation_by_default() {
    let args = parse(&v(&["run", "claude"])).unwrap();
    assert!(
        args.strict_sandbox,
        "protected launch must require isolation"
    );
    assert!(args.isolate_net, "protected launch must isolate networking");
}

#[test]
fn weaker_launch_requires_explicit_compatibility() {
    assert!(parse(&v(&["run", "claude", "--no-sandbox"])).is_err());
    let args = parse(&v(&["run", "claude", "--compatibility"])).unwrap();
    assert!(!args.strict_sandbox && !args.isolate_net);
    assert!(parse(&v(&["run", "claude", "--compatibility", "--no-sandbox"])).is_ok());
    assert!(parse(&v(&[
        "run",
        "claude",
        "--compatibility",
        "--strict-sandbox"
    ]))
    .is_err());
}

#[test]
fn compatibility_network_flag_is_independent_of_argument_order() {
    for flags in [
        ["--compatibility", "--isolate-net"],
        ["--isolate-net", "--compatibility"],
    ] {
        let args = parse(&v(&["run", "claude", flags[0], flags[1]])).unwrap();
        assert!(args.isolate_net);
    }
}

#[test]
fn explicit_privacy_preset_cannot_be_downgraded_and_local_only_stops_before_launch() {
    assert!(parse(&v(&["run", "claude", "--security-preset", "unknown"])).is_err());
    assert!(parse(&v(&[
        "run",
        "claude",
        "--security-preset",
        "private-cloud",
        "--compatibility"
    ]))
    .is_err());
    assert!(parse(&v(&["run", "codex", "--compatibility", "--no-sandbox"])).is_err());
    match main(&v(&["run", "claude", "--security-preset", "local-only"])) {
        Response::Err { error } => assert!(error.contains("local inference routing")),
        _ => panic!("local-only launch must stop before daemon access"),
    }
}

#[test]
fn unknown_verb_is_an_error() {
    match main(&v(&["frobnicate"])) {
        Response::Err { error } => assert!(error.contains("unknown agent command")),
        other => panic!("{other:?}"),
    }
    match main(&v(&["doctor", "--bogus"])) {
        Response::Err { error } => assert!(error.contains("kepr agent doctor")),
        other => panic!("{other:?}"),
    }
}
