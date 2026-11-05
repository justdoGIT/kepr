#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Args {
        let raw = std::iter::once("kepr".to_owned())
            .chain(args.iter().map(|arg| (*arg).to_owned()))
            .collect::<Vec<_>>();
        parse_args_from(&raw).expect("arguments should parse")
    }

    #[test]
    fn bare_set_options_match_double_hyphen_forms() {
        let bare = parse(&["set", "k", "value", "v", "gen-kind", "pass", "ttl", "60"]);
        let dashed = parse(&[
            "set",
            "k",
            "--value",
            "v",
            "--gen-kind",
            "pass",
            "--ttl",
            "60",
        ]);
        assert_eq!(bare.value, dashed.value);
        assert_eq!(bare.gen_kind.as_str(), dashed.gen_kind.as_str());
        assert_eq!(bare.ttl_secs, dashed.ttl_secs);
        let policy = parse(&["set", "k", "requires-consent", "requires-fido2"]);
        assert!(policy.requires_consent && policy.requires_fido2);
    }

    #[test]
    fn bare_boolean_and_global_options_parse() {
        let args = parse(&["json", "get", "API_KEY", "quiet", "export"]);
        assert!(args.json);
        assert!(args.quiet);
        assert!(args.export);
        assert_eq!(args.name.as_deref(), Some("API_KEY"));

        let args = parse(&["delete", "API_KEY", "force"]);
        assert!(args.force);
        let generated = parse(&["set", "API_KEY", "generate"]);
        assert!(generated.generate);
        let stdin = parse(&["set", "API_KEY", "stdin"]);
        assert!(stdin.stdin);
    }

    #[test]
    fn bare_exec_options_allow_command_without_separator() {
        let bare = parse(&["exec", "env", "API_KEY,DB", "/usr/bin/env"]);
        let dashed = parse(&["exec", "--env", "API_KEY,DB", "--", "/usr/bin/env"]);
        assert_eq!(bare.env_vars, dashed.env_vars);
        let memfd = parse(&["exec", "memfd", "API_KEY", "/usr/bin/env"]);
        assert_eq!(memfd.memfd_vars, vec!["API_KEY"]);
        assert_eq!(bare.exec_argv, dashed.exec_argv);
    }

    #[test]
    fn bare_value_options_work_for_other_commands() {
        let env = parse(&["env", "manifest", "/tmp/kepr.toml"]);
        assert_eq!(
            env.manifest_path.as_deref(),
            Some(std::path::Path::new("/tmp/kepr.toml"))
        );

        let rotate = parse(&[
            "rotate",
            "API_KEY",
            "hook",
            "/tmp/validate",
            "gen-kind",
            "uuid",
        ]);
        assert_eq!(
            rotate.hook_path.as_deref(),
            Some(std::path::Path::new("/tmp/validate"))
        );
        assert_eq!(rotate.gen_kind.as_str(), "uuid");

        let sync = parse(&["sync-pull", "API_KEY", "url", "vault:team/key"]);
        assert_eq!(sync.url.as_deref(), Some("vault:team/key"));
    }
}
