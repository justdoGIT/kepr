// cli_help.rs — plain `kepr help` and command-specific help.
//
// The request parser and help output live here so the argument parser
// can short-circuit help before attempting a daemon connection.

use crate::cli_args::VERSION;

#[derive(Debug, PartialEq, Eq)]
pub enum HelpRequest {
    General,
    Command(String),
}

pub fn help_request(args: &[String]) -> Option<HelpRequest> {
    match args {
        [first, ..] if first == "help" => match args.get(1) {
            Some(topic) if !topic.starts_with('-') => Some(HelpRequest::Command(topic.clone())),
            _ => Some(HelpRequest::General),
        },
        [first, ..] if first == "--help" || first == "-h" => Some(HelpRequest::General),
        [command, flag, ..] if flag == "help" || flag == "--help" || flag == "-h" => {
            Some(HelpRequest::Command(command.clone()))
        }
        _ => None,
    }
}

fn command_help_text(command: &str) -> Option<&'static str> {
    Some(match command {
"set" => concat!(
    "USAGE:\n  kepr set KEY [stdin | value VALUE | generate] ",
    "[gen-kind KIND] [ttl SECS] [requires-consent] [requires-fido2]\n\n",
    "Store a credential. `stdin` reads from stdin; `value` supplies a value; ",
    "`generate` creates one.\n\n",
    "EXAMPLES:\n",
    "  kepr set OPENAI_API_KEY              # interactive, masked input\n",
    "  kepr set BOB_TOKEN generate          # auto-generate\n",
    "  printf '%s\\n' secret | kepr set MY_KEY stdin\n",
    "  kepr set TMP_TOKEN generate ttl 3600 # expires in 1h\n",
),
"get" => concat!(
    "USAGE:\n  kepr get KEY [quiet] [export]\n\n",
    "Decrypt and print KEY. `quiet` prints only the value; `export` prints a shell assignment.\n\n",
    "EXAMPLES:\n",
    "  kepr get OPENAI_API_KEY              # decrypt and print\n",
    "  kepr get OPENAI_API_KEY export       # print as: export VAR=value\n",
    "  kepr get OPENAI_API_KEY quiet        # raw value only\n",
    "  kepr json get OPENAI_API_KEY         # json output for scripts\n",
),
"list" | "ls" => concat!(
    "USAGE:\n  kepr list\n\n",
    "List stored credential names. Alias: ls.\n\n",
    "EXAMPLES:\n",
    "  kepr ls                              # alias for list\n",
    "  kepr json list                       # machine-readable output\n",
),
"delete" | "rm" => concat!(
    "USAGE:\n  kepr delete KEY [force]\n\n",
    "Delete KEY. Alias: rm.\n\n",
    "EXAMPLES:\n",
    "  kepr rm BOB_TOKEN force              # delete without prompt\n",
),
"check" => concat!(
    "USAGE:\n  kepr check\n\n",
    "Verify that stored credentials can be decrypted.\n\n",
    "EXAMPLES:\n",
    "  kepr check                           # verify all decrypt ok\n",
),
"lock" => concat!(
    "USAGE:\n  kepr lock\n\n",
    "Lock the password-protected credential store.\n\n",
    "EXAMPLES:\n",
    "  kepr lock                            # Argon2id-protect the master key\n",
),
"unlock" => concat!(
    "USAGE:\n  kepr unlock\n\n",
    "Unlock the password-protected credential store with the masked password prompt.\n\n",
    "EXAMPLES:\n",
    "  kepr unlock                          # unlock with the masked password prompt\n",
    "  kepr get KK_SUDO_PASSWORD --quiet | kepr unlock --stdin\n",
),
"status" => concat!(
    "USAGE:\n  kepr status\n\n",
    "Show whether the credential store is locked and password-protected.\n\n",
    "EXAMPLES:\n",
    "  kepr status                          # show locked/protection state\n",
),
"exec" => concat!(
    "USAGE:\n  kepr exec [env CSV | memfd CSV | manifest PATH] [--] COMMAND [ARGS...]\n\n",
    "Run COMMAND with selected credentials provided through the environment or sealed memfds. ",
    "The `--` separator is optional.\n\n",
    "EXAMPLES:\n",
    "  kepr exec env OPENAI_API_KEY python train.py\n",
    "  kepr exec memfd OPENAI_API_KEY python train.py\n",
    "  kepr exec python train.py            # .kepr.toml discovery\n",
),
"doctor" => concat!(
    "USAGE:\n  kepr doctor\n\n",
    "Check common Kepr setup requirements.\n\n",
    "EXAMPLES:\n",
    "  kepr doctor                          # list of setup checks\n",
),
"env" => concat!(
    "USAGE:\n  kepr env [env CSV | manifest PATH]\n\n",
    "Print shell export statements for the selected credentials.\n\n",
    "EXAMPLES:\n",
    "  eval \"$(kepr env env DB_PASS,DB_USER)\"\n",
    "  kepr env env OPENAI_API_KEY          # single key\n",
),
"rotate" => concat!(
    "USAGE:\n  kepr rotate KEY hook PATH [gen-kind KIND]\n\n",
    "Generate a replacement value, validate it with PATH, and commit only when the hook succeeds.\n\n",
    "EXAMPLES:\n",
    "  kepr rotate STRIPE_KEY hook ./bin/refresh-stripe.sh\n",
),
"audit-verify" => concat!(
    "USAGE:\n  kepr audit-verify\n\n",
    "Verify the append-only audit hash chain.\n\n",
    "EXAMPLES:\n",
    "  kepr audit-verify                    # verify chain integrity\n",
),
"sync-push" => concat!(
    "USAGE:\n  kepr sync-push KEY url SCHEME:PATH\n\n",
    "Push KEY to a supported remote secret store.\n\n",
    "EXAMPLES:\n",
    "  kepr sync-push DB_PASS url vault:secret/team/db_pass\n",
    "  kepr sync-push DB_PASS url aws-sm:prod/db/password\n",
    "  kepr sync-push DB_PASS url gcp-sm:projects/myproj/secrets/db_pass\n",
),
"sync-pull" => concat!(
    "USAGE:\n  kepr sync-pull KEY url SCHEME:PATH\n\n",
    "Fetch a remote secret and store it as KEY.\n\n",
    "EXAMPLES:\n",
    "  kepr sync-pull DB_PASS url vault:secret/team/db_pass\n",
),
"fido2-register" => concat!(
    "USAGE:\n  kepr fido2-register LABEL CRED_ID COSE_KEY\n\n",
    "Register a FIDO2 credential for assertions.\n\n",
    "EXAMPLES:\n",
    "  kepr fido2-register yubikey <cred_id> <cose_key>\n",
),
"fido2-list" => concat!(
    "USAGE:\n  kepr fido2-list\n\n",
    "List registered FIDO2 credentials.\n\n",
    "EXAMPLES:\n",
    "  kepr fido2-list\n",
),
"protect-agent" => concat!(
    "USAGE:\n  kepr protect-agent NAME [--] COMMAND [ARGS...]\n\n",
    "Run an agent command with Kepr-managed credentials. The `--` separator is optional.\n\n",
    "EXAMPLES:\n",
    "  kepr protect-agent cursor -- cursor\n",
    "  kepr protect-agent windsurf -- windsurf\n",
),
"agent" => concat!(
    "USAGE:\n  kepr agent add NAME [--for PROVIDER]... [--stdin|--from-clipboard]\n",
    "  kepr agent add-cloudflare\n",
    "  kepr agent run HARNESS [--workspace PATH | --workspace-session SESSION] [--window] ",
    "[--security-preset private-cloud|local-only] [--compatibility [--no-sandbox]] ",
    "[--port N] [--max-requests N] [--max-tokens N] [--rate N] [--max-requests-day N] [--max-tokens-day N] [-- ARGV...]\n",
    "  kepr agent install omp|grok|opencode|claude|codex|cursor|copilot\n",
    "  kepr agent doctor [--port N] [--json]\n",
    "  kepr agent shim HARNESS [--dir DIR] [--remove]\n",
    "  kepr agent ls\n",
    "  kepr agent revoke NAME\n\n",
    "EXAMPLES:\n",
    "  kepr agent add ANTHROPIC_API_KEY --for anthropic     # interactive, masked input\n",
    "  printf 'sk-ant-v0-...\\n' | kepr agent add ANTHROPIC_API_KEY --for anthropic --stdin\n",
    "  kepr agent add OPENAI_API_KEY --for openai --for github  # multiple destinations\n",
    "  kepr agent ls                                      # list bindings\n",
    "  kepr agent run omp                                 # snapshot mode (current dir)\n",
    "  kepr agent run omp --compatibility                 # in-place mode (git for rollback)\n",
    "  kepr agent run omp --window                        # dedicated Rio terminal window\n",
    "  kepr agent install omp                             # one-time harness integration\n",
    "  kepr agent install grok                            # Grok Build integration\n",
    "  kepr agent install codex                           # Codex integration\n",
    "  kepr agent doctor                                  # diagnose protected harness setup\n",
    "  kepr agent shim omp --dir ~/.local/bin             # create wrapper script\n",
    "  kepr agent revoke ANTHROPIC_API_KEY                # remove sealed agent credential\n",
),
        _ => return None,
    })
}

pub fn print_help_for(topic: Option<&str>) -> Result<(), String> {
    match topic {
        None => print_help(),
        Some(command) => {
            let text = command_help_text(command)
                .ok_or_else(|| format!("unknown command for help: {command}"))?;
            println!(
                "{text}\n\nOptions accept bare names or their `--`-prefixed forms (for example, `quiet` and `--quiet`)."
            );
        }
    }
    Ok(())
}

pub fn print_help() {
    print!(
        r#"kepr {VERSION} — credential manager

USAGE:
  kepr [GLOBAL_FLAGS] COMMAND [ARGS...]
  kepr help [COMMAND]
  kepr COMMAND help

COMMANDS:
  help [COMMAND]                       show general or command-specific help
  set KEY [stdin|value V|generate] [gen-kind KIND] [ttl SECS] [requires-consent] [requires-fido2]
  get KEY [quiet] [export]
  list                                 (alias: ls)
  delete KEY [force]                   (alias: rm)
  lock | unlock | status               password-protect or inspect the store
  exec [env CSV|memfd CSV|manifest PATH] [--] COMMAND ARGS
  doctor                               diagnose common setup issues
  env [env CSV|manifest PATH]          emit `export VAR='value'` lines for eval
  rotate KEY hook PATH [gen-kind KIND] atomic rotation
  audit-verify                         verify the hash-chained audit log
  sync-push KEY url SCHEME:PATH        push KEY's value to a remote
  sync-pull KEY url SCHEME:PATH        pull KEY's value from a remote
  fido2-register LABEL CRED_ID COSE_KEY register a FIDO2 key
  fido2-list                           list registered FIDO2 keys
  protect-agent NAME [--] COMMAND ARGS  run CMD with Kepr-managed creds
  agent add-cloudflare                 seal existing Cloudflare login inside the daemon
  agent run HARNESS [--workspace PATH]  protected run; defaults to current folder (or reuse a session)
  agent install HARNESS | agent doctor install or check protected harness integration
{more_help}

GLOBAL OPTIONS (bare names or `--`-prefixed names are accepted):
  json / --json       machine-readable output; no stderr on clean errors
  color / --color     enable ANSI colours (default is plain text)
  no-color / --no-color force plain text (overrides CLICOLOR_FORCE=1)
  version / --version print the version
  help / --help       print general help; use COMMAND help for command help

ENVIRONMENT:
  NO_COLOR           any value disables colours (overrides color)
  CLICOLOR_FORCE=1   enables colours without color

EXAMPLES:
  kepr help                            # general command reference
  kepr list help                       # command-specific help; no daemon connection
  kepr unlock help
  kepr set OPENAI_API_KEY              # interactive, masked input
  kepr set BOB_TOKEN generate          # auto-generate
  printf '%s\n' secret | kepr set MY_KEY stdin
  kepr set TMP_TOKEN generate ttl 3600 # expires in 1h
  kepr lock                            # Argon2id-protect the master key
  kepr unlock                          # unlock with the masked password prompt
  kepr status                          # show locked/protection state
  kepr set API_KEY requires-fido2  # interactive, masked input
  kepr get OPENAI_API_KEY              # decrypt and print
  kepr get OPENAI_API_KEY export       # print as: export VAR=value
  kepr get OPENAI_API_KEY quiet        # raw value only
  kepr json get OPENAI_API_KEY         # json output for scripts
  kepr ls                              # alias for list
  kepr rm BOB_TOKEN force              # delete without prompt
  kepr check                           # verify all decrypt ok
  kepr exec memfd OPENAI_API_KEY python train.py
  kepr exec env OPENAI_API_KEY python train.py
  kepr doctor                          # ✓/✗ list of setup checks
  kepr rotate STRIPE_KEY hook ./bin/refresh-stripe.sh
  kepr sync-push DB_PASS url vault:secret/team/db_pass
  kepr sync-push DB_PASS url aws-sm:prod/db/password
  kepr sync-push DB_PASS url gcp-sm:projects/myproj/secrets/db_pass
  eval "$(kepr env env DB_PASS,DB_USER)"
  kepr exec python train.py            # .kepr.toml discovery

MANIFEST:
  Place a `.kepr.toml` in the project root:
    [env]
    required = ["DB_PASS", "DB_USER", "OPENAI_API_KEY"]
  Then `kepr exec python train.py` and `kepr env` need no options.
  `env CSV` overrides the manifest; `manifest PATH` pins a different file.

  Every bare option also accepts a `--` prefix (for example, `json` and `--json`).
  For `exec` and `protect-agent`, the optional `--` separates Kepr options from the child command.

  View audit log: journalctl -t kepr-daemon
    journalctl -t kepr-daemon KEPR_OP=get
"#,
        more_help = crate::cli_more::help(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| (*arg).to_string()).collect()
    }

    #[test]
    fn recognizes_plain_general_and_command_help_forms() {
        assert_eq!(help_request(&words(&["help"])), Some(HelpRequest::General));
        assert_eq!(
            help_request(&words(&["help", "list"])),
            Some(HelpRequest::Command("list".to_string()))
        );
        assert_eq!(
            help_request(&words(&["list", "help"])),
            Some(HelpRequest::Command("list".to_string()))
        );
        assert_eq!(
            help_request(&words(&["unlock", "--help"])),
            Some(HelpRequest::Command("unlock".to_string()))
        );
        assert_eq!(help_request(&words(&["get"])), None);
    }

    #[test]
    fn every_supported_command_and_alias_has_help() {
        for command in [
            "set",
            "get",
            "list",
            "ls",
            "delete",
            "rm",
            "check",
            "lock",
            "unlock",
            "status",
            "exec",
            "doctor",
            "env",
            "rotate",
            "audit-verify",
            "sync-push",
            "sync-pull",
            "fido2-register",
            "fido2-list",
            "protect-agent",
        ] {
            assert!(
                command_help_text(command).is_some(),
                "missing help for {command}"
            );
        }
    }

    #[test]
    fn command_usage_prefers_bare_option_names() {
        assert!(command_help_text("set")
            .unwrap()
            .contains("[stdin | value VALUE"));
        assert!(command_help_text("get")
            .unwrap()
            .contains("[quiet] [export]"));
        assert!(command_help_text("delete").unwrap().contains("[force]"));
        assert!(command_help_text("rotate")
            .unwrap()
            .contains("KEY hook PATH"));
        assert!(command_help_text("sync-pull")
            .unwrap()
            .contains("KEY url SCHEME:PATH"));
        assert!(command_help_text("exec")
            .unwrap()
            .contains("env CSV | memfd CSV"));
    }
}
