// cli_more.rs — verb registry for the P2–P11 ticket batches (2026-10-05).
//
// Each batch owns a directory module `src/cli_<batch>/` with
//
//   pub const VERBS: &[&str];
//   pub const HELP: &str;          // lines appended to `kepr --help`
//   pub fn dispatch(verb: &str, args: &[String]) -> Response;
//
// and registers it with one line under its own marker below, so batches
// developed on parallel branches merge without conflicts.

use kepr_core::protocol::Response;

type Group = (
    &'static [&'static str],
    &'static str,
    fn(&str, &[String]) -> Response,
);

const GROUPS: &[Group] = &[
    // batch: vault
    (
        crate::cli_vault::VERBS,
        crate::cli_vault::HELP,
        crate::cli_vault::dispatch,
    ),
    // batch: seal
    (
        crate::cli_seal::VERBS,
        crate::cli_seal::HELP,
        crate::cli_seal::dispatch,
    ),
    // batch: store
    (
        crate::cli_store::VERBS,
        crate::cli_store::HELP,
        crate::cli_store::dispatch,
    ),
    // batch: records
    (
        crate::cli_recordsx::VERBS,
        crate::cli_recordsx::HELP,
        crate::cli_recordsx::dispatch,
    ),
    // batch: share
    (
        crate::cli_sharing::VERBS,
        crate::cli_sharing::HELP,
        crate::cli_sharing::dispatch,
    ),
    // batch: sync
    // batch: policy
    (
        crate::cli_policy::VERBS,
        crate::cli_policy::HELP,
        crate::cli_policy::dispatch,
    ),
    // batch: gate
    (
        crate::cli_gatex::VERBS,
        crate::cli_gatex::HELP,
        crate::cli_gatex::dispatch,
    ),
    // batch: aws
    // batch: eco
    (
        crate::cli_eco::VERBS,
        crate::cli_eco::HELP,
        crate::cli_eco::dispatch,
    ),
    // batch: platform
    // batch: session
    // end of batches
];

pub fn is_verb(verb: &str) -> bool {
    GROUPS.iter().any(|(verbs, _, _)| verbs.contains(&verb))
}

pub fn dispatch(verb: &str, args: &[String]) -> Response {
    match GROUPS.iter().find(|(verbs, _, _)| verbs.contains(&verb)) {
        Some((_, _, f)) => f(verb, args),
        None => Response::fail(format!("unknown command: {verb}")),
    }
}

/// Help lines from every batch, in registry order.
pub fn help() -> String {
    GROUPS.iter().map(|(_, h, _)| *h).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verbs_are_unique_and_not_core_verbs() {
        let mut seen = std::collections::HashSet::new();
        for (verbs, _, _) in GROUPS {
            for v in *verbs {
                assert!(seen.insert(*v), "verb {v} registered twice");
                assert!(
                    !crate::cli_extra::VERBS.contains(v),
                    "verb {v} shadows a cli_extra verb"
                );
            }
        }
    }

    #[test]
    fn unknown_verb_fails() {
        assert!(!is_verb("no-such-verb"));
        assert!(matches!(
            dispatch("no-such-verb", &[]),
            Response::Err { .. }
        ));
    }
}
