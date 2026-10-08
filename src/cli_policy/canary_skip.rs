// cli_policy/canary_skip.rs — `kepr import`, `kepr discover` and `kepr
// agent adopt` leave planted canaries (T9.08) alone: stored as a real
// credential a decoy would look like a working key, and adopt would also
// delete the bait from the file it was planted in. Matched by the
// fingerprint `kepr canary ls` carries, never by sending values.

use std::collections::HashSet;

use kepr_core::protocol::{Request, Response};
use kepr_core::protocol_policy::{PolicyRequest, PolicyResponse};

pub const SKIP: &str = "a planted canary (kepr canary ls); left where it is";

#[derive(Default)]
pub struct Canaries(HashSet<String>);

impl Canaries {
    /// The caller's planted canaries; none when the daemon can't say.
    pub fn planted() -> Self {
        match crate::client::send_request(&Request::Policy(PolicyRequest::CanaryList)) {
            Ok(Response::Policy(PolicyResponse::CanaryListing { canaries })) => Self(
                canaries
                    .into_iter()
                    .map(|c| c.fingerprint)
                    .filter(|f| !f.is_empty())
                    .collect(),
            ),
            _ => Self::default(),
        }
    }

    pub fn contains(&self, value: &str) -> bool {
        !self.0.is_empty()
            && self
                .0
                .contains(&kepr_core::canary::fingerprint(value.as_bytes()))
    }
}

#[cfg(test)]
impl Canaries {
    pub fn of(values: &[&str]) -> Self {
        Self(
            values
                .iter()
                .map(|v| kepr_core::canary::fingerprint(v.as_bytes()))
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_by_fingerprint_only() {
        let c = Canaries::of(&["sk-proj-decoy"]);
        assert!(c.contains("sk-proj-decoy"));
        assert!(!c.contains("sk-proj-real"));
        assert!(!Canaries::default().contains("sk-proj-decoy"));
    }
}
