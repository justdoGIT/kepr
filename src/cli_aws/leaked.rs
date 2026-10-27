// leaked.rs — `kepr leaked NAME --rotate` (T9.09): after the daemon has
// stopped the agent sessions and deleted the exposed value, replace it
// through the provider's API where one exists, else point at the page
// where the user revokes it (as plain `kepr leaked` does).
//
// The value is read (`get`) before the leak is reported, because the
// daemon deletes it; a sealed value can't be read, so a sealed key gets
// the revocation URL. What a value is comes from `TABLE`:
//
//   aws-iam     IAM user key JSON      new key via IAM (T7.05), old deleted
//   aws-sts     key JSON with a token  temporary: expires on its own
//   github-app  `ghs_…`                installation token: expires in 1 h
//
// Anything else falls back to the revocation URL.

use kepr_core::generate::ZeroString;
use kepr_core::providers;
use kepr_core::sigv4_req::AwsKey;

use super::rotate_iam::{short, Rotated};
use crate::cli_exec::{CredFetcher, DaemonFetcher};

/// Where AWS users manage their own access keys.
pub const AWS_KEYS_URL: &str = "https://console.aws.amazon.com/iam/home#/security_credentials";

pub enum Via {
    AwsIam,
    /// No API call: the value stops working by itself. Why, for the user.
    Expires(&'static str),
}

pub struct ProviderRotation {
    pub provider: &'static str,
    pub matches: fn(&str) -> bool,
    pub via: Via,
}

fn aws_key(v: &str) -> Option<AwsKey> {
    AwsKey::parse(v).ok()
}

pub const TABLE: &[ProviderRotation] = &[
    ProviderRotation {
        provider: "aws-iam",
        matches: |v| aws_key(v).is_some_and(|k| k.session_token.is_none()),
        via: Via::AwsIam,
    },
    ProviderRotation {
        provider: "aws-sts",
        matches: |v| aws_key(v).is_some_and(|k| k.session_token.is_some()),
        via: Via::Expires(
            "temporary AWS credentials expire on their own; to cut them off now, \
             revoke the role's active sessions in the IAM console",
        ),
    },
    ProviderRotation {
        provider: "github-app",
        matches: |v| v.starts_with("ghs_"),
        via: Via::Expires("GitHub App installation tokens expire within an hour by design"),
    },
];

pub fn rotation_for(value: &str) -> Option<&'static ProviderRotation> {
    TABLE.iter().find(|r| (r.matches)(value))
}

/// What `--rotate` will do, decided before the value is deleted.
pub enum Plan {
    Rotate(AwsKey),
    /// `(provider, why)`: nothing to call, the value expires by itself.
    Expires(&'static str, &'static str),
    /// No provider API: revoke by hand. Why, when it isn't obvious.
    Url(Option<String>),
}

pub fn plan_for(value: Result<ZeroString, String>) -> Plan {
    let v = match value {
        Ok(v) => v,
        Err(e) => return Plan::Url(Some(format!("its value can't be read here ({e})"))),
    };
    match rotation_for(v.as_str()).map(|r| (r.provider, &r.via)) {
        Some((_, Via::AwsIam)) => aws_key(v.as_str()).map_or(Plan::Url(None), Plan::Rotate),
        Some((provider, Via::Expires(why))) => Plan::Expires(provider, why),
        None => Plan::Url(None),
    }
}

/// `plan_for` the stored NAME; a sealed value is never asked for.
pub fn plan(name: &str) -> Plan {
    let sealed = crate::cli_agent_run::sealed_creds()
        .map(|cs| cs.iter().any(|c| c.name == name))
        .unwrap_or(false);
    if sealed {
        return Plan::Url(Some("sealed keys never leave the gate".into()));
    }
    plan_for(DaemonFetcher.fetch(name))
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    pub rotated: Option<Rotated>,
    /// Shown to the user (why nothing was rotated, or what to do next).
    pub note: Option<String>,
    pub error: Option<String>,
    /// Where to revoke the old value by hand (empty once rotated).
    pub revoke_urls: Vec<&'static str>,
}

/// After `Leaked` succeeded: carry out `plan`. `rotate` is the IAM
/// rotator (`rotate_iam::run` in production).
pub fn finish(
    plan: Plan,
    hosts: &[String],
    rotate: &mut dyn FnMut(&AwsKey) -> Result<Rotated, String>,
) -> Outcome {
    let mut urls: Vec<&'static str> = hosts
        .iter()
        .filter_map(|h| match providers::by_host(h) {
            Some(p) => Some(p.keys_url),
            None => h.ends_with("amazonaws.com").then_some(AWS_KEYS_URL),
        })
        .collect();
    let mut out = Outcome::default();
    match plan {
        Plan::Rotate(key) => match rotate(&key) {
            Ok(done) => {
                out.rotated = Some(done);
                urls.clear();
            }
            Err(e) => {
                out.error = Some(format!(
                    "rotation of {} failed: {e}",
                    short(&key.access_key_id)
                ));
                urls.push(AWS_KEYS_URL);
            }
        },
        Plan::Expires(provider, why) => out.note = Some(format!("{provider}: {why}")),
        Plan::Url(why) => {
            out.note = Some(match why {
                Some(w) => format!("no provider API rotation: {w}"),
                None => "no provider API rotation for this kind of key".into(),
            })
        }
    }
    urls.sort_unstable();
    urls.dedup();
    out.revoke_urls = urls;
    out
}

/// Production `finish` for NAME.
pub fn finish_for(name: &str, plan: Plan, hosts: &[String]) -> Outcome {
    finish(plan, hosts, &mut |k| {
        super::rotate_iam::run(name, k)
            .map(|(done, _)| done)
            .map_err(|(e, stored)| {
                if stored {
                    e
                } else {
                    format!("{e}; {name} is deleted from kepr")
                }
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const IAM: &str = r#"{"access_key_id":"AKIAOLDOLDOLDOLD0001","secret_access_key":"s"}"#;
    const STS: &str =
        r#"{"access_key_id":"ASIAOLDOLDOLDOLD0001","secret_access_key":"s","session_token":"t"}"#;

    fn ok(v: &str) -> Result<ZeroString, String> {
        Ok(ZeroString::from(v))
    }

    #[test]
    fn provider_dispatch_table() {
        let p = |v: &str| rotation_for(v).map(|r| r.provider);
        assert_eq!(p(IAM), Some("aws-iam"));
        assert_eq!(p(STS), Some("aws-sts"));
        assert_eq!(
            p("ghs_16C7e42F292c6912E7710c838347Ae178B4a"),
            Some("github-app")
        );
        assert_eq!(p("sk-ant-api03-abcdefghijklmnop"), None);
        assert_eq!(p("ghp_personal"), None);
        assert!(matches!(plan_for(ok(IAM)), Plan::Rotate(_)));
        assert!(matches!(plan_for(ok(STS)), Plan::Expires("aws-sts", _)));
        assert!(matches!(
            plan_for(Err("credential unavailable".into())),
            Plan::Url(Some(_))
        ));
    }

    #[test]
    fn the_aws_path_calls_the_rotator() {
        let mut called = Vec::new();
        let out = finish(plan_for(ok(IAM)), &[], &mut |k| {
            called.push(k.access_key_id.clone());
            Ok(Rotated {
                old_id: k.access_key_id.clone(),
                new_id: "AKIANEWNEWNEWNEW0002".into(),
            })
        });
        assert_eq!(called, ["AKIAOLDOLDOLDOLD0001"]);
        assert_eq!(out.rotated.unwrap().new_id, "AKIANEWNEWNEWNEW0002");
        assert!(out.revoke_urls.is_empty() && out.error.is_none());
    }

    #[test]
    fn a_failed_aws_rotation_points_at_the_console() {
        let out = finish(plan_for(ok(IAM)), &[], &mut |_| Err("AccessDenied".into()));
        assert!(out.error.unwrap().contains("AccessDenied"));
        assert_eq!(out.revoke_urls, [AWS_KEYS_URL]);
        assert!(out.rotated.is_none());
    }

    #[test]
    fn an_unknown_provider_falls_back_to_the_url() {
        let mut rotator =
            |_: &AwsKey| -> Result<Rotated, String> { panic!("no provider API for this key") };
        let out = finish(
            plan_for(ok("sk-ant-api03-abcdefghijklmnop")),
            &["api.anthropic.com".to_string()],
            &mut rotator,
        );
        assert_eq!(
            out.revoke_urls,
            ["https://console.anthropic.com/settings/keys"]
        );
        assert!(out.note.unwrap().contains("no provider API"));
        let out = finish(
            Plan::Url(Some("sealed keys never leave the gate".into())),
            &["sts.amazonaws.com".to_string()],
            &mut rotator,
        );
        assert_eq!(out.revoke_urls, [AWS_KEYS_URL]);
        assert!(out.note.unwrap().contains("sealed"));
        let out = finish(plan_for(ok(STS)), &[], &mut rotator);
        assert!(out.note.unwrap().contains("expire on their own"));
    }
}
