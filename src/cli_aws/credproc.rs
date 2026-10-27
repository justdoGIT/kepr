// credproc.rs — `kepr aws credential-process NAME` (T2.03).
//
// For `~/.aws/config`:
//
//     [profile prod]
//     credential_process = kepr aws credential-process PROD_AWS
//
// Inside an agent session (`KEPR_SESSION` set by `kepr agent run`) it
// prints the session's SigV4 placeholder pair for NAME, from the session's
// own environment: the daemon is never asked. Outside a session it asks
// STS for temporary credentials (GetSessionToken, or AssumeRole with
// --role-arn) with the stored key and prints those. A long-lived key is
// never printed; a sealed key outside a session is refused (it never
// leaves the gate).

use kepr_core::generate::ZeroString;
use kepr_core::protocol::Response;
use kepr_core::sigv4_req::placeholder_access_key_id;

use super::session::PH_VAR_PREFIX;
use super::sts::{self, Endpoint, TempCreds};
use crate::cli_exec::{CredFetcher, DaemonFetcher};

pub const DURATIONS: std::ops::RangeInclusive<u32> = 900..=43_200;

#[derive(Debug, PartialEq, Eq)]
pub struct Opts {
    pub name: String,
    pub duration: u32,
    pub region: Option<String>,
    pub role_arn: Option<String>,
}

pub fn parse(args: &[&str]) -> Result<Opts, String> {
    let valued = ["--duration", "--region", "--role-arn"];
    let name = super::positional(args, &valued).ok_or(
        "usage: kepr aws credential-process KEY [--duration SECS] [--region R] [--role-arn ARN]",
    )?;
    let duration = match super::flag(args, "--duration") {
        None => 3600,
        Some(d) => d.parse().map_err(|_| "--duration takes seconds")?,
    };
    if !DURATIONS.contains(&duration) {
        return Err(format!(
            "--duration must be {}..={} seconds",
            DURATIONS.start(),
            DURATIONS.end()
        ));
    }
    Ok(Opts {
        name: name.to_uppercase(),
        duration,
        region: super::flag(args, "--region").map(str::to_string),
        role_arn: super::flag(args, "--role-arn").map(str::to_string),
    })
}

/// `YYYY-MM-DDTHH:MM:SSZ`.
pub fn iso8601(secs: u64) -> String {
    let d = kepr_core::sigv4::format_amz_date(secs);
    format!(
        "{}-{}-{}T{}:{}:{}Z",
        &d[..4],
        &d[4..6],
        &d[6..8],
        &d[9..11],
        &d[11..13],
        &d[13..15]
    )
}

/// The `credential_process` output (AWS CLI / SDK spec, `Version: 1`).
pub fn json(key_id: &str, secret: &str, token: Option<&str>, expiration: &str) -> ZeroString {
    let mut v = serde_json::json!({
        "Version": 1,
        "AccessKeyId": key_id,
        "SecretAccessKey": secret,
        "Expiration": expiration,
    });
    if let Some(t) = token {
        v["SessionToken"] = serde_json::Value::String(t.to_string());
    }
    let out = ZeroString::from_string(v.to_string());
    for k in ["SecretAccessKey", "SessionToken"] {
        if let Some(serde_json::Value::String(s)) = v.get_mut(k) {
            zeroize::Zeroize::zeroize(s);
        }
    }
    out
}

/// Inside a session: the placeholder pair for `name`, from the session
/// environment only. Valid for an hour, then the SDK asks again.
pub fn in_session(
    name: &str,
    env: &dyn Fn(&str) -> Option<String>,
    now: u64,
) -> Result<ZeroString, String> {
    let ph = env(&format!("{PH_VAR_PREFIX}{name}"))
        .ok_or_else(|| format!("{name} is not an AWS key of this agent session"))?;
    Ok(json(
        &placeholder_access_key_id(&ph),
        &ph,
        None,
        &iso8601(now + 3600),
    ))
}

/// Outside a session: temporary credentials from STS.
pub fn temporary(
    ep: &Endpoint,
    key: &kepr_core::sigv4_req::AwsKey,
    o: &Opts,
    now: u64,
) -> Result<ZeroString, String> {
    let c: TempCreds = match &o.role_arn {
        Some(arn) => sts::assume_role(ep, key, (arn, "kepr"), o.duration, now)?,
        None => sts::get_session_token(ep, key, o.duration, now)?,
    };
    let token = c.key.session_token.as_ref().map(|t| t.as_str());
    Ok(json(
        &c.key.access_key_id,
        c.key.secret_access_key.as_str(),
        token,
        &c.expiration,
    ))
}

pub fn run(
    o: &Opts,
    env: &dyn Fn(&str) -> Option<String>,
    fetcher: &dyn CredFetcher,
    now: u64,
) -> Result<ZeroString, String> {
    if env("KEPR_SESSION").is_some() {
        return in_session(&o.name, env, now);
    }
    let ep = super::sts_endpoint(o.region.as_deref())?;
    let key = super::load_key(&o.name, fetcher)?;
    temporary(&ep, &key, o, now)
}

pub fn cmd(args: &[&str]) -> Response {
    let out = parse(args).and_then(|o| {
        let env = |k: &str| std::env::var(k).ok();
        run(&o, &env, &DaemonFetcher, sts::now_secs())
    });
    match out {
        Ok(j) => {
            println!("{}", j.as_str());
            Response::Pong
        }
        Err(e) => Response::fail(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli_aws::fake;

    struct NoDaemon;
    impl CredFetcher for NoDaemon {
        fn fetch(&self, _: &str) -> Result<ZeroString, String> {
            panic!("the daemon must not be asked inside a session")
        }
    }

    fn opts(extra: &[&str]) -> Result<Opts, String> {
        let mut a = vec!["PROD_AWS"];
        a.extend_from_slice(extra);
        parse(&a)
    }

    #[test]
    fn json_shape_matches_the_aws_spec() {
        let v: serde_json::Value =
            serde_json::from_str(json("ASIA1", "s", Some("t"), "2026-10-07T12:00:00Z").as_str())
                .unwrap();
        assert_eq!(v["Version"], 1);
        assert_eq!(v["AccessKeyId"], "ASIA1");
        assert_eq!(v["SecretAccessKey"], "s");
        assert_eq!(v["SessionToken"], "t");
        assert_eq!(v["Expiration"], "2026-10-07T12:00:00Z");
        let v: serde_json::Value =
            serde_json::from_str(json("K", "s", None, "x").as_str()).unwrap();
        assert!(v.get("SessionToken").is_none());
        assert_eq!(iso8601(1_440_938_160), "2015-08-30T12:36:00Z");
    }

    #[test]
    fn inside_a_session_prints_the_placeholder_pair_without_the_daemon() {
        let env = |k: &str| match k {
            "KEPR_SESSION" => Some("0123456789abcdef".to_string()),
            "KEPR_AWS_PROD_AWS" => Some("kepr-ph-0123456789abcdef-0001-aa".to_string()),
            _ => None,
        };
        let out = run(&opts(&[]).unwrap(), &env, &NoDaemon, 0).unwrap();
        let v: serde_json::Value = serde_json::from_str(out.as_str()).unwrap();
        assert_eq!(v["SecretAccessKey"], "kepr-ph-0123456789abcdef-0001-aa");
        assert!(v["AccessKeyId"].as_str().unwrap().starts_with("KEPRPH"));
        assert_eq!(v["Expiration"], "1970-01-01T01:00:00Z");
        let o = Opts {
            name: "OTHER".into(),
            ..opts(&[]).unwrap()
        };
        assert!(run(&o, &env, &NoDaemon, 0)
            .unwrap_err()
            .contains("not an AWS key"));
    }

    #[test]
    fn outside_a_session_prints_sts_credentials_never_the_stored_key() {
        let xml = "<GetSessionTokenResult><Credentials><SessionToken>TOK</SessionToken>\
            <SecretAccessKey>TEMPSECRET</SecretAccessKey><Expiration>2026-10-07T13:00:00Z\
            </Expiration><AccessKeyId>ASIATEMP</AccessKeyId></Credentials></GetSessionTokenResult>";
        let f = fake::serve(vec![(200, xml.into())]);
        let ep = Endpoint {
            url: f.url.clone(),
            ..Endpoint::sts(None).unwrap()
        };
        let key = kepr_core::sigv4_req::AwsKey::parse(
            r#"{"access_key_id":"AKIAIOSFODNN7EXAMPLE","secret_access_key":"LONGLIVED"}"#,
        )
        .unwrap();
        let out = temporary(&ep, &key, &opts(&["--duration", "900"]).unwrap(), 0).unwrap();
        let v: serde_json::Value = serde_json::from_str(out.as_str()).unwrap();
        assert_eq!(v["AccessKeyId"], "ASIATEMP");
        assert_eq!(v["SessionToken"], "TOK");
        assert_eq!(v["Expiration"], "2026-10-07T13:00:00Z");
        assert!(!out.as_str().contains("LONGLIVED") && !out.as_str().contains("AKIAIOSFODNN7"));
        assert!(f.requests.recv().unwrap().contains("DurationSeconds=900"));
    }

    #[test]
    fn refuses_durations_outside_the_sts_range() {
        assert!(opts(&["--duration", "899"]).is_err());
        assert!(opts(&["--duration", "43201"]).is_err());
        assert!(opts(&["--duration", "soon"]).is_err());
        assert_eq!(opts(&["--duration", "43200"]).unwrap().duration, 43_200);
        assert_eq!(opts(&[]).unwrap().duration, 3600);
        assert_eq!(
            opts(&["--role-arn", "arn:aws:iam::1:role/r"])
                .unwrap()
                .role_arn
                .as_deref(),
            Some("arn:aws:iam::1:role/r")
        );
        assert!(parse(&[]).is_err());
    }
}
