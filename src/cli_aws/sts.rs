// sts.rs — a small AWS Query-API client (T7.06): STS `GetSessionToken`,
// `AssumeRole` and `GetCallerIdentity`, plus the signed POST the IAM
// rotator (T7.05) reuses. Signing is `kepr_core::sigv4_req`; HTTP is the
// shared ureq agent (no redirects, 30 s timeout). Replies are XML; error
// text carries only the provider's `Code` and `Message`, never the body,
// and every secret from a reply goes straight into a `ZeroString`.

use kepr_core::generate::ZeroString;
use kepr_core::sigv4::{format_amz_date, hex_sha256};
use kepr_core::sigv4_req::{authorization, aws_encode, signature, AwsKey, Canonical, Scope};
use zeroize::Zeroizing;

const STS_VERSION: &str = "2011-06-15";
const FORM: &str = "application/x-www-form-urlencoded; charset=utf-8";

/// Where a Query-API call goes. `url` is what is dialled; `host` is
/// what is signed (they differ only for the tests' loopback fakes).
#[derive(Debug, Clone)]
pub struct Endpoint {
    pub url: String,
    pub host: String,
    pub region: String,
    pub service: &'static str,
}

impl Endpoint {
    /// Regional STS for `region`, or the global endpoint (us-east-1).
    pub fn sts(region: Option<&str>) -> Result<Self, String> {
        let (host, region) = match region {
            Some(r) if kepr_core::sigv4_req::valid_region(r) => {
                (format!("sts.{r}.amazonaws.com"), r.to_string())
            }
            Some(r) => return Err(format!("{r:?} is not an AWS region name")),
            None => ("sts.amazonaws.com".to_string(), "us-east-1".to_string()),
        };
        Ok(Self {
            url: format!("https://{host}/"),
            host,
            region,
            service: "sts",
        })
    }

    /// IAM is global, signed for us-east-1.
    pub fn iam() -> Self {
        Self {
            url: "https://iam.amazonaws.com/".into(),
            host: "iam.amazonaws.com".into(),
            region: "us-east-1".into(),
            service: "iam",
        }
    }
}

/// Temporary credentials from STS (`key.session_token` is always set).
pub struct TempCreds {
    pub key: AwsKey,
    /// ISO 8601, as STS returns it (`2026-10-07T12:00:00Z`).
    pub expiration: String,
}

#[derive(Debug, PartialEq, Eq)]
pub struct CallerIdentity {
    pub account: String,
    pub arn: String,
    pub user_id: String,
}

/// The form body and the headers to send (signed at `amz_date`).
pub fn signed_request(
    ep: &Endpoint,
    key: &AwsKey,
    params: &[(&str, &str)],
    amz_date: &str,
) -> (String, Vec<(String, String)>) {
    let body: Vec<String> = params
        .iter()
        .map(|(k, v)| format!("{}={}", aws_encode(k, false), aws_encode(v, false)))
        .collect();
    let body = body.join("&");
    let mut headers = vec![
        ("content-type".to_string(), FORM.to_string()),
        ("host".to_string(), ep.host.clone()),
        ("x-amz-date".to_string(), amz_date.to_string()),
    ];
    if let Some(t) = &key.session_token {
        headers.push(("x-amz-security-token".into(), t.as_str().to_string()));
    }
    let hash = hex_sha256(body.as_bytes());
    let (text, signed) = Canonical {
        method: "POST",
        uri: "/",
        query: "",
        headers: &headers,
        payload_hash: &hash,
    }
    .build();
    let scope = Scope {
        date: amz_date[..8].to_string(),
        region: ep.region.clone(),
        service: ep.service.to_string(),
    };
    let sig = signature(key.secret_access_key.as_str(), amz_date, &scope, &text);
    let auth = authorization(&key.access_key_id, &scope, &signed, &sig);
    headers.retain(|(n, _)| n != "host");
    headers.push(("authorization".into(), auth));
    (body, headers)
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// One signed Query-API call. `Ok(body)` for a 2xx reply; otherwise the
/// provider's error code and message (`what` names the action).
pub fn call(
    ep: &Endpoint,
    key: &AwsKey,
    params: &[(&str, &str)],
    now: u64,
) -> Result<Zeroizing<String>, String> {
    let what = params
        .iter()
        .find(|(k, _)| *k == "Action")
        .map_or("request", |(_, v)| *v);
    let (body, headers) = signed_request(ep, key, params, &format_amz_date(now));
    let mut req = crate::sync_http::agent().post(&ep.url);
    for (n, v) in &headers {
        req = req.set(n, v);
    }
    let (status, reply) = crate::sync_http::send(req, Some(body.as_bytes()))
        .map_err(|e| format!("{} {what}: {e}", ep.service))?;
    let reply = Zeroizing::new(reply);
    if (200..300).contains(&status) {
        return Ok(reply);
    }
    Err(format!(
        "{} {what}: HTTP {status} {}",
        ep.service,
        error_summary(&reply)
    ))
}

/// The text of the first `<tag>…</tag>` in `xml`, entities decoded.
pub fn xml_text(xml: &str, tag: &str) -> Option<String> {
    let start = xml.find(&format!("<{tag}>"))? + tag.len() + 2;
    let len = xml[start..].find(&format!("</{tag}>"))?;
    Some(
        xml[start..start + len]
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&amp;", "&"),
    )
}

/// `Code: Message` from an AWS XML error body, at most 200 chars.
pub fn error_summary(xml: &str) -> String {
    let code = xml_text(xml, "Code").unwrap_or_default();
    let msg = xml_text(xml, "Message").unwrap_or_default();
    let s = match (code.is_empty(), msg.is_empty()) {
        (false, false) => format!("{code}: {msg}"),
        _ => format!("{code}{msg}"),
    };
    s.chars().take(200).collect()
}

/// The `<Credentials>` block of a GetSessionToken / AssumeRole reply.
pub fn parse_credentials(xml: &str) -> Result<TempCreds, String> {
    let block = xml_text(xml, "Credentials").ok_or("STS reply has no credentials")?;
    let block = Zeroizing::new(block);
    let field = |t: &str| xml_text(&block, t).ok_or(format!("STS reply has no {t}"));
    let key = AwsKey {
        access_key_id: field("AccessKeyId")?,
        secret_access_key: ZeroString::from_string(field("SecretAccessKey")?),
        session_token: Some(ZeroString::from_string(field("SessionToken")?)),
    };
    Ok(TempCreds {
        key,
        expiration: field("Expiration")?,
    })
}

pub fn parse_caller_identity(xml: &str) -> Result<CallerIdentity, String> {
    let field = |t: &str| xml_text(xml, t).ok_or(format!("STS reply has no {t}"));
    Ok(CallerIdentity {
        account: field("Account")?,
        arn: field("Arn")?,
        user_id: field("UserId")?,
    })
}

pub fn get_session_token(
    ep: &Endpoint,
    key: &AwsKey,
    duration_secs: u32,
    now: u64,
) -> Result<TempCreds, String> {
    let d = duration_secs.to_string();
    let p = [
        ("Action", "GetSessionToken"),
        ("Version", STS_VERSION),
        ("DurationSeconds", d.as_str()),
    ];
    parse_credentials(&call(ep, key, &p, now)?)
}

pub fn assume_role(
    ep: &Endpoint,
    key: &AwsKey,
    (role_arn, session_name): (&str, &str),
    duration_secs: u32,
    now: u64,
) -> Result<TempCreds, String> {
    let d = duration_secs.to_string();
    let p = [
        ("Action", "AssumeRole"),
        ("Version", STS_VERSION),
        ("RoleArn", role_arn),
        ("RoleSessionName", session_name),
        ("DurationSeconds", d.as_str()),
    ];
    parse_credentials(&call(ep, key, &p, now)?)
}

pub fn get_caller_identity(
    ep: &Endpoint,
    key: &AwsKey,
    now: u64,
) -> Result<CallerIdentity, String> {
    let p = [("Action", "GetCallerIdentity"), ("Version", STS_VERSION)];
    parse_caller_identity(&call(ep, key, &p, now)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli_aws::fake;

    const NOW: u64 = 1_440_938_160; // 2015-08-30T12:36:00Z

    fn key(token: Option<&str>) -> AwsKey {
        AwsKey {
            access_key_id: "AKIDEXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
            session_token: token.map(ZeroString::from),
        }
    }

    fn loopback(url: &str) -> Endpoint {
        Endpoint {
            url: url.to_string(),
            ..Endpoint::sts(None).unwrap()
        }
    }

    const SESSION_XML: &str = r#"<GetSessionTokenResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetSessionTokenResult>
    <Credentials>
      <SessionToken>FQoGZXIvYXdzE&amp;tok</SessionToken>
      <SecretAccessKey>wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY</SecretAccessKey>
      <Expiration>2011-07-11T19:55:29.611Z</Expiration>
      <AccessKeyId>ASIAIOSFODNN7EXAMPLE</AccessKeyId>
    </Credentials>
  </GetSessionTokenResult>
  <ResponseMetadata><RequestId>58c5dbae</RequestId></ResponseMetadata>
</GetSessionTokenResponse>"#;

    #[test]
    fn signing_matches_a_reference_at_a_fixed_date() {
        // Expected values computed independently from the SigV4 spec.
        let ep = Endpoint::sts(None).unwrap();
        let p = [("Action", "GetCallerIdentity"), ("Version", STS_VERSION)];
        let (body, h) = signed_request(&ep, &key(None), &p, "20150830T123600Z");
        assert_eq!(body, "Action=GetCallerIdentity&Version=2011-06-15");
        let auth = &h.iter().find(|(n, _)| n == "authorization").unwrap().1;
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/sts/aws4_request, \
             SignedHeaders=content-type;host;x-amz-date, \
             Signature=6fb20d31f734d876c5682fdd2678d194cf68b862755f83b7ba1373c0874be25c"
        );
        let (_, h) = signed_request(&ep, &key(Some("TOKEN")), &p, "20150830T123600Z");
        let auth = &h.iter().find(|(n, _)| n == "authorization").unwrap().1;
        assert!(auth.ends_with(
            "SignedHeaders=content-type;host;x-amz-date;x-amz-security-token, \
             Signature=704fedc5a1ba24c82bb5628741289ceec724719ec5c53ad340baa3dc32b73796"
        ));
        assert!(h
            .iter()
            .any(|(n, v)| n == "x-amz-security-token" && v == "TOKEN"));
        assert!(Endpoint::sts(Some("x@evil.com#")).is_err());
        assert_eq!(
            Endpoint::sts(Some("eu-west-2")).unwrap().host,
            "sts.eu-west-2.amazonaws.com"
        );
    }

    #[test]
    fn parses_credentials_and_identity() {
        let c = parse_credentials(SESSION_XML).unwrap();
        assert_eq!(c.key.access_key_id, "ASIAIOSFODNN7EXAMPLE");
        assert_eq!(
            c.key.secret_access_key.as_str(),
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY"
        );
        assert_eq!(
            c.key.session_token.as_ref().unwrap().as_str(),
            "FQoGZXIvYXdzE&tok"
        );
        assert_eq!(c.expiration, "2011-07-11T19:55:29.611Z");
        let id = parse_caller_identity(
            "<GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/Alice</Arn>\
             <UserId>AKIAI44QH8DHBEXAMPLE</UserId><Account>123456789012</Account>\
             </GetCallerIdentityResult>",
        )
        .unwrap();
        assert_eq!(id.account, "123456789012");
        assert_eq!(id.arn, "arn:aws:iam::123456789012:user/Alice");
        assert!(parse_credentials("<x/>").is_err());
    }

    #[test]
    fn get_session_token_against_a_loopback_fake() {
        let f = fake::serve(vec![(200, SESSION_XML.into())]);
        let c = get_session_token(&loopback(&f.url), &key(None), 900, NOW).unwrap();
        assert_eq!(c.key.access_key_id, "ASIAIOSFODNN7EXAMPLE");
        let req = f.requests.recv().unwrap();
        assert!(req.starts_with("POST / "));
        assert!(req.ends_with("Action=GetSessionToken&Version=2011-06-15&DurationSeconds=900"));
        assert!(req
            .to_ascii_lowercase()
            .contains("x-amz-date: 20150830t123600z"));
        assert!(!req.contains("wJalrXUtnFEMI"), "the secret is never sent");
    }

    #[test]
    fn assume_role_sends_the_role_and_errors_carry_only_code_and_message() {
        let err = r#"<ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code>
            <Message>not authorized</Message></Error><Secret>hunter2</Secret></ErrorResponse>"#;
        let f = fake::serve(vec![(200, SESSION_XML.into()), (403, err.into())]);
        let ep = loopback(&f.url);
        let arn = "arn:aws:iam::123456789012:role/dev";
        assume_role(&ep, &key(None), (arn, "kepr"), 3600, NOW).unwrap();
        let req = f.requests.recv().unwrap();
        assert!(req.contains("RoleArn=arn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2Fdev"));
        assert!(req.contains("RoleSessionName=kepr"));
        let e = get_caller_identity(&ep, &key(None), NOW).unwrap_err();
        assert_eq!(
            e,
            "sts GetCallerIdentity: HTTP 403 AccessDenied: not authorized"
        );
    }
}
