// iam.rs — the three IAM Query-API calls the access-key rotator (T7.05)
// needs: `ListAccessKeys`, `CreateAccessKey` and `DeleteAccessKey`, all
// for the calling user (no `UserName`), signed by `sts::call` for the
// global IAM endpoint. The new secret goes straight into a `ZeroString`.

use kepr_core::generate::ZeroString;
use kepr_core::sigv4_req::AwsKey;
use zeroize::Zeroizing;

use super::sts::{call, xml_text, Endpoint};

const IAM_VERSION: &str = "2010-05-08";

/// The access key ids of the calling user (IAM allows at most two).
pub fn parse_key_ids(xml: &str) -> Result<Vec<String>, String> {
    let list = xml_text(xml, "AccessKeyMetadata").ok_or("IAM reply has no key list")?;
    let mut ids = Vec::new();
    let mut rest = list.as_str();
    while let Some(i) = rest.find("<AccessKeyId>") {
        let id = xml_text(&rest[i..], "AccessKeyId").ok_or("IAM reply is malformed")?;
        rest = &rest[i + "<AccessKeyId>".len()..];
        ids.push(id);
    }
    Ok(ids)
}

/// The `<AccessKey>` block of a CreateAccessKey reply.
pub fn parse_new_key(xml: &str) -> Result<AwsKey, String> {
    let block = Zeroizing::new(xml_text(xml, "AccessKey").ok_or("IAM reply has no access key")?);
    let field = |t: &str| xml_text(&block, t).ok_or(format!("IAM reply has no {t}"));
    Ok(AwsKey {
        access_key_id: field("AccessKeyId")?,
        secret_access_key: ZeroString::from_string(field("SecretAccessKey")?),
        session_token: None,
    })
}

pub fn list_access_keys(ep: &Endpoint, key: &AwsKey, now: u64) -> Result<Vec<String>, String> {
    let p = [("Action", "ListAccessKeys"), ("Version", IAM_VERSION)];
    parse_key_ids(&call(ep, key, &p, now)?)
}

pub fn create_access_key(ep: &Endpoint, key: &AwsKey, now: u64) -> Result<AwsKey, String> {
    let p = [("Action", "CreateAccessKey"), ("Version", IAM_VERSION)];
    parse_new_key(&call(ep, key, &p, now)?)
}

/// Delete the calling user's key `id` (signed with `key`).
pub fn delete_access_key(ep: &Endpoint, key: &AwsKey, id: &str, now: u64) -> Result<(), String> {
    let p = [
        ("Action", "DeleteAccessKey"),
        ("Version", IAM_VERSION),
        ("AccessKeyId", id),
    ];
    call(ep, key, &p, now).map(|_| ())
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::cli_aws::fake;

    pub fn list_xml(ids: &[&str]) -> String {
        let members: String = ids
            .iter()
            .map(|id| {
                format!(
                    "<member><UserName>bob</UserName><AccessKeyId>{id}</AccessKeyId>\
                     <Status>Active</Status></member>"
                )
            })
            .collect();
        format!(
            "<ListAccessKeysResponse><ListAccessKeysResult><UserName>bob</UserName>\
             <AccessKeyMetadata>{members}</AccessKeyMetadata><IsTruncated>false</IsTruncated>\
             </ListAccessKeysResult></ListAccessKeysResponse>"
        )
    }

    pub fn create_xml(id: &str, secret: &str) -> String {
        format!(
            "<CreateAccessKeyResponse><CreateAccessKeyResult><AccessKey><UserName>bob</UserName>\
             <AccessKeyId>{id}</AccessKeyId><Status>Active</Status>\
             <SecretAccessKey>{secret}</SecretAccessKey></AccessKey></CreateAccessKeyResult>\
             </CreateAccessKeyResponse>"
        )
    }

    pub const DELETE_XML: &str = "<DeleteAccessKeyResponse><ResponseMetadata>\
        <RequestId>1</RequestId></ResponseMetadata></DeleteAccessKeyResponse>";

    fn key() -> AwsKey {
        AwsKey::parse(
            r#"{"access_key_id":"AKIAOLDOLDOLDOLD0001","secret_access_key":"OLD/secret"}"#,
        )
        .unwrap()
    }

    #[test]
    fn parses_list_and_create_replies() {
        assert_eq!(
            parse_key_ids(&list_xml(&["AKIA1111111111111111", "AKIA2222222222222222"])).unwrap(),
            ["AKIA1111111111111111", "AKIA2222222222222222"]
        );
        assert!(parse_key_ids(&list_xml(&[])).unwrap().is_empty());
        assert!(parse_key_ids("<x/>").is_err());
        let k = parse_new_key(&create_xml("AKIANEWNEWNEWNEW0002", "NEW/sec&amp;ret")).unwrap();
        assert_eq!(k.access_key_id, "AKIANEWNEWNEWNEW0002");
        assert_eq!(k.secret_access_key.as_str(), "NEW/sec&ret");
        assert!(k.session_token.is_none());
        assert!(parse_new_key("<AccessKey><AccessKeyId>A</AccessKeyId></AccessKey>").is_err());
    }

    #[test]
    fn query_api_request_shapes() {
        let f = fake::serve(vec![
            (200, list_xml(&["AKIAOLDOLDOLDOLD0001"])),
            (200, create_xml("AKIANEWNEWNEWNEW0002", "s")),
            (200, DELETE_XML.into()),
        ]);
        let ep = Endpoint {
            url: f.url.clone(),
            ..Endpoint::iam()
        };
        list_access_keys(&ep, &key(), 1_440_938_160).unwrap();
        create_access_key(&ep, &key(), 1_440_938_160).unwrap();
        delete_access_key(&ep, &key(), "AKIAOLDOLDOLDOLD0001", 1_440_938_160).unwrap();
        let bodies: Vec<String> = (0..3).map(|_| f.requests.recv().unwrap()).collect();
        assert!(bodies[0].ends_with("\r\n\r\nAction=ListAccessKeys&Version=2010-05-08"));
        assert!(bodies[1].ends_with("\r\n\r\nAction=CreateAccessKey&Version=2010-05-08"));
        assert!(bodies[2].ends_with(
            "\r\n\r\nAction=DeleteAccessKey&Version=2010-05-08&AccessKeyId=AKIAOLDOLDOLDOLD0001"
        ));
        for b in &bodies {
            assert!(b.contains("/20150830/us-east-1/iam/aws4_request"), "{b}");
            assert!(!b.contains("OLD/secret"));
        }
    }
}
