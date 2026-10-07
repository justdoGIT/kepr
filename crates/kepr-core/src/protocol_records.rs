// protocol_records.rs — wire types of the `records` ticket batch:
// attachments (T5.03), record convert (T11.7). Wrapped by `Request::Records` / `Response::Records`,
// which are `#[serde(untagged)]` and tried after every tagged variant, so
// the `cmd` / `kind` names here must not repeat one in protocol.rs or
// protocol_store.rs.
//
// Attachment bytes travel base64-encoded in `ZeroString`s (a chunk is
// secret material), one chunk per frame: CHUNK_BYTES raw bytes encode to
// 61 440 characters, which leaves room for the envelope inside the 64 KiB
// frame limit.

use serde::{Deserialize, Serialize};

use crate::generate::ZeroString;

/// Raw bytes per attachment chunk (the last chunk may be shorter).
pub const CHUNK_BYTES: usize = 45 * 1024;
/// Largest attachment.
pub const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
/// Largest total of one credential's attachments.
pub const MAX_RECORD_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum RecordsRequest {
    /// T5.03: one chunk of an upload. Chunk 0 starts an upload and the
    /// reply names it (`upload`); later chunks carry that id. `last`
    /// finishes it: the daemon checks the size caps and lists the file.
    AttachPut {
        name: String,
        file: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        upload: Option<String>,
        index: u32,
        /// Base64 of at most CHUNK_BYTES bytes (exactly that, unless last).
        chunk: ZeroString,
        #[serde(default)]
        last: bool,
    },
    /// T5.03: chunk `index` of an attachment.
    AttachGet {
        name: String,
        file: String,
        index: u32,
    },
    /// T5.03: a credential's attachments (names, sizes, digests).
    AttachList { name: String },
    /// T5.03: drop one attachment.
    AttachRemove { name: String, file: String },
    /// T11.7: re-type a record. Fields named in `fields` (the new type's,
    /// from the caller's type table) stay fields, custom fields with such
    /// a name become fields again, and every other field becomes a custom
    /// field. An empty `fields` (an any-fields type) keeps them all.
    RecordConvert {
        name: String,
        record_type: String,
        #[serde(default)]
        fields: Vec<String>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RecordsResponse {
    AttachPutOk {
        name: String,
        file: String,
        upload: String,
        /// True once the last chunk is stored and the file is listed.
        done: bool,
    },
    AttachChunkOk {
        name: String,
        file: String,
        index: u32,
        chunks: u32,
        size: u64,
        sha256: String,
        /// Base64 of this chunk's bytes.
        data: ZeroString,
    },
    AttachListOk {
        name: String,
        files: Vec<AttachInfo>,
    },
    AttachRemoveOk {
        name: String,
        file: String,
    },
    /// T11.7. `moved` (now custom fields) and `promoted` (custom fields
    /// that became fields) are empty for a consent- or FIDO2-gated record,
    /// whose field names are not reported without a prompt.
    RecordConvertOk {
        name: String,
        record_type: String,
        #[serde(default)]
        moved: Vec<String>,
        #[serde(default)]
        promoted: Vec<String>,
        #[serde(default)]
        gated: bool,
    },
}

/// One attachment, as the credential's `.meta` manifest records it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttachInfo {
    /// Random hex id; chunks are stored as `NAME~a<id>~<n>`.
    pub id: String,
    pub file: String,
    pub size: u64,
    /// Hex SHA-256 of the whole file.
    pub sha256: String,
}

impl AttachInfo {
    /// Number of stored chunks (an empty file still has chunk 0).
    pub fn chunks(&self) -> u32 {
        let n = self.size.div_ceil(CHUNK_BYTES as u64).max(1);
        u32::try_from(n).unwrap_or(u32::MAX)
    }
}

/// An attachment's file name: 1-128 characters, no `/`, no `..`, no
/// control characters.
pub fn validate_file_name(f: &str) -> Result<(), String> {
    if f.is_empty() || f.chars().count() > 128 {
        return Err("attachment name must be 1-128 characters".into());
    }
    if f.contains('/') || f.contains("..") || f.chars().any(char::is_control) {
        return Err(format!(
            "invalid attachment name {f:?}: no '/', '..' or control characters"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Request, Response};
    use serde_json::{json, Value};

    fn req_round_trip(r: Request) -> Value {
        let v = serde_json::to_value(&r).unwrap();
        let back: Request = serde_json::from_value(v.clone()).unwrap();
        assert!(matches!(back, Request::Records(_)), "{v}");
        assert_eq!(serde_json::to_value(&back).unwrap(), v);
        v
    }

    fn resp_round_trip(r: Response) -> Value {
        let v = serde_json::to_value(&r).unwrap();
        let back: Response = serde_json::from_value(v.clone()).unwrap();
        assert!(matches!(back, Response::Records(_)), "{v}");
        assert_eq!(serde_json::to_value(&back).unwrap(), v);
        v
    }

    #[test]
    fn attach_requests_round_trip() {
        let v = req_round_trip(Request::Records(RecordsRequest::AttachPut {
            name: "DOC".into(),
            file: "a.pdf".into(),
            upload: None,
            index: 0,
            chunk: "aGk=".into(),
            last: true,
        }));
        assert_eq!(v["cmd"], json!("attach_put"));
        assert!(v.get("upload").is_none(), "{v}");
        for (r, cmd) in [
            (
                RecordsRequest::AttachGet {
                    name: "DOC".into(),
                    file: "a.pdf".into(),
                    index: 2,
                },
                "attach_get",
            ),
            (
                RecordsRequest::AttachList { name: "DOC".into() },
                "attach_list",
            ),
            (
                RecordsRequest::AttachRemove {
                    name: "DOC".into(),
                    file: "a.pdf".into(),
                },
                "attach_remove",
            ),
            (
                RecordsRequest::RecordConvert {
                    name: "DOC".into(),
                    record_type: "wifi".into(),
                    fields: vec!["ssid".into()],
                },
                "record_convert",
            ),
        ] {
            assert_eq!(req_round_trip(Request::Records(r))["cmd"], json!(cmd));
        }
    }

    #[test]
    fn attach_responses_round_trip() {
        let info = AttachInfo {
            id: "00ff".into(),
            file: "a.pdf".into(),
            size: 3,
            sha256: "ab".into(),
        };
        for r in [
            RecordsResponse::AttachPutOk {
                name: "DOC".into(),
                file: "a.pdf".into(),
                upload: "00ff".into(),
                done: false,
            },
            RecordsResponse::AttachChunkOk {
                name: "DOC".into(),
                file: "a.pdf".into(),
                index: 0,
                chunks: 1,
                size: 3,
                sha256: "ab".into(),
                data: "aGk=".into(),
            },
            RecordsResponse::AttachListOk {
                name: "DOC".into(),
                files: vec![info],
            },
            RecordsResponse::AttachRemoveOk {
                name: "DOC".into(),
                file: "a.pdf".into(),
            },
            RecordsResponse::RecordConvertOk {
                name: "DOC".into(),
                record_type: "wifi".into(),
                moved: vec!["url".into()],
                promoted: vec![],
                gated: false,
            },
        ] {
            resp_round_trip(Response::Records(r));
        }
    }

    #[test]
    fn a_full_chunk_fits_in_one_frame() {
        let chunk = "A".repeat(CHUNK_BYTES.div_ceil(3) * 4);
        let req = Request::Records(RecordsRequest::AttachPut {
            name: "N".repeat(128),
            file: "f".repeat(128),
            upload: Some("0".repeat(16)),
            index: u32::MAX,
            chunk: chunk.into(),
            last: false,
        });
        let n = serde_json::to_vec(&req).unwrap().len();
        assert!(n < crate::protocol::MAX_MSG_BYTES, "{n}");
    }

    #[test]
    fn chunk_count_and_file_names() {
        let info = |size| AttachInfo {
            id: String::new(),
            file: String::new(),
            size,
            sha256: String::new(),
        };
        assert_eq!(info(0).chunks(), 1);
        assert_eq!(info(CHUNK_BYTES as u64).chunks(), 1);
        assert_eq!(info(CHUNK_BYTES as u64 + 1).chunks(), 2);
        assert!(validate_file_name("report 2026.pdf").is_ok());
        for bad in ["", "a/b", "..", "x..y", "a\nb", &"x".repeat(129)] {
            assert!(validate_file_name(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn existing_variants_still_win() {
        let back: Request = serde_json::from_value(json!({"cmd": "list"})).unwrap();
        assert!(matches!(back, Request::List));
        let back: Request = serde_json::from_value(json!({"cmd": "dupes"})).unwrap();
        assert!(matches!(back, Request::Store(_)));
    }
}
