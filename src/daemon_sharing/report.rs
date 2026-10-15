// daemon_sharing/report.rs — T11.15 `kepr share report`: what the caller
// has shared, and with whom.
//
// Two sources, merged: the sent-share ledger (sent.rs: recipient, expiry,
// opened) and the hash-chained audit log (every `share-send` /
// `share-link` that succeeded, including ones from before the ledger
// existed or after it was pruned). A chain entry the ledger already
// covers (same name and kind, within a few seconds) is not repeated;
// one it doesn't cover is a row with what the chain knows: name, kind
// and time (no id, recipient or expiry: `expires_unix` 0).

use std::path::Path;

use kepr_core::protocol::Response;
use kepr_core::protocol_sharing::{SentShare, SharingResponse};

use crate::audit_chain::ChainEntry;

/// Ledger rows and chain entries this close together are one share.
const SAME_SHARE_SECS: u64 = 5;

fn kind_of(op: &str) -> Option<&'static str> {
    match op {
        "share-send" => Some("envelope"),
        "share-link" => Some("link"),
        _ => None,
    }
}

/// Merge `uid`'s ledger with its chain entries, oldest first.
pub(crate) fn merge(ledger: Vec<SentShare>, chain: &[ChainEntry], uid: u32) -> Vec<SentShare> {
    let mut rows = ledger;
    for e in chain.iter().filter(|e| e.uid == uid && e.result == "ok") {
        let (Some(kind), Some(name)) = (kind_of(&e.op), e.name.as_ref()) else {
            continue;
        };
        let covered = rows.iter().any(|r| {
            r.kind == kind
                && &r.name == name
                && r.sent_unix.abs_diff(e.timestamp_unix) <= SAME_SHARE_SECS
        });
        if !covered {
            rows.push(SentShare {
                id: String::new(),
                name: name.clone(),
                kind: kind.into(),
                to: None,
                relay: None,
                sent_unix: e.timestamp_unix,
                expires_unix: 0,
                opened_unix: None,
                self_destruct: false,
                settled: false,
            });
        }
    }
    rows.sort_by_key(|r| r.sent_unix);
    rows
}

fn read_chain(path: &Path) -> Vec<ChainEntry> {
    use std::io::BufRead;
    let Ok(f) = std::fs::File::open(path) else {
        return Vec::new();
    };
    std::io::BufReader::new(f)
        .lines()
        .map_while(Result::ok)
        .filter_map(|l| serde_json::from_str(&l).ok())
        .collect()
}

pub fn handle_report(uid: u32, username: &str, chain_path: &Path) -> Response {
    let shares = merge(super::sent::rows(uid), &read_chain(chain_path), uid);
    super::audit_r::<()>("share-report", uid, username, None, &Ok(()));
    SharingResponse::ShareSent { shares }.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(uid: u32, ts: u64, op: &str, name: &str, result: &str) -> ChainEntry {
        ChainEntry {
            seq: ts,
            timestamp_unix: ts,
            op: op.into(),
            name: Some(name.into()),
            uid,
            username: "u".into(),
            result: result.into(),
            prev_hash: String::new(),
            hash: String::new(),
        }
    }

    fn row(name: &str, kind: &str, to: Option<&str>, sent: u64) -> SentShare {
        SentShare {
            id: format!("id-{name}"),
            name: name.into(),
            kind: kind.into(),
            to: to.map(Into::into),
            relay: None,
            sent_unix: sent,
            expires_unix: sent + 3600,
            opened_unix: Some(sent + 60),
            self_destruct: false,
            settled: false,
        }
    }

    #[test]
    fn rows_from_a_fixture_chain_and_the_ledger() {
        let chain = [
            // Before the ledger: only the chain knows.
            entry(7, 1_000, "share-send", "OLD_KEY", "ok"),
            // The ledger has these two (timestamps a second apart).
            entry(7, 2_001, "share-send", "API_KEY", "ok"),
            entry(7, 3_000, "share-link", "DB_PASS", "ok"),
            // Not shares, failed, or someone else's: ignored.
            entry(7, 3_500, "get", "API_KEY", "ok"),
            entry(
                7,
                3_600,
                "share-send",
                "NOPE",
                "fail: this credential can't be shared",
            ),
            entry(8, 3_700, "share-send", "THEIRS", "ok"),
        ];
        let ledger = vec![
            row("API_KEY", "envelope", Some("bob"), 2_000),
            row("DB_PASS", "link", None, 3_000),
        ];
        let rows = merge(ledger, &chain, 7);
        let got: Vec<String> = rows
            .iter()
            .map(|r| {
                format!(
                    "{} {} {} {} {} {}",
                    r.name,
                    r.kind,
                    r.to.as_deref().unwrap_or("-"),
                    r.sent_unix,
                    r.expires_unix,
                    r.opened_unix.is_some()
                )
            })
            .collect();
        assert_eq!(
            got,
            [
                "OLD_KEY envelope - 1000 0 false",
                "API_KEY envelope bob 2000 5600 true",
                "DB_PASS link - 3000 6600 true",
            ]
        );
    }

    #[test]
    fn handler_reads_the_chain_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let uid = crate::daemon_store::testkit::uid();
        let lines: Vec<String> = [entry(uid, 5, "share-link", "X", "ok")]
            .iter()
            .map(|e| serde_json::to_string(e).unwrap())
            .collect();
        std::fs::write(&path, lines.join("\n") + "\nnot json\n").unwrap();
        match handle_report(uid, "u", &path) {
            Response::Sharing(SharingResponse::ShareSent { shares }) => {
                assert_eq!(shares.len(), 1);
                assert_eq!(
                    (shares[0].name.as_str(), shares[0].kind.as_str()),
                    ("X", "link")
                );
            }
            other => panic!("{other:?}"),
        }
    }
}
