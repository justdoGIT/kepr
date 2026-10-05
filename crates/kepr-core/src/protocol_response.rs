// protocol_response.rs — the daemon's reply type. Split out of
// protocol.rs (LOC limit) along the request/response line; re-exported
// from there, so callers keep using `kepr_core::protocol::Response`.

use crate::generate::ZeroString;
use crate::protocol_types::{
    CredInfo, Fido2CredInfo, HistoryEntry, KeyHealth, KeyUsage, SshKeyInfo,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Response ──────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Response {
    SetOk {
        name: String,
        cred_name: String,
        /// Whether the master key is Argon2id-wrapped at the time of this
        /// write. Carried on the response so the CLI can warn about an
        /// un-wrapped key without a second `Request::Status` round-trip.
        password_protected: bool,
    },
    /// Reply to `StartGate`: where the gate listens and the session
    /// placeholders (credential NAME → placeholder; not secrets).
    GateStarted {
        port: u16,
        placeholders: HashMap<String, String>,
        gate_pid: i32,
        /// Egress CA and database ports; boxed to keep `Response` small,
        /// flattened so the wire format is unchanged.
        #[serde(flatten)]
        extras: Box<crate::protocol_types::GateExtras>,
    },
    GetOk {
        name: String,
        // ZeroString rather than String so the deserialised secret on
        // the client side is wiped from memory when the Response is
        // dropped, instead of leaking through serde's allocation pool
        // until the GC happens to overwrite the heap region. Wire
        // format unchanged (still a JSON string); old daemons / new
        // clients and vice versa interoperate.
        value: ZeroString,
    },
    DeleteOk {
        name: String,
    },
    ListOk {
        credentials: Vec<CredInfo>,
        count: usize,
    },
    CheckOk {
        results: HashMap<String, String>,
        count: usize,
        all_ok: bool,
    },
    /// Phase 2 δ.3 — successful audit-chain verification. `entries`
    /// is the count of validated chain entries; `last_hash` is the
    /// hex-encoded head, intended for external attestation against
    /// a checkpoint store (Phase 3 Sigstore Rekor anchor).
    AuditOk {
        entries: usize,
        last_hash: String,
    },
    /// Phase 2 η: a FIDO2 assertion is required to decrypt this
    /// credential. The client should obtain an assertion from the
    /// FIDO2 authenticator identified by `credential_ids` over
    /// `challenge`, then retry `Get` with `fido2_assertion` set.
    Fido2Needed {
        name: String,
        /// 32 random bytes, hex-encoded. The client must include
        /// this challenge verbatim in the `clientDataJSON` passed
        /// to the authenticator.
        challenge: String,
        /// The credential IDs registered for this user whose
        /// associated public keys the daemon can verify. The
        /// client picks one that the user's authenticator holds.
        credential_ids: Vec<String>, // hex
    },
    /// Phase 2 η: successful FIDO2 registration. The daemon echoes
    /// the credential ID it stored.
    Fido2RegisterOk {
        credential_id: String,
    },
    /// Phase 2 η: list of registered FIDO2 credentials.
    Fido2ListOk {
        credentials: Vec<Fido2CredInfo>,
    },
    Pong,
    PanicOk {
        gates_stopped: usize,
        locked: bool,
    },
    SshKeyOk {
        name: String,
        /// `ssh-ed25519 AAAA… comment`
        public_line: String,
    },
    SshListOk {
        keys: Vec<SshKeyInfo>,
    },
    /// OpenSSH signature blob (`string "ssh-ed25519" || string sig`), base64.
    SshSignOk {
        signature_b64: String,
    },
    HistoryOk {
        name: String,
        versions: Vec<HistoryEntry>,
    },
    RestoreOk {
        name: String,
        version: u32,
    },
    UsageOk {
        /// Window start (`YYYY-MM-DD HH:MM` UTC); absent = all time.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        since: Option<String>,
        /// False if the audit chain failed verification.
        chain_intact: bool,
        gate_sessions: u64,
        keys: Vec<KeyUsage>,
    },
    HealthOk {
        items: Vec<KeyHealth>,
    },
    BreachOk {
        name: String,
        breached: bool,
    },
    ShareKeyOk {
        /// `kepr-pub1-…`, safe to publish.
        public: String,
    },
    ShareOk {
        /// `kepr-share1-…`; readable only by the recipient.
        envelope: String,
        expires_at: String,
    },
    DbRotateOk {
        name: String,
        phase: String,
    },
    RecoveryKitOk {
        fingerprint: String,
        shares: Vec<ZeroString>,
    },
    RecoveryRestoreOk {
        fingerprint: String,
        credentials_opened: usize,
    },
    LeakedOk {
        name: String,
        gates_stopped: usize,
        /// Hosts the credential was bound to (to find where to revoke it).
        hosts: Vec<String>,
    },
    LockedOk,
    UnlockedOk,
    StatusOk {
        locked: bool,
        password_protected: bool,
    },
    Err {
        error: String,
    },
    // ── P2–P11 ticket batches: one `#[serde(untagged)]` variant per batch
    // (that batch's `#[serde(tag = "kind")]` enum). Untagged variants last.
    // batch: vault
    // batch: seal
    // batch: store
    #[serde(untagged)]
    Store(crate::protocol_store::StoreResponse),
    // batch: records
    // batch: share
    #[serde(untagged)]
    Sharing(crate::protocol_sharing::SharingResponse),
    // batch: sync
    // batch: policy
    // batch: gate
    // batch: aws
    // batch: eco
    #[serde(untagged)]
    Eco(crate::protocol_eco::EcoResponse),
    // batch: platform
    // batch: session
    // end of batches
}

impl Response {
    /// Transport-level success (request was understood and not rejected).
    /// A CheckOk with `all_ok=false` is still transport-ok.
    #[allow(dead_code)]
    pub fn is_transport_ok(&self) -> bool {
        !matches!(self, Response::Err { .. })
    }

    /// Semantic success — used for the CLI's exit code.
    /// False for any Err and for CheckOk with a failing credential.
    pub fn is_success(&self) -> bool {
        match self {
            Response::Err { .. } => false,
            Response::CheckOk { all_ok, .. } => *all_ok,
            _ => true,
        }
    }

    #[allow(dead_code)]
    pub fn err_msg(&self) -> Option<&str> {
        if let Response::Err { error } = self {
            Some(error)
        } else {
            None
        }
    }

    /// Convenience constructor used throughout the codebase.
    pub fn fail(msg: impl Into<String>) -> Self {
        Response::Err { error: msg.into() }
    }
}
