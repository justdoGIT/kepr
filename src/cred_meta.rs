// cred_meta.rs — the `.meta` sidecar record. Split out of expiry.rs
// (2026-10-05) so the P2–P11 ticket batches have room for new fields;
// the read/write helpers and `impl CredMeta` stay in expiry.rs, which
// re-exports these types.

/// On-disk record. Every field is `Option<…>` with `#[serde(default)]`
/// so meta files written by older daemons parse cleanly under newer
/// ones. Empty `CredMeta` is equivalent to "no flags" (callers should
/// skip writing the meta file in that case).
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct CredMeta {
    /// Absolute unix timestamp (seconds since epoch) at which this
    /// credential expires. The daemon refuses to decrypt past this
    /// instant. Phase 2 α.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub expires_at_unix: Option<u64>,
    /// True iff `kepr get` requires a polkit consent prompt before
    /// the daemon decrypts. Phase 2 ε.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub requires_consent: Option<bool>,
    /// True iff `kepr get` requires a FIDO2 hardware-key assertion
    /// before the daemon decrypts. Phase 2 η.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub requires_fido2: Option<bool>,
    /// True iff the value is write-only: `Get` is refused and only a
    /// daemon-spawned kepr-gate may resolve it, for a host listed in
    /// `bindings`. Agent vault plan §4.3.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sealed: Option<bool>,
    /// Destinations a sealed value may be sent to.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub bindings: Option<Vec<kepr_core::binding::Binding>>,
    /// P2.4: the value is an Ed25519 SSH key seed. Like `sealed`, `Get`
    /// refuses it; the daemon only signs with it (`SshSign`).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ssh: Option<SshMeta>,
    /// P5.1: the value is a typed record of this type (login, card, …).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub record_type: Option<String>,
    /// P6.1: the value is this user's X25519 share key; `Get` refuses it.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub share_key: Option<bool>,
    // ── P2–P11 ticket batches: new fields go under the batch's marker,
    // each `#[serde(skip_serializing_if = "Option::is_none", default)]`.
    // batch: vault
    // batch: seal
    // batch: store
    /// T5.01: tags (`[a-z0-9_-]{1,32}`, at most 16) and a `/`-separated
    /// folder. Organisation only; kept across `set`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub folder: Option<String>,
    /// T11.2: on a trash entry (`NAME~t<unix>`): when it was deleted.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub trashed_at: Option<u64>,
    /// T11.5: this name is an alias of that credential (no value file).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub alias_of: Option<String>,
    // batch: records
    /// T5.03: attachment manifest; chunks are `NAME~a<id>~<n>` values.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub attachments: Option<Vec<kepr_core::protocol_records::AttachInfo>>,
    /// T11.23: `kepr health` finding kinds the owner ignores; a new value
    /// starts without (handle_set does not carry it over).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub health_ignore: Option<Vec<String>>,
    // batch: share
    /// T6.05: delete this record (and its history) once the one-time
    /// link with this id is opened or expires. A new `set` drops it.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub self_destruct_share: Option<String>,
    /// T11.15: a received share with a view window. The first `get`
    /// turns it into `expires_at_unix` = then + this, and clears it.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub view_window_secs: Option<u64>,
    /// T6.07: the value was revealed by break-glass; rotate it. The next
    /// `set` drops it (handle_set doesn't carry it over).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub must_rotate: Option<bool>,
    // batch: sync
    // batch: policy
    /// T9.04: consent prompts for this credential may be answered by the
    /// registered approver (`kepr approvals serve`): desktop | ntfy | any.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub approve_via: Option<String>,
    /// T9.08: the value is a decoy (`kepr canary plant`): reading it,
    /// or a gate seeing it, raises the alarm; gates never release it.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub canary: Option<crate::daemon_policy::CanaryMeta>,
    // batch: gate
    // batch: aws
    // batch: eco
    // batch: platform
    /// T10.09: identities (`kepr_core::exe_digest`) of the executables
    /// allowed to read the value through `Get`. Kept across `set`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub exe_digests: Option<Vec<String>>,
    // batch: session
    /// T11.14: `get` / `copy` / `record show --reveal` need the store
    /// passphrase again (a 60 s window per credential). Kept across `set`;
    /// only an open window may clear it.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub requires_reauth: Option<bool>,
    // end of batches
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct SshMeta {
    /// Public key blob, base64 (not secret).
    pub public_b64: String,
    pub comment: String,
}
