//! Shared types and helpers for the kepr CLI and daemon.
//!
//! This crate exposes the wire protocol (`protocol`), the
//! length-prefixed frame format (`framing`), and the `ZeroString`
//! primitive plus secret-generator (`generate`). It contains no
//! IO logic beyond the `read_frame` / `write_frame` helpers, and
//! deliberately has zero knowledge of `systemd-creds`, the daemon
//! cache, or the credential store layout — those live in the
//! daemon binary so that future out-of-tree consumers (the
//! forthcoming `docker-credential-kepr`, the External Secrets
//! Operator provider, language bindings) can depend on this crate
//! without pulling in root-only privileges.

pub mod auth;
pub mod binding;
pub mod fdpass;
pub mod framing;
pub mod gate_protocol;
pub mod generate;
pub mod keyring;
pub mod leak;
pub mod memfd;
pub mod protocol;
pub mod protocol_response;
pub mod protocol_types;
pub mod providers;
pub mod secmem;
pub mod shamir;
pub mod sigv4;
pub mod ssh_wire;

// ── P2–P11 ticket batches (2026-10-05): `protocol_<batch>` and other
// shared modules, declared under each batch's marker.
// batch: vault
pub mod protocol_vault;
// batch: seal
pub mod protocol_seal;
pub mod recovery_words;
pub mod seal_factor;
// batch: store
pub mod protocol_store;
// batch: records
pub mod generate_profile;
pub mod health_policy;
pub mod protocol_records;
pub mod record_types;
pub mod strength;
// batch: share
pub mod protocol_sharing;
pub mod protocol_sharing_types;
// batch: sync
pub mod protocol_syncx;
// batch: policy
pub mod policy;
pub mod protocol_policy;
// batch: gate
pub mod gate_journal;
pub mod gate_record;
pub mod mysql_handshake;
pub mod mysql_wire;
pub mod protocol_gatex;
// batch: aws
pub mod github_app;
pub mod sigv4_req;
// batch: eco
pub mod protocol_eco;
// batch: platform
// batch: session
pub mod http_lite;
pub mod profile;
pub mod protocol_session;
// end of batches
