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
// batch: seal
// batch: store
// batch: records
// batch: share
// batch: sync
// batch: policy
// batch: gate
// batch: aws
// batch: eco
// batch: platform
// batch: session
// end of batches
