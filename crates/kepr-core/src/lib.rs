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
pub mod framing;
pub mod generate;
pub mod memfd;
pub mod protocol;
