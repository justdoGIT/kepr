// Fuzz target: the private daemon <-> gate messages and the session
// config the gate reads from stdin.
//
// Must return, never panic. Run with:
//   cd crates/kepr-core
//   cargo +nightly fuzz run gate_protocol_fuzz -- -max_total_time=60

#![no_main]

use libfuzzer_sys::fuzz_target;

use kepr_core::gate_protocol::{GateRequest, GateResponse, ReadyLine, SessionConfig};

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<GateRequest>(data);
    let _ = serde_json::from_slice::<GateResponse>(data);
    let _ = serde_json::from_slice::<SessionConfig>(data);
    let _ = serde_json::from_slice::<ReadyLine>(data);
});
