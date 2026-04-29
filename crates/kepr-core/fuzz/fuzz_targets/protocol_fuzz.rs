// Fuzz target: serde_json deserialisation into kepr_core::protocol::Request
//
// The daemon's accept loop reads a frame and runs
// `serde_json::from_slice::<Request>(&buf)` on the payload (see
// kepr-daemon's handle_client). The wire frame is attacker-controlled
// up to MAX_MSG_BYTES; any panic in the deserialiser is a denial-of-
// service vector against the bounded worker pool.
//
// libfuzzer feeds arbitrary bytes; the target asserts deserialisation
// returns Ok or a serde Error — never panics, never recurses without
// bound. Inputs that almost-parse (valid JSON shape, wrong tag, deep
// nesting, oversized strings, control chars in field names) get the
// most coverage feedback under libfuzzer's mutator.
//
// Run with:
//   cd crates/kepr-core
//   cargo +nightly fuzz run protocol_fuzz -- -max_total_time=60

#![no_main]

use libfuzzer_sys::fuzz_target;

use kepr_core::protocol::Request;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<Request>(data);
});
