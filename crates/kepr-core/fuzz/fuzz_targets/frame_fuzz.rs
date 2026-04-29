// Fuzz target: kepr_core::framing::read_frame
//
// read_frame parses an attacker-controlled byte stream over the daemon's
// Unix socket: a u32 little-endian length prefix followed by `length`
// payload bytes, bounded by MAX_MSG_BYTES. A malformed or truncated
// frame must return an error — never panic, never block, never read
// beyond the declared length.
//
// libfuzzer feeds arbitrary `&[u8]` slices wrapped in std::io::Cursor
// and asserts the call terminates without panic. AFL-style coverage
// guidance steers the mutator toward inputs that exercise the bounds
// check, the truncated-payload path, and the maximum-length boundary.
//
// Run with:
//   cd crates/kepr-core
//   cargo +nightly fuzz run frame_fuzz -- -max_total_time=60

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

use kepr_core::framing::read_frame;
use kepr_core::protocol::MAX_MSG_BYTES;

fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    let _ = read_frame(&mut cursor, MAX_MSG_BYTES);
});
