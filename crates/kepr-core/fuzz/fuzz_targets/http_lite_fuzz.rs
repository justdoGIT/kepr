// Fuzz target: bounded HTTP line reading.
//
// Must return, never panic. Run with:
//   cd crates/kepr-core
//   cargo +nightly fuzz run http_lite_fuzz -- -max_total_time=60

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut r = std::io::BufReader::new(data);
    let mut line = String::new();
    let _ = kepr_core::http_lite::read_bounded_line(&mut r, &mut line);
});
