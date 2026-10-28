// Fuzz target: recovery words decoding.
//
// Must return, never panic. Run with:
//   cd crates/kepr-core
//   cargo +nightly fuzz run recovery_words_fuzz -- -max_total_time=60

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = kepr_core::recovery_words::decode(s);
    }
});
