// Fuzz target: MySQL packet parsing helpers.
//
// Must return, never panic. Run with:
//   cd crates/kepr-core
//   cargo +nightly fuzz run mysql_wire_fuzz -- -max_total_time=60

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut b = data;
    let _ = kepr_core::mysql_wire::take_lenenc(&mut b);
    let mut b = data;
    let _ = kepr_core::mysql_wire::take_nul(&mut b);
    let _ = kepr_core::mysql_wire::parse_err(data);
    if data.len() >= 4 {
        let _ = kepr_core::mysql_wire::header([data[0], data[1], data[2], data[3]]);
    }
});
