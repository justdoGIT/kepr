// Fuzz target: OpenSSH wire strings, base64 and the unencrypted private-key parser.
//
// Must return, never panic. Run with:
//   cd crates/kepr-core
//   cargo +nightly fuzz run ssh_wire_fuzz -- -max_total_time=60

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut b = data;
    while kepr_core::ssh_wire::take_string(&mut b).is_some() {}
    let mut b = data;
    let _ = kepr_core::ssh_wire::take_u32(&mut b);
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = kepr_core::ssh_wire::parse_openssh_private(s);
        let _ = kepr_core::ssh_wire::unb64(s);
    }
});
