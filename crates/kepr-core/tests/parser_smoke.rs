// parser_smoke.rs — a stable-toolchain stand-in for the fuzz targets in
// fuzz/fuzz_targets: the same entry points over seeded pseudo-random and
// mutated inputs. Nothing may panic. (Real fuzzing: `cargo +nightly fuzz run`.)

use kepr_core::{http_lite, mysql_wire, recovery_words, shamir, ssh_wire};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn bytes(&mut self, max: usize) -> Vec<u8> {
        let n = (self.next() as usize) % (max + 1);
        (0..n).map(|_| self.next() as u8).collect()
    }
}

fn mutate(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut v = seed.to_vec();
    for _ in 0..1 + rng.next() % 4 {
        if v.is_empty() {
            break;
        }
        let i = (rng.next() as usize) % v.len();
        match rng.next() % 3 {
            0 => v[i] = rng.next() as u8,
            1 => {
                v.remove(i);
            }
            _ => v.insert(i, rng.next() as u8),
        }
    }
    v
}

fn run(data: &[u8]) {
    let mut b = data;
    while ssh_wire::take_string(&mut b).is_some() {}
    let mut b = data;
    let _ = ssh_wire::take_u32(&mut b);
    let mut b = data;
    let _ = mysql_wire::take_lenenc(&mut b);
    let mut b = data;
    let _ = mysql_wire::take_nul(&mut b);
    let _ = mysql_wire::parse_err(data);
    if data.len() >= 4 {
        let _ = mysql_wire::header([data[0], data[1], data[2], data[3]]);
    }
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = ssh_wire::parse_openssh_private(s);
        let _ = ssh_wire::unb64(s);
        let _ = recovery_words::decode(s);
        let _ = shamir::decode(s);
    }
    let mut r = std::io::BufReader::new(data);
    let mut line = String::new();
    let _ = http_lite::read_bounded_line(&mut r, &mut line);
}

#[test]
fn parsers_survive_random_and_mutated_input() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let words = recovery_words::encode(&[7u8; 32]);
    let share = shamir::split(&[1, 2, 3, 4], 2, 3).unwrap();
    let share_text = shamir::encode(&share[0], "ab12");
    let seeds: Vec<Vec<u8>> = vec![
        words.as_bytes().to_vec(),
        share_text.as_bytes().to_vec(),
        b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA\n-----END OPENSSH PRIVATE KEY-----".to_vec(),
        mysql_wire::err_packet(1045, "28000", "denied"),
        b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(),
    ];
    for _ in 0..20_000 {
        run(&rng.bytes(300));
    }
    for seed in &seeds {
        run(seed);
        for _ in 0..4_000 {
            run(&mutate(&mut rng, seed));
        }
    }
}
