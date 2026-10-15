// Benchmarks for the hot paths in kepr-core: the daemon's wire framing and
// request decoding, the leak scanner used by the gate's DLP and `kepr scan`,
// SigV4 signing, policy evaluation, recovery shares and strength estimates.
//
// Run locally with `cargo bench -p kepr-core`, or under CodSpeed with
// `cargo codspeed build -p kepr-core && cargo codspeed run -p kepr-core`.

use divan::{black_box, Bencher};
use kepr_core::framing::{read_frame, write_frame};
use kepr_core::generate::ZeroString;
use kepr_core::policy::{Ctx, PolicyFile};
use kepr_core::protocol::{Request, MAX_MSG_BYTES};
use kepr_core::sigv4::{self, SigV4Input};
use kepr_core::{leak, recovery_words, shamir, strength};

fn main() {
    divan::main();
}

// ── Wire protocol ────────────────────────────────────────────────────────────

mod protocol {
    use super::*;

    const GET: &[u8] = br#"{"cmd":"get","name":"OPENAI_API_KEY"}"#;
    const SET: &[u8] =
        br#"{"cmd":"set","name":"DATABASE_URL","value":"postgres://user:pass@db.internal:5432/app","ttl_secs":3600}"#;

    #[divan::bench]
    fn parse_get_request() -> Request {
        serde_json::from_slice(black_box(GET)).unwrap()
    }

    #[divan::bench]
    fn parse_set_request() -> Request {
        serde_json::from_slice(black_box(SET)).unwrap()
    }

    #[divan::bench(args = [64, 4096, 60_000])]
    fn frame_roundtrip(bencher: Bencher, size: usize) {
        let payload = vec![b'x'; size];
        bencher.bench_local(|| {
            let mut buf = Vec::with_capacity(size + 4);
            write_frame(&mut buf, black_box(&payload)).unwrap();
            read_frame(&mut buf.as_slice(), MAX_MSG_BYTES).unwrap()
        });
    }
}

// ── Leak scanner ─────────────────────────────────────────────────────────────

mod leak_scan {
    use super::*;

    /// A log/config-like blob of `lines` lines with a key every 50 lines.
    fn corpus(lines: usize) -> Vec<u8> {
        let mut s = String::new();
        for i in 0..lines {
            if i % 50 == 25 {
                s.push_str("export ANTHROPIC_API_KEY=sk-ant-api03-");
                s.push_str(&"aB3dE5fG7hJ9kL1mN".repeat(5));
                s.push('\n');
            } else {
                s.push_str("2026-10-15T12:00:00Z INFO request handled path=/v1/items status=200\n");
            }
        }
        s.into_bytes()
    }

    #[divan::bench(args = [100, 10_000])]
    fn find_all(bencher: Bencher, lines: usize) {
        let text = corpus(lines);
        bencher.bench_local(|| leak::find_all(black_box(&text)));
    }

    #[divan::bench]
    fn canary_probes(bencher: Bencher) {
        let text = corpus(500);
        bencher.bench_local(|| leak::canary_probes(black_box(&[text.as_slice()])));
    }
}

// ── AWS SigV4 ────────────────────────────────────────────────────────────────

mod sigv4_sign {
    use super::*;

    #[divan::bench(args = [128, 16_384])]
    fn sign(bencher: Bencher, body_len: usize) {
        let secret = ZeroString::from("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
        let body = vec![b'{'; body_len];
        let amz_date = sigv4::format_amz_date(1_760_000_000);
        bencher.bench_local(|| {
            let input = SigV4Input {
                access_key: "AKIDEXAMPLE",
                secret_key: &secret,
                region: "us-east-1",
                service: "secretsmanager",
                session_token: None,
                method: "POST",
                host: "secretsmanager.us-east-1.amazonaws.com",
                path: "/",
                query: "",
                amz_target: "secretsmanager.GetSecretValue",
                body: black_box(&body),
                amz_date: &amz_date,
            };
            sigv4::sign(&input)
        });
    }
}

// ── Policy evaluation ────────────────────────────────────────────────────────

mod policy {
    use super::*;

    fn policy_file() -> PolicyFile {
        let mut rules = Vec::new();
        for i in 0..30 {
            rules.push(serde_json::json!({
                "effect": "deny",
                "ops": ["export", "share"],
                "names": [format!("TEAM{i}_*")],
                "exe": ["/usr/bin/curl*"],
            }));
        }
        rules.push(serde_json::json!({
            "effect": "allow",
            "ops": ["get", "exec"],
            "names": ["PROD_*_TOKEN", "STAGING_*"],
            "exe": ["/usr/local/bin/*", "/home/*/bin/deploy"],
        }));
        serde_json::from_value(serde_json::json!({ "rule": rules })).unwrap()
    }

    #[divan::bench]
    fn check(bencher: Bencher) {
        let p = policy_file();
        let hosts: Vec<String> = Vec::new();
        bencher.bench_local(|| {
            let ctx = Ctx {
                op: "get",
                name: black_box("PROD_PAYMENTS_TOKEN"),
                exe: Some("/home/alice/bin/deploy"),
                parent: Some("/bin/bash"),
                harness: None,
                hosts: &hosts,
                ttl: None,
            };
            p.check(&ctx)
        });
    }

    #[divan::bench]
    fn glob() -> bool {
        kepr_core::policy::glob(
            black_box("/home/*/projects/*/target/release/*"),
            black_box("/home/alice/projects/kepr/target/release/kepr-daemon"),
        )
    }
}

// ── Recovery kit ─────────────────────────────────────────────────────────────

mod recovery {
    use super::*;

    const KEY: [u8; 32] = [
        0x4b, 0x65, 0x70, 0x72, 0x20, 0x6d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x20, 0x6b, 0x65, 0x79,
        0x20, 0x62, 0x65, 0x6e, 0x63, 0x68, 0x6d, 0x61, 0x72, 0x6b, 0x20, 0x76, 0x61, 0x6c, 0x75,
        0x65, 0x21,
    ];

    #[divan::bench]
    fn shamir_split_3_of_5() -> Vec<shamir::Share> {
        shamir::split(black_box(&KEY), 3, 5).unwrap()
    }

    #[divan::bench]
    fn shamir_combine_3_of_5(bencher: Bencher) {
        let shares = shamir::split(&KEY, 3, 5).unwrap();
        let subset = &shares[1..4];
        bencher.bench_local(|| shamir::combine(black_box(subset)).unwrap());
    }

    #[divan::bench]
    fn words_encode(bencher: Bencher) {
        // Warm the lazily built wordlist so it is not measured.
        recovery_words::encode(&KEY);
        bencher.bench_local(|| recovery_words::encode(black_box(&KEY)));
    }

    #[divan::bench]
    fn words_decode(bencher: Bencher) {
        let words = recovery_words::encode(&KEY);
        bencher.bench_local(|| recovery_words::decode(black_box(words.as_str())).unwrap());
    }
}

// ── Strength estimate ────────────────────────────────────────────────────────

mod strength_estimate {
    use super::*;

    #[divan::bench(args = ["hunter2", "Tr0ub4dor&3", "correct horse battery staple"])]
    fn estimate(bencher: Bencher, value: &str) {
        // Warm the lazily built wordlist set so it is not measured.
        strength::estimate(value);
        bencher.bench_local(|| strength::estimate(black_box(value)));
    }
}
