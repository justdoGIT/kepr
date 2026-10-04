// cli_mask.rs — `kepr exec --mask` (agent vault T9.03). Runs the child
// with piped stdout/stderr and replaces every occurrence of a provided
// secret with `****` before it reaches our own stdout/stderr, so a
// command that echoes a key can't leak it into an agent's context or a
// log. Without --mask, `kepr exec` keeps using execvp (no filtering).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::process::{Command, Stdio};

use kepr_core::generate::ZeroString;
use kepr_core::protocol::Response;

const MASK: &[u8] = b"****";

pub struct Masker {
    secrets: Vec<ZeroString>,
    carry: Vec<u8>,
}

impl Masker {
    pub fn new(secrets: Vec<ZeroString>) -> Self {
        let mut secrets: Vec<ZeroString> = secrets
            .into_iter()
            .filter(|s| !s.as_str().is_empty())
            .collect();
        // Longest first: if one secret is a prefix of another, the longer
        // must win or its tail would be printed.
        secrets.sort_by_key(|s| std::cmp::Reverse(s.as_str().len()));
        Self {
            secrets,
            carry: Vec::new(),
        }
    }

    /// Length of the longest suffix of `carry` that is a proper prefix of
    /// some secret: only those bytes might still turn into a secret.
    fn pending_len(&self) -> usize {
        let c = &self.carry;
        self.secrets
            .iter()
            .map(|s| {
                let s = s.as_str().as_bytes();
                (1..s.len().min(c.len() + 1))
                    .rev()
                    .find(|&k| c.ends_with(&s[..k]))
                    .unwrap_or(0)
            })
            .max()
            .unwrap_or(0)
    }

    /// Bytes safe to emit now. Holds back only a trailing partial match
    /// of a secret, so a secret split across two reads is still caught
    /// while ordinary output (e.g. a `Password: ` prompt) appears at once.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.carry.extend_from_slice(chunk);
        let keep = self.pending_len();
        let (out, used) = self.mask_prefix(self.carry.len() - keep);
        self.carry.drain(..used);
        out
    }

    /// Mask the first `limit` bytes of carry, extending a match that
    /// starts before `limit` to its full length. Returns (output, bytes
    /// consumed from carry).
    fn mask_prefix(&self, limit: usize) -> (Vec<u8>, usize) {
        let buf = &self.carry;
        let mut out = Vec::with_capacity(limit);
        let mut i = 0;
        'outer: while i < limit {
            for s in &self.secrets {
                let n = s.as_str().as_bytes();
                if buf[i..].starts_with(n) {
                    out.extend_from_slice(MASK);
                    i += n.len();
                    continue 'outer;
                }
            }
            out.push(buf[i]);
            i += 1;
        }
        (out, i)
    }

    pub fn finish(&mut self) -> Vec<u8> {
        let (out, _) = self.mask_prefix(self.carry.len());
        self.carry.clear();
        out
    }
}

fn pump(mut from: impl Read, mut to: impl Write, mut m: Masker) {
    let mut buf = [0u8; 8192];
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let out = m.feed(&buf[..n]);
                if to.write_all(&out).and_then(|_| to.flush()).is_err() {
                    return;
                }
            }
        }
    }
    let _ = to.write_all(&m.finish());
    let _ = to.flush();
}

fn dup_secrets(env: &HashMap<String, String>, names: &[String]) -> Vec<ZeroString> {
    names
        .iter()
        .filter_map(|n| env.get(n))
        .map(|v| ZeroString::from_string(v.clone()))
        .collect()
}

/// Spawn `argv` with `env` merged in, mask `secret_names`' values in its
/// output, and exit with the child's status. Returns only on failure.
pub fn run_masked(
    env: HashMap<String, String>,
    secret_names: &[String],
    argv: &[String],
) -> Response {
    if argv.is_empty() {
        return Response::fail("missing command after `--`");
    }
    let mut child = match Command::new(&argv[0])
        .args(&argv[1..])
        .envs(&env)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return Response::fail(format!("exec failed: {e}")),
    };
    let (out, err) = (child.stdout.take(), child.stderr.take());
    let (m1, m2) = (
        Masker::new(dup_secrets(&env, secret_names)),
        Masker::new(dup_secrets(&env, secret_names)),
    );
    drop(env);
    let t1 = out.map(|o| std::thread::spawn(move || pump(o, std::io::stdout(), m1)));
    let t2 = err.map(|e| std::thread::spawn(move || pump(e, std::io::stderr(), m2)));
    let status = child.wait();
    for t in [t1, t2].into_iter().flatten() {
        let _ = t.join();
    }
    match status {
        Ok(s) => std::process::exit(s.code().unwrap_or(1)),
        Err(e) => Response::fail(format!("wait failed: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(secrets: &[&str]) -> Masker {
        Masker::new(
            secrets
                .iter()
                .map(|s| ZeroString::from_string(s.to_string()))
                .collect(),
        )
    }

    fn run(mk: &mut Masker, chunks: &[&[u8]]) -> String {
        let mut out = Vec::new();
        for c in chunks {
            out.extend(mk.feed(c));
        }
        out.extend(mk.finish());
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn whole_split_multiple_and_none() {
        assert_eq!(run(&mut m(&["s3cret"]), &[b"key=s3cret ok"]), "key=**** ok");
        assert_eq!(
            run(&mut m(&["s3cret"]), &[b"key=s3c", b"ret ok"]),
            "key=**** ok"
        );
        assert_eq!(
            run(&mut m(&["aaaa", "bbbbbb"]), &[b"x aaaa y bbbb", b"bb z"]),
            "x **** y **** z"
        );
        assert_eq!(
            run(&mut m(&["s3cret"]), &[b"nothing ", b"here"]),
            "nothing here"
        );
        assert_eq!(run(&mut m(&[]), &[b"plain"]), "plain");
    }

    #[test]
    fn holds_back_only_partial_matches() {
        let mut mk = m(&["longsecret"]);
        assert_eq!(
            mk.feed(b"Password: "),
            b"Password: ",
            "prompt is not delayed"
        );
        assert_eq!(
            mk.feed(b"abc lon"),
            b"abc ",
            "possible start of a secret is held"
        );
        assert_eq!(mk.finish(), b"lon");
    }

    #[test]
    fn longer_secret_wins_over_its_prefix() {
        assert_eq!(
            run(
                &mut m(&["abcd1234", "abcd1234XYZsecret"]),
                &[b"v=abcd1234XYZsecret!"]
            ),
            "v=****!"
        );
    }

    #[test]
    fn secret_split_byte_by_byte() {
        let mut mk = m(&["topsecret"]);
        let input = b"a topsecret b";
        let chunks: Vec<&[u8]> = input.chunks(1).collect();
        assert_eq!(run(&mut mk, &chunks), "a **** b");
    }
}
