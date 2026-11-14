use crate::policy::{Ctx, Decision, Effect, PolicyFile};

impl PolicyFile {
    /// Run the `[[test]]` cases: `(passed, one line per case)`.
    pub fn run_tests(&self) -> (bool, Vec<String>) {
        let mut all = true;
        let mut lines = Vec::new();
        for (i, t) in self.tests.iter().enumerate() {
            let name = t.name.to_ascii_uppercase();
            let ctx = Ctx {
                op: &t.op,
                name: &name,
                exe: t.exe.as_deref(),
                parent: t.parent.as_deref(),
                harness: t.harness.as_deref(),
                roles: &t.roles,
                hosts: &t.hosts,
                ttl: t.ttl,
            };
            let got = self.check(&ctx);
            let pass = got.allowed() == (t.expect == Effect::Allow);
            all &= pass;
            let who = [
                ("exe", &t.exe),
                ("parent", &t.parent),
                ("harness", &t.harness),
            ]
            .iter()
            .filter_map(|(k, v)| v.as_ref().map(|v| format!(" {k}={v}")))
            .collect::<String>();
            let verdict = match &got {
                Decision::Allow(n) => format!("allow (rule {n})"),
                Decision::Deny(_, why) => format!("deny ({why})"),
            };
            let expect = match t.expect {
                Effect::Allow => "allow",
                Effect::Deny => "deny",
            };
            lines.push(match pass {
                true => format!("ok    test {}: {} {name}{who} -> {verdict}", i + 1, t.op),
                false => format!(
                    "FAIL  test {}: {} {name}{who} -> {verdict}, expected {expect}",
                    i + 1,
                    t.op
                ),
            });
        }
        (all, lines)
    }
}
