// cli_policy/siem.rs — how one audit record looks to a SIEM (T7.14): a
// JSON line, an RFC 5424 syslog line, or an OTLP/HTTP JSON log body.
// A record is op / name / uid / user / result / time / seq / hash: the
// audit chain never holds a value, so nothing here can carry one.

use kepr_core::protocol_policy::AuditRecord;

/// `YYYY-MM-DDTHH:MM:SSZ` (UTC) for a unix timestamp.
pub fn rfc3339(unix: u64) -> String {
    let (days, secs) = (unix / 86_400, unix % 86_400);
    // Civil-from-days (H. Hinnant), valid for every u64 day count we see.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

fn failed(r: &AuditRecord) -> bool {
    r.result != "ok"
}

/// One JSON object per line.
pub fn jsonl(r: &AuditRecord) -> String {
    serde_json::json!({
        "time": rfc3339(r.time),
        "ts": r.time,
        "seq": r.seq,
        "op": r.op,
        "name": r.name,
        "uid": r.uid,
        "user": r.user,
        "result": r.result,
        "hash": r.hash,
    })
    .to_string()
}

/// RFC 5424 PARAM-VALUE escaping: `"`, `\` and `]`.
fn sd_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '"' | '\\' | ']') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// A header field: printable ASCII without spaces, at most `max` long,
/// `-` when empty.
fn header_field(s: &str, max: usize) -> String {
    let f: String = s
        .chars()
        .filter(|c| c.is_ascii_graphic())
        .take(max)
        .collect();
    if f.is_empty() {
        "-".into()
    } else {
        f
    }
}

/// SD-ID enterprise number: 32473 is the one RFC 5612 reserves for
/// documentation and examples; collectors key on the `kepr` name.
const SD_ID: &str = "kepr@32473";

/// `<PRI>1 TIME HOST kepr - MSGID [kepr@32473 …] MSG`, facility authpriv
/// (10), severity info (6) or warning (4) for a failed operation.
pub fn rfc5424(r: &AuditRecord, hostname: &str) -> String {
    let pri = 10 * 8 + if failed(r) { 4 } else { 6 };
    let name = r.name.as_deref().unwrap_or("-");
    let sd = format!(
        "[{SD_ID} op=\"{}\" name=\"{}\" uid=\"{}\" user=\"{}\" result=\"{}\" seq=\"{}\" hash=\"{}\"]",
        sd_escape(&r.op),
        sd_escape(name),
        r.uid,
        sd_escape(&r.user),
        sd_escape(&r.result),
        r.seq,
        sd_escape(&r.hash),
    );
    format!(
        "<{pri}>1 {} {} kepr - {} {sd} {} {} {}",
        rfc3339(r.time),
        header_field(hostname, 255),
        header_field(&r.op, 32),
        r.op,
        name,
        r.result
    )
}

fn attr(key: &str, v: serde_json::Value) -> serde_json::Value {
    let value = match v {
        serde_json::Value::Number(n) => serde_json::json!({ "intValue": n.to_string() }),
        other => serde_json::json!({ "stringValue": other.as_str().unwrap_or_default() }),
    };
    serde_json::json!({ "key": key, "value": value })
}

/// An OTLP/HTTP JSON `ExportLogsServiceRequest` for `POST …/v1/logs`.
pub fn otlp_body(records: &[AuditRecord], hostname: &str) -> String {
    let logs: Vec<serde_json::Value> = records
        .iter()
        .map(|r| {
            let mut attrs = vec![
                attr("kepr.op", r.op.clone().into()),
                attr("kepr.uid", r.uid.into()),
                attr("kepr.user", r.user.clone().into()),
                attr("kepr.result", r.result.clone().into()),
                attr("kepr.seq", r.seq.into()),
                attr("kepr.hash", r.hash.clone().into()),
            ];
            if let Some(n) = &r.name {
                attrs.insert(1, attr("kepr.name", n.clone().into()));
            }
            let (num, text) = if failed(r) { (13, "WARN") } else { (9, "INFO") };
            serde_json::json!({
                "timeUnixNano": (u128::from(r.time) * 1_000_000_000).to_string(),
                "severityNumber": num,
                "severityText": text,
                "body": { "stringValue": format!("{} {} {}", r.op, r.name.as_deref().unwrap_or("-"), r.result) },
                "attributes": attrs,
            })
        })
        .collect();
    serde_json::json!({
        "resourceLogs": [{
            "resource": { "attributes": [
                attr("service.name", "kepr".into()),
                attr("host.name", hostname.into()),
            ]},
            "scopeLogs": [{ "scope": { "name": "kepr.audit" }, "logRecords": logs }],
        }]
    })
    .to_string()
}

/// This machine's name for the syslog header and the OTLP resource.
pub fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

#[cfg(test)]
pub fn record(seq: u64, op: &str, name: Option<&str>, result: &str) -> AuditRecord {
    AuditRecord {
        seq,
        time: 1_791_331_200 + seq,
        op: op.into(),
        name: name.map(String::from),
        uid: 1000,
        user: "alice".into(),
        result: result.into(),
        hash: format!("h{seq}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_dates() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(1_791_331_200 + 3_723), "2026-10-07T01:02:03Z");
    }

    #[test]
    fn rfc5424_line_format() {
        let ok = rfc5424(&record(7, "get", Some("DB_PASS"), "ok"), "host1");
        assert_eq!(
            ok,
            "<86>1 2026-10-07T00:00:07Z host1 kepr - get [kepr@32473 op=\"get\" \
             name=\"DB_PASS\" uid=\"1000\" user=\"alice\" result=\"ok\" seq=\"7\" \
             hash=\"h7\"] get DB_PASS ok"
        );
        let mut r = record(8, "policy-deny", None, "fail: denied by \"rule 2\" ]");
        r.user = String::new();
        let line = rfc5424(&r, "");
        assert!(line.starts_with("<84>1 2026-10-07T00:00:08Z - kepr - policy-deny ["));
        assert!(line.contains("name=\"-\""));
        assert!(line.contains("result=\"fail: denied by \\\"rule 2\\\" \\]\""));
    }

    #[test]
    fn otlp_log_body() {
        let body = otlp_body(
            &[
                record(1, "get", Some("K"), "ok"),
                record(2, "start-gate", None, "fail: x"),
            ],
            "h",
        );
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let rl = &v["resourceLogs"][0];
        assert_eq!(
            rl["resource"]["attributes"][0]["value"]["stringValue"],
            "kepr"
        );
        let logs = &rl["scopeLogs"][0]["logRecords"];
        assert_eq!(logs[0]["timeUnixNano"], "1791331201000000000");
        assert_eq!(logs[0]["severityNumber"], 9);
        assert_eq!(logs[0]["body"]["stringValue"], "get K ok");
        assert_eq!(logs[0]["attributes"][1]["key"], "kepr.name");
        assert_eq!(logs[0]["attributes"][2]["value"]["intValue"], "1000");
        assert_eq!(logs[1]["severityText"], "WARN");
        assert!(logs[1]["attributes"]
            .as_array()
            .unwrap()
            .iter()
            .all(|a| a["key"] != "kepr.name"));
    }

    #[test]
    fn jsonl_has_the_record_fields() {
        let v: serde_json::Value =
            serde_json::from_str(&jsonl(&record(3, "set", Some("K"), "ok"))).unwrap();
        assert_eq!(v["time"], "2026-10-07T00:00:03Z");
        assert_eq!(v["op"], "set");
        assert_eq!(v["hash"], "h3");
    }
}
