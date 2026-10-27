// health_score.rs — the overall `kepr health` score: 100 minus a weight per
// finding kind for each credential (floor 0), averaged over the credentials.
// Ignored findings (T11.23) do not count. Computed here from the daemon's
// flags, so no value and no extra request is involved.

use kepr_core::health_policy::finding_kind;
use kepr_core::protocol::KeyHealth;

fn weight(kind: &str) -> u32 {
    match kind {
        "breached" => 60,
        "common" => 50,
        "weak" => 40,
        "reused" | "expired" => 30,
        "short" | "cert" => 20,
        "old" | "policy" => 15,
        _ => 0,
    }
}

/// One credential's score, 0-100.
pub fn item_score(item: &KeyHealth) -> u32 {
    let penalty: u32 = item.issues.iter().map(|i| weight(finding_kind(i))).sum();
    100u32.saturating_sub(penalty)
}

/// The overall score, 0-100 (100 when there are no credentials).
pub fn overall(items: &[KeyHealth]) -> u32 {
    if items.is_empty() {
        return 100;
    }
    let total: u32 = items.iter().map(item_score).sum();
    (total + items.len() as u32 / 2) / items.len() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(issues: &[&str]) -> KeyHealth {
        KeyHealth {
            name: "X".into(),
            issues: issues.iter().map(|s| s.to_string()).collect(),
            age_days: 0,
            hibp_prefix: None,
            ignored: vec!["weak".into()],
            ignore: vec![],
        }
    }

    #[test]
    fn findings_cost_points_and_floor_at_zero() {
        assert_eq!(item_score(&item(&[])), 100);
        assert_eq!(item_score(&item(&["not changed in 400 days"])), 85);
        assert_eq!(
            item_score(&item(&["weak (low entropy)", "found in a data breach"])),
            0
        );
        assert_eq!(item_score(&item(&["unreadable"])), 100);
    }

    #[test]
    fn overall_averages_and_handles_none() {
        assert_eq!(overall(&[]), 100);
        let items = [item(&[]), item(&["same value as A"])];
        assert_eq!(overall(&items), 85);
    }

    #[test]
    fn no_2fa_finding_counts_as_policy() {
        assert_eq!(
            item_score(&item(&["policy: no 2FA (totp) secret stored"])),
            85
        );
    }
}
