/// Split inherited variables into those passed on and the names of those
/// withheld because their value looks like a real API key or private key
/// (an `OPENAI_API_KEY` exported in ~/.bashrc must not reach a Claude
/// session just because Claude doesn't use it).
pub fn keep_safe_env(
    vars: impl Iterator<Item = (String, String)>,
) -> (Vec<(String, String)>, Vec<String>) {
    let (mut keep, mut withheld) = (Vec::new(), Vec::new());
    for (k, v) in vars {
        if kepr_core::leak::looks_like_key(v.as_bytes()) {
            withheld.push(k);
        } else {
            keep.push((k, v));
        }
    }
    withheld.sort();
    (keep, withheld)
}
