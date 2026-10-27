// cli_recordsx/stages.rs — the `[env]` tables of `.kepr.toml`
// (cli_manifest.rs): T5.06 `map` references and T5.02 stages.
//
//   [env]
//   required = ["API_KEY"]
//   [env.map]
//   LOG_TOKEN = "kepr://LOGS/token"
//   [env.dev]
//   required = ["DEV_DB_PASS"]
//   [env.dev.map]
//   DATABASE_URL = "kepr://DEV_DB/url"
//
// `kepr exec --stage dev` (default: $KEPR_STAGE) provisions the base set
// plus the stage's: names are merged, and a stage's `map` entry replaces
// a base entry or plain name for the same variable.

use std::collections::BTreeMap;

/// One `[env]` or `[env.<stage>]` table.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct EnvSet {
    /// Credential names, provisioned as $NAME.
    pub required: Vec<String>,
    /// `VAR=kepr://…` entries, checked at load.
    pub map: Vec<String>,
}

fn map_entries(v: &toml::Value, at: &str) -> Result<Vec<String>, String> {
    let t = v
        .as_table()
        .ok_or_else(|| format!("`{at}` must be a table of VAR = \"kepr://…\""))?;
    t.iter()
        .map(|(var, r)| {
            let r = r
                .as_str()
                .ok_or_else(|| format!("`{at}` {var}: the value must be a kepr:// string"))?;
            let entry = format!("{var}={r}");
            super::refs::check_entry(&entry).map_err(|e| format!("`{at}` {var}: {e}"))?;
            Ok(entry)
        })
        .collect()
}

/// `required` and `map` of the table at `[path]` (`env`, `env.dev`).
pub fn env_set(t: &toml::Table, path: &str) -> Result<EnvSet, String> {
    let mut set = EnvSet::default();
    if let Some(map) = t.get("map") {
        set.map = map_entries(map, &format!("[{path}.map]"))?;
    }
    if let Some(req) = t.get("required") {
        let at = format!("[{path}].required");
        let arr = req
            .as_array()
            .ok_or_else(|| format!("`{at}` must be an array of strings"))?;
        for entry in arr {
            let s = entry
                .as_str()
                .ok_or_else(|| format!("`{at}` must contain only strings"))?;
            if s.is_empty() {
                return Err(format!("`{at}` contains an empty entry"));
            }
            set.required.push(s.to_string());
        }
    }
    Ok(set)
}

/// Every `[env.<stage>]` table: the keys of `[env]` other than
/// `required` and `map` whose value is a table.
pub fn stages(env: &toml::Table) -> Result<BTreeMap<String, EnvSet>, String> {
    env.iter()
        .filter(|(k, v)| !matches!(k.as_str(), "required" | "map") && v.is_table())
        .map(|(k, v)| {
            let t = v.as_table().cloned().unwrap_or_default();
            Ok((k.clone(), env_set(&t, &format!("env.{k}"))?))
        })
        .collect()
}

fn var_of(entry: &str) -> &str {
    entry.split_once('=').map_or(entry, |(v, _)| v)
}

/// The entries to provision: `base`, plus `stage`'s set when one is
/// named. Unknown stages are refused with the list of known ones.
pub fn merge(
    base: EnvSet,
    mut stages: BTreeMap<String, EnvSet>,
    stage: Option<&str>,
) -> Result<Vec<String>, String> {
    let EnvSet {
        mut required,
        mut map,
    } = base;
    if let Some(s) = stage {
        let Some(st) = stages.remove(s) else {
            let known: Vec<&str> = stages.keys().map(String::as_str).collect();
            return Err(if known.is_empty() {
                format!("unknown stage {s:?}: the manifest has no [env.<stage>] tables")
            } else {
                format!("unknown stage {s:?}; known stages: {}", known.join(", "))
            });
        };
        for r in st.required {
            if !required.iter().any(|x| x.eq_ignore_ascii_case(&r)) {
                required.push(r);
            }
        }
        map.extend(st.map);
    }
    // A later map entry replaces an earlier one for the same variable.
    let mut refs: Vec<String> = Vec::new();
    for e in map {
        refs.retain(|r| var_of(r) != var_of(&e));
        refs.push(e);
    }
    // ... and a plain name provisioned as the same variable.
    let mut out: Vec<String> = required
        .into_iter()
        .filter(|n| !refs.iter().any(|r| var_of(r) == n.to_uppercase()))
        .collect();
    out.extend(refs);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> (EnvSet, BTreeMap<String, EnvSet>) {
        let v: toml::Table = toml::from_str(text).unwrap();
        let env = v["env"].as_table().unwrap();
        (env_set(env, "env").unwrap(), stages(env).unwrap())
    }

    const MANIFEST: &str = r#"
[env]
required = ["API_KEY", "DB_URL"]
[env.map]
LOG = "kepr://LOGS/token"
[env.dev]
required = ["DEV_ONLY", "api_key"]
[env.dev.map]
DB_URL = "kepr://R/url[1]"
LOG = "kepr://R/login"
[env.prod]
required = ["PROD_ONLY"]
"#;

    #[test]
    fn a_stage_merges_with_the_base() {
        let (base, st) = parse(MANIFEST);
        assert_eq!(st.keys().collect::<Vec<_>>(), ["dev", "prod"]);
        assert_eq!(
            merge(base.clone(), st.clone(), None).unwrap(),
            ["API_KEY", "DB_URL", "LOG=kepr://LOGS/token"]
        );
        assert_eq!(
            merge(base.clone(), st.clone(), Some("dev")).unwrap(),
            [
                "API_KEY",
                "DEV_ONLY",
                "DB_URL=kepr://R/url[1]",
                "LOG=kepr://R/login"
            ]
        );
        assert_eq!(
            merge(base, st, Some("prod")).unwrap(),
            ["API_KEY", "DB_URL", "PROD_ONLY", "LOG=kepr://LOGS/token"]
        );
    }

    #[test]
    fn unknown_stage_lists_the_known_ones() {
        let (base, st) = parse(MANIFEST);
        let e = merge(base, st, Some("qa")).unwrap_err();
        assert_eq!(e, "unknown stage \"qa\"; known stages: dev, prod");
        let (base, st) = parse("[env]\nrequired = [\"A\"]\n");
        let e = merge(base, st, Some("qa")).unwrap_err();
        assert!(e.contains("no [env.<stage>] tables"), "{e}");
    }

    #[test]
    fn stage_map_entries_resolve_through_the_inject_resolver() {
        let (base, st) = parse(MANIFEST);
        let src = super::super::resolve::tests::fixture();
        let entries = merge(base, st, Some("dev")).unwrap();
        let got: Vec<(String, String)> = entries[2..]
            .iter()
            .map(|e| {
                let (k, v) = super::super::refs::entry(e, &src).unwrap();
                (k, v.as_str().to_string())
            })
            .collect();
        assert_eq!(
            got,
            [
                ("DB_URL".to_string(), "https://b.example".to_string()),
                ("LOG".to_string(), "me".to_string())
            ]
        );
    }

    #[test]
    fn bad_stage_tables_name_their_path() {
        for (text, what) in [
            (
                "[env.dev]\nrequired = 3\n",
                "`[env.dev].required` must be an array",
            ),
            ("[env.dev.map]\nX = \"nope\"\n", "`[env.dev.map]` X:"),
            ("[env.dev]\nrequired = [\"\"]\n", "contains an empty entry"),
        ] {
            let v: toml::Table = toml::from_str(text).unwrap();
            let e = stages(v["env"].as_table().unwrap()).unwrap_err();
            assert!(e.contains(what), "{text}: {e}");
        }
    }
}
