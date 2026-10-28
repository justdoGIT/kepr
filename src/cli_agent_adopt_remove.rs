// cli_agent_adopt_remove.rs — `kepr agent adopt --remove`: delete the
// source lines of adopted keys (split out of cli_agent_adopt.rs, T12.19).
//
// Lines are only deleted, never rewritten with other text, and no
// plaintext backup is kept. JSON / YAML harness files (T12.18) and files
// that are not UTF-8 (zsh history, T12.19) are never rewritten: kepr says
// which file, or which lines, to edit by hand.

use std::path::PathBuf;

use zeroize::Zeroizing;

use crate::cli_agent_adopt::{Found, Plan};
use crate::cli_ui;

/// Delete the given 1-based line numbers from `text`.
pub fn remove_lines(text: &str, lines: &[usize]) -> String {
    let mut out: String = text
        .lines()
        .enumerate()
        .filter(|(i, _)| !lines.contains(&(i + 1)))
        .map(|(_, l)| format!("{l}\n"))
        .collect();
    if !text.ends_with('\n') && out.ends_with('\n') {
        out.pop();
    }
    out
}

/// Delete the source lines of the keys that were stored, and return the
/// files rewritten.
pub fn remove_adopted(
    paths: &[PathBuf],
    plan: &Plan,
    found: &[Found],
    stored: &[&str],
) -> Vec<PathBuf> {
    let mut rewritten = Vec::new();
    for file in paths {
        let lines: Vec<usize> = plan
            .remove
            .iter()
            .filter(|(p, _)| p == file)
            .filter(|(p, l)| {
                found
                    .iter()
                    .any(|f| &f.file == p && f.line == *l && stored.contains(&f.name.as_str()))
            })
            .map(|(_, l)| *l)
            .collect();
        if lines.is_empty() {
            continue;
        }
        if crate::cli_agent_adopt_harness::is_structured(file) {
            cli_ui::warn(&format!(
                "remove the key from {} by hand; under `kepr agent run` the harness gets a placeholder",
                file.display()
            ));
            continue;
        }
        let bytes = match std::fs::read(file).map(Zeroizing::new) {
            Ok(b) => b,
            Err(e) => {
                cli_ui::err(&format!("{}: {e}", file.display()));
                continue;
            }
        };
        let Ok(text) = std::str::from_utf8(&bytes) else {
            let at: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
            cli_ui::warn(&format!(
                "{} is not valid UTF-8 and was not rewritten; delete line(s) {} by hand",
                file.display(),
                at.join(", ")
            ));
            continue;
        };
        // A history entry goes whole (fish `when:` lines, zsh `\` lines).
        let lines = crate::cli_agent_adopt_history::entry_lines(text, &lines);
        let out = Zeroizing::new(remove_lines(text, &lines));
        match std::fs::write(file, out.as_bytes()) {
            Ok(()) => {
                cli_ui::ok(&format!(
                    "removed {} line(s) from {}",
                    lines.len(),
                    file.display()
                ));
                rewritten.push(file.clone());
            }
            Err(e) => cli_ui::err(&format!("{}: {e}", file.display())),
        }
    }
    rewritten
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli_agent_adopt::{plan, scan_file, scan_text};
    use crate::cli_agent_adopt_history::is_history_file;

    #[test]
    fn remove_leaves_structured_files_byte_identical() {
        let dir = std::env::temp_dir().join(format!("kepr-adopt-rm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let env = dir.join(".env");
        let json = dir.join("auth.json");
        let yml = dir.join("models.yml");
        std::fs::write(&env, "A=1\nXAI_API_KEY=xai-abcdefghijkl\n").unwrap();
        let json_text = "{\n  \"OPENAI_API_KEY\": \"sk-proj-abcdefghijkl\"\n}\n";
        std::fs::write(&json, json_text).unwrap();
        let yml_text = "providers:\n  p:\n    apiKey: sk-ant-api03-abcdefghijkl\n";
        std::fs::write(&yml, yml_text).unwrap();
        let mut found = scan_text(&env, &std::fs::read_to_string(&env).unwrap());
        for f in [&json, &yml] {
            let t = std::fs::read_to_string(f).unwrap();
            found.extend(crate::cli_agent_adopt_harness::scan_structured(f, &t));
        }
        assert_eq!(found.len(), 3);
        let p = plan(&found, &Default::default(), &Default::default());
        let stored: Vec<&str> = found.iter().map(|f| f.name.as_str()).collect();
        let paths = vec![env.clone(), json.clone(), yml.clone()];
        assert_eq!(
            remove_adopted(&paths, &p, &found, &stored),
            vec![env.clone()]
        );
        assert_eq!(std::fs::read_to_string(&env).unwrap(), "A=1\n");
        assert_eq!(std::fs::read_to_string(&json).unwrap(), json_text);
        assert_eq!(std::fs::read_to_string(&yml).unwrap(), yml_text);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn non_utf8_history_is_scanned_but_never_rewritten() {
        let dir = std::env::temp_dir().join(format!("kepr-adopt-hist-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let hist = dir.join(".zsh_history");
        // zsh metafies non-ASCII bytes, so its history is not UTF-8.
        let bytes = b": 1:0;echo caf\x83\xa9\n: 2:0;export XAI_API_KEY=xai-abcdefghijkl\n".to_vec();
        std::fs::write(&hist, &bytes).unwrap();
        assert!(is_history_file(&hist, &[]));
        let found = scan_file(&hist, true);
        assert_eq!(found.len(), 1);
        assert_eq!((found[0].line, found[0].name.as_str()), (2, "XAI_API_KEY"));
        let p = plan(&found, &Default::default(), &Default::default());
        let one = std::slice::from_ref(&hist);
        assert!(remove_adopted(one, &p, &found, &["XAI_API_KEY"]).is_empty());
        assert_eq!(std::fs::read(&hist).unwrap(), bytes);
        // The same entry in a UTF-8 history is deleted, and reported.
        let utf8 = ": 2:0;export XAI_API_KEY=xai-abcdefghijkl\n: 3:0;ls\n";
        std::fs::write(&hist, utf8).unwrap();
        let found = scan_file(&hist, true);
        let p = plan(&found, &Default::default(), &Default::default());
        let rewritten = remove_adopted(one, &p, &found, &["XAI_API_KEY"]);
        assert_eq!(rewritten, vec![hist.clone()]);
        assert_eq!(std::fs::read_to_string(&hist).unwrap(), ": 3:0;ls\n");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn remove_lines_keeps_the_rest() {
        assert_eq!(remove_lines("a\nb\nc\n", &[2]), "a\nc\n");
        assert_eq!(remove_lines("a\nb", &[2]), "a");
        assert_eq!(remove_lines("a\nb\nc", &[1, 3]), "b");
    }
}
