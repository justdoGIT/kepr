//! The decisions the PAM entry points make, without any PAM call, so they
//! test on their own.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub const DEFAULT_KEPR: &[&str] = &["/usr/bin/kepr", "/usr/local/bin/kepr"];

#[derive(Debug, PartialEq, Eq)]
pub struct Opts {
    /// Candidate `kepr` paths, in order.
    pub kepr: Vec<PathBuf>,
    pub debug: bool,
}

/// Module arguments from the PAM config line. An unknown or relative
/// `kepr=` is dropped (the default stands), never guessed at.
pub fn parse_opts(args: &[String]) -> Opts {
    let mut o = Opts {
        kepr: Vec::new(),
        debug: false,
    };
    for a in args {
        match a.split_once('=') {
            Some(("kepr", p)) if Path::new(p).is_absolute() => o.kepr = vec![p.into()],
            None if a == "debug" => o.debug = true,
            _ => {}
        }
    }
    if o.kepr.is_empty() {
        o.kepr = DEFAULT_KEPR.iter().map(PathBuf::from).collect();
    }
    o
}

/// May this file be run with a user's password on its stdin? A regular
/// file owned by root that neither group nor others can write.
pub fn trusted_binary(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.uid() == 0 && m.mode() & 0o022 == 0)
}

/// The first candidate that is trusted.
pub fn pick_kepr(candidates: &[PathBuf]) -> Option<&PathBuf> {
    candidates.iter().find(|p| trusted_binary(p))
}

/// The environment the helper gets: nothing inherited from the login.
pub fn helper_env(uid: u32, home: &str) -> Vec<(String, String)> {
    vec![
        ("HOME".into(), home.into()),
        ("PATH".into(), "/usr/bin:/bin".into()),
        ("XDG_RUNTIME_DIR".into(), format!("/run/user/{uid}")),
        ("KEPR_PAM_WAIT".into(), "20".into()),
    ]
}

/// Does PAM data for this login mean anything to us? Root is left alone.
pub fn applies_to(uid: u32) -> bool {
    uid != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn options() {
        assert_eq!(parse_opts(&[]).kepr.len(), 2);
        let o = parse_opts(&s(&["kepr=/opt/kepr/bin/kepr", "debug"]));
        assert_eq!(o.kepr, [PathBuf::from("/opt/kepr/bin/kepr")]);
        assert!(o.debug);
        // A relative path is ignored; so is anything unknown.
        let o = parse_opts(&s(&["kepr=kepr", "wat=1", "nodebug"]));
        assert_eq!(o.kepr.len(), 2);
        assert!(!o.debug);
    }

    #[test]
    fn only_a_root_owned_closed_binary_is_trusted() {
        let d = std::env::temp_dir().join(format!("kepr-pam-test-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("kepr");
        std::fs::write(&f, b"#!/bin/sh\n").unwrap();
        let mine = std::fs::metadata(&f).unwrap().uid();
        for mode in [0o755, 0o775, 0o757, 0o777] {
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(mode)).unwrap();
            let want = mine == 0 && mode & 0o022 == 0;
            assert_eq!(trusted_binary(&f), want, "{mode:o} owned by {mine}");
        }
        assert!(!trusted_binary(&d), "a directory");
        assert!(!trusted_binary(&d.join("missing")));
        assert_eq!(pick_kepr(&[d.join("missing")]), None);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_helper_gets_a_clean_environment() {
        let env = helper_env(1000, "/home/a");
        let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        assert_eq!(get("XDG_RUNTIME_DIR"), Some("/run/user/1000"));
        assert_eq!(get("HOME"), Some("/home/a"));
        assert_eq!(get("PATH"), Some("/usr/bin:/bin"));
        assert!(env.iter().all(|(k, _)| !k.contains("PASS")));
    }

    #[test]
    fn root_is_left_alone() {
        assert!(!applies_to(0));
        assert!(applies_to(1000));
    }
}
