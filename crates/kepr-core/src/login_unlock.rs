// login_unlock.rs — the per-user switch for unlocking at login (T13.25),
// shared by `kepr login-unlock`, `kepr pam-unlock` / `pam-passwd` and the
// daemon's start-up wait.
//
// The switch is a file, `~/.config/kepr/login-unlock`, always under
// `$HOME/.config` whatever `XDG_CONFIG_HOME` says: pam_kepr.so starts the
// helpers with a clean environment (HOME and little else), so the file has
// to be where that environment finds it. Only the default profile unlocks
// at login (the helpers run without `KEPR_PROFILE`).

use std::path::{Path, PathBuf};

/// Where the switch lives, relative to the home directory.
pub const MARKER: &str = ".config/kepr/login-unlock";

/// Failed login unlocks in a row after which the login path stops trying
/// until the passphrase is checked another way (`kepr unlock`).
pub const MAX_FAILURES: u32 = 5;

pub fn marker(home: &Path) -> PathBuf {
    home.join(MARKER)
}

/// Is login unlock on for the user whose home this is?
pub fn enabled(home: &Path) -> bool {
    marker(home).is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_switch_is_a_file_under_dot_config_whatever_xdg_says() {
        let home = std::env::temp_dir().join(format!("kepr-login-unlock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        assert_eq!(marker(&home), home.join(".config/kepr/login-unlock"));
        assert!(!enabled(&home));
        std::fs::create_dir_all(marker(&home)).unwrap();
        assert!(!enabled(&home), "a directory is not the switch");
        std::fs::remove_dir(marker(&home)).unwrap();
        std::fs::write(marker(&home), b"").unwrap();
        assert!(enabled(&home));
        std::fs::remove_dir_all(&home).unwrap();
    }
}
