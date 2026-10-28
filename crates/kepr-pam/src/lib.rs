//! `pam_kepr.so` — unlock the kepr store with the login password.
//!
//! Add to the session stack (after the module that checks the password):
//!
//! ```text
//! auth     optional  pam_kepr.so
//! session  optional  pam_kepr.so
//! ```
//!
//! `auth` only remembers the password the authentication stack collected
//! (`PAM_AUTHTOK`), in memory, until the session opens. `session` then runs
//! `kepr pam-unlock` as the user, detached, and gives it the password on
//! stdin. The module never fails or delays a login: every path returns
//! `PAM_IGNORE`. It does nothing for root, for a user it cannot look up, or
//! when the `kepr` binary is not root-owned and closed to group / other
//! writes. It helps only when the store passphrase is the login password.
//!
//! Options: `kepr=/abs/path` (default `/usr/bin/kepr`, then
//! `/usr/local/bin/kepr`), `debug` (syslog the steps, never the password).

pub mod logic;

#[cfg(not(test))]
mod ffi;
#[cfg(not(test))]
mod spawn;
