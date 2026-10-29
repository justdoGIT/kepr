// cli_desktop/takeover.rs — the `takeover` and `restore` commands of
// `kepr secret-service`. What they change on disk is takeover_files.rs; the
// current provider's items are copied first (import.rs), and nothing changes
// when that fails. With --now the running provider is asked to exit (only
// the keyrings kepr knows) and kepr is started in its place.

use std::time::{Duration, Instant};

use kepr_core::protocol::Response;

use super::ss::bus_caller::{owner_of, Owner};
use super::ss::names as n;
use super::takeover_files::{install, report, uninstall, Dirs, UserSystemd};
use super::{bus, import};
use crate::{cli_mode, cli_ui};

const USAGE: &str = "usage: kepr secret-service takeover [--now] [--no-import]";
/// Providers `--now` may ask to exit.
const KNOWN_PROVIDERS: &[&str] = &["gnome-keyring-daemon", "kwalletd5", "kwalletd6", "ksecretd"];

fn say(m: &str) {
    if !cli_mode::json_mode() {
        cli_ui::info(m);
    }
}

fn exit_provider(o: &Owner) -> Result<(), String> {
    let name = o
        .exe
        .as_deref()
        .and_then(|e| e.rsplit('/').next())
        .unwrap_or("");
    let pid = o.pid.ok_or("the provider's process is unknown")?;
    if !KNOWN_PROVIDERS.contains(&name) {
        return Err(format!("{} is not a keyring kepr knows how to stop; stop it yourself, then run `kepr secret-service takeover --now` again", o.describe()));
    }
    // SAFETY: kill with a pid we read from the bus and a plain signal number.
    let rc = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    if rc != 0 {
        return Err(format!(
            "could not stop {}: {}",
            o.describe(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Start kepr in the provider's place and wait until it owns the name.
fn switch_now(conn: &super::dbus::Conn, owner: Option<&Owner>) -> Result<(), String> {
    use super::dbus::conn::{BUS, BUS_PATH};
    use super::dbus::{Message, Value};
    if let Some(o) = owner.filter(|o| !o.is_kepr()) {
        exit_provider(o)?;
        let t = Instant::now();
        while owner_of(conn, n::BUS_NAME).is_some() {
            if t.elapsed() > Duration::from_secs(10) {
                return Err(format!("{} did not exit", o.describe()));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    let start = Message::call(
        BUS,
        BUS_PATH,
        BUS,
        "StartServiceByName",
        vec![Value::str(n::BUS_NAME), Value::U32(0)],
    );
    conn.call(start, Duration::from_secs(10))
        .map_err(|e| format!("the bus could not start kepr: {e}"))?;
    match owner_of(conn, n::BUS_NAME) {
        Some(o) if o.is_kepr() => Ok(()),
        Some(o) => Err(format!("{} owns the name, not kepr", o.describe())),
        None => Err("kepr did not take the name".into()),
    }
}

pub fn takeover(args: &[&str]) -> Response {
    let (mut now, mut no_import) = (false, false);
    for a in args {
        match *a {
            "--now" => now = true,
            "--no-import" => no_import = true,
            _ => return Response::fail(USAGE),
        }
    }
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => return Response::fail(format!("cannot find the kepr binary: {e}")),
    };
    let conn = bus::connect();
    let owner = conn.as_ref().ok().and_then(|c| owner_of(c, n::BUS_NAME));
    if let (Some(o), false) = (owner.as_ref().filter(|o| !o.is_kepr()), no_import) {
        say(&format!("importing from {} first", o.describe()));
        match import::from_session(false, false) {
            Ok(rep) => {
                import::print(&rep, false);
                if !rep.failed.is_empty() {
                    return Response::fail("nothing was changed because some items could not be imported; fix that, or run again with --no-import");
                }
            }
            Err(e) => {
                return Response::fail(format!(
                    "nothing was changed: {e} (or run again with --no-import)"
                ))
            }
        }
    }
    match install(&Dirs::from_env(), &UserSystemd, &exe) {
        Ok(done) => done.iter().for_each(|l| say(l)),
        Err(e) => return Response::fail(e),
    }
    for l in report().iter().skip(1) {
        cli_ui::warn(l);
    }
    if now {
        match conn
            .as_ref()
            .map_err(Clone::clone)
            .and_then(|c| switch_now(c, owner.as_ref()))
        {
            Ok(()) => cli_ui::ok("kepr is now this session's Secret Service."),
            Err(e) => return Response::fail(e),
        }
    } else {
        cli_ui::ok("Done. Log out and in again, or run `kepr secret-service takeover --now`, to start using kepr.");
    }
    Response::Pong
}

pub fn restore() -> Response {
    match uninstall(&Dirs::from_env(), &UserSystemd) {
        Ok(done) if done.is_empty() => {
            say("nothing to restore: kepr's takeover is not installed");
            Response::Pong
        }
        Ok(done) => {
            done.iter().for_each(|l| say(l));
            cli_ui::ok("Restored. GNOME Keyring takes over again at the next login; kepr's items stay in kepr.");
            Response::Pong
        }
        Err(e) => Response::fail(e),
    }
}
