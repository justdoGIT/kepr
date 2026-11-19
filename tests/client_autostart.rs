use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

#[test]
fn supervised_clients_never_launch_a_standalone_daemon() {
    let home = tempfile::tempdir().unwrap();
    let bin = home.path().join("bin");
    let runtime = home.path().join("runtime");
    fs::create_dir(&bin).unwrap();
    fs::create_dir(&runtime).unwrap();
    let daemon = bin.join("kepr-daemon");
    fs::write(&daemon, "#!/bin/sh\nprintf started > \"$HOME/daemon-started\"\n").unwrap();
    fs::set_permissions(&daemon, fs::Permissions::from_mode(0o700)).unwrap();
    let marker = home.path().join("daemon-started");
    let ping = |supervised: bool| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_kepr"));
        command
            .env_clear()
            .env("HOME", home.path())
            .env("XDG_RUNTIME_DIR", &runtime)
            .env("PATH", &bin)
            .args(["status", "--json"]);
        if supervised {
            command.env("KEPR_NO_AUTOSTART", "1");
        }
        command.output().unwrap()
    };

    let stopped = ping(true);
    assert!(!stopped.status.success());
    assert!(!marker.exists(), "supervised clients must wait for their service");
    let autonomous = ping(false);
    assert!(!autonomous.status.success(), "fixture daemon never binds a socket");
    assert!(marker.exists(), "ordinary clients retain their autostart behavior");
}
