src/
├── main.rs        → credman CLI binary
├── daemon.rs      → credman-daemon binary
├── protocol.rs    → shared request/response types
├── crypto.rs      → systemd-creds wrapper (daemon only)
├── generate.rs    → CSPRNG (shared)
├── store.rs       → path + naming (shared)
└── audit.rs       → systemd journal logger (daemon only)
