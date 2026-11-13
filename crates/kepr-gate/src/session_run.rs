use super::*;

pub fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let owner = pidfd_open(parse_owner_pid(&args)?)?;

    let mut raw = Zeroizing::new(String::new());
    std::io::stdin()
        .take(MAX_CONFIG)
        .read_to_string(&mut raw)
        .map_err(|e| format!("reading config: {e}"))?;
    let mut cfg: SessionConfig =
        serde_json::from_str(&raw).map_err(|_| "malformed session config")?;
    drop(raw); // wiped: it held the session key in hex
    validate_config(&cfg)?;
    confine()?;
    let key = decode_key(cfg.session_key_hex.as_str())?;
    cfg.session_key_hex = kepr_core::generate::ZeroString::from_string(String::new());
    if !fd3_is_open() {
        return Err("daemon channel (fd 3) missing".into());
    }
    let cache = Arc::new(
        Cache::new(Box::new(FdResolver::from_fd3()?), DEFAULT_TTL).with_durable_decisions(),
    );

    let mut placeholders = HashMap::new();
    let mut table = HashMap::new();
    let mut db_routes = Vec::new();
    for r in &cfg.routes {
        // A raw tunnel (T7.03) takes no credential, hence no placeholder.
        if !r.is_tunnel() {
            placeholders.insert(
                r.provider.clone(),
                placeholder::make(&key, &cfg.session_id, r.slot),
            );
        }
        // A Kubernetes API server (T13.04) is served by the egress proxy.
        if let Some(target) = r.target.as_ref().filter(|_| !crate::kube::is_kube(r)) {
            db_routes.push(Arc::new(crate::db::DbRoute::new(
                r.provider.clone(),
                r.cred.clone(),
                r.slot,
                target.clone(),
            )));
            continue;
        }
        table.insert(
            r.provider.clone(),
            Route {
                cred: r.cred.clone(),
                slot: r.slot,
            },
        );
    }
    let bind_port = cfg.port.unwrap_or(0);
    let ca = crate::ca::for_routes(&cfg.routes)?;
    let ca_pem = ca.as_ref().map(|c| c.pem().to_string());
    let recorder = Arc::new(crate::recording::Recorder::new(cfg.record));
    crate::recording::spawn_flusher(recorder.clone(), cache.clone());
    let state = Arc::new(
        State::new(
            cfg.session_id.clone(),
            SplitKey::new(&key)?,
            table,
            cache.clone(),
        )
        .with_privacy(cfg.privacy.clone())?
        .with_limits(cfg.limits)
        .with_egress(ca, cfg.tunnel)
        .with_tunnels(&cfg.routes)
        .with_kube(&cfg.routes)
        .with_recorder(recorder.clone())
        .validated()?,
    );
    // Keep only SplitKey shares in secret memory; wipe the plain key.
    drop(key);
    crate::journal::spawn_flusher(state.journal.clone(), cache.clone());
    // Rotation is a one-shot daemon operation, not an agent proxy route.
    let rotation = cfg.rotation.take();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))?;
    if let Some(rotation) = rotation {
        let rotation_client = state.client.clone();
        let port = rt.block_on(async {
            crate::rotate_provider_http::run(&cache, &rotation_client, &rotation).await?;
            bind_gate(0)
                .await?
                .local_addr()
                .map_err(|e| format!("bind: {e}"))
                .map(|addr| addr.port())
        })?;
        let ready = ReadyLine {
            privacy: cfg.privacy.as_ref().map(|p| p.preset),
            ready: true,
            port,
            placeholders: HashMap::new(),
            ca_pem: None,
            db_ports: HashMap::new(),
            error: None,
        };
        let mut out = std::io::stdout();
        writeln!(
            out,
            "{}",
            serde_json::to_string(&ready).map_err(|e| e.to_string())?
        )
        .and_then(|_| out.flush())
        .map_err(|e| format!("stdout: {e}"))?;
        cache.clear();
        return Ok(());
    }
    rt.block_on(async move {
        let listener = bind_gate(bind_port).await?;
        let port = listener
            .local_addr()
            .map_err(|e| format!("bind: {e}"))?
            .port();
        // P7.1: one loopback listener per database route.
        let mut db_ports = HashMap::new();
        let jit_routes = db_routes.clone();
        for route in db_routes {
            let l = tokio::net::TcpListener::bind(("127.0.0.1", 0))
                .await
                .map_err(|e| format!("database listener: {e}"))?;
            let p = l.local_addr().map_err(|e| e.to_string())?.port();
            db_ports.insert(route.key.clone(), p);
            let st = state.clone();
            tokio::spawn(async move {
                while let Ok((c, _)) = l.accept().await {
                    tokio::spawn(crate::db::serve_conn(st.clone(), route.clone(), c));
                }
            });
        }
        let ready = ReadyLine {
            privacy: cfg.privacy.as_ref().map(|p| p.preset),
            ready: true,
            port,
            placeholders,
            ca_pem,
            db_ports,
            error: None,
        };
        let mut out = std::io::stdout();
        writeln!(
            out,
            "{}",
            serde_json::to_string(&ready).map_err(|e| e.to_string())?
        )
        .and_then(|_| out.flush())
        .map_err(|e| format!("stdout: {e}"))?;

        let st = state.clone();
        tokio::spawn(async move {
            // `owner` is a pidfd this task owns; newer tokio deprecates `new`
            // for `register`, which older releases in our range lack.
            #[allow(deprecated)]
            let afd = tokio::io::unix::AsyncFd::new(owner);
            if let Ok(afd) = afd {
                let _ = afd.readable().await;
            }
            // T7.18: take back the roles this session granted.
            crate::pg_jit::revoke_all(&st, &jit_routes).await;
            // T13.02: and drop the logins it made.
            crate::pg_ephemeral::drop_all(&st, &jit_routes).await;
            // Connections the agent closed as it exited are still winding
            // down: let them journal (and record) their last lines.
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            recorder.flush(&cache);
            st.journal.flush(&cache);
            cache.clear();
            std::process::exit(0);
        });
        proxy::serve(listener, state).await;
        Ok::<(), String>(())
    })
}
