//! Per-session state and fixed trust roots for the forwarding proxy.

use super::{routing, Route};
use crate::limits::Limiter;
use crate::placeholder;
use crate::vault::Cache;
use bytes::Bytes;
use http_body_util::Full;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use kepr_core::secmem::SplitKey;
use std::collections::HashMap;
use std::sync::Arc;

pub(crate) type UpstreamClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

pub struct State {
    pub privacy: crate::privacy::Filter,
    pub session_id: String,
    pub session_key: SplitKey<32>,
    pub routes: HashMap<String, Route>,
    pub(super) route_index: routing::Index,
    pub cache: Arc<Cache>,
    pub limiter: Arc<Limiter>,
    /// P2.1 egress proxy: the session CA and whether unbound hosts tunnel.
    pub ca: Option<Arc<crate::ca::SessionCa>>,
    pub tunnel: bool,
    /// T7.03: host:port of the session's raw tunnels (tunnel.rs).
    pub tunnels: Vec<(String, u16)>,
    /// T13.04: the session's Kubernetes API servers (kube.rs).
    pub kube: Vec<crate::kube::KubeTarget>,
    pub(crate) kube_clients: crate::kube::Clients,
    /// T7.09: what the agent sends and receives (`--record`).
    pub recorder: Arc<crate::recording::Recorder>,
    /// T11.22: request journal entries on their way to the daemon.
    pub journal: Arc<crate::journal::Queue>,
    pub(crate) client: UpstreamClient,
    pub(crate) base_override: Option<String>,
}

/// T12.07: generic over the request body, for git pushes streamed upstream.
pub(crate) fn build_client<B>(allow_plain_http: bool) -> Client<HttpsConnector<HttpConnector>, B>
where
    B: hyper::body::Body + Send,
    B::Data: Send,
{
    // Compiled-in roots only: never trust CA files or proxies from the
    // environment, which the agent may control.
    let b = hyper_rustls::HttpsConnectorBuilder::new()
        .with_provider_and_webpki_roots(crate::tls_provider::provider())
        .expect("the TLS provider supports the default protocol versions");
    let b = if allow_plain_http {
        b.https_or_http()
    } else {
        b.https_only()
    };
    // HTTP/1.1 only: every provider serves it, and h2 would add ~400 KB.
    let conn = b.enable_http1().build();
    Client::builder(hyper_util::rt::TokioExecutor::new()).build(conn)
}

impl State {
    pub fn new(
        session_id: String,
        session_key: SplitKey<32>,
        routes: HashMap<String, Route>,
        cache: Arc<Cache>,
    ) -> Self {
        Self {
            privacy: crate::privacy::Filter::new(None).expect("absent privacy policy is valid"),
            session_id,
            session_key,
            route_index: routing::Index::new(&routes),
            routes,
            cache,
            limiter: Arc::new(Limiter::new(Default::default())),
            client: build_client(false),
            base_override: None,
            ca: None,
            tunnel: false,
            tunnels: Vec::new(),
            kube: Vec::new(),
            kube_clients: Default::default(),
            recorder: Arc::new(crate::recording::Recorder::new(false)),
            journal: Arc::default(),
        }
    }

    pub fn with_egress(mut self, ca: Option<Arc<crate::ca::SessionCa>>, tunnel: bool) -> Self {
        (self.ca, self.tunnel) = (ca, tunnel);
        self
    }

    pub fn with_limits(mut self, limits: kepr_core::gate_protocol::GateLimits) -> Self {
        self.limiter = Arc::new(Limiter::new(limits));
        self
    }

    pub fn with_privacy(
        mut self,
        policy: Option<kepr_core::privacy::Policy>,
    ) -> Result<Self, String> {
        self.privacy = crate::privacy::Filter::new(policy)?;
        Ok(self)
    }

    /// The gate re-checks what the daemon already validated.
    pub fn validated(self) -> Result<Self, String> {
        self.limiter.config().validate()?;
        if self.privacy.enabled()
            && (self.tunnel
                || !self.tunnels.is_empty()
                || !self.kube.is_empty()
                || self
                    .routes
                    .keys()
                    .any(|p| !kepr_core::privacy::supports_provider(p)))
        {
            return Err("privacy session contains an uninspected route".into());
        }
        Ok(self)
    }

    pub(crate) fn configured_routes(&self, host: &str) -> Option<Arc<HashMap<String, String>>> {
        self.route_index.host(host)
    }

    pub(crate) fn valid_placeholder(&self, s: &str, slot: u16) -> bool {
        match placeholder::parse(s) {
            Some(p) => {
                p.session_id == self.session_id
                    && p.slot == slot
                    && self.session_key.with_key(|k| placeholder::verify(k, &p))
            }
            None => false,
        }
    }
}
