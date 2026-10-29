// cli_desktop/bus.rs — a plain client connection to the session bus for
// the commands that look at it or talk to another Secret Service.

use std::sync::Arc;

use super::dbus::conn::Handler;
use super::dbus::{addr, Conn, Message};
use super::ss::run::my_uid;

/// Connect; every incoming call is ignored, every signal handed to `on`.
pub fn connect_with(on: impl Fn(Message) + Send + Sync + 'static) -> Result<Arc<Conn>, String> {
    let handler: Arc<Handler> = Arc::new(move |_, m| {
        if m.kind == super::dbus::msg::SIGNAL {
            on(m);
        }
    });
    Conn::connect(&addr::session_bus()?, my_uid(), handler)
}

pub fn connect() -> Result<Arc<Conn>, String> {
    connect_with(|_| {})
}
