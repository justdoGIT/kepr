// cli_desktop/ss/ — the Secret Service server.

pub mod audit;
pub mod bus_caller;
pub mod caller;
pub mod collection;
pub mod daemon_store;
pub mod dh;
pub mod intro;
pub mod item;
pub mod names;
pub mod policy;
pub mod prompt;
pub mod props;
pub mod run;
pub mod server;
pub mod service;
pub mod session;
pub mod sig_types;
pub mod store;
pub mod unlock;
pub mod view;
pub mod watch;

#[cfg(test)]
mod server_tests;
