//! lib.rs — window.ml's process host: the extension sends argv, the host resolves the facts, waits for the worker's
//! verdict, and runs the call under the OS sandbox, keeping its output as pointers. The wire: docs/PROTOCOL.md.

pub mod env;
pub mod facts;
pub mod framing;
pub mod fsx;
pub mod gitconfig;
#[cfg(feature = "hub")]
pub mod hub;
pub mod install;
pub mod runner;
pub mod sandbox;
pub mod session;
pub mod store;
pub mod walk;
