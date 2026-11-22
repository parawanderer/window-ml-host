//! lib.rs — window.ml's process host: the extension sends argv, the host resolves the facts, waits for the worker's
//! verdict, and runs the call under the OS sandbox, keeping its output as pointers. The wire: docs/PROTOCOL.md.

pub mod credential;
pub mod elf;
pub mod env;
pub mod exec_under;
pub mod facts;
pub mod framing;
pub mod fsx;
pub mod gitconfig;
pub mod gitfacts;
pub mod glob;
#[cfg(feature = "hub")]
pub mod hub;
pub mod install;
pub mod mounts;
pub mod owners;
pub mod procs;
pub mod proxy;
pub mod put;
pub mod register;
pub mod runner;
pub mod sandbox;
pub mod session;
pub mod snapshot;
pub mod snapshot_bounds;
pub mod snapshot_report;
pub mod store;
pub mod tilde;
pub mod tripwire;
pub mod walk;

// The describer lives in its own crate so the extension's wasm builds it without the host; these keep the old paths.
pub use wmlhost_describe::{manifest, script_grammar};
