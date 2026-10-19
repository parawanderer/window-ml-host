//! hub — the hub transport, compiled only with the `hub` feature: the same calls as native messaging, carried as
//! sealed commands from a principal holding the `desktop` scope (window-ml's RUNTIME_HUB.md, SHELL.md "Where processes
//! run"). This slice is the host's identity on a hub: its keys, pairing as a runtime, and the two files only the person
//! at this machine writes (the roots a remote caller may work in, and who may call). Serving comes next.

pub mod cli;
pub mod pair;
pub mod state;

/// Whether this build carries the hub transport.
pub const BUILT: bool = true;
