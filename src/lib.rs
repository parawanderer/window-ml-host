//! lib.rs — window.ml's process host: the extension sends argv, the host resolves the facts, waits for the worker's
//! verdict, and runs the call under the OS sandbox, keeping its output as pointers. The wire: docs/PROTOCOL.md.

pub mod framing;
pub mod install;
