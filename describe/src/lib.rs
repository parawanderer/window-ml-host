//! lib.rs — the describer: what one argv does under a program manifest, with no I/O and no host dependency, so the
//! process host and the extension's wasm (`describe-wasm`) run the same code.

pub mod manifest;
pub mod script_grammar;
