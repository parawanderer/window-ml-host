//! hub.rs — the hub transport, compiled only with the `hub` feature: the same calls as native messaging, carried as
//! sealed commands from a principal holding the `desktop` scope (window-ml's RUNTIME_HUB.md). Not built yet; this module
//! is the seam, so that the feature names a place and the default build stays free of hub code.

/// Whether this build carries the hub transport.
pub const BUILT: bool = false;
