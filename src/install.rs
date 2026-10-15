//! install.rs — registers the host with Chromium-family browsers: writes the native messaging host manifest that names
//! this binary and the one extension allowed to start it.

use std::path::{Path, PathBuf};

/// The native messaging host name the extension connects to (`chrome.runtime.connectNative`).
pub const HOST_NAME: &str = "com.parawanderer.window_ml_host";

/// A browser whose per-user NativeMessagingHosts directory the installer knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Browser {
    Chrome,
    ChromeBeta,
    Chromium,
    Brave,
    Edge,
}

/// The per-user directory a browser reads host manifests from, under `home`, on this platform.
pub fn manifest_dir(browser: Browser, home: &Path) -> PathBuf {
    let _ = (browser, home);
    todo!()
}

/// The manifest JSON for `binary`, allowing only `extension_id`. Refuses an id that is not 32 letters a-p.
pub fn manifest_json(binary: &Path, extension_id: &str) -> Result<String, String> {
    let _ = (binary, extension_id);
    todo!()
}

/// `wmlhost install` / `wmlhost uninstall`: parses its own arguments (everything after the subcommand) and returns
/// the process exit code.
pub fn main(args: &[String]) -> i32 {
    let _ = args;
    todo!()
}
