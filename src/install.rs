//! install.rs — registers the host with Chromium-family browsers: writes the native messaging host manifest that names
//! this binary and the one extension allowed to start it.

use clap::{Parser, Subcommand, ValueEnum};
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
    let rel = if cfg!(target_os = "macos") {
        match browser {
            Browser::Chrome => "Library/Application Support/Google/Chrome",
            Browser::ChromeBeta => "Library/Application Support/Google/Chrome Beta",
            Browser::Chromium => "Library/Application Support/Chromium",
            Browser::Brave => "Library/Application Support/BraveSoftware/Brave-Browser",
            Browser::Edge => "Library/Application Support/Microsoft Edge",
        }
    } else {
        match browser {
            Browser::Chrome => ".config/google-chrome",
            Browser::ChromeBeta => ".config/google-chrome-beta",
            Browser::Chromium => ".config/chromium",
            Browser::Brave => ".config/BraveSoftware/Brave-Browser",
            Browser::Edge => ".config/microsoft-edge",
        }
    };
    home.join(rel).join("NativeMessagingHosts")
}

/// The manifest JSON for `binary`, allowing only `extension_id`. Refuses an id that is not 32 letters a-p.
pub fn manifest_json(binary: &Path, extension_id: &str) -> Result<String, String> {
    if extension_id.len() != 32 || !extension_id.bytes().all(|b| (b'a'..=b'p').contains(&b)) {
        return Err(format!("extension id must be 32 characters in a-p, got {extension_id:?}"));
    }
    if !binary.is_absolute() {
        return Err(format!("binary path must be absolute, got {}", binary.display()));
    }
    let path = binary.to_str().ok_or_else(|| format!("binary path is not valid UTF-8: {}", binary.display()))?;
    let value = serde_json::json!({
        "name": HOST_NAME,
        "description": "window.ml process host",
        "path": path,
        "type": "stdio",
        "allowed_origins": [format!("chrome-extension://{extension_id}/")],
    });
    serde_json::to_string_pretty(&value).map_err(|e| e.to_string())
}

#[derive(Parser)]
#[command(name = "wmlhost", no_binary_name = true)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Write the host manifest into each browser's NativeMessagingHosts directory.
    Install {
        /// The extension id allowed to start the host.
        #[arg(long)]
        extension_id: String,
        /// Browser(s) to register with; repeatable.
        #[arg(long, value_enum, default_value = "chrome")]
        browser: Vec<BrowserArg>,
        /// The host binary; defaults to this executable.
        #[arg(long)]
        binary: Option<PathBuf>,
        /// Print what would be written and write nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Remove the host manifest from each browser's NativeMessagingHosts directory.
    Uninstall {
        /// Browser(s) to unregister from; repeatable.
        #[arg(long, value_enum, default_value = "chrome")]
        browser: Vec<BrowserArg>,
        /// Print what would be removed and remove nothing.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum BrowserArg {
    Chrome,
    ChromeBeta,
    Chromium,
    Brave,
    Edge,
    All,
}

/// Expands `--browser` values (with `all`) into distinct browsers, in first-seen order.
fn expand(args: &[BrowserArg]) -> Vec<Browser> {
    let mut out: Vec<Browser> = Vec::new();
    for a in args {
        let list: &[Browser] = match a {
            BrowserArg::Chrome => &[Browser::Chrome],
            BrowserArg::ChromeBeta => &[Browser::ChromeBeta],
            BrowserArg::Chromium => &[Browser::Chromium],
            BrowserArg::Brave => &[Browser::Brave],
            BrowserArg::Edge => &[Browser::Edge],
            BrowserArg::All => {
                &[Browser::Chrome, Browser::ChromeBeta, Browser::Chromium, Browser::Brave, Browser::Edge]
            }
        };
        for b in list {
            if !out.contains(b) {
                out.push(*b);
            }
        }
    }
    out
}

/// Runs `install`/`uninstall` against `home` (`args[0]` is the subcommand) and returns the lines it prints.
pub fn run(args: &[String], home: &Path) -> Result<Vec<String>, String> {
    let cli = Cli::try_parse_from(args).map_err(|e| e.to_string())?;
    let mut lines = Vec::new();
    match cli.cmd {
        Cmd::Install { extension_id, browser, binary, dry_run } => {
            let binary = match binary {
                Some(b) => b,
                None => std::env::current_exe()
                    .and_then(|p| p.canonicalize())
                    .map_err(|e| format!("cannot resolve this executable: {e}"))?,
            };
            let json = manifest_json(&binary, &extension_id)?;
            for b in expand(&browser) {
                let dir = manifest_dir(b, home);
                let file = dir.join(format!("{HOST_NAME}.json"));
                if dry_run {
                    lines.push(format!("would write {}", file.display()));
                    lines.push(json.clone());
                    continue;
                }
                std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
                std::fs::write(&file, &json).map_err(|e| format!("{}: {e}", file.display()))?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644))
                        .map_err(|e| format!("{}: {e}", file.display()))?;
                }
                lines.push(format!("wrote {}", file.display()));
            }
        }
        Cmd::Uninstall { browser, dry_run } => {
            for b in expand(&browser) {
                let file = manifest_dir(b, home).join(format!("{HOST_NAME}.json"));
                if !file.exists() {
                    continue;
                }
                if dry_run {
                    lines.push(format!("would remove {}", file.display()));
                    continue;
                }
                std::fs::remove_file(&file).map_err(|e| format!("{}: {e}", file.display()))?;
                lines.push(format!("removed {}", file.display()));
            }
        }
    }
    Ok(lines)
}

/// `wmlhost install` / `wmlhost uninstall`: parses its own arguments (everything after the subcommand) and returns
/// the process exit code.
pub fn main(args: &[String]) -> i32 {
    // A parse error is usage (2); clap's own `--help` output also lands here and exits 2 too.
    if let Err(e) = Cli::try_parse_from(args) {
        eprintln!("{e}");
        return 2;
    }
    let Some(home) = std::env::var_os("HOME") else {
        eprintln!("wmlhost: HOME is not set");
        return 1;
    };
    match run(args, Path::new(&home)) {
        Ok(lines) => {
            for l in lines {
                println!("{l}");
            }
            0
        }
        Err(e) => {
            eprintln!("wmlhost: {e}");
            1
        }
    }
}

// --- installer ---
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const ID: &str = "abcdefghijklmnopabcdefghijklmnop";

    fn sv(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    fn file_for(b: Browser, home: &Path) -> PathBuf {
        manifest_dir(b, home).join(format!("{HOST_NAME}.json"))
    }

    #[test]
    fn manifest_json_accepts_a_valid_id() {
        let j = manifest_json(Path::new("/abs/wmlhost"), ID).unwrap();
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        let o = v.as_object().unwrap();
        assert_eq!(o.len(), 5);
        assert_eq!(v["name"], HOST_NAME);
        assert_eq!(v["description"], "window.ml process host");
        assert_eq!(v["path"], "/abs/wmlhost");
        assert_eq!(v["type"], "stdio");
        assert_eq!(v["allowed_origins"], serde_json::json!([format!("chrome-extension://{ID}/")]));
    }

    #[test]
    fn manifest_json_refuses_bad_input() {
        let bin = Path::new("/abs/wmlhost");
        assert!(manifest_json(bin, &ID[..31]).is_err());
        assert!(manifest_json(bin, "qbcdefghijklmnopabcdefghijklmnop").is_err());
        assert!(manifest_json(bin, &ID.to_uppercase()).is_err());
        assert!(manifest_json(Path::new("wmlhost"), ID).is_err());
    }

    #[test]
    fn manifest_json_round_trips_an_awkward_path() {
        let p = "/abs/we\"ird dir/wmlhost";
        let v: serde_json::Value = serde_json::from_str(&manifest_json(Path::new(p), ID).unwrap()).unwrap();
        assert_eq!(v["path"], p);
    }

    #[test]
    fn install_writes_two_browsers() {
        let tmp = tempfile::tempdir().unwrap();
        let lines = run(
            &sv(&[
                "install",
                "--extension-id",
                ID,
                "--browser",
                "chrome",
                "--browser",
                "brave",
                "--binary",
                "/abs/wmlhost",
            ]),
            tmp.path(),
        )
        .unwrap();
        assert_eq!(lines.len(), 2);
        let expected = manifest_json(Path::new("/abs/wmlhost"), ID).unwrap();
        for b in [Browser::Chrome, Browser::Brave] {
            let f = file_for(b, tmp.path());
            assert!(lines.contains(&format!("wrote {}", f.display())));
            assert_eq!(std::fs::read_to_string(&f).unwrap(), expected);
            assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o644);
        }
        assert!(!file_for(Browser::Edge, tmp.path()).exists());
    }

    #[test]
    fn install_all_writes_five() {
        let tmp = tempfile::tempdir().unwrap();
        let lines =
            run(&sv(&["install", "--extension-id", ID, "--browser", "all", "--binary", "/abs/wmlhost"]), tmp.path())
                .unwrap();
        assert_eq!(lines.len(), 5);
        for b in [Browser::Chrome, Browser::ChromeBeta, Browser::Chromium, Browser::Brave, Browser::Edge] {
            assert!(file_for(b, tmp.path()).exists());
        }
    }

    #[test]
    fn install_dry_run_writes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let lines =
            run(&sv(&["install", "--extension-id", ID, "--binary", "/abs/wmlhost", "--dry-run"]), tmp.path()).unwrap();
        assert!(lines.iter().any(|l| l.contains("NativeMessagingHosts")));
        assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
    }

    #[test]
    fn install_refuses_a_bad_id_and_writes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(run(&sv(&["install", "--extension-id", "nope", "--binary", "/abs/w"]), tmp.path()).is_err());
        assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
    }

    #[test]
    fn uninstall_removes_and_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        run(&sv(&["install", "--extension-id", ID, "--browser", "all", "--binary", "/abs/wmlhost"]), tmp.path())
            .unwrap();
        let lines = run(&sv(&["uninstall", "--browser", "all"]), tmp.path()).unwrap();
        assert_eq!(lines.len(), 5);
        assert!(lines.iter().all(|l| l.starts_with("removed ")));
        assert!(!file_for(Browser::Chrome, tmp.path()).exists());
        assert_eq!(run(&sv(&["uninstall", "--browser", "all"]), tmp.path()).unwrap(), Vec::<String>::new());
    }

    #[test]
    fn manifest_dir_chrome_path() {
        let home = Path::new("/h");
        let want = if cfg!(target_os = "macos") {
            "/h/Library/Application Support/Google/Chrome/NativeMessagingHosts"
        } else {
            "/h/.config/google-chrome/NativeMessagingHosts"
        };
        assert_eq!(manifest_dir(Browser::Chrome, home), PathBuf::from(want));
    }

    #[test]
    fn bad_arguments_are_a_parse_error() {
        assert_eq!(main(&sv(&["install"])), 2);
    }
}
