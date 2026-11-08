//! credential.rs — the credentials the host holds and injects into a call, by provider: which program may name one,
//! which manifest bytes it is honoured for, how its token is obtained outside the sandbox, and what the credentialed
//! profile adds to the call's environment. A manifest names only the provider and its ports; the rest is code here.
//!
//! The token never crosses the protocol and is never logged: it is read from the provider's own program at launch,
//! after the verdict, and lives only in the child's environment. No token is `SecretUnavailable` and the call never
//! runs, so it never runs anonymously by surprise.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::manifest::Manifest;

/// A credential the host knows how to obtain and inject.
#[derive(Debug)]
pub struct Provider {
    /// The name a manifest's `credential.provider` gives.
    pub name: &'static str,
    /// The one program that may name it: the manifest's `program`, `argv[0]`'s basename and the resolved binary's name.
    pub program: &'static str,
    /// The ports its profile may connect to; a manifest's `network.ports` is a subset.
    pub ports: &'static [u16],
    /// What `done`'s envelope reports as `profile`.
    pub profile: &'static str,
    /// The resolved program's arguments that print the token, run unconfined at launch.
    pub token_args: &'static [&'static str],
    /// The variable that receives the token.
    pub token_env: &'static str,
    /// The variable that points the program at a throwaway config directory under the call's temp dir, so none of
    /// the person's own config (pager, browser, editor, aliases) is read.
    pub config_env: &'static str,
    /// Fixed settings: no prompt, no update check, no telemetry.
    pub fixed_env: &'static [(&'static str, &'static str)],
    /// The host's own variables the TOKEN FETCH sees (where the person's program keeps its config); never the call.
    pub fetch_pass: &'static [&'static str],
}

/// Every provider this host holds.
pub const PROVIDERS: &[Provider] = &[Provider {
    name: "github",
    program: "gh",
    ports: &[443],
    profile: "credentialed:github",
    token_args: &["auth", "token", "--hostname", "github.com"],
    token_env: "GH_TOKEN",
    config_env: "GH_CONFIG_DIR",
    fixed_env: &[("GH_PROMPT_DISABLED", "1"), ("GH_NO_UPDATE_NOTIFIER", "1"), ("GH_TELEMETRY", "0")],
    fetch_pass: &["GH_CONFIG_DIR", "XDG_CONFIG_HOME", "GH_TOKEN", "GITHUB_TOKEN"],
}];

/// The manifests a credential is honoured for: byte copies of window-ml's shipped ones, pinned with the rest of
/// `vectors/program-manifests/` (`tests/manifest_vectors.rs`). A unit test holds every vector manifest that names a
/// credential to this list.
const PINNED: &[(&str, &[u8])] = &[("gh.json", include_bytes!("../vectors/program-manifests/manifests/gh.json"))];

/// How long the token fetch may take, its output included. A Keychain dialog would block it; none fired when measured
/// (gh 2.103.0 on macOS 25.6, keyring storage, a scrubbed environment and no terminal: exit 0 in under a second).
pub const TOKEN_TIMEOUT: Duration = Duration::from_secs(30);

/// The longest token accepted.
const MAX_TOKEN: usize = 1024;

/// A credential a spawn asked for and the host will honour: the provider and the ports its manifest names.
#[derive(Debug, Clone)]
pub struct Grant {
    pub provider: &'static Provider,
    pub ports: Vec<u16>,
}

/// The provider called `name`.
pub fn provider(name: &str) -> Option<&'static Provider> {
    PROVIDERS.iter().find(|p| p.name == name)
}

/// The sha256 of the pinned manifest bytes, lowercase hex, by file name.
pub fn pinned_hashes() -> Vec<(&'static str, String)> {
    PINNED.iter().map(|(n, b)| (*n, hex::encode(Sha256::digest(b)))).collect()
}

/// Whether the host honours `provider` for a call whose manifest's bytes hash to `manifest` (sha256, hex), with
/// `argv0` as given and `program` as resolved, `in_root` when that is inside a workspace root. Every check is a
/// refusal with its reason; nothing here falls back.
///
/// The token is read by running `program` UNCONFINED, so it must be the person's own: named bare (`gh`, found on
/// PATH) and outside every root, where a repository could not have planted it.
pub fn honour(
    provider_name: &str,
    manifest: &str,
    argv0: &str,
    program: &Path,
    in_root: bool,
) -> Result<Grant, String> {
    let Some(provider) = provider(provider_name) else {
        return Err(format!("this host holds no credential provider {provider_name:?}"));
    };
    let Some((_, bytes)) = PINNED.iter().find(|(_, b)| hex::encode(Sha256::digest(b)) == manifest) else {
        return Err("the manifest is not one this host pinned, so it names no credential here".into());
    };
    let m: Manifest = serde_json::from_slice(bytes).map_err(|e| format!("a pinned manifest does not parse: {e}"))?;
    if m.credential.as_ref().map(|c| c.provider.as_str()) != Some(provider.name) {
        return Err(format!("the manifest names no {} credential", provider.name));
    }
    let resolved = program.file_name().and_then(|s| s.to_str());
    if m.program != provider.program || argv0 != provider.program || resolved != Some(provider.program) {
        return Err(format!(
            "the {} credential is {}'s alone, named bare and found on PATH",
            provider.name, provider.program
        ));
    }
    if in_root {
        return Err(format!("{} is inside a workspace root: the repository's, not the person's", program.display()));
    }
    let ports = m.network.map(|n| n.ports).unwrap_or_default();
    if ports.is_empty() || !ports.iter().all(|p| provider.ports.contains(p)) {
        return Err(format!("the manifest's ports are not a subset of {:?}", provider.ports));
    }
    Ok(Grant { provider, ports })
}

/// The token, from running `program` (the call's resolved binary) with the provider's arguments, unconfined, in a
/// scrubbed environment: `base` (the call's whitelisted base, PATH included) plus the provider's `fetch_pass` from
/// the host's own environment. stdout is the token; stderr is discarded unread. The error never carries the output.
pub fn fetch_token(
    p: &Provider,
    program: &Path,
    base: &[(String, String)],
    host: &dyn Fn(&str) -> Option<String>,
) -> Result<String, String> {
    let mut c = Command::new(program);
    c.args(p.token_args).env_clear().current_dir("/").stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
    c.envs(base.iter().map(|(k, v)| (k, v)));
    for k in p.fetch_pass {
        if let Some(v) = host(k) {
            c.env(k, v);
        }
    }
    c.envs(p.fixed_env.iter().copied());
    let mut child = c.spawn().map_err(|e| format!("{} could not start: {e}", program.display()))?;
    let mut out = child.stdout.take().expect("stdout is piped");
    // Read on a thread with a deadline: a descendant that kept stdout open must not hold the launch forever.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = out.by_ref().take(MAX_TOKEN as u64 + 2).read_to_end(&mut b);
        let _ = tx.send(b);
    });
    let deadline = Instant::now() + TOKEN_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{} gave no token within {}s", p.program, TOKEN_TIMEOUT.as_secs()));
            }
            Err(e) => return Err(format!("{}: {e}", p.program)),
        }
    };
    let bytes = rx.recv_timeout(deadline.saturating_duration_since(Instant::now())).unwrap_or_default();
    if !status.success() {
        return Err(format!("{} {} exited {status}: not logged in?", p.program, p.token_args.join(" ")));
    }
    token_from(&bytes).ok_or_else(|| format!("{} {} printed no token", p.program, p.token_args.join(" ")))
}

/// The token in a fetch's stdout: one line of printable ASCII with no space, at most `MAX_TOKEN` bytes.
fn token_from(b: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(b).ok()?;
    let s = s.strip_suffix('\n').unwrap_or(s);
    let s = s.strip_suffix('\r').unwrap_or(s);
    (!s.is_empty() && s.len() <= MAX_TOKEN && s.bytes().all(|c| c.is_ascii_graphic())).then(|| s.to_string())
}

/// What a credentialed `gh` may exec beside its own chain: `git`, the first on the call's PATH as gh finds it, and from
/// git's exec path `git` itself (how git runs its own subcommands) and the https remote helpers. Missing pieces are left
/// out, so a call that runs no git still starts; git over ssh stays impossible (no `ssh`, `~/.ssh` unreadable). A git
/// for which `in_root` holds is the repository's: none is added, and it is never run here (`--exec-path` runs
/// unconfined).
pub fn git_set(path: Option<&str>, in_root: &dyn Fn(&Path) -> bool) -> Vec<PathBuf> {
    let Some(git) = path.and_then(|p| {
        p.split(':').filter(|d| d.starts_with('/')).map(|d| Path::new(d).join("git")).find(|c| c.is_file())
    }) else {
        return vec![];
    };
    let git = std::fs::canonicalize(&git).unwrap_or(git);
    if in_root(&git) {
        return vec![];
    }
    let mut out = vec![git.clone()];
    let exec_path = Command::new(&git)
        .arg("--exec-path")
        .env_clear()
        .env("PATH", path.unwrap_or_default())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .current_dir("/")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output();
    if let Some(o) = exec_path.ok().filter(|o| o.status.success()) {
        let dir = PathBuf::from(String::from_utf8_lossy(&o.stdout).trim());
        for name in ["git", "git-remote-http", "git-remote-https"] {
            let c = dir.join(name);
            if c.is_file() {
                out.push(c);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gh_hash() -> String {
        pinned_hashes().into_iter().find(|(n, _)| *n == "gh.json").unwrap().1
    }

    // --- which calls a credential is honoured for ---

    #[test]
    fn every_vector_manifest_naming_a_credential_is_pinned_here() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors/program-manifests/manifests");
        for e in std::fs::read_dir(dir).unwrap() {
            let e = e.unwrap();
            let bytes = std::fs::read(e.path()).unwrap();
            let m: Manifest = serde_json::from_slice(&bytes).unwrap();
            let name = e.file_name().to_string_lossy().into_owned();
            let pinned = PINNED.iter().find(|(n, _)| *n == name).map(|(_, b)| *b);
            if m.credential.is_some() {
                assert_eq!(pinned, Some(bytes.as_slice()), "{name} names a credential: pin its bytes in PINNED");
            }
        }
    }

    #[test]
    fn gh_is_honoured_for_its_pinned_manifest_and_its_own_binary() {
        let g = honour("github", &gh_hash(), "gh", Path::new("/opt/homebrew/Cellar/gh/2.103.0/bin/gh"), false).unwrap();
        assert_eq!(g.provider.name, "github");
        assert_eq!(g.ports, [443]);
    }

    #[test]
    fn every_other_request_is_refused() {
        let h = gh_hash();
        let gh = Path::new("/x/gh");
        assert!(honour("aws", &h, "gh", gh, false).unwrap_err().contains("no credential provider"));
        assert!(honour("github", &"0".repeat(64), "gh", gh, false).unwrap_err().contains("not one this host pinned"));
        assert!(honour("github", &h.to_uppercase(), "gh", gh, false).is_err(), "the hash is compared as given");
        // another program's name, as argv[0] or as the binary it resolved to
        assert!(honour("github", &h, "curl", gh, false).unwrap_err().contains("gh's alone"));
        assert!(honour("github", &h, "gh", Path::new("/usr/bin/curl"), false).unwrap_err().contains("gh's alone"));
        assert!(honour("github", &h, "gh", Path::new("/x/gh-wrapper"), false).is_err());
        // a path, not the bare name: `./gh` is whatever the repository put there
        for argv0 in ["./gh", "/x/gh", "bin/gh"] {
            assert!(honour("github", &h, argv0, gh, false).unwrap_err().contains("named bare"), "{argv0}");
        }
        // a gh inside a root is run unconfined for its token: refused
        assert!(honour("github", &h, "gh", gh, true).unwrap_err().contains("inside a workspace root"));
    }

    #[test]
    fn a_git_inside_a_root_is_neither_run_nor_added() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let marker = d.path().join("ran");
        let git = d.path().join("git");
        std::fs::write(&git, format!("#!/bin/sh\necho > {}\n", marker.display())).unwrap();
        std::fs::set_permissions(&git, std::fs::Permissions::from_mode(0o755)).unwrap();
        let root = d.path().canonicalize().unwrap();
        let path = d.path().to_string_lossy().into_owned();
        assert_eq!(git_set(Some(&path), &|p: &Path| p.starts_with(&root)), Vec::<PathBuf>::new());
        assert!(!marker.exists(), "a repository's git ran unconfined");
    }

    // --- the token ---

    #[test]
    fn a_token_is_one_printable_line() {
        assert_eq!(token_from(b"gho_abc123\n").as_deref(), Some("gho_abc123"));
        assert_eq!(token_from(b"gho_abc123\r\n").as_deref(), Some("gho_abc123"));
        assert_eq!(token_from(b"gho_abc123").as_deref(), Some("gho_abc123"));
        for bad in [&b""[..], b"\n", b"a b\n", b"a\nb\n", b"a\tb", b"\xff\n", &[b'a'; MAX_TOKEN + 1]] {
            assert_eq!(token_from(bad), None, "{bad:?}");
        }
    }

    fn script(dir: &Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join("gh");
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    #[test]
    fn the_fetch_runs_the_programs_token_arguments_in_a_scrubbed_environment() {
        let d = tempfile::tempdir().unwrap();
        // prints the token only for the provider's exact argv, and only when the scrub held
        let gh = script(
            d.path(),
            r#"[ "$*" = "auth token --hostname github.com" ] || exit 3
[ -z "$LEAK" ] || exit 4
[ "$GH_PROMPT_DISABLED" = 1 ] || exit 5
[ "$GH_CONFIG_DIR" = /person/gh ] || exit 6
echo tok_123"#,
        );
        let host = |k: &str| match k {
            "LEAK" => Some("x".to_string()),
            "GH_CONFIG_DIR" => Some("/person/gh".to_string()),
            _ => None,
        };
        let base = vec![("PATH".to_string(), "/usr/bin:/bin".to_string())];
        assert_eq!(fetch_token(&PROVIDERS[0], &gh, &base, &host).as_deref(), Ok("tok_123"));
    }

    #[test]
    fn a_failed_or_empty_fetch_is_an_error_that_carries_none_of_the_output() {
        let d = tempfile::tempdir().unwrap();
        let base = vec![("PATH".to_string(), "/usr/bin:/bin".to_string())];
        let none = |_: &str| None;
        let gh = script(d.path(), "echo secret_on_stdout; echo secret_on_stderr >&2; exit 1");
        let e = fetch_token(&PROVIDERS[0], &gh, &base, &none).unwrap_err();
        assert!(!e.contains("secret"), "{e}");
        let gh = script(d.path(), "exit 0");
        assert!(fetch_token(&PROVIDERS[0], &gh, &base, &none).unwrap_err().contains("printed no token"));
        let gh = script(d.path(), "echo 'two words'");
        let e = fetch_token(&PROVIDERS[0], &gh, &base, &none).unwrap_err();
        assert!(!e.contains("two words"), "{e}");
    }
}
