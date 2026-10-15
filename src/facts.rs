//! facts.rs — resolving what a call names: `argv[0]` after the `PATH` lookup, `cwd` and each marked path argument
//! resolved with `realpath` and judged against the workspace roots, and the secret-name check. Facts only: whether the
//! call may run is the worker's decision (SHELL.md, "The split").

use std::ffi::OsStr;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

/// Resolves a workspace root: absolute, an existing directory, never `/`. Returns its realpath.
pub fn resolve_root(given: &str) -> Result<PathBuf, String> {
    let p = Path::new(given);
    if !p.is_absolute() {
        return Err(format!("root {given:?} is not absolute"));
    }
    let real = p.canonicalize().map_err(|e| format!("root {given:?}: {e}"))?;
    if !real.is_dir() {
        return Err(format!("root {given:?} is not a directory"));
    }
    if real.parent().is_none() {
        return Err("the filesystem root cannot be a workspace root".into());
    }
    Ok(real)
}

/// `p` is one of the roots or beneath one, compared by path COMPONENT (`/a/bc` is not under `/a/b`). Both sides are
/// realpaths.
pub fn in_roots(p: &Path, roots: &[PathBuf]) -> bool {
    roots.iter().any(|r| p.starts_with(r))
}

/// A path argument or `cwd` after resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// The realpath, or for a path that does not exist yet, its deepest existing ancestor's realpath plus the rest.
    pub path: PathBuf,
    pub exists: bool,
    /// False when the part that does not exist yet could still step elsewhere: it contains `..`, or its first
    /// component is a dangling symlink. Such a path is never `inRoot`.
    pub clean: bool,
}

/// Resolves `given` against `cwd` (already a realpath), following symlinks the way the child's own open will.
pub fn resolve_path(given: &str, cwd: &Path) -> Resolved {
    let joined = if Path::new(given).is_absolute() { PathBuf::from(given) } else { cwd.join(given) };
    if let Ok(real) = joined.canonicalize() {
        return Resolved { path: real, exists: true, clean: true };
    }
    // The deepest prefix that resolves; everything after it does not exist (or cannot be resolved).
    let comps: Vec<Component> = joined.components().collect();
    for i in (1..comps.len()).rev() {
        let prefix: PathBuf = comps[..i].iter().collect();
        let Ok(base) = prefix.canonicalize() else { continue };
        let rest = &comps[i..];
        let mut clean = rest.iter().all(|c| matches!(c, Component::Normal(_)));
        // canonicalize failed on prefix + rest[0], yet something may sit there: a dangling symlink (it points
        // somewhere that a write would create), or an entry we may not traverse. Either way, not vouched for.
        if std::fs::symlink_metadata(base.join(rest[0])).is_ok() {
            clean = false;
        }
        let path = rest.iter().fold(base, |acc, c| acc.join(c));
        return Resolved { path, exists: false, clean };
    }
    Resolved { path: joined, exists: false, clean: false }
}

/// `argv[0]` resolved to the file that will run. A name with a `/` is taken relative to `cwd`; a bare name is looked
/// up in `path_dirs` in order, skipping relative entries, so a program named `git` in the cwd is never picked by
/// accident. The result is a realpath to an executable regular file.
pub fn resolve_program(argv0: &str, cwd: &Path, path_dirs: &[PathBuf]) -> io::Result<PathBuf> {
    let not_found = || io::Error::new(io::ErrorKind::NotFound, format!("{argv0}: not found"));
    if argv0.is_empty() {
        return Err(not_found());
    }
    if argv0.contains('/') {
        let p = if Path::new(argv0).is_absolute() { PathBuf::from(argv0) } else { cwd.join(argv0) };
        return executable(&p).ok_or_else(not_found);
    }
    path_dirs.iter().filter(|d| d.is_absolute()).find_map(|d| executable(&d.join(argv0))).ok_or_else(not_found)
}

fn executable(p: &Path) -> Option<PathBuf> {
    let real = p.canonicalize().ok()?;
    let md = std::fs::metadata(&real).ok()?;
    (md.is_file() && md.permissions().mode() & 0o111 != 0).then_some(real)
}

/// File names that look like credentials, matched case-insensitively against the last component. Broad on purpose:
/// a false positive costs a question, a false negative a disclosure.
const SECRET_NAMES: &[&str] = &[
    ".env",
    ".envrc",
    ".netrc",
    "_netrc",
    ".npmrc",
    ".pypirc",
    ".pgpass",
    ".git-credentials",
    ".htpasswd",
    "credentials",
    "credentials.json",
    "credentials.db",
    "known_hosts",
    "authorized_keys",
    "hosts.yml",
];

/// Suffixes of credential files (`*.pem`, `*.key`, …), matched case-insensitively.
const SECRET_SUFFIXES: &[&str] =
    &[".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".kdbx", ".gpg", ".asc", ".ovpn", ".tfvars"];

/// Directories whose whole contents are credentials, matched as any component of the path.
const SECRET_DIRS: &[&str] = &[".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker", ".password-store", "Keychains"];

/// Whether a path looks like a credential: by the name of its last component (`.env`, `.env.local`, `*.pem`, `id_*`,
/// …) or by any component being a credentials directory (`.ssh`, `.aws`, …). SHELL.md, "Workspace roots".
pub fn looks_secret(p: &Path) -> bool {
    let comps: Vec<String> = p
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(lower(s)),
            _ => None,
        })
        .collect();
    if comps.iter().any(|c| SECRET_DIRS.iter().any(|d| c == &d.to_lowercase())) {
        return true;
    }
    if comps.windows(2).any(|w| w[0] == ".config" && (w[1] == "gcloud" || w[1] == "gh")) {
        return true;
    }
    let Some(name) = comps.last() else { return false };
    SECRET_NAMES.contains(&name.as_str())
        || name.starts_with(".env.")
        || name.starts_with("id_")
        || SECRET_SUFFIXES.iter().any(|s| name.ends_with(s))
}

fn lower(s: &OsStr) -> String {
    s.to_string_lossy().to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- roots ---

    #[test]
    fn a_root_must_be_absolute_existing_and_not_slash() {
        let d = tempfile::tempdir().unwrap();
        assert!(resolve_root(d.path().to_str().unwrap()).is_ok());
        assert!(resolve_root("relative/dir").is_err());
        assert!(resolve_root("/").is_err());
        assert!(resolve_root("/no/such/dir/anywhere").is_err());
        let f = d.path().join("file");
        std::fs::write(&f, "").unwrap();
        assert!(resolve_root(f.to_str().unwrap()).is_err());
    }

    #[test]
    fn in_roots_compares_components_not_strings() {
        let roots = vec![PathBuf::from("/a/b")];
        assert!(in_roots(Path::new("/a/b"), &roots));
        assert!(in_roots(Path::new("/a/b/c"), &roots));
        assert!(!in_roots(Path::new("/a/bc"), &roots));
        assert!(!in_roots(Path::new("/a"), &roots));
    }

    // --- path resolution ---

    fn real(d: &tempfile::TempDir) -> PathBuf {
        d.path().canonicalize().unwrap()
    }

    #[test]
    fn an_existing_path_is_its_realpath() {
        let d = tempfile::tempdir().unwrap();
        let root = real(&d);
        std::fs::create_dir(root.join("sub")).unwrap();
        let r = resolve_path("sub/../sub", &root);
        assert_eq!(r, Resolved { path: root.join("sub"), exists: true, clean: true });
    }

    #[test]
    fn a_symlink_out_of_the_root_resolves_outside() {
        let d = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        let root = real(&d);
        std::os::unix::fs::symlink(real(&out), root.join("link")).unwrap();
        let r = resolve_path("link", &root);
        assert_eq!(r.path, real(&out));
        assert!(!in_roots(&r.path, std::slice::from_ref(&root)));
        // and through it, to a file that does not exist yet
        let r = resolve_path("link/new.txt", &root);
        assert_eq!(r.path, real(&out).join("new.txt"));
        assert!(!r.exists);
    }

    #[test]
    fn a_new_path_is_its_existing_ancestor_plus_the_rest() {
        let d = tempfile::tempdir().unwrap();
        let root = real(&d);
        let r = resolve_path("a/b/c.txt", &root);
        assert_eq!(r, Resolved { path: root.join("a/b/c.txt"), exists: false, clean: true });
    }

    #[test]
    fn a_new_path_with_dot_dot_after_the_missing_part_is_not_clean() {
        let d = tempfile::tempdir().unwrap();
        let root = real(&d);
        let r = resolve_path("missing/../../etc", &root);
        assert!(!r.clean);
    }

    #[test]
    fn a_dangling_symlink_is_not_clean() {
        let d = tempfile::tempdir().unwrap();
        let root = real(&d);
        std::os::unix::fs::symlink("/nonexistent/elsewhere", root.join("dangling")).unwrap();
        let r = resolve_path("dangling", &root);
        assert!(!r.exists);
        assert!(!r.clean);
        let r = resolve_path("dangling/file", &root);
        assert!(!r.clean);
    }

    // --- program lookup ---

    #[test]
    fn a_bare_name_is_found_on_path_and_never_in_the_cwd() {
        let d = tempfile::tempdir().unwrap();
        let cwd = real(&d);
        let fake = cwd.join("ls");
        std::fs::write(&fake, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let p = resolve_program("ls", &cwd, &[PathBuf::from("/bin"), PathBuf::from("/usr/bin")]).unwrap();
        assert_ne!(p, fake);
        // a relative PATH entry (".") is skipped
        assert!(resolve_program("ls", &cwd, &[PathBuf::from(".")]).is_err());
        // an explicit ./ls is the cwd's, by the caller's own words
        assert_eq!(resolve_program("./ls", &cwd, &[]).unwrap(), fake);
    }

    #[test]
    fn a_non_executable_or_missing_program_is_not_found() {
        let d = tempfile::tempdir().unwrap();
        let cwd = real(&d);
        std::fs::write(cwd.join("plain"), "").unwrap();
        assert!(resolve_program("./plain", &cwd, &[]).is_err());
        assert!(resolve_program("no-such-program-xyz", &cwd, &[PathBuf::from("/usr/bin")]).is_err());
        assert!(resolve_program("", &cwd, &[PathBuf::from("/usr/bin")]).is_err());
        assert!(resolve_program("/tmp", &cwd, &[]).is_err());
    }

    // --- secret names ---

    #[test]
    fn secret_looking_paths_are_flagged() {
        for p in [
            "/r/.env",
            "/r/.ENV",
            "/r/.env.local",
            "/r/certs/server.pem",
            "/r/tls.KEY",
            "/home/u/.ssh/config",
            "/home/u/.ssh",
            "/home/u/.aws/credentials",
            "/r/id_rsa",
            "/r/id_ed25519.pub",
            "/home/u/.config/gh/hosts.yml",
            "/home/u/.config/gcloud/application_default_credentials.json",
            "/r/.git-credentials",
            "/r/.netrc",
            "/Users/u/Library/Keychains/login.keychain-db",
        ] {
            assert!(looks_secret(Path::new(p)), "{p}");
        }
    }

    #[test]
    fn ordinary_paths_are_not_flagged() {
        for p in ["/r/src/main.rs", "/r/README.md", "/r/environment.ts", "/r/.envoy/x", "/r/keys.rs", "/r/.gitignore"] {
            assert!(!looks_secret(Path::new(p)), "{p}");
        }
    }
}
