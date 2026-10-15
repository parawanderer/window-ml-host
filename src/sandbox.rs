//! sandbox.rs — the OS sandbox each call runs under: a Seatbelt profile generated per call on macOS (`sandbox-exec`),
//! bubblewrap on Linux. Writes are confined to the workspace roots and the call's own temp directory, the network is
//! denied, credential stores are unreadable, and the files in a root that would run code later (`.git/hooks`,
//! `.git/config`, shell rc files, editor and agent config) are not writable.
//!
//! On by default and FAILS CLOSED: when the sandbox is not available a call reports `sandboxed: false` and the worker
//! asks; when a sandboxed call's sandbox fails to start, the call fails. Nothing here ever falls back to running a
//! program unsandboxed. The base Seatbelt profile follows Anthropic's `sandbox-runtime` (Apache-2.0), which SHELL.md
//! names as the reference.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Which sandbox this platform uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Seatbelt,
    Bwrap,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Seatbelt => "seatbelt",
            Kind::Bwrap => "bwrap",
        }
    }
}

/// Whether the sandbox can run here, found once at start by actually running it.
#[derive(Debug, Clone)]
pub struct Availability {
    pub kind: Option<Kind>,
    /// The sandbox program (`/usr/bin/sandbox-exec`, a `bwrap`), when found.
    pub program: Option<PathBuf>,
    pub available: bool,
    /// Why not, when not.
    pub reason: Option<String>,
}

const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";
const BWRAP_CANDIDATES: &[&str] = &["/usr/bin/bwrap", "/bin/bwrap", "/usr/local/bin/bwrap"];

/// Finds the platform's sandbox and runs a trivial program under it, with the same kind of arguments a call uses, so
/// "available" means "a call would start".
pub fn probe() -> Availability {
    let unavailable =
        |kind, program, reason: String| Availability { kind, program, available: false, reason: Some(reason) };
    if cfg!(target_os = "macos") {
        let prog = PathBuf::from(SANDBOX_EXEC);
        if !prog.exists() {
            return unavailable(Some(Kind::Seatbelt), None, format!("{SANDBOX_EXEC} not found"));
        }
        let profile = format!("{}\n(allow file-read*)\n", base_profile());
        return run_probe(Kind::Seatbelt, prog, &["-p".into(), profile.into(), "/usr/bin/true".into()]);
    }
    if cfg!(target_os = "linux") {
        let Some(prog) = BWRAP_CANDIDATES.iter().map(PathBuf::from).find(|p| p.exists()) else {
            return unavailable(Some(Kind::Bwrap), None, "bwrap not found (install bubblewrap)".into());
        };
        let mut args: Vec<OsString> = bwrap_fixed_args().into_iter().map(OsString::from).collect();
        args.extend(["--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--", "/bin/true"].map(OsString::from));
        return run_probe(Kind::Bwrap, prog, &args);
    }
    unavailable(None, None, "no sandbox on this platform".into())
}

fn run_probe(kind: Kind, prog: PathBuf, args: &[OsString]) -> Availability {
    let out = Command::new(&prog).args(args).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).output();
    match out {
        Ok(o) if o.status.success() => {
            Availability { kind: Some(kind), program: Some(prog), available: true, reason: None }
        }
        Ok(o) => Availability {
            kind: Some(kind),
            program: Some(prog),
            available: false,
            reason: Some(format!(
                "{} failed to start a program: {}",
                kind.name(),
                String::from_utf8_lossy(&o.stderr).trim()
            )),
        },
        Err(e) => Availability { kind: Some(kind), program: Some(prog), available: false, reason: Some(e.to_string()) },
    }
}

/// What one call's sandbox allows, all realpaths.
#[derive(Debug, Clone)]
pub struct Plan {
    /// Writable: the workspace roots.
    pub roots: Vec<PathBuf>,
    /// Writable: the call's own temp directory (its `TMPDIR`).
    pub tmp: PathBuf,
    /// Neither readable nor writable: the session's held output.
    pub hidden: Vec<PathBuf>,
    /// Secret-looking paths the call NAMES (its marked path arguments flagged `secret`): readable despite the
    /// credential denies, because the person approved this exact call with them shown.
    pub allow_read: Vec<PathBuf>,
    /// The home directory, for the credential stores under it (Linux masks them by path).
    pub home: Option<PathBuf>,
}

/// The command that runs `program` with `args` under the sandbox in `cwd`. `program` is a realpath.
pub fn wrap(
    av: &Availability,
    plan: &Plan,
    program: &Path,
    args: &[String],
    cwd: &Path,
) -> Option<(PathBuf, Vec<OsString>)> {
    let sandbox = av.program.clone()?;
    match av.kind? {
        Kind::Seatbelt => {
            let mut a: Vec<OsString> = vec!["-p".into(), seatbelt_profile(plan).into(), program.into()];
            a.extend(args.iter().map(OsString::from));
            Some((sandbox, a))
        }
        Kind::Bwrap => {
            let mut a: Vec<OsString> = bwrap_args(plan, cwd);
            a.push("--".into());
            a.push(program.into());
            a.extend(args.iter().map(OsString::from));
            Some((sandbox, a))
        }
    }
}

// --- Seatbelt (macOS) ---

/// Everything a profile allows before the filesystem and network rules: process, IPC, the mach services and sysctls
/// ordinary command-line programs need. From `sandbox-runtime`'s profile, minus its PTY, Apple Events and proxy parts.
fn base_profile() -> String {
    let lines = [
        "(version 1)",
        "(deny default)",
        "(allow process-exec)",
        "(allow process-fork)",
        "(allow process-info* (target same-sandbox))",
        "(allow signal (target same-sandbox))",
        "(allow mach-priv-task-port (target same-sandbox))",
        "(allow user-preference-read)",
        "(allow mach-lookup",
        "  (global-name \"com.apple.audio.systemsoundserver\")",
        "  (global-name \"com.apple.distributed_notifications@Uv3\")",
        "  (global-name \"com.apple.FontObjectsServer\")",
        "  (global-name \"com.apple.fonts\")",
        "  (global-name \"com.apple.logd\")",
        "  (global-name \"com.apple.lsd.mapdb\")",
        "  (global-name \"com.apple.PowerManagement.control\")",
        "  (global-name \"com.apple.system.logger\")",
        "  (global-name \"com.apple.system.notification_center\")",
        "  (global-name \"com.apple.system.opendirectoryd.libinfo\")",
        "  (global-name \"com.apple.system.opendirectoryd.membership\")",
        "  (global-name \"com.apple.bsd.dirhelper\")",
        "  (global-name \"com.apple.securityd.xpc\")",
        "  (global-name \"com.apple.coreservices.launchservicesd\"))",
        "(allow ipc-posix-shm)",
        "(allow ipc-posix-sem)",
        "(allow iokit-open (iokit-registry-entry-class \"IOSurfaceRootUserClient\") (iokit-registry-entry-class \"RootDomainUserClient\") (iokit-user-client-class \"IOSurfaceSendRight\"))",
        "(allow iokit-get-properties)",
        "(allow system-socket (require-all (socket-domain AF_SYSTEM) (socket-protocol 2)))",
        "(allow sysctl-read)",
        "(allow distributed-notification-post)",
        "(allow file-ioctl (literal \"/dev/null\") (literal \"/dev/zero\") (literal \"/dev/random\") (literal \"/dev/urandom\") (literal \"/dev/dtracehelper\"))",
    ];
    lines.join("\n")
}

/// Path segments under which nothing is readable: credential stores. Matched anywhere in a path, so a copy or a moved
/// home is covered the same way. A segment is `[^/]*`-free text, matched case-insensitively.
const DENY_READ_DIRS: &[&str] = &[
    ".ssh",
    ".gnupg",
    ".aws",
    ".azure",
    ".password-store",
    "Library/Keychains",
    ".config/gh",
    ".config/gcloud",
    ".kube",
    ".docker",
];

/// File names that are never readable: credential files outside a credential directory.
const DENY_READ_FILES: &[&str] = &[".netrc", ".git-credentials", ".pgpass"];

/// Regexes (POSIX ERE, case-insensitive by construction) for paths in a root that, written, run code later: git's
/// hooks and config, shell and tool rc files, editor and agent configuration. From `sandbox-runtime`'s mandatory
/// denies. Matched anywhere in a path, so renaming a parent cannot carry one out from under its rule.
fn deny_write_regexes() -> Vec<String> {
    let mut v = vec![
        format!("/{}(/|$)", ci(".git/hooks")),
        format!("/{}$", ci(".git/config")),
        format!("/{}$", ci(".gitmodules")),
        format!("/{}(/|$)", ci(".vscode")),
        format!("/{}(/|$)", ci(".idea")),
        format!("/{}(/|$)", ci(".claude/commands")),
        format!("/{}(/|$)", ci(".claude/agents")),
        format!("/{}$", ci(".claude/settings.json")),
        format!("/{}$", ci(".claude/settings.local.json")),
    ];
    for f in [
        ".gitconfig",
        ".bashrc",
        ".bash_profile",
        ".zshrc",
        ".zprofile",
        ".profile",
        ".ripgreprc",
        ".mcp.json",
        ".envrc",
    ] {
        v.push(format!("/{}$", ci(f)));
    }
    v
}

/// A regex fragment matching `s` literally and case-insensitively (macOS filesystems are case-insensitive, and
/// Seatbelt's regexes are not).
fn ci(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if c.is_ascii_alphabetic() {
            out.push('[');
            out.push(c.to_ascii_lowercase());
            out.push(c.to_ascii_uppercase());
            out.push(']');
        } else if "\\.^$|()[]{}*+?".contains(c) {
            out.push('\\');
            out.push(c);
        } else {
            out.push(c);
        }
    }
    out
}

/// An SBPL string literal.
fn lit(p: &Path) -> String {
    let s = p.to_string_lossy();
    let mut out = String::from("\"");
    for c in s.chars() {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

/// An SBPL regex filter, `(regex "…")`, its pattern as an escaped string literal.
fn re(r: &str) -> String {
    format!("(regex {})", lit(Path::new(r)))
}

/// The profile for one call. Later rules win in SBPL, which the order below relies on.
pub fn seatbelt_profile(plan: &Plan) -> String {
    let mut p = vec![base_profile()];
    p.push("; network: nothing (deny default covers network*)".into());
    p.push("; reads: everywhere, except credential stores, unless the call names one".into());
    p.push("(allow file-read*)".into());
    let mut deny_read: Vec<String> = DENY_READ_DIRS.iter().map(|d| re(&format!("/{}(/|$)", ci(d)))).collect();
    deny_read.extend(DENY_READ_FILES.iter().map(|f| re(&format!("/{}$", ci(f)))));
    deny_read.extend(plan.hidden.iter().map(|h| format!("(subpath {})", lit(h))));
    p.push(format!("(deny file-read* {})", deny_read.join(" ")));
    if !plan.allow_read.is_empty() {
        let allow: Vec<String> = plan.allow_read.iter().map(|a| format!("(literal {})", lit(a))).collect();
        p.push(format!("(allow file-read* {})", allow.join(" ")));
    }
    p.push("; writes: the roots and the call's temp dir, never what would run code later".into());
    let mut write: Vec<String> = plan.roots.iter().map(|r| format!("(subpath {})", lit(r))).collect();
    write.push(format!("(subpath {})", lit(&plan.tmp)));
    write.extend(
        ["(literal \"/dev/null\")", "(literal \"/dev/stdout\")", "(literal \"/dev/stderr\")"].map(String::from),
    );
    write.push(re("^/dev/fd/"));
    p.push(format!("(allow file-write* {})", write.join(" ")));
    let deny_write: Vec<String> = deny_write_regexes().iter().map(|r| re(r)).collect();
    p.push(format!("(deny file-write* {})", deny_write.join(" ")));
    // Renaming `.git` itself is an unlink of that path; with this, a hook cannot be planted by moving the directory.
    p.push(format!("(deny file-write-unlink {})", re(&format!("/{}$", ci(".git")))));
    if !plan.hidden.is_empty() {
        let hidden: Vec<String> = plan.hidden.iter().map(|h| format!("(subpath {})", lit(h))).collect();
        p.push(format!("(deny file-write* {})", hidden.join(" ")));
    }
    p.join("\n")
}

// --- bubblewrap (Linux) ---

fn bwrap_fixed_args() -> Vec<&'static str> {
    vec![
        "--new-session",
        "--die-with-parent",
        "--unshare-net",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup-try",
        "--cap-drop",
        "ALL",
    ]
}

/// bubblewrap's arguments for one call: the whole filesystem read-only, the roots and temp dir writable, the files in
/// a root that would run code later re-bound read-only, credential stores and the held output masked. Unlike
/// Seatbelt's regexes, these are paths that exist NOW at the top of each root; see LIMITS in docs/SANDBOX.md.
pub fn bwrap_args(plan: &Plan, cwd: &Path) -> Vec<OsString> {
    let mut a: Vec<OsString> = bwrap_fixed_args().into_iter().map(OsString::from).collect();
    let mut push = |xs: &[&OsString]| a.extend(xs.iter().map(|x| (*x).clone()));
    let s = |x: &str| OsString::from(x);
    push(&[&s("--ro-bind"), &s("/"), &s("/"), &s("--dev"), &s("/dev"), &s("--proc"), &s("/proc")]);
    for r in plan.roots.iter().chain(std::iter::once(&plan.tmp)) {
        push(&[&s("--bind"), &r.clone().into(), &r.clone().into()]);
    }
    for r in &plan.roots {
        for rel in [
            ".git/hooks",
            ".git/config",
            ".gitmodules",
            ".vscode",
            ".idea",
            ".claude",
            ".mcp.json",
            ".envrc",
            ".bashrc",
            ".zshrc",
            ".profile",
        ] {
            let p = r.join(rel);
            if std::fs::symlink_metadata(&p).is_ok_and(|m| !m.file_type().is_symlink()) {
                push(&[&s("--ro-bind"), &p.clone().into(), &p.into()]);
            }
        }
    }
    let mut masks: Vec<PathBuf> = plan.hidden.clone();
    if let Some(home) = &plan.home {
        masks.extend(DENY_READ_DIRS.iter().map(|d| home.join(d)));
        masks.extend(DENY_READ_FILES.iter().map(|f| home.join(f)));
    }
    for m in masks {
        if plan.allow_read.iter().any(|a| a.starts_with(&m)) {
            continue;
        }
        match std::fs::symlink_metadata(&m) {
            Ok(md) if md.is_dir() => push(&[&s("--tmpfs"), &m.into()]),
            Ok(md) if md.is_file() => push(&[&s("--ro-bind"), &s("/dev/null"), &m.into()]),
            _ => {}
        }
    }
    push(&[&s("--chdir"), &cwd.into()]);
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- profile text ---

    fn plan() -> Plan {
        Plan {
            roots: vec![PathBuf::from("/w/proj")],
            tmp: PathBuf::from("/t/s/tmp/c1"),
            hidden: vec![PathBuf::from("/t/s/out")],
            allow_read: vec![],
            home: Some(PathBuf::from("/home/u")),
        }
    }

    #[test]
    fn the_profile_denies_by_default_and_writes_only_to_the_roots_and_tmp() {
        let p = seatbelt_profile(&plan());
        assert!(p.starts_with("(version 1)\n(deny default)"));
        assert!(!p.contains("(allow network"), "no network rule may be allowed");
        assert!(p.contains("(allow file-write* (subpath \"/w/proj\") (subpath \"/t/s/tmp/c1\")"));
        assert!(p.contains("(deny file-write* (subpath \"/t/s/out\"))"));
    }

    #[test]
    fn a_named_secret_is_re_allowed_after_the_credential_denies() {
        let mut pl = plan();
        pl.allow_read.push(PathBuf::from("/home/u/.ssh/id_ed25519.pub"));
        let p = seatbelt_profile(&pl);
        let deny = p.find("(deny file-read*").unwrap();
        let allow = p.find("(allow file-read* (literal \"/home/u/.ssh/id_ed25519.pub\"))").unwrap();
        assert!(allow > deny);
    }

    #[test]
    fn literals_and_regexes_are_escaped() {
        assert_eq!(lit(Path::new("/a\"b\\c")), "\"/a\\\"b\\\\c\"");
        assert_eq!(ci(".git/x"), "\\.[gG][iI][tT]/[xX]");
    }

    #[test]
    fn bwrap_masks_existing_credential_dirs_and_binds_the_roots() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir(home.path().join(".ssh")).unwrap();
        std::fs::write(home.path().join(".netrc"), "").unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join(".git/hooks")).unwrap();
        let pl = Plan {
            roots: vec![root.path().to_path_buf()],
            tmp: PathBuf::from("/tmp"),
            hidden: vec![],
            allow_read: vec![],
            home: Some(home.path().to_path_buf()),
        };
        let a: Vec<String> = bwrap_args(&pl, root.path()).iter().map(|s| s.to_string_lossy().into_owned()).collect();
        let joined = a.join(" ");
        assert!(joined.contains("--unshare-net"));
        assert!(joined.contains(&format!("--tmpfs {}", home.path().join(".ssh").display())));
        assert!(joined.contains(&format!("--ro-bind /dev/null {}", home.path().join(".netrc").display())));
        let hooks = root.path().join(".git/hooks").display().to_string();
        assert!(joined.contains(&format!("--ro-bind {hooks} {hooks}")));
        assert!(joined.find("--ro-bind / /").unwrap() < joined.find("--bind ").unwrap());
    }
}
