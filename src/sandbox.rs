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
    /// Linux only: the Landlock ABI a ruleset can be fully enforced at, when one can. `None` means the
    /// restriction is unavailable (no Landlock, or only a best-effort one), and a call asking for a
    /// bound narrower than the bwrap floor fails `SandboxFailed` rather than running unrestricted.
    pub landlock_abi: Option<i32>,
}

impl Availability {
    /// Whether this platform can hold every bound `plan` names. Seatbelt always can; Linux needs
    /// Landlock for anything narrower than the bwrap floor (and for the name-immutable top level).
    pub fn can_hold(&self, plan: &Plan) -> bool {
        match self.kind {
            Some(Kind::Seatbelt) => true,
            Some(Kind::Bwrap) => {
                self.landlock_abi.is_some() || (plan.write == WriteScope::Today && matches!(plan.exec, ExecScope::Any))
            }
            None => false,
        }
    }
}

/// What a call may write. `Roots` and `None` are NARROWER than today's floor (`Today`), never wider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteScope {
    /// The host's default floor for this call: bubblewrap's binds on Linux, the Seatbelt profile on
    /// macOS. What an ABSENT envelope means and what `done` reports then ("today", never "roots").
    Today,
    /// The roots with a NAME-IMMUTABLE top level (no create, remove or rename of any top-level name)
    /// and the protected names kept out of the grants beneath it. Needs Landlock on Linux.
    Roots,
    /// Only the call's temp dir.
    None,
}

/// What a call may exec. Both values are NARROWER than or equal to today's floor (`Any`), never wider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecScope {
    /// Today's floor: any program.
    Any,
    /// Only this set: the resolved program, its `#!` interpreters (and `env`'s target), each hashed path
    /// argument's own chain, and on Linux each ELF's `PT_INTERP`.
    ProgramOnly(Vec<PathBuf>),
}

/// The wire names of the scopes. `done` reports `wire`; `start`/`pipe` accept `parse`, which has no
/// "today": a worker names a bound or sends nothing.
impl WriteScope {
    pub fn wire(self) -> &'static str {
        match self {
            WriteScope::Today => "today",
            WriteScope::Roots => "roots",
            WriteScope::None => "none",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "roots" => Some(WriteScope::Roots),
            "none" => Some(WriteScope::None),
            _ => None,
        }
    }
}

impl ExecScope {
    pub fn wire(&self) -> &'static str {
        match self {
            ExecScope::Any => "any",
            ExecScope::ProgramOnly(_) => "program-only",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "any" => Some(ExecScope::Any),
            "program-only" => Some(ExecScope::ProgramOnly(Vec::new())),
            _ => None,
        }
    }
}

/// The worker's narrowing envelope, as `start`/`pipe` carry it. Both fields travel together; absent
/// means today's floor. The exec set is resolved at launch (`exec_set`), not here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Envelope {
    pub write: WriteScope,
    pub program_only: bool,
}

impl Envelope {
    pub fn json(self) -> serde_json::Value {
        serde_json::json!({ "write": self.write.wire(), "exec": if self.program_only { "program-only" } else { "any" } })
    }
    /// Today's floor, what an absent envelope means and what `done` reports then (`write: "today"`).
    pub fn today() -> Self {
        Envelope { write: WriteScope::Today, program_only: false }
    }
}

const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";
const BWRAP_CANDIDATES: &[&str] = &["/usr/bin/bwrap", "/bin/bwrap", "/usr/local/bin/bwrap"];

/// Finds the platform's sandbox and runs a trivial program under it, with the same kind of arguments a call uses, so
/// "available" means "a call would start".
pub fn probe() -> Availability {
    let unavailable = |kind, program, reason: String| Availability {
        kind,
        program,
        available: false,
        reason: Some(reason),
        landlock_abi: landlock_abi(),
    };
    if cfg!(target_os = "macos") {
        let prog = PathBuf::from(SANDBOX_EXEC);
        if !prog.exists() {
            return unavailable(Some(Kind::Seatbelt), None, format!("{SANDBOX_EXEC} not found"));
        }
        let profile = format!("{}\n(allow process-exec)\n(allow file-read*)\n", base_profile());
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
    let landlock_abi = landlock_abi();
    let out = Command::new(&prog).args(args).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).output();
    match out {
        Ok(o) if o.status.success() => {
            Availability { kind: Some(kind), program: Some(prog), available: true, reason: None, landlock_abi }
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
            landlock_abi,
        },
        Err(e) => Availability {
            kind: Some(kind),
            program: Some(prog),
            available: false,
            reason: Some(e.to_string()),
            landlock_abi,
        },
    }
}

/// Linux only: the Landlock ABI `wmlhost landlock-abi` can fully enforce our ruleset at, or `None`
/// (no Landlock, or one that would only enforce best-effort — treated as unavailable). Probed in a
/// child of our own binary because a ruleset cannot be tested without restricting the tester.
fn landlock_abi() -> Option<i32> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let exe = std::env::current_exe().ok()?;
    let out = Command::new(exe).arg("landlock-abi").stdin(Stdio::null()).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let n: i32 = String::from_utf8_lossy(&out.stdout).trim().parse().ok()?;
    (n > 0).then_some(n)
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
    /// The call may outlive the host (its owner-loss policy is "orphan"). Otherwise bubblewrap's `--die-with-parent`
    /// has the kernel end it with the host, however the host ended; the warden covers the rest (src/owners.rs).
    pub outlives_host: bool,
    /// What the call may write. `Roots` is today's floor; `None` is tmp alone.
    pub write: WriteScope,
    /// What the call may exec. `Any` is today's floor; `ProgramOnly` carries the resolved set.
    pub exec: ExecScope,
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
            // An envelope narrower than today's floor rides an `exec-under` shim inside bwrap, which
            // applies the Landlock ruleset the host computed. An ABSENT envelope is today's floor and
            // gets plain bwrap (the documented gap stays). Without Landlock a narrow plan is refused
            // (`can_hold`), never run wide.
            let narrow = plan.write != WriteScope::Today || !matches!(plan.exec, ExecScope::Any);
            if narrow {
                let abi = av.landlock_abi?;
                let exe = std::env::current_exe().ok()?;
                let rules = landlock_rules(plan, abi);
                let json = serde_json::to_string(&rules).ok()?;
                a.push(exe.into());
                a.push("exec-under".into());
                a.push(json.into());
                a.push("--".into());
            }
            a.push(program.into());
            a.extend(args.iter().map(OsString::from));
            Some((sandbox, a))
        }
    }
}

/// Top-level names in a root that are never writable: they run code later. Under `write: "roots"` the
/// whole top level is name-immutable anyway; these are also the names bubblewrap re-binds read-only,
/// and the ones the Landlock enumeration refuses to grant beneath `.git`.
pub(crate) const PROTECTED_TOP: &[&str] = &[
    ".gitmodules",
    ".vscode",
    ".idea",
    ".claude",
    ".mcp.json",
    ".envrc",
    ".bashrc",
    ".bash_profile",
    ".zshrc",
    ".zprofile",
    ".profile",
    ".gitconfig",
    ".ripgreprc",
];

/// Names under `.git` that are never writable.
pub(crate) const PROTECTED_GIT: &[&str] = &["hooks", "config"];

/// Every protected name of a root, relative to it: `PROTECTED_GIT` under `.git`, then `PROTECTED_TOP`. Public so the
/// integration tests enumerate the same list the sandbox binds.
pub fn protected_rels() -> impl Iterator<Item = String> {
    PROTECTED_GIT.iter().map(|n| format!(".git/{n}")).chain(PROTECTED_TOP.iter().map(|n| n.to_string()))
}

/// What `wmlhost exec-under` enforces. The host computes this; the shim only applies it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LandlockRules {
    /// The ABI to build the ruleset at (from `hello.sandbox.landlockAbi`).
    pub abi: i32,
    /// EXECUTE grants. Empty means do not handle EXECUTE at all (`exec: "any"`).
    pub exec: Vec<PathBuf>,
    /// Edit-only grants (`WriteFile`/`Truncate`): a name-immutable top level. No create, remove or
    /// rename of any name under these paths.
    pub write_edit: Vec<PathBuf>,
    /// File-level write grants (create/remove/truncate a file inside; never a directory or symlink).
    pub write_files: Vec<PathBuf>,
    /// Full write grants (a tree that may take new directories). Directories only.
    pub write_trees: Vec<PathBuf>,
}

/// The Landlock ruleset for one call.
///
/// `write: Roots` is the name-immutable shape: `WriteFile`/`Truncate` on each root (so an existing
/// top-level file stays editable and `touch inside` / `mkdir .vscode` / `rm x` / `ln -s` / `mv` at the
/// top level do not), file-level ops on each `.git` (so `git add` can create `.git/index`), full write
/// on each existing non-protected top-level DIRECTORY and each existing non-protected child of `.git`,
/// and full write on tmp. `write: Today` is the bwrap floor approximated under Landlock (used only when
/// the exec scope alone is narrowed): full write on the roots and tmp, gap included. `write: None` is
/// tmp alone. The exec list is the set for `program-only`, empty for `any`.
pub fn landlock_rules(plan: &Plan, abi: i32) -> LandlockRules {
    let exec = match &plan.exec {
        ExecScope::Any => vec![],
        ExecScope::ProgramOnly(s) => s.clone(),
    };
    let mut write_edit = Vec::new();
    let mut write_files = Vec::new();
    let mut write_trees = vec![plan.tmp.clone()];
    match plan.write {
        WriteScope::Today => {
            for root in &plan.roots {
                write_trees.push(root.clone());
            }
        }
        WriteScope::Roots => {
            for root in &plan.roots {
                write_edit.push(root.clone());
                if let Ok(rd) = std::fs::read_dir(root) {
                    for ent in rd.flatten() {
                        let name = ent.file_name().to_string_lossy().into_owned();
                        if PROTECTED_TOP.contains(&name.as_str()) {
                            continue;
                        }
                        // Symlinks are never granted: a dangling one breaks the ruleset, a live one
                        // grants write on a path the enumeration never judged.
                        if ent.file_type().is_ok_and(|t| t.is_symlink()) {
                            continue;
                        }
                        if name == ".git" {
                            write_files.push(ent.path());
                            // one level down: full write on each existing DIRECTORY except
                            // hooks/config, so `git add` works and absent `.git/hooks` cannot be
                            // created. Files need no extra grant: `.git`'s file-level ops cover them.
                            if let Ok(gd) = std::fs::read_dir(ent.path()) {
                                for g in gd.flatten() {
                                    let gn = g.file_name().to_string_lossy().into_owned();
                                    if PROTECTED_GIT.contains(&gn.as_str()) {
                                        continue;
                                    }
                                    if g.file_type().is_ok_and(|t| t.is_dir()) {
                                        write_trees.push(g.path());
                                    }
                                }
                            }
                            continue;
                        }
                        // Only directories: a file child is already covered by the root's edit grant,
                        // and a full-write rule on a file is a hard Landlock error.
                        if ent.file_type().is_ok_and(|t| t.is_dir()) {
                            write_trees.push(ent.path());
                        }
                    }
                }
            }
        }
        WriteScope::None => {}
    }
    LandlockRules { abi, exec, write_edit, write_files, write_trees }
}

/// The exec set of one call: `program` plus its `#!` chain (including `env`'s target, resolved
/// against `path`), each hashed path argument's own chain defensively, and on Linux each ELF's
/// `PT_INTERP` (the kernel checks EXECUTE on the dynamic linker too). Fails closed: an unresolvable
/// target is an error, never a silent omission.
pub fn exec_set(program: &Path, hashed_paths: &[PathBuf], path: Option<&str>) -> Result<Vec<PathBuf>, String> {
    let mut out: Vec<PathBuf> = Vec::new();
    push_unique(&mut out, program.to_path_buf());
    let mut stack: Vec<(PathBuf, usize)> = vec![(program.to_path_buf(), 0)];
    for h in hashed_paths {
        stack.push((h.clone(), 0));
    }
    while let Some((file, depth)) = stack.pop() {
        if depth >= 4 {
            continue;
        }
        for v in shell_variants(&file) {
            push_unique(&mut out, v);
        }
        if let Some((interp, rest)) = shebang(&file) {
            let mut targets = vec![interp.clone()];
            // `#!/usr/bin/env foo` runs `env`, which execs `foo`.
            if interp.ends_with("/env") || interp == Path::new("env") {
                let Some(name) = rest.iter().find(|t| !t.starts_with('-')) else {
                    return Err(format!("{}: #! env with no program", file.display()));
                };
                let resolved = if name.contains('/') {
                    let p = PathBuf::from(name);
                    std::fs::canonicalize(&p).unwrap_or(p)
                } else {
                    which(name, path).ok_or_else(|| format!("{}: #! env cannot resolve {name}", file.display()))?
                };
                targets.push(resolved);
            }
            for t in targets {
                push_unique(&mut out, t.clone());
                stack.push((t, depth + 1));
            }
        }
        if let Some(i) = crate::elf::pt_interp(&file) {
            push_unique(&mut out, i);
        }
    }
    Ok(out)
}

/// macOS runs `/bin/sh` by exec'ing a "variant" (`bash` or `dash`, same directory). Without them in
/// the set, `sh` itself cannot start under `exec: "program-only"` — the literal allow on `/bin/sh`
/// does not cover the variant the kernel actually execs. Anything else stays out of the set.
#[cfg(target_os = "macos")]
fn shell_variants(p: &Path) -> Vec<PathBuf> {
    let Some(name) = p.file_name().and_then(|s| s.to_str()) else { return vec![] };
    if name != "sh" {
        return vec![];
    }
    let dir = p.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("/bin"));
    ["bash", "dash"]
        .iter()
        .filter_map(|v| {
            let c = dir.join(v);
            c.exists().then(|| std::fs::canonicalize(&c).unwrap_or(c))
        })
        .collect()
}

#[cfg(not(target_os = "macos"))]
fn shell_variants(_p: &Path) -> Vec<PathBuf> {
    vec![]
}

fn push_unique(out: &mut Vec<PathBuf>, p: PathBuf) {
    let p = std::fs::canonicalize(&p).unwrap_or(p);
    if !out.contains(&p) {
        out.push(p);
    }
}

/// The `#!` line's interpreter and its remaining tokens, when `file` is a script.
fn shebang(file: &Path) -> Option<(PathBuf, Vec<String>)> {
    use std::io::Read;
    let mut f = std::fs::File::open(file).ok()?;
    let mut head = [0u8; 256];
    let n = f.read(&mut head).ok()?;
    let line = String::from_utf8_lossy(&head[..n]);
    let line = line.split('\n').next()?;
    let rest = line.strip_prefix("#!")?.trim();
    let mut parts = rest.split_whitespace();
    let interp = parts.next()?;
    let args: Vec<String> = parts.map(|s| s.to_string()).collect();
    Some((PathBuf::from(interp), args))
}

fn which(name: &str, path: Option<&str>) -> Option<PathBuf> {
    let path = path?;
    for dir in path.split(':') {
        if dir.is_empty() {
            continue;
        }
        let candidate = Path::new(dir).join(name);
        if candidate.is_file() {
            return Some(std::fs::canonicalize(&candidate).unwrap_or(candidate));
        }
    }
    None
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

/// Regexes (POSIX ERE, case-insensitive by construction) for paths in a root that, written, run code later: every
/// protected name ([`protected_rels`]), the same list bubblewrap re-binds on Linux, so the two OSes hold the same names.
/// Matched anywhere in a path and as a whole subtree (`(/|$)`), so renaming a parent cannot carry one out from under its
/// rule and a directory's contents are held with it (`.claude/` whole, as Linux binds it).
fn deny_write_regexes() -> Vec<String> {
    protected_rels().map(|r| format!("/{}(/|$)", ci(&r))).collect()
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
    let mut write: Vec<String> = Vec::new();
    if plan.write != WriteScope::None {
        write.extend(plan.roots.iter().map(|r| format!("(subpath {})", lit(r))));
    }
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
    // Name-immutable top level under `write: "roots"`: the root inode is edit-only (WriteFile/Truncate),
    // so no name directly under a root may be created, removed or renamed. `file-write-create` is
    // checked on the name being made and `file-write-unlink` on the name going away (or the rename's
    // dest), which together are MakeReg|MakeDir|MakeSym|RemoveFile|RemoveDir|Refer withheld. An edit
    // of an existing top-level file and anything below an existing subdirectory still work. The
    // universal, and what it costs a call: docs/SANDBOX.md.
    if plan.write == WriteScope::Roots {
        for r in &plan.roots {
            let top = format!("^{}/[^/]+$", ci(&r.to_string_lossy()));
            p.push(format!("(deny file-write-create {})", re(&top)));
            p.push(format!("(deny file-write-unlink {})", re(&top)));
        }
    }
    if !plan.hidden.is_empty() {
        let hidden: Vec<String> = plan.hidden.iter().map(|h| format!("(subpath {})", lit(h))).collect();
        p.push(format!("(deny file-write* {})", hidden.join(" ")));
    }
    if let ExecScope::ProgramOnly(set) = &plan.exec {
        p.push("; exec: only the program and its interpreters".into());
        p.push("(deny process-exec)".into());
        let lits: Vec<String> = set.iter().map(|s| format!("(literal {})", lit(s))).collect();
        p.push(format!("(allow process-exec {})", lits.join(" ")));
    }
    p.join("\n")
}

// --- bubblewrap (Linux) ---

fn bwrap_fixed_args() -> Vec<&'static str> {
    vec![
        "--new-session",
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
    if !plan.outlives_host {
        a.push("--die-with-parent".into());
    }
    let mut push = |xs: &[&OsString]| a.extend(xs.iter().map(|x| (*x).clone()));
    let s = |x: &str| OsString::from(x);
    push(&[&s("--ro-bind"), &s("/"), &s("/"), &s("--dev"), &s("/dev"), &s("--proc"), &s("/proc")]);
    for r in plan.roots.iter().chain(std::iter::once(&plan.tmp)) {
        push(&[&s("--bind"), &r.clone().into(), &r.clone().into()]);
    }
    for r in &plan.roots {
        // Every protected name, from the lists the grants and the tripwire read, so a name added there is bound here.
        for rel in protected_rels() {
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
            outlives_host: false,
            write: WriteScope::Today,
            exec: ExecScope::Any,
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

    // --- the envelope: every accepted value is a SUBSET of today's Plan ---

    #[test]
    fn every_envelope_value_is_a_subset_of_todays_plan() {
        let root = tempfile::tempdir().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("inside"), "x").unwrap();
        std::fs::write(root.path().join("README.md"), "x").unwrap();
        std::fs::create_dir(root.path().join("src")).unwrap();
        std::fs::create_dir(root.path().join(".git")).unwrap();
        std::fs::write(root.path().join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        std::fs::create_dir(root.path().join(".git/objects")).unwrap();
        std::fs::create_dir(root.path().join(".vscode")).unwrap();
        std::fs::create_dir(root.path().join("dangling")).unwrap();
        std::fs::remove_dir(root.path().join("dangling")).unwrap();
        // a live symlink and a dangling one: neither may be granted
        std::os::unix::fs::symlink(root.path().join("src"), root.path().join("link")).unwrap();
        std::os::unix::fs::symlink(root.path().join("nowhere"), root.path().join("stale")).unwrap();

        let today = Plan {
            roots: vec![root.path().to_path_buf()],
            tmp: tmp.path().to_path_buf(),
            hidden: vec![],
            allow_read: vec![],
            home: None,
            outlives_host: false,
            write: WriteScope::Today,
            exec: ExecScope::Any,
        };

        // write: none drops every root write, keeps tmp
        let none = Plan { write: WriteScope::None, ..today.clone() };
        let rules = landlock_rules(&none, 3);
        assert!(rules.write_edit.is_empty(), "write: none grants no root: {:?}", rules.write_edit);
        assert!(rules.write_files.is_empty(), "write: none grants no root file ops: {:?}", rules.write_files);
        assert_eq!(rules.write_trees, vec![tmp.path().to_path_buf()]);
        let p = seatbelt_profile(&none);
        assert!(!p.contains(&format!("(subpath {})", lit(root.path()))), "write: none may not write a root");
        assert!(p.contains(&format!("(subpath {})", lit(tmp.path()))), "write: none keeps tmp");

        // exec: program-only narrows to the named set
        let sh = PathBuf::from("/bin/sh");
        let only = Plan { exec: ExecScope::ProgramOnly(vec![sh.clone()]), ..today.clone() };
        let rules = landlock_rules(&only, 3);
        assert_eq!(rules.exec, vec![sh.clone()]);
        let p = seatbelt_profile(&only);
        assert!(p.contains("(deny process-exec)"));
        assert!(p.contains(&format!("(allow process-exec (literal {}))", lit(&sh))));

        // today's floor (an absent envelope) writes the roots in full: the gap stays
        let rules = landlock_rules(&today, 3);
        assert!(rules.exec.is_empty(), "exec: any does not handle EXECUTE");
        assert!(rules.write_edit.is_empty());
        assert!(rules.write_files.is_empty());
        assert!(rules.write_trees.contains(&root.path().to_path_buf()), "today writes the root itself");
        assert!(rules.write_trees.contains(&tmp.path().to_path_buf()));
        let p = seatbelt_profile(&today);
        assert!(
            !p.contains("file-write-create"),
            "today's Seatbelt profile does not withhold create at the top level: {p}"
        );

        // write: roots is a SUBSET of today: name-immutable top level, directories only below it
        let roots = Plan { write: WriteScope::Roots, ..today.clone() };
        let rules = landlock_rules(&roots, 3);
        assert_eq!(rules.write_edit, vec![root.path().to_path_buf()], "the root is edit-only");
        assert_eq!(rules.write_files, vec![root.path().join(".git")], "only .git gets file-level ops");
        assert!(rules.write_trees.contains(&tmp.path().to_path_buf()));
        assert!(rules.write_trees.contains(&root.path().join("src")), "an existing directory is writable");
        assert!(rules.write_trees.contains(&root.path().join(".git").join("objects")));
        assert!(
            !rules.write_trees.iter().any(|p| p.ends_with(".vscode")),
            "protected names are not granted: {:?}",
            rules.write_trees
        );
        assert!(!rules.write_trees.iter().any(|p| p.ends_with(".git")), ".git is file-ops only, not a write tree");
        assert!(!rules.write_trees.iter().any(|p| p.ends_with("README.md")), "a file child needs no grant");
        assert!(!rules.write_trees.iter().any(|p| p.ends_with("HEAD")), "a .git file child needs no grant");
        assert!(!rules.write_trees.iter().any(|p| p.ends_with("link")), "a symlink is never granted");
        assert!(!rules.write_trees.iter().any(|p| p.ends_with("stale")), "a dangling symlink is never granted");
        // the same universal on Seatbelt: create and unlink of a name directly under a root are denied
        let p = seatbelt_profile(&roots);
        let top = re(&format!("^{}/[^/]+$", ci(&root.path().to_string_lossy())));
        assert!(p.contains(&format!("(deny file-write-create {top})")), "missing create deny: {p}");
        assert!(p.contains(&format!("(deny file-write-unlink {top})")), "missing unlink deny: {p}");
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
            outlives_host: false,
            write: WriteScope::Roots,
            exec: ExecScope::Any,
        };
        let a: Vec<String> = bwrap_args(&pl, root.path()).iter().map(|s| s.to_string_lossy().into_owned()).collect();
        let joined = a.join(" ");
        assert!(joined.contains("--unshare-net"));
        assert!(joined.contains("--die-with-parent"), "a call dies with its host unless it may be orphaned");
        let orphanable = Plan { outlives_host: true, ..pl };
        assert!(!bwrap_args(&orphanable, root.path()).iter().any(|x| x == "--die-with-parent"));
        assert!(joined.contains(&format!("--tmpfs {}", home.path().join(".ssh").display())));
        assert!(joined.contains(&format!("--ro-bind /dev/null {}", home.path().join(".netrc").display())));
        let hooks = root.path().join(".git/hooks").display().to_string();
        assert!(joined.contains(&format!("--ro-bind {hooks} {hooks}")));
        assert!(joined.find("--ro-bind / /").unwrap() < joined.find("--bind ").unwrap());
    }

    #[test]
    fn bwrap_re_binds_every_protected_name_that_exists() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join(".git/hooks")).unwrap();
        let rels: Vec<String> = protected_rels().collect();
        assert_eq!(rels.len(), PROTECTED_TOP.len() + PROTECTED_GIT.len());
        for rel in &rels {
            let p = root.path().join(rel);
            if !p.exists() {
                std::fs::write(&p, "").unwrap();
            }
        }
        let pl = Plan {
            roots: vec![root.path().to_path_buf()],
            tmp: PathBuf::from("/tmp"),
            hidden: vec![],
            allow_read: vec![],
            home: None,
            outlives_host: false,
            write: WriteScope::Roots,
            exec: ExecScope::Any,
        };
        let a: Vec<String> = bwrap_args(&pl, root.path()).iter().map(|s| s.to_string_lossy().into_owned()).collect();
        for rel in &rels {
            let p = root.path().join(rel).display().to_string();
            assert!(
                a.windows(3).any(|w| w[0] == "--ro-bind" && w[1] == p && w[2] == p),
                "{rel} is not re-bound read-only"
            );
        }
        // An absent name is not bound (bwrap fails on a missing source), and a symlink is never followed into a bind.
        let bare = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("/etc/hostname", bare.path().join(".gitconfig")).unwrap();
        let pl = Plan { roots: vec![bare.path().to_path_buf()], ..pl };
        let a: Vec<String> = bwrap_args(&pl, bare.path()).iter().map(|s| s.to_string_lossy().into_owned()).collect();
        let bare_s = bare.path().display().to_string();
        assert!(!a.iter().any(|x| x.starts_with(&bare_s) && x != &bare_s), "{a:?}");
    }

    #[test]
    fn landlock_grants_no_protected_name_and_leaves_the_files_to_the_re_bind() {
        // Each name as a DIRECTORY, the shape that would earn a full-write grant if the enumeration missed it.
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join(".git")).unwrap();
        for rel in protected_rels() {
            std::fs::create_dir_all(root.path().join(rel)).unwrap();
        }
        let pl = Plan { roots: vec![root.path().to_path_buf()], write: WriteScope::Roots, ..plan() };
        let rules = landlock_rules(&pl, 4);
        for rel in protected_rels() {
            let p = root.path().join(&rel);
            assert!(!rules.write_trees.contains(&p) && !rules.write_files.contains(&p), "{rel} is granted write");
        }
        // The root's WriteFile|Truncate still reaches an existing protected FILE: the read-only re-bind is what holds
        // it (`bwrap_re_binds_every_protected_name_that_exists`), the second layer docs/SANDBOX.md names.
        assert_eq!(rules.write_edit, vec![root.path().to_path_buf()]);
    }

    #[test]
    fn seatbelt_denies_writing_every_protected_name() {
        let rx = deny_write_regexes();
        for rel in protected_rels() {
            assert!(rx.contains(&format!("/{}(/|$)", ci(&rel))), "{rel} has no whole-subtree deny-write regex");
        }
    }
}
