//! tripwire.rs — what changed among a root's protected names during a call: recorded at `start`, compared at `done`,
//! reported as `protectedChanged` and never reverted.
//!
//! The names are the ones that run code LATER, when an editor, git, direnv or an MCP client acts on them
//! (`sandbox::PROTECTED_TOP`, `.git/config`, `.git/hooks` and each entry of it). The OS sandbox holds the existing
//! ones read-only, but on Linux it cannot refuse an absent one under today's floor (docs/SANDBOX.md), so this reports
//! what the call's lifetime left behind, on both OSes. It reports and never attributes: two calls in one root see each
//! other's change. Only the top of each root is read; a nested repository's hooks are not walked.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::sandbox::{PROTECTED_GIT, PROTECTED_TOP};

/// What a name looked like: enough to tell a create, a remove, an edit, a `chmod` or a replacement apart. `ctime` is
/// kept because a program can set `mtime` back (`touch -d`) but not `ctime`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Stamp {
    kind: u32,
    ino: u64,
    size: u64,
    mode: u32,
    mtime_ns: i64,
    ctime_ns: i64,
}

/// `S_IFMT`: the file-type bits of `st_mode`, the same on Linux and macOS.
const S_IFMT: u32 = 0o170000;

impl Stamp {
    fn of(path: &Path) -> Option<Stamp> {
        let m = std::fs::symlink_metadata(path).ok()?;
        Some(Stamp {
            kind: m.mode() & S_IFMT,
            ino: m.ino(),
            size: m.size(),
            mode: m.mode(),
            mtime_ns: m.mtime().saturating_mul(1_000_000_000).saturating_add(m.mtime_nsec()),
            ctime_ns: m.ctime().saturating_mul(1_000_000_000).saturating_add(m.ctime_nsec()),
        })
    }
}

/// The protected names of every root at one moment, each with its stamp or `None` when absent. It is kept on an
/// orphan's ledger entry, so a later host's `status` can compare against it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot(Vec<(PathBuf, String, Option<Stamp>)>);

impl Snapshot {
    /// The roots it was taken over, in order, each once.
    pub fn roots(&self) -> Vec<PathBuf> {
        let mut out: Vec<PathBuf> = Vec::new();
        for (r, _, _) in &self.0 {
            if !out.contains(r) {
                out.push(r.clone());
            }
        }
        out
    }
}

/// The most `.git/hooks` entries read per root, in name order. Past it, a new hook is not named, but `.git/hooks`
/// itself still reports `modified` (its own stamp moves), so the change is never silent. Bounds the snapshot kept on a
/// ledger entry and the report on `done`.
pub const MAX_HOOKS: usize = 256;

/// The most changes one report lists, across every root; past it the list is cut and `truncated` says so.
pub const MAX_CHANGES: usize = 256;

/// The names one root is read for: every protected top-level name, `.git`'s protected names, and each entry of
/// `.git/hooks` that exists (at most [`MAX_HOOKS`]). An absent name is recorded too, so its creation shows.
fn names_of(root: &Path) -> Vec<String> {
    let mut names: Vec<String> = PROTECTED_TOP.iter().map(|n| n.to_string()).collect();
    names.extend(PROTECTED_GIT.iter().map(|n| format!(".git/{n}")));
    if let Ok(rd) = std::fs::read_dir(root.join(".git").join("hooks")) {
        let mut hooks: Vec<String> =
            rd.flatten().map(|e| format!(".git/hooks/{}", e.file_name().to_string_lossy())).collect();
        hooks.sort();
        hooks.truncate(MAX_HOOKS);
        names.extend(hooks);
    }
    names
}

/// Records the protected names of `roots` now. A root named twice is read once.
pub fn snapshot(roots: &[PathBuf]) -> Snapshot {
    let mut out = Vec::new();
    let mut seen: Vec<&PathBuf> = Vec::new();
    for root in roots {
        if seen.contains(&root) {
            continue;
        }
        seen.push(root);
        for name in names_of(root) {
            let stamp = Stamp::of(&root.join(&name));
            out.push((root.clone(), name, stamp));
        }
    }
    Snapshot(out)
}

/// One change, as `done` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub root: PathBuf,
    pub name: String,
    pub change: &'static str,
}

impl Change {
    pub fn json(&self) -> Value {
        json!({ "root": self.root.to_string_lossy(), "name": self.name, "change": self.change })
    }
}

/// A report: the changes, sorted and cut at [`MAX_CHANGES`], and whether it was cut.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Report {
    pub changes: Vec<Change>,
    pub truncated: bool,
}

impl Report {
    /// The changes as `protectedChanged` lists them.
    pub fn json(&self) -> Value {
        self.changes.iter().map(Change::json).collect()
    }
}

/// [`changed`], cut at [`MAX_CHANGES`].
pub fn report(before: &Snapshot) -> Report {
    let mut changes = changed(before, &before.roots());
    let truncated = changes.len() > MAX_CHANGES;
    changes.truncate(MAX_CHANGES);
    Report { changes, truncated }
}

/// What changed between `before` and now: a name present now and absent before is `created`, the reverse `removed`,
/// and a different stamp `modified`. A hook that appeared since is read now, so a new `.git/hooks/<name>` is
/// `created`. Sorted by root and name, so two hosts report one change the same way.
pub fn changed(before: &Snapshot, roots: &[PathBuf]) -> Vec<Change> {
    let now = snapshot(roots);
    let was = |root: &Path, name: &str| before.0.iter().find(|(r, n, _)| r == root && n == name).map(|(_, _, s)| s);
    let mut out = Vec::new();
    for (root, name, stamp) in &now.0 {
        let prior = was(root, name).cloned().flatten();
        let change = match (&prior, stamp) {
            (None, Some(_)) => "created",
            (Some(_), None) => "removed",
            (Some(a), Some(b)) if a != b => "modified",
            _ => continue,
        };
        out.push(Change { root: root.clone(), name: name.clone(), change });
    }
    // A hook present before and gone now is not among the names read now.
    for (root, name, stamp) in &before.0 {
        if stamp.is_some() && !now.0.iter().any(|(r, n, _)| r == root && n == name) {
            out.push(Change { root: root.clone(), name: name.clone(), change: "removed" });
        }
    }
    out.sort_by(|a, b| (&a.root, &a.name).cmp(&(&b.root, &b.name)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn root() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        fs::create_dir_all(d.path().join(".git/hooks")).unwrap();
        fs::write(d.path().join(".git/config"), "[core]\n").unwrap();
        fs::write(d.path().join(".git/hooks/pre-commit.sample"), "#!/bin/sh\n").unwrap();
        fs::write(d.path().join("README.md"), "x").unwrap();
        d
    }

    fn names(c: &[Change]) -> Vec<(String, &'static str)> {
        c.iter().map(|c| (c.name.clone(), c.change)).collect()
    }

    #[test]
    fn nothing_changed_is_an_empty_list() {
        let r = root();
        let roots = vec![r.path().to_path_buf()];
        let s = snapshot(&roots);
        fs::write(r.path().join("README.md"), "an unprotected edit").unwrap();
        fs::create_dir(r.path().join("target")).unwrap();
        assert_eq!(changed(&s, &roots), vec![], "only protected names are reported");
    }

    #[test]
    fn a_created_top_level_name_is_created_whether_file_or_directory() {
        let r = root();
        let roots = vec![r.path().to_path_buf()];
        let s = snapshot(&roots);
        fs::write(r.path().join(".envrc"), "eval x").unwrap();
        fs::create_dir(r.path().join(".vscode")).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", r.path().join(".mcp.json")).unwrap();
        assert_eq!(
            names(&changed(&s, &roots)),
            vec![(".envrc".into(), "created"), (".mcp.json".into(), "created"), (".vscode".into(), "created")]
        );
    }

    #[test]
    fn a_new_hook_is_created_a_removed_one_removed_and_an_edited_config_modified() {
        let r = root();
        let roots = vec![r.path().to_path_buf()];
        let s = snapshot(&roots);
        fs::write(r.path().join(".git/hooks/pre-commit"), "#!/bin/sh\ncurl x\n").unwrap();
        fs::remove_file(r.path().join(".git/hooks/pre-commit.sample")).unwrap();
        fs::write(r.path().join(".git/config"), "[core]\n\tfsmonitor = x\n").unwrap();
        assert_eq!(
            names(&changed(&s, &roots)),
            vec![
                (".git/config".into(), "modified"),
                (".git/hooks".into(), "modified"),
                (".git/hooks/pre-commit".into(), "created"),
                (".git/hooks/pre-commit.sample".into(), "removed"),
            ]
        );
    }

    #[test]
    fn a_chmod_or_a_replacement_with_the_old_mtime_is_still_modified() {
        use std::os::unix::fs::PermissionsExt;
        let r = root();
        let roots = vec![r.path().to_path_buf()];
        let hook = r.path().join(".git/hooks/pre-commit.sample");
        let s = snapshot(&roots);
        fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(names(&changed(&s, &roots)), vec![(".git/hooks/pre-commit.sample".into(), "modified")], "chmod +x");
        // Same size, mtime set back: ctime still moves.
        let s = snapshot(&roots);
        let before = fs::metadata(&hook).unwrap().modified().unwrap();
        fs::write(&hook, "#!/bin/sx\n").unwrap();
        fs::File::options().write(true).open(&hook).unwrap().set_modified(before).unwrap();
        assert_eq!(names(&changed(&s, &roots)), vec![(".git/hooks/pre-commit.sample".into(), "modified")], "touch -d");
    }

    #[test]
    fn every_root_is_read_and_reported_by_its_own_path() {
        let (a, b) = (root(), root());
        let roots = vec![a.path().to_path_buf(), b.path().to_path_buf()];
        let s = snapshot(&roots);
        fs::write(b.path().join(".gitmodules"), "").unwrap();
        let c = changed(&s, &roots);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].root, b.path());
        assert_eq!(
            c[0].json(),
            json!({ "root": b.path().to_string_lossy(), "name": ".gitmodules", "change": "created" })
        );
    }

    #[test]
    fn a_flood_of_hooks_is_bounded_and_still_reported() {
        let r = root();
        let roots = vec![r.path().to_path_buf()];
        let s = snapshot(&roots);
        for i in 0..(MAX_HOOKS + 50) {
            fs::write(r.path().join(format!(".git/hooks/h{i:05}")), "").unwrap();
        }
        let after = snapshot(&roots);
        assert!(after.0.len() <= PROTECTED_TOP.len() + PROTECTED_GIT.len() + MAX_HOOKS, "the snapshot is bounded");
        let rep = report(&s);
        assert!(rep.changes.len() <= MAX_CHANGES);
        assert!(rep.truncated, "past the cap the report says it was cut");
        assert_eq!(rep.changes[0].name, ".git/hooks", "the directory's own change sorts first and is never cut");
        assert_eq!(rep.changes[0].change, "modified");
    }

    #[test]
    fn a_root_named_twice_is_read_and_reported_once() {
        let r = root();
        let roots = vec![r.path().to_path_buf(), r.path().to_path_buf()];
        let s = snapshot(&roots);
        fs::write(r.path().join(".envrc"), "").unwrap();
        assert_eq!(names(&changed(&s, &s.roots())), vec![(".envrc".into(), "created")]);
    }

    #[test]
    fn a_root_without_git_reports_a_created_git_config() {
        let d = tempfile::tempdir().unwrap();
        let roots = vec![d.path().to_path_buf()];
        let s = snapshot(&roots);
        fs::create_dir_all(d.path().join(".git/hooks")).unwrap();
        fs::write(d.path().join(".git/config"), "").unwrap();
        fs::write(d.path().join(".git/hooks/post-checkout"), "").unwrap();
        assert_eq!(
            names(&changed(&s, &roots)),
            vec![
                (".git/config".into(), "created"),
                (".git/hooks".into(), "created"),
                (".git/hooks/post-checkout".into(), "created"),
            ]
        );
    }

    /// The cost the PR reports: one snapshot plus one compare, against spawning `true`. Run with
    /// `cargo test --release --lib tripwire::tests::cost -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn cost() {
        let r = root();
        for n in PROTECTED_TOP {
            fs::write(r.path().join(n), "").ok();
        }
        for i in 0..20 {
            fs::write(r.path().join(format!(".git/hooks/h{i}.sample")), "").unwrap();
        }
        let roots = vec![r.path().to_path_buf()];
        let n = 2000;
        let t = std::time::Instant::now();
        for _ in 0..n {
            let s = snapshot(&roots);
            assert!(changed(&s, &roots).is_empty());
        }
        let trip = t.elapsed() / n;
        let t = std::time::Instant::now();
        for _ in 0..200 {
            std::process::Command::new("true").status().unwrap();
        }
        let spawn = t.elapsed() / 200;
        eprintln!("snapshot+compare over {} names: {trip:?}; spawn of true: {spawn:?}", snapshot(&roots).0.len());
    }
}
