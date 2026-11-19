//! snapshot_report.rs — what changed during an `ml.sh` call, read from its two snapshots (window-ml's
//! FILE_ATTACHMENTS.md, H13).
//!
//! A [`CallSnapshot`] is taken before the call starts: a scratch store (src/snapshot.rs), the tree of the work tree as
//! it was, and the H12 lists (big files, paths not captured). [`CallSnapshot::report`] fills the scratch index afresh
//! from the person's index, takes the tree again, and compares the two with `git diff-tree -r --no-renames
//! --no-ext-diff --no-textconv`: so no diff driver, textconv or external diff program runs, `-O/dev/null` keeps a
//! configured `diff.orderFile` from being read, and `--submodule=short` keeps a submodule from being read at all.
//!
//! What it says (the body, held as output is): each change as "changed during this call", never attributed to the
//! call's process, since another process may have written meanwhile; the paths not captured after the call, so none
//! is silently absent; the files over the diff cap with their size and sha256; then the patch. `done` carries only
//! the summary line (`edited a.py (+3 −1); deleted old.log`).
//!
//! A path whose name looks like a secret ([`looks_secret`]) never shows a line of its body, tracked or untracked: a
//! tracked one that changed (deleted, or only its mode) is listed as `changed <path> (contents withheld)`, with no
//! size, hash or line count, and is left out of the patch by a literal exclude pathspec. So is a path under an
//! ordinary name whose old or new blob is the blob of a secret-looking path in either tree (`cp .env notes.txt` of a
//! tracked `.env`, or `git mv .env notes.txt`). The empty blob is not counted as a secret's body: it shows nothing.
//! More than [`EXCLUDE_MAX`] such paths leave the patch out whole, rather than pass an argument list that long.
//!
//! The tree diff is reconciled with the lists: a file that crossed the diff cap, or stopped (or started) being
//! captured, shows in the tree diff as an add or a delete, and is reported as the edit it is, with no patch. A big file
//! is compared by size and sha256; one past the hashing budget in either snapshot, at the same size, is reported as
//! not compared.

use std::collections::{BTreeMap, HashSet};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use crate::facts::looks_secret;
use crate::gitconfig::RepoConfig;
use crate::gitfacts::Git;
use crate::snapshot::Scratch;
#[cfg(test)]
use crate::snapshot_bounds::DIFF_CAP;
use crate::snapshot_bounds::{Big, BigHashes, NotCaptured};

/// The most changes the summary line names; past it, `and N more`.
pub const SUMMARY_MAX: usize = 20;
/// The most paths left out of the patch by name; past it the patch is left out whole (closed).
pub const EXCLUDE_MAX: usize = 1000;
/// The most bytes of a tree listing or a raw diff read; a longer one fails the report rather than miss a path.
const LIST_MAX: usize = 64 << 20;
/// git's id of the empty blob, SHA-1 and SHA-256.
const EMPTY_BLOBS: [&str; 2] =
    ["e69de29bb2d1d6434b8b29ae775ad8c2e48c5391", "473a0f4c3be8a93681a267e3b1e9a7dcda1185436fe141f7749120a303721813"];
/// What the body says when the tree diff, the big files and the paths not captured show no change.
pub const NOTHING: &str = "nothing changed during this call";

/// One snapshot: the tree and what H12 left out of it.
struct Side {
    tree: String,
    big: Vec<Big>,
    not_captured: Vec<NotCaptured>,
}

/// A call's first snapshot, held until its end: the scratch store, the big files' hashes (held for both snapshots),
/// and the tree with its lists.
pub struct CallSnapshot {
    git: Git,
    repo: RepoConfig,
    uploads: Option<PathBuf>,
    scratch: Scratch,
    hashes: BigHashes,
    before: Side,
}

/// What [`CallSnapshot::report`] found.
#[derive(Debug, PartialEq)]
pub struct Report {
    /// The held output: the changes, the lists, then the patch, cut at the cap.
    pub body: Vec<u8>,
    /// The body passed the cap and was cut.
    pub truncated: bool,
    /// The changes on one line, at most [`SUMMARY_MAX`] named.
    pub summary: String,
    /// Either snapshot's index came from HEAD (a split index, or none): the stat cache was lost, never the result.
    pub from_head: bool,
}

/// One line of the change list.
#[derive(Debug, PartialEq)]
struct Change {
    path: Vec<u8>,
    line: String,
}

/// One record of `git diff-tree -r -z --raw`.
#[derive(Debug, PartialEq)]
struct Raw {
    old_mode: String,
    new_mode: String,
    old: String,
    new: String,
    status: u8,
    path: Vec<u8>,
}

impl CallSnapshot {
    /// Takes the first snapshot of `repo`'s work tree into a scratch store under `base` (the host's own directory).
    /// `Err` is a null diff's reason.
    pub fn take(git: Git, repo: &RepoConfig, base: &Path, uploads: Option<&Path>) -> Result<CallSnapshot, String> {
        let scratch = Scratch::new(&git, repo, base)?;
        let mut hashes = BigHashes::default();
        let before = side(&git, repo, &scratch, uploads, &mut hashes)?;
        Ok(CallSnapshot { git, repo: repo.clone(), uploads: uploads.map(Path::to_path_buf), scratch, hashes, before })
    }

    /// Takes the second snapshot and reports what changed between the two, the body cut at `cap` bytes. Can be
    /// called again (each stage of a pipe reports at its own end): each call compares with the first snapshot.
    pub fn report(&mut self, cap: usize) -> Result<Report, String> {
        let first_from_head = self.scratch.from_head;
        self.scratch.fill(&self.git, &self.repo)?;
        let after = side(&self.git, &self.repo, &self.scratch, self.uploads.as_deref(), &mut self.hashes)?;
        let from_head = first_from_head || self.scratch.from_head;
        let raws = if after.tree == self.before.tree {
            vec![]
        } else {
            let out = self.list(&[
                "diff-tree",
                "-r",
                "-z",
                "--raw",
                "--no-renames",
                "--no-abbrev",
                &self.before.tree,
                &after.tree,
            ])?;
            parse_raw(&out)?
        };
        let counts = if raws.is_empty() {
            BTreeMap::new()
        } else {
            let out = self.list(&[
                "diff-tree",
                "-r",
                "-z",
                "--numstat",
                "--no-renames",
                "--no-ext-diff",
                "--no-textconv",
                &self.before.tree,
                &after.tree,
            ])?;
            parse_numstat(&out)
        };
        let mut secret = HashSet::new();
        if !raws.is_empty() {
            for tree in [&self.before.tree, &after.tree] {
                let out = self.list(&["ls-tree", "-r", "-z", "--full-tree", tree])?;
                secret.extend(secret_blobs(&out));
            }
        }
        let (changes, unshown) = classify(&self.before, &after, &raws, &counts, &secret);
        let mut body = Vec::new();
        list_section(&mut body, &changes, &after);
        let mut truncated = false;
        let left: HashSet<&[u8]> = unshown.iter().map(Vec::as_slice).collect();
        let shown = raws.iter().filter(|r| !left.contains(r.path.as_slice())).count();
        if shown > 0 {
            if unshown.len() > EXCLUDE_MAX {
                body.extend_from_slice(format!("\n{}\n", left_out(unshown.len())).as_bytes());
            } else {
                let room = cap.saturating_sub(body.len()).saturating_add(1);
                let mut args: Vec<std::ffi::OsString> = [
                    "diff-tree",
                    "-r",
                    "-p",
                    "--no-renames",
                    "--no-ext-diff",
                    "--no-textconv",
                    "--no-color",
                    "--submodule=short",
                    "-O/dev/null",
                    &self.before.tree,
                    &after.tree,
                    "--",
                ]
                .iter()
                .map(std::ffi::OsString::from)
                .collect();
                // The path's own bytes: a name that is not UTF-8 must reach git as it is, or the exclude misses it.
                args.extend(
                    unshown
                        .iter()
                        .map(|p| std::ffi::OsString::from_vec([b":(exclude,literal)".as_slice(), p].concat())),
                );
                match self.scratch.git_capped(&self.git, &self.repo, &args, room) {
                    Some((0, patch)) => {
                        body.push(b'\n');
                        body.extend_from_slice(&patch);
                    }
                    Some((code, _)) => return Err(format!("git diff-tree exited {code}")),
                    None => return Err("git could not be run".into()),
                }
            }
        }
        if body.len() > cap {
            body.truncate(cap);
            truncated = true;
        }
        let mut summary = summary(&changes);
        if shown > 0 && unshown.len() > EXCLUDE_MAX {
            summary = format!("{summary}; {}", left_out(unshown.len()));
        }
        Ok(Report { body, truncated, summary, from_head })
    }

    /// A listing from the scratch, whole or an error.
    fn list(&self, args: &[&str]) -> Result<Vec<u8>, String> {
        match self.scratch.git_capped(&self.git, &self.repo, args, LIST_MAX) {
            Some((0, out)) if out.len() < LIST_MAX => Ok(out),
            Some((0, _)) => Err(format!("git {} listed more than {LIST_MAX} bytes", args[0])),
            Some((code, _)) => Err(format!("git {} exited {code}", args[0])),
            None => Err("git could not be run".into()),
        }
    }
}

/// Enters the work tree's changes and writes the tree.
fn side(git: &Git, repo: &RepoConfig, s: &Scratch, uploads: Option<&Path>, h: &mut BigHashes) -> Result<Side, String> {
    let e = s.enter_changes_with(git, repo, uploads, h)?;
    Ok(Side { tree: s.tree(git, repo)?, big: e.big, not_captured: e.not_captured })
}

/// Reads `:<old mode> <new mode> <old id> <new id> <status>\0<path>\0` records.
fn parse_raw(out: &[u8]) -> Result<Vec<Raw>, String> {
    let mut v = Vec::new();
    let mut it = out.split(|b| *b == 0);
    while let Some(head) = it.next() {
        if head.is_empty() {
            continue;
        }
        let bad = || format!("git diff-tree --raw printed {:?}", String::from_utf8_lossy(head));
        let text = std::str::from_utf8(head.strip_prefix(b":").ok_or_else(bad)?).map_err(|_| bad())?;
        let f: Vec<&str> = text.split(' ').collect();
        let path = it.next().ok_or_else(bad)?.to_vec();
        if f.len() != 5 || f[4].is_empty() {
            return Err(bad());
        }
        v.push(Raw {
            old_mode: f[0].into(),
            new_mode: f[1].into(),
            old: f[2].into(),
            new: f[3].into(),
            status: f[4].as_bytes()[0],
            path,
        });
    }
    Ok(v)
}

/// Reads `<added>\t<deleted>\t<path>\0` records: `None` counts for a binary file (`-`).
fn parse_numstat(out: &[u8]) -> BTreeMap<Vec<u8>, Option<(u64, u64)>> {
    let mut m = BTreeMap::new();
    for rec in out.split(|b| *b == 0).filter(|r| !r.is_empty()) {
        let mut f = rec.splitn(3, |b| *b == b'\t');
        let (Some(a), Some(d), Some(p)) = (f.next(), f.next(), f.next()) else { continue };
        let n = |x: &[u8]| std::str::from_utf8(x).ok()?.parse::<u64>().ok();
        m.insert(p.to_vec(), n(a).zip(n(d)));
    }
    m
}

/// The blob ids of the paths in `git ls-tree -r -z` output whose name looks like a secret, the empty blob aside.
fn secret_blobs(out: &[u8]) -> Vec<String> {
    out.split(|b| *b == 0)
        .filter_map(|rec| {
            let tab = rec.iter().position(|b| *b == b'\t')?;
            let (meta, path) = (&rec[..tab], &rec[tab + 1..]);
            let f: Vec<&[u8]> = meta.split(|b| *b == b' ').collect();
            (f.len() == 3 && f[1] == b"blob" && looks_secret(Path::new(std::ffi::OsStr::from_bytes(path))))
                .then(|| String::from_utf8_lossy(f[2]).into_owned())
        })
        .filter(|id| !EMPTY_BLOBS.contains(&id.as_str()))
        .collect()
}

fn secret_name(p: &[u8]) -> bool {
    looks_secret(Path::new(std::ffi::OsStr::from_bytes(p)))
}

/// A path as the report prints it: as is when it is plain text, else quoted with C escapes, so a name cannot forge a
/// line or a `; ` of the summary.
fn shown(p: &[u8]) -> String {
    let plain = std::str::from_utf8(p)
        .ok()
        .filter(|s| !s.is_empty() && !s.chars().any(|c| c.is_control() || breaks(c) || matches!(c, '"' | '\\' | ';')));
    if let Some(s) = plain {
        return s.to_string();
    }
    let mut q = String::from("\"");
    for chunk in p.utf8_chunks() {
        for c in chunk.valid().chars() {
            match c {
                '"' => q.push_str("\\\""),
                '\\' => q.push_str("\\\\"),
                '\n' => q.push_str("\\n"),
                '\t' => q.push_str("\\t"),
                c if c.is_control() => q.push_str(&format!("\\x{:02x}", c as u32)),
                c if breaks(c) => q.push_str(&format!("\\u{{{:04x}}}", c as u32)),
                c => q.push(c),
            }
        }
        for b in chunk.invalid() {
            q.push_str(&format!("\\x{b:02x}"));
        }
    }
    q.push('"');
    q
}

/// A character that is not a control but that a reader may take for a line break or that reorders what is shown:
/// U+2028 and U+2029, and the bidirectional overrides and isolates.
fn breaks(c: char) -> bool {
    matches!(c, '\u{2028}' | '\u{2029}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

const WITHHELD: &str = "(contents withheld)";

/// The change list, in path order, and the paths left out of the patch: the withheld and the reconciled ones.
fn classify(
    before: &Side,
    after: &Side,
    raws: &[Raw],
    counts: &BTreeMap<Vec<u8>, Option<(u64, u64)>>,
    secret: &HashSet<String>,
) -> (Vec<Change>, Vec<Vec<u8>>) {
    let big_b: BTreeMap<&[u8], &Big> = before.big.iter().map(|b| (b.path.as_slice(), b)).collect();
    let big_a: BTreeMap<&[u8], &Big> = after.big.iter().map(|b| (b.path.as_slice(), b)).collect();
    let nc_b: BTreeMap<&[u8], &str> = before.not_captured.iter().map(|n| (n.path.as_slice(), n.reason)).collect();
    let nc_a: BTreeMap<&[u8], &str> = after.not_captured.iter().map(|n| (n.path.as_slice(), n.reason)).collect();
    let mut changes = Vec::new();
    let mut unshown = Vec::new();
    let mut seen: HashSet<&[u8]> = HashSet::new();
    let withheld_line = |p: &[u8]| format!("changed {} {WITHHELD}", shown(p));
    for r in raws {
        let p = r.path.as_slice();
        seen.insert(p);
        let gitlink = r.old_mode == "160000" || r.new_mode == "160000";
        let withheld = secret_name(p) || (!gitlink && (secret.contains(&r.old) || secret.contains(&r.new)));
        let reconciled = match r.status {
            b'A' => big_b
                .get(p)
                .map(|_| "was over the diff cap".to_string())
                .or_else(|| nc_b.get(p).map(|why| format!("was not captured: {why}"))),
            b'D' => big_a
                .get(p)
                .map(|_| "now over the diff cap".to_string())
                .or_else(|| nc_a.get(p).map(|why| format!("now not captured: {why}"))),
            _ => None,
        };
        let s = shown(p);
        if withheld || reconciled.is_some() {
            unshown.push(r.path.clone());
        }
        let line = if withheld {
            withheld_line(p)
        } else if let Some(note) = reconciled {
            format!("edited {s} ({note})")
        } else {
            let lines = match counts.get(p) {
                _ if gitlink => " (submodule)".to_string(),
                Some(Some((a, d))) => format!(" (+{a} \u{2212}{d})"),
                Some(None) => " (binary)".to_string(),
                None => String::new(),
            };
            match r.status {
                b'A' => format!("added {s}{lines}"),
                b'D' => format!("deleted {s}"),
                b'T' => format!("type changed {s} ({} \u{2192} {})", kind(&r.old_mode), kind(&r.new_mode)),
                _ if r.old == r.new => format!("mode changed {s} ({} \u{2192} {})", r.old_mode, r.new_mode),
                _ => format!("edited {s}{lines}"),
            }
        };
        changes.push(Change { path: r.path.clone(), line });
    }
    // The big files the tree diff does not name: compared by size and sha256.
    let bigs: std::collections::BTreeSet<&[u8]> = big_b.keys().chain(big_a.keys()).copied().collect();
    let bigs: Vec<&[u8]> = bigs.into_iter().filter(|p| !seen.contains(p)).collect();
    seen.extend(bigs.iter().copied());
    for p in bigs {
        let s = shown(p);
        let line = match (big_b.get(p), big_a.get(p)) {
            (Some(b), Some(a)) => match (&b.sha256, &a.sha256) {
                (Some(x), Some(y)) if x == y && b.size == a.size && b.executable == a.executable => continue,
                (Some(_), Some(_)) => format!("edited {s} (over the diff cap)"),
                _ if b.size != a.size => format!("edited {s} (over the diff cap)"),
                _ => format!("not compared {s} (over the diff cap, past the hashing budget)"),
            },
            (None, Some(_)) => match nc_b.get(p) {
                Some(why) => format!("edited {s} (was not captured: {why}; now over the diff cap)"),
                None => format!("added {s} (over the diff cap)"),
            },
            (Some(_), None) => match nc_a.get(p) {
                Some(why) => format!("edited {s} (was over the diff cap; now not captured: {why})"),
                None => format!("deleted {s} (was over the diff cap)"),
            },
            (None, None) => continue,
        };
        let line = if secret_name(p) { withheld_line(p) } else { line };
        changes.push(Change { path: p.to_vec(), line });
    }
    // The paths not captured that neither of the above names.
    let ncs: std::collections::BTreeSet<&[u8]> = nc_b.keys().chain(nc_a.keys()).copied().collect();
    for p in ncs.into_iter().filter(|p| !seen.contains(p)) {
        let s = shown(p);
        let line = match (nc_b.get(p), nc_a.get(p)) {
            (Some(x), Some(y)) if x == y => continue,
            (Some(_), Some(y)) => format!("changed {s} (not captured: {y})"),
            (None, Some(y)) => format!("added {s} (not captured: {y})"),
            (Some(x), None) => format!("deleted {s} (was not captured: {x})"),
            (None, None) => continue,
        };
        changes.push(Change { path: p.to_vec(), line });
    }
    changes.sort_by(|a, b| a.path.cmp(&b.path));
    (changes, unshown)
}

/// A tree entry's kind by its mode.
fn kind(mode: &str) -> &'static str {
    match mode {
        "120000" => "symlink",
        "160000" => "submodule",
        "000000" => "nothing",
        _ => "file",
    }
}

/// The body's text before the patch: the changes, then what was not captured and what was over the cap after the
/// call.
fn list_section(body: &mut Vec<u8>, changes: &[Change], after: &Side) {
    if changes.is_empty() {
        body.extend_from_slice(format!("{NOTHING}\n").as_bytes());
    } else {
        body.extend_from_slice(b"changed during this call (by this call or any other process):\n");
        for c in changes {
            body.extend_from_slice(format!("{}\n", c.line).as_bytes());
        }
    }
    if !after.not_captured.is_empty() {
        body.extend_from_slice(b"\nnot captured, after the call:\n");
        for n in &after.not_captured {
            body.extend_from_slice(format!("{} ({})\n", shown(&n.path), n.reason).as_bytes());
        }
    }
    if !after.big.is_empty() {
        body.extend_from_slice(b"\nover the diff cap (1 MiB), after the call:\n");
        for b in &after.big {
            let line = if secret_name(&b.path) {
                format!("{} {WITHHELD}\n", shown(&b.path))
            } else {
                match &b.sha256 {
                    Some(h) => format!("{} ({} bytes, sha256 {h})\n", shown(&b.path), b.size),
                    None => format!("{} ({} bytes, not hashed: past the hashing budget)\n", shown(&b.path), b.size),
                }
            };
            body.extend_from_slice(line.as_bytes());
        }
    }
}

/// What the body and the summary say when the patch is left out whole: how many paths, over [`EXCLUDE_MAX`].
fn left_out(n: usize) -> String {
    format!("the patch is left out: {n} paths would be left out of it, more than {EXCLUDE_MAX}")
}

/// The summary line: the changes joined by `; `, at most [`SUMMARY_MAX`] named.
fn summary(changes: &[Change]) -> String {
    if changes.is_empty() {
        return NOTHING.into();
    }
    let mut s: Vec<&str> = changes.iter().take(SUMMARY_MAX).map(|c| c.line.as_str()).collect();
    let more = changes.len().saturating_sub(SUMMARY_MAX);
    let tail = format!("and {more} more");
    if more > 0 {
        s.push(&tail);
    }
    s.join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    fn run(dir: &Path, args: &[&str]) {
        let out = Command::new("git")
            .args(["-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"])
            .args(["-c", "maintenance.auto=false", "-c", "gc.auto=0"])
            .args(args)
            .current_dir(dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    }

    /// A committed repository holding `files`, and a scratch base beside it.
    fn repo(files: &[(&str, &[u8])]) -> (tempfile::TempDir, PathBuf, PathBuf) {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("w");
        let base = t.path().join("host");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&base).unwrap();
        run(&root, &["init", "-q"]);
        for (name, body) in files {
            let p = root.join(name);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
        }
        run(&root, &["add", "-f", "."]);
        run(&root, &["commit", "-q", "-m", "c"]);
        let root = root.canonicalize().unwrap();
        (t, root, base)
    }

    fn take(root: &Path, base: &Path) -> CallSnapshot {
        let repo = crate::gitconfig::inspect(root).unwrap();
        let git = Git::on(&std::env::split_paths(&std::env::var_os("PATH").unwrap()).collect::<Vec<_>>());
        CallSnapshot::take(git, &repo, base, None).unwrap()
    }

    fn text(r: &Report) -> String {
        String::from_utf8_lossy(&r.body).into_owned()
    }

    // --- what a change reads as ---

    #[test]
    fn an_edit_an_add_and_a_delete_read_as_such_with_the_patch_in_the_body() {
        let (_t, root, base) = repo(&[("a.txt", b"one\n"), ("sub/b.txt", b"two\n")]);
        let mut s = take(&root, &base);
        std::fs::write(root.join("a.txt"), "uno\n").unwrap();
        std::fs::remove_file(root.join("sub/b.txt")).unwrap();
        std::fs::write(root.join("n.txt"), "new\nlines\n").unwrap();
        let r = s.report(1 << 20).unwrap();
        assert_eq!(r.summary, "edited a.txt (+1 \u{2212}1); added n.txt (+2 \u{2212}0); deleted sub/b.txt");
        let body = text(&r);
        assert!(body.starts_with("changed during this call (by this call or any other process):\n"), "{body}");
        assert!(body.contains("-one\n+uno\n") && body.contains("+lines\n") && body.contains("-two\n"), "{body}");
        assert!(!r.truncated && !r.from_head);
    }

    #[test]
    fn nothing_changed_says_so_and_a_second_report_compares_with_the_first_snapshot() {
        let (_t, root, base) = repo(&[("a.txt", b"one\n")]);
        let mut s = take(&root, &base);
        let r = s.report(1 << 20).unwrap();
        assert_eq!((r.summary.as_str(), text(&r).as_str()), (NOTHING, "nothing changed during this call\n"));
        std::fs::write(root.join("a.txt"), "two\n").unwrap();
        assert_eq!(s.report(1 << 20).unwrap().summary, "edited a.txt (+1 \u{2212}1)");
        assert_eq!(s.report(1 << 20).unwrap().summary, "edited a.txt (+1 \u{2212}1)", "still against the first");
    }

    #[test]
    fn a_mode_change_a_type_change_and_a_binary_edit() {
        let (_t, root, base) = repo(&[("a.sh", b"echo\n"), ("l", b"x\n"), ("b.bin", b"\0\x01")]);
        let mut s = take(&root, &base);
        std::fs::set_permissions(root.join("a.sh"), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::remove_file(root.join("l")).unwrap();
        std::os::unix::fs::symlink("a.sh", root.join("l")).unwrap();
        std::fs::write(root.join("b.bin"), b"\0\x02").unwrap();
        let r = s.report(1 << 20).unwrap();
        assert_eq!(
            r.summary,
            "mode changed a.sh (100644 \u{2192} 100755); edited b.bin (binary); type changed l (file \u{2192} symlink)"
        );
    }

    #[test]
    fn a_path_that_could_forge_a_line_is_quoted() {
        let (_t, root, base) = repo(&[("a.txt", b"one\n")]);
        let mut s = take(&root, &base);
        std::fs::write(root.join("x\nnothing changed; deleted y"), "z\n").unwrap();
        let r = s.report(1 << 20).unwrap();
        assert_eq!(r.summary, "added \"x\\nnothing changed; deleted y\" (+1 \u{2212}0)");
    }

    #[test]
    fn a_line_separator_or_a_bidi_override_in_a_name_is_quoted_in_the_list_and_in_the_patch() {
        let (_t, root, base) = repo(&[("a.txt", b"one\n")]);
        // The repository asks for raw names in a patch's headers: the scratch's own config overrides it.
        run(&root, &["config", "core.quotePath", "false"]);
        let mut s = take(&root, &base);
        std::fs::write(root.join("x\u{2028}deleted id_rsa (contents withheld)"), "z\n").unwrap();
        std::fs::write(root.join("y\u{202e}txt.exe"), "w\n").unwrap();
        let r = s.report(1 << 20).unwrap();
        assert_eq!(
            r.summary,
            "added \"x\\u{2028}deleted id_rsa (contents withheld)\" (+1 \u{2212}0); added \"y\\u{202e}txt.exe\" (+1 \u{2212}0)"
        );
        let body = text(&r);
        assert!(
            !body.contains('\u{2028}') && !body.contains('\u{202e}'),
            "no raw separator or override anywhere: {body}"
        );
    }

    #[test]
    fn the_summary_names_twenty_and_counts_the_rest_and_the_body_is_cut_at_the_cap() {
        let (_t, root, base) = repo(&[("a.txt", b"one\n")]);
        let mut s = take(&root, &base);
        for i in 0..25 {
            std::fs::write(root.join(format!("f{i:02}.txt")), "x\n".repeat(100)).unwrap();
        }
        let r = s.report(1 << 20).unwrap();
        assert!(r.summary.ends_with("; and 5 more"), "{}", r.summary);
        assert_eq!(r.summary.matches("added ").count(), SUMMARY_MAX);
        let r = s.report(300).unwrap();
        assert!(r.truncated && r.body.len() == 300);
    }

    // --- a secret's body never shows (FILE_ATTACHMENTS.md H13, amended 2026-11-19) ---

    const SECRET: &str = "API_KEY=sk-live-0123456789";

    fn assert_no_secret(r: &Report) {
        let body = text(r);
        for needle in [SECRET, "sk-live", "rotated"] {
            assert!(!body.contains(needle) && !r.summary.contains(needle), "{needle} in {body}\n{}", r.summary);
        }
    }

    #[test]
    fn a_tracked_secret_changed_deleted_or_chmodded_is_listed_withheld() {
        for act in ["edit", "delete", "chmod"] {
            let (_t, root, base) = repo(&[(".env", SECRET.as_bytes()), ("a.txt", b"one\n")]);
            let mut s = take(&root, &base);
            match act {
                "edit" => std::fs::write(root.join(".env"), "API_KEY=rotated").unwrap(),
                "delete" => std::fs::remove_file(root.join(".env")).unwrap(),
                _ => std::fs::set_permissions(root.join(".env"), std::fs::Permissions::from_mode(0o755)).unwrap(),
            }
            let r = s.report(1 << 20).unwrap();
            assert_eq!(r.summary, "changed .env (contents withheld)", "{act}");
            assert!(!text(&r).contains("diff --git"), "{act}: no patch at all: {}", text(&r));
            assert_no_secret(&r);
        }
    }

    #[test]
    fn a_copy_or_a_move_of_a_tracked_secret_under_an_ordinary_name_is_withheld_by_its_blob() {
        for act in ["cp", "mv"] {
            let (_t, root, base) = repo(&[(".env", SECRET.as_bytes()), ("a.txt", b"one\n")]);
            let mut s = take(&root, &base);
            std::fs::copy(root.join(".env"), root.join("notes.txt")).unwrap();
            if act == "mv" {
                std::fs::remove_file(root.join(".env")).unwrap();
            }
            std::fs::write(root.join("a.txt"), "two\n").unwrap();
            let r = s.report(1 << 20).unwrap();
            let want = if act == "mv" {
                "changed .env (contents withheld); edited a.txt (+1 \u{2212}1); changed notes.txt (contents withheld)"
            } else {
                "edited a.txt (+1 \u{2212}1); changed notes.txt (contents withheld)"
            };
            assert_eq!(r.summary, want, "{act}");
            assert!(text(&r).contains("+two\n"), "{act}: the ordinary edit keeps its patch");
            assert_no_secret(&r);
        }
    }

    #[test]
    fn an_empty_tracked_secret_withholds_no_empty_file() {
        let (_t, root, base) = repo(&[(".env", b""), ("a.txt", b"one\n")]);
        let mut s = take(&root, &base);
        std::fs::write(root.join("e.txt"), "").unwrap();
        assert_eq!(s.report(1 << 20).unwrap().summary, "added e.txt (+0 \u{2212}0)");
        // The other side: an empty file whose own name looks like a secret is withheld by the name.
        std::fs::remove_file(root.join(".env")).unwrap();
        assert_eq!(s.report(1 << 20).unwrap().summary, "changed .env (contents withheld); added e.txt (+0 \u{2212}0)");
    }

    #[test]
    fn a_tracked_secret_over_the_cap_shows_no_size_and_no_hash() {
        let mut big = SECRET.as_bytes().to_vec();
        big.resize((DIFF_CAP + 10) as usize, b'#');
        let (_t, root, base) = repo(&[(".env", &big), ("a.txt", b"one\n")]);
        let mut s = take(&root, &base);
        big[0] = b'X';
        std::fs::write(root.join(".env"), &big).unwrap();
        let r = s.report(1 << 20).unwrap();
        assert_eq!(r.summary, "changed .env (contents withheld)");
        let body = text(&r);
        assert!(body.contains("\nover the diff cap (1 MiB), after the call:\n.env (contents withheld)\n"), "{body}");
        assert!(!body.contains("sha256") && !body.contains(&(DIFF_CAP + 10).to_string()), "{body}");
        assert_no_secret(&r);
    }

    #[test]
    fn a_secret_name_in_a_directory_like_ssh_is_withheld_too() {
        let (_t, root, base) = repo(&[(".ssh/config", b"Host x\n"), ("a.txt", b"one\n")]);
        let mut s = take(&root, &base);
        std::fs::write(root.join(".ssh/config"), "Host rotated\n").unwrap();
        let r = s.report(1 << 20).unwrap();
        assert_eq!(r.summary, "changed .ssh/config (contents withheld)");
        assert_no_secret(&r);
    }

    #[test]
    fn past_the_exclude_bound_the_patch_is_left_out_and_both_the_body_and_the_summary_say_so() {
        let pems: Vec<(String, Vec<u8>)> =
            (0..=EXCLUDE_MAX).map(|i| (format!("k/{i}.pem"), b"key\n".to_vec())).collect();
        let mut files: Vec<(&str, &[u8])> = pems.iter().map(|(n, b)| (n.as_str(), b.as_slice())).collect();
        files.push(("a.txt", b"one\n"));
        let (_t, root, base) = repo(&files);
        let mut s = take(&root, &base);
        for (n, _) in &pems {
            std::fs::write(root.join(n), "rotated\n").unwrap();
        }
        std::fs::write(root.join("a.txt"), "two\n").unwrap();
        let r = s.report(4 << 20).unwrap();
        let said = format!(
            "the patch is left out: {} paths would be left out of it, more than {EXCLUDE_MAX}",
            EXCLUDE_MAX + 1
        );
        assert!(r.summary.ends_with(&format!("; and {} more; {said}", EXCLUDE_MAX + 2 - SUMMARY_MAX)), "{}", r.summary);
        let body = text(&r);
        assert!(body.contains(&format!("\n{said}\n")) && !body.contains("diff --git"), "{}", &body[body.len() - 300..]);
        assert!(body.contains("edited a.txt (+1 \u{2212}1)\n"), "the change list stays");
    }

    // --- reconciled with H12's lists ---

    #[test]
    fn a_big_file_is_compared_by_hash_and_a_same_size_rewrite_inside_one_tick_reads_as_an_edit() {
        let big = vec![b'a'; (DIFF_CAP + 10) as usize];
        let (_t, root, base) = repo(&[("big.bin", &big), ("still.bin", &big), ("a.txt", b"one\n")]);
        let mut s = take(&root, &base);
        // Same size, written at once: inside one tick of the first snapshot's read, so its hash was not kept.
        let mut other = big.clone();
        other[0] = b'b';
        std::fs::write(root.join("big.bin"), &other).unwrap();
        let r = s.report(1 << 20).unwrap();
        assert_eq!(r.summary, "edited big.bin (over the diff cap)");
        let body = text(&r);
        assert!(body.contains(&format!("big.bin ({} bytes, sha256 ", DIFF_CAP + 10)), "{body}");
        assert!(!body.contains("aaaa") && !body.contains("diff --git"), "no body of a big file");
    }

    #[test]
    fn a_file_crossing_the_cap_reads_as_an_edit_with_no_patch() {
        let big = vec![b'a'; (DIFF_CAP + 10) as usize];
        let (_t, root, base) = repo(&[("grows.txt", b"small\n"), ("shrinks.txt", &big)]);
        let mut s = take(&root, &base);
        std::fs::write(root.join("grows.txt"), &big).unwrap();
        std::fs::write(root.join("shrinks.txt"), "small now\n").unwrap();
        let r = s.report(1 << 20).unwrap();
        assert_eq!(r.summary, "edited grows.txt (now over the diff cap); edited shrinks.txt (was over the diff cap)");
        assert!(!text(&r).contains("diff --git"), "{}", text(&r));
    }

    #[test]
    fn a_tracked_big_file_that_is_also_ignored_and_unchanged_is_not_reported() {
        let big = vec![b'a'; (DIFF_CAP + 10) as usize];
        let (_t, root, base) = repo(&[("big.bin", &big), (".gitignore", b"*.bin\n")]);
        let mut s = take(&root, &base);
        let r = s.report(1 << 20).unwrap();
        assert_eq!(r.summary, NOTHING, "{}", text(&r));
    }

    #[test]
    fn a_fifo_made_during_the_call_is_added_not_captured_and_an_unchanged_secret_name_is_listed_only() {
        let (_t, root, base) = repo(&[("a.txt", b"one\n")]);
        std::fs::write(root.join("id_utils.py"), "x = 1\n").unwrap();
        let mut s = take(&root, &base);
        let ok = Command::new("mkfifo").arg(root.join("pipe")).status().unwrap().success();
        assert!(ok);
        std::fs::write(root.join("id_utils.py"), "x = 2\n").unwrap();
        let r = s.report(1 << 20).unwrap();
        assert_eq!(r.summary, "added pipe (not captured: not a regular file)");
        let body = text(&r);
        assert!(
            body.contains("\nnot captured, after the call:\nid_utils.py (withheld: the name looks like a secret)\npipe (not a regular file)\n"),
            "{body}"
        );
        assert!(!body.contains("x = 2"));
    }

    // --- what the person's repository keeps ---

    #[test]
    fn an_intent_to_add_entry_and_a_from_head_index_report_like_any_other() {
        let (_t, root, base) = repo(&[("a.txt", b"one\n")]);
        std::fs::write(root.join("n.txt"), "planned\n").unwrap();
        run(&root, &["add", "-N", "n.txt"]);
        let mut s = take(&root, &base);
        assert_eq!(s.report(1 << 20).unwrap().summary, NOTHING);
        std::fs::write(root.join("n.txt"), "planned\nmore\n").unwrap();
        assert_eq!(s.report(1 << 20).unwrap().summary, "edited n.txt (+1 \u{2212}0)");
        // No index at all: both trees come from HEAD, and the report says so.
        let (_t2, root2, base2) = repo(&[("a.txt", b"one\n")]);
        std::fs::remove_file(root2.join(".git/index")).unwrap();
        let mut s = take(&root2, &base2);
        std::fs::write(root2.join("a.txt"), "two\n").unwrap();
        let r = s.report(1 << 20).unwrap();
        assert!(r.from_head);
        assert_eq!(r.summary, "edited a.txt (+1 \u{2212}1)");
    }

    #[test]
    fn reporting_writes_nothing_into_the_repository_and_the_scratch_goes_on_drop() {
        let (_t, root, base) = repo(&[("a.txt", b"one\n"), (".env", SECRET.as_bytes())]);
        let read_git = || {
            let mut m = BTreeMap::new();
            let mut stack = vec![root.join(".git")];
            while let Some(d) = stack.pop() {
                for e in std::fs::read_dir(&d).unwrap().flatten() {
                    if e.file_type().unwrap().is_dir() {
                        stack.push(e.path());
                    } else {
                        m.insert(e.path(), std::fs::read(e.path()).unwrap());
                    }
                }
            }
            m
        };
        let was = read_git();
        let mut s = take(&root, &base);
        std::fs::write(root.join("a.txt"), "two\n").unwrap();
        std::fs::write(root.join(".env"), "API_KEY=rotated").unwrap();
        s.report(1 << 20).unwrap();
        assert_eq!(read_git(), was);
        drop(s);
        assert_eq!(std::fs::read_dir(&base).unwrap().count(), 0);
    }
}
