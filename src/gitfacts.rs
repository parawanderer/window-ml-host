//! gitfacts.rs — the host's OWN git queries about one file in a mount: whether git ignores it, and whether git can
//! undo a write to it (window-ml's FILE_ATTACHMENTS.md, H7).
//!
//! These spawns are the host's, not a call's, so they run under a stricter belt than a call does: the person's global
//! and system config are not read (`git lfs install` puts a `filter.lfs.clean` there, which a content compare would
//! run), `GIT_DIR` and `GIT_WORK_TREE` are named so a repository's `core.worktree` cannot point the query elsewhere, and
//! no command that compares the work tree's content (`diff`, `status`, `add`) is ever run: undoability is decided by
//! hashing the file's bytes with `--no-filters` and comparing the blob with the index's and HEAD's entries.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::gitconfig::RepoConfig;

/// How long one of the host's git queries may take before it is killed and its answer is unknown.
const GIT_TIMEOUT: Duration = Duration::from_secs(10);
/// The most bytes of a file hashed to decide undoability; past it the answer is false (asks), never a guess.
pub const MAX_HASHED: u64 = 64 << 20;
/// The most bytes of a query's stdout kept.
const MAX_STDOUT: usize = 1 << 20;

/// What the host's git queries need: the git program, found on the session's PATH.
pub struct Git {
    pub program: Option<PathBuf>,
}

impl Git {
    /// Finds `git` on `path` the way `spawn` finds a program.
    pub fn on(path: &[PathBuf]) -> Git {
        let program = path.iter().map(|d| d.join("git")).find(|p| p.is_file());
        Git { program }
    }

    /// Runs one query in the repository: `(exit code, stdout)`, `None` when git is missing, failed to start, or ran past
    /// the timeout (killed). `stdin` is written whole and closed.
    fn query(&self, repo: &RepoConfig, args: &[&str], stdin: Option<&mut dyn Read>) -> Option<(i32, Vec<u8>)> {
        let program = self.program.as_ref()?;
        let git_dir = repo.git_dir.as_ref()?;
        let mut c = Command::new(program);
        c.env_clear()
            .envs(belt(git_dir, &repo.root))
            .current_dir(&repo.root)
            .args(args)
            .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = c.spawn().ok()?;
        if let Some(input) = stdin {
            let mut w = child.stdin.take()?;
            // A write error (git exited early) shows in the exit status below.
            let _ = std::io::copy(input, &mut w);
            let _ = w.flush();
        }
        let mut out = child.stdout.take()?;
        let reader = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = out.by_ref().take(MAX_STDOUT as u64).read_to_end(&mut buf);
            // Drain the rest so git is never blocked on a full pipe.
            let _ = std::io::copy(&mut out, &mut std::io::sink());
            buf
        });
        let started = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(s)) => break s,
                Ok(None) if started.elapsed() < GIT_TIMEOUT => std::thread::sleep(Duration::from_millis(2)),
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
            }
        };
        let stdout = reader.join().ok()?;
        Some((status.code()?, stdout))
    }

    /// Whether git ignores `rel` (relative to the work tree): `None` when git cannot be asked.
    pub fn ignored(&self, repo: &RepoConfig, rel: &str) -> Option<bool> {
        match self.query(repo, &["check-ignore", "-q", "--", rel], None)? {
            (0, _) => Some(true),
            (1, _) => Some(false),
            _ => None,
        }
    }

    /// Whether a `git checkout` of `rel` would give back the bytes `content` holds now: the file is tracked at stage 0,
    /// carries no assume-unchanged or skip-worktree bit (either hides a change from git), and its blob is the index's
    /// and HEAD's. `None` when the repository's config runs code (the undo itself would run it) or git cannot be asked;
    /// `false` for an untracked, modified or ignored file, one over [`MAX_HASHED`], or a repository with no commit.
    pub fn undoable(&self, repo: &RepoConfig, rel: &str, size: u64, content: &mut dyn Read) -> Option<bool> {
        if repo.runs_code || repo.git_dir.is_none() {
            return None;
        }
        let (code, out) = self.query(repo, &["ls-files", "-s", "-v", "-z", "--", rel], None)?;
        if code != 0 {
            return None;
        }
        let Some(index) = parse_ls_files(&out, rel) else { return Some(false) };
        if !index.plain {
            return Some(false);
        }
        let head = match self.query(repo, &["ls-tree", "-z", "HEAD", "--", rel], None)? {
            (0, out) => parse_ls_tree(&out, rel),
            // No HEAD: a repository with no commit has nothing to check out.
            _ => None,
        };
        let Some(head) = head else { return Some(false) };
        if head != index.blob || size > MAX_HASHED {
            return Some(false);
        }
        let mut limited = content.take(MAX_HASHED);
        let (code, out) = self.query(repo, &["hash-object", "--no-filters", "--stdin"], Some(&mut limited))?;
        if code != 0 {
            return None;
        }
        Some(String::from_utf8_lossy(&out).trim() == index.blob)
    }
}

/// The environment of every host git query: nothing of the host's but `HOME`'s absence, the person's global and system
/// config off, the repository named, no optional locks, no prompt, no pager, no fsmonitor.
pub fn belt(git_dir: &Path, work_tree: &Path) -> Vec<(String, String)> {
    let p = |p: &Path| p.to_string_lossy().into_owned();
    [
        ("GIT_DIR", p(git_dir)),
        ("GIT_WORK_TREE", p(work_tree)),
        ("GIT_CONFIG_GLOBAL", "/dev/null".into()),
        ("GIT_CONFIG_NOSYSTEM", "1".into()),
        ("GIT_OPTIONAL_LOCKS", "0".into()),
        ("GIT_TERMINAL_PROMPT", "0".into()),
        ("GIT_CONFIG_COUNT", "2".into()),
        ("GIT_CONFIG_KEY_0", "core.fsmonitor".into()),
        ("GIT_CONFIG_VALUE_0", "false".into()),
        ("GIT_CONFIG_KEY_1", "core.pager".into()),
        ("GIT_CONFIG_VALUE_1", "cat".into()),
        ("LC_ALL", "C".into()),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect()
}

/// One index entry of `git ls-files -s -v -z`.
#[derive(Debug, PartialEq)]
struct IndexEntry {
    blob: String,
    /// Stage 0, a regular file's mode, and tag `H` (cached, neither assume-unchanged nor skip-worktree).
    plain: bool,
}

/// Reads the entry for exactly `rel` from `<tag> <mode> <blob> <stage>\t<path>\0` records.
fn parse_ls_files(out: &[u8], rel: &str) -> Option<IndexEntry> {
    out.split(|b| *b == 0).find_map(|rec| {
        let rec = std::str::from_utf8(rec).ok()?;
        let (meta, path) = rec.split_once('\t')?;
        if path != rel {
            return None;
        }
        let mut f = meta.split(' ');
        let (tag, mode, blob, stage) = (f.next()?, f.next()?, f.next()?, f.next()?);
        let plain = tag == "H" && stage == "0" && (mode == "100644" || mode == "100755");
        Some(IndexEntry { blob: blob.to_string(), plain })
    })
}

/// Reads HEAD's blob for exactly `rel` from `<mode> <type> <blob>\t<path>\0` records.
fn parse_ls_tree(out: &[u8], rel: &str) -> Option<String> {
    out.split(|b| *b == 0).find_map(|rec| {
        let rec = std::str::from_utf8(rec).ok()?;
        let (meta, path) = rec.split_once('\t')?;
        let mut f = meta.split(' ');
        let (_mode, kind, blob) = (f.next()?, f.next()?, f.next()?);
        (path == rel && kind == "blob").then(|| blob.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- reading git's records ---

    #[test]
    fn an_index_entry_is_plain_only_when_cached_at_stage_zero() {
        let rec = |tag: &str, stage: &str| format!("{tag} 100644 abc {stage}\ta.txt\0").into_bytes();
        assert_eq!(parse_ls_files(&rec("H", "0"), "a.txt"), Some(IndexEntry { blob: "abc".into(), plain: true }));
        assert!(!parse_ls_files(&rec("h", "0"), "a.txt").unwrap().plain, "assume-unchanged");
        assert!(!parse_ls_files(&rec("S", "0"), "a.txt").unwrap().plain, "skip-worktree");
        assert!(!parse_ls_files(&rec("H", "2"), "a.txt").unwrap().plain, "a conflict stage");
        assert_eq!(parse_ls_files(&rec("H", "0"), "b.txt"), None, "only the exact path");
        assert!(!parse_ls_files(b"H 120000 abc 0\ta.txt\0", "a.txt").unwrap().plain, "a symlink entry");
    }

    #[test]
    fn a_head_entry_is_a_blob_at_the_exact_path() {
        assert_eq!(parse_ls_tree(b"100644 blob abc\ta.txt\0", "a.txt").as_deref(), Some("abc"));
        assert_eq!(parse_ls_tree(b"040000 tree abc\ta.txt\0", "a.txt"), None);
        assert_eq!(parse_ls_tree(b"100644 blob abc\tsub/a.txt\0", "a.txt"), None);
    }
}
