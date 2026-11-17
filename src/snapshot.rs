//! snapshot.rs — the tree an `ml.sh` call's diff is made from, built without writing into the repository (window-ml's
//! FILE_ATTACHMENTS.md, H10).
//!
//! A [`Scratch`] holds a copy of the person's index (for its stat cache) and a private object directory, both in the
//! host's own directory, with the repository's object directory as an alternate (named in the private directory's
//! `info/alternates`, which has no separator to quote, unlike `GIT_ALTERNATE_OBJECT_DIRECTORIES`). Every git spawn that
//! reads or writes the index or objects names the copy as `GIT_INDEX_FILE` and the private directory as
//! `GIT_OBJECT_DIRECTORY`, under the host's git belt (src/gitfacts.rs), so a tree or a blob it writes lands there and the
//! person's index, HEAD, stash list and object store are unchanged; the two `rev-parse --git-path` queries that find the
//! repository's object directory and index run before the scratch exists and name neither.
//! The private directory goes when the `Scratch` is dropped, which is when the diff has been made. A split index
//! (`sharedindex.*` beside it) is not copied, since its shared half would be read from, and could be rewritten in, the
//! repository's git directory: the tree is built from HEAD instead, so the stat cache is lost but nothing is written.
//! Entering the changed files is H11; this module only holds the store and writes the tree.

use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use crate::gitconfig::RepoConfig;
use crate::gitfacts::Git;

/// A call's scratch index and private object directory. Removed on drop.
pub struct Scratch {
    dir: PathBuf,
    env: Vec<(String, String)>,
    /// Whether the index came from HEAD because the person's was a split index, missing (a `clone --no-checkout`), or
    /// could not be copied.
    pub from_head: bool,
}

impl Scratch {
    /// Makes a scratch store for `repo` under `base` (the host's own directory) and fills its index: a copy of the
    /// person's, or HEAD's tree when that is a split index. A repository with neither an index nor a commit gets an
    /// empty one. `Err` names why the store could not be made, which the call reports as a null diff.
    pub fn new(git: &Git, repo: &RepoConfig, base: &Path) -> Result<Scratch, String> {
        let git_dir = repo.git_dir.as_ref().ok_or("the repository's git directory was not found")?;
        let path_of = |name: &str| -> Result<PathBuf, String> {
            let (code, out) = git
                .query_env(repo, &[], None, &["rev-parse", "--git-path", name], None)
                .ok_or("git could not be run")?;
            if code != 0 {
                return Err(format!("git rev-parse --git-path {name} exited {code}"));
            }
            let out = out.strip_suffix(b"\n").unwrap_or(&out);
            let p = PathBuf::from(std::ffi::OsStr::from_bytes(out));
            Ok(if p.is_absolute() { p } else { repo.root.join(p) })
        };
        let objects = path_of("objects")?;
        let index = path_of("index")?;
        let dir = base.join(format!("snapshot-{}", hex::encode(rand_bytes())));
        let made = |e: std::io::Error| format!("the scratch directory could not be made: {e}");
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir).map_err(made)?;
        // From here on the directory exists, so every early return below removes it (Drop).
        let mut s = Scratch { env: vec![], dir, from_head: false };
        let objects_dir = s.dir.join("objects");
        std::fs::create_dir_all(objects_dir.join("info")).map_err(made)?;
        std::fs::create_dir(s.dir.join("empty")).map_err(made)?;
        let alt = objects.as_os_str().as_bytes();
        if alt.contains(&b'\n') {
            return Err("the repository's object directory has a newline in its path".into());
        }
        std::fs::write(objects_dir.join("info/alternates"), [alt, b"\n"].concat()).map_err(made)?;
        let p = |p: &Path| p.to_string_lossy().into_owned();
        s.env = vec![
            ("GIT_INDEX_FILE".into(), p(&s.dir.join("index"))),
            ("GIT_OBJECT_DIRECTORY".into(), p(&objects_dir)),
            // Writing the index runs `post-index-change`, and its check of a racily clean entry reads the file
            // through the clean filter, at its path from the process's directory (write-tree never enters the work
            // tree): no hook resolves, and the spawn runs in, and names as its work tree, an empty directory.
            ("GIT_WORK_TREE".into(), p(&s.dir.join("empty"))),
            ("GIT_CONFIG_COUNT".into(), "3".into()),
            ("GIT_CONFIG_KEY_2".into(), "core.hooksPath".into()),
            ("GIT_CONFIG_VALUE_2".into(), "/dev/null".into()),
        ];
        if split_index(git_dir) || std::fs::copy(&index, s.dir.join("index")).is_err() {
            s.from_head = true;
            // No HEAD (a repository with no commit) leaves the index empty, which is what that repository has.
            let _ = s.git(git, repo, &["read-tree", "HEAD"]);
        }
        Ok(s)
    }

    /// Runs one git query against the scratch index and private objects: `(exit code, stdout)`.
    pub fn git(&self, git: &Git, repo: &RepoConfig, args: &[&str]) -> Option<(i32, Vec<u8>)> {
        git.query_env(repo, &self.env, Some(&self.dir.join("empty")), args, None)
    }

    /// Writes the scratch index as a tree into the private objects and returns its id.
    pub fn tree(&self, git: &Git, repo: &RepoConfig) -> Result<String, String> {
        match self.git(git, repo, &["write-tree"]) {
            Some((0, out)) => Ok(String::from_utf8_lossy(&out).trim().to_string()),
            Some((code, _)) => Err(format!("git write-tree exited {code}")),
            None => Err("git could not be run".into()),
        }
    }

    /// The scratch directory: the index and the private objects.
    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Whether the repository keeps a split index: its index's shared half is a `sharedindex.<id>` in the git directory.
fn split_index(git_dir: &Path) -> bool {
    std::fs::read_dir(git_dir)
        .map(|d| d.flatten().any(|e| e.file_name().to_string_lossy().starts_with("sharedindex.")))
        .unwrap_or(true)
}

fn rand_bytes() -> [u8; 8] {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).expect("the OS random source");
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::process::Command;

    fn have_git() -> bool {
        Command::new("git").arg("--version").output().is_ok()
    }

    fn run(dir: &Path, args: &[&str]) -> String {
        let out = Command::new("git")
            .args(["-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"])
            .args(args)
            .current_dir(dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// Every file under `.git` with its bytes, so a write anywhere there (an object, the index, a ref, a stash) shows.
    fn dot_git(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        let mut m = BTreeMap::new();
        let mut stack = vec![root.join(".git")];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap().flatten() {
                let p = e.path();
                if e.file_type().unwrap().is_dir() {
                    stack.push(p);
                } else {
                    m.insert(p.clone(), std::fs::read(&p).unwrap_or_default());
                }
            }
        }
        m
    }

    /// A repository with one commit, a hook, a clean filter and an fsmonitor configured, each of which would leave
    /// `marks/<name>` if it ran.
    fn repo() -> (tempfile::TempDir, PathBuf, PathBuf) {
        repo_named("w")
    }

    fn repo_named(name: &str) -> (tempfile::TempDir, PathBuf, PathBuf) {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join(name);
        let marks = t.path().join("marks");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&marks).unwrap();
        run(&root, &["init", "-q"]);
        std::fs::write(root.join("a.txt"), "one\n").unwrap();
        std::fs::create_dir(root.join("sub")).unwrap();
        std::fs::write(root.join("sub/b.txt"), "two\n").unwrap();
        run(&root, &["add", "."]);
        run(&root, &["commit", "-q", "-m", "c"]);
        let m = |n: &str| format!("touch {}", marks.join(n).display());
        run(&root, &["config", "filter.f.clean", &m("clean")]);
        run(&root, &["config", "core.fsmonitor", &m("fsmonitor")]);
        std::fs::write(root.join(".gitattributes"), "* filter=f\n").unwrap();
        let hook = root.join(".git/hooks/post-index-change");
        std::fs::write(&hook, format!("#!/bin/sh\n{}\n", m("hook"))).unwrap();
        std::fs::set_permissions(&hook, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        (t, root, marks)
    }

    /// Forgets the marks the test's own git commands left, so what remains is what the snapshot ran.
    fn clear(marks: &Path) {
        for e in std::fs::read_dir(marks).unwrap().flatten() {
            std::fs::remove_file(e.path()).unwrap();
        }
    }

    fn scratch_base(t: &tempfile::TempDir) -> PathBuf {
        t.path().join("host")
    }

    fn inspect(root: &Path) -> RepoConfig {
        crate::gitconfig::inspect(root).unwrap()
    }

    fn git_on_path() -> Git {
        Git::on(&std::env::split_paths(&std::env::var_os("PATH").unwrap()).collect::<Vec<_>>())
    }

    // --- the tree, built from the person's index ---

    #[test]
    fn a_clean_index_gives_heads_tree_and_writes_nothing_into_the_repository() {
        if !have_git() {
            return;
        }
        let (t, root, marks) = repo();
        clear(&marks);
        let before = dot_git(&root);
        let (g, r) = (git_on_path(), inspect(&root));
        let s = Scratch::new(&g, &r, &scratch_base(&t)).unwrap();
        assert!(!s.from_head);
        assert_eq!(s.tree(&g, &r).unwrap(), run(&root, &["rev-parse", "HEAD^{tree}"]));
        let dir = s.dir().to_path_buf();
        drop(s);
        assert!(!dir.exists(), "the scratch directory goes with the Scratch");
        assert_eq!(dot_git(&root), before, "index, HEAD, refs, stash and objects are byte-identical");
        assert_eq!(std::fs::read_dir(&marks).unwrap().count(), 0, "no filter, fsmonitor or hook ran");
    }

    #[test]
    fn a_staged_change_gets_its_new_trees_in_the_private_objects_only() {
        if !have_git() {
            return;
        }
        let (t, root, marks) = repo();
        std::fs::write(root.join("sub/c.txt"), "three\n").unwrap();
        run(&root, &["-c", "filter.f.clean=cat", "add", "sub/c.txt"]);
        clear(&marks);
        let before = dot_git(&root);
        let (g, r) = (git_on_path(), inspect(&root));
        let s = Scratch::new(&g, &r, &scratch_base(&t)).unwrap();
        let tree = s.tree(&g, &r).unwrap();
        assert_ne!(tree, run(&root, &["rev-parse", "HEAD^{tree}"]));
        // The new trees exist through the scratch store and not in the repository: a build that drops
        // GIT_OBJECT_DIRECTORY writes them into .git/objects and fails the comparison below.
        assert_eq!(s.git(&g, &r, &["cat-file", "-t", &tree]).unwrap().0, 0);
        let loose = s.dir().join("objects").join(&tree[..2]).join(&tree[2..]);
        assert!(loose.exists(), "{} holds the root tree", loose.display());
        drop(s);
        assert_eq!(dot_git(&root), before);
        let in_repo = Command::new("git").args(["cat-file", "-e", &tree]).current_dir(&root).status().unwrap();
        assert!(!in_repo.success(), "the tree never reached the repository's object store");
        assert_eq!(
            std::fs::read_dir(&marks).unwrap().flatten().map(|e| e.file_name()).collect::<Vec<_>>(),
            Vec::<std::ffi::OsString>::new()
        );
    }

    #[test]
    fn a_repository_with_no_commit_and_no_index_gives_the_empty_tree() {
        if !have_git() {
            return;
        }
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("w");
        std::fs::create_dir_all(&root).unwrap();
        run(&root, &["init", "-q"]);
        let before = dot_git(&root);
        let (g, r) = (git_on_path(), inspect(&root));
        let s = Scratch::new(&g, &r, &scratch_base(&t)).unwrap();
        let empty = run(&root, &["hash-object", "-t", "tree", "/dev/null"]);
        assert_eq!(s.tree(&g, &r).unwrap(), empty);
        drop(s);
        assert_eq!(dot_git(&root), before);
    }

    // --- the alternate, and a scratch that fails part-way ---

    #[test]
    fn a_colon_in_the_repository_path_keeps_its_objects_reachable() {
        if !have_git() {
            return;
        }
        // `GIT_ALTERNATE_OBJECT_DIRECTORIES` splits on ':', which would drop this store while write-tree still exits 0.
        let (t, root, _marks) = repo_named("w:x");
        let blob = run(&root, &["rev-parse", "HEAD:a.txt"]);
        let (g, r) = (git_on_path(), inspect(&root));
        let s = Scratch::new(&g, &r, &scratch_base(&t)).unwrap();
        let read = s.git(&g, &r, &["cat-file", "blob", &blob]).unwrap();
        assert_eq!((read.0, read.1), (0, b"one\n".to_vec()), "HEAD's blob is read through the alternate");
        assert_eq!(s.tree(&g, &r).unwrap(), run(&root, &["rev-parse", "HEAD^{tree}"]));
    }

    #[test]
    fn a_scratch_that_fails_after_its_directory_exists_leaves_nothing_behind() {
        if !have_git() {
            return;
        }
        // A newline in the object directory's path cannot be written to `info/alternates`: refused after the
        // scratch directory was made, which must go with it.
        let (t, root, _marks) = repo_named("w\nx");
        let (g, r) = (git_on_path(), inspect(&root));
        let base = scratch_base(&t);
        let e = Scratch::new(&g, &r, &base).err().unwrap();
        assert!(e.contains("newline"), "{e}");
        assert_eq!(std::fs::read_dir(&base).unwrap().count(), 0, "no scratch directory is left in {}", base.display());
    }

    #[test]
    fn a_commit_with_no_index_takes_heads_tree_not_the_empty_one() {
        if !have_git() {
            return;
        }
        // `git clone --no-checkout` leaves a commit and no `.git/index`: the base is HEAD's tree, and from_head says so.
        let (t, root, marks) = repo();
        std::fs::remove_file(root.join(".git/index")).unwrap();
        clear(&marks);
        let before = dot_git(&root);
        let (g, r) = (git_on_path(), inspect(&root));
        let s = Scratch::new(&g, &r, &scratch_base(&t)).unwrap();
        assert!(s.from_head);
        assert_eq!(s.tree(&g, &r).unwrap(), run(&root, &["rev-parse", "HEAD^{tree}"]));
        drop(s);
        assert_eq!(dot_git(&root), before);
        assert_eq!(std::fs::read_dir(&marks).unwrap().count(), 0);
    }

    // --- the split index falls back to HEAD ---

    #[test]
    fn a_split_index_is_not_copied_and_the_tree_comes_from_head() {
        if !have_git() {
            return;
        }
        let (t, root, marks) = repo();
        run(&root, &["update-index", "--split-index"]);
        std::fs::write(root.join("d.txt"), "four\n").unwrap();
        run(&root, &["-c", "filter.f.clean=cat", "add", "d.txt"]);
        clear(&marks);
        let before = dot_git(&root);
        let (g, r) = (git_on_path(), inspect(&root));
        let s = Scratch::new(&g, &r, &scratch_base(&t)).unwrap();
        assert!(s.from_head);
        assert_eq!(s.tree(&g, &r).unwrap(), run(&root, &["rev-parse", "HEAD^{tree}"]));
        drop(s);
        assert_eq!(dot_git(&root), before);
        assert_eq!(
            std::fs::read_dir(&marks).unwrap().flatten().map(|e| e.file_name()).collect::<Vec<_>>(),
            Vec::<std::ffi::OsString>::new()
        );
    }

    // --- a linked worktree reads the common object store ---

    #[test]
    fn a_linked_worktree_finds_its_objects_through_the_common_directory() {
        if !have_git() {
            return;
        }
        let (t, root, _marks) = repo();
        let wt = t.path().join("wt");
        run(&root, &["worktree", "add", "-q", wt.to_str().unwrap()]);
        let before = dot_git(&root);
        let (g, r) = (git_on_path(), inspect(&wt));
        let s = Scratch::new(&g, &r, &scratch_base(&t)).unwrap();
        assert_eq!(s.tree(&g, &r).unwrap(), run(&wt, &["rev-parse", "HEAD^{tree}"]));
        drop(s);
        assert_eq!(dot_git(&root), before);
    }
}
