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
//! The private directory goes when the `Scratch` is dropped, which is when the diff has been made. The person's index
//! is opened without following a link and copied only when it is a regular file of at most 256 MiB (a link, a larger
//! one or a missing one leaves the tree to come from HEAD, and a link's target is never opened). A split index (git's `rev-parse
//! --shared-index-path` names a shared half) is not copied either, since its shared half would be read from, and could
//! be rewritten in, the repository's git directory: the tree is built from HEAD instead, so the stat cache is lost but
//! nothing is written. The scratch index is never written split (`core.splitIndex=false`).
//!
//! Entering the work tree's changes (H11, [`Scratch::enter_changes`]): the changed set is the host's own comparison of
//! each entry's cached stat with an `lstat` of its path, never a `git status` or `update-index --refresh` (either reads
//! a racily clean file through the clean filter). A changed file is hashed with `git hash-object -w --no-filters
//! --stdin-paths` into the private objects and entered with `git update-index -z --index-info`, which takes the id as
//! given and runs no filter. Untracked files come from `ls-files --others --exclude-standard`, so an ignored file
//! (an ignored `.env`) never enters a tree, except inside the uploads folder, whose untracked files all do; and an
//! untracked file whose path looks like a secret ([`looks_secret`]) enters neither tree, ignored or not, in the uploads
//! folder or out. A path with
//! a symlink among its parents is treated as deleted, as git treats it, so nothing outside the work tree is hashed;
//! a symlink itself is entered as a link (its target text), never followed. An entry git keeps out of `status`
//! (assume-unchanged, skip-worktree) and a submodule's gitlink are left as they are.
//! A file swapped for a link between the `lstat` and git's open of it would be hashed through the link, so every file
//! is `lstat`ed again after hashing and one that changed is hashed again from a descriptor the host opened without
//! following links; a swap and a swap back inside that window is the residue.
//! Bounds (H12, src/snapshot_bounds.rs): only a captured file is in the tree. A regular file over `DIFF_CAP` (1 MiB)
//! is left out, tracked or not, and listed with its size and sha256; a FIFO, a socket, a device, a file the host cannot
//! open and an untracked file whose name looks like a secret are listed as not captured, with the reason, and a tracked
//! one leaves the tree. git lists no FIFO, socket or device, so the host finds them by type in the directories the
//! listings reached, never opening one; one in a directory that holds no file git lists is not found, and is in no
//! tree either. A work tree of more than `WALK_CAP` (20 000) files, tracked and untracked but not ignored, gives a null
//! diff with the reason, before any file is read. The changed set is hashed in one `hash-object --stdin-paths` batch
//! whose answer is read under the git query's 1 MiB cap, about 25 500 ids: a larger changed set fails the snapshot
//! (closed) rather than pair a path with another file's id, which `WALK_CAP` keeps out of reach (janitor-2, host#51).
//!
//! A git too old for `rev-parse --shared-index-path` echoes the option back, which reads as a split index: every
//! repository's tree then comes from HEAD, so the stat cache is lost and every tracked file is hashed, and nothing is
//! written into the repository.

use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::facts::looks_secret;
use crate::gitconfig::RepoConfig;
use crate::gitfacts::{BELT_CONFIG, Git};
use crate::snapshot_bounds::{
    Big, BigHashes, DIFF_CAP, Hashed, NOT_A_FILE, NotCaptured, UNREADABLE, WITHHELD_NAME, open_nofollow, special_files,
};
use crate::walk::WALK_CAP;

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
        if repo.git_dir.is_none() {
            return Err("the repository's git directory was not found".into());
        }
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
            ("GIT_CONFIG_COUNT".into(), (BELT_CONFIG + 2).to_string()),
            (format!("GIT_CONFIG_KEY_{BELT_CONFIG}"), "core.hooksPath".into()),
            (format!("GIT_CONFIG_VALUE_{BELT_CONFIG}"), "/dev/null".into()),
            // The scratch index is never written split, whatever the repository's config says: a split write puts
            // its shared half beside the index.
            (format!("GIT_CONFIG_KEY_{}", BELT_CONFIG + 1), "core.splitIndex".into()),
            (format!("GIT_CONFIG_VALUE_{}", BELT_CONFIG + 1), "false".into()),
        ];
        // The person's index is opened without following a link and must be a regular file, before git reads it:
        // a symlink to a FIFO would block the copy (and git), one to /dev/zero would fill the scratch. A link is
        // treated as no index at all: its target is never opened, and the tree comes from HEAD.
        let person = open_index(&index)?;
        let copied = match person {
            Some(f) if !split_index(git, repo) => copy_index(f, &s.dir.join("index"))
                .map_err(|e| format!("the repository's index could not be copied into the scratch: {e}"))?,
            _ => false,
        };
        if !copied {
            let _ = std::fs::remove_file(s.dir.join("index"));
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

    /// Enters the work tree's changes into the scratch index (H11): each tracked path whose `lstat` differs from its
    /// cached stat (or is racily clean) is hashed again or removed, and each untracked file not ignored, and every
    /// untracked file inside `uploads` (an absolute path in the work tree), is added. Only a captured file is in the
    /// tree (H12): one over [`DIFF_CAP`] is listed in [`Entered::big`] with its size and sha256 (from `hashes`), and a
    /// FIFO, a socket, a device, an unreadable file and an untracked file whose name looks like a secret are listed in
    /// [`Entered::not_captured`]; a tracked one of either kind leaves the tree. `Err` is a null diff's reason, which
    /// includes a work tree of more than [`WALK_CAP`] files, tracked and untracked.
    pub fn enter_changes(&self, git: &Git, repo: &RepoConfig, uploads: Option<&Path>) -> Result<Entered, String> {
        self.enter_changes_with(git, repo, uploads, &mut BigHashes::default())
    }

    /// [`Scratch::enter_changes`] with the big files' hashes kept in `hashes`, so a call's second snapshot reads no
    /// big file whose stat is unchanged since its first.
    pub fn enter_changes_with(
        &self,
        git: &Git,
        repo: &RepoConfig,
        uploads: Option<&Path>,
        hashes: &mut BigHashes,
    ) -> Result<Entered, String> {
        hashes.start();
        let root = &repo.root;
        let listing = |extra: &[(String, String)], cwd: Option<&Path>, args: &[&str]| -> Result<Vec<u8>, String> {
            match git.query_capped(repo, extra, cwd, args, None, LIST_MAX) {
                Some((0, out)) if out.len() < LIST_MAX => Ok(out),
                Some((0, _)) => Err(format!("git {} listed more than {LIST_MAX} bytes", args[0])),
                Some((code, _)) => Err(format!("git {} exited {code}", args[0])),
                None => Err("git could not be run".into()),
            }
        };
        let empty = self.dir.join("empty");
        let entries =
            parse_debug_entries(&listing(&self.env, Some(&empty), &["ls-files", "-s", "-v", "--debug", "-z"])?)?;
        let index_mtime =
            std::fs::symlink_metadata(self.dir.join("index")).map(|m| (m.mtime(), m.mtime_nsec())).unwrap_or((0, 0));
        let null_oid = "0".repeat(entries.first().map_or(40, |e| e.oid.len()));
        // Untracked: what git does not ignore, then everything untracked in the uploads folder. Run against the
        // scratch index in the real work tree (no hook or filter runs for a listing).
        let index_only = [self.env[0].clone()];
        let mut untracked = listing(&index_only, None, &["ls-files", "-z", "--others", "--exclude-standard"])?;
        if let Some(rel) = uploads.and_then(|u| u.strip_prefix(root).ok()).filter(|r| !r.as_os_str().is_empty()) {
            let spec = [b":(literal)".as_slice(), rel.as_os_str().as_bytes()].concat();
            let spec = String::from_utf8(spec).map_err(|_| "the uploads folder's path is not UTF-8")?;
            untracked.extend(listing(&index_only, None, &["ls-files", "-z", "--others", "--", &spec])?);
        }
        let uploads_rel = uploads.and_then(|u| u.strip_prefix(root).ok()).map(|r| r.as_os_str().as_bytes().to_vec());
        // The walk's bound (H12), before any path is looked at: a conflicted path's stages count once.
        let tracked_count =
            entries.iter().enumerate().filter(|(i, e)| *i == 0 || entries[i - 1].path != e.path).count();
        let untracked_count = untracked.split(|b| *b == 0).filter(|p| !p.is_empty()).count();
        if tracked_count + untracked_count > WALK_CAP {
            return Err(format!("the work tree has more than {WALK_CAP} files, so no diff is made"));
        }
        let mut not_captured: Vec<NotCaptured> = vec![];
        let mut bigs: Vec<(Vec<u8>, std::fs::Metadata)> = vec![];
        let mut parents = ParentCheck::default();
        let mut removals: Vec<Vec<u8>> = vec![];
        let mut files: Vec<(Vec<u8>, std::fs::Metadata)> = vec![];
        let mut links: Vec<(Vec<u8>, Vec<u8>)> = vec![];
        let mut seen: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
        // One pass: the paths with any entry past stage 0 (a conflict's stages are consecutive in the listing).
        let conflicts: std::collections::HashSet<&[u8]> =
            entries.iter().filter(|e| e.stage != 0).map(|e| e.path.as_slice()).collect();
        for e in &entries {
            // A conflicted path's stages come as consecutive entries: the first decides for all of them.
            if !seen.insert(e.path.clone()) {
                continue;
            }
            let kept_by_git = e.tag == b'S' || e.tag.is_ascii_lowercase() || e.mode == 0o160000;
            if kept_by_git && e.stage == 0 {
                continue;
            }
            let conflicted = conflicts.contains(e.path.as_slice());
            match now(root, &e.path, &mut parents) {
                Now::File(md) if md.size() > DIFF_CAP => {
                    removals.push(e.path.clone());
                    bigs.push((e.path.clone(), md));
                }
                Now::Special => {
                    removals.push(e.path.clone());
                    not_captured.push(NotCaptured { path: e.path.clone(), reason: NOT_A_FILE });
                }
                Now::File(md) => {
                    let regular = e.mode == 0o100644 || e.mode == 0o100755;
                    let exec_same = (e.mode == 0o100755) == (md.mode() & 0o111 != 0);
                    if conflicted || !regular || !exec_same || !e.matches(&md) || e.racy(index_mtime) {
                        if conflicted {
                            removals.push(e.path.clone());
                        }
                        files.push((e.path.clone(), md));
                    }
                }
                Now::Link(md, target) => {
                    if conflicted || e.mode != 0o120000 || !e.matches(&md) || e.racy(index_mtime) {
                        if conflicted {
                            removals.push(e.path.clone());
                        }
                        links.push((e.path.clone(), target));
                    }
                }
                Now::Gone => removals.push(e.path.clone()),
            }
        }
        let tracked: std::collections::HashSet<Vec<u8>> = seen.clone();
        for p in untracked.split(|b| *b == 0).filter(|p| !p.is_empty() && !p.ends_with(b"/")) {
            if !seen.insert(p.to_vec()) {
                continue;
            }
            // A secret-looking path never enters either tree, so the diff draws nothing for it (FILE_ATTACHMENTS.md
            // H11, amended 2026-11-19); a tracked one is withheld by the report (H13).
            // It is listed as not captured, since the name rule also matches ordinary files (`id_utils.py`).
            if looks_secret(Path::new(std::ffi::OsStr::from_bytes(p))) {
                not_captured.push(NotCaptured { path: p.to_vec(), reason: WITHHELD_NAME });
                continue;
            }
            match now(root, p, &mut parents) {
                Now::File(md) if md.size() > DIFF_CAP => bigs.push((p.to_vec(), md)),
                Now::File(md) => files.push((p.to_vec(), md)),
                Now::Link(_, target) => links.push((p.to_vec(), target)),
                Now::Special => not_captured.push(NotCaptured { path: p.to_vec(), reason: NOT_A_FILE }),
                Now::Gone => {}
            }
        }
        // A file the host cannot open for reading is not captured, and a tracked one leaves the tree; one that turns
        // unreadable after this check fails the snapshot at the hash.
        files.retain(|(p, _)| {
            let ok = open_nofollow(&root.join(std::ffi::OsStr::from_bytes(p))).is_ok();
            if !ok {
                not_captured.push(NotCaptured { path: p.clone(), reason: UNREADABLE });
                if tracked.contains(p.as_slice()) {
                    removals.push(p.clone());
                }
            }
            ok
        });
        let mut big = vec![];
        for (p, md) in bigs {
            match hashes.sha256(&root.join(std::ffi::OsStr::from_bytes(&p)), &md) {
                Hashed::Sha(sha256) => {
                    big.push(Big { path: p, size: md.size(), executable: md.mode() & 0o111 != 0, sha256 })
                }
                Hashed::Unreadable => not_captured.push(NotCaptured { path: p, reason: UNREADABLE }),
            }
        }
        // A FIFO, a socket or a device git lists no file for: found by type in the directories the listings reached
        // (every one checked to be a real directory), never opened; an ignored one is left out, as git leaves out an
        // ignored file, except in the uploads folder.
        let mut dirs: Vec<Vec<u8>> = vec![vec![]];
        dirs.extend(parents.0.iter().filter(|(_, real)| **real).map(|(d, _)| d.clone()));
        let listed: std::collections::HashSet<Vec<u8>> = not_captured.iter().map(|n| n.path.clone()).collect();
        let special: Vec<Vec<u8>> =
            special_files(root, &dirs).into_iter().filter(|p| !listed.contains(p) && !seen.contains(p)).collect();
        let in_uploads = |p: &[u8]| {
            uploads_rel.as_deref().is_some_and(|u| !u.is_empty() && p.starts_with(u) && p.get(u.len()) == Some(&b'/'))
        };
        let ask: Vec<&Vec<u8>> = special.iter().filter(|p| !in_uploads(p)).collect();
        let ignored: std::collections::HashSet<Vec<u8>> = if ask.is_empty() {
            Default::default()
        } else {
            let input: Vec<u8> = ask.iter().flat_map(|p| p.iter().copied().chain([0])).collect();
            let args = ["check-ignore", "-z", "--stdin"];
            match git.query_capped(repo, &index_only, None, &args, Some(&mut input.as_slice()), LIST_MAX) {
                Some((0 | 1, out)) => out.split(|b| *b == 0).filter(|p| !p.is_empty()).map(<[u8]>::to_vec).collect(),
                Some((code, _)) => return Err(format!("git check-ignore exited {code}")),
                None => return Err("git could not be run".into()),
            }
        };
        for p in special.into_iter().filter(|p| !ignored.contains(p)) {
            not_captured.push(NotCaptured { path: p, reason: NOT_A_FILE });
        }
        not_captured.sort_by(|a, b| a.path.cmp(&b.path));
        big.sort_by(|a, b| a.path.cmp(&b.path));
        removals.sort();
        removals.dedup();
        let mut info: Vec<u8> = vec![];
        for p in &removals {
            info.extend_from_slice(format!("0 {null_oid} 0\t").as_bytes());
            info.extend_from_slice(p);
            info.push(0);
        }
        let oids = self.hash_files(git, repo, root, &files)?;
        for ((p, md), oid) in files.iter().zip(&oids) {
            let mode = if md.mode() & 0o111 != 0 { "100755" } else { "100644" };
            info.extend_from_slice(format!("{mode} {oid} 0\t").as_bytes());
            info.extend_from_slice(p);
            info.push(0);
        }
        for (p, target) in &links {
            let oid = self.hash_stdin(git, repo, &mut target.as_slice())?;
            info.extend_from_slice(format!("120000 {oid} 0\t").as_bytes());
            info.extend_from_slice(p);
            info.push(0);
        }
        if !info.is_empty() {
            match self.git_stdin(git, repo, &["update-index", "-z", "--index-info"], &mut info.as_slice()) {
                Some((0, _)) => {}
                Some((code, _)) => return Err(format!("git update-index --index-info exited {code}")),
                None => return Err("git could not be run".into()),
            }
        }
        Ok(Entered { hashed: files.len() + links.len(), removed: removals.len(), big, not_captured })
    }

    /// Hashes `files` (work-tree paths with the `lstat` taken before) into the private objects, in order. A file whose
    /// `lstat` afterwards differs from the one before is hashed again from a descriptor opened without following links.
    fn hash_files(
        &self,
        git: &Git,
        repo: &RepoConfig,
        root: &Path,
        files: &[(Vec<u8>, std::fs::Metadata)],
    ) -> Result<Vec<String>, String> {
        let abs = |p: &[u8]| root.join(std::ffi::OsStr::from_bytes(p));
        // `--stdin-paths` reads a line per path and unquotes one that starts with `"`: those, and a name with a
        // newline, go through a descriptor instead.
        let batch: Vec<usize> = (0..files.len())
            .filter(|&i| {
                let a = abs(&files[i].0);
                let b = a.as_os_str().as_bytes();
                !b.contains(&b'\n') && !b.starts_with(b"\"")
            })
            .collect();
        let mut oids: Vec<Option<String>> = vec![None; files.len()];
        if !batch.is_empty() {
            let mut input: Vec<u8> = vec![];
            for &i in &batch {
                input.extend_from_slice(abs(&files[i].0).as_os_str().as_bytes());
                input.push(b'\n');
            }
            let args = ["hash-object", "-w", "--no-filters", "--stdin-paths"];
            let out = match self.git_stdin(git, repo, &args, &mut input.as_slice()) {
                Some((0, out)) => out,
                Some((code, _)) => return Err(format!("git hash-object exited {code}")),
                None => return Err("git could not be run".into()),
            };
            let got: Vec<&[u8]> = out.split(|b| *b == b'\n').filter(|l| !l.is_empty()).collect();
            if got.len() != batch.len() {
                return Err("git hash-object answered a different number of ids".into());
            }
            for (&i, oid) in batch.iter().zip(got) {
                oids[i] = Some(String::from_utf8_lossy(oid).into_owned());
            }
        }
        for (i, (p, before)) in files.iter().enumerate() {
            let same = std::fs::symlink_metadata(abs(p)).is_ok_and(|after| same_file(before, &after));
            if oids[i].is_none() || !same {
                oids[i] = Some(self.hash_fd(git, repo, &abs(p))?);
            }
        }
        Ok(oids.into_iter().map(|o| o.unwrap_or_default()).collect())
    }

    /// Hashes one file read from a descriptor opened with `O_NOFOLLOW | O_NONBLOCK`, refusing anything but a regular
    /// file.
    fn hash_fd(&self, git: &Git, repo: &RepoConfig, path: &Path) -> Result<String, String> {
        use std::os::unix::fs::OpenOptionsExt;
        let flags = (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32;
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(flags)
            .open(path)
            .map_err(|e| format!("a changed file could not be opened: {e}"))?;
        if !f.metadata().is_ok_and(|m| m.is_file()) {
            return Err("a changed file stopped being a regular file while it was hashed".into());
        }
        self.hash_stdin(git, repo, &mut f)
    }

    /// Hashes the bytes of `input` as a blob into the private objects.
    fn hash_stdin(
        &self,
        git: &Git,
        repo: &RepoConfig,
        input: &mut (dyn std::io::Read + Send),
    ) -> Result<String, String> {
        match self.git_stdin(git, repo, &["hash-object", "-w", "--no-filters", "--stdin"], input) {
            Some((0, out)) => Ok(String::from_utf8_lossy(&out).trim().to_string()),
            Some((code, _)) => Err(format!("git hash-object exited {code}")),
            None => Err("git could not be run".into()),
        }
    }

    fn git_stdin(
        &self,
        git: &Git,
        repo: &RepoConfig,
        args: &[&str],
        input: &mut (dyn std::io::Read + Send),
    ) -> Option<(i32, Vec<u8>)> {
        git.query_env(repo, &self.env, Some(&self.dir.join("empty")), args, Some(input))
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

/// What [`Scratch::enter_changes`] did: how many paths it hashed and how many entries it removed, and what it left out
/// of the tree (H12).
#[derive(Debug, PartialEq)]
pub struct Entered {
    pub hashed: usize,
    pub removed: usize,
    /// The regular files over [`DIFF_CAP`], by size and sha256, in path order.
    pub big: Vec<Big>,
    /// The paths not captured, with the reason, in path order.
    pub not_captured: Vec<NotCaptured>,
}

/// The most bytes of a listing (`ls-files`) read; a longer one fails the snapshot rather than leave paths out.
const LIST_MAX: usize = 64 << 20;

/// One entry of `git ls-files -s -v --debug -z`, with the stat git cached for it (each field as git keeps it, 32 bits).
#[derive(Debug)]
struct DebugEntry {
    tag: u8,
    mode: u32,
    oid: String,
    stage: u8,
    path: Vec<u8>,
    ctime: (u64, u64),
    mtime: (u64, u64),
    ino: u64,
    uid: u64,
    gid: u64,
    size: u64,
}

impl DebugEntry {
    /// Whether `md` (an `lstat`) is the stat git cached: times, inode, owner and size, each cut to 32 bits as git cuts it.
    fn matches(&self, md: &std::fs::Metadata) -> bool {
        let w = |v: u64| v & 0xffff_ffff;
        self.mtime == (w(md.mtime() as u64), w(md.mtime_nsec() as u64))
            && self.ctime == (w(md.ctime() as u64), w(md.ctime_nsec() as u64))
            && self.ino == w(md.ino())
            && self.uid == w(md.uid() as u64)
            && self.gid == w(md.gid() as u64)
            && self.size == w(md.size())
    }

    /// Whether the entry is racily clean: modified no earlier than the index was written, so an equal stat says nothing.
    fn racy(&self, index_mtime: (i64, i64)) -> bool {
        let (s, n) = (index_mtime.0 as u64 & 0xffff_ffff, index_mtime.1 as u64);
        self.mtime.0 > s || (self.mtime.0 == s && self.mtime.1 >= n)
    }
}

/// Reads `<tag> <mode> <oid> <stage>\t<path>\0` records, each followed by git's five `--debug` lines (`ctime: s:n`,
/// `mtime: s:n`, `dev: d\tino: i`, `uid: u\tgid: g`, `size: z\tflags: f`).
fn parse_debug_entries(out: &[u8]) -> Result<Vec<DebugEntry>, String> {
    let bad = || "git ls-files --debug printed a record this host cannot read".to_string();
    let mut v = vec![];
    let mut rest = out;
    while !rest.is_empty() {
        let nul = rest.iter().position(|b| *b == 0).ok_or_else(bad)?;
        let (head, tail) = rest.split_at(nul);
        rest = &tail[1..];
        let tab = head.iter().position(|b| *b == b'\t').ok_or_else(bad)?;
        let meta = std::str::from_utf8(&head[..tab]).map_err(|_| bad())?;
        let mut m = meta.split(' ');
        let tag = *m.next().and_then(|t| t.as_bytes().first()).ok_or_else(bad)?;
        let mode = u32::from_str_radix(m.next().ok_or_else(bad)?, 8).map_err(|_| bad())?;
        let oid = m.next().ok_or_else(bad)?.to_string();
        let stage: u8 = m.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
        let mut fields: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
        for _ in 0..5 {
            let nl = rest.iter().position(|b| *b == b'\n').ok_or_else(bad)?;
            let line = std::str::from_utf8(&rest[..nl]).map_err(|_| bad())?;
            rest = &rest[nl + 1..];
            for kv in line.trim().split('\t') {
                let (k, val) = kv.split_once(": ").ok_or_else(bad)?;
                fields.insert(k, val);
            }
        }
        let num = |k: &str| -> Result<u64, String> { fields.get(k).ok_or_else(bad)?.parse().map_err(|_| bad()) };
        let pair = |k: &str| -> Result<(u64, u64), String> {
            let (a, b) = fields.get(k).ok_or_else(bad)?.split_once(':').ok_or_else(bad)?;
            Ok((a.parse().map_err(|_| bad())?, b.parse().map_err(|_| bad())?))
        };
        v.push(DebugEntry {
            tag,
            mode,
            oid,
            stage,
            path: head[tab + 1..].to_vec(),
            ctime: pair("ctime")?,
            mtime: pair("mtime")?,
            ino: num("ino")?,
            uid: num("uid")?,
            gid: num("gid")?,
            size: num("size")?,
        });
    }
    Ok(v)
}

/// What a work-tree path is now, by `lstat`, with every parent a real directory.
enum Now {
    File(std::fs::Metadata),
    Link(std::fs::Metadata, Vec<u8>),
    /// A FIFO, a socket or a device, which is never opened.
    Special,
    /// Missing, behind a symlinked or missing parent, or a directory.
    Gone,
}

fn now(root: &Path, rel: &[u8], parents: &mut ParentCheck) -> Now {
    if !parents.real(root, rel) {
        return Now::Gone;
    }
    let p = root.join(std::ffi::OsStr::from_bytes(rel));
    match std::fs::symlink_metadata(&p) {
        Ok(md) if md.is_file() => Now::File(md),
        Ok(md) if md.file_type().is_symlink() => match std::fs::read_link(&p) {
            Ok(t) => Now::Link(md, t.into_os_string().into_vec()),
            Err(_) => Now::Gone,
        },
        Ok(md) if !md.is_dir() => Now::Special,
        _ => Now::Gone,
    }
}

/// Whether every parent directory of a work-tree path is a real directory (not a link), each answered once.
#[derive(Default)]
struct ParentCheck(std::collections::HashMap<Vec<u8>, bool>);

impl ParentCheck {
    fn real(&mut self, root: &Path, rel: &[u8]) -> bool {
        let mut end = 0;
        while let Some(i) = rel[end..].iter().position(|b| *b == b'/') {
            end += i;
            let dir = &rel[..end];
            let ok = *self.0.entry(dir.to_vec()).or_insert_with(|| {
                std::fs::symlink_metadata(root.join(std::ffi::OsStr::from_bytes(dir))).is_ok_and(|m| m.is_dir())
            });
            if !ok {
                return false;
            }
            end += 1;
        }
        true
    }
}

/// Whether two `lstat`s are of the same unchanged regular file.
fn same_file(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    b.is_file()
        && (a.dev(), a.ino(), a.size(), a.mtime(), a.mtime_nsec(), a.ctime(), a.ctime_nsec())
            == (b.dev(), b.ino(), b.size(), b.mtime(), b.mtime_nsec(), b.ctime(), b.ctime_nsec())
}

/// The most bytes of the person's index copied; a larger one is not copied and the tree comes from HEAD.
const INDEX_MAX: u64 = 256 << 20;

/// Whether the person's index is split, by git's own answer (`rev-parse --shared-index-path` prints the shared half's
/// path, nothing when it is not split): a `sharedindex.*` left in the git directory by `--no-split-index` does not
/// make it so. When git cannot answer, it is treated as split, so nothing is copied that could name a shared half.
fn split_index(git: &Git, repo: &RepoConfig) -> bool {
    match git.query_env(repo, &[], None, &["rev-parse", "--shared-index-path"], None) {
        Some((0, out)) => !out.iter().all(u8::is_ascii_whitespace),
        _ => true,
    }
}

/// The person's index, opened for reading without following a link and without blocking on a FIFO: `None` when there
/// is none (a `clone --no-checkout`) or it is a link, which is never followed; `Err` when it is anything else but a
/// regular file (a FIFO, a device, a directory) or cannot be opened at all (a socket, an unreadable file).
fn open_index(path: &Path) -> Result<Option<std::fs::File>, String> {
    use std::os::unix::fs::OpenOptionsExt;
    let flags = (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32;
    let f = match std::fs::OpenOptions::new().read(true).custom_flags(flags).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        // `O_NOFOLLOW` on a link fails with ELOOP, on macOS and Linux alike.
        Err(e) if e.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error()) => return Ok(None),
        Err(e) => return Err(format!("the repository's index could not be opened: {e}")),
    };
    match f.metadata() {
        Ok(m) if m.is_file() => Ok(Some(f)),
        Ok(_) => Err("the repository's index is not a regular file".into()),
        Err(e) => Err(format!("the repository's index could not be read: {e}")),
    }
}

/// Copies the person's index into the scratch, at most [`INDEX_MAX`] bytes, keeping its mtime so the entries git
/// treats as racily clean stay so. `false` when it is larger, which leaves the tree to come from HEAD.
fn copy_index(mut from: std::fs::File, to: &Path) -> std::io::Result<bool> {
    let md = from.metadata()?;
    if md.len() > INDEX_MAX {
        return Ok(false);
    }
    let mut out = std::fs::File::create_new(to)?;
    let n = std::io::copy(&mut std::io::Read::take(&mut from, INDEX_MAX + 1), &mut out)?;
    if n > INDEX_MAX {
        return Ok(false);
    }
    out.set_modified(md.modified()?)?;
    Ok(true)
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
            // No detached auto-maintenance: it would write `objects/maintenance.lock` into .git while a row compares it.
            .args(["-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"])
            .args(["-c", "maintenance.auto=false", "-c", "gc.auto=0"])
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
    fn an_index_that_is_a_link_takes_heads_tree_without_reading_the_target() {
        if !have_git() {
            return;
        }
        // A link to a real index holding a staged change, and a dangling one: each is treated as no index, the base
        // is HEAD's tree (so the staged change in the target was not read), and nothing under .git changes.
        for target in ["real-index", "nowhere"] {
            let (t, root, marks) = repo();
            std::fs::write(root.join("a.txt"), "staged\n").unwrap();
            run(&root, &["add", "a.txt"]);
            let index = root.join(".git/index");
            if target == "real-index" {
                std::fs::rename(&index, root.join(".git/real-index")).unwrap();
            } else {
                std::fs::remove_file(&index).unwrap();
            }
            std::os::unix::fs::symlink(root.join(".git").join(target), &index).unwrap();
            clear(&marks);
            let before = dot_git(&root);
            let (g, r) = (git_on_path(), inspect(&root));
            let s = Scratch::new(&g, &r, &scratch_base(&t)).unwrap();
            assert!(s.from_head, "{target}");
            assert_eq!(s.tree(&g, &r).unwrap(), run(&root, &["rev-parse", "HEAD^{tree}"]), "{target}");
            drop(s);
            assert_eq!(dot_git(&root), before, "{target}");
            assert_eq!(std::fs::read_dir(&marks).unwrap().count(), 0, "{target}");
            assert!(std::fs::symlink_metadata(&index).unwrap().file_type().is_symlink(), "{target}: the link stays");
        }
    }

    #[test]
    fn an_index_that_is_a_fifo_or_a_directory_is_refused() {
        if !have_git() {
            return;
        }
        for shape in ["fifo", "dir"] {
            let (t, root, _marks) = repo();
            let index = root.join(".git/index");
            std::fs::remove_file(&index).unwrap();
            if shape == "fifo" {
                assert!(Command::new("mkfifo").arg(&index).status().unwrap().success());
            } else {
                std::fs::create_dir(&index).unwrap();
            }
            let (g, r) = (git_on_path(), inspect(&root));
            let base = scratch_base(&t);
            let e = Scratch::new(&g, &r, &base).err().unwrap();
            assert!(e.contains("not a regular file") || e.contains("could not be opened"), "{shape}: {e}");
            assert_eq!(std::fs::read_dir(&base).unwrap().count(), 0, "{shape}: no scratch is left");
        }
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
    // --- entering the work tree's changes (H11) ---

    /// The scratch tree's entries as `mode oid path` lines, read through the scratch's own objects.
    fn scratch_tree(s: &Scratch, g: &Git, r: &RepoConfig) -> Vec<String> {
        let tree = s.tree(g, r).unwrap();
        let (code, out) = s.git(g, r, &["ls-tree", "-r", "-z", &tree]).unwrap();
        assert_eq!(code, 0);
        out.split(|b| *b == 0)
            .filter(|l| !l.is_empty())
            .map(|l| {
                let l = String::from_utf8_lossy(l);
                let (meta, path) = l.split_once('\t').unwrap();
                let mut m = meta.split(' ');
                let (mode, _, oid) = (m.next().unwrap(), m.next(), m.next().unwrap());
                format!("{mode} {oid} {path}")
            })
            .collect()
    }

    /// The blob id git gives `bytes`, written nowhere.
    fn blob_of(root: &Path, bytes: &[u8]) -> String {
        let mut c = Command::new("git")
            .args(["hash-object", "--no-filters", "--stdin"])
            .current_dir(root)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        std::io::Write::write_all(&mut c.stdin.take().unwrap(), bytes).unwrap();
        String::from_utf8(c.wait_with_output().unwrap().stdout).unwrap().trim().to_string()
    }

    /// Records the work tree's stat in the person's index with every mtime a minute back, so no entry is racily clean.
    fn settle(root: &Path, marks: &Path) {
        let past = std::time::SystemTime::now() - std::time::Duration::from_secs(60);
        for p in ["a.txt", "sub/b.txt"] {
            std::fs::File::options().write(true).open(root.join(p)).unwrap().set_modified(past).unwrap();
        }
        // The test's own refresh, through a pass-through filter: the configured one prints nothing.
        run(root, &["-c", "filter.f.clean=cat", "-c", "core.fsmonitor=false", "update-index", "--refresh"]);
        clear(marks);
    }

    #[test]
    fn the_changes_enter_the_tree_and_nothing_enters_the_repository() {
        if !have_git() {
            return;
        }
        let (t, root, marks) = repo();
        std::fs::write(root.join(".gitignore"), ".env\nup/\n").unwrap();
        settle(&root, &marks);
        std::fs::write(root.join("a.txt"), "one, edited\n").unwrap();
        std::fs::remove_file(root.join("sub/b.txt")).unwrap();
        std::fs::write(root.join("new.txt"), "made by the call\n").unwrap();
        std::fs::write(root.join(".env"), "TOKEN=hunter2\n").unwrap();
        std::fs::create_dir(root.join("up")).unwrap();
        std::fs::write(root.join("up/report.csv"), "x,y\n").unwrap();
        clear(&marks);
        let before = dot_git(&root);
        let (g, r) = (git_on_path(), inspect(&root));
        let s = Scratch::new(&g, &r, &scratch_base(&t)).unwrap();
        let entered = s.enter_changes(&g, &r, Some(&root.join("up"))).unwrap();
        let tree = scratch_tree(&s, &g, &r);
        let has = |path: &str, body: &[u8]| tree.contains(&format!("100644 {} {path}", blob_of(&root, body)));
        assert!(has("a.txt", b"one, edited\n"), "{tree:?}");
        assert!(has("new.txt", b"made by the call\n"), "an untracked file the call made is in the tree: {tree:?}");
        assert!(has("up/report.csv", b"x,y\n"), "an ignored file in the uploads folder is in the tree: {tree:?}");
        assert!(!tree.iter().any(|l| l.ends_with(" sub/b.txt")), "a deleted file leaves the tree: {tree:?}");
        assert!(!tree.iter().any(|l| l.ends_with(" .env")), "an ignored .env never enters a tree: {tree:?}");
        assert_eq!(entered.removed, 1);
        let env_blob = blob_of(&root, b"TOKEN=hunter2\n");
        let (code, _) = s.git(&g, &r, &["cat-file", "-e", &env_blob]).unwrap();
        assert_ne!(code, 0, "the ignored .env's body is not in the private objects either");
        drop(s);
        assert_eq!(dot_git(&root), before, "index, HEAD, refs, stash and objects are byte-identical");
        assert_eq!(std::fs::read_dir(&marks).unwrap().count(), 0, "no filter, fsmonitor or hook ran");
    }

    #[test]
    fn an_unchanged_settled_file_keeps_the_index_blob_and_is_not_hashed() {
        if !have_git() {
            return;
        }
        let (t, root, marks) = repo();
        std::fs::write(root.join(".gitignore"), ".gitattributes\n.gitignore\n").unwrap();
        settle(&root, &marks);
        let (g, r) = (git_on_path(), inspect(&root));
        let s = Scratch::new(&g, &r, &scratch_base(&t)).unwrap();
        assert_eq!(
            s.enter_changes(&g, &r, None).unwrap(),
            Entered { hashed: 0, removed: 0, big: vec![], not_captured: vec![] }
        );
        assert_eq!(s.tree(&g, &r).unwrap(), run(&root, &["rev-parse", "HEAD^{tree}"]));
    }

    #[test]
    fn an_entry_modified_no_earlier_than_the_index_is_racily_clean() {
        // A file rewritten within the timestamp's granularity of the index write keeps a cached stat that matches; on a
        // filesystem with nanosecond times the write's ctime gives it away, so the predicate is what this row reads.
        let e = |mtime| DebugEntry {
            tag: b'H',
            mode: 0o100644,
            oid: String::new(),
            stage: 0,
            path: vec![],
            ctime: mtime,
            mtime,
            ino: 0,
            uid: 0,
            gid: 0,
            size: 0,
        };
        assert!(e((100, 5)).racy((100, 5)), "the same instant");
        assert!(e((100, 6)).racy((100, 5)), "later in the same second");
        assert!(e((101, 0)).racy((100, 5)), "a later second");
        assert!(!e((100, 4)).racy((100, 5)), "earlier in the same second");
        assert!(!e((99, 9)).racy((100, 5)), "an earlier second");
        assert!(e((0, 0)).racy((0, 0)), "an index with no mtime (read from HEAD) makes every entry racy");
    }

    #[test]
    fn a_symlinked_parent_hashes_nothing_outside_and_a_link_is_entered_as_a_link() {
        if !have_git() {
            return;
        }
        let (t, root, marks) = repo();
        settle(&root, &marks);
        let outside = t.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("b.txt"), "outside secret\n").unwrap();
        std::fs::remove_dir_all(root.join("sub")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("sub")).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", root.join("pw")).unwrap();
        let (g, r) = (git_on_path(), inspect(&root));
        let s = Scratch::new(&g, &r, &scratch_base(&t)).unwrap();
        s.enter_changes(&g, &r, None).unwrap();
        let tree = scratch_tree(&s, &g, &r);
        assert!(!tree.iter().any(|l| l.ends_with(" sub/b.txt")), "behind a linked parent is deleted: {tree:?}");
        let link = |target: &[u8], path: &str| format!("120000 {} {path}", blob_of(&root, target));
        assert!(tree.contains(&link(outside.as_os_str().as_bytes(), "sub")), "{tree:?}");
        assert!(tree.contains(&link(b"/etc/passwd", "pw")), "a link is its target's text: {tree:?}");
        for body in [b"outside secret\n".as_slice(), &std::fs::read("/etc/passwd").unwrap()] {
            let (code, _) = s.git(&g, &r, &["cat-file", "-e", &blob_of(&root, body)]).unwrap();
            assert_ne!(code, 0, "no file behind a link was hashed");
        }
    }

    #[test]
    fn a_name_with_a_newline_or_a_leading_quote_is_hashed_from_a_descriptor() {
        if !have_git() {
            return;
        }
        let (t, root, marks) = repo();
        settle(&root, &marks);
        std::fs::write(root.join("two\nlines"), "n\n").unwrap();
        std::fs::write(root.join("\"quoted"), "q\n").unwrap();
        let (g, r) = (git_on_path(), inspect(&root));
        let s = Scratch::new(&g, &r, &scratch_base(&t)).unwrap();
        s.enter_changes(&g, &r, None).unwrap();
        let tree = scratch_tree(&s, &g, &r);
        assert!(tree.contains(&format!("100644 {} two\nlines", blob_of(&root, b"n\n"))), "{tree:?}");
        assert!(tree.contains(&format!("100644 {} \"quoted", blob_of(&root, b"q\n"))), "{tree:?}");
    }

    #[test]
    fn a_conflicted_path_enters_once_at_stage_zero() {
        if !have_git() {
            return;
        }
        let (t, root, marks) = repo();
        run(&root, &["config", "--unset", "filter.f.clean"]);
        std::fs::remove_file(root.join(".gitattributes")).unwrap();
        run(&root, &["checkout", "-q", "-b", "other"]);
        std::fs::write(root.join("a.txt"), "theirs\n").unwrap();
        run(&root, &["commit", "-q", "-am", "theirs"]);
        run(&root, &["checkout", "-q", "-"]);
        std::fs::write(root.join("a.txt"), "ours\n").unwrap();
        run(&root, &["commit", "-q", "-am", "ours"]);
        let _ = Command::new("git").args(["merge", "-q", "other"]).current_dir(&root).output();
        std::fs::write(root.join("a.txt"), "resolved\n").unwrap();
        clear(&marks);
        let (g, r) = (git_on_path(), inspect(&root));
        let s = Scratch::new(&g, &r, &scratch_base(&t)).unwrap();
        s.enter_changes(&g, &r, None).unwrap();
        let tree = scratch_tree(&s, &g, &r);
        let a: Vec<_> = tree.iter().filter(|l| l.ends_with(" a.txt")).collect();
        assert_eq!(a, [&format!("100644 {} a.txt", blob_of(&root, b"resolved\n"))], "{tree:?}");
    }
    #[test]
    fn an_untracked_secret_looking_file_enters_neither_tree_and_an_ordinary_one_beside_it_does() {
        if !have_git() {
            return;
        }
        let (t, root, marks) = repo();
        std::fs::write(root.join(".gitignore"), "up/\n").unwrap();
        settle(&root, &marks);
        std::fs::write(root.join(".env.local"), "TOKEN=hunter2\n").unwrap();
        std::fs::write(root.join("notes.txt"), "plain\n").unwrap();
        std::fs::create_dir_all(root.join("up/.ssh")).unwrap();
        std::fs::write(root.join("up/id_ed25519"), "PRIVATE KEY\n").unwrap();
        std::fs::write(root.join("up/.ssh/config"), "Host x\n").unwrap();
        std::fs::write(root.join("up/report.csv"), "x,y\n").unwrap();
        let (g, r) = (git_on_path(), inspect(&root));
        let s = Scratch::new(&g, &r, &scratch_base(&t)).unwrap();
        s.enter_changes(&g, &r, Some(&root.join("up"))).unwrap();
        let tree = scratch_tree(&s, &g, &r);
        for secret in [".env.local", "up/id_ed25519", "up/.ssh/config"] {
            assert!(!tree.iter().any(|l| l.ends_with(&format!(" {secret}"))), "{secret} is in no tree: {tree:?}");
        }
        for body in [b"TOKEN=hunter2\n".as_slice(), b"PRIVATE KEY\n", b"Host x\n"] {
            let (code, _) = s.git(&g, &r, &["cat-file", "-e", &blob_of(&root, body)]).unwrap();
            assert_ne!(code, 0, "nor is its body in the private objects");
        }
        let has = |path: &str, body: &[u8]| tree.contains(&format!("100644 {} {path}", blob_of(&root, body)));
        assert!(has("notes.txt", b"plain\n"), "an ordinary untracked file still enters: {tree:?}");
        assert!(has("up/report.csv", b"x,y\n"), "and one in the uploads folder: {tree:?}");
    }
    #[test]
    fn a_changed_set_larger_than_a_pipe_holds_is_hashed_and_entered() {
        if !have_git() {
            return;
        }
        // About 4 000 absolute paths on stdin and as many ids on stdout: well past both pipes' buffers, which deadlocked
        // when stdin was written whole before stdout was read (janitor-2, host#51: 2 400 paths hung).
        let (t, root, marks) = repo();
        std::fs::write(root.join(".gitignore"), ".gitattributes\n.gitignore\n").unwrap();
        settle(&root, &marks);
        let many = root.join("many-files-with-a-long-directory-name-so-each-absolute-path-is-long");
        std::fs::create_dir(&many).unwrap();
        for i in 0..4000 {
            std::fs::write(many.join(format!("file-{i:05}.txt")), format!("{i}\n")).unwrap();
        }
        let (g, r) = (git_on_path(), inspect(&root));
        let s = Scratch::new(&g, &r, &scratch_base(&t)).unwrap();
        let entered = s.enter_changes(&g, &r, None).unwrap();
        assert_eq!(entered.hashed, 4000);
        let tree = scratch_tree(&s, &g, &r);
        assert_eq!(tree.iter().filter(|l| l.contains("/file-")).count(), 4000);
        assert!(tree.contains(&format!(
            "100644 {} many-files-with-a-long-directory-name-so-each-absolute-path-is-long/file-03999.txt",
            blob_of(&root, b"3999\n")
        )));
    }

    // --- the bounds (H12): only a captured file is in the tree ---

    fn paths_of(n: &[NotCaptured], reason: &str) -> Vec<String> {
        n.iter().filter(|n| n.reason == reason).map(|n| String::from_utf8_lossy(&n.path).into_owned()).collect()
    }

    #[test]
    fn a_fifo_a_socket_and_an_unreadable_file_are_listed_as_not_captured_and_never_opened() {
        if !have_git() || rustix::process::geteuid().is_root() {
            return;
        }
        let (t, root, marks) = repo();
        settle(&root, &marks);
        let fifo = |p: &Path| assert!(Command::new("mkfifo").arg(p).status().unwrap().success());
        // An untracked FIFO, one beside a tracked file, a socket, and a tracked file swapped for a FIFO: opening any
        // FIFO for reading would block the snapshot.
        fifo(&root.join("pipe"));
        fifo(&root.join("sub/inner-pipe"));
        std::fs::remove_file(root.join("a.txt")).unwrap();
        fifo(&root.join("a.txt"));
        let _sock = std::os::unix::net::UnixListener::bind(root.join("sock")).unwrap();
        std::fs::write(root.join("locked.txt"), "secret-ish\n").unwrap();
        std::fs::set_permissions(root.join("locked.txt"), std::os::unix::fs::PermissionsExt::from_mode(0o000)).unwrap();
        std::fs::write(root.join("plain.txt"), "plain\n").unwrap();
        let (g, r) = (git_on_path(), inspect(&root));
        let s = Scratch::new(&g, &r, &scratch_base(&t)).unwrap();
        let start = std::time::Instant::now();
        let e = s.enter_changes(&g, &r, None).unwrap();
        assert!(start.elapsed() < std::time::Duration::from_secs(20), "within budget: {:?}", start.elapsed());
        assert_eq!(paths_of(&e.not_captured, NOT_A_FILE), ["a.txt", "pipe", "sock", "sub/inner-pipe"]);
        assert_eq!(paths_of(&e.not_captured, UNREADABLE), ["locked.txt"]);
        let tree = scratch_tree(&s, &g, &r);
        for gone in ["a.txt", "pipe", "sock", "sub/inner-pipe", "locked.txt"] {
            assert!(!tree.iter().any(|l| l.ends_with(&format!(" {gone}"))), "{gone} is in no tree: {tree:?}");
        }
        assert!(tree.contains(&format!("100644 {} plain.txt", blob_of(&root, b"plain\n"))), "{tree:?}");
        std::fs::set_permissions(root.join("locked.txt"), std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    }

    #[test]
    fn an_ignored_fifo_is_not_listed_and_one_in_the_uploads_folder_is() {
        if !have_git() {
            return;
        }
        let (t, root, marks) = repo();
        std::fs::write(root.join(".gitignore"), "*.pipe\nup/\n").unwrap();
        settle(&root, &marks);
        let fifo = |p: &Path| assert!(Command::new("mkfifo").arg(p).status().unwrap().success());
        fifo(&root.join("sub/x.pipe"));
        std::fs::create_dir(root.join("up")).unwrap();
        std::fs::write(root.join("up/report.csv"), "x,y\n").unwrap();
        fifo(&root.join("up/y.pipe"));
        let (g, r) = (git_on_path(), inspect(&root));
        let s = Scratch::new(&g, &r, &scratch_base(&t)).unwrap();
        let e = s.enter_changes(&g, &r, Some(&root.join("up"))).unwrap();
        assert_eq!(paths_of(&e.not_captured, NOT_A_FILE), ["up/y.pipe"]);
    }

    #[test]
    fn a_file_over_the_cap_is_listed_by_size_and_sha256_and_its_body_enters_no_tree() {
        if !have_git() {
            return;
        }
        use sha2::Digest;
        let (t, root, marks) = repo();
        let body = vec![b'z'; (DIFF_CAP + 1) as usize];
        settle(&root, &marks);
        // A tracked file the call grows past the cap, and an untracked one over it.
        std::fs::write(root.join("sub/b.txt"), &body).unwrap();
        std::fs::write(root.join("big.bin"), &body).unwrap();
        let (g, r) = (git_on_path(), inspect(&root));
        let s = Scratch::new(&g, &r, &scratch_base(&t)).unwrap();
        let mut hashes = BigHashes::default();
        let e = s.enter_changes_with(&g, &r, None, &mut hashes).unwrap();
        let sha = hex::encode(sha2::Sha256::digest(&body));
        let listed: Vec<(String, u64, Option<String>)> =
            e.big.iter().map(|b| (String::from_utf8_lossy(&b.path).into_owned(), b.size, b.sha256.clone())).collect();
        assert_eq!(
            listed,
            [("big.bin".into(), DIFF_CAP + 1, Some(sha.clone())), ("sub/b.txt".into(), DIFF_CAP + 1, Some(sha))]
        );
        let tree = scratch_tree(&s, &g, &r);
        assert!(!tree.iter().any(|l| l.ends_with(" big.bin") || l.ends_with(" sub/b.txt")), "{tree:?}");
        let (code, _) = s.git(&g, &r, &["cat-file", "-e", &blob_of(&root, &body)]).unwrap();
        assert_ne!(code, 0, "the big body is not in the private objects");
        assert!(e.not_captured.is_empty(), "{:?}", e.not_captured);
    }

    #[test]
    fn a_file_under_the_cap_whose_only_change_is_its_mtime_keeps_the_same_tree() {
        if !have_git() {
            return;
        }
        let (t, root, marks) = repo();
        settle(&root, &marks);
        let (g, r) = (git_on_path(), inspect(&root));
        let tree_now = || {
            let s = Scratch::new(&g, &r, &scratch_base(&t)).unwrap();
            s.enter_changes(&g, &r, None).unwrap();
            s.tree(&g, &r).unwrap()
        };
        let before = tree_now();
        std::fs::File::options()
            .write(true)
            .open(root.join("a.txt"))
            .unwrap()
            .set_modified(std::time::SystemTime::now())
            .unwrap();
        assert_eq!(tree_now(), before, "a touched file hashes to the blob it had");
    }

    #[test]
    fn an_untracked_name_that_looks_like_a_secret_is_listed_with_the_name_reason() {
        if !have_git() {
            return;
        }
        let (t, root, marks) = repo();
        settle(&root, &marks);
        std::fs::write(root.join("id_utils.py"), "def f(): pass\n").unwrap();
        std::fs::write(root.join(".env.local"), "TOKEN=hunter2\n").unwrap();
        let (g, r) = (git_on_path(), inspect(&root));
        let s = Scratch::new(&g, &r, &scratch_base(&t)).unwrap();
        let e = s.enter_changes(&g, &r, None).unwrap();
        assert_eq!(paths_of(&e.not_captured, WITHHELD_NAME), [".env.local", "id_utils.py"]);
        assert_eq!(WITHHELD_NAME, "withheld: the name looks like a secret", "the spec's wording");
    }

    #[test]
    fn a_work_tree_past_the_walk_cap_gives_a_null_diff_with_the_reason() {
        if !have_git() {
            return;
        }
        let (t, root, marks) = repo();
        settle(&root, &marks);
        let many = root.join("many");
        std::fs::create_dir(&many).unwrap();
        // Two tracked files and .gitattributes, so WALK_CAP untracked files take the count past it.
        for i in 0..WALK_CAP {
            std::fs::write(many.join(format!("{i}")), "").unwrap();
        }
        let (g, r) = (git_on_path(), inspect(&root));
        let s = Scratch::new(&g, &r, &scratch_base(&t)).unwrap();
        let err = s.enter_changes(&g, &r, None).unwrap_err();
        assert!(err.contains(&format!("more than {WALK_CAP} files")), "{err}");
    }
}
