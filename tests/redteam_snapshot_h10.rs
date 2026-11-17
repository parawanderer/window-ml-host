//! redteam_snapshot_h10.rs — taking a snapshot, from the HOST's side (window-ml FILE_ATTACHMENTS.md H10, as built at
//! a6e4971f). The property: taking a snapshot writes nothing into the person's repository and runs none of the
//! repository's own code.
//!
//! The lane's own rows (src/snapshot.rs tests) walk the happy path and the split index. These state what a repository
//! the host did not write must NOT get, one shape per section, each over the guard that decides it, so a weakened
//! guard reds a row rather than passing quietly. Every row ends with the same three assertions — the tree is the one
//! the person's index describes, no marker file exists (`marks/` is outside `.git`, so a second count of what ran is
//! read from beside the byte map), and every file under `.git` is byte-identical afterwards:
//!
//!   A. no HOOK runs, by any name and in either place it can be named: all of git's hooks are planted executable in
//!      `.git/hooks` and again in a directory the repository names as `core.hooksPath`.
//!   B. the person's FILE is never read through a filter, clean or process: `.gitattributes` names a filter whose
//!      `process` command marks and whose `required` is true, and the index is made racily clean (its mtime set to
//!      the file's), which is the state that makes git compare work-tree content.
//!   C. `core.fsmonitor` naming a command does not run it, over an index that really carries the FSMN extension; the
//!      value the snapshot's own git spawn reads back is the belt's `false`, never the repository's command.
//!   D. a repository config that re-points the hooks, the work tree or a filter changes nothing: one file, named by
//!      `include`, `includeIf "gitdir:"` and `includeIf "onbranch:"`, and a `config.worktree` beside it.
//!   E. a gitlink is written as a gitlink, and the `submodule.<name>.update` command is not run.
//!   F. an index that is not split is not treated as one: a `sharedindex.*` left behind by `--no-split-index` (git
//!      leaves it, and answers `rev-parse --shared-index-path` empty) must not send the tree to HEAD and lose the
//!      person's staged change; and a `sharedindex.*` that is a symlink out of the repository is never read through.
//!   G. a stale `.git/index.lock` neither fails the snapshot nor is disturbed.
//!   H. a repository built by `clone --shared` resolves its objects through its alternates (the scratch names the
//!      repository's store in its own `objects/info/alternates` at this head), and the alternate store is byte-identical
//!      afterwards.
//!   I. an index mid-merge (conflict stages) makes the call SAY it cannot build a tree, and writes nothing trying.
//!   J. the index's SHAPE and SIZE, which the copy must decide from the file itself: a FIFO does not block the host, a
//!      socket, a directory, a link to `/dev/zero` and a link to a real index are all refused (the last named as a link,
//!      never followed), an index too large to copy is not copied and leaves nothing large in the host's directory, and
//!      the person's own index keeps its bytes, mtime and inode.
//!
//! MUTATION PER ROW, MEASURED AT a6e4971f (notes, not committed changes — one applied alone, this file run, the
//! source reverted with `git checkout -- src/`; it was 10/10 green before and after):
//!   A  src/snapshot.rs `Scratch::new`: the `GIT_CONFIG_COUNT`/`KEY_2`/`VALUE_2` trio (`core.hooksPath=/dev/null`)
//!      removed → A red: `rev-parse --git-path hooks` answers the directory the repository names. Measured separately
//!      in a shell at the same env, because the mark alone cannot show it: with the trio gone, `git write-tree` really
//!      DOES run the repository's `post-index-change` (and `git read-tree HEAD` does too), so the mark assertion below
//!      is not vacuous — but whether git rewrites the index, and so fires it, is git's business, so the row asserts the
//!      resolved directory first and the marks after it.
//!   B  src/snapshot.rs `Scratch::git`: `Some(&self.dir.join("empty"))` → `None` (the spawn runs in the work tree, the
//!      dropped cwd guard) → B red: `tree()` is `Err("git write-tree exited 128")` and `marks/process` exists, because
//!      git reads `<cwd>/<path>` and hands it to the filter. THE GUARD, NOT THE RACINESS, IS WHAT SAVES IT: with the
//!      index copy's own mtime newer than every entry (no racy entry at all) the same mutation still runs the filter,
//!      measured in a shell — the row holds on any platform, not only where timestamps are coarse.
//!   C  src/gitfacts.rs `belt`: the `core.fsmonitor=false` pair removed → C red: the value the snapshot's spawn reads
//!      back is the repository's command.
//!   D  src/snapshot.rs `Scratch::new`: the `GIT_WORK_TREE` pair removed → D red: `rev-parse --show-toplevel` answers
//!      the repository, the belt's `GIT_WORK_TREE` taking over again.
//!   F  src/snapshot.rs `split_index`: the git query replaced by the old directory listing (any `sharedindex.*` means
//!      split) → F red: the leftover shared half sends the tree to HEAD and the staged `late.txt` is gone. With
//!      `rev-parse --shared-index-path` in place the row is green.
//!   J1 src/snapshot.rs `open_index`: `OFlags::NONBLOCK` dropped → J1 red, by timeout: opening a FIFO for reading
//!      without it waits for a writer, and no writer comes.
//!   J2 src/snapshot.rs `open_index`: `OFlags::NOFOLLOW` dropped → J2 red on the link-to-a-regular-index case: the
//!      link is followed, the file behind it is accepted, and the reason no longer says a link was refused.
//!   J3 src/snapshot.rs `INDEX_MAX` → 64 (a cap below a real index) → J4 red at "the copy is the person's index": the
//!      bound's comparison is load-bearing, and a real index has to be under it. The bound's VALUE cannot be measured
//!      from above (see CANNOT ROW): a 256 MiB index cannot be made VALID, and an invalid one is refused by the split
//!      query before the cap is consulted, so raising `INDEX_MAX` moves nothing.
//!   J4 pins a one-way copy (read, never written back); no one-line change to src/ reds it, which is the point.
//!
//! WHAT THIS FILE CANNOT ROW (named so the next reader does not look for it):
//!   - `INDEX_MAX`'s VALUE: 256 MiB of VALID index entries cannot be built in a test's time, and a sparse file that
//!     size is not a valid index (git refuses it at the split query, before the cap). J3 rows the consequence for an
//!     index that cannot be used — nothing large reaches the host's directory, the tree comes from HEAD — and the cap's
//!     comparison is measured by mutation from below. The scratch's own path is private, so J3 walks the `base` it
//!     was handed.
//!   - The copy's mtime (`copy_index`'s `set_modified`) is set so the racily-clean set matches the person's, but the
//!     scratch's index path is private and the scratch's work tree is EMPTY, so git cannot re-read a file that is not
//!     there and the decision cannot change the tree. No outcome row can see it; it stays a mechanism, not a pin.
//!   - `Scratch::new` takes `base` from its caller (H11), so "the scratch is never created inside the repository"
//!     cannot be a row of the module: it is the caller's argument. The module's own tests pass a temp dir.
//!   - A git whose `core.hooksPath = /dev/null` resolves (A asserts exactly that answer) and yet runs a hook anyway
//!     would need BOTH halves of A to be wrong at once; no such version is known here, and the marks are the second
//!     half, so the row does not lean on the directory alone.
use std::collections::BTreeMap;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;

use window_ml_host::gitconfig::RepoConfig;
use window_ml_host::gitfacts::Git;
use window_ml_host::snapshot::Scratch;

fn have_git() -> bool {
    Command::new("git").arg("--version").output().is_ok()
}

/// The `-c` flags every fixture git command carries. The last two are the row's own defence: git 2.56 spawns a DETACHED
/// `git maintenance run --auto --quiet --detach` after every commit (measured here: `GIT_TRACE=1 git commit` prints the
/// run_command), and when a task decides to work it takes and removes `objects/maintenance.lock` — a path that appears
/// in a row's before-picture of `.git` and is gone by its after, with the snapshot writing nothing. It is this fixture's
/// own background process, so the fixture turns it off at the source; `gc.auto=0` is the path a git without
/// `maintenance.auto` takes instead.
const GIT_FIXTURE: [&str; 10] = [
    "-c",
    "user.name=t",
    "-c",
    "user.email=t@t",
    "-c",
    "commit.gpgsign=false",
    "-c",
    "maintenance.auto=false",
    "-c",
    "gc.auto=0",
];

/// The flags above, then the row's own command.
fn git_fixture_args(args: &[&str]) -> Vec<String> {
    let mut v: Vec<String> = GIT_FIXTURE.iter().map(|s| s.to_string()).collect();
    v.extend(args.iter().map(|s| s.to_string()));
    v
}

/// A git command in `dir` that must succeed.
fn run(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(git_fixture_args(args))
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?} in {}: {}", dir.display(), String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// A git command in `dir` whose exit status the row is about.
fn try_run(dir: &Path, args: &[&str]) -> i32 {
    Command::new("git")
        .args(git_fixture_args(args))
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap()
        .status
        .code()
        .unwrap_or(-1)
}

/// Every file under `.git` with its bytes: an object, an index, a ref, a lock or a rewritten config all show.
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

/// A repository with one commit and two files, and an empty `marks/` beside it. Nothing is configured to run: each row
/// plants exactly its own shape, so an empty `marks/` means that shape did not run.
fn repo() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("w");
    let marks = t.path().join("marks");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&marks).unwrap();
    run(&root, &["init", "-q", "-b", "main"]);
    std::fs::write(root.join("a.txt"), "one\n").unwrap();
    std::fs::create_dir(root.join("sub")).unwrap();
    std::fs::write(root.join("sub/b.txt"), "two\n").unwrap();
    run(&root, &["add", "."]);
    run(&root, &["commit", "-q", "-m", "c"]);
    (t, root, marks)
}

/// An executable that leaves `marks/<name>` behind when it runs.
fn marker(path: &Path, marks: &Path, name: &str) {
    std::fs::write(path, format!("#!/bin/sh\ntouch {}\nexit 0\n", marks.join(name).display())).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// Forgets what the row's own setup ran, so what remains is what the snapshot ran.
fn clear(marks: &Path) {
    for e in std::fs::read_dir(marks).unwrap().flatten() {
        std::fs::remove_file(e.path()).unwrap();
    }
}

/// The rows' shared tail: nothing ran.
fn assert_no_marks(marks: &Path) {
    let mut names: Vec<String> =
        std::fs::read_dir(marks).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    names.sort();
    assert!(names.is_empty(), "the snapshot ran repository code: {names:?}");
}

fn scratch_base(t: &tempfile::TempDir) -> PathBuf {
    t.path().join("host")
}

fn inspect(root: &Path) -> RepoConfig {
    window_ml_host::gitconfig::inspect(root).unwrap()
}

fn git_on_path() -> Git {
    Git::on(&std::env::split_paths(&std::env::var_os("PATH").unwrap()).collect::<Vec<_>>())
}

/// The tree `HEAD` names, read without writing into the repository.
fn head_tree(root: &Path) -> String {
    run(root, &["rev-parse", "HEAD^{tree}"])
}

/// The entries of `tree` as `mode object<TAB>path` lines, read through the scratch store.
fn entries(s: &Scratch, g: &Git, r: &RepoConfig, tree: &str) -> String {
    let (code, out) = s.git(g, r, &["ls-tree", "-r", tree]).unwrap();
    assert_eq!(code, 0, "the scratch store could not read its own tree");
    String::from_utf8_lossy(&out).trim().to_string()
}

/// Makes an index entry racily clean the way the guard's comment describes: the index's mtime is set to the file's.
fn make_racy(root: &Path, file: &str, index: &Path) {
    let mtime = std::fs::metadata(root.join(file)).unwrap().modified().unwrap();
    let f = std::fs::File::options().write(true).open(index).unwrap();
    f.set_modified(mtime).unwrap();
}

// --- A: no hook runs, whatever it is named and wherever it is named ---

/// Every hook name git documents. A row that planted one of them would be a row about that hook; the snapshot may run
/// none, and the belt's `core.hooksPath = /dev/null` is what says so.
const HOOKS: &[&str] = &[
    "applypatch-msg",
    "pre-applypatch",
    "post-applypatch",
    "pre-commit",
    "pre-merge-commit",
    "prepare-commit-msg",
    "commit-msg",
    "post-commit",
    "pre-rebase",
    "post-checkout",
    "post-merge",
    "pre-push",
    "pre-receive",
    "update",
    "proc-receive",
    "post-receive",
    "post-update",
    "reference-transaction",
    "push-to-checkout",
    "pre-auto-gc",
    "post-rewrite",
    "sendemail-validate",
    "fsmonitor-watchman",
    "p4-changelist",
    "p4-prepare-changelist",
    "p4-post-changelist",
    "p4-pre-submit",
    "post-index-change",
];

#[test]
fn a_hook_is_not_run_by_any_name_in_either_hooks_path() {
    if !have_git() {
        return;
    }
    let (t, root, marks) = repo();
    let named = t.path().join("named-hooks");
    std::fs::create_dir_all(&named).unwrap();
    for name in HOOKS {
        marker(&root.join(".git/hooks").join(name), &marks, name);
        marker(&named.join(name), &marks, name);
    }
    // The repository names its own hooks directory, which the belt must beat.
    run(&root, &["config", "core.hooksPath", named.to_str().unwrap()]);
    clear(&marks);
    let before = dot_git(&root);
    let (g, r) = (git_on_path(), inspect(&root));
    let s = Scratch::new(&g, &r, &scratch_base(&t)).unwrap();
    // The directory git RESOLVES, read through the snapshot's own spawn: the belt's answer, never the repository's.
    let (code, out) = s.git(&g, &r, &["rev-parse", "--git-path", "hooks"]).unwrap();
    assert_eq!(code, 0);
    assert_eq!(String::from_utf8_lossy(&out).trim(), "/dev/null", "the hooks git would run are none");
    assert_eq!(s.tree(&g, &r).unwrap(), head_tree(&root));
    drop(s);
    assert_eq!(dot_git(&root), before, "index, refs, config, hooks and objects are byte-identical");
    assert_no_marks(&marks);
}

// --- B: the person's file is never read through a filter ---

/// The state that makes git compare work-tree content: `filter.<f>.process` is what git starts, `required` is what
/// makes a failure fatal, and a racily clean index is what makes the compare happen at all.
#[test]
fn a_file_is_not_read_through_a_clean_or_process_filter_even_when_the_index_is_racily_clean() {
    if !have_git() {
        return;
    }
    let (t, root, marks) = repo();
    // The attribute first, staged with no filter configured, so the setup itself cannot be the mark.
    std::fs::write(root.join(".gitattributes"), "* filter=f\n").unwrap();
    run(&root, &["add", ".gitattributes"]);
    run(&root, &["config", "filter.f.clean", &format!("touch {}; cat", marks.join("clean").display())]);
    run(&root, &["config", "filter.f.process", &format!("touch {}; exit 1", marks.join("process").display())]);
    run(&root, &["config", "filter.f.required", "true"]);
    make_racy(&root, "a.txt", &root.join(".git/index"));
    clear(&marks);
    let before = dot_git(&root);
    // The blob the person's index holds for the file, read without writing into the repository.
    let indexed = run(&root, &["rev-parse", ":a.txt"]);
    let (g, r) = (git_on_path(), inspect(&root));
    let s = Scratch::new(&g, &r, &scratch_base(&t)).unwrap();
    // `required` is what makes this the assertion it is: a process filter git DID start fails the call outright.
    let listed = entries(&s, &g, &r, &s.tree(&g, &r).unwrap());
    assert!(listed.contains(&format!("100644 blob {indexed}\ta.txt")), "the tree holds the index's own blob: {listed}");
    drop(s);
    assert_eq!(dot_git(&root), before);
    assert_no_marks(&marks);
}

// --- C: core.fsmonitor as a command, over an index that carries it ---

#[test]
fn a_repository_that_configures_fsmonitor_as_a_command_does_not_run_it() {
    if !have_git() {
        return;
    }
    let (t, root, marks) = repo();
    // An index git itself stamps with the FSMN extension, so the row is about a state this repository really has.
    let watchman = t.path().join("watchman");
    std::fs::write(
        &watchman,
        format!("#!/bin/sh\ntouch {}\nprintf '2\\0{}\\0'\n", marks.join("watchman").display(), "0".repeat(19)),
    )
    .unwrap();
    std::fs::set_permissions(&watchman, std::fs::Permissions::from_mode(0o755)).unwrap();
    run(&root, &["config", "core.fsmonitor", watchman.to_str().unwrap()]);
    let _ = try_run(&root, &["status", "--porcelain"]);
    assert!(
        std::fs::read(root.join(".git/index")).unwrap().windows(4).any(|w| w == b"FSMN"),
        "premise: the person's index carries the FSMN extension"
    );
    // Now the repository names a command that marks when it is started.
    run(&root, &["config", "core.fsmonitor", &format!("touch {}", marks.join("fsmonitor").display())]);
    clear(&marks);
    let before = dot_git(&root);
    let (g, r) = (git_on_path(), inspect(&root));
    let s = Scratch::new(&g, &r, &scratch_base(&t)).unwrap();
    let (code, out) = s.git(&g, &r, &["config", "--get", "core.fsmonitor"]).unwrap();
    assert_eq!(code, 0);
    assert_eq!(
        String::from_utf8_lossy(&out).trim(),
        "false",
        "the snapshot's own spawn reads the belt, not the repository"
    );
    assert_eq!(s.tree(&g, &r).unwrap(), head_tree(&root));
    drop(s);
    assert_eq!(dot_git(&root), before);
    assert_no_marks(&marks);
}

// --- D: a repository config that re-points the hooks, the work tree or a filter ---

#[test]
fn a_repository_config_that_re_points_hooks_the_work_tree_or_a_filter_changes_nothing() {
    if !have_git() {
        return;
    }
    let (t, root, marks) = repo();
    let named = t.path().join("inc-hooks");
    std::fs::create_dir_all(&named).unwrap();
    for name in ["post-index-change", "pre-commit", "post-checkout"] {
        marker(&named.join(name), &marks, name);
    }
    let elsewhere = t.path().join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::fs::write(elsewhere.join("a.txt"), "not the person's file\n").unwrap();
    let inc = t.path().join("outside.inc");
    std::fs::write(
        &inc,
        format!(
            "[core]\n\thooksPath = {}\n\tworktree = {}\n[filter \"f\"]\n\tprocess = touch {}; exit 1\n\tsmudge = cat\n\tclean = touch {}; cat\n",
            named.display(),
            elsewhere.display(),
            marks.join("inc-process").display(),
            marks.join("inc-clean").display()
        ),
    )
    .unwrap();
    // Named three ways, and once from a config.worktree the repository enables.
    let mut cfg = std::fs::read_to_string(root.join(".git/config")).unwrap();
    cfg.push_str(&format!(
        "[include]\n\tpath = {inc}\n[includeIf \"gitdir:**\"]\n\tpath = {inc}\n[includeIf \"onbranch:main\"]\n\tpath = {inc}\n",
        inc = inc.display()
    ));
    std::fs::write(root.join(".git/config"), cfg).unwrap();
    run(&root, &["config", "extensions.worktreeConfig", "true"]);
    let wt_cfg = std::fs::read_to_string(root.join(".git/config")).unwrap();
    let key = format!("[core]\n\thooksPath = {}\n", named.display());
    std::fs::write(root.join(".git/config.worktree"), key.clone()).unwrap();
    assert!(wt_cfg.contains("worktreeConfig"), "premise: the worktree config is read");
    // A staged change: the tree must be the person's INDEX, not HEAD, so a fallback would be visible here.
    std::fs::write(root.join("sub/staged.txt"), "staged\n").unwrap();
    run(&root, &["-c", "filter.f.process=", "add", "sub/staged.txt"]);
    clear(&marks);
    let before = dot_git(&root);
    let (g, r) = (git_on_path(), inspect(&root));
    let s = Scratch::new(&g, &r, &scratch_base(&t)).unwrap();
    let (code, out) = s.git(&g, &r, &["rev-parse", "--show-toplevel"]).unwrap();
    assert_eq!(code, 0);
    assert_eq!(
        std::fs::canonicalize(String::from_utf8_lossy(&out).trim()).unwrap(),
        std::fs::canonicalize(s.dir().join("empty")).unwrap(),
        "the work tree is the empty directory the scratch names; no repository config is asked for it"
    );
    let tree = s.tree(&g, &r).unwrap();
    assert_ne!(tree, head_tree(&root), "the person's staged change is in the tree the snapshot writes");
    assert!(
        entries(&s, &g, &r, &tree).contains("sub/staged.txt"),
        "the staged file is an entry: {}",
        entries(&s, &g, &r, &tree)
    );
    drop(s);
    assert_eq!(dot_git(&root), before);
    assert_no_marks(&marks);
}

// --- E: a gitlink entry ---

#[test]
fn a_gitlink_is_written_as_a_gitlink_and_runs_no_submodule_command() {
    if !have_git() {
        return;
    }
    let (t, root, marks) = repo();
    let head = run(&root, &["rev-parse", "HEAD"]);
    run(&root, &["update-index", "--add", "--cacheinfo", &format!("160000,{head},vendor")]);
    run(&root, &["config", "submodule.vendor.path", "vendor"]);
    run(&root, &["config", "submodule.vendor.update", &format!("!touch {}", marks.join("submodule-update").display())]);
    clear(&marks);
    let before = dot_git(&root);
    let (g, r) = (git_on_path(), inspect(&root));
    let s = Scratch::new(&g, &r, &scratch_base(&t)).unwrap();
    let tree = s.tree(&g, &r).unwrap();
    let listed = entries(&s, &g, &r, &tree);
    assert!(
        listed.contains(&format!("160000 commit {head}\tvendor")),
        "the gitlink is an entry as it was in the index: {listed}"
    );
    drop(s);
    assert_eq!(dot_git(&root), before);
    assert_no_marks(&marks);
}

// --- F: an index that is not split is not treated as one ---

/// `git update-index --no-split-index` rewrites a whole index and LEAVES the `sharedindex.*` beside it, and git's own
/// answer to "is this index split" (`rev-parse --shared-index-path`) is then empty. A directory listing is not that
/// answer: it sends the tree to HEAD and the person's staged change is silently missing from the diff.
#[test]
fn a_sharedindex_left_behind_by_no_split_index_does_not_lose_the_persons_staged_change() {
    if !have_git() {
        return;
    }
    let (t, root, marks) = repo();
    run(&root, &["update-index", "--split-index"]);
    run(&root, &["update-index", "--no-split-index"]);
    let leftover: Vec<String> = std::fs::read_dir(root.join(".git"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("sharedindex."))
        .collect();
    assert_eq!(leftover.len(), 1, "premise: git left a sharedindex behind: {leftover:?}");
    assert_eq!(run(&root, &["rev-parse", "--shared-index-path"]), "", "premise: git says the index is NOT split");
    std::fs::write(root.join("late.txt"), "late\n").unwrap();
    run(&root, &["add", "late.txt"]);
    clear(&marks);
    let before = dot_git(&root);
    let (g, r) = (git_on_path(), inspect(&root));
    let s = Scratch::new(&g, &r, &scratch_base(&t)).unwrap();
    let tree = s.tree(&g, &r).unwrap();
    let listed = entries(&s, &g, &r, &tree);
    assert!(listed.contains("late.txt"), "the staged file is in the tree: {listed}");
    drop(s);
    assert_eq!(dot_git(&root), before);
    assert_no_marks(&marks);
}

#[test]
fn a_sharedindex_that_is_a_symlink_out_of_the_repository_is_never_read_through() {
    if !have_git() {
        return;
    }
    let (t, root, marks) = repo();
    let outside = t.path().join("outside-shared");
    std::fs::write(&outside, b"a shared half that is not this repository's\n").unwrap();
    symlink(&outside, root.join(".git/sharedindex.0000000000000000000000000000000000000000")).unwrap();
    clear(&marks);
    let before = dot_git(&root);
    let outside_before = std::fs::read(&outside).unwrap();
    let (g, r) = (git_on_path(), inspect(&root));
    let s = Scratch::new(&g, &r, &scratch_base(&t)).unwrap();
    // WHICH tree it reports is F1's question; this row is the link: the shared half is never opened, so the file it
    // names cannot be read as an index, and the snapshot still ends honestly.
    assert!(s.tree(&g, &r).is_ok(), "the snapshot ends honestly beside a sharedindex it cannot use");
    drop(s);
    assert_eq!(dot_git(&root), before);
    assert_eq!(std::fs::read(&outside).unwrap(), outside_before, "the file the link names is untouched");
    assert_no_marks(&marks);
}

// --- G: a stale index.lock ---

#[test]
fn a_stale_index_lock_neither_fails_the_snapshot_nor_is_disturbed() {
    if !have_git() {
        return;
    }
    let (t, root, marks) = repo();
    std::fs::write(root.join(".git/index.lock"), b"left behind by a git that died\n").unwrap();
    clear(&marks);
    let before = dot_git(&root);
    let (g, r) = (git_on_path(), inspect(&root));
    let s = Scratch::new(&g, &r, &scratch_base(&t)).unwrap();
    assert!(!s.from_head);
    assert_eq!(s.tree(&g, &r).unwrap(), head_tree(&root));
    drop(s);
    assert_eq!(dot_git(&root), before, "the lock is where it was, and no second lock was made");
    assert_no_marks(&marks);
}

// --- H: alternates pointing outside the repository ---

#[test]
fn a_shared_clone_reads_its_alternates_and_writes_nothing_into_them() {
    if !have_git() {
        return;
    }
    let (t, _root, marks) = repo();
    let origin = t.path().join("w");
    let clone = t.path().join("shared");
    run(t.path(), &["clone", "-q", "--shared", origin.to_str().unwrap(), clone.to_str().unwrap()]);
    let alternates = std::fs::read_to_string(clone.join(".git/objects/info/alternates")).unwrap();
    assert!(
        alternates.contains(".git/objects"),
        "premise: every object of the clone lives in the alternate: {alternates}"
    );
    clear(&marks);
    let clone_before = dot_git(&clone);
    let origin_before = dot_git(&origin);
    let (g, r) = (git_on_path(), inspect(&clone));
    let s = Scratch::new(&g, &r, &scratch_base(&t)).unwrap();
    assert_eq!(s.tree(&g, &r).unwrap(), head_tree(&clone), "HEAD's tree resolves through the alternate");
    drop(s);
    assert_eq!(dot_git(&clone), clone_before);
    assert_eq!(dot_git(&origin), origin_before, "nothing was borrowed into the alternate's store");
    assert_no_marks(&marks);
}

// --- I: an index mid-merge ---

#[test]
fn an_index_with_conflict_stages_makes_the_call_say_it_cannot_build_a_tree() {
    if !have_git() {
        return;
    }
    let (t, root, marks) = repo();
    run(&root, &["checkout", "-q", "-b", "side"]);
    std::fs::write(root.join("a.txt"), "side\n").unwrap();
    run(&root, &["commit", "-q", "-am", "side"]);
    run(&root, &["checkout", "-q", "main"]);
    std::fs::write(root.join("a.txt"), "main\n").unwrap();
    run(&root, &["commit", "-q", "-am", "main"]);
    assert_ne!(try_run(&root, &["merge", "side"]), 0, "premise: the merge conflicts and leaves stages in the index");
    clear(&marks);
    let before = dot_git(&root);
    let (g, r) = (git_on_path(), inspect(&root));
    let s = Scratch::new(&g, &r, &scratch_base(&t)).unwrap();
    let tree = s.tree(&g, &r);
    assert!(tree.is_err(), "a tree it cannot build is reported, never a tree of the wrong thing: {tree:?}");
    drop(s);
    assert_eq!(dot_git(&root), before);
    assert_no_marks(&marks);
}

// --- J: the index's shape and size ---

/// What is under `base`, with the size of every regular file: the walk J3 needs, since the scratch's own path is
/// private to the module.
fn base_files(base: &Path) -> Vec<(PathBuf, u64)> {
    let mut out = vec![];
    let mut stack = vec![base.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            match e.file_type() {
                Ok(t) if t.is_dir() => stack.push(p),
                Ok(t) if t.is_file() => out.push((p.clone(), e.metadata().map(|m| m.len()).unwrap_or(0))),
                _ => {}
            }
        }
    }
    out
}

/// `Scratch::new` with a bound on wall time, so a row can fail instead of hanging the suite: `None` means it had not
/// answered after `secs`, which is the FIFO's failure mode.
fn scratch_within(g: Git, r: RepoConfig, base: PathBuf, secs: u64) -> Option<Result<Scratch, String>> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(Scratch::new(&g, &r, &base));
    });
    rx.recv_timeout(std::time::Duration::from_secs(secs)).ok()
}

/// A refused index leaves no scratch behind and runs nothing: the tail of every J row that expects a refusal.
fn refused_cleanly(t: &tempfile::TempDir, marks: &Path, e: &str) {
    assert_eq!(base_files(&scratch_base(t)), vec![], "a refusal leaves no scratch behind: {e}");
    assert_no_marks(marks);
}

#[test]
fn an_index_that_is_a_fifo_is_refused_instead_of_blocking_the_host() {
    if !have_git() {
        return;
    }
    let (t, root, marks) = repo();
    let index = root.join(".git/index");
    std::fs::remove_file(&index).unwrap();
    assert!(Command::new("mkfifo").arg(&index).status().unwrap().success(), "premise: a FIFO at .git/index");
    let (g, r) = (git_on_path(), inspect(&root));
    let got = scratch_within(g, r, scratch_base(&t), 10);
    let Some(got) = got else { panic!("the host blocked on a FIFO index and never answered") };
    let e = got.err().expect("a FIFO index is refused, not copied");
    assert!(e.contains("not a regular file"), "the refusal names the shape: {e}");
    assert!(index.exists(), "the FIFO is still the person's .git/index");
    refused_cleanly(&t, &marks, &e);
}

#[test]
fn the_shapes_the_index_copy_refuses_and_what_it_calls_them() {
    if !have_git() {
        return;
    }
    // Every shape a `.git/index` can be that is not a readable regular file, and the reason each is refused. A link to
    // a REAL index is the one that would be copied if the open followed it. A socket is refused by the OPEN (macOS
    // answers "Operation not supported on socket"), so its reason is the open's wording rather than the shape's — either
    // is a refusal, and both are reported to the person.
    for (shape, want) in [
        ("link-to-index", &["without following a link"][..]),
        ("link-to-dev-zero", &["without following a link"][..]),
        ("dangling", &["without following a link"][..]),
        ("socket", &["not a regular file", "could not be opened"][..]),
        ("directory", &["not a regular file"][..]),
    ] {
        let (t, root, marks) = repo();
        let index = root.join(".git/index");
        let real = root.join(".git/real-index");
        std::fs::rename(&index, &real).unwrap();
        let target = match shape {
            "link-to-index" => {
                symlink(&real, &index).unwrap();
                Some(real.clone())
            }
            "link-to-dev-zero" => {
                symlink("/dev/zero", &index).unwrap();
                None
            }
            "dangling" => {
                symlink(root.join(".git/nowhere"), &index).unwrap();
                None
            }
            "socket" => {
                let _l = std::os::unix::net::UnixListener::bind(&index).unwrap();
                None
            }
            "directory" => {
                std::fs::create_dir(&index).unwrap();
                None
            }
            _ => unreachable!(),
        };
        let real_before = target.as_ref().map(|p| (std::fs::read(p).unwrap(), std::fs::metadata(p).unwrap().len()));
        let (g, r) = (git_on_path(), inspect(&root));
        let e = Scratch::new(&g, &r, &scratch_base(&t)).err().unwrap_or_else(|| panic!("{shape}: refused"));
        assert!(
            want.iter().any(|w| e.contains(w)),
            "{shape}: the refusal names the shape, want one of {want:?} in {e}"
        );
        if let (Some(p), Some(before)) = (&target, real_before) {
            assert_eq!(std::fs::read(p).unwrap(), before.0, "{shape}: the file the link names is untouched");
        }
        refused_cleanly(&t, &marks, &e);
    }
}

#[test]
fn an_index_too_large_to_copy_is_not_copied_and_leaves_nothing_large_behind() {
    if !have_git() {
        return;
    }
    let (t, root, marks) = repo();
    let index = root.join(".git/index");
    // Sparse, so this costs no disk: a file over the module's 256 MiB cap. Its content is not a valid index, which is
    // the other way a copy of it would be useless — the row is the SIZE: not one byte of it reaches the host's dir.
    let f = std::fs::OpenOptions::new().write(true).truncate(true).open(&index).unwrap();
    f.set_len((256 << 20) + 4096).unwrap();
    drop(f);
    clear(&marks);
    let len_before = std::fs::metadata(&index).unwrap().len();
    let (g, r) = (git_on_path(), inspect(&root));
    let s = Scratch::new(&g, &r, &scratch_base(&t)).unwrap();
    let large: Vec<_> = base_files(&scratch_base(&t)).into_iter().filter(|(_, n)| *n > 8 << 20).collect();
    assert!(large.is_empty(), "the host's directory holds a copy of the person's index: {large:?}");
    assert!(s.from_head, "a base it could not copy comes from HEAD, and says so");
    // HEAD's tree is readable, so the snapshot ends honestly rather than failing over a pathological index.
    assert_eq!(s.tree(&g, &r).unwrap(), head_tree(&root));
    drop(s);
    assert_eq!(std::fs::metadata(&index).unwrap().len(), len_before, "the person's index is not written");
    assert_eq!(base_files(&scratch_base(&t)), vec![], "the scratch goes when the Scratch drops");
    assert_no_marks(&marks);
}

#[test]
fn the_persons_index_keeps_its_bytes_mtime_and_inode() {
    if !have_git() {
        return;
    }
    let (t, root, marks) = repo();
    std::fs::write(root.join("late.txt"), "late\n").unwrap();
    run(&root, &["add", "late.txt"]);
    let index = root.join(".git/index");
    // An OLD mtime: if the copy wrote anything back, or the open left it rewritten, the timestamp would move.
    let old = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000);
    std::fs::File::options().write(true).open(&index).unwrap().set_modified(old).unwrap();
    use std::os::unix::fs::MetadataExt;
    let before = std::fs::metadata(&index).unwrap();
    clear(&marks);
    let git_before = dot_git(&root);
    let (g, r) = (git_on_path(), inspect(&root));
    let s = Scratch::new(&g, &r, &scratch_base(&t)).unwrap();
    assert!(entries(&s, &g, &r, &s.tree(&g, &r).unwrap()).contains("late.txt"), "the copy is the person's index");
    drop(s);
    let after = std::fs::metadata(&index).unwrap();
    assert_eq!(
        (after.ino(), after.len(), after.modified().unwrap()),
        (before.ino(), before.len(), old),
        "the same file, the same bytes, the same mtime"
    );
    assert_eq!(dot_git(&root), git_before, "and nothing else under .git moved either");
    assert_no_marks(&marks);
}
