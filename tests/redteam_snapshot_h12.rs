//! redteam_snapshot_h12.rs — the BOUNDS of the snapshot (window-ml FILE_ATTACHMENTS.md H12; window-ml-host#54, built at
//! 9dedd69d), from the adversarial side. The property: nothing a work tree holds enters the tree except a captured
//! regular file of 1 MiB or less, and every path left out is named with its reason rather than silently absent.
//!
//! The lane's own rows (src/snapshot_bounds.rs, src/snapshot.rs) test the cache, the tick and the hash budget. These
//! test what a writer can do to the tree and to the host: a file at and one byte past the cap, a tracked file grown
//! past it, a FIFO that would block if anything opened it, an ignored FIFO against the uploads folder's, a secret-named
//! file that is now LISTED rather than silently skipped, and the walk's bound at its exact edge.
//!
//! WHAT THIS FILE CANNOT ROW (named so the next reader does not look for it):
//!   - The hash budget (2 GiB) and the stat cache's tick as they interact with a REwrite: both need gigabytes or a
//!     clock the host can move, and src/snapshot_bounds.rs tests each with its state preset.
//!   - A file that grows between its `lstat` and the batch hash: the batch is git's own `hash-object --stdin-paths`,
//!     which opens the path itself, so a file swapped to a huge one inside that window is read by git before the
//!     host's second `lstat` can refuse it. The window is the writer's own; the private objects are local and removed
//!     with the scratch, and no deterministic row can pin it.
//!   - A device file in `/dev`: creating one needs privilege; a FIFO is the same branch of `special_files` and is rowed.
use std::path::{Path, PathBuf};
use std::process::Command;

use window_ml_host::gitconfig::RepoConfig;
use window_ml_host::gitfacts::Git;
use window_ml_host::snapshot::Scratch;
use window_ml_host::snapshot_bounds::{DIFF_CAP, NOT_A_FILE, WITHHELD_NAME};

fn have_git() -> bool {
    Command::new("git").arg("--version").output().is_ok()
}

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

fn run(dir: &Path, args: &[&str]) -> String {
    let mut v: Vec<&str> = GIT_FIXTURE.to_vec();
    v.extend_from_slice(args);
    let out = Command::new("git")
        .args(&v)
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn repo() -> (tempfile::TempDir, PathBuf) {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("w");
    std::fs::create_dir_all(&root).unwrap();
    run(&root, &["init", "-q", "-b", "main"]);
    std::fs::write(root.join("a.txt"), "one\n").unwrap();
    std::fs::create_dir(root.join("sub")).unwrap();
    std::fs::write(root.join("sub/b.txt"), "two\n").unwrap();
    run(&root, &["add", "."]);
    run(&root, &["commit", "-q", "-m", "c"]);
    std::fs::write(root.join(".gitignore"), "up/\nign/\n").unwrap();
    std::fs::create_dir_all(root.join("up")).unwrap();
    let past = std::time::SystemTime::now() - std::time::Duration::from_secs(60);
    for p in ["a.txt", "sub/b.txt"] {
        std::fs::File::options().write(true).open(root.join(p)).unwrap().set_modified(past).unwrap();
    }
    run(&root, &["-c", "core.fsmonitor=false", "update-index", "--refresh"]);
    (t, root)
}

fn git_on_path() -> Git {
    Git::on(&std::env::split_paths(&std::env::var_os("PATH").unwrap()).collect::<Vec<_>>())
}

fn tree(s: &Scratch, g: &Git, r: &RepoConfig) -> Vec<String> {
    let t = s.tree(g, r).unwrap();
    let (code, out) = s.git(g, r, &["ls-tree", "-r", "-z", &t]).unwrap();
    assert_eq!(code, 0);
    out.split(|b| *b == 0).filter(|l| !l.is_empty()).map(|l| String::from_utf8_lossy(l).into_owned()).collect()
}

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

fn sha_of(p: &Path) -> String {
    let out = Command::new("shasum").args(["-a", "256"]).arg(p).output().unwrap();
    assert!(out.status.success());
    String::from_utf8_lossy(&out.stdout).split_whitespace().next().unwrap().to_string()
}

fn mkfifo(p: &Path) {
    assert!(Command::new("mkfifo").arg(p).status().unwrap().success());
}

fn enter(
    root: &Path,
    t: &tempfile::TempDir,
) -> (Git, RepoConfig, Scratch, window_ml_host::snapshot::Entered, Vec<String>) {
    let (g, r) = (git_on_path(), window_ml_host::gitconfig::inspect(root).unwrap());
    let s = Scratch::new(&g, &r, &t.path().join("host")).unwrap();
    let e = s.enter_changes(&g, &r, Some(&root.join("up"))).unwrap();
    let tree = tree(&s, &g, &r);
    (g, r, s, e, tree)
}

// --- the cap, at its edge ---

#[test]
fn a_file_of_exactly_the_cap_enters_and_one_byte_more_is_big_with_no_blob_in_the_tree() {
    if !have_git() {
        return;
    }
    let (t, root) = repo();
    let at = vec![b'a'; DIFF_CAP as usize];
    let over = vec![b'b'; DIFF_CAP as usize + 1];
    std::fs::write(root.join("at.bin"), &at).unwrap();
    std::fs::write(root.join("over.bin"), &over).unwrap();
    let (_, _, _, e, tree) = enter(&root, &t);
    // The file AT the cap is a captured file, under the SAME rule as any other: its body enters.
    assert!(
        tree.iter().any(|l| l.ends_with("\tat.bin") && l.contains(&blob_of(&root, &at))),
        "at the cap enters: {tree:?}"
    );
    // One byte past it is Big: listed with its size and sha256, and its body is in no blob.
    let big = e.big.iter().find(|b| b.path == b"over.bin").expect("over.bin is big");
    assert_eq!(big.size, DIFF_CAP + 1);
    assert_eq!(big.sha256.as_deref(), Some(sha_of(&root.join("over.bin")).as_str()));
    assert!(!big.executable);
    let oid = blob_of(&root, &over);
    assert!(!tree.iter().any(|l| l.contains(&oid)), "the big file's body is in the tree: {tree:?}");
    assert!(!tree.iter().any(|l| l.ends_with("\tover.bin")));
    assert!(
        !e.not_captured.iter().any(|n| n.path == b"over.bin"),
        "big is not 'not captured': it is reported with its hash"
    );
}

#[test]
fn a_tracked_file_grown_past_the_cap_leaves_the_tree() {
    if !have_git() {
        return;
    }
    let (t, root) = repo();
    let grown = vec![b'g'; DIFF_CAP as usize + 7];
    std::fs::write(root.join("a.txt"), &grown).unwrap();
    let (_, _, _, e, tree) = enter(&root, &t);
    // Its OLD body must not be diffed either: the tree's a.txt would otherwise be the committed one against which the
    // scratch index's removal has not been applied.
    assert!(!tree.iter().any(|l| l.ends_with("\ta.txt")), "a big tracked file is removed: {tree:?}");
    assert!(e.big.iter().any(|b| b.path == b"a.txt" && b.size == DIFF_CAP + 7));
    assert!(!tree.iter().any(|l| l.contains(&blob_of(&root, &grown))), "and its body is in no blob");
}

// --- special files are listed, never opened ---

#[test]
fn an_untracked_fifo_is_listed_and_never_opened() {
    if !have_git() {
        return;
    }
    let (t, root) = repo();
    // A FIFO with no writer: anything that OPENS it for reading blocks forever. The row finishing at all is the
    // assertion that nothing did.
    mkfifo(&root.join("pipe"));
    mkfifo(&root.join("sub/deep"));
    let (_, _, _, e, tree) = enter(&root, &t);
    let got: Vec<Vec<u8>> = e.not_captured.iter().filter(|n| n.reason == NOT_A_FILE).map(|n| n.path.clone()).collect();
    assert_eq!(got, [b"pipe".to_vec(), b"sub/deep".to_vec()], "both, sorted");
    assert!(!tree.iter().any(|l| l.ends_with("\tpipe") || l.ends_with("\tsub/deep")), "and in no tree");
}

#[test]
fn an_ignored_fifo_is_left_out_and_one_in_the_uploads_folder_is_listed() {
    if !have_git() {
        return;
    }
    let (t, root) = repo();
    std::fs::create_dir_all(root.join("ign")).unwrap();
    mkfifo(&root.join("ign/pipe"));
    // A regular file beside it, so `up/` is a directory the listings reached: a FIFO alone in a directory git lists
    // nothing for is in neither list, which the module names as its known width.
    std::fs::write(root.join("up/note.txt"), "up\n").unwrap();
    mkfifo(&root.join("up/pipe"));
    let (_, _, _, e, _) = enter(&root, &t);
    let got: Vec<Vec<u8>> = e.not_captured.iter().filter(|n| n.reason == NOT_A_FILE).map(|n| n.path.clone()).collect();
    // Ignored is left out as git leaves an ignored file out; the uploads folder is the one place the host lists
    // everything, so its FIFO is reported even though `up/` is ignored.
    assert_eq!(got, [b"up/pipe".to_vec()], "the ignored one is absent, the uploads one present: {got:?}");
}

#[test]
fn a_tracked_file_replaced_by_a_fifo_leaves_the_tree() {
    if !have_git() {
        return;
    }
    let (t, root) = repo();
    std::fs::remove_file(root.join("sub/b.txt")).unwrap();
    mkfifo(&root.join("sub/b.txt"));
    let (_, _, _, e, tree) = enter(&root, &t);
    assert!(e.not_captured.iter().any(|n| n.path == b"sub/b.txt" && n.reason == NOT_A_FILE));
    assert!(!tree.iter().any(|l| l.ends_with("\tsub/b.txt")), "the tracked path leaves the tree: {tree:?}");
}

// --- what a name decides ---

#[test]
fn a_secret_named_untracked_file_is_listed_as_withheld_and_its_body_is_in_no_blob() {
    if !have_git() {
        return;
    }
    let (t, root) = repo();
    let body = b"TOKEN=unique-to-this-row\n";
    std::fs::write(root.join(".env"), body).unwrap();
    std::fs::write(root.join("sub/id_rsa"), body).unwrap();
    let (_, _, _, e, tree) = enter(&root, &t);
    let got: Vec<Vec<u8>> =
        e.not_captured.iter().filter(|n| n.reason == WITHHELD_NAME).map(|n| n.path.clone()).collect();
    // The path is NAMED as withheld (the reason rule matches ordinary files too, so the person is told), and the body
    // is in neither tree.
    assert_eq!(got, [b".env".to_vec(), b"sub/id_rsa".to_vec()], "both listed, sorted: {got:?}");
    assert!(!tree.iter().any(|l| l.contains(&blob_of(&root, body))), "the body enters no tree: {tree:?}");
}

#[test]
fn an_unreadable_file_is_listed_and_a_tracked_one_leaves_the_tree() {
    use std::os::unix::fs::PermissionsExt;
    if !have_git() {
        return;
    }
    let (t, root) = repo();
    std::fs::write(root.join("locked.txt"), "x\n").unwrap();
    std::fs::set_permissions(root.join("locked.txt"), std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::File::open(root.join("locked.txt")).is_ok() {
        // Root ignores the mode; nothing to measure here.
        std::fs::set_permissions(root.join("locked.txt"), std::fs::Permissions::from_mode(0o644)).unwrap();
        return;
    }
    std::fs::set_permissions(root.join("sub/b.txt"), std::fs::Permissions::from_mode(0o000)).unwrap();
    let (_, _, _, e, tree) = enter(&root, &t);
    let got: Vec<Vec<u8>> =
        e.not_captured.iter().filter(|n| n.reason == "unreadable").map(|n| n.path.clone()).collect();
    assert_eq!(got, [b"locked.txt".to_vec(), b"sub/b.txt".to_vec()], "both listed as unreadable: {got:?}");
    assert!(!tree.iter().any(|l| l.ends_with("\tsub/b.txt")), "and the tracked one leaves the tree");
    std::fs::set_permissions(root.join("sub/b.txt"), std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::set_permissions(root.join("locked.txt"), std::fs::Permissions::from_mode(0o644)).unwrap();
}

// --- the walk's bound, at its edge ---

#[test]
fn the_walk_cap_is_exact_at_its_edge() {
    if !have_git() {
        return;
    }
    let (t, root) = repo();
    // Tracked: 2 (a.txt, sub/b.txt). Untracked: .gitignore. Fill with empty untracked files to exactly the cap, then
    // one more: the decision is `count > WALK_CAP`, so both sides are measured rather than sampled.
    let cap = window_ml_host::walk::WALK_CAP;
    let dir = root.join("many");
    std::fs::create_dir_all(&dir).unwrap();
    for i in 0..(cap - 3) {
        std::fs::write(dir.join(format!("f{i}")), "").unwrap();
    }
    let (g, r) = (git_on_path(), window_ml_host::gitconfig::inspect(&root).unwrap());
    let s = Scratch::new(&g, &r, &t.path().join("host")).unwrap();
    assert!(s.enter_changes(&g, &r, Some(&root.join("up"))).is_ok(), "exactly the cap is a snapshot");
    std::fs::write(dir.join("one-more"), "").unwrap();
    let err = s.enter_changes(&g, &r, Some(&root.join("up"))).unwrap_err();
    assert!(err.contains(&cap.to_string()), "past the cap: a null diff whose reason names the bound: {err}");
}
