//! redteam_snapshot_h11.rs — the SECRET-NAME exclusion of the H11 snapshot, from the HOST's side (window-ml
//! FILE_ATTACHMENTS.md H11, amended 2026-11-19; window-ml #1988, built at 31d2f8dd). The property: an untracked path
//! `facts::looks_secret` matches is in neither snapshot tree and its body is not in the private object directory.
//!
//! The lane's own row (src/snapshot.rs) plants `.env.local`, `up/id_ed25519` and `up/.ssh/config` and reads the tree.
//! These add the shapes that decide WHERE the filter sits rather than which name it knows: a shape is only exercised if
//! the file really is listed by the host's own two listings (an untracked, non-ignored file, or anything untracked under
//! the uploads folder), so each section plants its shapes in the listing it is about, and every row first asserts that
//! `looks_secret` matches the path it is about — a matcher that stopped catching a shape would otherwise turn the
//! absence into a vacuous pass.
//!
//!   A. outside the uploads folder, through `ls-files --others --exclude-standard`: the exact names, the case variants
//!      of each rule the matcher applies (a name, an `id_` prefix, a suffix, a credentials directory, the
//!      `.config/{gcloud,gh}` pair), and a secret-named file below an ordinary directory.
//!   B. inside the uploads folder, whose untracked files the host lists a second time WITHOUT `--exclude-standard`
//!      (the folder is ignored in the fixture): the same shapes, plus a suffix and a template's neighbour`.
//!   C. the templates the sandbox holds readable (`DOTENV_TEMPLATES`): `.env.example` and its case variants ENTER,
//!      so the exclusion is not a blanket dotfile or a blanket `up/` ban.
//!   D. links: a link whose own path looks secret is not entered at all; a link whose path does not look secret is
//!      entered as its TARGET TEXT (mode 120000), never followed, so the file behind it never reaches the objects.
//!
//! Every file's body is unique to it, so "the body is not in the objects" is a statement about that file alone.
//!
//! WHAT THIS FILE CANNOT ROW (named so the next reader does not look for it):
//!   - A TRACKED path whose path looks secret: the tracked loop is H13's, which withholds it from the report, not from
//!     the tree; the amendment is scoped to untracked paths and the coordinator's property says so.
//!   - A hardlink to a credentials file: its path is ordinary, so the name cannot show it and the tree gets the body.
//!     facts.rs names this too ("a hardlink to a hidden dotenv file is [a secret], which a name cannot show"): it is
//!     the call's facts (`sandbox::root_top_secrets`), not this filter.
//!   - A rename between the listing and the hash: `hash_files` re-hashes from a descriptor when the lstat moved, but a
//!     body whose PATH becomes ordinary between `ls-files` and the hash enters under that path. The filter is a
//!     decision on names read once; no deterministic row can pin the window, and the window is the writer's own.
//!   - A unicode look-alike: the matcher folds case by `to_lowercase` and matches exact names, so at 31d2f8dd it answers
//!     true for `.ENV` and false for `.ｅｎｖ` (fullwidth) and `idеd25519` (Cyrillic е); the property is stated only for
//!     paths it matches, so those shapes are the width of the name rule, not a hole in this filter. Measured, not rowed.
//!   - A path a listing emits outside the work tree's relative form (a `/`-prefixed or `./` path): `ls-files` emits
//!     root-relative names, so the filter never sees one; measured at 31d2f8dd, `looks_secret` is still true for
//!     `notes/../.env`, so the name rule alone would not rescue a listing that went wrong.
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::Command;

use window_ml_host::facts::looks_secret;
use window_ml_host::gitconfig::RepoConfig;
use window_ml_host::gitfacts::Git;
use window_ml_host::snapshot::Scratch;

fn have_git() -> bool {
    Command::new("git").arg("--version").output().is_ok()
}

/// The `-c` flags every fixture git command carries; the last two stop git 2.56's detached `maintenance run --auto`,
/// which would touch `.git` behind the row's back (src/snapshot.rs's own fixture says why).
const GIT_FIXTURE: [&str; 10] = [
    "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false", "-c", "maintenance.auto=false", "-c", "gc.auto=0",
];

fn run(dir: &Path, args: &[&str]) -> String {
    let mut v: Vec<&str> = GIT_FIXTURE.to_vec();
    v.extend_from_slice(args);
    let out = Command::new("git").args(&v).current_dir(dir).env("GIT_CONFIG_NOSYSTEM", "1").env("GIT_CONFIG_GLOBAL", "/dev/null").output().unwrap();
    assert!(out.status.success(), "git {args:?} in {}: {}", dir.display(), String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// A repository with one commit over two files, and the downloads folder `up/` IGNORED, so its contents reach the host
/// only through the uploads listing (the one without `--exclude-standard`).
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
    std::fs::write(root.join(".gitignore"), "up/\n").unwrap();
    std::fs::create_dir_all(root.join("up")).unwrap();
    // Mtimes a minute back and the index refreshed, so no tracked entry is racily clean: this row is not about that.
    let past = std::time::SystemTime::now() - std::time::Duration::from_secs(60);
    for p in ["a.txt", "sub/b.txt"] {
        std::fs::File::options().write(true).open(root.join(p)).unwrap().set_modified(past).unwrap();
    }
    run(&root, &["-c", "core.fsmonitor=false", "update-index", "--refresh"]);
    (t, root)
}

fn inspect(root: &Path) -> RepoConfig {
    window_ml_host::gitconfig::inspect(root).unwrap()
}

fn git_on_path() -> Git {
    Git::on(&std::env::split_paths(&std::env::var_os("PATH").unwrap()).collect::<Vec<_>>())
}

/// The scratch tree as `mode oid path` lines.
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

/// What one row writes and then asserts about: the path, its body (unique to it), the mode it would enter with, and
/// whether the tree must hold it.
struct Shape {
    path: &'static str,
    body: String,
    mode: &'static str,
}

/// Makes every body unique to its path, so an absence really is about this file.
fn shapes(paths: &[&'static str], mode: &'static str) -> Vec<Shape> {
    paths.iter().map(|p| Shape { path: p, body: format!("BODY-FOR {p}\n"), mode }).collect()
}

/// Writes each shape under `root` (parents created), then asserts: the path is one `looks_secret` matches, the tree has
/// no entry at it, and its own body is not in the private object store.
fn assert_excluded(s: &Scratch, g: &Git, r: &RepoConfig, tree: &[String], got: &[Shape]) {
    for shape in got {
        assert!(looks_secret(Path::new(shape.path)), "{} must be a shape the matcher catches", shape.path);
        assert!(!tree.iter().any(|l| l.ends_with(&format!(" {}", shape.path))), "{} is in the tree: {tree:?}", shape.path);
        let oid = blob_of(&r.root, shape.body.as_bytes());
        assert!(!tree.iter().any(|l| l.split(' ').nth(1) == Some(&oid)), "{}'s body is in the tree under another path", shape.path);
        let (code, _) = s.git(g, r, &["cat-file", "-e", &oid]).unwrap();
        assert_ne!(code, 0, "{}'s body is in the private objects", shape.path);
    }
}

/// The other half every row needs: an ordinary file beside the excluded ones IS entered, so the tree is not empty and
/// the listing really ran.
fn assert_entered(root: &Path, tree: &[String], got: &[Shape]) {
    for shape in got {
        let oid = blob_of(root, shape.body.as_bytes());
        let want = format!("{} {oid} {}", shape.mode, shape.path);
        assert!(tree.contains(&want), "{} did not enter the tree: {tree:?}", shape.path);
    }
}

fn write(root: &Path, got: &[Shape]) {
    for shape in got {
        let p = root.join(shape.path);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, &shape.body).unwrap();
    }
}

fn snapshot(root: &Path, t: &tempfile::TempDir) -> (Git, RepoConfig, Scratch, Vec<String>) {
    let (g, r) = (git_on_path(), inspect(root));
    let s = Scratch::new(&g, &r, &t.path().join("host")).unwrap();
    s.enter_changes(&g, &r, Some(&root.join("up"))).unwrap();
    let tree = scratch_tree(&s, &g, &r);
    (g, r, s, tree)
}

// --- A: the first listing, outside the uploads folder ---

#[test]
fn an_untracked_secret_looking_path_outside_the_uploads_folder_enters_neither_tree() {
    if !have_git() {
        return;
    }
    let (t, root) = repo();
    // One shape per rule the matcher applies, each also in the case a writer would choose: the exact names, the `id_`
    // prefix, the suffixes, a credentials directory, the `.config/{gcloud,gh}` pair, and a secret name below an
    // ordinary directory. A case variant lives under its own directory, since this row runs on a case-insensitive
    // file system too (macOS), where `.ENV` beside `.env` would be one file and half the table would vanish.
    let secrets = shapes(
        &[
            ".env",
            "notes-case/.ENV",
            ".env.production",
            "credentials",
            "notes-case/CREDENTIALS",
            "ID_ED25519",
            "server.pem",
            "notes-case/SERVER.PEM",
            "dump.gpg",
            ".aws/credentials",
            "KEYCHAINS/login",
            ".config/gcloud/legacy_credentials/x",
            "sub/.netrc",
            "notes/hosts.yml",
        ],
        "100644",
    );
    let ordinary = shapes(&["notes.txt", "data.csv", "sub/report.md"], "100644");
    write(&root, &secrets);
    write(&root, &ordinary);
    let (g, r, s, tree) = snapshot(&root, &t);
    assert_excluded(&s, &g, &r, &tree, &secrets);
    assert_entered(&r.root, &tree, &ordinary);
}

// --- B: the second listing, the uploads folder (ignored, so only this listing sees it) ---

#[test]
fn an_untracked_secret_looking_path_inside_the_uploads_folder_enters_neither_tree_either() {
    if !have_git() {
        return;
    }
    let (t, root) = repo();
    let secrets = shapes(
        &[
            "up/.aws/credentials",
            "up/SERVER.PEM",
            "up/vault.kdbx",
            "up/.config/gh/hosts.yml",
            "up/.gnupg/pubring.kbx",
            "up/deep/.ssh/id_rsa",
        ],
        "100644",
    );
    let ordinary = shapes(&["up/report.csv", "up/deep/notes.txt"], "100644");
    write(&root, &secrets);
    write(&root, &ordinary);
    let (g, r, s, tree) = snapshot(&root, &t);
    // The control that this section is about the second listing at all: the ignored folder's ordinary files are there
    // even though `--exclude-standard` alone would never have listed them.
    assert_excluded(&s, &g, &r, &tree, &secrets);
    assert_entered(&r.root, &tree, &ordinary);
}

// --- C: the templates, which the sandbox holds readable by name ---

#[test]
fn the_dotenv_templates_enter_so_the_exclusion_is_the_matchers_and_not_a_blanket_dotfile_ban() {
    if !have_git() {
        return;
    }
    let (t, root) = repo();
    let templates = shapes(&[".env.example", "templates-case/.ENV.EXAMPLE", "up/.env.sample", "up/.env.template"], "100644");
    let neighbours = shapes(&[".env", ".env.local", "up/.env"], "100644");
    write(&root, &templates);
    write(&root, &neighbours);
    let (g, r, s, tree) = snapshot(&root, &t);
    for shape in &templates {
        assert!(!looks_secret(Path::new(shape.path)), "{} is a template the sandbox holds readable", shape.path);
    }
    assert_entered(&r.root, &tree, &templates);
    assert_excluded(&s, &g, &r, &tree, &neighbours);
}

// --- D: links ---

#[test]
fn a_link_is_skipped_by_its_own_path_and_entered_as_its_target_text_never_followed() {
    if !have_git() {
        return;
    }
    let (t, root) = repo();
    // A file outside the repository: its body must never reach the objects, whatever points at it.
    let outside = t.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("id_ed25519"), "OUTSIDE KEY BODY\n").unwrap();
    std::fs::write(root.join(".env"), "TRACKED-STYLE SECRET\n").unwrap();
    // A link whose own path looks secret, to a real directory and to a real file: neither is entered, nor followed.
    std::fs::create_dir_all(root.join("up/.aws")).unwrap();
    symlink(&outside, root.join("up/.ssh")).unwrap();
    symlink(root.join(".env"), root.join("up/.env")).unwrap();
    symlink(&outside.join("id_ed25519"), root.join("up/.netrc")).unwrap();
    // A link whose path is ordinary: entered as the target TEXT, mode 120000, and the target is never read.
    symlink(&outside.join("id_ed25519"), root.join("up/notes.txt")).unwrap();
    let (g, r, s, tree) = snapshot(&root, &t);
    for path in ["up/.ssh", "up/.env", "up/.netrc"] {
        assert!(looks_secret(Path::new(path)), "{path} must be a shape the matcher catches");
        assert!(!tree.iter().any(|l| l.ends_with(&format!(" {path}"))), "{path} is in the tree: {tree:?}");
    }
    let target = b"OUTSIDE KEY BODY\n";
    let (code, _) = s.git(&g, &r, &["cat-file", "-e", &blob_of(&r.root, target)]).unwrap();
    assert_ne!(code, 0, "the link's target body is in the private objects: a link was followed");
    let link_oid = blob_of(&r.root, outside.join("id_ed25519").to_string_lossy().as_bytes());
    assert!(tree.contains(&format!("120000 {link_oid} up/notes.txt")), "the ordinary link is not entered as its target text: {tree:?}");
}
