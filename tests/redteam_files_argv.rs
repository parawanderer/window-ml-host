//! redteam_files_argv.rs — `/files` in a `spawn`, from the HOST's side (window-ml FILE_ATTACHMENTS.md H9, as built).
//! The lane's own rows in mounts.rs drive the shapes it thought of; these state what a call must NOT be able to do, each
//! over the guard that decides it, and are meant to fail when that guard is weakened rather than to re-walk the happy
//! path:
//!
//!   A. an escaping or ambiguous `/files` token is refused AS WRITTEN, and the call goes with it: no sibling argument
//!      is mapped or run, and the refusal quotes the token, never the folder's real path.
//!   B. `attached/` is judged on where a write LANDS, by every name that reaches it: a symlink under the uploads
//!      folder into `attached/` writes nowhere, and a symlink inside `attached/` pointing out is refused as a NAME (the
//!      link sits in attached/) while a write THROUGH it lands outside and runs.
//!   C. a recursive write (`walk`) is refused only where `attached/` lies beneath the path: the same `/files/` is
//!      InAttached with `walk` and runs without it.
//!   D. the retry the refusal teaches (`mv notes.txt /files/notes.txt`) passes the same check, and a write that names a
//!      file in the uploads folder is not refused with `attached/`: the rule is `attached/`, not the uploads folder.
//!   E. `spawn.files` names a MOUNT, never a folder: `/files` is the mount's own uploads rel whatever else the call
//!      puts in `files`, and another mount of the same session maps by its own rel.
//!   F. what the mapping does not touch reaches the program as written: an argument the worker did not mark as a path
//!      (a pattern, even `/files/../x`) and an env value. The host holds no description of the call, so scanning
//!      either would be it inventing a path (a stated trust: the worker's refusal is the check).
//!   G. the same folder by the SYSTEM's own other name — macOS's `/System/Volumes/Data` firmlink, which `realpath`
//!      does not fold — is refused for a write into `attached/` and allowed beside it. This is the only row that reds
//!      the device-and-inode half of the rule alone: by name alone the alias matches nothing.
//!
//! MUTATION PER ROW, MEASURED AT 784af69 (notes, not committed changes — one applied alone, this file run, the source
//! reverted with `git checkout -- src/`; it was clean 8/8 before and after):
//!   A  src/session.rs `files_to`: `mounts::rel_parts(inner, true)…?` → `let _ = mounts::rel_parts(inner, true);` →
//!      A red: `/files/../out.txt` is accepted and spawns.
//!   B1 src/mounts.rs `holds_in_attached`: both clauses removed (→ `false`) → B1, B2 and G red. NEITHER ALONE IS ENOUGH,
//!      and that is what to keep: with the name check gone (inode walk kept) all 8 stay GREEN, because `resolve_path`
//!      canonicalizes first and Rust's `canonicalize` folds a symlink AND a case variant (it answers the on-disk
//!      spelling). With the inode walk gone (name check kept) only G reds, so the lane's `Attached` row is not a second
//!      row for the walk: G is where the walk is load-bearing.
//!   B2 src/session.rs `refuse_written_attached`: `for k in ["path", "link"]` → `["path"]` → B2 red: the `rm` of a
//!      symlink sitting in `attached/` whose target is outside runs.
//!   C  src/mounts.rs `attached_beneath` → `false` → C red (and D, which needs a refusal to teach from); and the flag
//!      ignored (`let walked = true;`) → C and D red on the destinations that run without it.
//!   D  src/mounts.rs `holds_in_attached`: the name check widened from `…/attached` to the uploads folder → D red (and
//!      B1's read half): a plain `cp /x /files/` is refused, which the spec says would break the first two use cases.
//!   E  src/session.rs `map_files`: `let dir = m.path.clone();` after `uploads_dir()?` → E red: `/files` maps to the
//!      mount's root.
//!   F  src/session.rs `map_files`: the `pathArgs` loop replaced by every index in `1..argv.len()` → F red (the pattern
//!      `/files/../x` is refused, and no mapping reaches argv); and env values pushed into `files` → F red on the env
//!      assertion (the spawn is refused by the env value alone).
//!   G  measured with B1 above; it is the row the inode walk exists for.
//!
//! WHAT THIS FILE CANNOT ROW (named so the next reader does not look for it):
//!   - `attached_beneath` (C) is compared by NAME only, and the `role: "write"` loop (B) and `holds_in_attached` are
//!     per existing ancestor. Two canonical names for one directory need a bind mount or a firmlink; G uses the one
//!     this platform has. A row for `attached_beneath` by dev/ino has no shape to make: the path it compares is the
//!     mapping's realpath, so an alias of the folder holding `attached/` cannot be built unprivileged.
//!   - An OLD host (H15) is not a shape this binary can be: `hello.filesArgv` is one expression, and the connection it
//!     is false for (the hub's) cannot hold a mount at all. That half of H15 is the worker's `hostMapsFiles` gate.
//!   - `mv notes.txt /files/notes.txt` is shown to pass the SPAWN check, not run: this harness reads facts and never
//!     starts a call.
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{Value, json};

/// A refusal as the host sent it.
type Refused = Value;

struct Host {
    _state: tempfile::TempDir,
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: ChildStdout,
    seq: u64,
}

impl Host {
    fn start(home: &Path) -> Host {
        let state = tempfile::tempdir().unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_wmlhost"))
            .env("WMLHOST_STATE_DIR", state.path().join("owners"))
            .env("HOME", home)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .arg("chrome-extension://abcdefghijklmnopabcdefghijklmnop/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("wmlhost starts");
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        Host { _state: state, child, stdin, stdout, seq: 0 }
    }

    fn recv(&mut self) -> Value {
        let mut len = [0u8; 4];
        self.stdout.read_exact(&mut len).expect("a frame from the host");
        let mut b = vec![0u8; u32::from_ne_bytes(len) as usize];
        self.stdout.read_exact(&mut b).unwrap();
        serde_json::from_slice(&b).unwrap()
    }

    /// One call: the value, or the whole error object.
    fn raw(&mut self, name: &str, args: Value) -> Result<Value, Refused> {
        self.seq += 1;
        let seq = self.seq;
        let b = serde_json::to_vec(&json!({ "seq": seq, "call": name, "args": args })).unwrap();
        let w = self.stdin.as_mut().unwrap();
        w.write_all(&(b.len() as u32).to_ne_bytes()).unwrap();
        w.write_all(&b).unwrap();
        w.flush().unwrap();
        loop {
            let m = self.recv();
            if m.get("event").is_some() {
                continue;
            }
            assert_eq!(m["seq"], json!(seq));
            return match m.get("error") {
                Some(e) => Err(e.clone()),
                None => Ok(m["value"].clone()),
            };
        }
    }

    fn ok(&mut self, name: &str, args: Value) -> Value {
        self.raw(name, args).unwrap_or_else(|e| panic!("{name} failed: {e}"))
    }

    /// The error code of a call that must be refused.
    fn code(&mut self, name: &str, args: Value) -> String {
        match self.raw(name, args) {
            Ok(v) => panic!("{name} should have been refused, got {v}"),
            Err(e) => e["code"].as_str().unwrap().to_string(),
        }
    }

    fn close(mut self) {
        drop(self.stdin.take());
        let _ = self.child.wait();
    }
}

/// A host configured with one root, and a project directory inside it (the root's real path, mounts being compared by
/// realpath). The temporary directories live under the build's own temp directory: `tempdir()` is `/tmp` on Linux,
/// which `mount` refuses as reserved.
struct Env {
    _tmp: tempfile::TempDir,
    _home: tempfile::TempDir,
    proj: PathBuf,
    h: Host,
}

fn tmp() -> (tempfile::TempDir, PathBuf) {
    let d = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let p = d.path().canonicalize().unwrap();
    (d, p)
}

impl Env {
    fn new() -> Env {
        let (dir, root) = tmp();
        let (home, home_p) = tmp();
        let proj = root.join("proj");
        std::fs::create_dir(&proj).unwrap();
        let mut h = Host::start(&home_p);
        h.ok("configure", json!({ "roots": [root], "sandbox": false }));
        Env { _tmp: dir, _home: home, proj, h }
    }

    fn mount_at(&mut self, p: &Path, uploads: Option<&str>) -> String {
        let mut a = json!({ "session": "s1", "path": p, "mode": "rw" });
        if let Some(u) = uploads {
            a["uploads"] = json!(u);
        }
        self.h.ok("mount", a)["id"].as_str().unwrap().to_string()
    }
}

fn code_of(e: &Refused) -> &str {
    e["code"].as_str().unwrap()
}

/// Whether `msg` names `word` as a WORD, trimmed of the punctuation a sentence puts around a command: a retry sentence
/// names the program it teaches as a word, and a substring test would match it inside a path (`/files/cp`).
fn says(msg: &str, word: &str) -> bool {
    msg.split_whitespace().any(|t| t.trim_matches(|c: char| !c.is_alphanumeric() && c != '-') == word)
}

/// A spawn of `argv` in the project with `pathArgs`, naming the mount `m` as `/files` when `files` is set.
fn spawn_args(e: &Env, m: &str, argv: &[&str], path_args: Value, files: bool) -> Value {
    let mut a = json!({ "argv": argv, "cwd": e.proj, "pathArgs": path_args });
    if files {
        a["files"] = json!({ "mount": m, "session": "s1" });
    }
    a
}

/// A mounted project whose uploads folder holds `attached/in.txt` and `out.txt`.
fn uploads_env() -> (Env, String) {
    let mut e = Env::new();
    std::fs::create_dir_all(e.proj.join("window-ml-files/attached")).unwrap();
    std::fs::write(e.proj.join("window-ml-files/attached/in.txt"), "given").unwrap();
    std::fs::write(e.proj.join("window-ml-files/out.txt"), "mine").unwrap();
    let p = e.proj.clone();
    let m = e.mount_at(&p, Some("window-ml-files"));
    (e, m)
}

fn folder(e: &Env) -> String {
    e.proj.join("window-ml-files").to_string_lossy().into_owned()
}

// --- A. an escaping or ambiguous token is refused as written, and the call with it ---

#[test]
fn redteam_an_escaping_or_ambiguous_files_token_is_refused_as_written_and_nothing_of_the_call_is_mapped() {
    let (mut e, m) = uploads_env();
    let real = folder(&e);
    for token in [
        "/files/../out.txt",
        "/files//x",
        "/files/./attached",
        "/files/attached/../out.txt",
        "/files/...",
        "/files/a/../../out.txt",
    ] {
        // argv[1] is a good token and argv[2] the bad one: one bad token takes the call, so argv[1] is never mapped.
        let a = spawn_args(
            &e,
            &m,
            &["/bin/cp", "/files/out.txt", token],
            json!([{ "arg": 1 }, { "arg": 2, "role": "write" }]),
            true,
        );
        let r = e.h.raw("spawn", a).unwrap_err();
        assert_eq!(code_of(&r), "BadRequest", "{token}: {r}");
        let msg = r["message"].as_str().unwrap();
        assert!(msg.starts_with(&format!("{token}: ")), "{token}: the refusal does not quote the token: {msg}");
        assert!(!msg.contains(&real), "{token}: the refusal gave the folder's real path away: {msg}");
    }
    // The cwd is mapped by the same rule and refused by it, with the same wording.
    for cwd in ["/files/../x", "/files//attached", "/files/./attached"] {
        let mut a = spawn_args(&e, &m, &["/bin/cat", "/files/out.txt"], json!([{ "arg": 1 }]), true);
        a["cwd"] = json!(cwd);
        let r = e.h.raw("spawn", a).unwrap_err();
        assert_eq!(code_of(&r), "BadRequest", "cwd {cwd}");
        assert!(r["message"].as_str().unwrap().starts_with(&format!("{cwd}: ")), "cwd {cwd}: {r}");
    }
    // And the marks themselves are not a path: `/files` maps, `/files/` maps with its slash, `/filesystem` does not.
    for (token, mapped) in [("/files/x", true), ("/files", true), ("/files/", true), ("/filesystem/x", false)] {
        let a = spawn_args(&e, &m, &["/bin/cat", token], json!([{ "arg": 1 }]), true);
        let f = e.h.ok("spawn", a);
        assert_eq!(f["argv"][1] != json!(token), mapped, "{token}: {f}");
    }
    e.h.close();
}

// --- B. attached/ is judged by where a write lands, by every name ---

#[test]
fn redteam_a_write_through_a_symlink_into_attached_is_refused_and_a_read_of_the_same_name_is_not() {
    let (mut e, m) = uploads_env();
    let files = e.proj.join("window-ml-files");
    symlink("attached", files.join("link")).unwrap();
    std::fs::create_dir(files.join("sub")).unwrap();
    symlink("../attached", files.join("sub/up")).unwrap();
    let names = ["/files/link/new.txt", "/files/link/in.txt", "/files/sub/up/new.txt", "/files/sub/up/in.txt"];
    for token in names {
        let a =
            spawn_args(&e, &m, &["/bin/cp", "/x", token], json!([{ "arg": 1 }, { "arg": 2, "role": "write" }]), true);
        let r = e.h.raw("spawn", a).unwrap_err();
        assert_eq!(code_of(&r), "InAttached", "{token}: a write through a symlink into attached/");
        assert!(
            r["message"].as_str().unwrap().starts_with(token),
            "{token}: the refusal names something other than the path as written: {r}"
        );
    }
    // The same names, read: the rule is about writes, and a copy OUT of attached/ is the commonest call there is.
    for token in names {
        let a = spawn_args(&e, &m, &["/bin/cat", token], json!([{ "arg": 1 }]), true);
        assert!(e.h.raw("spawn", a).is_ok(), "a read of {token}");
    }
    // A recursive read is a read too: the walk flag alone refuses nothing.
    let a = spawn_args(
        &e,
        &m,
        &["/bin/cp", "-R", "/files/link", "/files/copy"],
        json!([{ "arg": 2, "walk": true }, { "arg": 3, "role": "write" }]),
        true,
    );
    assert!(e.h.raw("spawn", a).is_ok(), "a recursive read through the link");
    e.h.close();
}

#[test]
fn redteam_a_symlink_in_attached_is_a_write_on_the_link_itself_and_a_write_through_it_lands_outside() {
    let (mut e, m) = uploads_env();
    let files = e.proj.join("window-ml-files");
    std::fs::create_dir(e.proj.join("outside")).unwrap();
    symlink(e.proj.join("outside"), files.join("attached/esc")).unwrap();
    let outside = e.proj.join("outside").to_string_lossy().into_owned();
    // The link sits in attached/: removing or renaming it is a write there, whatever it points at.
    let a = spawn_args(&e, &m, &["/bin/rm", "/files/attached/esc"], json!([{ "arg": 1, "role": "write" }]), true);
    let r = e.h.raw("spawn", a).unwrap_err();
    assert_eq!(code_of(&r), "InAttached", "the link's own place");
    // Writing THROUGH it lands in outside/, no part of attached/: allowed, and the facts are of where it lands.
    let a = spawn_args(
        &e,
        &m,
        &["/bin/cp", "/x", "/files/attached/esc/new.txt"],
        json!([{ "arg": 1 }, { "arg": 2, "role": "write" }]),
        true,
    );
    let f = e.h.ok("spawn", a);
    assert_eq!(f["paths"][1]["path"], json!(format!("{outside}/new.txt")), "{f}");
    // Control: the target by its own name acts the same way, so it is the LINK's place that decided the refusal.
    let a = spawn_args(
        &e,
        &m,
        &["/bin/rm", format!("{outside}/new.txt").as_str()],
        json!([{ "arg": 1, "role": "write" }]),
        true,
    );
    assert!(e.h.raw("spawn", a).is_ok(), "the target by its own name");
    e.h.close();
}

// --- C. a recursive write only where attached/ lies beneath ---

#[test]
fn redteam_a_recursive_write_is_refused_only_where_attached_lies_beneath_the_path() {
    let (mut e, m) = uploads_env();
    std::fs::create_dir_all(e.proj.join("window-ml-files/sub")).unwrap();
    // cp -R with attached/ as the source's child into /files/: the write merges into attached/ without naming it.
    let a = spawn_args(
        &e,
        &m,
        &["/bin/cp", "-R", "/x/attached", "/files/"],
        json!([{ "arg": 2, "walk": true }, { "arg": 3, "role": "write", "walk": true }]),
        true,
    );
    let r = e.h.raw("spawn", a).unwrap_err();
    assert_eq!(code_of(&r), "InAttached");
    // The retry the sentence teaches is the CALL's own: built from the path alone it taught `mv notes.txt …` to a
    // `cp -R` call (janitor-2's finding on host#43), which is not that call's retry at all.
    let msg = r["message"].as_str().unwrap();
    assert!(msg.contains("/files"), "the path as the call wrote it: {msg}");
    assert!(says(msg, "cp"), "the retry names no `cp` for a cp call: {msg}");
    assert!(!says(msg, "mv"), "a cp call is taught an mv retry: {msg}");
    // The uploads folder itself, recursively.
    let a =
        spawn_args(&e, &m, &["/bin/rm", "-r", "/files"], json!([{ "arg": 2, "role": "write", "walk": true }]), true);
    let r = e.h.raw("spawn", a).unwrap_err();
    assert_eq!(code_of(&r), "InAttached", "rm -r of the folder that holds attached/");
    let msg = r["message"].as_str().unwrap();
    assert!(says(msg, "rm"), "the retry names no `rm` for an rm call: {msg}");
    assert!(!says(msg, "mv"), "an rm call is taught an mv retry: {msg}");
    // The same folder by its real path, from further up: the mount's root holds attached/ too.
    let proj = e.proj.to_string_lossy().into_owned();
    let a = spawn_args(&e, &m, &["/bin/rm", "-r", &proj], json!([{ "arg": 2, "role": "write", "walk": true }]), false);
    assert_eq!(e.h.code("spawn", a), "InAttached", "the mount's root, by its own name");
    // And without walk, the same two destinations run: the flag is the decision, not the path.
    let a =
        spawn_args(&e, &m, &["/bin/cp", "/x", "/files/"], json!([{ "arg": 1 }, { "arg": 2, "role": "write" }]), true);
    assert!(e.h.raw("spawn", a).is_ok(), "a plain copy into the folder makes one name beside attached/");
    let a = spawn_args(
        &e,
        &m,
        &["/bin/rm", "-r", "/files/sub"],
        json!([{ "arg": 2, "role": "write", "walk": true }]),
        true,
    );
    assert!(e.h.raw("spawn", a).is_ok(), "a folder beside attached/ holds nothing of it");
    e.h.close();
}

// --- D. the retry the refusal teaches passes the same check ---

#[test]
fn redteam_the_retry_the_refusal_teaches_passes_and_the_rule_is_attached_not_the_uploads_folder() {
    let (mut e, m) = uploads_env();
    let a = spawn_args(
        &e,
        &m,
        &["/bin/mv", "notes.txt", "/files/"],
        json!([{ "arg": 1, "role": "write", "walk": true }, { "arg": 2, "role": "write", "walk": true }]),
        true,
    );
    let r = e.h.raw("spawn", a).unwrap_err();
    assert_eq!(code_of(&r), "InAttached");
    let msg = r["message"].as_str().unwrap().to_string();
    assert!(msg.contains("as in mv notes.txt /files/notes.txt"), "{msg}");
    // The retry, as the sentence spells it: the last operand is one name in the folder, not the folder.
    let a = spawn_args(
        &e,
        &m,
        &["/bin/mv", "notes.txt", "/files/notes.txt"],
        json!([{ "arg": 1, "role": "write" }, { "arg": 2, "role": "write" }]),
        true,
    );
    let f = e.h.ok("spawn", a);
    assert_eq!(f["argv"][2], json!(format!("{}/notes.txt", folder(&e))), "{f}");
    // Every write that NAMES something runs, the folder itself included: only attached/ is refused, and only a walk.
    for token in ["/files/notes.txt", "/files/sub/notes.txt", "/files/"] {
        let a =
            spawn_args(&e, &m, &["/bin/cp", "/x", token], json!([{ "arg": 1 }, { "arg": 2, "role": "write" }]), true);
        assert!(e.h.raw("spawn", a).is_ok(), "{token} without walk: the rule is attached/, not the uploads folder");
    }
    e.h.close();
}

// --- E. `files` names a mount, and the folder is that mount's own uploads rel ---

#[test]
fn redteam_files_names_a_mount_and_the_folder_is_that_mounts_uploads_rel_whatever_else_the_call_says() {
    let mut e = Env::new();
    for dir in ["one", "two"] {
        std::fs::create_dir_all(e.proj.join(dir).join(format!("files-{dir}/attached"))).unwrap();
    }
    let (p1, p2) = (e.proj.join("one"), e.proj.join("two"));
    let m1 = e.mount_at(&p1, Some("files-one"));
    let m2 = e.mount_at(&p2, Some("files-two"));
    let one = e.proj.join("one/files-one").to_string_lossy().into_owned();
    let two = e.proj.join("two/files-two").to_string_lossy().into_owned();
    // Extra keys naming another folder (or an absolute one) move nothing: the folder is the mount's own.
    let mut a = spawn_args(&e, &m1, &["/bin/cat", "/files/x.txt"], json!([{ "arg": 1 }]), true);
    a["files"] = json!({ "mount": m1, "session": "s1", "uploads": "files-two", "dir": "/etc", "to": two });
    let f = e.h.ok("spawn", a);
    assert_eq!(
        f["argv"][1],
        json!(format!("{one}/x.txt")),
        "the named mount's uploads rel, not a folder the call named"
    );
    // The other mount maps by ITS rel: which folder /files is comes from the mount, and from nothing else.
    let mut a = spawn_args(&e, &m1, &["/bin/cat", "/files/x.txt"], json!([{ "arg": 1 }]), true);
    a["files"] = json!({ "mount": m2, "session": "s1" });
    let f = e.h.ok("spawn", a);
    assert_eq!(f["argv"][1], json!(format!("{two}/x.txt")));
    // The uploads folder's own name is not a shortcut: a mount with no attached/ found has no uploads folder at all.
    let plain = e.proj.join("plain");
    std::fs::create_dir(&plain).unwrap();
    let mp = e.mount_at(&plain, None);
    let a = spawn_args(&e, &mp, &["/bin/cat", "/files/x.txt"], json!([{ "arg": 1 }]), true);
    assert_eq!(e.h.code("spawn", a), "BadRequest", "a mount with no uploads folder");
    e.h.close();
}

// --- F. an unmarked argument and an env value reach the program as written ---

#[test]
fn redteam_an_argument_the_worker_did_not_mark_as_a_path_and_an_env_value_are_never_mapped_or_refused() {
    let (mut e, m) = uploads_env();
    // argv[1] is a pattern: even an escaping token is the program's text, not a path to refuse or to rewrite.
    let a = spawn_args(&e, &m, &["/bin/cat", "/files/../x", "/files/out.txt"], json!([{ "arg": 2 }]), true);
    let f = e.h.ok("spawn", a);
    assert_eq!(f["argv"][1], json!("/files/../x"), "an argument the worker did not mark was rewritten or refused: {f}");
    assert_eq!(f["files"].as_array().unwrap().len(), 1, "only the marked argument was mapped: {f}");
    // An env value is not an argument: not mapped, not refused, and the fact says the key is there.
    let mut a = spawn_args(&e, &m, &["/bin/cat", "/files/out.txt"], json!([{ "arg": 1 }]), true);
    a["env"] = json!({ "MY_DIR": "/files/../x" });
    let f = e.h.ok("spawn", a);
    assert_eq!(f["env"]["set"], json!(["MY_DIR"]), "{f}");
    assert_eq!(
        f["files"],
        json!([{ "index": 1, "from": "/files/out.txt", "to": format!("{}/out.txt", folder(&e)) }]),
        "an env value was mapped: {f}"
    );
    e.h.close();
}

// --- G. the same folder by the system's own other name ---

#[test]
fn redteam_a_write_into_attached_by_the_systems_other_name_for_the_folder_is_refused_and_beside_it_is_not() {
    let (mut e, m) = uploads_env();
    let files = e.proj.join("window-ml-files");
    // macOS's Data volume is a firmlink, not a symlink: `realpath` keeps the `/System/Volumes/Data` spelling, and the
    // directory is the same one by device and inode. Where there is no such name, the row says so and stops.
    let Some(alias) = macos_firmlink(&files) else {
        eprintln!(
            "no /System/Volumes/Data name for {} on this machine: the by-inode half is not checked",
            files.display()
        );
        e.h.close();
        return;
    };
    let (a, b) = (std::fs::metadata(&files).unwrap(), std::fs::metadata(&alias).unwrap());
    assert_eq!((a.dev(), a.ino()), (b.dev(), b.ino()), "control: the other name is not the uploads folder");
    assert!(!alias.starts_with(&files), "control: the other name is not a name the rule already matches");
    // A write into its attached/ is a write into attached/, by no name the rule compares.
    let into = alias.join("attached/new.txt").to_string_lossy().into_owned();
    let a = spawn_args(&e, &m, &["/bin/cp", "/x", &into], json!([{ "arg": 1 }, { "arg": 2, "role": "write" }]), false);
    let r = e.h.raw("spawn", a).unwrap_err();
    assert_eq!(code_of(&r), "InAttached", "attached/ by the same folder's other name");
    assert_eq!(
        r["message"],
        json!(format!(
            "{into} is in attached/, which holds the uploads as they were given: copy out of it, never into it"
        ))
    );
    // And beside attached/, by the same name, runs: the alias alone is not what is refused.
    let beside = alias.join("fine.txt").to_string_lossy().into_owned();
    let a =
        spawn_args(&e, &m, &["/bin/cp", "/x", &beside], json!([{ "arg": 1 }, { "arg": 2, "role": "write" }]), false);
    assert!(e.h.raw("spawn", a).is_ok(), "a write beside attached/ by the same name");
    e.h.close();
}

/// `/System/Volumes/Data` + `p` on macOS, when it names the same directory; `None` anywhere else.
fn macos_firmlink(p: &Path) -> Option<PathBuf> {
    let rest = p.strip_prefix("/").ok()?;
    let alias = Path::new("/System/Volumes/Data").join(rest);
    let (a, b) = (std::fs::metadata(p).ok()?, std::fs::metadata(&alias).ok()?);
    ((a.dev(), a.ino()) == (b.dev(), b.ino())).then_some(alias)
}
