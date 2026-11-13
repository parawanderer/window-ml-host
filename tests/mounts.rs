//! mounts.rs — drives the built `wmlhost` binary over native messaging framing through the mount calls (`mount`,
//! `stat`, `list`, `fetch`, `store`, `remove`, `rename`): what a mount refuses, the path rule, the basis a read and a
//! write compare, the uploads folder's `attached/`, and the git facts.

use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use base64::Engine;
use serde_json::{Value, json};

/// A refusal as the host sent it, `size` and `cap` of an `EFBIG` included.
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
/// realpath). The mounts live under the build's own temp directory: `tempdir()` is `/tmp` on Linux, which `mount`
/// refuses as reserved.
struct Env {
    _tmp: tempfile::TempDir,
    _home: tempfile::TempDir,
    root: PathBuf,
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
        let (tmp, root) = tmp();
        let (home, home_p) = tmp_home();
        let proj = root.join("proj");
        std::fs::create_dir(&proj).unwrap();
        let mut h = Host::start(&home_p);
        h.ok("configure", json!({ "roots": [root], "sandbox": false }));
        Env { _tmp: tmp, _home: home, root, proj, h }
    }

    /// Mounts the project read-write for session `s`; the mount's id.
    fn mount(&mut self, s: &str) -> String {
        let p = self.proj.clone();
        self.mount_at(s, &p, "rw", None)
    }

    fn mount_at(&mut self, s: &str, p: &Path, mode: &str, uploads: Option<&str>) -> String {
        let mut a = json!({ "session": s, "path": p, "mode": mode });
        if let Some(u) = uploads {
            a["uploads"] = json!(u);
        }
        self.h.ok("mount", a)["id"].as_str().unwrap().to_string()
    }

    fn stat(&mut self, m: &str, path: &str) -> Value {
        self.h.ok("stat", json!({ "mount": m, "session": "s1", "path": path }))
    }

    fn basis(&mut self, m: &str, path: &str) -> Value {
        self.stat(m, path)["basis"].clone()
    }

    fn fetch(&mut self, m: &str, path: &str, basis: &Value, extra: Value) -> Result<Value, Refused> {
        let mut a = json!({ "mount": m, "session": "s1", "path": path, "basis": basis });
        merge(&mut a, extra);
        self.h.raw("fetch", a)
    }

    /// store + write + commit; the commit's outcome. `basis` is `Value::Null` for a new file.
    fn put(&mut self, m: &str, path: &str, basis: &Value, data: &[u8]) -> Result<Value, Refused> {
        let id = self.begin(m, path, basis, data)?;
        self.h.raw("commit", json!({ "id": id }))
    }

    /// store + write, up to the commit.
    fn begin(&mut self, m: &str, path: &str, basis: &Value, data: &[u8]) -> Result<String, Refused> {
        let f = self
            .h
            .raw("store", json!({ "mount": m, "session": "s1", "path": path, "size": data.len(), "basis": basis }))?;
        let id = f["id"].as_str().unwrap().to_string();
        assert!(id.starts_with('s'), "{f}");
        self.h.ok("write", json!({ "id": id, "offset": 0, "bytes": b64(data) }));
        Ok(id)
    }

    fn code(&mut self, name: &str, args: Value) -> String {
        self.h.code(name, args)
    }
}

fn tmp_home() -> (tempfile::TempDir, PathBuf) {
    tmp()
}

fn merge(a: &mut Value, b: Value) {
    if let (Some(a), Value::Object(b)) = (a.as_object_mut(), b) {
        a.extend(b);
    }
}

fn b64(b: &[u8]) -> Value {
    json!({ "$bytes": base64::engine::general_purpose::STANDARD.encode(b) })
}

fn unb64(v: &Value) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(v["$bytes"].as_str().unwrap()).unwrap()
}

fn code_of(e: &Refused) -> &str {
    e["code"].as_str().unwrap()
}

/// The `.wmlhost-put-*` files directly in `dir`.
fn leftovers(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
        .filter(|n| n.starts_with(".wmlhost-put-"))
        .collect()
}

fn st(m: &str, path: &str) -> Value {
    json!({ "mount": m, "session": "s1", "path": path })
}

// --- hello ---

#[test]
fn hello_says_the_host_offers_mounts() {
    let e = Env::new();
    let mut h = e.h;
    assert_eq!(h.ok("hello", json!({}))["mounts"], json!(true));
    h.close();
}

// --- mounting ---

#[test]
fn a_project_directory_under_a_root_is_mounted_with_its_facts() {
    let mut e = Env::new();
    let f = e.h.ok("mount", json!({ "session": "s1", "path": e.proj, "mode": "rw" }));
    assert!(f["id"].as_str().unwrap().starts_with('m'), "{f}");
    assert_eq!(f["path"], json!(e.proj));
    assert_eq!(f["root"], json!(e.root));
    assert_eq!(f["mode"], json!("rw"));
    assert_eq!(f["uploads"], Value::Null);
    e.h.close();
}

#[test]
fn a_directory_outside_every_root_is_refused() {
    let mut e = Env::new();
    let (_d, outside) = tmp();
    let c = e.code("mount", json!({ "session": "s1", "path": outside, "mode": "rw" }));
    assert_eq!(c, "MountRefused");
    e.h.close();
}

#[test]
fn the_home_directory_a_missing_path_a_relative_path_and_a_reserved_prefix_are_refused() {
    let mut e = Env::new();
    // The home directory is refused even when a root holds it.
    let home = e._home.path().canonicalize().unwrap();
    e.h.ok("configure", json!({ "roots": [e.root, home], "sandbox": false }));
    let why = e.h.raw("mount", json!({ "session": "s1", "path": home, "mode": "rw" })).unwrap_err();
    assert_eq!(code_of(&why), "MountRefused");
    assert!(why["message"].as_str().unwrap().contains("home directory"), "{why}");
    let missing = e.root.join("nope");
    assert_eq!(e.code("mount", json!({ "session": "s1", "path": missing, "mode": "rw" })), "MountRefused");
    assert_eq!(e.code("mount", json!({ "session": "s1", "path": "proj", "mode": "rw" })), "BadRequest");
    assert_eq!(e.code("mount", json!({ "session": "s1", "path": "/tmp", "mode": "rw" })), "MountRefused");
    assert_eq!(e.code("mount", json!({ "session": "s1", "path": e.proj, "mode": "rwx" })), "BadRequest");
    e.h.close();
}

#[test]
fn a_directory_inside_a_mount_of_the_same_session_is_refused_and_allowed_in_another() {
    let mut e = Env::new();
    let nested = e.proj.join("sub");
    std::fs::create_dir(&nested).unwrap();
    e.mount("s1");
    assert_eq!(e.code("mount", json!({ "session": "s1", "path": nested, "mode": "rw" })), "MountRefused");
    assert_eq!(
        e.code("mount", json!({ "session": "s1", "path": e.root, "mode": "rw" })),
        "MountRefused",
        "above a mount of the session"
    );
    let other = e.mount_at("s2", &nested, "rw", None);
    assert!(other.starts_with('m'));
    e.h.close();
}

#[test]
fn an_uploads_folder_without_attached_is_refused() {
    let mut e = Env::new();
    std::fs::create_dir(e.proj.join("window-ml-files")).unwrap();
    let c = e.code("mount", json!({ "session": "s1", "path": e.proj, "mode": "rw", "uploads": "window-ml-files" }));
    assert_eq!(c, "MountRefused");
    let c = e.code("mount", json!({ "session": "s1", "path": e.proj, "mode": "rw", "uploads": "absent" }));
    assert_eq!(c, "MountRefused");
    std::fs::create_dir(e.proj.join("window-ml-files/attached")).unwrap();
    let id = e.mount_at("s1", &e.proj.clone(), "rw", Some("window-ml-files"));
    assert!(id.starts_with('m'));
    e.h.close();
}

#[test]
fn an_unmounted_id_is_gone_and_another_sessions_unmount_is_refused() {
    let mut e = Env::new();
    let m = e.mount("s1");
    assert_eq!(e.code("unmount", json!({ "mount": m, "session": "s2" })), "UnknownMount");
    e.h.ok("unmount", json!({ "mount": m, "session": "s1" }));
    assert_eq!(e.code("stat", st(&m, "")), "UnknownMount");
    assert_eq!(e.code("unmount", json!({ "mount": m, "session": "s1" })), "UnknownMount");
    e.h.close();
}

// --- the session check ---

#[test]
fn another_sessions_mount_id_reads_exactly_as_one_that_does_not_exist() {
    let mut e = Env::new();
    let m = e.mount("s1");
    let wrong = e.h.raw("stat", json!({ "mount": m, "session": "s2", "path": "" })).unwrap_err();
    let ghost = e.h.raw("stat", json!({ "mount": "m999", "session": "s2", "path": "" })).unwrap_err();
    assert_eq!(code_of(&wrong), "UnknownMount");
    assert_eq!(code_of(&ghost), "UnknownMount");
    let shape = |e: &Refused| e["message"].as_str().unwrap().replace(&m, "M").replace("m999", "M");
    assert_eq!(shape(&wrong), shape(&ghost), "the message does not tell the two apart");
    e.h.close();
}

// --- a replaced mount (H3) ---

#[test]
fn a_mount_whose_folder_was_moved_away_and_replaced_refuses_the_next_call() {
    let mut e = Env::new();
    std::fs::write(e.proj.join("a.txt"), "a").unwrap();
    let m = e.mount("s1");
    assert_eq!(e.stat(&m, "a.txt")["exists"], json!(true));
    std::fs::rename(&e.proj, e.root.join("proj-moved")).unwrap();
    std::fs::create_dir(&e.proj).unwrap();
    std::fs::write(e.proj.join("a.txt"), "impostor").unwrap();
    assert_eq!(e.code("stat", st(&m, "a.txt")), "MountReplaced");
    assert_eq!(e.code("list", st(&m, "")), "MountReplaced");
    e.h.close();
}

// --- the path rule ---

#[test]
fn a_path_that_could_leave_or_alias_the_mount_is_a_bad_request() {
    let mut e = Env::new();
    let m = e.mount("s1");
    for bad in ["../x", "/etc/passwd", "a\\b", "C:x", "a//b", "a/../b", "./a", "a/"] {
        assert_eq!(e.code("stat", st(&m, bad)), "BadRequest", "{bad:?}");
    }
    e.h.close();
}

#[test]
fn a_symlink_component_is_refused_and_a_final_symlink_is_reported_and_not_fetched() {
    let mut e = Env::new();
    std::fs::create_dir(e.proj.join("real")).unwrap();
    std::fs::write(e.proj.join("real/f.txt"), "hi").unwrap();
    symlink("real", e.proj.join("link")).unwrap();
    symlink("real/f.txt", e.proj.join("flink")).unwrap();
    let m = e.mount("s1");
    assert_eq!(e.code("stat", st(&m, "link/f.txt")), "IsSymlink");
    assert_eq!(e.code("list", st(&m, "link")), "IsSymlink");
    let f = e.stat(&m, "flink");
    assert_eq!((f["kind"].clone(), f["exists"].clone()), (json!("symlink"), json!(true)));
    let real = e.basis(&m, "real/f.txt");
    let r = e.fetch(&m, "flink", &real, json!({})).unwrap_err();
    assert!(r["code"].is_string(), "{r}");
    assert_ne!(code_of(&r), "EFBIG");
    // The listing shows it as a symlink too.
    let l = e.h.ok("list", st(&m, ""));
    let kinds: Vec<(String, String)> = l["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| (x["name"].as_str().unwrap().into(), x["kind"].as_str().unwrap().into()))
        .collect();
    assert!(kinds.contains(&("flink".into(), "symlink".into())), "{kinds:?}");
    assert!(kinds.contains(&("real".into(), "dir".into())), "{kinds:?}");
    e.h.close();
}

#[test]
fn a_listing_is_paged_and_sorted() {
    let mut e = Env::new();
    for n in ["c", "a", "b"] {
        std::fs::write(e.proj.join(n), n).unwrap();
    }
    let m = e.mount("s1");
    let l = e.h.ok("list", json!({ "mount": m, "session": "s1", "path": "", "offset": 1, "limit": 1 }));
    assert_eq!((l["total"].clone(), l["more"].clone()), (json!(3), json!(true)));
    assert_eq!(l["entries"][0]["name"], json!("b"));
    assert_eq!(l["entries"][0]["size"], json!(1));
    let l = e.h.ok("list", json!({ "mount": m, "session": "s1", "path": "", "offset": 2 }));
    assert_eq!((l["entries"].as_array().unwrap().len(), l["more"].clone()), (1, json!(false)));
    e.h.close();
}

// --- reading ---

#[test]
fn a_file_is_read_with_the_basis_stat_gave() {
    let mut e = Env::new();
    std::fs::write(e.proj.join("a.txt"), "hello").unwrap();
    let m = e.mount("s1");
    let s = e.stat(&m, "a.txt");
    assert_eq!(
        (s["kind"].clone(), s["exists"].clone(), s["inMount"].clone()),
        (json!("file"), json!(true), json!(true))
    );
    assert_eq!(s["basis"]["size"], json!(5));
    assert!(s["basis"]["sha256"].is_string(), "a small file carries its hash: {s}");
    let r = e.fetch(&m, "a.txt", &s["basis"], json!({})).unwrap();
    assert_eq!(
        (unb64(&r["data"]), r["offset"].clone(), r["size"].clone(), r["eof"].clone()),
        (b"hello".to_vec(), json!(0), json!(5), json!(true))
    );
    e.h.close();
}

#[test]
fn a_file_over_the_diff_cap_has_a_basis_without_a_hash() {
    let mut e = Env::new();
    std::fs::write(e.proj.join("big"), vec![1u8; (1 << 20) + 1]).unwrap();
    let m = e.mount("s1");
    let s = e.stat(&m, "big");
    assert_eq!(s["basis"]["size"], json!((1 << 20) + 1));
    assert!(s["basis"].get("sha256").is_none(), "{s}");
    e.h.close();
}

#[test]
fn a_fetch_without_the_basis_or_after_the_file_changed_is_changed_since_judged() {
    let mut e = Env::new();
    std::fs::write(e.proj.join("a.txt"), "hello").unwrap();
    let m = e.mount("s1");
    let b = e.basis(&m, "a.txt");
    let none = e.h.raw("fetch", st(&m, "a.txt")).unwrap_err();
    assert_eq!(code_of(&none), "ChangedSinceJudged");
    // Same size, different bytes: the hash (or the mtime) tells.
    std::fs::write(e.proj.join("a.txt"), "HELLO").unwrap();
    let r = e.fetch(&m, "a.txt", &b, json!({})).unwrap_err();
    assert_eq!(code_of(&r), "ChangedSinceJudged");
    // A basis for a different file is not this file's.
    std::fs::write(e.proj.join("b.txt"), "HELLO").unwrap();
    let other = e.basis(&m, "b.txt");
    let r = e.fetch(&m, "a.txt", &other, json!({})).unwrap_err();
    assert_eq!(code_of(&r), "ChangedSinceJudged");
    // A deleted file is changed too.
    std::fs::remove_file(e.proj.join("a.txt")).unwrap();
    let r = e.fetch(&m, "a.txt", &b, json!({})).unwrap_err();
    assert_eq!(code_of(&r), "ChangedSinceJudged");
    e.h.close();
}

#[test]
fn a_fetch_over_the_cap_is_efbig_with_the_size_and_the_cap() {
    let mut e = Env::new();
    std::fs::write(e.proj.join("a.txt"), "0123456789").unwrap();
    let m = e.mount("s1");
    let b = e.basis(&m, "a.txt");
    let r = e.fetch(&m, "a.txt", &b, json!({ "cap": 4 })).unwrap_err();
    assert_eq!(code_of(&r), "EFBIG");
    assert_eq!((r["size"].clone(), r["cap"].clone()), (json!(10), json!(4)));
    e.h.close();
}

#[test]
fn a_large_file_is_read_in_two_chunks_that_reassemble() {
    let mut e = Env::new();
    let data: Vec<u8> = (0..600 * 1024u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(e.proj.join("big.bin"), &data).unwrap();
    let m = e.mount("s1");
    let b = e.basis(&m, "big.bin");
    let first = e.fetch(&m, "big.bin", &b, json!({})).unwrap();
    assert_eq!(first["eof"], json!(false));
    let got = unb64(&first["data"]);
    assert_eq!(got.len(), 512 * 1024, "one chunk is at most 512 KiB");
    let second = e.fetch(&m, "big.bin", &b, json!({ "offset": got.len() })).unwrap();
    assert_eq!(second["eof"], json!(true));
    let mut all = got;
    all.extend(unb64(&second["data"]));
    assert_eq!(all, data);
    e.h.close();
}

// --- writing ---

#[test]
fn a_new_file_is_stored_written_and_committed() {
    let mut e = Env::new();
    std::fs::create_dir(e.proj.join("d")).unwrap();
    let m = e.mount("s1");
    let c = e.put(&m, "d/new.txt", &Value::Null, b"fresh").unwrap();
    assert_eq!(c["size"], json!(5));
    assert!(c["sha256"].is_string(), "{c}");
    assert_eq!(std::fs::read(e.proj.join("d/new.txt")).unwrap(), b"fresh");
    assert!(leftovers(&e.proj.join("d")).is_empty());
    assert_eq!(e.code("store", json!({ "mount": m, "session": "s1", "path": "nodir/x", "size": 1 })), "NoParent");
    e.h.close();
}

#[test]
fn a_file_replaced_with_its_basis_keeps_its_permission_bits() {
    let mut e = Env::new();
    let f = e.proj.join("a.txt");
    std::fs::write(&f, "old").unwrap();
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o640)).unwrap();
    let m = e.mount("s1");
    let b = e.basis(&m, "a.txt");
    e.put(&m, "a.txt", &b, b"newer bytes").unwrap();
    assert_eq!(std::fs::read(&f).unwrap(), b"newer bytes");
    assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o640);
    assert!(leftovers(&e.proj).is_empty());
    e.h.close();
}

#[test]
fn a_store_over_an_existing_file_without_its_basis_is_changed_since_judged() {
    let mut e = Env::new();
    std::fs::write(e.proj.join("a.txt"), "old").unwrap();
    let m = e.mount("s1");
    let r = e.h.raw("store", json!({ "mount": m, "session": "s1", "path": "a.txt", "size": 1 })).unwrap_err();
    assert_eq!(code_of(&r), "ChangedSinceJudged");
    // A basis for a file that is not there is just as stale.
    let r = e.put(&m, "gone.txt", &json!({ "dev": 1, "ino": 2, "size": 3, "mtimeNs": 4 }), b"x").unwrap_err();
    assert_eq!(code_of(&r), "ChangedSinceJudged");
    assert_eq!(std::fs::read(e.proj.join("a.txt")).unwrap(), b"old");
    e.h.close();
}

#[test]
fn a_file_changed_between_the_store_and_the_commit_is_left_alone_and_leaves_no_temp_file() {
    let mut e = Env::new();
    let f = e.proj.join("a.txt");
    std::fs::write(&f, "old").unwrap();
    let m = e.mount("s1");
    let b = e.basis(&m, "a.txt");
    let id = e.begin(&m, "a.txt", &b, b"mine").unwrap();
    std::fs::write(&f, "someone else's longer edit").unwrap();
    let r = e.h.raw("commit", json!({ "id": id })).unwrap_err();
    assert_eq!(code_of(&r), "ChangedSinceJudged");
    assert_eq!(std::fs::read(&f).unwrap(), b"someone else's longer edit");
    assert!(leftovers(&e.proj).is_empty(), "{:?}", leftovers(&e.proj));
    e.h.close();
}

#[test]
fn a_file_that_appears_between_the_store_and_the_commit_is_not_overwritten() {
    let mut e = Env::new();
    let m = e.mount("s1");
    let id = e.begin(&m, "new.txt", &Value::Null, b"mine").unwrap();
    std::fs::write(e.proj.join("new.txt"), "theirs").unwrap();
    let r = e.h.raw("commit", json!({ "id": id })).unwrap_err();
    assert_eq!(code_of(&r), "ChangedSinceJudged");
    assert_eq!(std::fs::read(e.proj.join("new.txt")).unwrap(), b"theirs");
    assert!(leftovers(&e.proj).is_empty(), "{:?}", leftovers(&e.proj));
    e.h.close();
}

#[test]
fn a_read_only_mount_refuses_every_write_and_creates_nothing() {
    let mut e = Env::new();
    std::fs::write(e.proj.join("a.txt"), "old").unwrap();
    let p = e.proj.clone();
    let m = e.mount_at("s1", &p, "ro", None);
    let b = e.basis(&m, "a.txt");
    assert_eq!(e.code("store", json!({ "mount": m, "session": "s1", "path": "new.txt", "size": 1 })), "EROFS");
    assert_eq!(
        e.code("store", json!({ "mount": m, "session": "s1", "path": "a.txt", "size": 1, "basis": b })),
        "EROFS"
    );
    assert_eq!(e.code("remove", json!({ "mount": m, "session": "s1", "path": "a.txt", "basis": b })), "EROFS");
    let ren = json!({ "mount": m, "session": "s1", "from": "a.txt", "to": "b.txt", "basis": b });
    assert_eq!(e.code("rename", ren), "EROFS");
    assert!(!e.proj.join("new.txt").exists());
    assert!(leftovers(&e.proj).is_empty());
    assert_eq!(std::fs::read(e.proj.join("a.txt")).unwrap(), b"old");
    e.h.close();
}

#[test]
fn a_hard_linked_target_is_refused() {
    let mut e = Env::new();
    std::fs::write(e.proj.join("a.txt"), "old").unwrap();
    std::fs::hard_link(e.proj.join("a.txt"), e.proj.join("alias.txt")).unwrap();
    let m = e.mount("s1");
    let s = e.stat(&m, "a.txt");
    assert_eq!(s["hardLinked"], json!(true));
    let r = e.put(&m, "a.txt", &s["basis"], b"new").unwrap_err();
    assert_eq!(code_of(&r), "HardLinked");
    assert_eq!(std::fs::read(e.proj.join("alias.txt")).unwrap(), b"old");
    assert_eq!(std::fs::metadata(e.proj.join("a.txt")).unwrap().nlink(), 2);
    e.h.close();
}

#[test]
fn a_git_directory_and_a_roots_protected_name_are_protected() {
    let mut e = Env::new();
    std::fs::create_dir_all(e.proj.join(".git/hooks")).unwrap();
    std::fs::create_dir_all(e.proj.join("sub/.GIT")).unwrap();
    let m = e.mount("s1");
    for p in [".git/hooks/pre-commit", "sub/.GIT/x", ".git/config"] {
        assert_eq!(e.stat(&m, p)["protected"], json!(true), "{p}");
        let c = e.code("store", json!({ "mount": m, "session": "s1", "path": p, "size": 1 }));
        assert_eq!(c, "Protected", "{p}");
    }
    assert!(!e.proj.join(".git/hooks/pre-commit").exists());
    assert_eq!(e.stat(&m, "sub")["protected"], json!(false));
    e.h.close();
}

// --- the uploads folder ---

fn uploads_env() -> (Env, String) {
    let mut e = Env::new();
    std::fs::create_dir_all(e.proj.join("window-ml-files/attached")).unwrap();
    std::fs::write(e.proj.join("window-ml-files/attached/in.txt"), "given").unwrap();
    std::fs::write(e.proj.join("window-ml-files/out.txt"), "mine").unwrap();
    let p = e.proj.clone();
    let m = e.mount_at("s1", &p, "rw", Some("window-ml-files"));
    (e, m)
}

#[test]
fn a_file_in_attached_is_marked_as_in_the_uploads_and_in_attached() {
    let (mut e, m) = uploads_env();
    let s = e.stat(&m, "window-ml-files/attached/in.txt");
    assert_eq!((s["inAttached"].clone(), s["inUploads"].clone()), (json!(true), json!(true)));
    let s = e.stat(&m, "window-ml-files/out.txt");
    assert_eq!((s["inAttached"].clone(), s["inUploads"].clone()), (json!(false), json!(true)));
    let s = e.stat(&m, "window-ml-files/attached");
    assert_eq!(s["inAttached"], json!(true), "the folder itself");
    e.h.close();
}

#[test]
fn a_store_into_attached_is_refused_whatever_the_case_of_its_name() {
    let (mut e, m) = uploads_env();
    let r = e.h.raw("store", json!({ "mount": m, "session": "s1", "path": "window-ml-files/attached/x", "size": 1 }));
    assert_eq!(code_of(&r.unwrap_err()), "InAttached");
    let b = e.basis(&m, "window-ml-files/attached/in.txt");
    let r = e.put(&m, "window-ml-files/attached/in.txt", &b, b"x").unwrap_err();
    assert_eq!(code_of(&r), "InAttached");
    assert_eq!(std::fs::read(e.proj.join("window-ml-files/attached/in.txt")).unwrap(), b"given");
    if e.proj.join("window-ml-files/Attached").exists() {
        let c =
            e.code("store", json!({ "mount": m, "session": "s1", "path": "window-ml-files/Attached/x", "size": 1 }));
        assert_eq!(c, "InAttached", "a case-insensitive filesystem reaches attached/ by another spelling");
    }
    e.h.close();
}

#[test]
fn a_rename_into_or_out_of_attached_is_refused() {
    let (mut e, m) = uploads_env();
    let b = e.basis(&m, "window-ml-files/attached/in.txt");
    let out = json!({ "mount": m, "session": "s1", "from": "window-ml-files/attached/in.txt", "to": "window-ml-files/moved.txt", "basis": b });
    assert_eq!(e.code("rename", out), "InAttached");
    let b = e.basis(&m, "window-ml-files/out.txt");
    let into = json!({ "mount": m, "session": "s1", "from": "window-ml-files/out.txt", "to": "window-ml-files/attached/out.txt", "basis": b });
    assert_eq!(e.code("rename", into), "InAttached");
    assert!(e.proj.join("window-ml-files/attached/in.txt").exists());
    assert!(e.proj.join("window-ml-files/out.txt").exists());
    e.h.close();
}

#[test]
fn a_remove_in_attached_with_the_basis_is_allowed() {
    let (mut e, m) = uploads_env();
    let b = e.basis(&m, "window-ml-files/attached/in.txt");
    let args = json!({ "mount": m, "session": "s1", "path": "window-ml-files/attached/in.txt", "basis": b });
    e.h.ok("remove", args);
    assert!(!e.proj.join("window-ml-files/attached/in.txt").exists());
    e.h.close();
}

// --- remove and rename ---

#[test]
fn a_remove_with_a_stale_basis_is_changed_since_judged_and_keeps_the_file() {
    let mut e = Env::new();
    std::fs::write(e.proj.join("a.txt"), "old").unwrap();
    let m = e.mount("s1");
    let b = e.basis(&m, "a.txt");
    std::fs::write(e.proj.join("a.txt"), "different").unwrap();
    let c = e.code("remove", json!({ "mount": m, "session": "s1", "path": "a.txt", "basis": b }));
    assert_eq!(c, "ChangedSinceJudged");
    assert_eq!(e.code("remove", json!({ "mount": m, "session": "s1", "path": "a.txt" })), "ChangedSinceJudged");
    let b = e.basis(&m, "a.txt");
    e.h.ok("remove", json!({ "mount": m, "session": "s1", "path": "a.txt", "basis": b }));
    assert!(!e.proj.join("a.txt").exists());
    e.h.close();
}

#[test]
fn a_rename_onto_an_existing_name_is_exists_and_both_files_stay() {
    let mut e = Env::new();
    std::fs::write(e.proj.join("a.txt"), "A").unwrap();
    std::fs::write(e.proj.join("b.txt"), "B").unwrap();
    let m = e.mount("s1");
    let b = e.basis(&m, "a.txt");
    let c = e.code("rename", json!({ "mount": m, "session": "s1", "from": "a.txt", "to": "b.txt", "basis": b }));
    assert_eq!(c, "Exists");
    assert_eq!(std::fs::read(e.proj.join("a.txt")).unwrap(), b"A");
    assert_eq!(std::fs::read(e.proj.join("b.txt")).unwrap(), b"B");
    e.h.close();
}

#[test]
fn a_rename_across_subdirectories_moves_the_file() {
    let mut e = Env::new();
    std::fs::create_dir_all(e.proj.join("x")).unwrap();
    std::fs::create_dir_all(e.proj.join("y")).unwrap();
    std::fs::write(e.proj.join("x/a.txt"), "A").unwrap();
    let m = e.mount("s1");
    let b = e.basis(&m, "x/a.txt");
    e.h.ok("rename", json!({ "mount": m, "session": "s1", "from": "x/a.txt", "to": "y/b.txt", "basis": b }));
    assert!(!e.proj.join("x/a.txt").exists());
    assert_eq!(std::fs::read(e.proj.join("y/b.txt")).unwrap(), b"A");
    let b = e.basis(&m, "y/b.txt");
    let c = e.code("rename", json!({ "mount": m, "session": "s1", "from": "y/b.txt", "to": "y/.git/c", "basis": b }));
    assert_eq!(c, "Protected");
    e.h.close();
}

// --- git facts ---

fn git(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.com")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.com")
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn a_committed_file_is_git_undoable_until_it_is_edited_and_an_ignored_one_is_ignored() {
    if Command::new("git").arg("--version").output().is_err() {
        eprintln!("skipped: no git on PATH");
        return;
    }
    let mut e = Env::new();
    let p = e.proj.clone();
    git(&p, &["init", "-q"]);
    std::fs::write(p.join("tracked.txt"), "v1\n").unwrap();
    std::fs::write(p.join(".gitignore"), "*.log\n").unwrap();
    std::fs::write(p.join("noise.log"), "x").unwrap();
    git(&p, &["add", "tracked.txt", ".gitignore"]);
    git(&p, &["commit", "-q", "-m", "init"]);
    let m = e.mount("s1");
    let s = e.stat(&m, "tracked.txt");
    assert_eq!(s["gitUndoable"], json!(true), "{s}");
    assert_eq!(s["ignored"], json!(false));
    std::fs::write(p.join("tracked.txt"), "v2 edited\n").unwrap();
    let s = e.stat(&m, "tracked.txt");
    assert_eq!(s["gitUndoable"], json!(false), "{s}");
    let s = e.stat(&m, "noise.log");
    assert_eq!(s["ignored"], json!(true), "{s}");
    let s = e.stat(&m, "tracked.txt");
    assert_eq!(s["ignored"], json!(false));
    e.h.close();
}

// --- reconfigure ---

#[test]
fn a_reconfigure_with_a_root_that_no_longer_holds_the_mount_drops_it() {
    let mut e = Env::new();
    std::fs::write(e.proj.join("a.txt"), "a").unwrap();
    let m = e.mount("s1");
    let kept = e.h.ok("configure", json!({ "roots": [e.root], "sandbox": false }));
    assert!(kept["roots"].is_array());
    assert_eq!(e.stat(&m, "a.txt")["exists"], json!(true), "a root that still holds it keeps the mount");
    let (_d, elsewhere) = tmp();
    e.h.ok("configure", json!({ "roots": [elsewhere], "sandbox": false }));
    assert_eq!(e.code("stat", st(&m, "a.txt")), "UnknownMount");
    e.h.close();
}
