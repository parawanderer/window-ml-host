//! hide_list.rs — the `hideList` arg of `spawn` against the built `wmlhost` under the real sandbox: what a `hide` holds
//! (read and write, a directory's subtree, multibyte names), what a `show` releases, precedence, and the refusals.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use base64::Engine;
use serde_json::{Value, json};

struct Host {
    state: tempfile::TempDir,
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: ChildStdout,
    seq: u64,
    events: Vec<Value>,
}

impl Host {
    fn start() -> Host {
        let state = tempfile::tempdir().unwrap();
        let dir = state.path().join("owners");
        let mut c = Command::new(env!("CARGO_BIN_EXE_wmlhost"));
        c.env("WMLHOST_STATE_DIR", &dir);
        c.arg("chrome-extension://abcdefghijklmnopabcdefghijklmnop/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let mut child = c.spawn().expect("wmlhost starts");
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        Host { state, child, stdin, stdout, seq: 0, events: vec![] }
    }

    fn send(&mut self, v: &Value) {
        let b = serde_json::to_vec(v).unwrap();
        let w = self.stdin.as_mut().unwrap();
        w.write_all(&(b.len() as u32).to_ne_bytes()).unwrap();
        w.write_all(&b).unwrap();
        w.flush().unwrap();
    }

    fn recv(&mut self) -> Value {
        let mut len = [0u8; 4];
        self.stdout.read_exact(&mut len).expect("a frame from the host");
        let n = u32::from_ne_bytes(len) as usize;
        let mut b = vec![0u8; n];
        self.stdout.read_exact(&mut b).unwrap();
        serde_json::from_slice(&b).unwrap()
    }

    /// One call; `done` events that arrive meanwhile are kept for `done`.
    fn call(&mut self, name: &str, args: Value) -> Result<Value, (String, String)> {
        self.seq += 1;
        let seq = self.seq;
        self.send(&json!({ "seq": seq, "call": name, "args": args }));
        loop {
            let m = self.recv();
            if m.get("event").is_some() {
                self.events.push(m);
                continue;
            }
            assert_eq!(m["seq"], json!(seq), "answers carry their seq");
            if let Some(e) = m.get("error") {
                return Err((e["code"].as_str().unwrap().into(), e["message"].as_str().unwrap_or("").into()));
            }
            return Ok(m["value"].clone());
        }
    }

    fn ok(&mut self, name: &str, args: Value) -> Value {
        self.call(name, args).unwrap_or_else(|e| panic!("{name} failed: {e:?}"))
    }

    fn done(&mut self, id: &str) -> Value {
        loop {
            if let Some(i) = self.events.iter().position(|e| e["id"] == json!(id)) {
                return self.events.remove(i);
            }
            let m = self.recv();
            assert!(m.get("event").is_some(), "unexpected answer while waiting for done: {m}");
            self.events.push(m);
        }
    }

    fn read_all(&mut self, stream: &Value) -> Vec<u8> {
        let ptr = stream["ptr"].as_str().expect("a pointer").to_string();
        let (mut out, mut off) = (Vec::new(), 0u64);
        loop {
            let r = self.ok("read", json!({ "ptr": ptr, "offset": off }));
            let b = base64::engine::general_purpose::STANDARD.decode(r["data"]["$bytes"].as_str().unwrap()).unwrap();
            off += b.len() as u64;
            out.extend(b);
            if r["eof"] == json!(true) {
                return out;
            }
        }
    }

    /// spawn + start + done, for calls that are expected to run.
    fn run(&mut self, args: Value) -> (Value, Value) {
        let facts = self.ok("spawn", args);
        let id = facts["id"].as_str().unwrap().to_string();
        self.ok("start", json!({ "id": id }));
        let d = self.done(&id);
        (facts, d)
    }

    fn sandbox_available(&mut self) -> bool {
        let h = self.ok("hello", json!({}));
        let avail = h["sandbox"]["available"] == json!(true);
        if cfg!(target_os = "macos") {
            assert!(avail, "Seatbelt must be available on macOS: {h}");
        } else if !avail {
            eprintln!("sandbox unavailable here, enforcement checks skipped: {}", h["sandbox"]);
        }
        avail
    }

    fn close(mut self) {
        drop(self.stdin.take());
        let _ = self.child.wait();
        drop(self.state);
    }

    /// Runs `cat` on each name from `r` in one shell, stderr dropped: the stdout is what was readable.
    fn cat_all(&mut self, r: &Path, hide: Value, names: &[&str]) -> (Value, String) {
        let script = names.iter().map(|n| format!("cat '{n}' 2>/dev/null")).collect::<Vec<_>>().join("; ");
        let (f, d) = self.run(json!({ "argv": ["sh", "-c", script], "cwd": r, "hideList": hide }));
        let out = text(&self.read_all(&d["stdout"]));
        (f, out)
    }
}

fn root() -> (tempfile::TempDir, PathBuf) {
    let d = tempfile::tempdir().unwrap();
    let r = d.path().canonicalize().unwrap();
    (d, r)
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn entry(id: &str, effect: &str, pattern: impl AsRef<Path>) -> Value {
    json!({ "id": id, "effect": effect, "pattern": pattern.as_ref().to_string_lossy() })
}

/// A started host with the sandbox, configured on `r`; `None` (closed) where there is no sandbox.
fn sandboxed(r: &Path) -> Option<Host> {
    let mut h = Host::start();
    if !h.sandbox_available() {
        h.close();
        return None;
    }
    h.ok("configure", json!({ "roots": [r] }));
    Some(h)
}

// --- the protocol ---

/// `hello` says the host takes the field.
#[test]
fn hello_announces_the_hide_list() {
    let mut h = Host::start();
    let v = h.ok("hello", json!({}));
    assert_eq!(v["hideList"], json!(true), "{v}");
    h.close();
}

// --- hide holds reading and writing ---

/// A `hide` of a glob holds its matches for read and write, leaves the rest, and lists the match in `hiddenSecrets`.
#[test]
fn a_hide_glob_holds_reading_and_writing_and_is_listed() {
    let (_d, r) = root();
    std::fs::create_dir(r.join("notes")).unwrap();
    std::fs::write(r.join("notes/a.txt"), "NOTE-A\n").unwrap();
    std::fs::write(r.join("other.txt"), "OTHER\n").unwrap();
    let Some(mut h) = sandboxed(&r) else { return };
    let hide = json!([entry("h1", "hide", r.join("notes/*"))]);
    let (f, out) = h.cat_all(&r, hide.clone(), &["notes/a.txt", "other.txt"]);
    assert!(!out.contains("NOTE-A"), "hidden file was read: {out}");
    assert!(out.contains("OTHER"), "{out}");
    assert!(f["hiddenSecrets"].as_array().unwrap().contains(&json!(r.join("notes/a.txt"))), "{f}");
    let (_f, d) = h.run(json!({ "argv": ["sh", "-c", "echo x > notes/a.txt"], "cwd": r, "hideList": hide }));
    assert_ne!(d["code"], 0, "write to a hidden file succeeded: {d}");
    assert_eq!(std::fs::read_to_string(r.join("notes/a.txt")).unwrap(), "NOTE-A\n");
    h.close();
}

/// A `hide` of a directory holds everything under it, and not a sibling that shares the name's prefix.
#[test]
fn a_hide_of_a_directory_holds_its_subtree_and_not_a_prefix_sibling() {
    let (_d, r) = root();
    std::fs::create_dir_all(r.join("priv/deep")).unwrap();
    std::fs::write(r.join("priv/deep/x.txt"), "DEEP-X\n").unwrap();
    std::fs::write(r.join("private.txt"), "PRIVATE-SIBLING\n").unwrap();
    let Some(mut h) = sandboxed(&r) else { return };
    let (_f, out) = h.cat_all(&r, json!([entry("h1", "hide", r.join("priv"))]), &["priv/deep/x.txt", "private.txt"]);
    assert!(!out.contains("DEEP-X"), "a file under a hidden directory was read: {out}");
    assert!(out.contains("PRIVATE-SIBLING"), "a prefix sibling was held: {out}");
    h.close();
}

// --- multibyte names: Seatbelt matches bytes, the host's matcher matches characters ---

/// A hide's `?` holds one character however many bytes it takes, and a short name besides (the safe side).
#[test]
fn a_question_mark_matches_a_multibyte_character() {
    let (_d, r) = root();
    for (n, c) in [("é.txt", "C-E"), ("a.txt", "C-A"), ("ab.txt", "C-AB")] {
        std::fs::write(r.join(n), format!("{c}\n")).unwrap();
    }
    let Some(mut h) = sandboxed(&r) else { return };
    let (_f, out) = h.cat_all(&r, json!([entry("h1", "hide", r.join("?.txt"))]), &["é.txt", "a.txt", "ab.txt"]);
    assert!(!out.contains("C-E"), "é.txt was readable: {out}");
    assert!(!out.contains("C-A\n"), "a.txt was readable: {out}");
    // A hide's `?` is one to four bytes (Seatbelt matches bytes), so it also holds a two-letter name: the stated over-hold.
    assert!(!out.contains("C-AB"), "ab.txt is held by the documented over-hold: {out}");
    h.close();
}

/// A bracket set naming a multibyte character holds that character's file and no other.
#[test]
fn a_bracket_set_of_a_multibyte_character_holds_only_it() {
    let (_d, r) = root();
    for (n, c) in [("é.txt", "C-E"), ("a.txt", "C-A")] {
        std::fs::write(r.join(n), format!("{c}\n")).unwrap();
    }
    let Some(mut h) = sandboxed(&r) else { return };
    let (_f, out) = h.cat_all(&r, json!([entry("h1", "hide", r.join("[é].txt"))]), &["é.txt", "a.txt"]);
    assert!(!out.contains("C-E"), "é.txt was readable: {out}");
    assert!(out.contains("C-A"), "a.txt must stay readable: {out}");
    h.close();
}

/// A negated bracket set holds a multibyte character's file (it is not `a`), and leaves `a.txt`.
#[test]
fn a_negated_bracket_set_holds_a_multibyte_character() {
    let (_d, r) = root();
    for (n, c) in [("é.txt", "C-E"), ("a.txt", "C-A")] {
        std::fs::write(r.join(n), format!("{c}\n")).unwrap();
    }
    let Some(mut h) = sandboxed(&r) else { return };
    let (_f, out) = h.cat_all(&r, json!([entry("h1", "hide", r.join("[!a].txt"))]), &["é.txt", "a.txt"]);
    assert!(!out.contains("C-E"), "é.txt was readable: {out}");
    assert!(out.contains("C-A"), "a.txt must stay readable: {out}");
    h.close();
}

/// A `show` with `?` releases the ASCII default hold and errs toward releasing less on a multibyte name.
#[test]
fn a_show_question_mark_releases_ascii_and_keeps_a_multibyte_name_held() {
    let (_d, r) = root();
    std::fs::write(r.join(".env.a"), "ENV-A\n").unwrap();
    std::fs::write(r.join(".env.é"), "ENV-E\n").unwrap();
    let Some(mut h) = sandboxed(&r) else { return };
    let (_f, out) = h.cat_all(&r, json!([entry("s1", "show", r.join(".env.?"))]), &[".env.a", ".env.é"]);
    assert!(out.contains("ENV-A"), ".env.a must be released: {out}");
    assert!(!out.contains("ENV-E"), ".env.é must stay held: {out}");
    h.close();
}

// --- show releases a default hold ---

/// A `show` of `.env` makes it readable and writable and unlisted, and leaves `.env.local` held.
#[test]
fn a_show_releases_a_dotenv_for_reading_and_writing_and_only_it() {
    let (_d, r) = root();
    std::fs::write(r.join(".env"), "DOTENV\n").unwrap();
    std::fs::write(r.join(".env.local"), "LOCAL\n").unwrap();
    let Some(mut h) = sandboxed(&r) else { return };
    let hide = json!([entry("s1", "show", r.join(".env"))]);
    let (f, out) = h.cat_all(&r, hide.clone(), &[".env", ".env.local"]);
    assert!(out.contains("DOTENV"), ".env must be readable: {out}");
    assert!(!out.contains("LOCAL"), ".env.local must stay held: {out}");
    let listed = f["hiddenSecrets"].as_array().unwrap();
    assert!(!listed.contains(&json!(r.join(".env"))), "{f}");
    assert!(listed.contains(&json!(r.join(".env.local"))), "{f}");
    let (_f, d) = h.run(json!({ "argv": ["sh", "-c", "echo NEW > .env"], "cwd": r, "hideList": hide }));
    assert_eq!(d["code"], 0, "a released .env must be writable: {d}");
    assert_eq!(std::fs::read_to_string(r.join(".env")).unwrap(), "NEW\n");
    h.close();
}

/// A `show` never opens a protected name for writing.
#[test]
fn a_show_does_not_make_a_protected_name_writable() {
    let (_d, r) = root();
    std::fs::create_dir(r.join(".claude")).unwrap();
    std::fs::write(r.join(".claude/settings.json"), "ORIGINAL\n").unwrap();
    let Some(mut h) = sandboxed(&r) else { return };
    let hide = json!([entry("s1", "show", r.join(".claude/settings.json"))]);
    let (_f, d) = h.run(json!({ "argv": ["sh", "-c", "echo x > .claude/settings.json"], "cwd": r, "hideList": hide }));
    assert_ne!(d["code"], 0, "a protected name was written: {d}");
    assert_eq!(std::fs::read_to_string(r.join(".claude/settings.json")).unwrap(), "ORIGINAL\n");
    h.close();
}

// --- precedence: the last entry that names a path decides ---

/// A later `hide` over an earlier `show` of the same file holds it.
#[test]
fn a_later_hide_beats_an_earlier_show() {
    let (_d, r) = root();
    std::fs::write(r.join(".env"), "DOTENV\n").unwrap();
    let Some(mut h) = sandboxed(&r) else { return };
    let hide = json!([entry("s1", "show", r.join(".env")), entry("h1", "hide", r.join(".env"))]);
    let (_f, out) = h.cat_all(&r, hide, &[".env"]);
    assert!(!out.contains("DOTENV"), "{out}");
    h.close();
}

/// A later `show` of one file inside an earlier `hide` of its directory releases that file only (macOS).
#[cfg(target_os = "macos")]
#[test]
fn a_later_show_inside_a_hidden_directory_releases_that_file_only() {
    let (_d, r) = root();
    std::fs::create_dir(r.join("d")).unwrap();
    std::fs::write(r.join("d/a.txt"), "D-A\n").unwrap();
    std::fs::write(r.join("d/b.txt"), "D-B\n").unwrap();
    let Some(mut h) = sandboxed(&r) else { return };
    let hide = json!([entry("h1", "hide", r.join("d")), entry("s1", "show", r.join("d/a.txt"))]);
    let (_f, out) = h.cat_all(&r, hide, &["d/a.txt", "d/b.txt"]);
    assert!(out.contains("D-A"), "d/a.txt must be released: {out}");
    assert!(!out.contains("D-B"), "d/b.txt must stay held: {out}");
    h.close();
}

// --- a named path ---

/// A path argument a `hide` holds is flagged with the entry's id and, approved by naming it, is read; unnamed it is not.
#[test]
fn a_named_hidden_path_says_which_entry_holds_it_and_is_read() {
    let (_d, r) = root();
    std::fs::write(r.join("secret.txt"), "SECRET-TXT\n").unwrap();
    let Some(mut h) = sandboxed(&r) else { return };
    let hide = json!([entry("rule-7", "hide", r.join("secret.txt"))]);
    let (f, d) = h.run(json!({
        "argv": ["cat", "secret.txt"], "cwd": r, "hideList": hide, "pathArgs": [{ "arg": 1 }]
    }));
    assert_eq!(f["paths"][0]["hiddenBy"], "rule-7", "{f}");
    assert_eq!(text(&h.read_all(&d["stdout"])), "SECRET-TXT\n");
    let (_f, out) = h.cat_all(&r, hide, &["secret.txt"]);
    assert!(!out.contains("SECRET-TXT"), "unnamed, the file was read: {out}");
    h.close();
}

// --- links ---

/// A hide of a symlink holds the link and the file it points at, by its own path as well.
#[test]
fn a_hide_of_a_symlink_holds_its_target_too() {
    let (_d, r) = root();
    let (_other, o) = root();
    std::fs::write(o.join("target.txt"), "TARGET\n").unwrap();
    std::os::unix::fs::symlink(o.join("target.txt"), r.join("link")).unwrap();
    let Some(mut h) = sandboxed(&r) else { return };
    let target = o.join("target.txt").to_string_lossy().into_owned();
    let (_f, base) = h.cat_all(&r, json!([]), &["link", &target]);
    assert_eq!(base, "TARGET\nTARGET\n", "baseline: both readable without the rule");
    let (_f, out) = h.cat_all(&r, json!([entry("h1", "hide", r.join("link"))]), &["link"]);
    assert!(!out.contains("TARGET"), "read through the hidden link: {out}");
    let (_f, out) = h.cat_all(&r, json!([entry("h1", "hide", r.join("link"))]), &[&target]);
    assert!(!out.contains("TARGET"), "read the link's target by its own path: {out}");
    h.close();
}

/// A link OUTSIDE the hidden pattern that resolves to a hidden file. A symlink, made before the call or by it, is held
/// on both platforms. A hard link the person made beforehand is another name of the inode, which neither sandbox sees:
/// readable on both, the stated limit. The call cannot make a hard link to the held file itself.
#[test]
fn a_link_outside_the_pattern_to_a_hidden_file() {
    let (_d, r) = root();
    std::fs::write(r.join("secret.txt"), "SECRET\n").unwrap();
    std::os::unix::fs::symlink("secret.txt", r.join("alias")).unwrap();
    std::fs::hard_link(r.join("secret.txt"), r.join("hl")).unwrap();
    let Some(mut h) = sandboxed(&r) else { return };
    let hide = json!([entry("h1", "hide", r.join("secret.txt"))]);
    let (_f, out) = h.cat_all(&r, hide.clone(), &["alias"]);
    assert!(!out.contains("SECRET"), "read through a symlink made before the call: {out}");
    let script =
        "ln -s secret.txt s2 2>/dev/null; cat s2 2>/dev/null; ln secret.txt hl2 2>/dev/null; cat hl2 2>/dev/null";
    let (_f, d) = h.run(json!({ "argv": ["sh", "-c", script], "cwd": r, "hideList": hide }));
    let out = text(&h.read_all(&d["stdout"]));
    assert!(!out.contains("SECRET"), "a symlink or hard link the call made reads the held file: {out}");
    assert!(
        !std::fs::read(r.join("hl2")).is_ok_and(|b| b == b"SECRET\n"),
        "the call made a hard link to the held file"
    );
    // The stated limit: a hard link that already existed, under a name the pattern does not match.
    let (_f, out) = h.cat_all(&r, hide, &["hl"]);
    assert_eq!(out, "SECRET\n", "the stated limit changed: a prior hard link is now held; update PROTOCOL.md");
    h.close();
}

// --- a file made after the spawn ---

/// A hide whose pattern matches nothing at spawn. A file made between `spawn` and `start` is held on both platforms
/// (macOS by pattern, Linux by the walk again at `start`). A file the call itself makes: macOS refuses to create it;
/// on Linux the call creates it and reads it back, the stated limit.
#[test]
fn a_file_made_after_the_spawn_that_matches_a_hide() {
    let (_d, r) = root();
    let Some(mut h) = sandboxed(&r) else { return };
    let hide = json!([entry("h1", "hide", r.join("late*.txt"))]);
    let f = h.ok("spawn", json!({ "argv": ["cat", "late1.txt"], "cwd": r, "hideList": hide }));
    assert_eq!(f["hiddenSecrets"], json!([]), "nothing matches at spawn: {f}");
    std::fs::write(r.join("late1.txt"), "LATE1\n").unwrap();
    let id = f["id"].as_str().unwrap().to_string();
    h.ok("start", json!({ "id": id }));
    let d = h.done(&id);
    assert!(!text(&h.read_all(&d["stdout"])).contains("LATE1"), "a file made between spawn and start was read");
    let script = "echo LATE2 > late2.txt; cat late2.txt";
    let (_f, d) = h.run(json!({ "argv": ["sh", "-c", script], "cwd": r, "hideList": hide }));
    let out = text(&h.read_all(&d["stdout"]));
    if cfg!(target_os = "macos") {
        assert!(!out.contains("LATE2"), "{out}");
        assert!(!r.join("late2.txt").exists(), "macOS denies creating a held name");
    } else {
        assert_eq!(out, "LATE2\n", "the stated Linux limit changed: update PROTOCOL.md");
        // Held from the next call's start.
        let (_f, out) = h.cat_all(&r, hide, &["late2.txt"]);
        assert!(!out.contains("LATE2"), "{out}");
    }
    h.close();
}

// --- refusals ---

/// A refused pattern fails the spawn with `BadRequest` naming the entry's id.
#[test]
fn a_refused_pattern_is_a_bad_request_naming_the_entry() {
    let (_d, r) = root();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r] }));
    let cases = [
        entry("dstar", "hide", format!("{}/**", r.display())),
        entry("dotdot", "hide", format!("{}/a/../b", r.display())),
        entry("rel", "hide", "notes/*"),
        entry("ssh", "show", r.join(".ssh")),
    ];
    for c in cases {
        let id = c["id"].as_str().unwrap().to_string();
        let e = h.call("spawn", json!({ "argv": ["true"], "cwd": r, "hideList": [c] })).unwrap_err();
        assert_eq!(e.0, "BadRequest", "{id}: {e:?}");
        assert!(e.1.contains(&id), "{id}: the message must name the entry: {e:?}");
    }
    h.close();
}

/// An entry with an unknown key, a missing key or an unknown effect is a `BadRequest`.
#[test]
fn a_malformed_entry_is_a_bad_request() {
    let (_d, r) = root();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r] }));
    let p = r.join("x").to_string_lossy().into_owned();
    let cases = [
        json!({ "id": "a", "effect": "hide", "pattern": p, "extra": 1 }),
        json!({ "id": "a", "effect": "hide" }),
        json!({ "id": "a", "pattern": p }),
        json!({ "effect": "hide", "pattern": p }),
        json!({ "id": "a", "effect": "allow", "pattern": p }),
    ];
    for c in cases {
        let e = h.call("spawn", json!({ "argv": ["true"], "cwd": r, "hideList": [c.clone()] })).unwrap_err();
        assert_eq!(e.0, "BadRequest", "{c}: {e:?}");
    }
    h.close();
}

// --- /files patterns ---

/// A `/files/...` pattern with no `files` arg holds nothing, and the spawn is not refused.
#[test]
fn a_files_pattern_without_a_files_arg_holds_nothing() {
    let (_d, r) = root();
    std::fs::write(r.join("a.txt"), "A\n").unwrap();
    let Some(mut h) = sandboxed(&r) else { return };
    let (f, out) = h.cat_all(&r, json!([entry("f1", "hide", "/files/*")]), &["a.txt"]);
    assert_eq!(out, "A\n");
    assert_eq!(f["hiddenSecrets"], json!([]), "{f}");
    h.close();
}

// --- the match bound ---

/// On Linux a hide matching more paths than a sandbox masks fails the spawn naming the entry.
#[cfg(target_os = "linux")]
#[test]
fn a_hide_over_the_match_bound_fails_the_spawn_on_linux() {
    let (_d, r) = root();
    for i in 0..300 {
        std::fs::write(r.join(format!("f{i}.txt")), "x").unwrap();
    }
    let Some(mut h) = sandboxed(&r) else { return };
    let e = h.call("spawn", json!({ "argv": ["true"], "cwd": r, "hideList": [entry("many", "hide", r.join("*"))] }));
    let e = e.unwrap_err();
    assert_eq!(e.0, "SandboxFailed", "{e:?}");
    assert!(e.1.contains("many"), "{e:?}");
    h.close();
}

/// On macOS the rule is a pattern, not a list of matches, so the same spawn succeeds.
#[cfg(target_os = "macos")]
#[test]
fn a_hide_over_the_match_bound_succeeds_on_macos() {
    let (_d, r) = root();
    for i in 0..300 {
        std::fs::write(r.join(format!("f{i}.txt")), "x").unwrap();
    }
    let Some(mut h) = sandboxed(&r) else { return };
    let (_f, d) = h.run(json!({ "argv": ["true"], "cwd": r, "hideList": [entry("many", "hide", r.join("*"))] }));
    assert_eq!(d["code"], 0, "{d}");
    h.close();
}
