//! stdio.rs — drives the built `wmlhost` binary over native messaging framing, the way the extension will: facts,
//! the verdict, the sandbox's denials, cancellation, time limits, held output read in ranges, the environment scrub.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::Duration;

use base64::Engine;
use serde_json::{Value, json};

struct Host {
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
        let mut c = Command::new(env!("CARGO_BIN_EXE_wmlhost"));
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
        Host { child, stdin, stdout, seq: 0, events: vec![] }
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
    let (_, d) = h.run(json!({ "argv": ["sh", "-c", "mkdir -p .vscode && echo x > .vscode/tasks.json"], "cwd": r }));
    let created = r.join(".vscode/tasks.json").exists();
    if cfg!(target_os = "macos") {
        assert_ne!(d["code"], 0);
        assert!(!created, "Seatbelt's regex covers a path that did not exist when the call started");
    } else {
        // bubblewrap re-binds read-only only what exists when the call starts (docs/SANDBOX.md, "Limits"). When this
        // starts failing, the gap is closed: make the assertion the macOS one and update SANDBOX.md.
        assert!(created, "the Linux gap documented in SANDBOX.md has closed; flip this test and the doc");
    }
    h.close();
}
