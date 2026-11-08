//! stdio.rs — drives the built `wmlhost` binary over native messaging framing, the way the extension will: facts,
//! the verdict, the sandbox's denials, cancellation, time limits, held output read in ranges, the environment scrub.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::Duration;

use base64::Engine;
use serde_json::{Value, json};
use sha2::Digest as _;

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
            // A name written `-NAME` removes NAME from the child's environment instead of setting it.
            match k.strip_prefix('-') {
                Some(name) => c.env_remove(name),
                None => c.env(k, v),
            };
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
    for n in [
        "PAGER",
        "GIT_EXTERNAL_DIFF",
        "LD_PRELOAD",
        "DYLD_INSERT_LIBRARIES",
        "GIT_CONFIG_COUNT",
        "PATH",
        "GH_TOKEN",
        "https_proxy",
        "SSL_CERT_FILE",
    ] {
        let e = h.call("spawn", json!({ "argv": ["true"], "cwd": r, "env": { n: "x" } })).unwrap_err();
        assert_eq!(e.0, "EnvRefused", "{n}");
    }
    let e = h
        .call("spawn", json!({ "argv": ["true"], "cwd": r, "env": { "API_TOKEN": { "$secret": "github" } } }))
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

// --- peek: the latest output of a call that is still running ---

impl Host {
    /// spawn + start, returning the id once the call is running.
    fn begin(&mut self, argv: &[&str], cwd: &Path) -> String {
        let id = self.ok("spawn", json!({ "argv": argv, "cwd": cwd, "timeoutMs": 20_000 }))["id"]
            .as_str()
            .unwrap()
            .to_string();
        self.ok("start", json!({ "id": id }));
        id
    }

    /// Peeks until `stream`'s size reaches `size` (at most 5 s), returning that answer.
    fn peek_until(&mut self, id: &str, args: Value, stream: &str, size: u64) -> Value {
        let mut args = args;
        args["id"] = json!(id);
        for _ in 0..100 {
            let v = self.ok("peek", args.clone());
            if v[stream]["size"].as_u64() == Some(size) {
                return v;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("{stream} never reached {size} bytes");
    }
}

fn peek_bytes(v: &Value) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(v["data"]["$bytes"].as_str().unwrap()).unwrap()
}

#[test]
fn hello_offers_peek() {
    let mut h = Host::start();
    assert_eq!(h.ok("hello", json!({}))["peek"], true);
    h.close();
}

#[test]
fn peek_shows_the_output_of_a_running_call() {
    let (_d, r) = root();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r] }));
    let id = h.begin(&["sh", "-c", "printf first; sleep 5"], &r);
    let v = h.peek_until(&id, json!({}), "stdout", 5);
    assert_eq!(v["id"], json!(id));
    assert_eq!(peek_bytes(&v["stdout"]), b"first");
    assert_eq!(v["stdout"]["truncated"], false);
    assert_eq!(v["stderr"]["size"], 0);
    assert_eq!(v["stderr"]["truncated"], false);
    assert_eq!(peek_bytes(&v["stderr"]), b"");
    h.ok("cancel", json!({ "id": id }));
    h.done(&id);
    h.close();
}

#[test]
fn bytes_bounds_the_tail_to_the_last_bytes() {
    let (_d, r) = root();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r] }));
    // 10000 bytes: 0..9 repeated per line, so the tail is recognisable.
    let id =
        h.begin(&["sh", "-c", "i=0; while [ $i -lt 1000 ]; do printf '012345678\\n'; i=$((i+1)); done; sleep 5"], &r);
    let v = h.peek_until(&id, json!({ "bytes": 100 }), "stdout", 10_000);
    assert_eq!(peek_bytes(&v["stdout"]), "012345678\n".repeat(10).into_bytes());
    // The default is 4096; a larger ask than the size returns it all.
    let v = h.peek_until(&id, json!({}), "stdout", 10_000);
    assert_eq!(peek_bytes(&v["stdout"]).len(), 4096);
    let v = h.ok("peek", json!({ "id": id, "bytes": 1_000_000 }));
    assert_eq!(peek_bytes(&v["stdout"]).len(), 10_000);
    h.ok("cancel", json!({ "id": id }));
    h.done(&id);
    h.close();
}

#[test]
fn bytes_past_max_read_is_clamped_without_a_hint() {
    let (_d, r) = root();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r], "outputCap": 2_000_000 }));
    let id = h.begin(&["sh", "-c", "head -c 700000 /dev/zero; sleep 5"], &r);
    let v = h.peek_until(&id, json!({ "bytes": 10_000_000 }), "stdout", 700_000);
    assert_eq!(peek_bytes(&v["stdout"]).len(), 512 * 1024, "clamped to MAX_READ");
    let mut keys: Vec<_> = v["stdout"].as_object().unwrap().keys().cloned().collect();
    keys.sort();
    assert_eq!(keys, ["data", "size", "truncated"], "no field says the ask was clamped");
    h.ok("cancel", json!({ "id": id }));
    h.done(&id);
    h.close();
}

#[test]
fn both_streams_at_the_cap_share_one_budget_and_the_answer_still_fits_a_message() {
    let (_d, r) = root();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r], "outputCap": 2_000_000 }));
    let id = h.begin(&["sh", "-c", "head -c 700000 /dev/zero; head -c 700000 /dev/zero >&2; sleep 5"], &r);
    h.peek_until(&id, json!({ "bytes": 1 }), "stderr", 700_000);
    // Each stream at 512 KiB would be ~1.4 MiB as base64, past the 1 MiB limit: the answer is the data, split.
    let v = h.ok("peek", json!({ "id": id, "bytes": 512 * 1024 }));
    let (o, e) = (peek_bytes(&v["stdout"]).len(), peek_bytes(&v["stderr"]).len());
    assert_eq!((o, e), (256 * 1024, 256 * 1024), "half each when both want more than half");
    assert_eq!((v["stdout"]["size"].as_u64(), v["stderr"]["size"].as_u64()), (Some(700_000), Some(700_000)));
    h.ok("cancel", json!({ "id": id }));
    h.done(&id);
    h.close();
}

#[test]
fn a_short_stream_leaves_the_rest_of_the_budget_to_the_other() {
    let (_d, r) = root();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r], "outputCap": 2_000_000 }));
    let id = h.begin(&["sh", "-c", "printf hello; head -c 700000 /dev/zero >&2; sleep 5"], &r);
    h.peek_until(&id, json!({ "bytes": 1 }), "stderr", 700_000);
    let v = h.ok("peek", json!({ "id": id, "bytes": 512 * 1024 }));
    assert_eq!(peek_bytes(&v["stdout"]), b"hello");
    assert_eq!(peek_bytes(&v["stderr"]).len(), 512 * 1024 - 5);
    h.ok("cancel", json!({ "id": id }));
    h.done(&id);
    h.close();
}

#[test]
fn peek_past_the_output_cap_is_truncated_at_the_cap() {
    let (_d, r) = root();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r], "outputCap": 1000 }));
    let id = h.begin(&["sh", "-c", "yes | head -c 100000; sleep 5"], &r);
    let v = h.peek_until(&id, json!({ "bytes": 10 }), "stdout", 1000);
    assert_eq!(v["stdout"]["truncated"], true);
    assert_eq!(peek_bytes(&v["stdout"]).len(), 10);
    h.ok("cancel", json!({ "id": id }));
    h.done(&id);
    h.close();
}

#[test]
fn peek_answers_only_for_a_running_call() {
    let (_d, r) = root();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r] }));
    assert_eq!(h.call("peek", json!({ "id": "c999" })).unwrap_err().0, "UnknownId");
    // Pending, not started.
    let pending = h.ok("spawn", json!({ "argv": ["true"], "cwd": r }))["id"].as_str().unwrap().to_string();
    assert_eq!(h.call("peek", json!({ "id": pending })).unwrap_err().0, "UnknownId");
    h.ok("discard", json!({ "id": pending }));
    // Ended: `done` has been seen.
    let (f, _d) = h.run(json!({ "argv": ["echo", "hi"], "cwd": r }));
    let ended = f["id"].as_str().unwrap();
    assert_eq!(h.call("peek", json!({ "id": ended })).unwrap_err().0, "UnknownId");
    h.close();
}

#[test]
fn peek_refuses_a_bad_bytes() {
    let (_d, r) = root();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r] }));
    let id = h.begin(&["sleep", "30"], &r);
    for bad in [json!(0), json!(-1), json!("x"), json!(1.5)] {
        let e = h.call("peek", json!({ "id": id, "bytes": bad })).unwrap_err();
        assert_eq!(e.0, "BadRequest", "bytes {bad}");
    }
    h.ok("peek", json!({ "id": id, "bytes": 1 }));
    h.ok("cancel", json!({ "id": id }));
    h.done(&id);
    h.close();
}

#[test]
fn a_piped_first_stage_has_no_stdout_to_peek() {
    let (_d, r) = root();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r] }));
    let ids = spawn_all(&mut h, &r, &[&["sh", "-c", "printf a >&2; sleep 5"], &["cat"]]);
    h.ok("pipe", json!({ "ids": ids }));
    let v = h.peek_until(&ids[0], json!({}), "stderr", 1);
    assert_eq!(v["stdout"], Value::Null);
    assert_eq!(peek_bytes(&v["stderr"]), b"a");
    let last = h.ok("peek", json!({ "id": ids[1] }));
    assert!(last["stdout"].is_object(), "the last stage's stdout is held: {last}");
    h.ok("cancel", json!({ "id": ids[0] }));
    h.done(&ids[0]);
    h.done(&ids[1]);
    h.close();
}

#[test]
fn another_connection_cannot_peek_at_this_ones_call() {
    let (_d, r) = root();
    let mut a = Host::start();
    let mut b = Host::start();
    a.ok("configure", json!({ "roots": [r] }));
    b.ok("configure", json!({ "roots": [r] }));
    let id = a.begin(&["sh", "-c", "printf mine; sleep 5"], &r);
    // The other session starts a call of its own, so an id of the same shape may exist there too.
    let other = b.begin(&["sleep", "5"], &r);
    let v = a.peek_until(&id, json!({}), "stdout", 4);
    assert_eq!(peek_bytes(&v["stdout"]), b"mine");
    if other != id {
        assert_eq!(b.call("peek", json!({ "id": id })).unwrap_err().0, "UnknownId");
    }
    let c = Host::start();
    let mut c = c;
    c.ok("configure", json!({ "roots": [r] }));
    assert_eq!(c.call("peek", json!({ "id": id })).unwrap_err().0, "UnknownId");
    for (h, i) in [(&mut a, &id), (&mut b, &other)] {
        h.ok("cancel", json!({ "id": i }));
        h.done(i);
    }
    a.close();
    b.close();
    c.close();
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
fn a_confined_call_that_runs_wmlhost_or_a_sandbox_tool_reaches_no_withheld_path() {
    // The call may exec any program, `wmlhost` and the sandbox tools included. None of them may widen what the
    // call's own sandbox withholds: the host's profile refuses a second `sandbox_apply`, Landlock and bubblewrap only
    // narrow, and a second host's call is the confined host's child. Found by the red-team session (2026-10-22).
    // Which vectors reach their write: macOS the second host and `install` (`sandbox-exec` dies in `sandbox_apply`,
    // `exec-under` is Linux-only, there is no `bwrap`); Linux all but `sandbox-exec`, which is absent.
    let (_d, r) = root();
    let (_o, outside) = root();
    let mut h = Host::start();
    if !h.sandbox_available() {
        return h.close();
    }
    h.ok("configure", json!({ "roots": [r] }));
    // Positive control: the confinement holds both ways, so the vectors below cannot pass vacuously.
    let (_, d) = h.run(json!({ "argv": ["touch", "inside"], "cwd": r }));
    assert_eq!(d["code"], 0, "{}", text(&h.read_all(&d["stderr"])));
    let (_, d) = h.run(json!({ "argv": ["touch", outside.join("pwned-ctl")], "cwd": r }));
    assert_ne!(d["code"], 0, "{d}");
    let wml = env!("CARGO_BIN_EXE_wmlhost");
    let o = outside.display();
    // A second host inside the call, told the outside is a root and not to sandbox: its frames, written ahead, one
    // file each. The host answers concurrently, so each is sent only once the previous answer is out (`w` waits on
    // the output, never on wall time); stdin stays open until `done` is. Its first spawn is `c1`.
    for (seq, call, args) in [
        (1, "hello", json!({})),
        (2, "configure", json!({ "roots": [r, outside], "sandbox": false })),
        (3, "spawn", json!({ "argv": ["touch", outside.join("pwned-v3")], "cwd": outside })),
        (4, "start", json!({ "id": "c1" })),
    ] {
        let b = serde_json::to_vec(&json!({ "seq": seq, "call": call, "args": args })).unwrap();
        std::fs::write(r.join(format!("f{seq}")), [&(b.len() as u32).to_ne_bytes()[..], &b].concat()).unwrap();
    }
    let ruleset = format!(r#"{{"abi":1,"exec":[],"writeEdit":[],"writeFiles":[],"writeTrees":["{o}"]}}"#);
    let vectors = [
        format!("/usr/bin/sandbox-exec -p '(version 1)(allow default)' touch {o}/pwned-v1"),
        format!("{wml} exec-under '{ruleset}' -- touch {o}/pwned-v2"),
        format!(
            "w() {{ i=0; until grep -aq \"$1\" second.out || [ $i -ge 600 ]; do sleep 0.1; i=$((i+1)); done; }}; \
             : > second.out; (cat f1; w '\"seq\":1'; cat f2; w '\"seq\":2'; cat f3; w '\"seq\":3'; cat f4; \
             w '\"event\":\"done\"') | WMLHOST_STATE_DIR=\"$TMPDIR/owners\" {wml} \
             chrome-extension://abcdefghijklmnopabcdefghijklmnop/ > second.out"
        ),
        format!("bwrap --bind / / touch {o}/pwned-v4"),
        // A new bind of the withheld path itself; bwrap and the kernel keep it read-only (the controls below show it
        // mounts, so the refusal is the write's). Then an explicit read-write remount of it.
        format!("bwrap --bind / / --bind {o} {o} touch {o}/pwned-v5"),
        format!("bwrap --bind / / --cap-add ALL sh -c 'mount -o remount,bind,rw {o} && touch {o}/pwned-v6'"),
        format!("HOME={o} {wml} install --extension-id aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
    ];
    // Whether a nested bwrap starts, and mounts the re-bind, decides whether the bwrap vectors reach their write.
    if cfg!(target_os = "linux") && std::env::var("WMLHOST_REQUIRE_SANDBOX").as_deref() == Ok("1") {
        for control in ["bwrap --bind / / true".to_string(), format!("bwrap --bind / / --bind {o} {o} true")] {
            let (_, d) = h.run(json!({ "argv": ["sh", "-c", control], "cwd": r }));
            assert_eq!(
                d["code"],
                0,
                "{control} must run here, or a bwrap vector tests nothing: {}",
                text(&h.read_all(&d["stderr"]))
            );
        }
    }
    for script in &vectors {
        // A vector may fail for any reason; what matters is that nothing appears outside.
        let (_, d) = h.run(json!({ "argv": ["sh", "-c", script], "cwd": r }));
        let names: Vec<_> = std::fs::read_dir(&outside).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert!(names.is_empty(), "{script} wrote outside the roots: {names:?} {d}");
    }
    // The second host did run and answer, and its call ended failed: the outside stayed withheld from it.
    let (out, mut frames) = (std::fs::read(r.join("second.out")).unwrap(), vec![]);
    let mut rest = &out[..];
    while rest.len() >= 4 {
        let n = u32::from_ne_bytes(rest[..4].try_into().unwrap()) as usize;
        frames.push(serde_json::from_slice::<Value>(&rest[4..4 + n]).unwrap());
        rest = &rest[4 + n..];
    }
    let done = frames.iter().find(|f| f["event"] == "done" && f["id"] == "c1");
    assert_eq!(done.map(|d| &d["ok"]), Some(&json!(false)), "{frames:?}");
    if cfg!(target_os = "macos") {
        // Its own probe is a second `sandbox-exec`, refused inside the profile: it reports no sandbox (SANDBOX.md).
        let hello = frames.iter().find(|f| f["seq"] == 1).expect("hello answered");
        assert_eq!(hello["value"]["sandbox"]["available"], false, "{hello}");
    }
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
    // No repository encloses cwd, so no repository config runs code: false, not null (null is "could not tell").
    assert_eq!(f["repoConfigRunsCode"], false);
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
fn a_symlink_argument_reports_the_link_and_both_ends_must_be_in_a_root() {
    let (_d, r) = root();
    let (_o, out) = root();
    std::fs::create_dir_all(r.join("src/gen")).unwrap();
    std::os::unix::fs::symlink(r.join("src/gen"), r.join("top")).unwrap();
    std::os::unix::fs::symlink(r.join("src/gen"), out.join("in")).unwrap();
    std::os::unix::fs::symlink(r.join("src/gen"), r.join(".env")).unwrap();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r] }));
    let spawn =
        |h: &mut Host, a: &str| h.ok("spawn", json!({ "argv": ["rm", a], "cwd": r, "pathArgs": [{ "arg": 1 }] }));
    let f = spawn(&mut h, "top");
    // rm removes the link /top, a top-level name, though its target is nested: the worker places both.
    assert_eq!(f["paths"][0]["path"], json!(r.join("src/gen")));
    assert_eq!(f["paths"][0]["link"], json!(r.join("top")));
    assert_eq!(f["paths"][0]["inRoot"], true);
    let f = spawn(&mut h, out.join("in").to_str().unwrap());
    assert_eq!(f["paths"][0]["inRoot"], false, "a link outside the roots to a target inside them");
    assert_eq!(spawn(&mut h, ".env")["paths"][0]["secret"], true, "a link named like a secret");
    assert!(spawn(&mut h, "src/gen")["paths"][0].get("link").is_none(), "not a link");
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
fn write_roots_holds_every_existing_protected_name_read_only() {
    // Enumerates the sandbox's own list. Each name exists as a file (`.git/hooks` as a directory); appending to it in
    // place is what the root's Landlock WriteFile|Truncate allows, so on Linux only the read-only re-bind stops it.
    let (_d, r) = root();
    std::fs::create_dir_all(r.join(".git/hooks")).unwrap();
    let rels: Vec<String> = window_ml_host::sandbox::protected_rels().collect();
    for rel in &rels {
        if rel != ".git/hooks" {
            std::fs::write(r.join(rel), "kept\n").unwrap();
        }
    }
    let mut h = Host::start();
    if !h.sandbox_available() {
        return h.close();
    }
    h.ok("configure", json!({ "roots": [r] }));
    if cfg!(target_os = "linux") && landlock_abi(&mut h).is_none() {
        return h.close();
    }
    for rel in &rels {
        if rel == ".git/hooks" {
            let d = roots_envelope(&mut h, &r, "echo x > .git/hooks/pre-commit");
            assert_ne!(d["code"], 0, "write: roots created a hook: {d}");
            assert!(!r.join(".git/hooks/pre-commit").exists(), "a hook appeared");
            continue;
        }
        let d = roots_envelope(&mut h, &r, &format!("echo x >> {rel}"));
        assert_ne!(d["code"], 0, "write: roots appended to {rel}: {d}");
        assert_eq!(std::fs::read_to_string(r.join(rel)).unwrap(), "kept\n", "{rel} was written in place");
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
    // The first call's marker is still there: without removing it, marker_call returns before THIS call's shell has
    // started, and the port closes while the sandbox is still coming up.
    std::fs::remove_file(r.join("started")).unwrap();
    marker_call(&mut h, &r, 3, json!({ "onOwnerLoss": "orphan", "orphanTimeoutMs": 500 }));
    let t = std::time::Instant::now();
    h.close();
    let closed_in = t.elapsed();
    let ledgers = |d: &Path| -> Vec<(String, String)> {
        std::fs::read_dir(d).map_or(vec![], |rd| {
            rd.flatten()
                .map(|e| {
                    (
                        e.file_name().to_string_lossy().into_owned(),
                        std::fs::read_to_string(e.path()).unwrap_or_default(),
                    )
                })
                .collect()
        })
    };
    let at_close = ledgers(&dir);
    std::thread::sleep(Duration::from_millis(4000));
    if r.join("late").exists() {
        let ps = Command::new("ps").args(["-eo", "pid,ppid,pgid,sid,etime,args"]).output().map(|o| text(&o.stdout));
        panic!(
            "the orphan outlived its deadline\nhost exited {closed_in:?} after the port closed\nledgers at close: \
             {at_close:#?}\nledgers now: {:#?}\nps:\n{}",
            ledgers(&dir),
            ps.unwrap_or_default()
        );
    }
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

// --- the ended record: a call nobody heard end, reported once to the next session ---

#[test]
fn an_orphan_killed_at_its_deadline_is_reported_once_to_the_next_session() {
    let (_d, r) = root();
    let state = tempfile::tempdir().unwrap();
    let dir = state.path().join("owners");
    let mut h = Host::start_in(&dir, &[]);
    h.ok("configure", json!({ "roots": [r] }));
    let owner = json!({ "run": "r7", "step": 2 });
    marker_call(&mut h, &r, 30, json!({ "owner": owner, "onOwnerLoss": "orphan", "orphanTimeoutMs": 1500 }));
    h.close();
    // After the port closed, with no session to ask `status`: the change K3b leaves unreported.
    std::fs::create_dir(r.join(".vscode")).unwrap();
    std::thread::sleep(Duration::from_millis(3500));

    let mut next = Host::start_in(&dir, &[]);
    let st = next.ok("status", json!({}));
    assert_eq!(st["orphans"], json!([]), "killed at its deadline: {st}");
    let ended = st["ended"].as_array().unwrap();
    assert_eq!(ended.len(), 1, "{st}");
    let e = &ended[0];
    assert_eq!((e["cause"].as_str(), e["killed"].as_bool()), (Some("deadline"), Some(true)), "{e}");
    assert_eq!(e["owner"], owner);
    assert!(e["deadlineMs"].as_u64().unwrap() <= e["endedMs"].as_u64().unwrap(), "{e}");
    assert_eq!(changes(&e["protectedChanged"]), vec![(".vscode".into(), "created".into())], "{e}");
    let again = next.ok("status", json!({}));
    assert_eq!(again["ended"], json!([]), "returned once: {again}");
    next.close();
    let mut third = Host::start_in(&dir, &[]);
    assert_eq!(third.ok("status", json!({}))["ended"], json!([]), "and to no later session");
    third.close();
}

#[test]
fn a_call_killed_with_its_port_is_reported_to_the_next_session() {
    let (_d, r) = root();
    let state = tempfile::tempdir().unwrap();
    let dir = state.path().join("owners");
    let mut h = Host::start_in(&dir, &[]);
    h.ok("configure", json!({ "roots": [r] }));
    marker_call(&mut h, &r, 30, json!({ "owner": { "run": "r8" } }));
    // While the call runs (the sandbox may refuse the call itself this name): `done` would have reported it.
    std::fs::create_dir(r.join(".vscode")).unwrap();
    h.close();
    let mut next = Host::start_in(&dir, &[]);
    let st = next.ok("status", json!({}));
    let ended = st["ended"].as_array().unwrap();
    assert_eq!(ended.len(), 1, "{st}");
    assert_eq!(ended[0]["cause"], "owner-lost", "{st}");
    assert_eq!(ended[0]["deadlineMs"], json!(null));
    assert_eq!(changes(&ended[0]["protectedChanged"]), vec![(".vscode".into(), "created".into())]);
    next.close();
}

#[test]
fn a_session_with_nothing_ended_lists_an_empty_ended() {
    let mut h = Host::start();
    let st = h.ok("status", json!({}));
    assert_eq!(st["ended"], json!([]), "present and empty: absent means an older host: {st}");
    assert!(st.get("endedMore").is_none() && st.get("endedDropped").is_none());
    h.close();
}

#[test]
fn a_sandboxed_call_cannot_touch_the_state_dir() {
    let (_d, r) = root();
    let mut h = Host::start();
    if !h.sandbox_available() {
        return h.close();
    }
    let dir = h.state.as_ref().unwrap().path().join("owners");
    assert!(dir.is_dir(), "the host made its state dir");
    h.ok("configure", json!({ "roots": [r] }));
    let forged = dir.join("1-1.c1.ended");
    let (_, d) = h.run(json!({ "argv": ["sh", "-c", format!("echo '{{}}' > '{}'", forged.display())], "cwd": r }));
    assert_ne!(d["code"], 0, "{d}");
    assert!(!forged.exists(), "a sandboxed call wrote into the ledger directory");
    h.close();
}

// --- register: a group a session started itself, owned by what the connection declares ---

/// A process group this test starts itself, as a harness would: `sh -c <script>` leading a group of its own.
fn own_group(script: &str) -> Child {
    use std::os::unix::process::CommandExt;
    Command::new("sh").args(["-c", script]).process_group(0).spawn().unwrap()
}

/// SIGKILL to a group this test started, and its reaping.
fn kill_group(mut c: Child) {
    let _ = Command::new("kill").args(["-KILL", &format!("-{}", c.id())]).status();
    let _ = c.wait();
}

/// The pid of `parent`'s child, once it has one.
fn child_of(parent: u32) -> u32 {
    let end = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let out = Command::new("pgrep").args(["-P", &parent.to_string()]).output().unwrap();
        if let Some(p) = text(&out.stdout).lines().next().and_then(|l| l.trim().parse().ok()) {
            return p;
        }
        assert!(std::time::Instant::now() < end, "{parent} never started a child");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_registered_group_is_a_row_its_members_answer_owner_and_its_end_is_a_done() {
    let mut h = Host::start();
    let hello = h.ok("hello", json!({}));
    assert_eq!(hello["owners"]["register"], true, "{hello}");
    assert!(hello["cpu"]["metric"].is_string(), "{hello}");
    let g = own_group("sleep 30 & wait");
    let leader = g.id();
    let sleeper = child_of(leader);
    let owner = json!({ "session": "abc123", "harness": "claude-code" });
    let r = h.ok("register", json!({ "pgid": leader, "owner": owner }));
    let id = r["id"].as_str().unwrap().to_string();
    assert_eq!(r["pid"], leader);
    let st = h.ok("status", json!({}));
    let row = st["running"].as_array().unwrap().iter().find(|c| c["id"] == json!(id)).cloned().expect("listed");
    assert_eq!(row["kind"], "registered");
    assert_eq!(row["owner"], owner);
    assert!(row["cpuMs"].is_u64(), "{row}");
    // Its output is not ours to hold, so a peek of it answers no stream.
    let p = h.ok("peek", json!({ "id": id }));
    assert_eq!(p, json!({ "id": id, "stdout": null, "stderr": null }), "{p}");
    // The leader and a descendant both answer with the declared owner; this test process is in no row.
    for pid in [leader, sleeper] {
        let o = h.ok("owner", json!({ "pid": pid }));
        assert_eq!(o["owner"], owner, "{pid}: {o}");
        assert_eq!(
            (o["kind"].as_str(), o["host"].as_str(), o["id"].as_str()),
            (Some("registered"), Some("this"), Some(&*id))
        );
    }
    assert_eq!(h.ok("owner", json!({ "pid": std::process::id() })), json!({ "owner": null }), "nobody's");
    // The group ends by another hand: the host is not its parent, so `done` says it ended and nothing of how.
    kill_group(g);
    let d = h.done(&id);
    assert_eq!(d["registered"], true, "{d}");
    assert_eq!((d["code"].clone(), d["ok"].clone(), d["killed"].clone()), (Value::Null, Value::Null, Value::Null));
    assert!(d["cpuMs"].is_u64(), "{d}");
    assert_eq!(h.ok("status", json!({}))["running"], json!([]));
    h.close();
}

#[test]
fn register_refuses_the_host_s_own_group_init_a_gone_group_a_bad_owner_and_a_group_already_owned() {
    let (_d, r) = root();
    let mut h = Host::start();
    let owner = json!({ "session": "s" });
    let bad = |h: &mut Host, args: Value| h.call("register", args).unwrap_err().0;
    // The host runs in this test's group: registering it would let the port closing kill the host and its parent.
    let mine = Command::new("ps").args(["-o", "pgid=", "-p", &std::process::id().to_string()]).output().unwrap();
    let mine: u32 = text(&mine.stdout).trim().parse().unwrap();
    assert_eq!(bad(&mut h, json!({ "pgid": mine, "owner": owner })), "BadRequest");
    assert_eq!(bad(&mut h, json!({ "pgid": 1, "owner": owner })), "BadRequest");
    let mut gone = Command::new("true").spawn().unwrap();
    let gone_id = gone.id();
    gone.wait().unwrap();
    assert_eq!(bad(&mut h, json!({ "pgid": gone_id, "owner": owner })), "BadRequest");
    let g = own_group("sleep 30");
    for o in [Value::Null, json!("s"), json!({ "s": "x".repeat(2000) })] {
        assert_eq!(bad(&mut h, json!({ "pgid": g.id(), "owner": o })), "BadRequest", "owner {o}");
    }
    h.ok("register", json!({ "pgid": g.id(), "owner": owner }));
    assert_eq!(bad(&mut h, json!({ "pgid": g.id(), "owner": owner })), "BadRequest", "registered twice");
    // A group this host spawned is already its row, and a second host sharing the state dir sees the first's rows.
    h.ok("configure", json!({ "roots": [r], "sandbox": false }));
    let f = h.ok("spawn", json!({ "argv": ["sleep", "30"], "cwd": r }));
    let started = h.ok("start", json!({ "id": f["id"] }));
    assert_eq!(bad(&mut h, json!({ "pgid": started["pid"], "owner": owner })), "BadRequest");
    let dir = h.state.as_ref().unwrap().path().join("owners");
    let mut other = Host::start_in(&dir, &[]);
    assert_eq!(bad(&mut other, json!({ "pgid": g.id(), "owner": owner })), "BadRequest", "another host's row");
    let o = other.ok("owner", json!({ "pid": g.id() }));
    assert_eq!((o["owner"].clone(), o["host"].as_str()), (owner.clone(), Some("other")), "{o}");
    other.close();
    h.close();
    // Registered under the default policy, so it died with the port.
    let mut g = g;
    assert!(!g.wait().unwrap().success());
}

#[test]
fn a_registered_group_dies_with_its_port_by_default_and_an_orphan_is_listed_to_the_next_host() {
    let state = tempfile::tempdir().unwrap();
    let dir = state.path().join("owners");
    let mut h = Host::start_in(&dir, &[]);
    let killed = own_group("sleep 30");
    let kept = own_group("sleep 30");
    let owner = json!({ "session": "s2", "harness": "claude-code" });
    h.ok("register", json!({ "pgid": killed.id(), "owner": owner }));
    h.ok("register", json!({ "pgid": kept.id(), "owner": owner, "onOwnerLoss": "orphan", "orphanTimeoutMs": 60_000 }));
    let (killed_pid, kept_pid) = (killed.id(), kept.id());
    h.close();
    let mut next = Host::start_in(&dir, &[]);
    let st = next.ok("status", json!({}));
    let orphans = st["orphans"].as_array().unwrap();
    assert_eq!(orphans.len(), 1, "{st}");
    assert_eq!((orphans[0]["pid"].as_u64(), orphans[0]["kind"].as_str()), (Some(kept_pid as u64), Some("registered")));
    assert!(orphans[0]["cpuMs"].is_u64(), "{st}");
    let ended = st["ended"].as_array().unwrap();
    let rec = ended.iter().find(|e| e["cause"] == "owner-lost").unwrap_or_else(|| panic!("{st}"));
    assert_eq!((rec["kind"].as_str(), rec["killed"].as_bool()), (Some("registered"), Some(true)));
    let o = next.ok("owner", json!({ "pid": kept_pid }));
    assert_eq!((o["host"].as_str(), o["orphan"].as_bool()), (Some("other"), Some(true)), "{o}");
    next.close();
    // Reaped here: the test is their parent, so a killed one is a zombie until waited for.
    let mut killed = killed;
    let status = killed.wait().unwrap();
    assert!(!status.success(), "the registered group was killed when its port closed");
    assert!(Command::new("kill").args(["-0", &kept_pid.to_string()]).status().unwrap().success(), "the orphan runs");
    let _ = killed_pid;
    kill_group(kept);
}

#[test]
fn a_registered_group_past_its_memory_bound_is_killed_and_one_cancelled_ends_with_it() {
    let mut h = Host::start();
    let mut c = {
        use std::os::unix::process::CommandExt;
        let a = allocator(1024);
        Command::new(&a[0]).args(&a[1..]).process_group(0).spawn().unwrap()
    };
    let bound: u64 = 128 << 20;
    let r = h.ok("register", json!({ "pgid": c.id(), "owner": { "session": "s" }, "memoryBound": bound }));
    let d = h.done(r["id"].as_str().unwrap());
    assert_eq!(d["killed"], "oom", "{d}");
    let peak = d["peakFootprint"].as_u64().unwrap();
    assert!(peak > bound && peak < 768 << 20, "killed soon after the bound: {peak}");
    assert!(!c.wait().unwrap().success());

    let g = own_group("sleep 30");
    let r = h.ok("register", json!({ "pgid": g.id(), "owner": { "session": "s" } }));
    let id = r["id"].as_str().unwrap().to_string();
    assert_eq!(h.ok("cancel", json!({ "id": id })), json!({ "signalled": true }));
    let d = h.done(&id);
    assert_eq!(d["cancelled"], true, "{d}");
    let mut g = g;
    assert!(!g.wait().unwrap().success(), "a cancelled group is signalled");
    h.close();
}

#[test]
fn a_spawned_call_s_done_carries_its_cpu_time() {
    let (_d, r) = root();
    let mut h = Host::start();
    h.ok("configure", json!({ "roots": [r], "sandbox": false }));
    let (_, d) = h.run(json!({ "argv": ["perl", "-e", "my $t = time + 2; while (time < $t) {}"], "cwd": r }));
    assert_eq!(d["ok"], true, "{d}");
    let cpu = d["cpuMs"].as_u64().unwrap();
    assert!(cpu >= 500, "about a second of spinning, sampled every 100 ms: {cpu} ms");
    h.close();
}

// --- tilde: a leading `~` in argv and cwd becomes HOME before anything is resolved ---

/// A host whose HOME is `home`, configured with `roots`.
fn tilde_host(home: &Path, roots: &[&Path]) -> Host {
    let mut h = Host::start_with_env(&[("HOME", home.to_str().unwrap())]);
    h.ok("configure", json!({ "roots": roots }));
    h
}

/// The facts of `argv` (run in `cwd`) on a host whose HOME is `home` and whose only root is `r`.
fn tilde_facts(home: &Path, r: &Path, argv: Value) -> Value {
    let mut h = tilde_host(home, &[r]);
    let f = h.ok("spawn", json!({ "argv": argv, "cwd": r }));
    h.close();
    f
}

#[test]
fn hello_offers_tilde() {
    let mut h = Host::start();
    assert_eq!(h.ok("hello", json!({}))["tilde"], true);
    h.close();
}

#[test]
fn tilde_is_always_present_and_empty_when_nothing_expanded() {
    let (_d, r) = root();
    let f = tilde_facts(&r, &r, json!(["echo", "plain"]));
    assert_eq!(f["tilde"], json!([]));
}

#[test]
fn a_tilde_operand_expands_and_the_facts_say_so() {
    let (_d, r) = root();
    let f = tilde_facts(&r, &r, json!(["echo", "~/x"]));
    let to = format!("{}/x", r.display());
    assert_eq!(f["argv"], json!(["echo", to]));
    assert_eq!(f["tilde"], json!([{ "index": 1, "from": "~/x", "to": to }]));
}

#[test]
fn a_lone_tilde_expands_to_home() {
    let (_d, r) = root();
    let f = tilde_facts(&r, &r, json!(["echo", "~"]));
    assert_eq!(f["argv"][1], json!(r));
    assert_eq!(f["tilde"], json!([{ "index": 1, "from": "~", "to": r }]));
}

#[test]
fn a_tilde_in_argv_zero_resolves_the_program_under_home() {
    let (_d, r) = root();
    std::fs::create_dir(r.join("bin")).unwrap();
    let tool = r.join("bin/tool");
    std::fs::write(&tool, "#!/bin/sh\necho hi\n").unwrap();
    std::fs::set_permissions(&tool, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    let f = tilde_facts(&r, &r, json!(["~/bin/tool"]));
    assert_eq!(f["program"]["path"], json!(tool));
    assert_eq!(f["tilde"][0]["index"], 0);
    assert_eq!(f["tilde"][0]["from"], "~/bin/tool");
}

#[test]
fn a_tilde_cwd_expands_and_must_still_lie_in_a_root() {
    let (_d, r) = root();
    std::fs::create_dir(r.join("proj")).unwrap();
    let mut h = tilde_host(&r, &[&r]);
    let f = h.ok("spawn", json!({ "argv": ["true"], "cwd": "~/proj" }));
    assert_eq!(f["cwd"]["path"], json!(r.join("proj")));
    assert_eq!(f["tilde"], json!([{ "index": "cwd", "from": "~/proj", "to": r.join("proj") }]));
    h.close();
}

#[test]
fn a_tilde_cwd_outside_the_roots_is_cwd_outside_roots() {
    let (_d, r) = root();
    let (_o, home) = root();
    std::fs::create_dir(home.join("outside")).unwrap();
    let mut h = tilde_host(&home, &[&r]);
    for cwd in ["~/outside", "~"] {
        let e = h.call("spawn", json!({ "argv": ["true"], "cwd": cwd })).unwrap_err();
        assert_eq!(e.0, "CwdOutsideRoots", "{cwd}");
    }
    h.close();
}

/// `arg` stays as written, with no tilde entry, while HOME is usable.
fn assert_literal(arg: &str) {
    let (_d, r) = root();
    let f = tilde_facts(&r, &r, json!(["echo", arg]));
    assert_eq!(f["argv"][1], arg);
    assert_eq!(f["tilde"], json!([]), "{arg}");
}

#[test]
fn tilde_user_stays_literal() {
    assert_literal("~user");
    assert_literal("~user/x");
}

#[test]
fn a_tilde_inside_a_word_stays_literal() {
    assert_literal("a~b");
}

#[test]
fn a_tilde_after_a_slash_or_a_word_slash_stays_literal() {
    assert_literal("a~/b");
    assert_literal("x/~");
}

#[test]
fn a_tilde_after_an_equals_sign_stays_literal() {
    assert_literal("--flag=~/x");
    assert_literal("x=~/a");
}

#[test]
fn double_tilde_and_tilde_space_stay_literal() {
    assert_literal("~~");
    assert_literal("~ ");
}

#[test]
fn without_a_usable_home_the_argument_stays_literal_with_a_reason() {
    let (_d, r) = root();
    for (env, reason) in
        [(("-HOME", ""), "no-home"), (("HOME", ""), "no-home"), (("HOME", "rel/home"), "home-not-absolute")]
    {
        let mut h = Host::start_with_env(&[env]);
        h.ok("configure", json!({ "roots": [r] }));
        let f = h.ok("spawn", json!({ "argv": ["echo", "~/x", "~"], "cwd": r }));
        assert_eq!(f["argv"], json!(["echo", "~/x", "~"]), "{env:?}");
        assert_eq!(
            f["tilde"],
            json!([
                { "index": 1, "from": "~/x", "to": null, "reason": reason },
                { "index": 2, "from": "~", "to": null, "reason": reason },
            ]),
            "{env:?}"
        );
        h.close();
    }
}

#[test]
fn a_tilde_cwd_without_home_is_a_bad_request() {
    let (_d, r) = root();
    let mut h = Host::start_with_env(&[("-HOME", "")]);
    h.ok("configure", json!({ "roots": [r] }));
    let e = h.call("spawn", json!({ "argv": ["true"], "cwd": "~/p" })).unwrap_err();
    assert_eq!(e.0, "BadRequest");
    h.close();
}

#[test]
fn the_child_receives_the_expanded_argument() {
    let (_d, r) = root();
    let mut h = tilde_host(&r, &[&r]);
    let (f, d) = h.run(json!({ "argv": ["echo", "~/x", "~y"], "cwd": r }));
    assert_eq!(text(&h.read_all(&d["stdout"])), format!("{}/x ~y\n", r.display()));
    assert_eq!(f["argv"][1], json!(format!("{}/x", r.display())));
    h.close();
}

#[test]
fn a_path_operand_with_a_tilde_resolves_under_home_and_agrees_with_argv() {
    let (_d, r) = root();
    std::fs::write(r.join("notes.txt"), "x").unwrap();
    let mut h = tilde_host(&r, &[&r]);
    let f = h.ok("spawn", json!({ "argv": ["cat", "~/notes.txt"], "cwd": r, "pathArgs": [{ "arg": 1 }] }));
    let want = r.join("notes.txt");
    assert_eq!(f["argv"][1], json!(want));
    assert_eq!(f["paths"][0]["given"], json!(want), "given is the expanded string; tilde holds the original");
    assert_eq!(f["paths"][0]["path"], json!(want));
    assert_eq!(f["paths"][0]["inRoot"], true);
    assert_eq!(f["paths"][0]["secret"], false);
    assert_eq!(f["paths"][0]["exists"], true);
    assert_eq!(f["tilde"][0]["from"], "~/notes.txt");
    h.close();
}

#[test]
fn a_tilde_ssh_config_operand_is_judged_at_its_real_path() {
    let (_d, r) = root();
    let (_o, home) = root();
    std::fs::create_dir(home.join(".ssh")).unwrap();
    std::fs::write(home.join(".ssh/config"), "Host *").unwrap();
    let mut h = tilde_host(&home, &[&r]);
    let f = h.ok("spawn", json!({ "argv": ["cat", "~/.ssh/config"], "cwd": r, "pathArgs": [{ "arg": 1 }] }));
    let p = &f["paths"][0];
    assert_eq!(p["path"], json!(home.join(".ssh/config")));
    assert_eq!(p["secret"], true);
    assert_eq!(p["inRoot"], false);
    h.close();
}

// --- put / write / commit: bytes to a file in a root ---

/// A host whose HOME is `home` and whose only root is `r`.
fn put_host(home: &Path, r: &Path) -> Host {
    tilde_host(home, &[r])
}

fn b64(b: &[u8]) -> Value {
    json!({ "$bytes": base64::engine::general_purpose::STANDARD.encode(b) })
}

/// The `.wmlhost-put-*` files directly in `dir`.
fn leftovers(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
                .filter(|n| n.starts_with(".wmlhost-put-"))
                .collect()
        })
        .unwrap_or_default()
}

fn code(r: Result<Value, (String, String)>) -> String {
    match r {
        Ok(v) => format!("ok {v}"),
        Err((c, _)) => c,
    }
}

/// put + write in 3 chunks of at most `chunk` bytes; the put's facts.
fn put_all(h: &mut Host, path: &str, cwd: &Path, data: &[u8], chunk: usize) -> Value {
    let f = h.ok("put", json!({ "path": path, "cwd": cwd, "size": data.len() }));
    let id = f["id"].as_str().unwrap().to_string();
    let mut off = 0;
    for c in data.chunks(chunk.max(1)) {
        let w = h.ok("write", json!({ "id": id, "offset": off, "bytes": b64(c) }));
        off += c.len();
        assert_eq!(w["received"], off);
    }
    f
}

#[test]
fn hello_reports_the_put_cap() {
    let mut h = Host::start();
    assert_eq!(h.ok("hello", json!({}))["put"], json!({ "max": 64 << 20 }));
    h.close();
}

#[test]
fn a_new_file_arrives_byte_for_byte_over_several_chunks() {
    let (_d, r) = root();
    std::fs::create_dir(r.join("inbox")).unwrap();
    let mut h = put_host(&r, &r);
    let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let f = put_all(&mut h, "inbox/report.bin", &r, &data, 100_000);
    assert_eq!(f["path"], json!(r.join("inbox/report.bin")));
    assert_eq!((f["root"].clone(), f["rel"].clone()), (json!(r), json!("inbox/report.bin")));
    assert_eq!(
        (f["exists"].clone(), f["existingSize"].clone(), f["size"].clone()),
        (json!(false), Value::Null, json!(300_000))
    );
    assert!(!r.join("inbox/report.bin").exists(), "put writes nothing");
    let id = f["id"].as_str().unwrap();
    let c = h.ok("commit", json!({ "id": id }));
    assert_eq!(c["rel"], "inbox/report.bin");
    assert_eq!(c["size"], 300_000);
    assert_eq!(c["path"], json!(r.join("inbox/report.bin")));
    assert_eq!(c["sha256"], hex::encode(sha2::Sha256::digest(&data)));
    assert_eq!(std::fs::read(r.join("inbox/report.bin")).unwrap(), data);
    // 0666 less the umask: group/other never get more than the umask leaves, and never execute.
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(r.join("inbox/report.bin")).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode & !0o666, 0, "{mode:o}");
    assert_eq!(mode & 0o600, 0o600, "{mode:o}");
    assert!(leftovers(&r.join("inbox")).is_empty());
    assert_eq!(code(h.call("commit", json!({ "id": id }))), "UnknownId", "a commit consumes the put");
    h.close();
}

#[test]
fn an_empty_file_commits_without_any_chunk() {
    let (_d, r) = root();
    let mut h = put_host(&r, &r);
    let f = h.ok("put", json!({ "path": "empty", "cwd": r, "size": 0 }));
    let c = h.ok("commit", json!({ "id": f["id"] }));
    assert_eq!(c["sha256"], hex::encode(sha2::Sha256::digest(b"")));
    assert_eq!(std::fs::read(r.join("empty")).unwrap(), b"");
    h.close();
}

#[test]
fn an_existing_file_is_reported_and_commit_without_replace_refuses_and_leaves_it() {
    let (_d, r) = root();
    std::fs::write(r.join("a.txt"), b"original").unwrap();
    let mut h = put_host(&r, &r);
    let f = put_all(&mut h, "a.txt", &r, b"new", 10);
    assert_eq!((f["exists"].clone(), f["existingSize"].clone()), (json!(true), json!(8)));
    assert_eq!(code(h.call("commit", json!({ "id": f["id"], "replace": false }))), "Exists");
    assert_eq!(std::fs::read(r.join("a.txt")).unwrap(), b"original");
    assert!(leftovers(&r).is_empty(), "a failed commit deletes its temp file");
    h.close();
}

#[test]
fn a_file_created_between_put_and_commit_is_exists_without_replace() {
    let (_d, r) = root();
    let mut h = put_host(&r, &r);
    let f = put_all(&mut h, "late.txt", &r, b"mine", 10);
    assert_eq!(f["exists"], false);
    std::fs::write(r.join("late.txt"), b"theirs").unwrap();
    assert_eq!(code(h.call("commit", json!({ "id": f["id"] }))), "Exists");
    assert_eq!(std::fs::read(r.join("late.txt")).unwrap(), b"theirs");
    assert!(leftovers(&r).is_empty());
    h.close();
}

#[test]
fn replace_true_overwrites() {
    let (_d, r) = root();
    std::fs::write(r.join("a.txt"), b"original").unwrap();
    let mut h = put_host(&r, &r);
    let f = put_all(&mut h, "a.txt", &r, b"replacement", 4);
    h.ok("commit", json!({ "id": f["id"], "replace": true }));
    assert_eq!(std::fs::read(r.join("a.txt")).unwrap(), b"replacement");
    assert!(leftovers(&r).is_empty());
    h.close();
}

#[test]
fn a_missing_parent_is_no_parent_and_nothing_is_created() {
    let (_d, r) = root();
    let mut h = put_host(&r, &r);
    assert_eq!(code(h.call("put", json!({ "path": "no/such/x", "cwd": r, "size": 1 }))), "NoParent");
    assert_eq!(code(h.call("put", json!({ "path": r.join("nodir/x"), "size": 1 }))), "NoParent");
    std::fs::write(r.join("file"), b"").unwrap();
    assert_eq!(
        code(h.call("put", json!({ "path": "file/x", "cwd": r, "size": 1 }))),
        "NoParent",
        "a file is no parent"
    );
    assert_eq!(std::fs::read_dir(&r).unwrap().count(), 1, "only the file we made");
    h.close();
}

#[test]
fn a_parent_outside_the_roots_is_refused_however_it_is_reached() {
    let (_d, r) = root();
    let (_o, other) = root();
    std::fs::create_dir(r.join("w")).unwrap();
    std::os::unix::fs::symlink(&other, r.join("w/out")).unwrap();
    let mut h = put_host(&r, &r.join("w"));
    let w = r.join("w");
    assert_eq!(code(h.call("put", json!({ "path": "../x", "cwd": w, "size": 1 }))), "OutsideRoots");
    assert_eq!(code(h.call("put", json!({ "path": other.join("x"), "size": 1 }))), "OutsideRoots");
    assert_eq!(code(h.call("put", json!({ "path": "out/x", "cwd": w, "size": 1 }))), "OutsideRoots", "a link out");
    assert_eq!(code(h.call("put", json!({ "path": "x", "cwd": other, "size": 1 }))), "CwdOutsideRoots");
    assert_eq!(code(h.call("put", json!({ "path": "x", "size": 1 }))), "BadRequest", "relative without a cwd");
    assert!(std::fs::read_dir(&other).unwrap().next().is_none());
    h.close();
}

#[test]
fn a_target_that_is_a_symlink_is_refused_whichever_way_it_points() {
    let (_d, r) = root();
    let (_o, other) = root();
    std::fs::write(r.join("real"), b"r").unwrap();
    std::fs::write(other.join("elsewhere"), b"e").unwrap();
    std::os::unix::fs::symlink(r.join("real"), r.join("in-link")).unwrap();
    std::os::unix::fs::symlink(other.join("elsewhere"), r.join("out-link")).unwrap();
    std::os::unix::fs::symlink(r.join("nothing"), r.join("dangling")).unwrap();
    let mut h = put_host(&r, &r);
    for n in ["in-link", "out-link", "dangling"] {
        assert_eq!(code(h.call("put", json!({ "path": n, "cwd": r, "size": 1 }))), "IsSymlink", "{n}");
    }
    assert_eq!(std::fs::read(r.join("real")).unwrap(), b"r");
    assert_eq!(std::fs::read(other.join("elsewhere")).unwrap(), b"e");
    h.close();
}

#[test]
fn a_symlink_that_appears_after_put_is_refused_by_a_replacing_commit() {
    let (_d, r) = root();
    std::fs::write(r.join("t"), b"orig").unwrap();
    std::fs::write(r.join("victim"), b"v").unwrap();
    let mut h = put_host(&r, &r);
    let f = put_all(&mut h, "t", &r, b"new", 10);
    std::fs::remove_file(r.join("t")).unwrap();
    std::os::unix::fs::symlink(r.join("victim"), r.join("t")).unwrap();
    assert_eq!(code(h.call("commit", json!({ "id": f["id"], "replace": true }))), "IsSymlink");
    assert_eq!(std::fs::read(r.join("victim")).unwrap(), b"v");
    assert!(leftovers(&r).is_empty());
    h.close();
}

#[test]
fn a_target_that_is_a_directory_is_refused() {
    let (_d, r) = root();
    std::fs::create_dir(r.join("d")).unwrap();
    let mut h = put_host(&r, &r);
    assert_eq!(code(h.call("put", json!({ "path": "d", "cwd": r, "size": 1 }))), "IsDirectory");
    for bad in ["d/", "d/.", ".", "..", ""] {
        assert_eq!(code(h.call("put", json!({ "path": bad, "cwd": r, "size": 1 }))), "BadRequest", "{bad:?}");
    }
    h.close();
}

#[test]
fn protected_and_credential_names_are_refused_with_no_way_to_allow_them() {
    let (_d, r) = root();
    for d in [".git/hooks", ".ssh", ".vscode"] {
        std::fs::create_dir_all(r.join(d)).unwrap();
    }
    let mut h = put_host(&r, &r);
    for p in [".git/hooks/pre-commit", ".git/config", ".bashrc", ".ssh/x", ".vscode/settings.json", ".env", "key.pem"] {
        assert_eq!(code(h.call("put", json!({ "path": p, "cwd": r, "size": 1 }))), "Protected", "{p}");
    }
    assert!(!r.join(".git/hooks/pre-commit").exists() && !r.join(".bashrc").exists());
    // Beside them is fine.
    h.ok("put", json!({ "path": ".git/HEAD", "cwd": r, "size": 1 }));
    h.close();
}

#[test]
fn a_parent_swapped_for_a_symlink_after_put_still_writes_into_the_original_directory() {
    let (_d, r) = root();
    let (_o, other) = root();
    std::fs::create_dir(r.join("dir")).unwrap();
    let mut h = put_host(&r, &r);
    let f = h.ok("put", json!({ "path": "dir/f.txt", "cwd": r, "size": 7 }));
    // The real parent moves away and a link to somewhere else takes its place, before any byte is written.
    std::fs::rename(r.join("dir"), r.join("dir-moved")).unwrap();
    std::os::unix::fs::symlink(&other, r.join("dir")).unwrap();
    for (off, c) in [(0, &b"pay"[..]), (3, b"load")] {
        h.ok("write", json!({ "id": f["id"], "offset": off, "bytes": b64(c) }));
    }
    let c = h.ok("commit", json!({ "id": f["id"] }));
    assert_eq!(c["sha256"], hex::encode(sha2::Sha256::digest(b"payload")));
    assert_eq!(std::fs::read(r.join("dir-moved/f.txt")).unwrap(), b"payload", "lands in the original directory");
    assert!(std::fs::read_dir(&other).unwrap().next().is_none(), "nothing in the link's target");
    assert!(leftovers(&r.join("dir-moved")).is_empty());
    h.close();
}

#[test]
fn a_parent_swapped_after_put_does_not_leak_a_temp_file_into_the_link_target_before_commit() {
    let (_d, r) = root();
    let (_o, other) = root();
    std::fs::create_dir(r.join("dir")).unwrap();
    let mut h = put_host(&r, &r);
    let f = h.ok("put", json!({ "path": "dir/f", "cwd": r, "size": 2 }));
    std::fs::rename(r.join("dir"), r.join("moved")).unwrap();
    std::os::unix::fs::symlink(&other, r.join("dir")).unwrap();
    h.ok("write", json!({ "id": f["id"], "offset": 0, "bytes": b64(b"ab") }));
    assert!(std::fs::read_dir(&other).unwrap().next().is_none());
    assert_eq!(leftovers(&r.join("moved")).len(), 1, "the temp file is in the original directory");
    h.ok("discard", json!({ "id": f["id"] }));
    assert!(leftovers(&r.join("moved")).is_empty());
    h.close();
}

#[test]
fn bad_offsets_oversized_chunks_and_oversized_puts_are_refused() {
    let (_d, r) = root();
    let mut h = put_host(&r, &r);
    let f = h.ok("put", json!({ "path": "f", "cwd": r, "size": 10 }));
    let id = f["id"].clone();
    h.ok("write", json!({ "id": id, "offset": 0, "bytes": b64(b"abcd") }));
    let (gap, repeat, past) = (
        h.call("write", json!({ "id": id, "offset": 6, "bytes": b64(b"x") })),
        h.call("write", json!({ "id": id, "offset": 0, "bytes": b64(b"x") })),
        h.call("write", json!({ "id": id, "offset": 4, "bytes": b64(b"1234567") })),
    );
    assert_eq!(
        (code(gap.clone()), code(repeat), code(past)),
        ("BadRequest".into(), "BadRequest".into(), "BadRequest".into())
    );
    assert!(gap.unwrap_err().1.contains('4'), "the message names the expected offset");
    assert_eq!(code(h.call("write", json!({ "id": id, "offset": 4, "bytes": "not an object" }))), "BadRequest");
    assert_eq!(code(h.call("write", json!({ "id": id, "offset": 4, "bytes": { "$bytes": "!!!" } }))), "BadRequest");
    // A chunk over 512 KiB, in a put big enough to hold it.
    let big = h.ok("put", json!({ "path": "big", "cwd": r, "size": 600 * 1024 }));
    let chunk = vec![7u8; 512 * 1024 + 1];
    assert_eq!(code(h.call("write", json!({ "id": big["id"], "offset": 0, "bytes": b64(&chunk) }))), "BadRequest");
    h.ok("write", json!({ "id": big["id"], "offset": 0, "bytes": b64(&chunk[..512 * 1024]) }));
    // The declared size.
    assert_eq!(code(h.call("put", json!({ "path": "huge", "cwd": r, "size": (64u64 << 20) + 1 }))), "TooLarge");
    h.ok("put", json!({ "path": "huge", "cwd": r, "size": 64u64 << 20 }));
    h.close();
}

#[test]
fn a_commit_short_of_the_size_is_refused_and_the_put_can_continue() {
    let (_d, r) = root();
    let mut h = put_host(&r, &r);
    let f = h.ok("put", json!({ "path": "f", "cwd": r, "size": 4 }));
    h.ok("write", json!({ "id": f["id"], "offset": 0, "bytes": b64(b"ab") }));
    assert_eq!(code(h.call("commit", json!({ "id": f["id"] }))), "BadRequest");
    assert!(!r.join("f").exists());
    h.ok("write", json!({ "id": f["id"], "offset": 2, "bytes": b64(b"cd") }));
    h.ok("commit", json!({ "id": f["id"] }));
    assert_eq!(std::fs::read(r.join("f")).unwrap(), b"abcd");
    h.close();
}

#[test]
fn discard_leaves_no_temp_file_and_the_id_is_gone() {
    let (_d, r) = root();
    let mut h = put_host(&r, &r);
    let f = h.ok("put", json!({ "path": "f", "cwd": r, "size": 3 }));
    h.ok("write", json!({ "id": f["id"], "offset": 0, "bytes": b64(b"abc") }));
    assert_eq!(leftovers(&r).len(), 1);
    h.ok("discard", json!({ "id": f["id"] }));
    assert!(leftovers(&r).is_empty());
    assert_eq!(code(h.call("write", json!({ "id": f["id"], "offset": 3, "bytes": b64(b"") }))), "UnknownId");
    assert!(!r.join("f").exists());
    h.close();
}

#[test]
fn reconfiguring_drops_a_put_and_its_temp_file() {
    let (_d, r) = root();
    let mut h = put_host(&r, &r);
    let f = h.ok("put", json!({ "path": "f", "cwd": r, "size": 1 }));
    h.ok("write", json!({ "id": f["id"], "offset": 0, "bytes": b64(b"a") }));
    h.ok("configure", json!({ "roots": [r] }));
    assert!(leftovers(&r).is_empty());
    assert_eq!(code(h.call("commit", json!({ "id": f["id"] }))), "UnknownId");
    h.close();
}

#[test]
fn the_end_of_the_connection_deletes_the_temp_file() {
    let (_d, r) = root();
    let mut h = put_host(&r, &r);
    let f = h.ok("put", json!({ "path": "f", "cwd": r, "size": 3 }));
    h.ok("write", json!({ "id": f["id"], "offset": 0, "bytes": b64(b"ab") }));
    assert_eq!(leftovers(&r).len(), 1);
    h.close();
    assert!(leftovers(&r).is_empty());
    assert!(!r.join("f").exists());
}

#[test]
fn a_tilde_path_expands_and_the_facts_say_so() {
    let (_d, r) = root();
    std::fs::create_dir(r.join("inbox")).unwrap();
    let mut h = put_host(&r, &r);
    let f = h.ok("put", json!({ "path": "~/inbox/x", "size": 1 }));
    let to = format!("{}/inbox/x", r.display());
    assert_eq!(f["tilde"], json!([{ "index": "path", "from": "~/inbox/x", "to": to }]));
    assert_eq!(f["rel"], "inbox/x");
    h.close();
}

#[test]
fn a_put_id_of_another_connection_is_unknown() {
    let (_d, r) = root();
    let mut a = put_host(&r, &r);
    let mut b = put_host(&r, &r);
    let f = a.ok("put", json!({ "path": "f", "cwd": r, "size": 1 }));
    assert_eq!(code(b.call("write", json!({ "id": f["id"], "offset": 0, "bytes": b64(b"a") }))), "UnknownId");
    assert_eq!(code(b.call("commit", json!({ "id": f["id"] }))), "UnknownId");
    assert_eq!(code(b.call("discard", json!({ "id": f["id"] }))), "UnknownId");
    a.close();
    b.close();
}

#[test]
fn put_ids_do_not_collide_with_spawn_ids() {
    let (_d, r) = root();
    let mut h = put_host(&r, &r);
    let p = h.ok("put", json!({ "path": "f", "cwd": r, "size": 1 }));
    let s = h.ok("spawn", json!({ "argv": ["echo", "x"], "cwd": r }));
    assert_ne!(p["id"], s["id"]);
    assert!(p["id"].as_str().unwrap().starts_with('p') && s["id"].as_str().unwrap().starts_with('c'));
    assert_eq!(code(h.call("start", json!({ "id": p["id"] }))), "UnknownId", "a put is not a call");
    h.close();
}

// --- a credentialed call: the host injects the provider's token (src/credential.rs) ---

/// The sha256 of the pinned gh manifest, the hash a worker names in `credential.manifest`.
fn gh_manifest_hash() -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors/program-manifests/manifests/gh.json");
    sha256_hex(&std::fs::read(p).unwrap())
}

/// A directory holding a fake `name` (a bash script): it prints `tok_fake` for gh's token arguments and runs `body`
/// otherwise. Put first on the session's PATH, it is what the call's `gh` resolves to.
fn fake_program(name: &str, body: &str) -> (tempfile::TempDir, PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().unwrap();
    let dir = d.path().canonicalize().unwrap();
    let p = dir.join(name);
    let script = format!(
        "#!/bin/bash\nif [ \"$*\" = \"auth token --hostname github.com\" ]; then echo tok_fake; exit 0; fi\n{body}\n"
    );
    std::fs::write(&p, script).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    (d, dir)
}

fn configure_with(h: &mut Host, r: &Path, bin: &Path, sandbox: bool) {
    h.ok("configure", json!({ "roots": [r], "sandbox": sandbox, "path": [bin, "/usr/bin", "/bin"] }));
}

#[test]
fn hello_offers_the_github_credential_only_where_the_sandbox_holds_it() {
    let mut h = Host::start();
    let v = h.ok("hello", json!({}));
    if cfg!(target_os = "macos") {
        assert_eq!(v["credentials"], json!(["github"]), "{v}");
    } else {
        assert_eq!(v["credentials"], json!([]), "Linux holds no credentialed profile yet: {v}");
    }
    h.close();
}

#[test]
fn a_credentialed_gh_reaches_port_443_with_the_token_and_no_other_port() {
    let (_d, r) = root();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    // By address: bash 3.2's /dev/tcp does not resolve github.com on macOS even unconfined. A failed `exec` redirect
    // ends a non-interactive bash, so each probe runs in its own subshell.
    use std::net::ToSocketAddrs;
    let Some(ip) = ("github.com", 443).to_socket_addrs().ok().and_then(|mut a| a.find(|a| a.is_ipv4())) else {
        eprintln!("github.com does not resolve here; the credentialed profile's network is not checked");
        return;
    };
    let ip = ip.ip();
    let body = format!(
        "echo \"token=$GH_TOKEN config=$GH_CONFIG_DIR tmp=$TMPDIR prompt=$GH_PROMPT_DISABLED\"\n\
         (exec 3<>/dev/tcp/{ip}/443) && echo reached-443\n\
         (exec 4<>/dev/tcp/127.0.0.1/{port}) && echo reached-local"
    );
    let (_b, bin) = fake_program("gh", &body);
    let mut h = Host::start();
    if !h.sandbox_available() {
        return h.close();
    }
    let cred = json!({ "provider": "github", "manifest": gh_manifest_hash() });
    if !cfg!(target_os = "macos") {
        configure_with(&mut h, &r, &bin, true);
        let e = h.call("spawn", json!({ "argv": ["gh", "api", "/x"], "cwd": r, "credential": cred })).unwrap_err();
        assert_eq!(e.0, "SandboxFailed", "Linux refuses the credentialed profile, never runs it ordinary: {e:?}");
        return h.close();
    }
    // Control: unsandboxed, github.com:443 is reachable from here, so the sandboxed result below means something.
    configure_with(&mut h, &r, &bin, false);
    let (_, d) = h.run(json!({ "argv": ["gh", "api", "/x"], "cwd": r }));
    if !text(&h.read_all(&d["stdout"])).contains("reached-443") {
        eprintln!("github.com:443 is unreachable from this machine; the credentialed profile's network is not checked");
        return h.close();
    }
    let _ = listener.accept();
    configure_with(&mut h, &r, &bin, true);
    // The ordinary profile reaches nothing.
    let (_, d) = h.run(json!({ "argv": ["gh", "api", "/x"], "cwd": r }));
    assert!(!text(&h.read_all(&d["stdout"])).contains("reached-443"), "the ordinary profile reached the network");
    let (f, d) = h.run(json!({ "argv": ["gh", "api", "/x"], "cwd": r, "credential": cred }));
    assert_eq!(f["credential"], json!({ "provider": "github", "ports": [443], "profile": "credentialed:github" }));
    assert_eq!(f["placement"], "host-sandbox");
    let out = text(&h.read_all(&d["stdout"]));
    assert!(out.contains("token=tok_fake "), "the provider's token is in the call's env: {out}");
    assert!(out.contains("prompt=1"), "{out}");
    let tmp = out.split("tmp=").nth(1).unwrap().split(' ').next().unwrap();
    assert!(out.contains(&format!("config={tmp}/github ")), "a throwaway config dir under the call's tmp: {out}");
    assert!(out.contains("reached-443"), "the credentialed profile reaches 443: {out}");
    assert!(!out.contains("reached-local"), "a port other than 443 was reached: {out}");
    std::thread::sleep(Duration::from_millis(100));
    assert!(listener.accept().is_err(), "a credentialed call reached a port other than 443");
    assert_eq!(d["envelope"], json!({ "write": "today", "exec": "program-only", "profile": "credentialed:github" }));
    assert!(!Path::new(tmp).exists(), "the call's tmp, config dir included, is gone after the call");
    h.close();
}

#[test]
fn no_token_is_secret_unavailable_and_the_program_never_runs() {
    use std::os::unix::fs::PermissionsExt;
    let (_d, r) = root();
    let (_b, bin) = fake_program("gh", "");
    let marker = r.join("ran");
    // logged out: the token arguments fail, anything else leaves a marker
    std::fs::write(bin.join("gh"), format!("#!/bin/bash\n[ \"$1\" = auth ] && exit 1\necho > {}\n", marker.display()))
        .unwrap();
    std::fs::set_permissions(bin.join("gh"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut h = Host::start();
    if !cfg!(target_os = "macos") || !h.sandbox_available() {
        return h.close();
    }
    configure_with(&mut h, &r, &bin, true);
    let cred = json!({ "provider": "github", "manifest": gh_manifest_hash() });
    let f = h.ok("spawn", json!({ "argv": ["gh", "api", "/x"], "cwd": r, "credential": cred }));
    let e = h.call("start", json!({ "id": f["id"] })).unwrap_err();
    assert_eq!(e.0, "SecretUnavailable", "{e:?}");
    assert!(!marker.exists(), "the call ran without its token");
    h.close();
}

#[test]
fn a_credential_is_refused_for_another_program_an_unpinned_manifest_a_bad_shape_or_no_sandbox() {
    let (_d, r) = root();
    let (_b, bin) = fake_program("gh", "true");
    let (_c, curl_bin) = fake_program("curl", "true");
    let mut h = Host::start();
    configure_with(&mut h, &r, &bin, true);
    let code = |h: &mut Host, argv: Value, cred: Value| {
        h.call("spawn", json!({ "argv": argv, "cwd": r, "credential": cred })).map(|_| ()).unwrap_err().0
    };
    let hash = gh_manifest_hash();
    assert_eq!(code(&mut h, json!(["gh"]), json!({ "provider": "aws", "manifest": hash })), "CredentialRefused");
    let zeros = "0".repeat(64);
    assert_eq!(code(&mut h, json!(["gh"]), json!({ "provider": "github", "manifest": zeros })), "CredentialRefused");
    for bad in [
        json!("github"),
        json!({ "provider": "github" }),
        json!({ "provider": "github", "manifest": hash, "env": "X" }),
    ] {
        assert_eq!(code(&mut h, json!(["gh"]), bad.clone()), "BadRequest", "{bad}");
    }
    let curl = curl_bin.join("curl");
    let refused = code(&mut h, json!([curl]), json!({ "provider": "github", "manifest": hash }));
    assert_eq!(refused, "CredentialRefused", "github is gh's alone");
    // a gh the repository put inside a root, found first on PATH: its token fetch would run it unconfined
    std::fs::copy(bin.join("gh"), r.join("gh")).unwrap();
    configure_with(&mut h, &r, &r, true);
    assert_eq!(code(&mut h, json!(["gh"]), json!({ "provider": "github", "manifest": hash })), "CredentialRefused");
    std::fs::remove_file(r.join("gh")).unwrap();
    configure_with(&mut h, &r, &bin, false);
    let unsandboxed = code(&mut h, json!(["gh"]), json!({ "provider": "github", "manifest": hash }));
    assert_eq!(unsandboxed, "SandboxFailed", "never the plain host with the person's token");
    h.close();
}
