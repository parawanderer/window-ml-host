//! session.rs — one native messaging connection: the calls of docs/PROTOCOL.md and the state between them. A `spawn`
//! only RESOLVES facts and parks the call; only an explicit `start` for its id runs it. The host never decides.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use serde_json::{Map, Value, json};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Notify, mpsc};

use crate::env::{self, CallEnv, EnvError, NoSecrets, SecretStore};
use crate::facts;
use crate::framing::{self, FrameError, MAX_OUT};
use crate::gitconfig;
use crate::runner::{self, Outcome, Prepared};
use crate::sandbox::{self, Availability, Plan};
use crate::store::{MAX_READ, Store};
use crate::walk;

/// The protocol version `hello` reports.
pub const PROTOCOL: u32 = 1;
/// How long a spawned call waits for its `start` (the person may be reading the card).
pub const PENDING_TTL: Duration = Duration::from_secs(30 * 60);
/// At most this many calls wait for a verdict at once.
pub const MAX_PENDING: usize = 256;
/// At most this many calls run at once.
pub const MAX_RUNNING: usize = 32;
/// The default and the ceiling of a call's time limit.
pub const DEFAULT_TIMEOUT_MS: u64 = 120_000;
pub const MAX_TIMEOUT_MS: u64 = 3_600_000;
/// The default and the ceiling of the bytes kept per stream.
pub const DEFAULT_OUTPUT_CAP: u64 = 64 << 20;
pub const MAX_OUTPUT_CAP: u64 = 1 << 30;
/// PATH directories added after the host's own when `configure` names none: where package managers put programs,
/// which Chrome's launchd environment usually lacks.
const EXTRA_PATH: &[&str] = &["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"];

/// A protocol error: its code (docs/PROTOCOL.md, "Error codes") and a message for a person.
#[derive(Debug)]
pub struct Fail(pub &'static str, pub String);

fn fail<T>(code: &'static str, msg: impl Into<String>) -> Result<T, Fail> {
    Err(Fail(code, msg.into()))
}

/// The session's settings, from `configure`.
#[derive(Clone)]
struct Config {
    roots: Vec<PathBuf>,
    sandbox: bool,
    path: Vec<PathBuf>,
    timeout_ms: u64,
    output_cap: u64,
}

/// A spawned call waiting for its verdict.
struct Pending {
    created: Instant,
    program: PathBuf,
    argv: Vec<String>,
    cwd: PathBuf,
    env: CallEnv,
    timeout_ms: u64,
    sandboxed: bool,
    /// Secret-flagged paths the call names: the sandbox lets the call read exactly these.
    named_secrets: Vec<PathBuf>,
    /// The config it was judged against (a reconfigure drops pending calls, so this is the current one).
    config: Config,
}

struct State {
    config: Option<Config>,
    pending: HashMap<String, Pending>,
    running: HashMap<String, (u32, Arc<Notify>)>,
    next_id: u64,
}

/// Reads one variable of the host's own environment.
pub type HostEnv = dyn Fn(&str) -> Option<String> + Send + Sync;

/// What a session needs from its surroundings; tests substitute the store's base and the host environment.
pub struct Host {
    pub sandbox: Availability,
    pub secrets: Box<dyn SecretStore>,
    pub store: Arc<Store>,
    /// The host's own environment, read for the scrubbed base and the default PATH.
    pub host_env: Box<HostEnv>,
}

impl Host {
    /// The production host: the real sandbox probe, the system temp dir, the process environment, no secrets.
    pub fn from_system() -> std::io::Result<Host> {
        Ok(Host {
            sandbox: sandbox::probe(),
            secrets: Box::new(NoSecrets),
            store: Arc::new(Store::create(&std::env::temp_dir())?),
            host_env: Box::new(|k| std::env::var(k).ok()),
        })
    }
}

struct Session {
    host: Host,
    state: Mutex<State>,
    tx: mpsc::UnboundedSender<Value>,
}

/// Serves one session until the input ends or breaks the framing, then kills every running call and deletes the held
/// output.
pub async fn serve<R, W>(mut input: R, mut output: W, host: Host) -> Result<(), FrameError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (tx, mut rx) = mpsc::unbounded_channel::<Value>();
    let writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let mut body = serde_json::to_vec(&msg).expect("JSON values serialize");
            if body.len() > MAX_OUT {
                // Only an answer can grow this large (one echoing a huge argv); say so instead of breaking the stream.
                body = serde_json::to_vec(&json!({ "seq": msg.get("seq"), "error":
                    { "code": "TooLarge", "message": "the answer exceeds the 1 MiB native message limit" } }))
                .expect("JSON");
            }
            if framing::write_frame(&mut output, &body).await.is_err() {
                break;
            }
        }
    });
    let s = Arc::new(Session {
        host,
        state: Mutex::new(State { config: None, pending: HashMap::new(), running: HashMap::new(), next_id: 1 }),
        tx,
    });
    let result = loop {
        match framing::read_frame(&mut input).await {
            Ok(Some(body)) => {
                let s = s.clone();
                tokio::spawn(async move { s.handle(&body).await });
            }
            Ok(None) => break Ok(()),
            Err(e) => break Err(e),
        }
    };
    let running: Vec<u32> = s.state.lock().unwrap().running.values().map(|(pg, _)| *pg).collect();
    for pg in running {
        runner::kill_now(pg);
    }
    s.host.store.cleanup();
    drop(s);
    writer.abort();
    result
}

impl Session {
    fn send(&self, v: Value) {
        let _ = self.tx.send(v);
    }

    async fn handle(self: &Arc<Self>, body: &[u8]) {
        let msg: Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(e) => return self.send(error_msg(Value::Null, "BadRequest", &format!("not JSON: {e}"))),
        };
        let seq = msg.get("seq").filter(|v| v.is_i64() || v.is_u64()).cloned();
        let (Some(seq), Some(call)) = (seq, msg.get("call").and_then(Value::as_str)) else {
            return self.send(error_msg(Value::Null, "BadRequest", "a call has a numeric seq and a string call"));
        };
        let empty = Map::new();
        let args = match msg.get("args") {
            None => &empty,
            Some(Value::Object(o)) => o,
            Some(_) => return self.send(error_msg(seq, "BadRequest", "args is an object")),
        };
        let answer = match call {
            "hello" => Ok(self.hello()),
            "configure" => self.configure(args),
            "spawn" => self.spawn(args),
            "start" => match self.start(&seq, args) {
                Ok(()) => return,
                Err(f) => Err(f),
            },
            "discard" => self.discard(args),
            "cancel" => self.cancel(args),
            "read" => self.read(args),
            "release" => self.release(args),
            other => fail("BadRequest", format!("unknown call {other:?}")),
        };
        match answer {
            Ok(v) => self.send(json!({ "seq": seq, "value": v })),
            Err(Fail(code, m)) => self.send(error_msg(seq, code, &m)),
        }
    }

    fn hello(&self) -> Value {
        let sb = &self.host.sandbox;
        let mut sandbox = json!({ "kind": sb.kind.map(|k| k.name()), "available": sb.available });
        if let Some(r) = &sb.reason {
            sandbox["reason"] = json!(r);
        }
        json!({
            "host": "window-ml-host",
            "version": env!("CARGO_PKG_VERSION"),
            "protocol": PROTOCOL,
            "platform": std::env::consts::OS,
            "sandbox": sandbox,
            "modes": ["host"],
        })
    }

    fn configure(&self, a: &Map<String, Value>) -> Result<Value, Fail> {
        let Some(roots_in) = a.get("roots").and_then(Value::as_array) else {
            return fail("BadRequest", "roots is an array of absolute paths");
        };
        let mut roots = Vec::new();
        let mut shown = Vec::new();
        for r in roots_in {
            let Some(g) = r.as_str() else { return fail("BadRequest", "a root is a string") };
            let real = facts::resolve_root(g).map_err(|m| Fail("BadRoot", m))?;
            shown.push(json!({ "given": g, "path": real }));
            roots.push(real);
        }
        if roots.is_empty() {
            return fail("BadRoot", "at least one root");
        }
        let sandbox = opt_bool(a, "sandbox")?.unwrap_or(true);
        let path = match a.get("path") {
            None => self.default_path(),
            Some(Value::Array(xs)) => {
                let dirs: Option<Vec<PathBuf>> = xs.iter().map(|x| x.as_str().map(PathBuf::from)).collect();
                dirs.ok_or_else(|| Fail("BadRequest", "path is an array of directories".into()))?
            }
            Some(_) => return fail("BadRequest", "path is an array of directories"),
        };
        let timeout_ms = opt_u64(a, "timeoutMs")?.unwrap_or(DEFAULT_TIMEOUT_MS).clamp(1, MAX_TIMEOUT_MS);
        let output_cap = opt_u64(a, "outputCap")?.unwrap_or(DEFAULT_OUTPUT_CAP).min(MAX_OUTPUT_CAP);
        let sandboxed = sandbox && self.host.sandbox.available;
        let mut st = self.state.lock().unwrap();
        st.pending.clear();
        st.config = Some(Config { roots, sandbox, path, timeout_ms, output_cap });
        Ok(json!({ "roots": shown, "sandboxed": sandboxed }))
    }

    fn default_path(&self) -> Vec<PathBuf> {
        let mut out: Vec<PathBuf> = Vec::new();
        let own = (self.host.host_env)("PATH").unwrap_or_default();
        for d in own.split(':').chain(EXTRA_PATH.iter().copied()) {
            let p = PathBuf::from(d);
            if p.is_absolute() && !out.contains(&p) {
                out.push(p);
            }
        }
        out
    }

    fn spawn(&self, a: &Map<String, Value>) -> Result<Value, Fail> {
        let config = self.state.lock().unwrap().config.clone();
        let Some(config) = config else { return fail("NotConfigured", "configure the session first") };
        let argv =
            string_array(a.get("argv")).ok_or_else(|| Fail("BadRequest", "argv is an array of strings".into()))?;
        if argv.is_empty() || argv.iter().any(|s| s.contains('\0')) {
            return fail("BadRequest", "argv is non-empty, with no NUL in any argument");
        }
        match a.get("mode").and_then(Value::as_str).unwrap_or("host") {
            "host" => {}
            "container" => return fail("Unsupported", "container mode has no runner in this version"),
            m => return fail("BadRequest", format!("mode {m:?}")),
        }
        let Some(cwd_given) = a.get("cwd").and_then(Value::as_str) else {
            return fail("BadRequest", "cwd is an absolute path");
        };
        if !Path::new(cwd_given).is_absolute() {
            return fail("BadRequest", "cwd is an absolute path");
        }
        let cwd = Path::new(cwd_given).canonicalize().ok().filter(|c| c.is_dir() && facts::in_roots(c, &config.roots));
        let Some(cwd) = cwd else {
            return fail("CwdOutsideRoots", format!("{cwd_given} is not a directory inside a root"));
        };
        let env = match a.get("env") {
            None => CallEnv::default(),
            Some(Value::Object(o)) => env::check_call_env(o, self.host.secrets.as_ref()).map_err(|e| match e {
                EnvError::Bad(m) => Fail("BadRequest", m),
                EnvError::Refused(n) => Fail("EnvRefused", format!("{n} may not be set by a call")),
                EnvError::SecretUnavailable(n) => Fail("SecretUnavailable", format!("the host holds no secret {n:?}")),
            })?,
            Some(_) => return fail("BadRequest", "env is an object"),
        };
        let program =
            facts::resolve_program(&argv[0], &cwd, &config.path).map_err(|e| Fail("ProgramNotFound", e.to_string()))?;
        let paths = self.path_facts(a.get("pathArgs"), &argv, &cwd, &config.roots)?;
        let mut cwd_fact = json!({ "path": cwd, "inRoot": true });
        if opt_bool(a, "walkCwd")?.unwrap_or(false) {
            cwd_fact["containsSecret"] = json!(walk::contains_secret(&cwd, walk::WALK_CAP));
        }
        // The repository the call acts in: the cwd's, or the one a `-C dir` names (`repoArg`, from the manifest).
        let repo_dir = match opt_u64(a, "repoArg")? {
            None => cwd.clone(),
            Some(i) if (1..argv.len()).contains(&(i as usize)) => facts::resolve_path(&argv[i as usize], &cwd).path,
            Some(_) => return fail("BadRequest", "repoArg is the index of an argument after argv[0]"),
        };
        let repo = gitconfig::inspect(&repo_dir);
        let timeout_ms = opt_u64(a, "timeoutMs")?.unwrap_or(config.timeout_ms).clamp(1, MAX_TIMEOUT_MS);
        let sandboxed = config.sandbox && self.host.sandbox.available;
        let named_secrets: Vec<PathBuf> = paths
            .iter()
            .filter(|p| p["secret"] == true)
            .filter_map(|p| p["path"].as_str().map(PathBuf::from))
            .collect();

        let mut st = self.state.lock().unwrap();
        st.pending.retain(|_, p| p.created.elapsed() < PENDING_TTL);
        if st.pending.len() >= MAX_PENDING {
            return fail("Busy", format!("{MAX_PENDING} calls already wait for a verdict"));
        }
        let id = format!("c{}", st.next_id);
        st.next_id += 1;
        let facts = json!({
            "id": id,
            "argv": argv,
            "program": { "path": program, "inRoot": facts::in_roots(&program, &config.roots) },
            "cwd": cwd_fact,
            "env": { "set": env.plain.keys().chain(env.secrets.keys()).collect::<Vec<_>>(),
                     "secrets": env.secrets.values().collect::<Vec<_>>(),
                     "free": env::is_free(&env) },
            "repo": repo.as_ref().map(|r| json!({ "root": r.root, "reasons": r.reasons })),
            "repoConfigRunsCode": repo.as_ref().map(|r| r.runs_code),
            "paths": paths,
            "effects": "unknown",
            "mode": "host",
            "sandboxed": sandboxed,
            "placement": if sandboxed { "host-sandbox" } else { "host-plain" },
            "expiresInMs": PENDING_TTL.as_millis() as u64,
        });
        st.pending.insert(
            id,
            Pending { created: Instant::now(), program, argv, cwd, env, timeout_ms, sandboxed, named_secrets, config },
        );
        Ok(facts)
    }

    fn path_facts(
        &self,
        spec: Option<&Value>,
        argv: &[String],
        cwd: &Path,
        roots: &[PathBuf],
    ) -> Result<Vec<Value>, Fail> {
        let Some(spec) = spec else { return Ok(vec![]) };
        let Some(list) = spec.as_array() else { return fail("BadRequest", "pathArgs is an array") };
        let mut out = Vec::new();
        for e in list {
            let i = e.get("arg").and_then(Value::as_u64).map(|i| i as usize);
            let Some(i) = i.filter(|i| (1..argv.len()).contains(i)) else {
                return fail("BadRequest", "pathArgs[].arg is the index of an argument after argv[0]");
            };
            let given = match e.get("split") {
                None => argv[i].as_str(),
                Some(Value::String(sep)) if !sep.is_empty() => match argv[i].split_once(sep.as_str()) {
                    Some((_, v)) => v,
                    None => return fail("BadRequest", format!("argument {i} has no {sep:?}")),
                },
                Some(_) => return fail("BadRequest", "pathArgs[].split is a non-empty string"),
            };
            let r = facts::resolve_path(given, cwd);
            let secret = facts::looks_secret(&r.path) || facts::looks_secret(Path::new(given));
            let mut fact = json!({
                "arg": i, "given": given, "path": r.path,
                "inRoot": r.clean && facts::in_roots(&r.path, roots),
                "secret": secret, "exists": r.exists,
            });
            // A recursive reader's argument: what lies beneath it, which it reads without naming.
            if e.get("walk") == Some(&Value::Bool(true)) {
                fact["containsSecret"] = json!(walk::contains_secret(&r.path, walk::WALK_CAP));
            }
            out.push(fact);
        }
        Ok(out)
    }

    /// Runs a pending call. Answers `seq` itself, BEFORE the call can end, so `done` never overtakes the answer.
    fn start(self: &Arc<Self>, seq: &Value, a: &Map<String, Value>) -> Result<(), Fail> {
        let id = req_str(a, "id")?;
        let p = {
            let mut st = self.state.lock().unwrap();
            if st.running.len() >= MAX_RUNNING {
                return fail("Busy", format!("{MAX_RUNNING} calls are already running"));
            }
            match st.pending.remove(id) {
                Some(p) if p.created.elapsed() < PENDING_TTL => p,
                _ => return fail("UnknownId", format!("no pending call {id:?}")),
            }
        };
        let store = self.host.store.clone();
        let tmp = store.call_tmp(id).map_err(|e| Fail("SpawnFailed", format!("temp dir: {e}")))?;
        let path = std::env::join_paths(&p.config.path).map_err(|e| Fail("SpawnFailed", e.to_string()))?;
        let envmap = env::build(
            &*self.host.host_env,
            &path.to_string_lossy(),
            &tmp.to_string_lossy(),
            &p.env,
            self.host.secrets.as_ref(),
        )
        .map_err(|_| Fail("SecretUnavailable", "a secret went away between spawn and start".into()))?;
        let prepared = if p.sandboxed {
            let plan = Plan {
                roots: p.config.roots.clone(),
                tmp: tmp.clone(),
                hidden: vec![store.out_dir().to_path_buf()],
                allow_read: p.named_secrets.clone(),
                home: (self.host.host_env)("HOME").map(PathBuf::from),
            };
            let Some((prog, args)) = sandbox::wrap(&self.host.sandbox, &plan, &p.program, &p.argv[1..], &p.cwd) else {
                store.remove_call_tmp(id);
                return fail("SandboxFailed", "the sandbox is not available");
            };
            Prepared { program: prog, args, argv0: None, cwd: p.cwd.clone(), env: envmap }
        } else {
            Prepared {
                program: p.program.clone(),
                args: p.argv[1..].iter().map(Into::into).collect(),
                argv0: Some(p.argv[0].clone()),
                cwd: p.cwd.clone(),
                env: envmap,
            }
        };
        let running = match runner::spawn(prepared) {
            Ok(r) => r,
            Err(e) => {
                store.remove_call_tmp(id);
                return fail(if p.sandboxed { "SandboxFailed" } else { "SpawnFailed" }, e.to_string());
            }
        };
        let pid = running.pid;
        let cancel = Arc::new(Notify::new());
        self.state.lock().unwrap().running.insert(id.to_string(), (pid, cancel.clone()));
        let s = self.clone();
        let id_owned = id.to_string();
        let timeout = Duration::from_millis(p.timeout_ms);
        let cap = p.config.output_cap;
        let sandboxed = p.sandboxed;
        self.send(json!({ "seq": seq, "value": { "id": id, "pid": pid } }));
        tokio::spawn(async move {
            let o = runner::finish(running, store.clone(), cancel, timeout, cap).await;
            s.state.lock().unwrap().running.remove(&id_owned);
            store.remove_call_tmp(&id_owned);
            let done = done_event(&id_owned, o, sandboxed, &store);
            s.send(done);
        });
        Ok(())
    }

    fn discard(&self, a: &Map<String, Value>) -> Result<Value, Fail> {
        let id = req_str(a, "id")?;
        match self.state.lock().unwrap().pending.remove(id) {
            Some(_) => Ok(json!({})),
            None => fail("UnknownId", format!("no pending call {id:?}")),
        }
    }

    fn cancel(&self, a: &Map<String, Value>) -> Result<Value, Fail> {
        let id = req_str(a, "id")?;
        match self.state.lock().unwrap().running.get(id) {
            Some((_, n)) => {
                n.notify_one();
                Ok(json!({ "signalled": true }))
            }
            None => fail("UnknownId", format!("no running call {id:?}")),
        }
    }

    fn read(&self, a: &Map<String, Value>) -> Result<Value, Fail> {
        let ptr = req_str(a, "ptr")?;
        let offset = opt_u64(a, "offset")?.unwrap_or(0);
        let length = opt_u64(a, "length")?.unwrap_or(MAX_READ);
        match self.host.store.read(ptr, offset, length) {
            None => fail("UnknownPtr", format!("no held output {ptr:?}")),
            Some(Err(e)) => fail("Failed", e.to_string()),
            Some(Ok((bytes, size, eof))) => Ok(json!({
                "ptr": ptr, "offset": offset.min(size), "length": bytes.len(), "size": size, "eof": eof,
                "data": { "$bytes": base64::engine::general_purpose::STANDARD.encode(&bytes) },
            })),
        }
    }

    fn release(&self, a: &Map<String, Value>) -> Result<Value, Fail> {
        let ptr = req_str(a, "ptr")?;
        if self.host.store.release(ptr) { Ok(json!({})) } else { fail("UnknownPtr", format!("no held output {ptr:?}")) }
    }
}

/// The `done` event for an ended call. A sandboxed call whose wrapper refused to start its program reports
/// `SandboxFailed`: the program never ran.
fn done_event(id: &str, o: Outcome, sandboxed: bool, store: &Store) -> Value {
    let stream = |c: &runner::Captured| match c {
        Ok((ptr, h)) => json!({ "ptr": ptr, "size": h.size, "sha256": h.sha256, "truncated": h.truncated }),
        Err(e) => json!({ "error": e }),
    };
    let mut v = json!({
        "event": "done", "id": id,
        "code": o.code, "signal": o.signal,
        "ok": o.code == Some(0),
        "timedOut": o.timed_out, "cancelled": o.cancelled, "durationMs": o.duration_ms,
        "stdout": stream(&o.stdout), "stderr": stream(&o.stderr),
    });
    if sandboxed && sandbox_refused(&o, store) {
        v["ok"] = json!(false);
        v["error"] = json!({ "code": "SandboxFailed", "message": "the OS sandbox did not start the program" });
    }
    v
}

/// The wrapper's own failure: `sandbox-exec` exits 65 or 71 with `sandbox-exec:` first on stderr; `bwrap` exits 1 with
/// `bwrap:`. A program could print the same to fake its own failure, which costs it nothing it did not have.
fn sandbox_refused(o: &Outcome, store: &Store) -> bool {
    let Ok((ptr, _)) = &o.stderr else { return false };
    let Some(Ok((head, _, _))) = store.read(ptr, 0, 32) else { return false };
    match o.code {
        Some(65) | Some(71) => head.starts_with(b"sandbox-exec:"),
        Some(1) => head.starts_with(b"bwrap:"),
        _ => false,
    }
}

fn error_msg(seq: Value, code: &str, message: &str) -> Value {
    json!({ "seq": seq, "error": { "code": code, "message": message } })
}

fn string_array(v: Option<&Value>) -> Option<Vec<String>> {
    v?.as_array()?.iter().map(|x| x.as_str().map(String::from)).collect()
}

fn req_str<'a>(a: &'a Map<String, Value>, k: &str) -> Result<&'a str, Fail> {
    a.get(k).and_then(Value::as_str).ok_or_else(|| Fail("BadRequest", format!("{k} is a string")))
}

fn opt_u64(a: &Map<String, Value>, k: &str) -> Result<Option<u64>, Fail> {
    match a.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v.as_u64().map(Some).ok_or_else(|| Fail("BadRequest", format!("{k} is a non-negative integer"))),
    }
}

fn opt_bool(a: &Map<String, Value>, k: &str) -> Result<Option<bool>, Fail> {
    match a.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(*b)),
        Some(_) => fail("BadRequest", format!("{k} is a boolean")),
    }
}
