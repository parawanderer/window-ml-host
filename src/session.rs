//! session.rs — one native messaging connection: the calls of docs/PROTOCOL.md and the state between them. A `spawn`
//! only RESOLVES facts and parks the call; only an explicit `start` (or a `pipe` naming it) for its id runs it. The
//! host never decides.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
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
use crate::glob;
use crate::owners::{self, Entry, Ledger};
use crate::procs;
use crate::runner::{self, Limits, Meter, Outcome, Prepared};
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
/// At most this many stages in one `pipe`.
pub const MAX_PIPE_STAGES: usize = 16;
/// The default and the ceiling of a `glob`'s matches.
pub const DEFAULT_GLOB_LIMIT: u64 = 10_000;
pub const MAX_GLOB_LIMIT: u64 = 100_000;
/// The default and the ceiling of a call's time limit.
pub const DEFAULT_TIMEOUT_MS: u64 = 120_000;
pub const MAX_TIMEOUT_MS: u64 = 3_600_000;
/// The default and the ceiling of the bytes kept per stream.
pub const DEFAULT_OUTPUT_CAP: u64 = 64 << 20;
pub const MAX_OUTPUT_CAP: u64 = 1 << 30;
/// The default memory bound of a call (its physical footprint, children included), the person's default ceiling, and
/// the floor no bound goes below.
pub const DEFAULT_MEMORY_BOUND: u64 = 4 << 30;
pub const DEFAULT_MEMORY_MAX: u64 = 16 << 30;
pub const MIN_MEMORY_BOUND: u64 = 16 << 20;
/// The default and the ceiling of how long an orphan outlives its owner.
pub const DEFAULT_ORPHAN_TIMEOUT_MS: u64 = 10 * 60_000;
pub const MAX_ORPHAN_TIMEOUT_MS: u64 = 24 * 3_600_000;
/// The most bytes of the `owner` a spawn names, as JSON.
pub const MAX_OWNER_BYTES: usize = 1024;
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
    memory_bound: u64,
    /// The person's ceiling: a call's `memoryBound` may be lowered or raised up to this.
    memory_max: u64,
    owner_loss: OwnerLoss,
}

/// What happens to a running call when the port closes (its owner is gone).
#[derive(Clone, Copy, Debug, PartialEq)]
enum OwnerLoss {
    /// The default: the group is killed.
    Kill,
    /// Parked on the orphan list for this many milliseconds, then killed anyway.
    Orphan(u64),
}

impl OwnerLoss {
    fn parse(v: Option<&Value>, timeout: Option<u64>, default: OwnerLoss) -> Result<OwnerLoss, Fail> {
        let ms = timeout.unwrap_or(DEFAULT_ORPHAN_TIMEOUT_MS).clamp(1, MAX_ORPHAN_TIMEOUT_MS);
        match v.map(|v| v.as_str()) {
            None => Ok(match (default, timeout) {
                (OwnerLoss::Orphan(_), Some(_)) => OwnerLoss::Orphan(ms),
                _ => default,
            }),
            Some(Some("kill")) => Ok(OwnerLoss::Kill),
            Some(Some("orphan")) => Ok(OwnerLoss::Orphan(ms)),
            Some(_) => fail("BadRequest", "onOwnerLoss is \"kill\" or \"orphan\""),
        }
    }

    fn json(self) -> Value {
        match self {
            OwnerLoss::Kill => json!({ "policy": "kill" }),
            OwnerLoss::Orphan(ms) => json!({ "policy": "orphan", "timeoutMs": ms }),
        }
    }
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
    /// Each hashed path argument and the hash its fact reported: `start` hashes it again and refuses on a change.
    pins: Vec<(PathBuf, Option<String>)>,
    /// Who the call is for, as the extension named it (`{ session, run, step }`): opaque to the host.
    owner: Value,
    memory_bound: u64,
    owner_loss: OwnerLoss,
    /// The config it was judged against (a reconfigure drops pending calls, so this is the current one).
    config: Config,
}

/// A running call: the owner table's row.
struct Call {
    entry: Entry,
    cancel: Arc<Notify>,
    meter: Arc<Meter>,
    owner_loss: OwnerLoss,
}

struct State {
    config: Option<Config>,
    pending: HashMap<String, Pending>,
    running: HashMap<String, Call>,
    next_id: u64,
    /// Whether this host's warden has been started (on the first call that runs).
    warden: bool,
    /// The port has closed: the ledger now holds only the orphans, and a call that still starts is killed at once.
    closed: bool,
}

impl State {
    fn entries(&self) -> Vec<Entry> {
        self.running.values().map(|c| c.entry.clone()).collect()
    }
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
    /// The owner table's ledger directory ([`owners`]); `None` keeps the table in memory only.
    pub owners_dir: Option<PathBuf>,
    /// The program started as this host's warden (`wmlhost warden …`): it reaps the calls of a host that was killed
    /// outright. `None` starts none.
    pub warden: Option<PathBuf>,
}

impl Host {
    /// The production host: the real sandbox probe, the system temp dir, the process environment, no secrets.
    pub fn from_system() -> std::io::Result<Host> {
        Ok(Host {
            sandbox: sandbox::probe(),
            secrets: Box::new(NoSecrets),
            store: Arc::new(Store::create(&std::env::temp_dir())?),
            host_env: Box::new(|k| std::env::var(k).ok()),
            owners_dir: Some(owners::default_dir(std::env::var("WMLHOST_STATE_DIR").ok())),
            warden: std::env::current_exe().ok(),
        })
    }
}

struct Session {
    host: Host,
    state: Mutex<State>,
    tx: mpsc::UnboundedSender<Value>,
    ledger: Option<Ledger>,
}

/// Serves one session until the input ends or breaks the framing, then deals with every running call by its owner-loss
/// policy (killed by default, else left on the orphan list until its deadline) and deletes the held output.
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
    let ledger = host.owners_dir.as_deref().and_then(Ledger::open);
    if let Some(dir) = &host.owners_dir {
        // Calls a host killed outright left behind, whose warden did not get to them.
        owners::sweep(dir, ledger.as_ref());
    }
    let s = Arc::new(Session {
        host,
        state: Mutex::new(State {
            config: None,
            pending: HashMap::new(),
            running: HashMap::new(),
            next_id: 1,
            warden: false,
            closed: false,
        }),
        tx,
        ledger,
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
    s.owner_lost();
    s.host.store.cleanup();
    drop(s);
    writer.abort();
    result
}

impl Session {
    /// The port closed: every running call is killed, or kept as an orphan with a deadline its warden enforces.
    fn owner_lost(&self) {
        let mut st = self.state.lock().unwrap();
        st.closed = true;
        let now = owners::now_ms();
        let mut orphans = Vec::new();
        for c in st.running.values() {
            match c.owner_loss {
                OwnerLoss::Kill => runner::kill_now(c.entry.pgid),
                OwnerLoss::Orphan(ms) => orphans.push(Entry { deadline_ms: Some(now + ms), ..c.entry.clone() }),
            }
        }
        if let Some(l) = &self.ledger {
            l.write(&orphans);
        } else {
            // No ledger and no warden to keep the deadline: an orphan would outlive its owner unseen, so it goes too.
            orphans.iter().for_each(|e| runner::kill_now(e.pgid));
        }
    }

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
            "pipe" => match self.pipe(&seq, args).await {
                Ok(()) => return,
                Err(f) => Err(f),
            },
            "glob" => self.glob(args).await,
            "discard" => self.discard(args),
            "cancel" => self.cancel(args),
            "read" => self.read(args),
            "release" => self.release(args),
            "status" => Ok(self.status()),
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
            "owners": { "ledger": self.ledger.is_some() },
            "memory": { "metric": procs::metric(), "enforcer": "watchdog", "everyMs": runner::WATCH_EVERY.as_millis() as u64 },
        })
    }

    /// The owner table: every running call with its owner and footprint, and the orphans other host processes left.
    fn status(&self) -> Value {
        let st = self.state.lock().unwrap();
        let mut running: Vec<Value> = st
            .running
            .values()
            .map(|c| {
                json!({ "id": c.entry.id, "pid": c.entry.pgid, "owner": c.entry.owner,
                        "startedMs": c.entry.started_ms, "memoryBound": c.entry.memory_bound,
                        "footprint": c.meter.now.load(std::sync::atomic::Ordering::Relaxed),
                        "peakFootprint": c.meter.peak.load(std::sync::atomic::Ordering::Relaxed),
                        "onOwnerLoss": c.owner_loss.json() })
            })
            .collect();
        running.sort_by(|a, b| a["startedMs"].as_u64().cmp(&b["startedMs"].as_u64()));
        drop(st);
        let orphans = match &self.host.owners_dir {
            Some(dir) => owners::sweep(dir, self.ledger.as_ref()).orphans.iter().map(owners::orphan_json).collect(),
            None => vec![],
        };
        json!({ "running": running, "orphans": orphans })
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
        let memory_max = opt_u64(a, "memoryMax")?.unwrap_or(DEFAULT_MEMORY_MAX).max(MIN_MEMORY_BOUND);
        let memory_bound =
            opt_u64(a, "memoryBound")?.unwrap_or(DEFAULT_MEMORY_BOUND).clamp(MIN_MEMORY_BOUND, memory_max);
        let owner_loss = OwnerLoss::parse(a.get("onOwnerLoss"), opt_u64(a, "orphanTimeoutMs")?, OwnerLoss::Kill)?;
        let sandboxed = sandbox && self.host.sandbox.available;
        let mut st = self.state.lock().unwrap();
        st.pending.clear();
        st.config = Some(Config { roots, sandbox, path, timeout_ms, output_cap, memory_bound, memory_max, owner_loss });
        Ok(json!({ "roots": shown, "sandboxed": sandboxed, "memoryBound": memory_bound, "memoryMax": memory_max,
                   "onOwnerLoss": owner_loss.json() }))
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
        let memory_bound =
            opt_u64(a, "memoryBound")?.unwrap_or(config.memory_bound).clamp(MIN_MEMORY_BOUND, config.memory_max);
        let owner_loss = OwnerLoss::parse(a.get("onOwnerLoss"), opt_u64(a, "orphanTimeoutMs")?, config.owner_loss)?;
        let owner = match a.get("owner") {
            None => Value::Null,
            Some(o @ Value::Object(_)) if o.to_string().len() <= MAX_OWNER_BYTES => o.clone(),
            Some(_) => return fail("BadRequest", format!("owner is an object of at most {MAX_OWNER_BYTES} bytes")),
        };
        let sandboxed = config.sandbox && self.host.sandbox.available;
        let named_secrets: Vec<PathBuf> = paths
            .iter()
            .filter(|p| p["secret"] == true)
            .filter_map(|p| p["path"].as_str().map(PathBuf::from))
            .collect();
        let pins: Vec<(PathBuf, Option<String>)> = paths
            .iter()
            .filter(|p| p.get("sha256").is_some())
            .filter_map(|p| Some((PathBuf::from(p["path"].as_str()?), p["sha256"].as_str().map(String::from))))
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
            "program": { "path": program, "inRoot": facts::in_roots(&program, &config.roots),
                         "fingerprint": facts::fingerprint(&program) },
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
            "memoryBound": memory_bound,
            "onOwnerLoss": owner_loss.json(),
            "owner": owner,
            "expiresInMs": PENDING_TTL.as_millis() as u64,
        });
        st.pending.insert(
            id,
            Pending {
                created: Instant::now(),
                program,
                argv,
                cwd,
                env,
                timeout_ms,
                sandboxed,
                named_secrets,
                pins,
                owner,
                memory_bound,
                owner_loss,
                config,
            },
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
            // An interpreted script's entrypoint: the hash its manifest is pinned by, of the file after symlinks.
            match e.get("hash") {
                None | Some(Value::Bool(false)) => {}
                Some(Value::Bool(true)) => fact["sha256"] = json!(facts::file_sha256(&r.path)),
                Some(_) => return fail("BadRequest", "pathArgs[].hash is a boolean"),
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
        let (running, _) = self.launch(id, &p, Stdio::null(), false)?;
        let pid = running.pid;
        let (cancel, meter) = self.register(id, pid, &p);
        self.send(json!({ "seq": seq, "value": { "id": id, "pid": pid } }));
        self.supervise(id.to_string(), running, cancel, meter, &p);
        Ok(())
    }

    /// Runs several pending calls joined by OS pipes: each stage's stdout is the next one's stdin, and only the last
    /// stage's stdout is held. Validation is all or nothing and happens before anything starts; the answer comes before
    /// any stage's `done`.
    async fn pipe(self: &Arc<Self>, seq: &Value, a: &Map<String, Value>) -> Result<(), Fail> {
        let bad = || Fail("BadRequest", format!("ids is an array of 2..={MAX_PIPE_STAGES} distinct strings"));
        let ids = string_array(a.get("ids")).ok_or_else(bad)?;
        if !(2..=MAX_PIPE_STAGES).contains(&ids.len()) || (1..ids.len()).any(|i| ids[..i].contains(&ids[i])) {
            return Err(bad());
        }
        let stages: Vec<Pending> = {
            let mut st = self.state.lock().unwrap();
            let live = |p: &Pending| p.created.elapsed() < PENDING_TTL;
            if let Some(id) = ids.iter().find(|id| !st.pending.get(*id).is_some_and(live)) {
                return fail("UnknownId", format!("no pending call {id:?}"));
            }
            if st.running.len() + ids.len() > MAX_RUNNING {
                return fail("Busy", format!("{MAX_RUNNING} calls at most are running at once"));
            }
            ids.iter().filter_map(|id| st.pending.remove(id)).collect()
        };
        let mut started: Vec<runner::Running> = Vec::new();
        let mut failure = None;
        let mut stdin = Stdio::null();
        for (i, (id, p)) in ids.iter().zip(&stages).enumerate() {
            match self.launch(id, p, stdin, i + 1 < stages.len()) {
                Ok((r, next)) => {
                    started.push(r);
                    stdin = next.unwrap_or_else(Stdio::null);
                }
                Err(f) => {
                    failure = Some(f);
                    break;
                }
            }
        }
        if let Some(f) = failure {
            // The stages already started never get a `done`: end them, and drop their temp directories.
            for (r, id) in started.into_iter().zip(&ids) {
                runner::abort(r).await;
                self.host.store.remove_call_tmp(id);
            }
            return Err(f);
        }
        let pids: Vec<u32> = started.iter().map(|r| r.pid).collect();
        let handles: Vec<_> =
            ids.iter().zip(&pids).zip(&stages).map(|((id, pid), p)| self.register(id, *pid, p)).collect();
        self.send(json!({ "seq": seq, "value": { "ids": ids, "pids": pids } }));
        for (((id, r), (cancel, meter)), p) in ids.into_iter().zip(started).zip(handles).zip(&stages) {
            self.supervise(id, r, cancel, meter, p);
        }
        Ok(())
    }

    /// Builds and starts one pending call: its temp directory, scrubbed environment and sandbox wrapping, with `stdin`
    /// as its standard input. With `pipe_out` its stdout is handed back as the next stage's stdin instead of being
    /// held. On failure nothing of it is left behind.
    fn launch(
        &self,
        id: &str,
        p: &Pending,
        stdin: Stdio,
        pipe_out: bool,
    ) -> Result<(runner::Running, Option<Stdio>), Fail> {
        // A pinned file that changed since its facts were read is a different program than the one judged.
        if let Some((path, _)) = p.pins.iter().find(|(path, h)| facts::file_sha256(path) != *h) {
            return fail("PinChanged", format!("{} changed after its facts were read", path.display()));
        }
        let store = &self.host.store;
        let tmp = store.call_tmp(id).map_err(|e| Fail("SpawnFailed", format!("temp dir: {e}")))?;
        let failed = |f: Fail| {
            store.remove_call_tmp(id);
            Err(f)
        };
        let path = match std::env::join_paths(&p.config.path) {
            Ok(path) => path,
            Err(e) => return failed(Fail("SpawnFailed", e.to_string())),
        };
        let envmap = match env::build(
            &*self.host.host_env,
            &path.to_string_lossy(),
            &tmp.to_string_lossy(),
            &p.env,
            self.host.secrets.as_ref(),
        ) {
            Ok(m) => m,
            Err(_) => return failed(Fail("SecretUnavailable", "a secret went away between spawn and start".into())),
        };
        let prepared = if p.sandboxed {
            let plan = Plan {
                roots: p.config.roots.clone(),
                tmp: tmp.clone(),
                hidden: vec![store.out_dir().to_path_buf()],
                allow_read: p.named_secrets.clone(),
                home: (self.host.host_env)("HOME").map(PathBuf::from),
                outlives_host: matches!(p.owner_loss, OwnerLoss::Orphan(_)),
            };
            let Some((prog, args)) = sandbox::wrap(&self.host.sandbox, &plan, &p.program, &p.argv[1..], &p.cwd) else {
                return failed(Fail("SandboxFailed", "the sandbox is not available".into()));
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
        let code = if p.sandboxed { "SandboxFailed" } else { "SpawnFailed" };
        let mut running = match runner::spawn(prepared, stdin) {
            Ok(r) => r,
            Err(e) => return failed(Fail(code, e.to_string())),
        };
        let next = if pipe_out {
            match running.take_stdout() {
                Ok(s) => Some(s),
                Err(e) => {
                    runner::kill_now(running.pid);
                    return failed(Fail(code, format!("pipe: {e}")));
                }
            }
        } else {
            None
        };
        Ok((running, next))
    }

    /// Records a started call in the owner table (and its ledger), starts the warden with the first one, and returns the
    /// handle `cancel` notifies and the call's footprint meter.
    fn register(&self, id: &str, pid: u32, p: &Pending) -> (Arc<Notify>, Arc<Meter>) {
        let cancel = Arc::new(Notify::new());
        let meter = Arc::new(Meter::default());
        let entry = Entry {
            id: id.to_string(),
            pgid: pid,
            start: procs::start_time(pid),
            owner: p.owner.clone(),
            started_ms: owners::now_ms(),
            deadline_ms: None,
            memory_bound: p.memory_bound,
        };
        let mut st = self.state.lock().unwrap();
        if st.closed {
            runner::kill_now(pid);
            return (cancel, meter);
        }
        st.running.insert(
            id.to_string(),
            Call { entry, cancel: cancel.clone(), meter: meter.clone(), owner_loss: p.owner_loss },
        );
        if let Some(l) = &self.ledger {
            l.write(&st.entries());
            if !st.warden {
                st.warden = true;
                if let Some(exe) = &self.host.warden {
                    l.start_warden(exe);
                }
            }
        }
        (cancel, meter)
    }

    /// Sees a started call to its end in the background, then sends its `done`.
    fn supervise(
        self: &Arc<Self>,
        id: String,
        running: runner::Running,
        cancel: Arc<Notify>,
        meter: Arc<Meter>,
        p: &Pending,
    ) {
        let s = self.clone();
        let store = self.host.store.clone();
        let limits = Limits {
            timeout: Duration::from_millis(p.timeout_ms),
            cap: p.config.output_cap,
            memory_bound: p.memory_bound,
        };
        let sandboxed = p.sandboxed;
        tokio::spawn(async move {
            let o = runner::finish(running, store.clone(), cancel, limits, meter).await;
            {
                let mut st = s.state.lock().unwrap();
                st.running.remove(&id);
                if let Some(l) = s.ledger.as_ref().filter(|_| !st.closed) {
                    l.write(&st.entries());
                }
            }
            store.remove_call_tmp(&id);
            let done = done_event(&id, o, sandboxed, &store);
            s.send(done);
        });
    }

    /// Expands a pattern within the roots (src/glob.rs).
    async fn glob(&self, a: &Map<String, Value>) -> Result<Value, Fail> {
        let config = self.state.lock().unwrap().config.clone();
        let Some(config) = config else { return fail("NotConfigured", "configure the session first") };
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
        let Some(pattern) = a.get("pattern").and_then(Value::as_str) else {
            return fail("BadRequest", "pattern is a string");
        };
        let pattern = glob::Pattern::parse(pattern).map_err(|m| Fail("BadRequest", m))?;
        let limit = opt_u64(a, "limit")?.unwrap_or(DEFAULT_GLOB_LIMIT).clamp(1, MAX_GLOB_LIMIT) as usize;
        let found = tokio::task::spawn_blocking(move || glob::expand(&cwd, &pattern, limit, walk::WALK_CAP))
            .await
            .map_err(|e| Fail("Failed", e.to_string()))?;
        Ok(json!({ "matches": found.matches, "truncated": found.truncated }))
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
            Some(c) => {
                c.cancel.notify_one();
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
        "killed": o.killed, "peakFootprint": o.peak_footprint, "memoryBound": o.memory_bound,
        "stdout": o.stdout.as_ref().map_or_else(|| json!({ "piped": true }), stream), "stderr": stream(&o.stderr),
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
