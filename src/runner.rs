//! runner.rs — starting one call and seeing it to its end: argv executed directly (no shell), stdin closed (or, in a
//! pipeline, the previous stage's stdout), no terminal, its own process group, the given environment only, a time
//! limit, a memory bound on its physical footprint, cancellation, and both streams captured into the store. When the
//! call ends, whatever is left of its process group is killed with it.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rustix::process::{Pid, Signal};
use tokio::process::{Child, Command};
use tokio::sync::Notify;

use crate::procs;
use crate::store::{Held, Store};

/// How long a call has after SIGTERM before SIGKILL.
pub const KILL_GRACE: Duration = Duration::from_secs(2);
/// How long to wait for the output pipes to close once the process group is gone.
const DRAIN_GRACE: Duration = Duration::from_secs(5);
/// How often the watchdog measures a call's footprint. An allocation faster than the bound per interval overshoots it
/// by at most one interval's growth before the kill.
pub const WATCH_EVERY: Duration = Duration::from_millis(100);

/// A call's measured footprint: the last sample and the peak, in bytes. `status` reads it while the call runs.
#[derive(Default, Debug)]
pub struct Meter {
    pub now: AtomicU64,
    pub peak: AtomicU64,
}

impl Meter {
    fn record(&self, bytes: u64) {
        self.now.store(bytes, Ordering::Relaxed);
        self.peak.fetch_max(bytes, Ordering::Relaxed);
    }
}

/// What a call is held to while it runs.
pub struct Limits {
    pub timeout: Duration,
    /// The most bytes of each stream kept.
    pub cap: u64,
    /// The physical footprint past which the whole call is killed (`alloc(process) ≤ bound`, EFFECTS.md).
    pub memory_bound: u64,
}

/// A call ready to start: the command line actually executed (the sandbox wrapper, or the program itself).
pub struct Prepared {
    pub program: PathBuf,
    pub args: Vec<OsString>,
    /// `argv[0]` as the caller wrote it, given to an unwrapped program (a wrapped one sees its realpath).
    pub argv0: Option<String>,
    pub cwd: PathBuf,
    pub env: BTreeMap<String, String>,
}

/// A started call.
pub struct Running {
    child: Child,
    pub pid: u32,
}

/// How a call ended.
#[derive(Debug)]
pub struct Outcome {
    pub code: Option<i32>,
    pub signal: Option<String>,
    pub timed_out: bool,
    pub cancelled: bool,
    /// Why the host killed the call on its own, beyond the time limit: `"oom"` past the memory bound.
    pub killed: Option<&'static str>,
    /// The highest footprint the watchdog measured, in bytes.
    pub peak_footprint: u64,
    pub memory_bound: u64,
    pub duration_ms: u64,
    /// `None` when the stdout went on to the next stage of a pipeline ([`Running::take_stdout`]).
    pub stdout: Option<Captured>,
    pub stderr: Captured,
}

/// A captured stream (its pointer and what was kept), or why it could not be kept.
pub type Captured = Result<(String, Held), String>;

impl Running {
    /// Hands this call's stdout to the next stage of a pipeline as its stdin. The host keeps no copy of the pipe's
    /// read end once that stage has started, so the writer gets SIGPIPE when the reader exits. [`finish`] then
    /// captures only stderr.
    pub fn take_stdout(&mut self) -> std::io::Result<Stdio> {
        let out = self.child.stdout.take().ok_or_else(|| std::io::Error::other("stdout is already taken"))?;
        out.try_into()
    }
}

/// Starts the call with `stdin` as its standard input (`Stdio::null()` for a call alone). The process leads a new
/// process group (its pid is the group id), so a signal reaches everything it started. Dropping the handle does NOT
/// kill it: the session decides what happens to a call whose owner is gone (`session::serve`).
pub fn spawn(p: Prepared, stdin: Stdio) -> std::io::Result<Running> {
    let mut c = Command::new(&p.program);
    c.args(&p.args)
        .env_clear()
        .envs(&p.env)
        .current_dir(&p.cwd)
        .stdin(stdin)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    if let Some(a0) = &p.argv0 {
        c.arg0(a0);
    }
    let child = c.spawn()?;
    let pid = child.id().unwrap_or(0);
    Ok(Running { child, pid })
}

fn signal_group(pgid: u32, sig: Signal) {
    if let Some(pid) = i32::try_from(pgid).ok().and_then(Pid::from_raw) {
        let _ = rustix::process::kill_process_group(pid, sig);
    }
}

/// Kills a call's group and any descendant a wrapper moved out of it (a new session), at once; whether anything was
/// there to kill. The members are read BEFORE anything is signalled: once the group's leader dies its children are
/// reparented, and a descendant in a session of its own (bubblewrap's `--new-session`) could no longer be found.
fn kill_tree(pgid: u32) -> bool {
    let members = procs::members(pgid);
    signal_group(pgid, Signal::KILL);
    for p in &members {
        if let Some(pid) = i32::try_from(*p).ok().and_then(Pid::from_raw) {
            let _ = rustix::process::kill_process(pid, Signal::KILL);
        }
    }
    !members.is_empty()
}

/// Measures the call's footprint every [`WATCH_EVERY`] into `meter`; returns once it passes `bound`.
async fn watchdog(pgid: u32, bound: u64, meter: Arc<Meter>) {
    let mut tick = tokio::time::interval(WATCH_EVERY);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let (bytes, _) = procs::call_footprint(pgid);
        meter.record(bytes);
        if bytes > bound {
            return;
        }
    }
}

/// Waits for the call to end, by itself, at the time limit, past the memory bound, or when `cancel` is notified;
/// captures both streams (a stdout already taken for a pipeline excepted) with at most `cap` bytes kept each.
pub async fn finish(
    mut r: Running,
    store: Arc<Store>,
    cancel: Arc<Notify>,
    limits: Limits,
    meter: Arc<Meter>,
) -> Outcome {
    let started = Instant::now();
    let Limits { timeout, cap, memory_bound } = limits;
    let pgid = r.pid;
    let out = r.child.stdout.take();
    let err = r.child.stderr.take().expect("piped");
    let s1 = store.clone();
    let out_task = out.map(|out| tokio::spawn(async move { s1.capture(out, cap).await.map_err(|e| e.to_string()) }));
    let s2 = store.clone();
    let err_task = tokio::spawn(async move { s2.capture(err, cap).await.map_err(|e| e.to_string()) });

    let (mut timed_out, mut cancelled, mut killed) = (false, false, None);
    let status: Option<ExitStatus> = tokio::select! {
        s = r.child.wait() => s.ok(),
        // No grace past the bound: the machine is the one short of memory.
        _ = watchdog(pgid, memory_bound, meter.clone()) => { killed = Some("oom"); kill_tree(pgid); r.child.wait().await.ok() }
        _ = tokio::time::sleep(timeout) => { timed_out = true; terminate(&mut r.child, pgid).await }
        _ = cancel.notified() => { cancelled = true; terminate(&mut r.child, pgid).await }
    };
    // The call is over: anything it left running in its group (holding the pipes open, or just lingering) goes too.
    kill_tree(pgid);
    let join = |t: tokio::task::JoinHandle<Captured>| async move {
        match tokio::time::timeout(DRAIN_GRACE, t).await {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => Err(e.to_string()),
            Err(_) => Err("output still open after the call ended (a process outside its group holds it)".into()),
        }
    };
    let stdout = match out_task {
        Some(t) => Some(join(t).await),
        None => None,
    };
    let stderr = join(err_task).await;
    use std::os::unix::process::ExitStatusExt;
    Outcome {
        code: status.and_then(|s| s.code()),
        signal: status.and_then(|s| s.signal()).map(signal_name),
        timed_out,
        cancelled,
        killed,
        peak_footprint: meter.peak.load(Ordering::Relaxed),
        memory_bound,
        duration_ms: started.elapsed().as_millis() as u64,
        stdout,
        stderr,
    }
}

/// SIGTERM to the group, then SIGKILL after [`KILL_GRACE`].
async fn terminate(child: &mut Child, pgid: u32) -> Option<ExitStatus> {
    signal_group(pgid, Signal::TERM);
    match tokio::time::timeout(KILL_GRACE, child.wait()).await {
        Ok(s) => s.ok(),
        Err(_) => {
            signal_group(pgid, Signal::KILL);
            child.wait().await.ok()
        }
    }
}

/// Kills a running call's whole group, and what it started outside it, at once (the session is ending).
pub fn kill_now(pgid: u32) {
    kill_tree(pgid);
}

/// [`kill_now`], saying whether the call had anything left to kill.
pub fn kill_call(pgid: u32) -> bool {
    kill_tree(pgid)
}

/// Kills a call that was started but will never be supervised (a later stage of its pipeline failed to start), and
/// reaps it.
pub async fn abort(mut r: Running) {
    kill_now(r.pid);
    let _ = r.child.wait().await;
}

/// A signal's name, for the numbers POSIX fixes; others as `SIG<n>`.
fn signal_name(n: i32) -> String {
    match n {
        1 => "SIGHUP".into(),
        2 => "SIGINT".into(),
        3 => "SIGQUIT".into(),
        4 => "SIGILL".into(),
        6 => "SIGABRT".into(),
        8 => "SIGFPE".into(),
        9 => "SIGKILL".into(),
        11 => "SIGSEGV".into(),
        13 => "SIGPIPE".into(),
        14 => "SIGALRM".into(),
        15 => "SIGTERM".into(),
        _ => format!("SIG{n}"),
    }
}
