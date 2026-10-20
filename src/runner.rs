//! runner.rs — starting one call and seeing it to its end: argv executed directly (no shell), stdin closed (or, in a
//! pipeline, the previous stage's stdout), no terminal, its own process group, the given environment only, a time
//! limit, a memory bound on its physical footprint, cancellation, and both streams captured into the store. When the
//! call ends, whatever is left of its process group is killed with it.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
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
    /// The call's members at the last sample, each with its start time ([`follow`]): what a kill reaches besides the
    /// group, once a descendant that left it has been reparented away from the call.
    tracked: Mutex<Vec<(u32, u64)>>,
}

impl Meter {
    fn record(&self, bytes: u64) {
        self.now.store(bytes, Ordering::Relaxed);
        self.peak.fetch_max(bytes, Ordering::Relaxed);
    }

    /// The members seen at the last sample, with their start times.
    pub fn tracked(&self) -> Vec<(u32, u64)> {
        self.tracked.lock().unwrap().clone()
    }
}

/// A call's members now, each with its start time: its group, the processes in `known` that are still the processes
/// recorded there (same start time), and every descendant of either. Followed over the call's life, this keeps a
/// descendant that left the group (`setsid`, bubblewrap's `--new-session`) after its parent exits and it is reparented.
pub fn follow(pgid: u32, known: &[(u32, u64)]) -> Vec<(u32, u64)> {
    let alive: Vec<u32> = known.iter().filter(|(p, t)| procs::start_time(*p) == Some(*t)).map(|(p, _)| *p).collect();
    procs::members_with(pgid, &alive).into_iter().filter_map(|p| procs::start_time(p).map(|t| (p, t))).collect()
}

/// [`follow`] without the group: the processes in `known` that are still the processes recorded there, and their
/// descendants. For a recorded call whose group id now names a group that is not the call's (its leader's pid reused).
pub fn follow_known(known: &[(u32, u64)]) -> Vec<(u32, u64)> {
    let alive: Vec<u32> = known.iter().filter(|(p, t)| procs::start_time(*p) == Some(*t)).map(|(p, _)| *p).collect();
    procs::descendants_of(&alive).into_iter().filter_map(|p| procs::start_time(p).map(|t| (p, t))).collect()
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
///
/// `known` are members seen earlier ([`Meter::tracked`]): a descendant whose parent already exited is found only
/// through them.
///
/// A pid is never trusted alone: each member is recorded with its start time, and is signalled only while that is
/// still its start time, so a member that exits after the read and whose pid is reused is not the one killed.
fn kill_tree(pgid: u32, known: &[(u32, u64)]) -> bool {
    let members = follow(pgid, known);
    signal_group(pgid, Signal::KILL);
    for &(p, started) in &members {
        kill_if_same(p, started);
    }
    !members.is_empty()
}

/// SIGKILLs `pid` only while it is still the process that started at `started`; true when it signalled.
fn kill_if_same(pid: u32, started: u64) -> bool {
    if procs::start_time(pid) != Some(started) {
        return false;
    }
    match i32::try_from(pid).ok().and_then(Pid::from_raw) {
        Some(p) => rustix::process::kill_process(p, Signal::KILL).is_ok(),
        None => false,
    }
}

/// Measures the call's footprint every [`WATCH_EVERY`] into `meter`; returns once it passes `bound`.
async fn watchdog(pgid: u32, bound: u64, meter: Arc<Meter>) {
    let mut tick = tokio::time::interval(WATCH_EVERY);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let members = follow(pgid, &meter.tracked());
        let bytes = members.iter().filter_map(|(p, _)| procs::footprint(*p)).sum();
        *meter.tracked.lock().unwrap() = members;
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
        _ = watchdog(pgid, memory_bound, meter.clone()) => { killed = Some("oom"); kill_tree(pgid, &meter.tracked()); r.child.wait().await.ok() }
        _ = tokio::time::sleep(timeout) => { timed_out = true; terminate(&mut r.child, pgid).await }
        _ = cancel.notified() => { cancelled = true; terminate(&mut r.child, pgid).await }
    };
    // The call is over: anything it left running in its group (holding the pipes open, or just lingering) goes too, and
    // what left the group: a descendant in a session of its own, found through the members the watchdog last saw.
    kill_tree(pgid, &meter.tracked());
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

/// Kills a just-started call's group and its descendants, at once: nothing has been tracked yet, so a descendant that
/// left the group and outlived its parent is not looked for ([`kill_call`] is the form that does).
pub fn kill_now(pgid: u32) {
    kill_tree(pgid, &[]);
}

/// [`kill_now`] for a call whose members were seen earlier (`known`, [`Meter::tracked`] or a ledger's record), saying
/// whether it had anything left to kill.
pub fn kill_call(pgid: u32, known: &[(u32, u64)]) -> bool {
    kill_tree(pgid, known)
}

/// Kills the recorded members still the processes they were, and their descendants, and signals no group: for a
/// recorded call whose group id now names another group. Whether anything was there to kill.
pub fn kill_known(known: &[(u32, u64)]) -> bool {
    let members = follow_known(known);
    for &(p, started) in &members {
        kill_if_same(p, started);
    }
    !members.is_empty()
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

#[cfg(test)]
mod tests {
    use super::*;

    // --- killing a call's tree: a pid is never trusted alone ---

    #[test]
    fn a_member_whose_start_time_changed_is_not_killed_and_one_whose_did_not_is() {
        let mut child = std::process::Command::new("sleep").arg("30").spawn().unwrap();
        let pid = child.id();
        let started = procs::start_time(pid).expect("a live child has a start time");
        // The same pid with another start time stands for a reused pid: it is left alone.
        assert!(!kill_if_same(pid, started.wrapping_add(1)), "a reused pid is never signalled");
        assert!(child.try_wait().unwrap().is_none(), "the process behind it is still running");
        // Its own start time: it is the process that was recorded, and it dies.
        assert!(kill_if_same(pid, started));
        let status = child.wait().unwrap();
        assert!(!status.success(), "killed, not exited");
    }

    // --- a call's tree is followed while it runs, so a descendant that left its group dies with the call ---

    /// Starts `sh -c <script>` as a call; `script` may name `$PIDFILE`, where a moved descendant writes its pid.
    fn run_call(script: &str, pidfile: &std::path::Path) -> (Running, Arc<Store>, tempfile::TempDir) {
        let base = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::create(base.path()).unwrap());
        let env = BTreeMap::from([
            ("PIDFILE".to_string(), pidfile.to_string_lossy().into_owned()),
            ("PATH".to_string(), "/usr/bin:/bin".to_string()),
        ]);
        let p = Prepared {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), script.into()],
            argv0: None,
            cwd: base.path().into(),
            env,
        };
        (spawn(p, Stdio::null()).unwrap(), store, base)
    }

    /// The pid a moved descendant wrote, once it has.
    fn moved_pid(pidfile: &std::path::Path) -> u32 {
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(p) = std::fs::read_to_string(pidfile).ok().and_then(|s| s.trim().parse().ok()) {
                return p;
            }
            assert!(Instant::now() < end, "the descendant never started");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Whether `pid` is gone within a few seconds (a SIGKILL is delivered, not instant).
    fn gone(pid: u32) -> bool {
        let end = Instant::now() + Duration::from_secs(3);
        while procs::start_time(pid).is_some() && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(20));
        }
        procs::start_time(pid).is_none()
    }

    /// A descendant in a session of its own whose parent exits: it is reparented out of the call's group and tree.
    const SETSID_THEN_LEADER_EXITS: &str = "perl -e 'use POSIX; POSIX::setsid(); open(F, \">$ENV{PIDFILE}\"); print F $$; close F; open(STDOUT, \">/dev/null\"); open(STDERR, \">/dev/null\"); sleep 30' & sleep 1";

    #[tokio::test(flavor = "multi_thread")]
    async fn a_descendant_that_left_the_group_dies_when_the_call_ends_by_itself() {
        let d = tempfile::tempdir().unwrap();
        let pidfile = d.path().join("pid");
        let (r, store, _base) = run_call(SETSID_THEN_LEADER_EXITS, &pidfile);
        let limits = Limits { timeout: Duration::from_secs(20), cap: 1 << 16, memory_bound: u64::MAX };
        let o = finish(r, store, Arc::new(Notify::new()), limits, Arc::new(Meter::default())).await;
        assert_eq!(o.code, Some(0), "the leader exited by itself");
        let moved = moved_pid(&pidfile);
        assert!(gone(moved), "the descendant in its own session outlived its call");
    }
}
