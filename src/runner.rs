//! runner.rs — starting one call and seeing it to its end: argv executed directly (no shell), stdin closed, no
//! terminal, its own process group, the given environment only, a time limit, cancellation, and both streams captured
//! into the store. When the call ends, whatever is left of its process group is killed with it.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustix::process::{Pid, Signal};
use tokio::process::{Child, Command};
use tokio::sync::Notify;

use crate::store::{Held, Store};

/// How long a call has after SIGTERM before SIGKILL.
pub const KILL_GRACE: Duration = Duration::from_secs(2);
/// How long to wait for the output pipes to close once the process group is gone.
const DRAIN_GRACE: Duration = Duration::from_secs(5);

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
    pub duration_ms: u64,
    pub stdout: Captured,
    pub stderr: Captured,
}

/// A captured stream (its pointer and what was kept), or why it could not be kept.
pub type Captured = Result<(String, Held), String>;

/// Starts the call. The process leads a new process group (its pid is the group id), so a signal reaches everything it
/// started.
pub fn spawn(p: Prepared) -> std::io::Result<Running> {
    let mut c = Command::new(&p.program);
    c.args(&p.args)
        .env_clear()
        .envs(&p.env)
        .current_dir(&p.cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .kill_on_drop(true);
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

/// Waits for the call to end, by itself, at `timeout`, or when `cancel` is notified; captures both streams with at
/// most `cap` bytes kept each.
pub async fn finish(mut r: Running, store: Arc<Store>, cancel: Arc<Notify>, timeout: Duration, cap: u64) -> Outcome {
    let started = Instant::now();
    let pgid = r.pid;
    let out = r.child.stdout.take().expect("piped");
    let err = r.child.stderr.take().expect("piped");
    let s1 = store.clone();
    let out_task = tokio::spawn(async move { s1.capture(out, cap).await.map_err(|e| e.to_string()) });
    let s2 = store.clone();
    let err_task = tokio::spawn(async move { s2.capture(err, cap).await.map_err(|e| e.to_string()) });

    let (mut timed_out, mut cancelled) = (false, false);
    let status: Option<ExitStatus> = tokio::select! {
        s = r.child.wait() => s.ok(),
        _ = tokio::time::sleep(timeout) => { timed_out = true; terminate(&mut r.child, pgid).await }
        _ = cancel.notified() => { cancelled = true; terminate(&mut r.child, pgid).await }
    };
    // The call is over: anything it left running in its group (holding the pipes open, or just lingering) goes too.
    signal_group(pgid, Signal::KILL);
    let join = |t: tokio::task::JoinHandle<Captured>| async move {
        match tokio::time::timeout(DRAIN_GRACE, t).await {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => Err(e.to_string()),
            Err(_) => Err("output still open after the call ended (a process outside its group holds it)".into()),
        }
    };
    let stdout = join(out_task).await;
    let stderr = join(err_task).await;
    use std::os::unix::process::ExitStatusExt;
    Outcome {
        code: status.and_then(|s| s.code()),
        signal: status.and_then(|s| s.signal()).map(signal_name),
        timed_out,
        cancelled,
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

/// Kills a running call's whole group at once (the session is ending).
pub fn kill_now(pgid: u32) {
    signal_group(pgid, Signal::KILL);
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
