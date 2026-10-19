//! owners.rs — the ONE owner table: every running call's process group, the process's start time, and the owner the
//! extension named (session, run, step). It lives in memory and is mirrored to a ledger file per host process, so a
//! host that is killed outright (SIGKILL, Jetsam) leaves a record the NEXT host reads: it kills those groups, or keeps
//! them on the orphan list until their deadline under the orphan policy. "Whose is this" is a read of this table, never
//! of `ps` (SHELL.md, "Every process has an owner, and a memory bound").
//!
//! A pid is never trusted alone. A recorded group is killed only when its leader is the same process (same start time),
//! or when no process has that pid at all: a process group's id cannot be reused while any member of the group is alive,
//! so a group with that id is still ours.

use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rustix::process::{Pid, Signal};
use serde_json::{Value, json};

use crate::procs;

/// Milliseconds since the epoch, the ledger's clock (it must mean the same thing to the next host process).
pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

/// One running call as the ledger records it.
#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub id: String,
    pub pgid: u32,
    /// The leader's start time ([`procs::start_time`]), `None` if it could not be read at start.
    pub start: Option<u64>,
    pub owner: Value,
    pub started_ms: u64,
    /// Set once the owner is gone under the orphan policy: the group is killed at this time.
    pub deadline_ms: Option<u64>,
    pub memory_bound: u64,
}

impl Entry {
    fn to_json(&self) -> Value {
        json!({ "id": self.id, "pgid": self.pgid, "start": self.start, "owner": self.owner,
                "startedMs": self.started_ms, "deadlineMs": self.deadline_ms, "memoryBound": self.memory_bound })
    }

    fn from_json(v: &Value) -> Option<Entry> {
        Some(Entry {
            id: v["id"].as_str()?.to_string(),
            pgid: u32::try_from(v["pgid"].as_u64()?).ok().filter(|p| *p > 1)?,
            start: v["start"].as_u64(),
            owner: v["owner"].clone(),
            started_ms: v["startedMs"].as_u64().unwrap_or(0),
            deadline_ms: v["deadlineMs"].as_u64(),
            memory_bound: v["memoryBound"].as_u64().unwrap_or(0),
        })
    }
}

/// Whether a recorded group still exists as OURS: its leader is the same process, or the leader is gone and the group
/// still has members.
pub fn still_ours(e: &Entry) -> bool {
    match procs::start_time(e.pgid) {
        Some(t) => e.start == Some(t),
        None => group_alive(e.pgid),
    }
}

fn pid(p: u32) -> Option<Pid> {
    i32::try_from(p).ok().and_then(Pid::from_raw)
}

fn group_alive(pgid: u32) -> bool {
    pid(pgid).is_some_and(|p| rustix::process::test_kill_process_group(p).is_ok())
}

/// SIGKILL to a recorded group, only if it is still ours ([`still_ours`]).
pub fn kill_if_ours(e: &Entry) -> bool {
    if !still_ours(e) {
        return false;
    }
    pid(e.pgid).is_some_and(|p| rustix::process::kill_process_group(p, Signal::KILL).is_ok())
}

/// One host process's ledger file. Writes are whole-file and atomic (a temp file renamed over), so a host killed
/// mid-write leaves the previous version.
pub struct Ledger {
    path: PathBuf,
}

/// The directory ledgers live in: `WMLHOST_STATE_DIR`, else `wmlhost-owners-<uid>` in the system temp dir. Private
/// (0700); a directory that is not ours, or not private, is not used.
pub fn default_dir(state_dir: Option<String>) -> PathBuf {
    match state_dir {
        Some(d) if Path::new(&d).is_absolute() => PathBuf::from(d),
        _ => std::env::temp_dir().join(format!("wmlhost-owners-{}", rustix::process::getuid().as_raw())),
    }
}

fn private_dir(dir: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let _ = std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir);
    match std::fs::symlink_metadata(dir) {
        Ok(m) => m.is_dir() && m.uid() == rustix::process::getuid().as_raw() && m.mode() & 0o077 == 0,
        Err(_) => false,
    }
}

impl Ledger {
    /// This host process's ledger in `dir`, named by its pid and start time. `None` if the directory cannot be used:
    /// the host then still owns its calls in memory, and says so in `hello`.
    pub fn open(dir: &Path) -> Option<Ledger> {
        if !private_dir(dir) {
            return None;
        }
        let me = std::process::id();
        let start = procs::start_time(me)?;
        Some(Ledger { path: dir.join(format!("{me}-{start}.json")) })
    }

    /// Replaces the ledger with `entries`; an empty table removes the file.
    pub fn write(&self, entries: &[Entry]) {
        if entries.is_empty() {
            let _ = std::fs::remove_file(&self.path);
            return;
        }
        let body = Value::Array(entries.iter().map(Entry::to_json).collect()).to_string();
        let tmp = self.path.with_extension("tmp");
        if std::fs::write(&tmp, body).is_ok() {
            let _ = std::fs::rename(&tmp, &self.path);
        }
    }

    pub fn remove(&self) {
        let _ = std::fs::remove_file(&self.path);
    }

    /// Starts this ledger's warden ([`warden_main`]): its own process group, so nothing signalling the host's group
    /// reaches it, and no stdio, so it never holds the browser's pipes open.
    pub fn start_warden(&self, exe: &Path) {
        use std::os::unix::process::CommandExt;
        let spawned = std::process::Command::new(exe)
            .arg("warden")
            .arg(&self.path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .process_group(0)
            .spawn();
        match spawned {
            // Reaped by a thread so it never lingers as a zombie of a long-lived host.
            Ok(mut c) => drop(std::thread::spawn(move || c.wait())),
            Err(e) => eprintln!("wmlhost: the warden did not start: {e}"),
        }
    }
}

/// What a sweep found of hosts that are gone.
#[derive(Debug, Default)]
pub struct Swept {
    /// Groups killed: their owner was lost with no orphan deadline, or the deadline passed.
    pub killed: Vec<Entry>,
    /// Groups left running until their deadline.
    pub orphans: Vec<Entry>,
}

/// Reads every ledger in `dir` whose host process is gone (its pid no longer names the process that wrote it): kills
/// what has no deadline or is past it, keeps the rest as orphans, and rewrites or removes each file accordingly. A live
/// host's ledger is never touched.
pub fn sweep(dir: &Path, own: Option<&Ledger>) -> Swept {
    let mut out = Swept::default();
    let Ok(rd) = std::fs::read_dir(dir) else { return out };
    for e in rd.flatten() {
        let path = e.path();
        if own.is_some_and(|l| l.path == path) || path.extension().is_none_or(|x| x != "json") {
            continue;
        }
        if let Some(s) = sweep_file(&path) {
            out.killed.extend(s.killed);
            out.orphans.extend(s.orphans);
        }
    }
    out
}

/// The host process a ledger file belongs to, from its name `<pid>-<start>.json`.
fn writer_of(path: &Path) -> Option<(u32, u64)> {
    let (p, t) = path.file_stem()?.to_str()?.split_once('-')?;
    Some((p.parse().ok()?, t.parse().ok()?))
}

fn host_alive(path: &Path) -> bool {
    writer_of(path).is_some_and(|(pid, start)| procs::start_time(pid) == Some(start))
}

/// Sweeps one ledger file if its host is gone; `None` if the host is alive or the name is not a ledger's.
fn sweep_file(path: &Path) -> Option<Swept> {
    writer_of(path)?;
    if host_alive(path) {
        return None;
    }
    let mut out = Swept::default();
    let now = now_ms();
    let entries: Vec<Entry> = std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .and_then(|v| v.as_array().map(|a| a.iter().filter_map(Entry::from_json).collect()))
        .unwrap_or_default();
    for en in entries {
        if !still_ours(&en) {
            continue;
        }
        if en.deadline_ms.is_some_and(|d| now < d) {
            out.orphans.push(en);
        } else if kill_if_ours(&en) {
            out.killed.push(en);
        }
    }
    if out.orphans.is_empty() {
        let _ = std::fs::remove_file(path);
    } else {
        let body = Value::Array(out.orphans.iter().map(Entry::to_json).collect()).to_string();
        let tmp = path.with_extension("tmp");
        if std::fs::write(&tmp, body).is_ok() {
            let _ = std::fs::rename(&tmp, path);
        }
    }
    Some(out)
}

/// How often a warden looks at its host.
pub const WARDEN_EVERY: std::time::Duration = std::time::Duration::from_millis(200);

/// `wmlhost warden <ledger>`: watches the host that writes `<ledger>` and, once that host is gone however it ended,
/// kills its calls (or keeps its orphans until their deadlines), then exits. A host that ends cleanly leaves no
/// ledger, and its warden exits with nothing to do.
pub fn warden_main(args: &[String]) -> i32 {
    let Some(path) = args.first().map(PathBuf::from) else {
        eprintln!("usage: wmlhost warden <ledger>");
        return 2;
    };
    if writer_of(&path).is_none() {
        eprintln!("wmlhost warden: {} is not a ledger", path.display());
        return 2;
    }
    loop {
        std::thread::sleep(WARDEN_EVERY);
        if host_alive(&path) {
            continue;
        }
        if !path.exists() {
            return 0;
        }
        sweep_file(&path);
    }
}

/// An orphan as `status` reports it.
pub fn orphan_json(e: &Entry) -> Value {
    json!({ "id": e.id, "pid": e.pgid, "owner": e.owner, "startedMs": e.started_ms, "deadlineMs": e.deadline_ms,
            "footprint": procs::call_footprint(e.pgid).0 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::CommandExt;

    fn sleeper() -> std::process::Child {
        std::process::Command::new("sleep").arg("30").process_group(0).spawn().unwrap()
    }

    fn entry(c: &std::process::Child, deadline_ms: Option<u64>) -> Entry {
        Entry {
            id: "c1".into(),
            pgid: c.id(),
            start: procs::start_time(c.id()),
            owner: json!({ "run": "r1" }),
            started_ms: now_ms(),
            deadline_ms,
            memory_bound: 0,
        }
    }

    /// A ledger as a dead host would have left it: a pid that names no process (or another process).
    fn dead_hosts_ledger(dir: &Path, entries: &[Entry]) -> PathBuf {
        let p = dir.join(format!("{}-1.json", std::process::id()));
        std::fs::write(&p, Value::Array(entries.iter().map(Entry::to_json).collect()).to_string()).unwrap();
        p
    }

    fn private_tmp() -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("owners");
        (d, p)
    }

    // --- sweeping a dead host's ledger ---

    #[test]
    fn a_dead_hosts_group_is_killed_and_its_ledger_removed() {
        let (_d, dir) = private_tmp();
        assert!(private_dir(&dir));
        let mut c = sleeper();
        let p = dead_hosts_ledger(&dir, &[entry(&c, None)]);
        let s = sweep(&dir, None);
        assert_eq!(s.killed.len(), 1);
        assert!(s.orphans.is_empty());
        assert!(c.wait().unwrap().code().is_none(), "killed by a signal");
        assert!(!p.exists());
    }

    #[test]
    fn an_orphan_before_its_deadline_is_kept_and_listed() {
        let (_d, dir) = private_tmp();
        assert!(private_dir(&dir));
        let mut c = sleeper();
        let p = dead_hosts_ledger(&dir, &[entry(&c, Some(now_ms() + 60_000))]);
        let s = sweep(&dir, None);
        assert!(s.killed.is_empty());
        assert_eq!(s.orphans.len(), 1);
        assert_eq!(s.orphans[0].owner, json!({ "run": "r1" }));
        assert!(c.try_wait().unwrap().is_none(), "still running");
        assert!(p.exists());
        let _ = c.kill();
        let _ = c.wait();
    }

    #[test]
    fn a_reused_pid_is_never_killed() {
        let (_d, dir) = private_tmp();
        assert!(private_dir(&dir));
        let mut c = sleeper();
        let mut e = entry(&c, None);
        e.start = e.start.map(|t| t + 1);
        dead_hosts_ledger(&dir, &[e]);
        let s = sweep(&dir, None);
        assert!(s.killed.is_empty());
        assert!(c.try_wait().unwrap().is_none(), "another process with the same pid survives");
        let _ = c.kill();
        let _ = c.wait();
    }

    #[test]
    fn a_live_hosts_ledger_is_not_touched() {
        let (_d, dir) = private_tmp();
        let own = Ledger::open(&dir).expect("a private dir");
        let mut c = sleeper();
        own.write(&[entry(&c, None)]);
        assert!(sweep(&dir, None).killed.is_empty(), "this process is alive, so its ledger is not a dead host's");
        assert!(c.try_wait().unwrap().is_none());
        own.write(&[]);
        assert!(!own.path.exists());
        let _ = c.kill();
        let _ = c.wait();
    }

    #[test]
    fn a_shared_or_foreign_directory_is_not_used() {
        use std::os::unix::fs::PermissionsExt;
        let (_d, dir) = private_tmp();
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(Ledger::open(&dir).is_none());
    }
}
