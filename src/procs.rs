//! procs.rs — what the host reads of the processes it started, never through `ps`: a process's start time (so a reused
//! pid is never taken for ours), a call's members (its process group and every descendant, which catches a sandboxed
//! program that a wrapper put in a session of its own), and each member's physical footprint.
//!
//! The footprint is what the memory bound is enforced on (SHELL.md, "Every process has an owner, and a memory bound"):
//! macOS's `ri_phys_footprint`, the number Activity Monitor and Jetsam use; on Linux the anonymous and shared resident
//! pages plus swap, which leaves out file-backed pages the kernel can drop. Never the address space: JITs and allocators
//! reserve ranges they never touch.

/// At most this many members are followed for one call (a fork bomb is not walked forever).
pub const MAX_MEMBERS: usize = 4096;

/// A process's start time in microseconds since the epoch (macOS) or clock ticks since boot (Linux): only ever compared
/// with another reading of the same process, so the unit does not matter.
pub fn start_time(pid: u32) -> Option<u64> {
    sys::start_time(pid)
}

/// The process group `pgid` and every descendant of its members, `pgid` first if it is alive.
pub fn members(pgid: u32) -> Vec<u32> {
    sys::members(Some(pgid), &[])
}

/// [`members`], also following `known`: processes seen in the call before, which the caller has checked are still
/// those processes. A descendant that left the group (`setsid`) is reparented away from the call once its parent
/// exits, so after that only an earlier sighting finds it, and its own descendants.
pub fn members_with(pgid: u32, known: &[u32]) -> Vec<u32> {
    sys::members(Some(pgid), known)
}

/// `known` and every descendant of them, and nothing else: no group is read. For a recorded call whose group id now
/// names another process's group, so that group is not taken for the call's.
pub fn descendants_of(known: &[u32]) -> Vec<u32> {
    sys::members(None, known)
}

/// One process's physical footprint in bytes; `None` once it is gone.
pub fn footprint(pid: u32) -> Option<u64> {
    sys::footprint(pid)
}

/// One process's CPU time in nanoseconds, user and system, its own plus that of the children it has reaped; `None` once
/// it is gone. A child is counted once: while it lives by itself, after its parent reaps it in the parent's figure. A
/// child reparented away and reaped by `init` takes its time with it.
pub fn cpu_ns(pid: u32) -> Option<u64> {
    sys::cpu_ns(pid)
}

/// A process's parent; `None` once it is gone.
pub fn parent(pid: u32) -> Option<u32> {
    sys::parent(pid)
}

/// The summed footprint of a call's members, and the members measured.
pub fn call_footprint(pgid: u32) -> (u64, Vec<u32>) {
    let pids = members(pgid);
    let total = pids.iter().filter_map(|p| footprint(*p)).sum();
    (total, pids)
}

/// What `hello` says about the measure, for the policy and the run log.
pub fn metric() -> &'static str {
    sys::METRIC
}

/// What `hello` says the CPU fact counts.
pub const CPU_METRIC: &str = "user+system, with reaped children";

/// Appends each of `known` the seed does not already hold.
fn add_known(seed: &mut Vec<u32>, known: &[u32]) {
    for &k in known {
        if k != 0 && !seed.contains(&k) {
            seed.push(k);
        }
    }
}

fn closure(seed: Vec<u32>, children: impl Fn(u32) -> Vec<u32>) -> Vec<u32> {
    let mut out = seed;
    let mut i = 0;
    while i < out.len() && out.len() < MAX_MEMBERS {
        for c in children(out[i]) {
            if c != 0 && !out.contains(&c) {
                out.push(c);
            }
        }
        i += 1;
    }
    out.truncate(MAX_MEMBERS);
    out
}

#[cfg(target_os = "macos")]
mod sys {
    use libproc::bsd_info::BSDInfo;
    use libproc::pid_rusage::{RUsageInfoV2, pidrusage};
    use libproc::proc_pid::pidinfo;
    use libproc::processes::{ProcFilter, pids_by_type};

    pub const METRIC: &str = "phys_footprint";

    pub fn start_time(pid: u32) -> Option<u64> {
        let b = pidinfo::<BSDInfo>(i32::try_from(pid).ok()?, 0).ok()?;
        (b.pbi_pid == pid).then(|| b.pbi_start_tvsec * 1_000_000 + b.pbi_start_tvusec)
    }

    pub fn members(pgid: Option<u32>, known: &[u32]) -> Vec<u32> {
        let list = |f| pids_by_type(f).unwrap_or_default().into_iter().filter(|p| *p != 0).collect::<Vec<u32>>();
        let mut seed = pgid.map(|g| list(ProcFilter::ByProgramGroup { pgrpid: g })).unwrap_or_default();
        seed.sort_by_key(|p| Some(*p) != pgid);
        super::add_known(&mut seed, known);
        super::closure(seed, |p| list(ProcFilter::ByParentProcess { ppid: p }))
    }

    pub fn footprint(pid: u32) -> Option<u64> {
        pidrusage::<RUsageInfoV2>(i32::try_from(pid).ok()?).ok().map(|r| r.ri_phys_footprint)
    }

    /// Mach absolute time units to nanoseconds: 125/3 on Apple silicon, 1/1 on Intel. Read as a constant because
    /// `mach_timebase_info` needs `unsafe`; `a_busy_child_s_cpu_time_tracks_the_wall_clock` fails if it is ever wrong.
    #[cfg(target_arch = "aarch64")]
    const TIMEBASE: (u64, u64) = (125, 3);
    #[cfg(not(target_arch = "aarch64"))]
    const TIMEBASE: (u64, u64) = (1, 1);

    pub fn cpu_ns(pid: u32) -> Option<u64> {
        let r = pidrusage::<RUsageInfoV2>(i32::try_from(pid).ok()?).ok()?;
        let ticks = r.ri_user_time + r.ri_system_time + r.ri_child_user_time + r.ri_child_system_time;
        Some((ticks as u128 * TIMEBASE.0 as u128 / TIMEBASE.1 as u128) as u64)
    }

    pub fn parent(pid: u32) -> Option<u32> {
        let b = pidinfo::<BSDInfo>(i32::try_from(pid).ok()?, 0).ok()?;
        (b.pbi_pid == pid).then_some(b.pbi_ppid)
    }
}

#[cfg(not(target_os = "macos"))]
mod sys {
    pub const METRIC: &str = "rss_anon+rss_shmem+swap";

    /// `(ppid, pgrp, starttime)` from `/proc/<pid>/stat`. The command name is in parentheses and may hold anything, so
    /// the fields are counted from the LAST `)`.
    fn stat(pid: u32) -> Option<(u32, u32, u64)> {
        let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let f: Vec<&str> = s.get(s.rfind(')')? + 1..)?.split_whitespace().collect();
        // f[0] is field 3 (state): ppid is field 4, pgrp field 5, starttime field 22.
        Some((f.get(1)?.parse().ok()?, f.get(2)?.parse().ok()?, f.get(19)?.parse().ok()?))
    }

    pub fn start_time(pid: u32) -> Option<u64> {
        stat(pid).map(|(_, _, t)| t)
    }

    pub fn parent(pid: u32) -> Option<u32> {
        stat(pid).map(|(pp, _, _)| pp)
    }

    /// utime, stime, cutime and cstime (fields 14 to 17 of `/proc/<pid>/stat`), in clock ticks.
    pub fn cpu_ns(pid: u32) -> Option<u64> {
        let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let f: Vec<&str> = s.get(s.rfind(')')? + 1..)?.split_whitespace().collect();
        let ticks: u64 = (11..15).map(|i| f.get(i)?.parse::<u64>().ok()).sum::<Option<u64>>()?;
        Some(ticks.saturating_mul(1_000_000_000) / rustix::param::clock_ticks_per_second().max(1))
    }

    pub fn members(pgid: Option<u32>, known: &[u32]) -> Vec<u32> {
        let all: Vec<(u32, u32, u32)> = std::fs::read_dir("/proc")
            .map(|d| {
                d.filter_map(|e| e.ok()?.file_name().to_str()?.parse::<u32>().ok())
                    .filter_map(|pid| stat(pid).map(|(pp, pg, _)| (pid, pp, pg)))
                    .collect()
            })
            .unwrap_or_default();
        let mut seed: Vec<u32> = all.iter().filter(|(_, _, pg)| Some(*pg) == pgid).map(|(p, _, _)| *p).collect();
        seed.sort_by_key(|p| Some(*p) != pgid);
        super::add_known(&mut seed, known);
        super::closure(seed, |p| all.iter().filter(|(_, pp, _)| *pp == p).map(|(c, _, _)| *c).collect())
    }

    pub fn footprint(pid: u32) -> Option<u64> {
        let s = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        let kb = |name: &str| -> u64 {
            s.lines()
                .find_map(|l| l.strip_prefix(name))
                .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
                .unwrap_or(0)
        };
        Some((kb("RssAnon:") + kb("RssShmem:") + kb("VmSwap:")) * 1024)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- reading our own processes ---

    #[test]
    fn this_process_has_a_start_time_and_a_footprint() {
        let me = std::process::id();
        assert!(start_time(me).is_some());
        assert_eq!(start_time(me), start_time(me), "a start time is stable");
        assert!(footprint(me).unwrap() > 0);
    }

    #[test]
    fn a_child_s_group_holds_it_and_its_descendants() {
        use std::os::unix::process::CommandExt;
        let mut c =
            std::process::Command::new("sh").args(["-c", "sleep 5 & sleep 5; wait"]).process_group(0).spawn().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(300));
        let m = members(c.id());
        assert_eq!(m.first(), Some(&c.id()), "{m:?}");
        assert!(m.len() >= 3, "sh and both sleeps: {m:?}");
        assert!(!m.contains(&std::process::id()));
        let _ = c.kill();
        let _ = rustix::process::kill_process_group(
            rustix::process::Pid::from_raw(c.id() as i32).unwrap(),
            rustix::process::Signal::KILL,
        );
        let _ = c.wait();
    }

    #[test]
    fn a_child_s_parent_is_this_process() {
        let mut c = std::process::Command::new("sleep").arg("5").spawn().unwrap();
        assert_eq!(parent(c.id()), Some(std::process::id()));
        let _ = c.kill();
        let _ = c.wait();
    }

    #[test]
    fn a_busy_child_s_cpu_time_tracks_the_wall_clock() {
        // One core spinning for a second: its CPU time is about a second. A wrong unit (Mach ticks read as nanoseconds,
        // clock ticks as milliseconds) is off by 24x or more, far outside the band.
        let mut c = std::process::Command::new("sh").args(["-c", "while :; do :; done"]).spawn().unwrap();
        let t0 = std::time::Instant::now();
        let before = cpu_ns(c.id()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1000));
        let spent = cpu_ns(c.id()).unwrap() - before;
        let wall = t0.elapsed().as_nanos() as u64;
        let _ = c.kill();
        let _ = c.wait();
        assert!(spent > wall / 3 && spent < wall * 3 / 2, "cpu {spent} ns over {wall} ns of wall clock");
    }

    #[test]
    fn a_gone_process_has_no_start_time_or_footprint() {
        let mut c = std::process::Command::new("true").spawn().unwrap();
        let pid = c.id();
        c.wait().unwrap();
        assert_eq!(start_time(pid), None);
        assert_eq!(footprint(pid), None);
        assert_eq!(cpu_ns(pid), None);
        assert_eq!(parent(pid), None);
    }
}
