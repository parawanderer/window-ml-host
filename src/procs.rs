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
    sys::members(pgid)
}

/// One process's physical footprint in bytes; `None` once it is gone.
pub fn footprint(pid: u32) -> Option<u64> {
    sys::footprint(pid)
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

    pub fn members(pgid: u32) -> Vec<u32> {
        let list = |f| pids_by_type(f).unwrap_or_default().into_iter().filter(|p| *p != 0).collect::<Vec<u32>>();
        let mut seed = list(ProcFilter::ByProgramGroup { pgrpid: pgid });
        seed.sort_by_key(|p| *p != pgid);
        super::closure(seed, |p| list(ProcFilter::ByParentProcess { ppid: p }))
    }

    pub fn footprint(pid: u32) -> Option<u64> {
        pidrusage::<RUsageInfoV2>(i32::try_from(pid).ok()?).ok().map(|r| r.ri_phys_footprint)
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

    pub fn members(pgid: u32) -> Vec<u32> {
        let all: Vec<(u32, u32, u32)> = std::fs::read_dir("/proc")
            .map(|d| {
                d.filter_map(|e| e.ok()?.file_name().to_str()?.parse::<u32>().ok())
                    .filter_map(|pid| stat(pid).map(|(pp, pg, _)| (pid, pp, pg)))
                    .collect()
            })
            .unwrap_or_default();
        let mut seed: Vec<u32> = all.iter().filter(|(_, _, pg)| *pg == pgid).map(|(p, _, _)| *p).collect();
        seed.sort_by_key(|p| *p != pgid);
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
    fn a_gone_process_has_no_start_time_or_footprint() {
        let mut c = std::process::Command::new("true").spawn().unwrap();
        let pid = c.id();
        c.wait().unwrap();
        assert_eq!(start_time(pid), None);
        assert_eq!(footprint(pid), None);
    }
}
