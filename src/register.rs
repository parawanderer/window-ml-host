//! register.rs — what a session may declare with `register`: a process group it started itself, which the host then
//! owns as it owns a spawn (SHELL.md, the ownership ruling of 2026-10-23). Ownership is DECLARED, never observed: the
//! host verifies nothing about who started the group, and refuses only what would turn the declaration against the
//! host or the browser, or what another row already owns (the four refusals of the coordinator's R2 ruling).

use rustix::process::Pid;

use crate::procs;

/// How far up the parent chain the ancestor check walks; a chain longer than this is not a real one.
const MAX_ANCESTORS: usize = 64;

/// Why `pgid` may not be registered, or `None` when it may. Checks that it is a group this host can signal at all (its
/// own uid), and that it holds neither this host nor any of its ancestors: the port closing kills a registered group
/// under the default policy, and a group holding the browser would take the browser with it. Whether another row
/// already owns the group is the caller's to check, since it holds the tables.
pub fn refusal(pgid: u32) -> Option<String> {
    if pgid <= 1 {
        return Some("pgid is a process group id above 1".into());
    }
    let group = i32::try_from(pgid).ok().and_then(Pid::from_raw);
    if group.is_none_or(|g| rustix::process::test_kill_process_group(g).is_err()) {
        return Some(format!("{pgid} is not a process group this host may signal"));
    }
    let mut at = Some(std::process::id());
    for _ in 0..MAX_ANCESTORS {
        let Some(pid) = at.filter(|p| *p > 1) else { break };
        let in_group = i32::try_from(pid)
            .ok()
            .and_then(Pid::from_raw)
            .and_then(|p| rustix::process::getpgid(Some(p)).ok())
            .is_some_and(|g| g.as_raw_nonzero().get() as u32 == pgid);
        if in_group {
            return Some(format!("process group {pgid} holds this host or one of its ancestors (pid {pid})"));
        }
        at = procs::parent(pid);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- what may be registered ---

    #[test]
    fn a_group_this_process_started_may_be_registered() {
        use std::os::unix::process::CommandExt;
        let mut c = std::process::Command::new("sleep").arg("5").process_group(0).spawn().unwrap();
        assert_eq!(refusal(c.id()), None);
        let _ = c.kill();
        let _ = c.wait();
    }

    #[test]
    fn the_host_s_own_group_and_its_ancestors_groups_are_refused() {
        let me = rustix::process::getpgid(None).unwrap().as_raw_nonzero().get() as u32;
        assert!(refusal(me).is_some_and(|m| m.contains("ancestors")), "{:?}", refusal(me));
        if let Some(parent) = procs::parent(std::process::id()) {
            let g = rustix::process::getpgid(Pid::from_raw(parent as i32)).unwrap().as_raw_nonzero().get() as u32;
            if g > 1 {
                assert!(refusal(g).is_some(), "the parent's group {g}");
            }
        }
    }

    #[test]
    fn init_a_gone_group_and_one_past_the_pid_range_are_refused() {
        assert!(refusal(0).is_some());
        assert!(refusal(1).is_some());
        let mut c = std::process::Command::new("true").spawn().unwrap();
        let gone = c.id();
        c.wait().unwrap();
        assert!(refusal(gone).is_some(), "a group that no longer exists");
        assert!(refusal(u32::MAX).is_some(), "an id no pid can have");
    }
}
