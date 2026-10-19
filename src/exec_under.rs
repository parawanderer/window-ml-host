//! exec_under.rs — the two Linux-only Landlock entry points of the `wmlhost` binary: `landlock-abi`
//! (probe, run as a child at start) and `exec-under` (apply a ruleset the host computed, then exec).
//! The host owns the policy; this module only enforces it. `unsafe` stays forbidden: the `landlock`
//! crate provides the syscalls.

use crate::sandbox::LandlockRules;

/// `wmlhost landlock-abi` — print the ABI our ruleset can be fully enforced at, or `0`. Run as a
/// child because a ruleset cannot be tested without restricting the tester.
pub fn landlock_abi_main() -> i32 {
    #[cfg(target_os = "linux")]
    {
        match probe_abi() {
            Ok(n) => {
                println!("{n}");
                0
            }
            Err(e) => {
                eprintln!("wmlhost landlock-abi: {e}");
                println!("0");
                0
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        println!("0");
        0
    }
}

/// `wmlhost exec-under <ruleset-json> -- <prog> <args…>` — apply the host's Landlock ruleset, then
/// exec. Exits non-zero when the ruleset cannot be fully enforced (never falls back to unrestricted).
pub fn exec_under_main(args: &[String]) -> i32 {
    let Some(json) = args.first() else {
        eprintln!("wmlhost exec-under: missing <ruleset-json>");
        return 2;
    };
    let rest = &args[1..];
    let Some(sep) = rest.iter().position(|a| a == "--") else {
        eprintln!("wmlhost exec-under: missing -- separator");
        return 2;
    };
    let prog = &rest[sep + 1..];
    let Some((program, prog_args)) = prog.split_first() else {
        eprintln!("wmlhost exec-under: missing program");
        return 2;
    };
    let rules: LandlockRules = match serde_json::from_str(json) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("wmlhost exec-under: bad ruleset: {e}");
            return 2;
        }
    };
    #[cfg(target_os = "linux")]
    {
        if let Err(e) = apply_and_exec(&rules, std::path::Path::new(program), prog_args) {
            eprintln!("wmlhost exec-under: {e}");
            return 2;
        }
        0
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (rules, program, prog_args);
        eprintln!("wmlhost exec-under: Landlock is Linux-only");
        2
    }
}

#[cfg(target_os = "linux")]
fn probe_abi() -> Result<i32, String> {
    use landlock::{
        ABI, AccessFs, CompatLevel, Compatible, LandlockStatus, PathBeneath, PathFd, Ruleset, RulesetAttr,
        RulesetCreatedAttr, RulesetStatus,
    };
    // Step 1: learn the kernel's own ABI with a BestEffort ruleset at the highest ABI this crate
    // knows. HardRequirement at V9 would be a CompatError on every kernel below ABI 9 and would
    // report "no Landlock" everywhere.
    let high = ABI::V9;
    let high_access = AccessFs::from_write(high) | AccessFs::Execute;
    let best = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(high_access)
        .map_err(|e| format!("handle_access: {e}"))?
        .create()
        .map_err(|e| format!("create: {e}"))?;
    let status = best
        .add_rule(PathBeneath::new(PathFd::new("/").map_err(|e| format!("PathFd: {e}"))?, high_access))
        .map_err(|e| format!("add_rule: {e}"))?
        .restrict_self()
        .map_err(|e| format!("restrict_self: {e}"))?;
    let effective = match status.landlock {
        LandlockStatus::Available { effective_abi, .. } => effective_abi,
        _ => return Err("landlock not available".into()),
    };
    // Step 2: require HardRequirement at that ABI, so the ABI we report is one a call's ruleset can
    // be fully enforced at. This restriction stacks on the best-effort one; the probe then exits.
    let access = AccessFs::from_write(effective) | AccessFs::Execute;
    let ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(access)
        .map_err(|e| format!("handle_access: {e}"))?
        .create()
        .map_err(|e| format!("create: {e}"))?;
    let status = ruleset
        .add_rule(PathBeneath::new(PathFd::new("/").map_err(|e| format!("PathFd: {e}"))?, access))
        .map_err(|e| format!("add_rule: {e}"))?
        .restrict_self()
        .map_err(|e| format!("restrict_self: {e}"))?;
    if status.ruleset != RulesetStatus::FullyEnforced {
        return Err(format!("ruleset only {:?}, not fully enforced", status.ruleset));
    }
    Ok(effective as i32)
}

/// The access sets one call's ruleset uses at `abi`. Pure so the ABI masking is testable on any
/// host that builds the Linux code: every bit a rule carries must be one `from_write`/`from_all`
/// reports at that ABI, or HardRequirement turns the whole ruleset into an error at V1–V2.
#[cfg(target_os = "linux")]
fn access_sets(abi: landlock::ABI) -> AccessSets {
    use landlock::AccessFs;
    let write = AccessFs::from_write(abi);
    AccessSets {
        // Name-immutable top level: edit the contents of what is there, create/remove/rename nothing.
        // Masked to the ABI: Truncate is V3+, and an unhandled bit is a hard error below that.
        edit: write & (AccessFs::WriteFile | AccessFs::Truncate),
        // File-level ops inside `.git`: create/remove/truncate a file, never mkdir/symlink.
        file_ops: write & (AccessFs::WriteFile | AccessFs::MakeReg | AccessFs::RemoveFile | AccessFs::Truncate),
        write,
        // EXECUTE grants for `program-only`. Execute has been in from_all since V1.
        exec: landlock::BitFlags::from(AccessFs::Execute),
    }
}

/// The four ruleset access sets, kept together so a test can assert each against the ABI.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy)]
struct AccessSets {
    edit: landlock::BitFlags<landlock::AccessFs>,
    file_ops: landlock::BitFlags<landlock::AccessFs>,
    write: landlock::BitFlags<landlock::AccessFs>,
    exec: landlock::BitFlags<landlock::AccessFs>,
}

#[cfg(target_os = "linux")]
fn apply_and_exec(rules: &LandlockRules, program: &std::path::Path, args: &[String]) -> Result<(), String> {
    use landlock::{ABI, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr, RulesetStatus};
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    let abi = ABI::from(rules.abi);
    if abi == ABI::Unsupported {
        return Err(format!("unsupported Landlock ABI {}", rules.abi));
    }
    let sets = access_sets(abi);
    let handle = if rules.exec.is_empty() { sets.write } else { sets.write | sets.exec };
    let ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(handle)
        .map_err(|e| format!("handle_access: {e}"))?
        .create()
        .map_err(|e| format!("create: {e}"))?;
    let mut created = ruleset;
    for p in rules.write_edit.iter() {
        created = add(created, p, sets.edit)?;
    }
    for p in rules.write_files.iter() {
        created = add(created, p, sets.file_ops)?;
    }
    for p in rules.write_trees.iter() {
        // A regular file never gets directory-only rights (HardRequirement would refuse the
        // whole ruleset); the host sends directories here, this is TOCTOU insurance.
        let acc = if std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_file()) {
            sets.write & AccessFs::from_file(abi)
        } else {
            sets.write
        };
        created = add(created, p, acc)?;
    }
    for p in rules.exec.iter() {
        created = add(created, p, sets.exec)?;
    }
    let status = created.restrict_self().map_err(|e| format!("restrict_self: {e}"))?;
    if status.ruleset != RulesetStatus::FullyEnforced {
        return Err(format!("ruleset only {:?}, not fully enforced", status.ruleset));
    }
    let err = Command::new(program).args(args).exec();
    Err(format!("exec {}: {err}", program.display()))
}

/// Adds one path rule. A missing or dangling path is "no grant" (dropping a grant only narrows); a
/// symlink is never granted (a dangling one would break the ruleset, a live one would grant a path
/// the enumeration never judged).
#[cfg(target_os = "linux")]
fn add(
    created: landlock::RulesetCreated,
    path: &std::path::Path,
    access: landlock::BitFlags<landlock::AccessFs>,
) -> Result<landlock::RulesetCreated, String> {
    use landlock::{PathBeneath, PathFd, RulesetCreatedAttr};
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => return Ok(created),
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(created),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    }
    let fd = PathFd::new(path).map_err(|e| format!("{}: {e}", path.display()))?;
    created.add_rule(PathBeneath::new(fd, access)).map_err(|e| format!("{}: {e}", path.display()))
}

/// The ABI surface: every access set the ruleset uses at each ABI carries only bits that ABI
/// handles. `edit` is the trap — Truncate is V3+, so an unmasked `WriteFile|Truncate` makes
/// HardRequirement reject the whole ruleset on an ABI 1–2 kernel and every `write: "roots"`
/// call becomes `SandboxFailed`. Execute is in `from_all` since V1. Refer is V2+, IoctlDev
/// V5+, ResolveUnix V9; none of those are in these sets, and this test keeps it that way.
#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::access_sets;
    use landlock::{ABI, AccessFs};

    #[test]
    fn every_access_set_is_handled_at_every_abi() {
        for abi in [ABI::V1, ABI::V2, ABI::V3, ABI::V4, ABI::V5, ABI::V6, ABI::V7, ABI::V8, ABI::V9] {
            let s = access_sets(abi);
            let handled = AccessFs::from_write(abi) | AccessFs::from_read(abi);
            assert!(handled.contains(s.edit), "edit at {abi:?}: {:?}", s.edit);
            assert!(handled.contains(s.file_ops), "file_ops at {abi:?}: {:?}", s.file_ops);
            assert!(handled.contains(s.write), "write at {abi:?}: {:?}", s.write);
            assert!(handled.contains(s.exec), "exec at {abi:?}: {:?}", s.exec);
        }
    }

    #[test]
    fn edit_is_truncate_only_where_the_abi_has_it() {
        for abi in [ABI::V1, ABI::V2, ABI::V3, ABI::V4, ABI::V5, ABI::V6, ABI::V7, ABI::V8, ABI::V9] {
            let s = access_sets(abi);
            assert!(s.edit.contains(AccessFs::WriteFile), "WriteFile must stay at {abi:?}");
            if matches!(abi, ABI::V1 | ABI::V2) {
                assert!(!s.edit.contains(AccessFs::Truncate), "Truncate must be masked off at {abi:?}");
            } else {
                assert!(s.edit.contains(AccessFs::Truncate), "Truncate must be present at {abi:?}");
            }
        }
    }

    #[test]
    fn file_ops_never_carries_directory_or_symlink_rights() {
        for abi in [ABI::V1, ABI::V2, ABI::V3, ABI::V4, ABI::V5, ABI::V6, ABI::V7, ABI::V8, ABI::V9] {
            let s = access_sets(abi);
            // edit = WriteFile|Truncate only: the name-immutable top level.
            assert!(!s.edit.contains(AccessFs::MakeReg), "edit must not make names at {abi:?}");
            assert!(!s.edit.contains(AccessFs::MakeDir), "edit must not make dirs at {abi:?}");
            assert!(!s.edit.contains(AccessFs::MakeSym), "edit must not make symlinks at {abi:?}");
            assert!(!s.edit.contains(AccessFs::RemoveFile), "edit must not unlink at {abi:?}");
            assert!(!s.edit.contains(AccessFs::RemoveDir), "edit must not rmdir at {abi:?}");
            assert!(!s.edit.contains(AccessFs::Refer), "edit must not refer at {abi:?}");
            // file_ops may create/remove a file, never mkdir/symlink/refer.
            assert!(!s.file_ops.contains(AccessFs::MakeDir), "file_ops must not mkdir at {abi:?}");
            assert!(!s.file_ops.contains(AccessFs::MakeSym), "file_ops must not symlink at {abi:?}");
            assert!(!s.file_ops.contains(AccessFs::Refer), "file_ops must not refer at {abi:?}");
        }
    }
}
