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
    // A ruleset that asks for every write right and EXECUTE, at the highest ABI this crate knows,
    // with HardRequirement: if the kernel cannot fully enforce that, we report no ABI at all.
    let abi = ABI::V9;
    let access = AccessFs::from_write(abi) | AccessFs::Execute;
    let ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(access)
        .map_err(|e| format!("handle_access: {e}"))?
        .create()
        .map_err(|e| format!("create: {e}"))?;
    // One real rule so create+restrict is exercised the way a call's would be.
    let _ = PathFd::new("/").map_err(|e| format!("PathFd: {e}"))?;
    let status = ruleset
        .add_rule(PathBeneath::new(PathFd::new("/").map_err(|e| format!("PathFd: {e}"))?, access))
        .map_err(|e| format!("add_rule: {e}"))?
        .restrict_self()
        .map_err(|e| format!("restrict_self: {e}"))?;
    if status.ruleset != RulesetStatus::FullyEnforced {
        return Err(format!("ruleset only {:?}, not fully enforced", status.ruleset));
    }
    match status.landlock {
        LandlockStatus::Available { effective_abi, .. } => Ok(effective_abi as i32),
        _ => Err("landlock not available".into()),
    }
}

#[cfg(target_os = "linux")]
fn apply_and_exec(rules: &LandlockRules, program: &std::path::Path, args: &[String]) -> Result<(), String> {
    use landlock::{
        ABI, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr,
        RulesetStatus,
    };
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    let abi = ABI::from(rules.abi);
    if abi == ABI::Unsupported {
        return Err(format!("unsupported Landlock ABI {}", rules.abi));
    }
    let write = AccessFs::from_write(abi);
    // File-level ops only on a root inode: create/remove/truncate a file, never mkdir/symlink.
    let file_ops = write & (AccessFs::WriteFile | AccessFs::MakeReg | AccessFs::RemoveFile | AccessFs::Truncate);
    let handle = if rules.exec.is_empty() { write } else { write | AccessFs::Execute };
    let ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(handle)
        .map_err(|e| format!("handle_access: {e}"))?
        .create()
        .map_err(|e| format!("create: {e}"))?;
    let mut created = ruleset;
    for p in rules.write_files.iter() {
        created = add(created, p, file_ops)?;
    }
    for p in rules.write_trees.iter() {
        created = add(created, p, write)?;
    }
    for p in rules.exec.iter() {
        created = add(created, p, AccessFs::Execute)?;
    }
    let status = created.restrict_self().map_err(|e| format!("restrict_self: {e}"))?;
    if status.ruleset != RulesetStatus::FullyEnforced {
        return Err(format!("ruleset only {:?}, not fully enforced", status.ruleset));
    }
    let err = Command::new(program).args(args).exec();
    Err(format!("exec {}: {err}", program.display()))
}

#[cfg(target_os = "linux")]
fn add(
    created: landlock::RulesetCreated,
    path: &std::path::Path,
    access: landlock::BitFlags<landlock::AccessFs>,
) -> Result<landlock::RulesetCreated, String> {
    use landlock::{Compatible, PathBeneath, PathFd, RulesetCreatedAttr};
    let fd = PathFd::new(path).map_err(|e| format!("{}: {e}", path.display()))?;
    created.add_rule(PathBeneath::new(fd, access)).map_err(|e| format!("{}: {e}", path.display()))
}
