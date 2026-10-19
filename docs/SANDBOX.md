# The OS sandbox, as built

What a call can and cannot do under each platform's sandbox, what the tests prove, and where the two platforms differ.
The design is window-ml's [`SHELL.md`](https://github.com/parawanderer/window-ml/blob/main/docs/spec/SHELL.md)
("An OS sandbox, on by default") and [`EFFECTS.md`](https://github.com/parawanderer/window-ml/blob/main/docs/spec/EFFECTS.md)
(what an enforcer bounds); the code is `src/sandbox.rs`.

## The rule

On by default, per session (`configure { sandbox }`), and **fails closed**:

- no sandbox available → every call's facts say `sandboxed: false`, `placement: "host-plain"`, and the worker asks;
- a sandboxed call whose sandbox does not start → `done` carries `error: { code: "SandboxFailed" }` and the program never
  ran. The host never retries it unsandboxed.

Availability is measured at start-up by running `/usr/bin/true` under the same kind of profile a call gets, so
"available" means "a call would start", not "the binary exists".

## What a sandboxed call may do

The worker can narrow either bound on `start`/`pipe` with an `envelope` (`{ write, exec }`, two enums and nothing
else). Every accepted value is a SUBSET of today's floor for the same call: `write: "roots"` is narrower than the
floor (name-immutable top level, below), `write: "none"` is `$TMPDIR` alone; `exec: "any"` is the floor, `exec:
"program-only"` is the host-resolved set (the program, its `#!` interpreters and `env`'s target, each hashed path
argument's chain, and on Linux each ELF's `PT_INTERP`; on macOS also the `sh`→`bash` variant). Absent means today;
malformed is `BadRequest`, never a silent fallback. `done` always reports the scope as APPLIED, and reports
`write: "today"` for an absent envelope — `"today"` is the host's name for the floor and a worker may never send it.

| | macOS (Seatbelt, `sandbox-exec -p`) | Linux (bubblewrap + Landlock) |
| --- | --- | --- |
| Read | everything, except credential stores | the same |
| Write, absent envelope (today's floor) | the workspace roots, its own `$TMPDIR`, `/dev/null`, `/dev/std{out,err}`, `/dev/fd/*` | the same via bwrap binds; the documented gap stays (a protected name created during the call is writable) |
| Write (`write: "roots"`) | the same roots and tmp, with a NAME-IMMUTABLE top level (below) | the same via Landlock: name-immutable top level, protected names never granted (below) |
| Write (`write: "none"`) | its own `$TMPDIR` and the `/dev/*` exceptions only | the same |
| Network | nothing, loopback included | nothing (`--unshare-net`) |
| Processes (`exec: "any"`, the floor) | start any program, all inheriting the profile | the same, in a fresh PID namespace |
| Processes (`exec: "program-only"`) | only the resolved set, by `literal`; `sh -c 'ls'` cannot exec `ls` | the same, by Landlock EXECUTE grants |
| Credential stores (`.ssh`, `.gnupg`, `.aws`, `.azure`, `.kube`, `.docker`, `.password-store`, `~/Library/Keychains`, `.config/gh`, `.config/gcloud`, `.netrc`, `.git-credentials`, `.pgpass`) | unreadable at ANY depth, matched by regex, case-insensitively | masked under `$HOME` only (an empty tmpfs or `/dev/null` bound over each that exists) |
| …unless the call NAMES one | a marked path argument flagged `secret` is re-allowed by a `literal` rule: the person approved this exact path | the same, by not masking it |
| Files that run code later (`.git/hooks/`, `.git/config`, `.gitmodules`, `.vscode/`, `.idea/`, `.claude/commands`, `.claude/agents`, `.claude/settings*.json`, `.mcp.json`, `.envrc`, shell rc files) | unwritable at any depth (regex), and `.git` cannot be renamed away | absent envelope: re-bound read-only where they exist at the TOP of each root when the call starts (the gap stays); `write: "roots"`: never writable, the name-immutable top level covers the ones that do not exist yet |
| The session's held output | neither readable nor writable | masked (empty tmpfs) |

Why each part exists: writes confined, or a process rewrites its way out of the network limit; network denied, or a
process sends out what it reads (Anthropic's reasoning for Claude Code's sandbox, which `SHELL.md` cites); credential
stores hidden, because under the sandbox no legitimate local call needs them (`git push` and `gh` need the network,
which is denied anyway), and a read of one is a disclosure no enforcer bounds; hooks and rc files read-only, because a
write there runs code the NEXT time the person's own unsandboxed git or shell starts.

## What the tests show (tests/stdio.rs)

Measured on macOS 26 (Seatbelt) and on GitHub's Ubuntu 24.04 runner (bubblewrap, with an AppArmor profile that grants
it user namespaces, `.github/workflows/ci.yml`) on 2026-10-15. CI sets `WMLHOST_REQUIRE_SANDBOX=1` on Linux, so a
sandbox that does not start fails the job instead of taking the fail-closed path.

| Test | Denied | Allowed |
| --- | --- | --- |
| `the_sandbox_confines_writes_to_the_roots` | `touch <outside>/pwned` (EPERM, file absent) | `touch inside` in the root; a write and read in `$TMPDIR` |
| `the_sandbox_keeps_files_that_run_code_later_read_only` | appending to `.git/hooks/pre-commit`, `.git/config`, `.vscode/settings.json` (contents unchanged) | `git add a` in the same repository |
| `the_sandbox_denies_a_network_connect` | `bash` `/dev/tcp` to a listener on 127.0.0.1 (the listener sees nothing) | the same call with `sandbox: false` connects (the control) |
| `the_sandbox_hides_credential_stores_unless_the_call_names_one` | `sh -c 'cat ~/.ssh/id_test'` (not named) | `cat ~/.ssh/id_test` with the path marked, facts showing `secret: true` |
| `held_output_is_hidden_from_children` | `cat $TMPDIR/../../out/*` | |
| `a_protected_path_created_during_the_call_…` | macOS: `mkdir .vscode && echo > .vscode/tasks.json` | Linux (absent envelope): the same call SUCCEEDS (the gap below, pinned by the test) |
| `write_roots_withholds_make_dir_so_envrc_cannot_appear_as_a_directory` (sibling under `write: "roots"`) | macOS and Linux-with-Landlock: the same `mkdir .vscode` is denied | Linux-without-Landlock: the call is `SandboxFailed` (`can_hold`), never run wide |
| `write_none_lets_the_call_write_only_its_temp_dir` | `touch inside` under `write: "none"` | a write and read in `$TMPDIR` under `write: "none"` |
| `exec_program_only_lets_the_call_run_only_its_program` | `sh -c 'ls'` under `exec: "program-only"` (ls is not in the set) | `sh -c 'echo … > work/out.txt'` under `exec: "program-only"` (in an existing directory) |
| `an_absent_envelope_is_todays_floor_and_done_says_so` | | `touch inside` with no envelope; `done.envelope` is `{ write: "today", exec: "any" }` |
| `a_malformed_envelope_is_bad_request_and_never_todays_floor` | every malformed `envelope` / `envelopes`, including `write: "today"` sent by a worker (`BadRequest`, call gone) | |
| `hello_reports_the_landlock_abi_or_null` | | `hello.sandbox.landlockAbi` is a positive number or `null` (a number under `WMLHOST_REQUIRE_SANDBOX=1`) |
| `write_roots_starts_in_a_root_that_holds_files_and_symlinks` | | a call in a root with `README.md`, `.git/HEAD` and two symlinks starts and edits `README.md` (defects 2 and 4) |
| `write_roots_withholds_make_reg_so_envrc_and_mcp_json_cannot_appear` | `echo x > .envrc` / `echo x > .mcp.json` under `write: "roots"` | |
| `write_roots_withholds_make_sym_so_mcp_json_cannot_be_planted` | `ln -s elsewhere/x .mcp.json` / `.envrc` under `write: "roots"` | |
| `write_roots_withholds_remove_file_so_a_top_level_file_cannot_be_replaced` | `rm scratch` and `rm .mcp.json` under `write: "roots"` | |
| `write_roots_withholds_remove_dir_so_a_top_level_dir_cannot_be_dropped` | `rmdir scratchdir` under `write: "roots"` | |
| `write_roots_withholds_refer_so_mcp_json_cannot_be_moved_in` | `mv elsewhere/x .mcp.json` under `write: "roots"` | |
| `an_envelope_on_an_unsandboxed_call_is_refused_not_misreported` | `start` with an envelope and `sandbox: false` (`SandboxFailed`) | the same call without one; `done.envelope` is `{ write: "today", … }` |
| `exec_unders_failure_is_spoken_in_the_shape_sandbox_failed_listens_for` | `wmlhost exec-under` with an unenforceable ruleset exits 2, stderr head `wmlhost exec-under:` | |

Each enforcement test was checked to FAIL against a weakened profile (writes and network allowed; the hooks deny
removed; the named-secret allow removed), so none passes vacuously.

## The envelope's monotonicity invariant

For every field, every value the host accepts yields a sandbox that is a SUBSET of today's sandbox for the same call.
Stated as: `write: "none"` ⊆ `write: "roots"` ⊆ today; `exec: "program-only"` ⊆ `exec: "any"` = today. The worker can
only NARROW. A test (`every_envelope_value_is_a_subset_of_todays_plan`) asserts the generated grants carry no root
under `write: "none"`, a name-immutable top level under `write: "roots"` on both platforms, and no exec member
outside the named set under `exec: "program-only"`.

## `write: "roots"` is NAME-IMMUTABLE at the top level of every root

One universal, no list: the root inode is edit-only (`WriteFile`/`Truncate` — on Seatbelt, `file-write-create` and
`file-write-unlink` denied on any name directly under a root). No `MakeReg`, `MakeDir`, `MakeSym`, `RemoveFile`,
`RemoveDir` or `Refer` at the top level of a root. What that gives and what it costs:

- An existing non-protected top-level file stays editable (`echo x >> package.json`).
- Existing protected names stay read-only (bwrap re-binds them; Seatbelt denies them by regex at any depth).
- Below a non-protected top-level DIRECTORY, nothing changes: `src/` may grow, shrink and take new names. `.git`
  keeps file-level ops (`git add` writes `.git/index`) and its existing directory children stay writable, so
  `git add` works and an absent `.git/hooks` cannot be created.
- The Linux protected-name gap closes as a consequence: `.vscode` and `.mcp.json` cannot appear at the top level,
  because no new top-level name can.

Named casualties of the envelope, as properties of asking for it (the worker sends `write: "roots"` only when the
claims permit):

- `cargo build` — creates `target/` at the top level.
- `npm install` — creates `node_modules/` at the top level.
- `git rebase` / `git worktree add` — new directories under `.git`.
- An atomic-rename edit of a top-level file (`sed -i`, write-file-atomic): the temp name is a new top-level name, so
  the claim is on a name the envelope does not grant. Edit in place, or claim a bound that allows it.

Cost is the envelope's own. A manifest claiming `write(fs(p))` at the top level does not get `write: "roots"`.

## Things learned the hard way

- **SBPL regexes are `(regex "…")`, a quoted string,** not a bare `#"…"` literal: the latter is an "illegal argument",
  and the first version of the profile failed every call. It failed CLOSED (`SandboxFailed`, nothing ran, the write
  outside the roots did not happen), which is the property worth having.
- **Rule order is not the whole precedence story in Seatbelt.** A later `(allow file-read* (literal p))` does override an
  earlier `(deny file-read* (regex …))`, but a later unfiltered `(allow file-write*)` did NOT override an earlier
  `(deny file-write* (regex …))`. The profile relies only on the first behaviour, and the tests cover both. A later
  FILTERED allow overrides an earlier deny; a later UNFILTERED allow does NOT. So `program-only` appends `(deny
  process-exec)` then `(allow process-exec (literal …))` per member, after the base's unfiltered allow.
- **A call's background children keep its pipes open.** The host kills the call's whole process group when the call
  ends, so `sh -c 'slow & echo started'` neither leaves a process behind nor stalls `done`.
- **macOS runs `/bin/sh` by exec'ing a "variant" (`bash` or `dash`).** A literal allow on `/bin/sh` alone is not
  enough: the kernel execs the variant and `process-exec` refuses it. The exec set therefore includes the variants of
  a `sh` member (same directory).
- **Landlock rules only GRANT;** access is allowed if any ancestor grants it. "The roots minus the protected names"
  cannot subtract, so under `write: "roots"` the Linux grants follow the NAME-IMMUTABLE universal: `WriteFile|Truncate`
  only on each root inode (so an existing top-level file stays editable and `touch inside` / `mkdir .vscode` / `rm x`
  / `ln -s` / `mv` at the top level do not), file-level ops on each `.git` (so `git add` can create `.git/index`),
  full write on each existing non-protected top-level DIRECTORY and each existing non-protected child of `.git`, and
  full write on `tmp`. Symlinks are never granted (a dangling one would break the ruleset, a live one would grant a
  path the enumeration never judged). A missing path is "no grant": dropping a grant only narrows. Under an ABSENT
  envelope the Linux write is the bwrap binds alone, gap included — the enumeration does not run.
- **Seatbelt expresses the same universal** with two denies on names directly under each root (`file-write-create`
  and `file-write-unlink` on `^<root>/[^/]+$`). `file-write-create` is checked on the name being made and
  `file-write-unlink` on the name going away (or the rename's dest), so together they withhold
  MakeReg|MakeDir|MakeSym|RemoveFile|RemoveDir|Refer without touching an edit of an existing file or anything below
  a subdirectory. `file-write-unlink` alone is not enough: it still leaves `touch .envrc` possible.

## Limits, said plainly

- **Linux protects less than macOS when Landlock is unavailable** (no Landlock, or one that cannot fully enforce our
  ruleset — reported as `hello.sandbox.landlockAbi: null`). bubblewrap binds paths, it cannot match patterns, so a
  hook in a NESTED repository inside a root (`root/vendor/x/.git/hooks`), or a protected path created during the
  call, is writable there. A call asking for an envelope narrower than today's floor (including any `write: "roots"`)
  then fails `SandboxFailed` rather than running unrestricted. With Landlock and `write: "roots"` the top-level gap
  closes (the name-immutable universal above); nested repositories and credential stores outside `$HOME` remain
  weaker than macOS. An ABSENT envelope keeps the gap on Linux in every case — that is what "today" means, and the
  report-only tripwire watches it without closing it: `done.protectedChanged` (docs/PROTOCOL.md) names a protected
  top-level name, `.git/config` or hook that changed during the call, on both OSes, and the host never reverts it.
  `the_linux_floor_gap_is_reported_and_a_refused_write_reports_nothing` pins that the report matches the disk.
- **Two layers hold an existing protected name under `write: "roots"` on Linux, and one of them is not Landlock.**
  Landlock rights are inherited below the inode they are granted on: the root's `WriteFile` reaches every existing
  file beneath it, `.git`'s `MakeReg`/`RemoveFile` reach an existing `.git/hooks/`. What keeps `.envrc`, `.vscode/`,
  `.git/config` and the existing hooks read-only is bubblewrap's read-only re-binds of those names. Do not drop a bind
  as redundant with Landlock.
- **`write: "roots"` refuses the named casualties above.** That is the cost of asking for a name-immutable top level,
  not a defect: the worker sends it only when the claims permit no new top-level name.
- **A secret inside a root is not hidden from a directory walk.** `rg pattern .` reads `root/.env`. The facts flag `.env`
  only when it is NAMED. Hiding every secret-looking file in the roots would break dotenv-using test suites, which the
  person approved by name. Flagged to window-ml's `SHELL.md` as an open question.
- **`sysctl-read` is allowed in full** on macOS (`sandbox-runtime` lists names). It discloses machine facts such as the
  hostname, not files.
- **The child reopens its arguments by name**, so a symlink swapped between `spawn` (facts) and `start` can redirect it.
  The sandbox bounds where that redirect can WRITE; on the plain host nothing does, and every call asks there anyway.

## Container mode: what each runner would need on macOS (not chosen, not built)

The seam is `mode: "container"` in `spawn` (answered `Unsupported` today). A runner turns the same resolved call into a
`Prepared` command line, `src/runner.rs` runs it unchanged, and facts report `placement: "container"`.

| | Docker Desktop | Podman | Apple `container` |
| --- | --- | --- | --- |
| What the person installs | Docker Desktop (a Linux VM; licence terms for larger companies) | `podman` + `podman machine init/start` (a Linux VM, rootless) | Apple's `container` CLI; macOS 26 on Apple silicon (one lightweight VM per container) |
| The roots inside | `-v <root>:<root>` through the VM's file sharing (virtiofs) | the same; the machine shares `/Users` by default, other roots need configuring | `-v`/`--mount`, per container |
| No network | `--network none` | `--network none` | check: networking options are narrower and newer |
| What the host must not do | treat the daemon socket as harmless: whoever reaches `/var/run/docker.sock` is root in the VM | the same, for the machine's socket | |
| Start cost | a running VM; ~100s of ms per `run` | similar | a VM per container; measured cost unknown |

None of these is a reason to pick yet. The open question in `SHELL.md` stays open.
