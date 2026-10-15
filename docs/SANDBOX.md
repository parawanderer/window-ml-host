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

| | macOS (Seatbelt, `sandbox-exec -p`) | Linux (bubblewrap) |
| --- | --- | --- |
| Read | everything, except credential stores | the same |
| Write | the workspace roots, its own `$TMPDIR`, `/dev/null`, `/dev/std{out,err}`, `/dev/fd/*` | the roots and its `$TMPDIR`; the rest of `/` is mounted read-only |
| Network | nothing, loopback included | nothing (`--unshare-net`) |
| Processes | start any program, all inheriting the profile | the same, in a fresh PID namespace |
| Credential stores (`.ssh`, `.gnupg`, `.aws`, `.azure`, `.kube`, `.docker`, `.password-store`, `~/Library/Keychains`, `.config/gh`, `.config/gcloud`, `.netrc`, `.git-credentials`, `.pgpass`) | unreadable at ANY depth, matched by regex, case-insensitively | masked under `$HOME` only (an empty tmpfs or `/dev/null` bound over each that exists) |
| …unless the call NAMES one | a marked path argument flagged `secret` is re-allowed by a `literal` rule: the person approved this exact path | the same, by not masking it |
| Files that run code later (`.git/hooks/`, `.git/config`, `.gitmodules`, `.vscode/`, `.idea/`, `.claude/commands`, `.claude/agents`, `.claude/settings*.json`, `.mcp.json`, `.envrc`, shell rc files) | unwritable at any depth (regex), and `.git` cannot be renamed away | re-bound read-only where they exist at the TOP of each root when the call starts |
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
| `a_protected_path_created_during_the_call_…` | macOS: `mkdir .vscode && echo > .vscode/tasks.json` | Linux: the same call SUCCEEDS (the gap below, pinned by the test) |

Each enforcement test was checked to FAIL against a weakened profile (writes and network allowed; the hooks deny
removed; the named-secret allow removed), so none passes vacuously.

## Things learned the hard way

- **SBPL regexes are `(regex "…")`, a quoted string,** not a bare `#"…"` literal: the latter is an "illegal argument",
  and the first version of the profile failed every call. It failed CLOSED (`SandboxFailed`, nothing ran, the write
  outside the roots did not happen), which is the property worth having.
- **Rule order is not the whole precedence story in Seatbelt.** A later `(allow file-read* (literal p))` does override an
  earlier `(deny file-read* (regex …))`, but a later unfiltered `(allow file-write*)` did NOT override an earlier
  `(deny file-write* (regex …))`. The profile relies only on the first behaviour, and the tests cover both.
- **A call's background children keep its pipes open.** The host kills the call's whole process group when the call
  ends, so `sh -c 'slow & echo started'` neither leaves a process behind nor stalls `done`.

## Limits, said plainly

- **Linux protects less than macOS.** bubblewrap binds paths, it cannot match patterns, so a hook in a NESTED repository
  inside a root (`root/vendor/x/.git/hooks`), or one created during the call, is writable there (the first Linux run
  found exactly this: `.vscode/settings.json`, absent when the call started, was written), and credential stores
  are masked only under `$HOME`. Closing it needs Landlock or a seccomp-notify broker; neither is built.
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
