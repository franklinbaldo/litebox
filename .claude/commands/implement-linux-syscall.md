---
description: Implement a Linux syscall in litebox_shim_linux, with a native-validated C test that also passes on LiteBox.
argument-hint: <syscall_name> [notes]
---

You are implementing a Linux syscall in `litebox_shim_linux` so that programs running through `litebox_runner_linux_userland` see Linux-compatible behavior. The user's request is `$ARGUMENTS`. The first token is the syscall name (e.g. `shutdown`, `mknodat`); everything after is optional scoping notes (e.g. `unix datagram only`).

## Guiding rules

1. **Follow the existing code.** Pick the closest already-implemented syscall as your template and mirror its file layout, naming, error mapping, and visibility. Do not invent new patterns when an established one exists.
2. **Match Linux's behavior exactly.** Add a C test under `litebox_runner_linux_userland/tests/<name>.c` that *first runs natively on the host* to confirm what real Linux does. Only then claim that the LiteBox implementation matches.
3. **Reach Linux parity for the scope you advertise.** It is fine to land a partial implementation (e.g. UNIX datagram only, no stream) if the scope is explicit — but every code path the test exercises must work, and unimplemented branches must return a clean errno (or `todo!()` only if genuinely unreachable from your test).

## Step 1 — Pick the closest analog and announce it

Find the most similar already-implemented syscall by looking at recent commits and the existing files under `litebox_shim_linux/src/syscalls/`.

- `git log --oneline -- litebox_shim_linux/src/syscalls/` shows recent syscall additions.
- Commit `e97079ef9 add syscall shutdown` is a clean end-to-end template — read it with `git show e97079ef9` if `shutdown` is at all related.
- Pick the analog by **subsystem + shape**: same domain (socket / fs / signal / mm), similar argument count, similar return type, similar resource lookup (fd table, path, pid).

State your choice in one sentence: *"Using `<analog_syscall>` as the template because <reason>."* Then proceed. If the user pushes back, switch analogs.

## Step 2 — Write the C test first

Create `litebox_runner_linux_userland/tests/<syscall_name>.c` (or a more specific name like `unix_dgram_<op>.c` if the scope is narrower). It will be auto-discovered by `find_c_test_files` in `tests/run.rs` and run by both `test_dynamic_lib_with_rewriter` and `test_static_exec_with_rewriter`. **You do not need to edit `run.rs`** — dropping the file in the directory is enough.

Test file conventions (mirrored from `tests/unix_dgram_shutdown.c`):

- Start with the MIT license header.
- `#define _GNU_SOURCE` at the top, then standard `<errno.h>`, `<stdio.h>`, `<sys/socket.h>`, `<sys/syscall.h>`, etc.
- Call the syscall **directly via `syscall(SYS_<name>, ...)`** when you want to test the raw syscall surface that LiteBox intercepts — not the libc wrapper, which may do its own argument massaging. Use the libc wrapper only when the test is about libc-level behavior.
- Write small `expect_*` / `fail_*` helpers that print a descriptive `FAIL: ...` and `exit(1)` on mismatch. Each named test case is its own `static void test_<scenario>(void)`.
- `main` prints a banner, calls each `test_*` function in order, prints "All ... passed.", returns 0.
- File ends *without* a trailing newline only if you are intentionally matching the sibling files; otherwise end with a newline.

Cover at minimum:
- The happy path documented by the man page.
- One error path for each `EINVAL` / `EBADF` / `EPIPE` / `EAGAIN` / etc. branch the syscall is supposed to produce.
- State-change observability: if the syscall changes a resource's state, the test must observe that state via a *different* syscall afterwards (e.g. `shutdown` is observed via subsequent `send`/`recv`).

## Step 3 — Validate the test against real Linux first

Before touching any Rust code, compile and run the test with the host's gcc:

```sh
gcc -O0 -g -o /tmp/lb_test_<syscall_name> litebox_runner_linux_userland/tests/<syscall_name>.c
/tmp/lb_test_<syscall_name>
```

It must print the "All ... passed." line. If it does not, **the test is wrong, not Linux** — fix the test until it encodes Linux's actual behavior. Do not proceed to the Rust implementation while the native run fails. (If you genuinely believe the kernel is buggy, stop and surface that to the user; do not silently work around it.)

If you need a behavior that is only visible at the raw syscall level (no libc wrapper), use `syscall(SYS_<name>, ...)`. If `SYS_<name>` is not defined on the build host, that is a signal you are picking up a stale glibc header; mention it instead of papering over.

## Step 4 — Wire the syscall into `litebox_common_linux`

In `litebox_common_linux/src/lib.rs`:

1. **If the syscall takes a strongly-typed argument** (flags enum, mode, etc.), define a `#[repr(...)] #[derive(Debug, IntEnum)] enum` near related types. See `ShutdownHow` for the pattern.
2. **Add a variant to `SyscallRequest`**. Keep field names matching the Linux man-page argument names. Use `Platform::RawConstPointer<T>` / `RawMutPointer<T>` for user pointers — never bare `*const T`.
3. **Add a `sys_req!` arm** in `SyscallRequest::try_from_raw`, keyed on `Sysno::<name>`. Use `:*` for pointer fields. Trust the macro to wire argument indices from field order — do not pre-parse complex types here; the comment above `try_from_raw` is explicit about keeping this function trivial.

## Step 5 — Wire the dispatch in `litebox_shim_linux`

1. In `litebox_shim_linux/src/lib.rs`, add a match arm for `SyscallRequest::<Name> { .. } => syscall!(sys_<name>(args...))`. Keep arms ordered to match the variant order in `SyscallRequest` when reasonable.
2. In the appropriate `litebox_shim_linux/src/syscalls/<file>.rs`, add a `pub(crate) fn sys_<name>(&self, ...) -> Result<..., Errno>` method on `impl<FS: ShimFS> Task<FS>`. Pick the file by subsystem:
   - sockets → `net.rs`
   - fs / fd ops → `file.rs`
   - unix-socket-specific logic → `unix.rs`
   - signals → `signal/`
   - process / scheduling → `process.rs`
   - mm → `mm.rs`
   - everything else → `misc.rs`
3. Inside `sys_<name>`, do the argument validation that maps to errno (`u32::try_from` → `EBADF`, `TryFrom<i32>` on the enum → `EINVAL`, etc.), then delegate to a `do_<name>` or to a method on the resource (`UnixSocket`, `File`, …).
4. Place the actual logic on the resource type itself (e.g. `UnixDatagram::shutdown` in `unix.rs`). This keeps `sys_<name>` thin and the behavior testable via the resource API.

Visibility rules (per `CLAUDE.md`): `pub(crate)` is the default for new shim functions; use `pub(super)` if the only caller is in the same module's parent. No bare `pub` unless the item is genuinely public API.

## Step 6 — Implement, run cargo, iterate

```sh
cargo fmt
cargo build
cargo clippy --all-targets --all-features
cargo nextest run -E 'test(test_dynamic_lib_with_rewriter) | test(test_static_exec_with_rewriter)'
```

If clippy complains, fix the code — do not add `#[allow(...)]` unless the lint is genuinely wrong, in which case scope the allow to one item and write a comment explaining why.

For unsafe blocks (rare in syscall handlers, but possible when crossing the user-memory boundary): every `unsafe` needs a safety comment justifying *why* the precondition holds here.

If the test fails on LiteBox but passes natively, the implementation is wrong, not the test. Common pitfalls:
- Forgot to wake pollers / notify observers after a state change.
- Wrong errno mapping (e.g. returning `EINVAL` where Linux returns `EBADF`).
- Off-by-one in length / offset arguments because the request variant used the wrong type.
- Logic placed only in one of `Stream` / `Datagram` when both should handle it.

### Unit tests that assert Linux-mirroring behavior

Rust unit tests for the internal helpers you wrote are useful, but the moment a unit test asserts a *value* that is supposed to match Linux (an errno, a return code, a state transition observable from user space), the test is making a claim about Linux behavior. That claim must be independently verified, or you are setting future-you up to calcify a LiteBox bug as the spec.

Rules for every Rust unit test you add in this work:

1. **If the assertion mirrors syscall-observable behavior, a C test must exercise the same surface.** A unit test on an internal helper proves only that the helper agrees with itself; it does not prove Linux compatibility. Add a C test (and probe Linux first, per Step 3) for any observable contract you are locking in.
2. **Cover every distinct caller of a shared helper, not just one.** A helper that branches on a flag, a state, or "who called me" may pass its unit test for one branch while quietly being wrong for another. If your C tests only drive one of the branches, the unit test is hiding a half-tested path — extend coverage to each distinct entry until the C tests exercise every branch the unit test claims to verify.
3. **Never bake current LiteBox behavior into an assertion you have not verified against Linux.** If you are writing `assert_eq!(value, X)` because that is what the function currently returns, stop and probe Linux. A unit test that encodes a LiteBox bug as "expected" is worse than no test: it will actively reject the correct fix later, and the next person will trust the assertion over their instincts.
4. **Write probes down.** When you run a quick C program to confirm Linux's behavior, either commit it as a C test or paste the relevant line of its output into a comment next to the unit-test assertion. The running kernel is the authority; memory and man-page recollection are not.

These rules apply to every unit test you add in this work, regardless of how the test is named. What matters is whether the assertion is a claim about Linux.

## Step 7 — Run `/review-litebox` and fix what it flags

Once cargo is green, the implementation is functionally complete but not yet *house-style* complete. Invoke the `review-litebox` skill — it dispatches five specialist subagents (correctness, unsafe/security, no_std/deps, style/cross-crate, tests/docs) and aggregates findings grouped as **blocker / major / minor / nit**.

Triage the report:

- **Blockers** and **majors**: must fix. These are correctness bugs, unsound `unsafe`, sandbox-escape risks, parity breaks, missing tests for new public API, or compile/lint failures. Address each one in code, not by arguing.
- **Minors**: fix when cheap (sibling drift, missing doc on a public item, visibility wider than needed, comments that restate the code). If a minor is intentional, leave a one-line rationale in the final report rather than silently ignoring it.
- **Nits**: ignore by default. Only revisit if the same nit recurs across multiple review rounds — that usually means it was actually a minor in disguise.

After each fix-pass, re-run the cargo gate before re-reviewing:

```sh
cargo fmt
cargo clippy --all-targets --all-features
cargo nextest run -E 'test(test_dynamic_lib_with_rewriter) | test(test_static_exec_with_rewriter)'
```

Then re-invoke `/review-litebox`. Loop until **one** of:

1. The review returns `0 blocker / 0 major`, and every minor is either fixed or has a documented rationale. **This is the success exit.**
2. You hit **3 review rounds** and the remaining findings are the same ones the reviewer flagged last round — i.e. you and the reviewer disagree. Stop, and surface the disagreement to the user in your final report; do not keep fighting the reviewer.

Common pitfalls during the review loop:

- A finding may point at *sibling* code (e.g. the existing dgram impl when you added the stream impl). CLAUDE.md says to apply the better pattern to existing crates rather than diverging — fix the sibling too rather than carving out an exception for your new code.
- Do not silence a flagged clippy lint with `#[allow(...)]` to make the review pass. The review will spot the `allow` next round and the reviewer is right.
- If the review demands a test for an inet branch you scoped to `Errno::ENOSYS`, that's a scope-vs-test argument; the right answer is usually to defend the scope choice in the final report, not to invent a fake test.
- If a fix in one file silently breaks a previously-passing test in another, the cargo gate above will catch it before the next review round. Don't skip the cargo step "to save time."

## Step 8 — Report

When you finish, in one or two sentences tell the user:
- the analog you used,
- the scope you implemented (full vs. partial — name the partial branches),
- which `cargo` commands you ran, that the new C test passed both natively and under LiteBox,
- the final `/review-litebox` verdict (e.g. "0 blocker / 0 major / 2 minor — both minors addressed").

Do not write a long summary; the diff speaks for itself.

## Things to **not** do

- Do not edit `tests/run.rs` to register the new C test; auto-discovery handles it.
- Do not add new dependencies to `Cargo.toml` files for this work.
- Do not pre-parse complex argument shapes inside `SyscallRequest::try_from_raw`; that function is intentionally trivial.
- Do not commit; the user runs `git commit` themselves.
- Do not skip Step 3 (native validation). Implementing first and then writing a test that matches your implementation defeats the parity check.
- Do not skip Step 7. The review loop is the last quality gate before the user sees the work, and the multi-agent setup catches things a single pass over the diff will miss (especially style drift from sibling crates and missing safety comments).
- Do not invoke `/review-litebox` *before* cargo is green. The review assumes a buildable, lint-clean tree; running it earlier wastes the review pass on noise.
