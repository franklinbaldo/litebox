---
description: Multi-agent review of the current branch's changes, tuned to LiteBox conventions.
---

You are orchestrating a code review of the changes on the current branch versus `main`. Each subagent below owns one narrow concern. Dispatch them **in parallel** (one message, multiple `Agent` tool uses), then aggregate their findings.

## Step 1 — Gather the diff

Run `git diff main...HEAD` and `git diff main...HEAD --stat` to learn the scope. If the diff is empty, stop and tell the user there is nothing to review.

## Step 2 — Dispatch subagents in parallel

Each prompt is self-contained. Subagents have no memory of this conversation, so include the diff scope and the relevant `CLAUDE.md` excerpts inline. All agents must return findings in this format, one finding per block:

```
[severity: blocker | major | minor | nit] path/to/file.rs:LINE
<one-sentence issue>
<one-sentence suggested fix>
```

Each agent's prompt must end with: *"If you find nothing in your assigned concern, return exactly the string `NO FINDINGS`. Do not comment on concerns outside your scope — other agents own those."*

Severity rubric:
- **blocker** — unsound `unsafe`, broken invariant, security regression, will not compile/lint on CI
- **major** — correctness bug, missing test for new public API, platform parity break, contradictory style with sibling crates
- **minor** — silent style drift, missing doc on public item, over-broad visibility
- **nit** — taste-level suggestion the author can ignore

### Correctness cluster

**Agent 1 — Control flow, boundaries & panics.** Only look for: off-by-ones, missing match arms, unreachable code that is reachable, infinite loops, integer overflow/wraparound, slice indexing past length, and implicit panic sites in non-test code (`unwrap()`, `expect()`, `panic!()`, direct indexing, integer division) — especially in `no_std` paths and on the South provider trait surface. Test code is exempt from the panic rule. Ignore error propagation (Agent 2), unsafe (Agent 3), style.

**Agent 2 — Error propagation.** Only look for: `Result`/`Option` misuse — silently dropped errors, `.ok()` that should be `?`, error types that lose information when mapped, missing `From` impls that force boilerplate `.map_err`, errors that get re-wrapped into a less specific variant. Ignore panic sites (Agent 1) and unsafe (Agent 3).

### Safety cluster

**Agent 3 — Unsafe soundness.** Only look at `unsafe` blocks/functions added or modified by the diff. For each one verify: (a) a `// SAFETY:` comment exists, (b) the comment's claim actually holds given the surrounding preconditions, (c) the unsafe scope is as narrow as possible (no incidental safe code inside). Read the full file when needed. Ignore non-unsafe code.

**Agent 4 — Trust-boundary validation.** Only look at code that crosses a trust boundary: the North/South interface, FFI calls into host syscalls/WinAPI, anything that receives a pointer/length pair from the guest. Verify inputs are validated before use (bounds, alignment, nullness, range). Ignore internal-only code.

### Build hygiene cluster

**Agent 5 — `no_std` discipline.** Only look for: `std::` paths or `format!`/`println!`/`thread::` in crates that are `no_std`, `alloc` usage in paths that should use `core`. Identify which crates are `no_std` from their `lib.rs` `#![no_std]` attribute. Ignore dependency additions themselves (Agent 6's job).

**Agent 6 — Cargo & dependency hygiene.** Only look at `Cargo.toml` changes: new dependencies (must be justified and use `default-features = false`), feature flag additions, `[features]` block consistency, OP-TEE/Linux runner feature conflicts, workspace lints inheritance. Ignore code outside `Cargo.toml`.

### Code-quality cluster

**Agent 7 — Cross-crate consistency.** Only look at: when the diff adds or modifies a shim, platform, or runner, does it mirror the closest existing sibling (per `CLAUDE.md` Coding Style)? Check module layout, trait impl ordering, error type conventions, public API surface shape. Silent drift = **minor**, contradictory patterns = **major**. A new pattern that is genuinely better should be backported to siblings — flag missing backport as **minor**. Ignore naming, comments, visibility, clippy (other agents).

**Agent 8 — Code duplication.** Look for: (a) copy-pasted blocks within the diff, (b) blocks that duplicate code already present elsewhere in the workspace, (c) near-duplicate functions that differ only in a constant or type and could be parametrized, (d) round-trip type conversions where data flows `A → B → A` and `B` exists only as a packaging artifact between two layers — typical shape: caller packs N fields into an enum/struct, callee immediately unpacks them via accessors and never holds `B`. Drop `B` and plumb `A` directly. Flag the location of both copies (or both ends of the round-trip). Severity **minor** for two copies / one round-trip, **major** for three+ copies or for cross-crate duplication of platform-specific logic that should live in `litebox_common_*`.

**Agent 9 — Naming.** Only look at identifier names introduced or renamed by the diff. A function name should imply its observable behavior — including the specific error or value it produces when that is part of its contract. Examples of drift: a helper that returns `ESPIPE` named only after the rejection (`reject_offset_for_non_seekable` vs. `espipe_for_non_seekable_offset`); a `validate_x` that mutates; a `get_y` that performs I/O; abbreviations that obscure (`hdl`, `mgr`, `proc`). Severity **nit** unless the name actively misleads about side effects or error mapping, then **minor**.

**Agent 10 — Comments & visibility.** Three related concerns:
- *Restating or duplicative comments*: flag any comment added by the diff that adds no information a reader could not get from the code or the nearby comments. Three subcases:
  - *Restates the code* — `// increment counter` above `count += 1`, `/// Returns the address` on `fn address() -> Addr`. Comments should explain *why* (non-obvious constraints, invariants, workarounds), not *what*. Apply this clause-by-clause, not comment-by-comment: a multi-line comment that mixes one genuine WHY with two clauses of restating still warrants a flag — the restating clauses should be trimmed away, leaving only the WHY. Do not give a pass to a comment just because part of it is useful; surface the specific clauses that restate and propose the trimmed version.
  - *Duplicates information already given by an adjacent doc comment or by literal syntax* — e.g. an enum-level doc that lists the discriminant values when each variant already has its own doc and the `= 0`/`= 1` literals are visible in the declaration; a function-level doc that re-explains a parameter that already has its own `# Arguments` entry. Each piece of information should live in exactly one place; the layer where it is most local wins.
  - *Documents consumer behavior, not the item itself* — a comment on a type, enum variant, struct field, or argument that describes what the *consuming* code does with the value rather than what the value *is*. E.g. an enum variant `Read = 0` documented with "queued data may still be drained, then subsequent reads observe EOF and the peer's writes fail with EPIPE" — that behavior lives in the syscall handler that interprets the variant, not in the variant's contract. The item's doc should describe its identity/meaning/role; consumer-side behavior belongs at the consumer (and is verified by tests there). This is the most pernicious of the three because the comment looks helpful, but it drifts every time the consumer's behavior changes.
  - Severity **nit** for all three subcases. Missing safety comments on `unsafe` blocks are Agent 3's job, not yours.
- *Comments that do not match the code*: flag any comment whose claim disagrees with the surrounding code in any way — stale parameter names a refactor missed, references to functions/types/branches that have since been renamed or removed, an assertion that "X returns Y" when X now returns Z, a doc block listing arguments in the wrong order, an inline `// foo is true` next to `if !foo`, a `Returns: ...` doc on a function whose return type has changed, an example in a docstring whose API call no longer compiles. Read the comment, then read the code; if the comment's claims are not all true under the current code, flag it. This is more harmful than restatement because it actively misleads the next reader. Severity **minor** by default; **major** when the contradiction would lead a reader to a wrong assumption about an invariant, an error path, or a security-relevant precondition.
- *Visibility*: for each `pub`, `pub(crate)`, `pub(super)` declaration added or modified by the diff, determine the actual use sites by grepping the workspace and suggest the tightest visibility that still compiles (`pub(super)` before `pub(crate)` before `pub`). Severity **minor**.

**Agent 11 — Clippy suppressions.** Only look for new `#[allow(clippy::...)]` or `#![allow(clippy::...)]` attributes introduced by the diff. The default is that the warning gets fixed, not silenced. An `allow` is acceptable only when (a) scoped to a single item and (b) accompanied by a justifying comment. Unjustified item-level allow = **minor**; module-or-crate-level blanket allow = **major**.

### Tests & docs cluster

**Agent 12 — Public API doc coverage.** Only look at public items (`pub fn`, `pub struct`, `pub enum`, `pub trait`, `pub mod`, public trait methods) added or modified by the diff. Each should have a `///` doc comment that explains purpose, not just signature. Ignore private items and tests. Severity **minor**.

**Agent 13 — Test coverage.** Only look for new non-trivial functions or new trait impls (especially new `Provider` impls and new fs/net handlers) without a corresponding unit/integration test. Trivial pure functions and getters are exempt (per `.github/copilot-instructions.md`). Ignore everything else. Severity **major** for missing tests on new `Provider` surface, **minor** otherwise.

**Agent 14 — Test fidelity to Linux/host.** Agent 13 asks "is there a test?" — your concern is "does the test encode the right behavior?" Look at every assertion in new or modified tests (Rust unit tests, integration tests, C tests) and apply these checks:

- *Linux-mirroring assertions need a real-syscall test.* If a Rust unit test asserts a value that mirrors observable syscall behavior (a specific `Errno`, an EOF, a `Result` shape that maps to a libc errno, a poll-revents pattern), there must be at least one test that exercises the same condition through the real syscall surface — typically a C test under `litebox_runner_*/tests/`. A unit test alone proves only that the helper agrees with itself, not that Linux agrees. Severity **minor**.
- *Asymmetric coverage hiding parity gaps.* If a Rust unit test has branches (e.g. `_after_self_X` and `_after_peer_X`, or `_init` and `_listen` and `_connected`), each conceptually-distinct branch should also be exercised by a C test. Asymmetric coverage where the unit test covers a path the C test does not is a Linux-parity bug magnet. Severity **minor** by default; **major** when the missing branch covers a code path with a different errno or return shape (so the unverified branch could be silently wrong against Linux).
- *Assertions that bake in current LiteBox behavior.* If a test assertion appears to have been written by reading what the function currently returns (no probe output cited, no kernel-source reference, no man-page quote), and the assertion locks in a specific errno or return value, flag it. The recurring trap: `assert_eq!(err, Errno::ETIMEDOUT)` because `SO_RCVTIMEO` happened to return `ETIMEDOUT`, when Linux returns `EAGAIN`. Severity **major** when the assertion locks in non-Linux behavior; **minor** when it locks in plausible-but-unverified behavior. A `// Linux: …` comment next to the assertion citing a probe or kernel source clears this finding.
- *Specific recurring Linux quirks to spot-check.* If the diff touches any of these, verify the test reflects Linux: `SO_RCVTIMEO`/`SO_SNDTIMEO` expiry returns `EAGAIN` (not `ETIMEDOUT`); `shutdown(SHUT_RD)` on a Unix datagram queue keeps queued data readable; dgram peer-`SHUT_WR` does *not* synthesize EOF on blocking recv (it just stops senders); `shutdown` on an unconnected Unix socket succeeds silently; `accept` on a shut-down listen socket returns `EINVAL`; `connect` on a listen-shut socket returns `ECONNREFUSED`; level-triggered poll bits stay set across repeated polls.

Severity totals: at most one **major** per assertion (do not stack). Ignore tests that are pure structural sanity checks (e.g., "method returns Ok on the happy path") — focus on assertions that mirror a Linux-observable value.

## Step 3 — Aggregate

Collect all findings. Dedupe by `(file, line, concern)` — if two agents flagged the same line for the same underlying issue, keep the higher severity. Group by severity, blocker first. List each agent that returned `NO FINDINGS` under a short trailing line so the user knows it ran. End with a summary: `N blocker / N major / N minor / N nit across N/14 agents`.

Do **not** fix anything. This command reviews only.
