Please run `cargo nextest run -- python` and fix the underlying root cause that causes this failure for `$ORIGIN`-based library dependencies.

Notes from a previous attempt:

```
# Goal
* Make LiteBox handle $ORIGIN-based library dependencies correctly as a fundamental runtime behavior.
* No brittle per-test hacks in run.rs.
* No LD_PRELOAD workaround.

# Key Findings So Far
* The failing case is a Python executable whose DT_NEEDED contains a slash path with token expansion: $ORIGIN/../lib/libpython3.12.so.1.0
* Failure symptom in LiteBox runtime: `undefined symbol: Py_BytesMain from the python executable.`
* Rewritten binary still preserves that DT_NEEDED entry textually.
* The issue is not simply missing libpython file in rootfs in the successful workaround paths; it is how runtime resolution happens for slash-containing DT_NEEDED with $ORIGIN.
* Test harness-level environment workarounds can make it pass, but those are not architecturally acceptable by the requirements.

# Hard Requirements (From You)
* No $ORIGIN patching logic in run.rs.
* No LD_PRELOAD usage as fix strategy.
* Fix must be fundamental in LiteBox/loader/audit/runtime path.
* Outcome should generalize beyond this single Python test shape.

# Approaches Tried And Why They Were Rejected
* LD_LIBRARY_PATH augmentation in test runner. Rejected: brittle, environment-dependent, not root-cause.
* LD_PRELOAD for $ORIGIN-resolved DT_NEEDED libraries. Rejected: brittle and explicitly disallowed.
* Rewriting execution path layout in test harness to preserve $ORIGIN adjacency. Helped in some dimensions, but still test-layer coupling and not robust enough as the fundamental fix.
* rtld_audit la_objsearch token expansion attempt. Not sufficient for this specific resolution behavior; still saw unresolved Py_BytesMain.
# Test-side staging tweaks and copy logic improvements. Useful for avoiding secondary failures (encodings missing), but still not the root runtime fix.

# Important Secondary Findings
* Python staging logic can create false negatives: If destination dir exists early, copy skips can break stdlib availability (ModuleNotFoundError: encodings).
* litebox_rtld_audit is built with -nostdlib, so new C helpers must avoid implicit libc symbol dependencies.

# Most Likely Root-Cause Zone
* How LiteBox-rewritten binaries plus loader/audit interactions handle slash-containing DT_NEEDED entries using $ORIGIN.
* Resolution behavior appears different from what glibc path semantics require for this tokenized dependency shape.

# What A Clean Reattempt Should Do
* Reproduce baseline failure with minimal test setup (smaller than Python)
* Instrument fundamental path:
  - Loader + audit logs around dependency name seen by resolver.
  - Verify whether $ORIGIN token is expanded before/after LiteBox interception points.
* Implement fix at runtime/loader level, not test level:
  - Proper token-aware resolution handling for slash DT_NEEDED
```
