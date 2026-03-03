# OP-TEE / LVBS Address Space Abstraction Plan

## Goal

Replace direct LVBS page-table calls (`create_task_page_table`, `load_task`,
`delete_task_page_table`) with the platform-agnostic `AddressSpaceProvider` trait.
This decouples the OP-TEE shim from LVBS internals and prepares for multi-TA
process support. Defer fork/COW — focus on the abstraction layer.

## Current State

- `AddressSpaceProvider` trait defined in `litebox/src/platform/address_space.rs`
  with 6 methods (create, destroy, fork, activate, with_address_space, address_space_range),
  all defaulting to `NotSupported`.
- LVBS has a stub impl: `type AddressSpaceId = u32`, no methods overridden.
- `PageTableManager` is an LVBS-specific concrete struct (not a trait) that has the
  real implementations:
  - `create_task_page_table()` → allocates PML4, copies kernel entries
  - `load_task(id)` → writes CR3
  - `load_base()` → restores kernel-only page table
  - `delete_task_page_table(id)` → cleans up P1-P3 frames, deallocates P4
- Runner (`litebox_runner_lvbs`) calls these directly via `platform.page_table_manager()`,
  `platform.create_task_page_table()`, and `platform.delete_task_page_table()`.
- OP-TEE shim (`litebox_shim_optee`) doesn't call LVBS directly — the runner
  orchestrates everything and passes `task_page_table_id: usize` to `TaInstance`.

## Step 1: Implement AddressSpaceProvider on LVBS Platform

**Files:** `litebox/src/platform/address_space.rs`, `litebox_platform_lvbs/src/lib.rs`

1.1. **Set LVBS `AddressSpaceId` to `usize`**
   - Existing `task_page_table_id` is `usize` (PML4 physical frame address).
   - This is LVBS-local — `AddressSpaceId` is a per-platform associated type,
     so other platforms (e.g., LinuxUserland with `u32`) are unaffected.

1.2. **Implement `create_address_space()`**
   - Delegates to `self.page_table_manager().create_task_page_table()`.
   - Maps `Errno` → `AddressSpaceError::NoSpace` (currently only `ENOMEM`
     can occur; if new error paths are added later, revisit the mapping).

1.3. **Implement `destroy_address_space(id)`**
   - Delegates to `self.page_table_manager().delete_task_page_table(id)`.
   - Error mapping:
     - `EINVAL` (base page table ID passed) → `debug_assert!` + `InvalidId`
       (this is a programming error; callers should never pass the base ID).
     - `ENOENT` (no such page table) → `InvalidId`.
     - `EBUSY` (address space is currently active) → add new
       `AddressSpaceError::Busy` variant. This is a recoverable precondition
       violation, not a panic condition.
   - The underlying `delete_task_page_table` is `unsafe`; the LVBS impl of
     this safe trait method must enforce preconditions internally: check that the
     address space is not active (CR3 check already exists) and that caller has
     released user mappings. Document these requirements on the trait method.

1.4. **Implement `activate_address_space(id)`**
   - Delegates to `self.page_table_manager().load_task(id)`.
   - Maps `EINVAL` → `InvalidId`, `ENOENT` → `InvalidId`.
   - Note: `EINVAL` means caller passed `BASE_PAGE_TABLE_ID`, which is a
     programming error. `debug_assert!` in this case.

1.5. **Override `with_address_space(id, f)` — primary scoped API**
   - Activate task PT → run `f` → restore base PT (`load_base`).
   - Must be panic-safe: use an RAII drop guard to ensure `load_base()` runs
     even if `f` panics.
   - This is the **primary API** for address space switching on LVBS. All
     runner call sites should prefer `with_address_space` over raw
     `activate_address_space` (see Step 2.5).
   - Also fix the default `with_address_space` impl in the trait: it currently
     activates but never restores. Either add a doc comment that platforms MUST
     override if `activate` has side effects, or change the default to call
     `activate` → `f()` → undo (which requires a "get previous" or "deactivate"
     concept — better to just document the override requirement).

1.6. **Implement `address_space_range(id)`**
   - Returns `USER_ADDR_MIN..USER_ADDR_MAX` (0x10000..0x7FFFFFFFE000).
   - Same for all LVBS task address spaces (each has its own page table with
     full canonical user half). This differs from LinuxUserland where each
     address space gets a per-partition sub-range.

1.7. **Leave `fork_address_space` as `NotSupported`** (deferred).
   - Future path: fork on LVBS would return `Independent(new_id)` using a new
     page table with kernel PML4 entries copied (essentially `create_task_page_table`)
     plus COW user page table entries. Deferred until multi-TA fork is needed.

## Step 2: Replace Direct LVBS Calls in Runner with AddressSpaceProvider

**Files:** `litebox_runner_lvbs/src/lib.rs`, `litebox_shim_optee/src/session.rs`

2.1. **Replace `create_task_page_table()` helper**
   - Change from `platform.create_task_page_table()` to
     `platform.create_address_space()`.
   - Update error mapping to `OpteeSmcReturnCode`:
     `NoSpace` → `ENomem`, `NotSupported` → `ENotAvail`.

2.2. **Replace `delete_task_page_table(id)` helper**
   - Change from `platform.delete_task_page_table(id)` to
     `platform.destroy_address_space(id)`.
   - Map `Busy` → `EBusy` or similar, `InvalidId` → `EBadCmd`.

2.3. **Rename `TaInstance.task_page_table_id` → `address_space_id`**
   - Change the field name and update all access sites (`SessionEntry`,
     `SessionManager`, all runner handler code).
   - Keep the concrete type as `usize` inside the runner (matches LVBS
     `AddressSpaceId`). If the shim needs to store it generically in the
     future, use the platform's associated type.

2.4. **Replace all activate/deactivate patterns with `with_address_space`**
   - The runner pattern `switch_to_task_page_table → do work →
     switch_to_base_page_table` is replaced with:
     ```rust
     platform.with_address_space(id, || {
         // run TA, read params, write response
     })?;
     ```
   - This eliminates the need for standalone `switch_to_task_page_table()` and
     `switch_to_base_page_table()` helpers entirely. The RAII guard in the LVBS
     `with_address_space` impl ensures the base PT is always restored, even on
     panic or early error return.
   - **Critical ordering:** VTL0 response write-back (`write_msg_args_to_normal_world`)
     must happen **inside** the `with_address_space` scope, because it reads
     TA user-space memory for output parameters.
   - Evaluate each handler (open_session, invoke_command, close_session) and
     convert. For `close_session` where the last session triggers
     address-space destruction, the destruction must happen *after*
     `with_address_space` returns (i.e., outside the scope, after the response
     is written and the base PT is restored).

2.5. **Verify all direct LVBS page-table calls are removed**
   - Grep for `page_table_manager()`, `create_task_page_table`,
     `delete_task_page_table`, `load_task`, `load_base` in `litebox_runner_lvbs`.
   - After this step, none of these should appear in the runner. They should
     only exist in LVBS-internal code (`litebox_platform_lvbs`).

## Step 3: Move TA Lifecycle Logic from Runner to Shim

**Goal:** The runner becomes a thin platform adapter. The shim owns TA lifecycle
orchestration (open/invoke/close session) and calls back to the platform for
the 3 truly platform-specific operations:
  (A) address space management (via `AddressSpaceProvider`)
  (B) guest code execution (enter user mode, handle syscalls)
  (C) host/normal-world I/O (write responses back to VTL0)

This is a larger refactor, broken into sub-steps.

### Step 3a: Define Platform Execution Callback Trait

**Files:** `litebox_shim_optee/src/lib.rs` (new trait; consider `litebox` core
if non-OP-TEE runners would also need it)

- Define a trait that the shim calls to execute guest code:
  ```rust
  /// Execution mode for TA entry.
  pub enum TaExecMode {
      /// First-time entry: initialize thread and enter TA.
      Init,
      /// Re-entry: resume TA from a previous syscall/exception return.
      Reenter,
  }

  /// Result of TA execution.
  pub enum TaExecResult {
      /// TA returned normally. Check PtRegs for return value.
      Returned,
      /// TA panicked / hit fatal error. Instance must be torn down.
      TargetDead,
  }

  /// Platform callback for executing guest TA code.
  pub trait TaExecutor {
      /// Context type for guest execution (e.g., PtRegs on x86_64).
      type ExecContext;

      /// Execute the TA. Returns when the TA hits exit or fatal error.
      fn execute_ta(
          &self,
          entrypoints: &OpteeShimEntrypoints,
          ctx: &mut Self::ExecContext,
          mode: TaExecMode,
      ) -> TaExecResult;
  }
  ```
- LVBS runner implements:
  - `type ExecContext = PtRegs`
  - `Init` → `run_thread_ref()`, `Reenter` → `reenter_thread_ref()`
  - Returns `TargetDead` if `ctx.rax` indicates `TARGET_DEAD`
- The associated `ExecContext` type avoids baking `PtRegs` (architecture-specific)
  into the trait directly.

### Step 3b: Define Host Response Writer Trait

**Files:** `litebox_shim_optee/src/lib.rs` or `msg_handler.rs` (new trait)

- Define a trait for writing OP-TEE responses to the host:
  ```rust
  pub trait TaResponseWriter {
      fn write_msg_args(
          &self,
          msg_args: &mut OpteeMsgArgs,
          phys_addr: u64,
      ) -> Result<(), OpteeSmcReturnCode>;
  }
  ```
- Note: `&mut OpteeMsgArgs` (not `&`) because the current runner modifies
  `msg_args.ret`, `msg_args.params_info`, and `msg_args.num_params` before
  serializing and writing.
- LVBS runner implements this using `NormalWorldMutPtr`.
- This isolates VTL0 memory access (strictly LVBS-specific) from TA lifecycle.

### Step 3c: Move Open Session Logic to Shim

**Files:** `litebox_shim_optee/src/lib.rs`, `litebox_runner_lvbs/src/lib.rs`

- Create a shim-level handler. The shim already has access to the platform via
  `Task.global.platform` (which implements `AddressSpaceProvider`), so no
  separate `platform` parameter is needed for address space operations. The
  `executor` and `writer` are runner-provided callbacks:
  ```rust
  pub fn handle_open_session(
      &self,
      executor: &impl TaExecutor,
      writer: &impl TaResponseWriter,
      ta_uuid: TeeUuid,
      params: &[UteeParamOwned],
      client: Option<TeeIdentity>,
      msg_args: &mut OpteeMsgArgs,
      msg_args_phys_addr: u64,
  ) -> Result<(u32, TeeResult), OpteeSmcReturnCode>
  ```
- **Structured response:** The return type includes `session_id` and `TeeResult`.
  The method also populates `msg_args` with TA output params, `ret_origin`
  (TrustedApp or Tee for TargetDead), and calls `writer.write_msg_args()` to
  flush to VTL0 — all inside `with_address_space` scope.
- **Single-instance concurrency:** The shim's `SessionManager` already manages
  `Arc<SpinMutex<TaInstance>>`. The handler must acquire the instance lock via
  `try_lock()` and return `EThreadLimit` if contended, mirroring the current
  runner behavior.
- **Error cleanup / rollback** (mirrors existing runner error paths):
  1. `create_address_space` fails → return error, nothing to clean up.
  2. `with_address_space` (activate) fails → `destroy_address_space(id)`.
  3. ldelf loading fails → release user mappings, deactivate, destroy AS.
  4. TA open-session entry returns error → release user mappings, deactivate,
     destroy AS (for new instances only; single-instance reuse keeps the TA).
  5. Session registration fails → unregister, teardown if last session.
- Runner becomes: parse SMC args → call shim → shim returns result.

### Step 3d: Move Invoke Command Logic to Shim

**Files:** same as 3c

- Create shim handler:
  ```rust
  pub fn handle_invoke_command(
      &self,
      executor: &impl TaExecutor,
      writer: &impl TaResponseWriter,
      session_id: u32,
      cmd_id: u32,
      params: &[UteeParamOwned],
      msg_args: &mut OpteeMsgArgs,
      msg_args_phys_addr: u64,
  ) -> Result<TeeResult, OpteeSmcReturnCode>
  ```
- Shim handler:
  1. Looks up session → gets `TaInstance`, acquires lock via `try_lock()`.
  2. Calls `platform.with_address_space(id, || { ... })`:
     - Loads TA context (already in shim).
     - Calls `executor.execute_ta(entrypoints, ctx, Reenter)`.
     - If `TargetDead`: sets `ret_origin = Tee`, marks for cleanup.
     - Reads TA output params, populates `msg_args`.
     - Calls `writer.write_msg_args()` (inside scope — needs TA memory).
  3. If `TargetDead`: unregisters session, tears down instance if last session
     (destroy address space happens outside `with_address_space` scope).
  4. Returns `TeeResult`.

### Step 3e: Move Close Session Logic to Shim

**Files:** same as 3c

- Create shim handler:
  ```rust
  pub fn handle_close_session(
      &self,
      executor: &impl TaExecutor,
      writer: &impl TaResponseWriter,
      session_id: u32,
      msg_args: &mut OpteeMsgArgs,
      msg_args_phys_addr: u64,
  ) -> Result<TeeResult, OpteeSmcReturnCode>
  ```
- Shim handler:
  1. Looks up session → gets `TaInstance`, acquires lock.
  2. Calls `platform.with_address_space(id, || { ... })`:
     - Loads close context (empty params).
     - Calls `executor.execute_ta(entrypoints, ctx, Reenter)`.
     - Calls `writer.write_msg_args()` (inside scope).
  3. Unregisters session.
  4. If last session on instance and not `INSTANCE_KEEP_ALIVE`:
     - Releases user mappings (`shim.release_user_mappings()`).
     - `platform.destroy_address_space(id)` (outside scope — base PT active).
  5. Returns `TeeResult` (per OP-TEE spec, close always succeeds).
- Note: `teardown_ta_page_table()` (runner line 347) bundles
  `release_user_mappings` + `switch_to_base` + `delete_pt`. In the shim,
  this becomes: user mapping release inside `with_address_space` scope,
  address space destruction outside.

### Step 3f: Thin Runner Adapter

**Files:** `litebox_runner_lvbs/src/lib.rs`

- Runner's `optee_smc_handler()` becomes:
  ```rust
  fn optee_smc_handler(smc_args_addr: usize) -> OpteeSmcArgs {
      let (smc_args, msg_args, phys_addr) = parse_smc_request(smc_args_addr)?;
      let executor = LvbsExecutor;       // impl TaExecutor
      let writer = LvbsResponseWriter;   // impl TaResponseWriter

      let result = match msg_args.cmd {
          OpenSession => session_mgr.handle_open_session(
              &executor, &writer, ta_uuid, params, client,
              &mut msg_args, phys_addr,
          ),
          InvokeCommand => session_mgr.handle_invoke_command(
              &executor, &writer, session_id, cmd_id, params,
              &mut msg_args, phys_addr,
          ),
          CloseSession => session_mgr.handle_close_session(
              &executor, &writer, session_id,
              &mut msg_args, phys_addr,
          ),
          _ => handle_non_ta_msg_args(&msg_args),
      };
      // Response already written by shim (inside with_address_space).
      // Address space already deactivated by with_address_space RAII guard.
      build_smc_response(smc_args, result)
  }
  ```
- Runner implements `TaExecutor` (wrapping `run_thread_ref`/`reenter_thread_ref`)
  and `TaResponseWriter` (wrapping `NormalWorldMutPtr`).
- All OP-TEE protocol logic, session management, concurrency control, and
  error handling are in the shim.

## Notes and Considerations

- **`AddressSpaceError::Busy` variant:** Add to the trait's error enum.
  Maps to `OpteeSmcReturnCode::EBusy` (or closest equivalent). This
  replaces the "or panic" option from the original plan.
- **Error mapping:** `NoSpace` → `ENomem`, `InvalidId` → `EBadCmd`,
  `Busy` → `EBusy`, `NotSupported` → `ENotAvail`.
- **Default `with_address_space`:** The default impl activates but doesn't
  restore. Add a doc requirement that platforms with side-effectful
  `activate_address_space` MUST override `with_address_space`. LinuxUserland
  (where activate is a no-op) is safe with the default.
- **Testing:** Steps 1-2 should be verifiable by running the existing OPTEE/LVBS
  tests (if any exist in CI). Step 3 sub-steps should be individually testable
  by running the same tests after each move. Step 1 APIs can also be
  unit-tested with a mock `PageTableManager`.
- **Incremental commits:** Each step (1, 2, 3a-3f) should be a separate commit
  for reviewability.
- **Fork/COW deferred:** `fork_address_space` stays `NotSupported` for LVBS.
  When we implement multi-TA fork, we'll add COW page table copy.
- **Multi-TA calls:** TA-to-TA calls (`TEE_OpenTASession`) are not currently
  supported. The `with_address_space` implementation currently assumes the
  caller is in the base address space and does **not** support nesting. If
  TA-to-TA calls are added, the RAII guard must save/restore the previous CR3
  instead of unconditionally calling `load_base()`.
- **TA lifecycle state machine:** A TA instance goes through: Created → Loaded →
  OpenSession → (InvokeCommand)* → CloseSession → Destroyed. After Step 3,
  the shim owns all state transitions. The runner only owns the
  VTL0↔VTL1 boundary.
