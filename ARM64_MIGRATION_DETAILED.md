# DETAILED ARM64 MIGRATION REFERENCE FOR LITEBOX WINDOWS PLATFORM

## Part 1: ASSEMBLY IMPLEMENTATION ROADMAP

### 1.1 X86-64 run_thread_arch → ARM64 Equivalent

**Current x86-64 (Lines 425-587)**:
- Entry: rcx=thread_ctx (Arg 0), rdx=tls_state (Arg 1)
- Saves: rbx, r12-r15, rsp, rbp + xmm6-xmm15
- Uses: GS segment for TLS access (TEB_TLS_SLOTS_OFFSET = 5248)
- Exit: Jump to init_handler, then main loop

**Required ARM64 Changes**:
`
Entry:
  x0 = thread_ctx
  x1 = tls_state
  
Prologue:
  stp x29, x30, [sp, #-16]!    // Save fp, lr
  stp x27, x26, [sp, #-16]!    // Non-volatile GPRs
  stp x25, x24, [sp, #-16]!
  stp x23, x22, [sp, #-16]!
  stp x21, x20, [sp, #-16]!
  stp x19, x28, [sp, #-16]!    // Include x28 (BP equivalent)
  
  // Save v8-v15 (non-volatile vector regs)
  stp d8, d9, [sp, #-16]!
  stp d10, d11, [sp, #-16]!
  stp d12, d13, [sp, #-16]!
  stp d14, d15, [sp, #-16]!
  
  // Get and save current sp to TLS
  mov x2, sp
  str x2, [x1, #HOST_SP_OFFSET]  // tls.host_sp = current sp
  mov x2, x29
  str x2, [x1, #HOST_BP_OFFSET]  // tls.host_bp = current fp (x29)
`

Key differences:
- ARM64 has 10 non-volatile GPRs vs x86-64's 7
- ARM64 vector regs (v8-v15) vs x86-64 (xmm6-xmm15) - same count
- ARM64 must save LR (x30) explicitly
- x19-x28 are callee-saved (x29=FP, x30=LR implicit)

### 1.2 TLS Access Pattern

**X86-64 (Line 496-497)**:
`sm
mov r11d, DWORD PTR [rip + TLS_INDEX]  // Load TLS index
mov r11, QWORD PTR gs:[r11 * 8 + TEB_TLS_SLOTS_OFFSET]  // TLS slot lookup via GS
`

**ARM64 Equivalent**:
ARM64 doesn't have segment registers. Use two approaches:

Option A: Load TLS pointer from TPIDR_EL0:
`sm
mrs x11, TPIDR_EL0              // Read thread pointer
ldr w12d, [rip + TLS_INDEX]      // Load TLS index (signed-extended to 64-bit)
ldr x11, [x11, x12, lsl #3]      // x11 = *(tpidr + index*8)
`

Option B: Use platform-specific TLS base (if available):
`sm
adrp x11, :got:PLATFORM_TLS      // Get address of PLATFORM_TLS
ldr x11, [x11, :got_lo12:PLATFORM_TLS]
ldr x11, [x11]                   // Dereference to get actual pointer
`

### 1.3 Context Saving and Stack Building (Lines 505-526)

**X86-64**: Pushes pt_regs structure on stack in reverse order
- Top of stack becomes pt_regs.r15
- Grows downward, sp becomes pointer to r15

**ARM64 Equivalent**: Same stack layout, but register order:
`sm
// From saved x0-x30 context, build pt_regs on stack
// pt_regs ARM64 layout: regs[31], sp, pc, pstate

// Working backwards from syscall_callback
// At syscall entry: x0-x7 are syscall args, x30 has return address

// Build stack with pt_regs.regs[30..0] (x30 down to x0)
stp x30, x29, [sp, #-16]!   // x30 (LR), x29 (FP)
stp x28, x27, [sp, #-16]!
... (continue for x26 down to x0)
stp x1, x0, [sp, #-16]!

// Then add special fields
mov x12, sp                  // Copy current SP before we modify it
pushq #0x2b                  // pstate equivalent? (NZCV flags)
push x12                     // sp field
push x30                     // pc (return address)
// etc.
`

### 1.4 Guest Context Switch (switch_to_guest_sysret)

**X86-64** (Lines 604-628):
`sm
mov rsp, rcx                // rcx has pointer to pt_regs
pop r15
... (pop all registers from stack)
pop rsp                     // Restore guest stack
jmp rcx                     // Jump to instruction pointer (from r15 context)
`

**ARM64 Equivalent**:
`sm
// x0 = pointer to PtRegs (ARM64 version)
// PtRegs layout: regs[31], sp, pc, pstate

ldp x0, x1, [x0, #(31*8)]   // Load x30, x29 from regs[30], regs[29]
ldp x2, x3, [x0, #(29*8)]   // Load x28, x27
... (continue unloading)
ldp x29, x30, [x0]          // Load FP, LR

// Load PC and PSTATE
ldr x8, [x0, #(32*8)]       // Load PC
ldr x9, [x0, #(33*8)]       // Load PSTATE

// Restore SP
ldr sp, [x0, #(31*8 + 8)]   // Load sp field

// Jump to guest entry point
br x8                        // Branch to PC (or can use ERET if coming from exception)
`

---

## Part 2: WINDOWS API CONTEXT HANDLING

### 2.1 Windows CONTEXT Structure for ARM64

**X86-64 CONTEXT** (used in save_guest_context, Lines 167-213):
`c
typedef struct {
    DWORD64 P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
    DWORD ContextFlags;
    DWORD MxCsr;
    
    // Integer registers
    DWORD64 Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi;
    DWORD64 R8, R9, R10, R11, R12, R13, R14, R15;
    
    // Program counter and flags
    DWORD64 Rip;
    
    // Floating point state (XMM/YMM)
    CHAR XmmRegisters[160];
    DWORD64 FltSave[32];
    
    // Control flags
    DWORD64 EFlags;
    DWORD64 Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
} CONTEXT_AMD64;
`

**ARM64 CONTEXT** (needed for ARM64 Windows):
`c
typedef struct {
    DWORD ContextFlags;
    DWORD Cpsr;              // PSTATE
    
    // Integer registers
    DWORD64 X0, X1, ..., X30;  // 31 general registers
    DWORD64 Sp;              // Stack pointer
    DWORD64 Pc;              // Program counter
    DWORD64 Lr;              // Link register (X30 alias)
    
    // Floating point state
    CHAR FloatingPoint[528]; // NEON/FP registers (v0-v31)
    DWORD64 Fpcr;            // FP control register
    DWORD64 Fpsr;            // FP status register
} CONTEXT_ARM64;
`

### 2.2 Updated save_guest_context for ARM64

Current implementation (Lines 167-213) maps X86-64 registers:
`ust
fn save_guest_context(
    guest_context: &mut litebox_common_linux::PtRegs,
    context: &windows_sys::Win32::System::Diagnostics::Debug::CONTEXT,
) {
    *r15 = context.R15.truncate();
    *r14 = context.R14.truncate();
    ...
}
`

**ARM64 Equivalent**:
`ust
#[cfg(target_arch = "aarch64")]
fn save_guest_context(
    guest_context: &mut litebox_common_linux::PtRegs,
    context: &windows_sys::Win32::System::Diagnostics::Debug::CONTEXT,
) {
    // Windows ARM64 CONTEXT has different layout
    // Map to PtRegs which has regs[31], sp, pc, pstate
    
    for i in 0..31 {
        guest_context.regs[i] = context.X[i] as usize;  // context.X0..X30
    }
    guest_context.sp = context.Sp.truncate();
    guest_context.pc = context.Pc.truncate();
    guest_context.pstate = context.Cpsr.truncate();
}
`

### 2.3 Exception Mapping for ARM64

**Current X86-64** (Lines 1693-1710):
`ust
match exception_record.ExceptionCode {
    Win32_Foundation::EXCEPTION_ACCESS_VIOLATION => { ... PAGE_FAULT ... }
    Win32_Foundation::EXCEPTION_ILLEGAL_INSTRUCTION => { ... INVALID_OPCODE ... }
    Win32_Foundation::EXCEPTION_BREAKPOINT => { ... BREAKPOINT ... }
    Win32_Foundation::EXCEPTION_INT_DIVIDE_BY_ZERO => { ... DIVIDE_ERROR ... }
}
`

**ARM64 Modifications**:
`ust
// ARM64-specific exception codes may differ
// Will need to add:
#[cfg(target_arch = "aarch64")]
match exception_record.ExceptionCode {
    EXCEPTION_ACCESS_VIOLATION => { ... PAGE_FAULT ... }
    EXCEPTION_ILLEGAL_INSTRUCTION => { ... INVALID_OPCODE ... }
    EXCEPTION_FLT_INVALID_OPERATION => { ... handling ... }
    // ARM64-specific exceptions may exist
}
`

---

## Part 3: TLS AND FS-BASE REPLACEMENT FOR ARM64

### 3.1 X86-64 rdfsbase/wrfsbase Functions

**Location**: litebox_common_linux/src/lib.rs Lines 1131-1162

**Current**:
`ust
#[cfg(target_arch = "x86_64")]
pub unsafe fn rdfsbase() -> usize {
    let ret: usize;
    core::arch::asm!("rdfsbase {}", out(reg) ret, ...);
    ret
}

#[cfg(target_arch = "x86_64")]
pub unsafe fn wrfsbase(fs_base: usize) {
    core::arch::asm!("wrfsbase {}", in(reg) fs_base, ...);
}
`

### 3.2 ARM64 Equivalents Using TPIDR_EL0

**TPIDR_EL0**: Thread Pointer ID Register (EL0 - Exception Level 0 = user mode)

`ust
#[cfg(target_arch = "aarch64")]
pub unsafe fn rdfsbase() -> usize {
    let ret: usize;
    // In user mode, read TPIDR_EL0 (Thread Pointer)
    core::arch::asm!(
        "mrs {}, tpidr_el0",
        out(reg) ret,
        options(nostack, nomem, preserves_flags)
    );
    ret
}

#[cfg(target_arch = "aarch64")]
pub unsafe fn wrfsbase(fs_base: usize) {
    // Write to TPIDR_EL0
    core::arch::asm!(
        "msr tpidr_el0, {}",
        in(reg) fs_base,
        options(nostack, nomem, preserves_flags)
    );
}
`

**CRITICAL NOTES**:
1. TPIDR_EL0 is the user-mode thread pointer register
2. TPIDR_EL1 is kernel-mode (not accessible from user space)
3. Both are 64-bit on ARM64
4. Windows on ARM64 may use TPIDR_EL0 for TLS, similar to Linux

### 3.3 FS Base Usage in Windows Platform (Lines 73-96)

Currently uses wrfsbase to restore FS base when cleared:
`ust
impl WindowsUserland {
    fn restore_thread_fs_base() {
        unsafe {
            litebox_common_linux::wrfsbase(THREAD_FS_BASE.get());
        }
    }
}
`

This will automatically work for ARM64 once wrfsbase is updated!

---

## Part 4: MEMORY MANAGEMENT ARCHITECTURE INDEPENDENCE

### 4.1 VirtualAlloc/VirtualProtect (Lines 1368-1580)

**Good news**: These are entirely architecture-independent!

- Windows.h provides these APIs for both x86_64 and ARM64
- Implementation just calls Windows system calls
- No architecture-specific assembly needed
- Address ranges may differ:

**X86-64** (Lines 1366-1367):
`ust
const TASK_ADDR_MIN: usize = 0x1_0000;
const TASK_ADDR_MAX: usize = 0x7FFF_FFFE_F000;
`

**ARM64 Typical Values**:
`ust
#[cfg(target_arch = "aarch64")]
const TASK_ADDR_MIN: usize = 0x0000_0000_0001_0000;  // 64KB (or based on system)
#[cfg(target_arch = "aarch64")]
const TASK_ADDR_MAX: usize = 0x0000_FFFF_FFFF_F000;  // 48-bit address space
`

Or use Windows API to query:
`ust
fn get_system_information(sys_info: &mut SYSTEM_INFO) {
    unsafe {
        GetSystemInfo(sys_info);
    }
}
// Then use: sys_info.lpMinimumApplicationAddress
//           sys_info.lpMaximumApplicationAddress
`

---

## Part 5: PTREG STRUCTURE LAYOUT DIFFERENCES

### 5.1 Stack Layout Comparison

**X86-64 PtRegs on stack** (built in syscall_callback, Lines 505-526):
`
[rsp + 0]    = r15
[rsp + 8]    = r14
[rsp + 16]   = r13
[rsp + 24]   = r12
[rsp + 32]   = rbp
[rsp + 40]   = rbx
[rsp + 48]   = r11
[rsp + 56]   = r10
[rsp + 64]   = r9
[rsp + 72]   = r8
[rsp + 80]   = rax
[rsp + 88]   = rcx
[rsp + 96]   = rdx
[rsp + 104]  = rsi
[rsp + 112]  = rdi
[rsp + 120]  = orig_rax
[rsp + 128]  = rip
[rsp + 136]  = cs
[rsp + 144]  = eflags
[rsp + 152]  = rsp
[rsp + 160]  = ss
Total: 21 * 8 = 168 bytes
`

**ARM64 PtRegs on stack** (must build similarly):
`
Need to follow PtRegs layout:
pub struct PtRegs {
    pub regs: [usize; 31],    // x0-x30 (31 registers)
    pub sp: usize,             // sp
    pub pc: usize,             // pc
    pub pstate: usize,         // pstate
}

Stack layout:
[rsp + 0]    = x0   (regs[0])
[rsp + 8]    = x1   (regs[1])
...
[rsp + 240]  = x30  (regs[30])
[rsp + 248]  = sp
[rsp + 256]  = pc
[rsp + 264]  = pstate
Total: 34 * 8 = 272 bytes
`

### 5.2 Offset Calculations

For ARM64, when accessing PtRegs fields in assembly:

`
#define REGS_OFFSET(n)      (n * 8)              // regs[n]
#define SP_OFFSET           (31 * 8)             // 248
#define PC_OFFSET           (32 * 8)             // 256
#define PSTATE_OFFSET       (33 * 8)             // 264
`

---

## Part 6: STEP-BY-STEP MIGRATION CHECKLIST

### Phase 1: Structure and Configuration
- [ ] Update lib.rs cfg gate: #![cfg(all(target_os = "windows", target_arch = "aarch64"))]
- [ ] Add ARM64 conditional compilation blocks
- [ ] Update Cargo.toml for ARM64 target

### Phase 2: TLS Functions
- [ ] Add ARM64 dfsbase() using MSR TPIDR_EL0
- [ ] Add ARM64 wrfsbase() using MRS TPIDR_EL0
- [ ] Test TLS access from Windows user-mode

### Phase 3: Assembly Implementation
- [ ] Replace un_thread_arch with ARM64 assembly
  - [ ] Prologue: Save x19-x28, x29-x30, v8-v15
  - [ ] TLS slot access: Use TPIDR_EL0 instead of GS
  - [ ] Syscall callback: Adjust register mapping
  - [ ] Stack building: Update for ARM64 PtRegs layout
  - [ ] Epilogue: Restore all saved registers
- [ ] Replace switch_to_guest_sysret with ARM64 branch sequence
- [ ] Update offset calculations for TlsState fields

### Phase 4: Context Handling
- [ ] Update save_guest_context() for ARM64 Windows CONTEXT
- [ ] Map Windows ARM64 exception codes to LiteBox exceptions
- [ ] Update set_context_to_interrupt_callback() for ARM64 registers
- [ ] Test exception/signal handling

### Phase 5: Handler Functions
- [ ] Verify handler signatures work with ARM64 ABI
- [ ] Test init_handler, syscall_handler, exception_handler
- [ ] Test interrupt_handler with thread suspension

### Phase 6: Memory Management
- [ ] Update TASK_ADDR_MIN/MAX for ARM64 address space
- [ ] Verify VirtualAlloc/VirtualProtect work on ARM64
- [ ] Test allocation, deallocation, permission changes

### Phase 7: Testing
- [ ] Single-threaded execution
- [ ] Multi-threaded execution
- [ ] Exception handling (page faults, invalid instructions)
- [ ] Interrupts and signals
- [ ] Memory management and page protection
- [ ] Full integration tests with Linux payload

---

## Part 7: KEY COMPILER INTRINSICS FOR ARM64 ASSEMBLY

Since Rust will use core::arch::asm!, here are key directives:

`ust
// Reading TPIDR_EL0
core::arch::asm!("mrs {}, tpidr_el0", out(reg) value);

// Writing TPIDR_EL0
core::arch::asm!("msr tpidr_el0, {}", in(reg) value);

// Load/Store operations (LDP/STP with pre/post-index)
core::arch::asm!(
    "ldp {x0}, {x1}, [{sp}], #16",  // Load pair and post-increment sp
    x0 = out(reg) r0,
    x1 = out(reg) r1,
    sp = inout(reg) sp_ptr,
);

// Branch to register (BR equivalent to x86 JMP)
core::arch::asm!("br {}", in(reg) target_address);

// Branch with link (call equivalent)
core::arch::asm!("blr {}", in(reg) target_address);

// Exception return (ERET)
core::arch::asm!("eret");

// Read condition flags
core::arch::asm!("mrs {}, nzcv", out(reg) flags);

// Write condition flags
core::arch::asm!("msr nzcv, {}", in(reg) flags);
`

---

## Part 8: REGISTER CLOBBER LISTS

X86-64 clobber list (from current code):
`ust
options(nostack, nomem, preserves_flags)
`

ARM64 equivalent (be more explicit about saved regs):
`ust
options(nostack, nomem, preserves_flags)
// OR
options(nostack, preserves_flags) // If accessing memory for TLS
`

---

## TESTING STRATEGY

1. **Unit Tests**: Test individual assembly functions
   - un_thread_arch prologue/epilogue
   - switch_to_guest_sysret register loading
   - TLS access functions

2. **Integration Tests**: Full execution
   - Single syscall through Windows → LiteBox
   - Multiple syscalls
   - Exception handling
   - Signal/interrupt delivery

3. **Functional Tests**: With actual Linux payloads
   - Basic syscalls (read, write, exit)
   - Memory operations (mmap, brk)
   - Threading
   - File I/O

