# ARM64 PORTING GUIDE: Windows Userland Platform for LiteBox

## COMPREHENSIVE ANALYSIS FOR ARCHITECTURE PORT

### FILE: litebox_platform_windows_userland/src/lib.rs

---

## SECTION 1: IMPORTS, CFG GATES, CONSTANTS, THREAD-LOCAL STORAGE (Lines 1-97)

\\\ust
// Line 8: CRITICAL - x86_64 ONLY requirement
#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

// Thread-local storage for FS base state (Lines 46-49)
thread_local! {
    static THREAD_FS_BASE: Cell<usize> = const { Cell::new(0) };
}

// Helper methods for FS base management (Lines 73-96)
impl WindowsUserland {
    fn get_thread_fs_base() -> usize { ... }
    fn set_thread_fs_base(new_base: usize) { ... }
    fn restore_thread_fs_base() { ... }
    fn init_thread_fs_base() { ... }
}
\\\

---

## SECTION 2: EXCEPTION HANDLING SETUP (Lines 99-165)

### Vectored Exception Handler (Lines 99-165)

\\\ust
unsafe extern "system" fn vectored_exception_handler(
    exception_info: *mut EXCEPTION_POINTERS,
) -> i32 {
    // Line 102-105: Check TLS slot initialization
    // Line 114-128: Check if in guest mode
    // Line 131: Save guest context
    // Line 140-162: Handle fsbase restoration via interrupt path
    // Line 145-162: Handle exception path with NtContinue
}
\\\

Key architecture-specific details:
- Uses Windows EXCEPTION_POINTERS structure
- Checks guest mode flag (is_in_guest)
- Restores FS base if cleared
- Saves CPU context via save_guest_context

---

## SECTION 3: SAVE_GUEST_CONTEXT & CORE STRUCTURES (Lines 167-321)

### save_guest_context Function (Lines 167-213)

Maps Windows CONTEXT registers to Linux PtRegs:

\\\ust
fn save_guest_context(
    guest_context: &mut litebox_common_linux::PtRegs,
    context: &windows_sys::Win32::System::Diagnostics::Debug::CONTEXT,
) {
    // Lines 194-212: Register mapping
    *r15 = context.R15.truncate();
    *r14 = context.R14.truncate();
    *r13 = context.R13.truncate();
    *r12 = context.R12.truncate();
    *rbp = context.Rbp.truncate();
    *rbx = context.Rbx.truncate();
    *r11 = context.R11.truncate();
    *r10 = context.R10.truncate();
    *r9 = context.R9.truncate();
    *r8 = context.R8.truncate();
    *rax = context.Rax.truncate();
    *rcx = context.Rcx.truncate();
    *rdx = context.Rdx.truncate();
    *rsi = context.Rsi.truncate();
    *rdi = context.Rdi.truncate();
    *orig_rax = context.Rax.truncate();
    *rip = context.Rip.truncate();
    *eflags = context.EFlags as usize;
    *rsp = context.Rsp.truncate();
}
\\\

### WindowsUserland Struct (Lines 55-71)

\\\ust
pub struct WindowsUserland {
    reserved_pages: alloc::vec::Vec<core::ops::Range<usize>>,
    sys_info: std::sync::RwLock<Win32_SysInfo::SYSTEM_INFO>,
}

impl WindowsUserland {
    pub fn new() -> &'static Self { ... }
    fn read_memory_maps() { ... }
    fn get_system_information() { ... }
    fn round_up_to_granu() { ... }
    fn round_down_to_granu() { ... }
    pub fn init_task() -> litebox_common_linux::TaskParams { ... }
}
\\\

---

## SECTION 4: RUN_THREAD_ARCH - NAKED ASSEMBLY FUNCTION (Lines 425-587)

### CRITICAL: Bare Metal x86-64 Assembly Implementation

This is THE MOST CRITICAL SECTION for ARM64 porting. Complete assembly listing:

\\\sm
.seh_proc run_thread
// PROLOGUE: Push all non-volatile x86-64 registers
push rbp
.seh_pushreg rbp
mov rbp, rsp
.seh_setframe rbp, 0
push rbx
.seh_pushreg rbx
push rdi
.seh_pushreg rdi
push rsi
.seh_pushreg rsi
push r12
.seh_pushreg r12
push r13
.seh_pushreg r13
push r14
.seh_pushreg r14
push r15
.seh_pushreg r15

// Save XMM6-XMM15 (non-volatile SSE/AVX registers)
sub rsp, 168 // align + space for xmm6-xmm15
.seh_stackalloc 168
movdqa [rsp + 0*16], xmm6
.seh_savexmm xmm6, 0*16
movdqa [rsp + 1*16], xmm7
.seh_savexmm xmm7, 1*16
movdqa [rsp + 2*16], xmm8
.seh_savexmm xmm8, 2*16
movdqa [rsp + 3*16], xmm9
.seh_savexmm xmm9, 3*16
movdqa [rsp + 4*16], xmm10
.seh_savexmm xmm10, 4*16
movdqa [rsp + 5*16], xmm11
.seh_savexmm xmm11, 5*16
movdqa [rsp + 6*16], xmm12
.seh_savexmm xmm12, 6*16
movdqa [rsp + 7*16], xmm13
.seh_savexmm xmm13, 7*16
movdqa [rsp + 8*16], xmm14
.seh_savexmm xmm14, 8*16
movdqa [rsp + 9*16], xmm15
.seh_savexmm xmm15, 9*16
.seh_endprologue

// TEB_TLS_SLOTS_OFFSET is Windows-specific (5248 bytes into TEB)
.equ TEB_TLS_SLOTS_OFFSET, 5248

push rcx // Alignment
push rcx // Save thread_ctx

// Save host stack and frame pointers to TLS
mov QWORD PTR [rdx + {HOST_SP}], rsp
mov QWORD PTR [rdx + {HOST_BP}], rbp

call {init_handler}
jmp .Ldone

// SYSCALL ENTRY POINT (called via jmp rcx from guest)
.globl syscall_callback
syscall_callback:
    // Get TLS state from Windows TLS slot
    mov r11d, DWORD PTR [rip + {TLS_INDEX}]
    mov r11, QWORD PTR gs:[r11 * 8 + TEB_TLS_SLOTS_OFFSET]
    mov BYTE PTR [r11 + {IS_IN_GUEST}], 0
    
    // Set rsp to top of guest context
    mov QWORD PTR [r11 + {SCRATCH}], rsp
    mov rsp, QWORD PTR [r11 + {GUEST_CONTEXT_TOP}]
    
    // Build pt_regs on stack (Lines 505-526)
    push 0x2b       // pt_regs->ss = __USER_DS
    push QWORD PTR [r11 + {SCRATCH}] // pt_regs->sp
    pushfq          // pt_regs->eflags
    push 0x33       // pt_regs->cs = __USER_CS
    push rcx        // pt_regs->ip
    push rax        // pt_regs->orig_ax
    
    push rdi        // pt_regs->di
    push rsi        // pt_regs->si
    push rdx        // pt_regs->dx
    push rcx        // pt_regs->cx
    push -38        // pt_regs->ax = ENOSYS
    push r8         // pt_regs->r8
    push r9         // pt_regs->r9
    push r10        // pt_regs->r10
    push [rsp + 88] // pt_regs->r11 = rflags
    push rbx        // pt_regs->bx
    push rbp        // pt_regs->bp
    push r12        // pt_regs->r12
    push r13        // pt_regs->r13
    push r14        // pt_regs->r14
    push r15        // pt_regs->r15
    
    // Restore host stack/frame pointers
    mov rsp, [r11 + {HOST_SP}]
    mov rbp, [r11 + {HOST_BP}]
    
    mov rcx, QWORD PTR [rsp] // thread_ctx
    call {syscall_handler}
    jmp .Ldone

// EXCEPTION CALLBACK (Lines 538-544)
exception_callback:
    mov rcx, QWORD PTR [rsp]
    call {exception_handler}
    jmp .Ldone

// INTERRUPT CALLBACK (Lines 546-549)
interrupt_callback:
    mov rcx, QWORD PTR [rsp]
    call {interrupt_handler}
    jmp .Ldone

// EPILOGUE: Restore all registers
.Ldone:
    lea rsp, [rbp - (168 + 56)]
    movdqa xmm6, [rsp + 0*16]
    movdqa xmm7, [rsp + 1*16]
    movdqa xmm8, [rsp + 2*16]
    movdqa xmm9, [rsp + 3*16]
    movdqa xmm10, [rsp + 4*16]
    movdqa xmm11, [rsp + 5*16]
    movdqa xmm12, [rsp + 6*16]
    movdqa xmm13, [rsp + 7*16]
    movdqa xmm14, [rsp + 8*16]
    movdqa xmm15, [rsp + 9*16]
    add rsp, 168
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    pop rbp
    ret
    .seh_endproc
\\\

### Key Assembly Details for ARM64 Port:
1. **Non-volatile registers**: x86-64 has 7 (rbx, rsp, rbp, r12-r15); ARM64 has x19-x28, sp, fp, lr
2. **Vector registers**: x86-64 saves xmm6-xmm15 (10 x 16-byte regs); ARM64 has v8-v15 (same)
3. **Segment registers**: x86-64 uses GS for TLS; ARM64 uses TPIDR_EL0
4. **Argument passing**: x86-64 rcx=ctx, rdx=tls; ARM64 would be x0=ctx, x1=tls
5. **Stack building**: Must match PtRegs layout (see Linux common library section)

---

## SECTION 5: GUEST CONTEXT SWITCHING (Lines 600-704)

### switch_to_guest Function (Lines 599-704)

\\\ust
unsafe extern "C" fn switch_to_guest(ctx: &litebox_common_linux::PtRegs) -> ! {
    #[unsafe(naked)]
    extern "C" fn switch_to_guest_sysret(ctx: &litebox_common_linux::PtRegs) -> ! {
        core::arch::naked_asm!(
            "switch_to_guest_start:",
            "mov rsp, rcx",
            "pop r15", ... "pop r15",
            "pop r14",
            "pop r13",
            "pop r12",
            "pop rbp",
            "pop rbx",
            "pop r11",
            "pop r10",
            "pop r9",
            "pop r8",
            "pop rax",
            "pop rcx",
            "pop rdx",
            "pop rsi",
            "pop rdi",
            "pop rcx",    // skip orig_rax
            "pop rcx",    // read rip into rcx
            "add rsp, 8", // skip cs
            "popfq",
            "pop rsp",
            "jmp rcx",    // jump to entry point
            "switch_to_guest_end:",
        );
    }
    
    fn switch_to_guest_ntcontinue(tls: &TlsState, ctx: &litebox_common_linux::PtRegs) -> ! {
        // Uses NtContinue syscall via Windows ntdll for non-sysret path
        // Handles register state setup via Windows CONTEXT structure
    }
}
\\\

**ARM64 Port Notes**:
- Fast path: Use sysret equivalent (ERET) after loading registers from stack
- Slow path: Use Windows NT equivalent on ARM64 (if available) or slow register pop

---

## SECTION 6: INTERRUPT HANDLING & CONTEXT SWITCHING (Lines 700-933)

### ThreadHandle::interrupt (Lines 807-933)

Implements thread interruption for signals/timers:
1. Suspend target thread (Lines 844-850)
2. Access TLS state to check guest mode (Lines 854-863)
3. Handle 4 cases:
   - Case 1: In register pop path - jump to interrupt callback without saving (Lines 898-904)
   - Case 2/3: In NtContinue path - update continue context (Lines 905-918)
   - Case 4: In guest - save context and jump to callback (Lines 920-923)
4. Resume thread (Lines 848-850)

### set_context_to_interrupt_callback (Lines 938-948)

Updates CPU context to jump to interrupt handler:
\\\ust
fn set_context_to_interrupt_callback(
    tls: &TlsState,
    context: &mut windows_sys::Win32::System::Diagnostics::Debug::CONTEXT,
) {
    context.Rip = interrupt_callback as *const () as usize as u64;
    context.Rsp = tls.host_sp.get().addr() as u64;
    context.Rbp = tls.host_bp.get().addr() as u64;
}
\\\

---

## SECTION 7: MEMORY MANAGEMENT (Lines 1350-1580)

### VirtualAlloc/VirtualProtect Wrappers

\\\ust
impl<const ALIGN: usize> litebox::platform::PageManagementProvider<ALIGN> for WindowsUserland {
    const TASK_ADDR_MIN: usize = 0x1_0000;
    const TASK_ADDR_MAX: usize = 0x7FFF_FFFE_F000;
    
    fn allocate_pages(...) -> Result<Self::RawMutPointer<u8>, AllocationError> {
        // Uses VirtualAlloc2 for reserve (MEM_RESERVE) + commit (MEM_COMMIT)
        // Handles fixed address behavior and populate_pages_immediately
    }
    
    unsafe fn deallocate_pages(range: core::ops::Range<usize>) {
        // Uses VirtualFree with MEM_DECOMMIT
    }
    
    unsafe fn update_permissions(range, new_permissions) {
        // Uses VirtualProtect to change page protection
    }
}
\\\

---

## SECTION 8: HANDLER FUNCTIONS (Lines 1681-1759)

### All Handler Entry Points

\\\ust
unsafe extern "C-unwind" fn init_handler(thread_ctx: &mut ThreadContext<'_>) {
    thread_ctx.call_shim(|shim, ctx, _interrupt| shim.init(ctx));
}

unsafe extern "C-unwind" fn syscall_handler(thread_ctx: &mut ThreadContext<'_>) {
    thread_ctx.call_shim(|shim, ctx, _interrupt| shim.syscall(ctx));
}

unsafe extern "C-unwind" fn exception_handler(
    thread_ctx: &mut ThreadContext<'_>,
    exception_record: &EXCEPTION_RECORD,
) {
    // Maps Win32 exceptions to LiteBox exceptions:
    // - EXCEPTION_ACCESS_VIOLATION -> PAGE_FAULT (with error code)
    // - EXCEPTION_ILLEGAL_INSTRUCTION -> INVALID_OPCODE
    // - EXCEPTION_BREAKPOINT -> BREAKPOINT
    // - EXCEPTION_INT_DIVIDE_BY_ZERO -> DIVIDE_ERROR
}

unsafe extern "C-unwind" fn interrupt_handler(thread_ctx: &mut ThreadContext<'_>) {
    thread_ctx.call_shim(|shim, ctx, interrupt| {
        if interrupt {
            shim.interrupt(ctx)
        } else {
            ContinueOperation::Resume
        }
    });
}
\\\

---

# FILE: litebox_common_linux/src/lib.rs - AARCH64 DEFINITIONS

---

## SECTION A: PtRegs STRUCTURES (Lines 3284-3367)

### X86-64 PtRegs (Lines 3287-3324)

\\\ust
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Clone, Debug, Default)]
pub struct PtRegs {
    pub r15: usize,
    pub r14: usize,
    pub r13: usize,
    pub r12: usize,
    pub rbp: usize,
    pub rbx: usize,
    pub r11: usize,
    pub r10: usize,
    pub r9: usize,
    pub r8: usize,
    pub rax: usize,
    pub rcx: usize,
    pub rdx: usize,
    pub rsi: usize,
    pub rdi: usize,
    pub orig_rax: usize,
    pub rip: usize,
    pub cs: usize,
    pub eflags: usize,
    pub rsp: usize,
    pub ss: usize,
}
\\\

### ARM64 PtRegs (Lines 3352-3367) - THE TARGET

\\\ust
#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Clone, Debug, Default)]
pub struct PtRegs {
    /// General-purpose registers x0-x30
    pub regs: [usize; 31],
    /// Stack pointer
    pub sp: usize,
    /// Program counter (return address after syscall)
    pub pc: usize,
    /// Processor state (PSTATE/CPSR)
    pub pstate: usize,
}
\\\

### Syscall Argument Extraction for ARM64 (Lines 3414-3425)

\\\ust
#[cfg(target_arch = "aarch64")]
pub fn syscall_arg(&self, idx: usize) -> usize {
    match idx {
        0 => self.regs[0],  // x0
        1 => self.regs[1],  // x1
        2 => self.regs[2],  // x2
        3 => self.regs[3],  // x3
        4 => self.regs[4],  // x4
        5 => self.regs[5],  // x5
        _ => panic!("Invalid syscall argument index: {}", idx),
    }
}
\\\

---

## SECTION B: FS BASE FUNCTIONS (Lines 1125-1162)

### X86-64 rdfsbase (Lines 1131-1142)

\\\ust
#[cfg(target_arch = "x86_64")]
pub unsafe fn rdfsbase() -> usize {
    let ret: usize;
    unsafe {
        core::arch::asm!(
            "rdfsbase {}",
            out(reg) ret,
            options(nostack, nomem, preserves_flags)
        );
    }
    ret
}
\\\

### X86-64 wrfsbase (Lines 1154-1162)

\\\ust
#[cfg(target_arch = "x86_64")]
pub unsafe fn wrfsbase(fs_base: usize) {
    unsafe {
        core::arch::asm!(
            "wrfsbase {}",
            in(reg) fs_base,
            options(nostack, nomem, preserves_flags)
        );
    }
}
\\\

### ARM64 Equivalents Needed:
- **ARM64 rdfsbase equivalent**: Read TPIDR_EL0 (Thread Pointer ID Register)
  \\\sm
  mrs {reg}, TPIDR_EL0
  \\\
  
- **ARM64 wrfsbase equivalent**: Write TPIDR_EL0
  \\\sm
  msr TPIDR_EL0, {reg}
  \\\

---

## KEY DIFFERENCES X86-64 → ARM64

| Aspect | X86-64 | ARM64 |
|--------|--------|-------|
| Non-volatile GPRs | rbx, r12-r15 (7 regs) | x19-x28 (10 regs) |
| Non-volatile FP regs | xmm6-xmm15 (10 x 128-bit) | v8-v15 (8 x 128-bit) |
| TLS register | GS (via segment base) | TPIDR_EL0 (MSR/MRS) |
| Argument registers | rdi, rsi, rdx, rcx, r8, r9 | x0-x5 |
| Stack pointer | RSP | SP |
| Frame pointer | RBP | X29 |
| Link register | (stack-based) | X30 |
| Return register | RAX | X0 |
| System call entry | jmp rcx (via sysret) | ERET |
| Exception handling | Windows vectored handlers | Windows ARM64 exception handling |
| Memory layout | PtRegs fields match x86-64 | PtRegs fields are completely different |
| Stack alignment | 16-byte | 16-byte (same) |

---

## CRITICAL IMPLEMENTATION NOTES FOR ARM64 PORT

### 1. Register Mapping
The Windows platform crate uses Linux-style PtRegs. For ARM64:
- Update run_thread_arch to save/restore ARM64 registers
- Change TLS access from GS segment to TPIDR_EL0
- Update prologue/epilogue for ARM64 ABI

### 2. Exception Handling
- Keep Windows vectored exception handler approach
- Map Windows exception codes to ARM64-equivalent faults
- Extract register context from Windows CONTEXT ARM64 variant

### 3. Assembly Entry Points
- syscall_callback: Must switch from guest x0-x5 args to host ABI
- switch_to_guest_sysret: Replace sysret with ARM64 equivalent
- Interrupt/exception handling: May need architecture-specific adjustments

### 4. Memory Management
- VirtualAlloc/VirtualProtect work identically on ARM64 Windows
- Update TASK_ADDR_MIN/MAX for ARM64 address space (typically 0x0 to 2^48)

### 5. TLS Management
- X86-64: Uses rdfsbase/wrfsbase to manipulate GS base
- ARM64: Must use MSR/MRS instructions for TPIDR_EL0 (or TPIDR_EL0 on user mode)
  
