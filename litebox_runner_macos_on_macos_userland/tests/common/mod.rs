// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, Once};

pub mod shared_cache;

/// Serialize test execution. Each test creates its own `MacosShimBuilder`
/// and `PageManager`, but the platform and global `HOST_TLS_TABLE_ADDR`
/// are process-wide singletons. Running tests concurrently causes the
/// second test's `update_host_tls_entry()` to access stale TLS table
/// memory from the first test's (now-dropped) `PageManager`.
static TEST_LOCK: Mutex<()> = Mutex::new(());

/// Ensure the litebox platform is initialized exactly once per test binary.
fn ensure_platform() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // Install a SIGSEGV handler that prints diagnostic info before dying.
        unsafe {
            install_crash_handler();
        }
        let platform = litebox_platform_macos_userland::MacosUserland::new(None);
        litebox_platform_multiplex::set_platform(platform);
    });
}

/// Install a signal handler that prints the faulting address and PC on crash.
unsafe fn install_crash_handler() {
    unsafe extern "C" fn crash_handler(
        sig: libc::c_int,
        info: *mut libc::siginfo_t,
        ctx: *mut libc::c_void,
    ) {
        let fault_addr = if info.is_null() {
            0
        } else {
            unsafe { (*info).si_addr as u64 }
        };

        // Extract PC from ucontext on aarch64 macOS
        let pc = if ctx.is_null() {
            0
        } else {
            let uctx = unsafe { &*(ctx as *const libc::ucontext_t) };
            let mctx = unsafe { &*uctx.uc_mcontext };
            // __ss.__pc on arm64 macOS
            mctx.__ss.__pc
        };

        // Use write(2) directly — signal-safe, no allocator.
        let mut buf = [0u8; 256];
        let msg = format_crash_msg(&mut buf, sig, fault_addr, pc);
        unsafe {
            libc::write(2, msg.as_ptr().cast(), msg.len());
            libc::_exit(128 + sig);
        }
    }

    fn format_crash_msg(buf: &mut [u8; 256], sig: i32, fault_addr: u64, pc: u64) -> &[u8] {
        // Manual formatting to avoid allocator in signal handler.
        let mut pos = 0;

        let prefix = b"\n*** CRASH HANDLER: signal=";
        buf[pos..pos + prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();

        #[allow(clippy::cast_sign_loss)]
        {
            pos += write_dec(&mut buf[pos..], sig as u64);
        }

        let fa_prefix = b" fault_addr=0x";
        buf[pos..pos + fa_prefix.len()].copy_from_slice(fa_prefix);
        pos += fa_prefix.len();

        pos += write_hex(&mut buf[pos..], fault_addr);

        let pc_prefix = b" pc=0x";
        buf[pos..pos + pc_prefix.len()].copy_from_slice(pc_prefix);
        pos += pc_prefix.len();

        pos += write_hex(&mut buf[pos..], pc);

        buf[pos] = b'\n';
        pos += 1;

        &buf[..pos]
    }

    fn write_dec(buf: &mut [u8], val: u64) -> usize {
        if val == 0 {
            buf[0] = b'0';
            return 1;
        }
        let mut tmp = [0u8; 20];
        let mut v = val;
        let mut i = 0;
        while v > 0 {
            tmp[i] = b'0' + (v % 10) as u8;
            v /= 10;
            i += 1;
        }
        for j in 0..i {
            buf[j] = tmp[i - 1 - j];
        }
        i
    }

    fn write_hex(buf: &mut [u8], val: u64) -> usize {
        if val == 0 {
            buf[0] = b'0';
            return 1;
        }
        let mut tmp = [0u8; 16];
        let mut v = val;
        let mut i = 0;
        while v > 0 {
            let digit = (v & 0xf) as u8;
            tmp[i] = if digit < 10 {
                b'0' + digit
            } else {
                b'a' + digit - 10
            };
            v >>= 4;
            i += 1;
        }
        for j in 0..i {
            buf[j] = tmp[i - 1 - j];
        }
        i
    }

    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = crash_handler as *const () as usize;
        sa.sa_flags = libc::SA_SIGINFO | libc::SA_RESETHAND;
        libc::sigaction(libc::SIGSEGV, &raw const sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGBUS, &raw const sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGABRT, &raw const sa, std::ptr::null_mut());
    }
}

/// Assemble and link an aarch64 Mach-O binary from an assembly source file.
///
/// Uses Xcode `as` and `ld` to produce a static MH_EXECUTE with LC_UNIXTHREAD
/// (no dyld, no libc).
pub fn assemble_macho(src_path: &str, name: &str) -> PathBuf {
    let dir = std::env::var("OUT_DIR")
        .unwrap_or_else(|_| std::env::temp_dir().to_str().unwrap().to_string());
    let dir = Path::new(&dir);

    let obj_path = dir.join(format!("{name}.o"));
    let bin_path = dir.join(name);

    // Assemble
    let output = std::process::Command::new("as")
        .args(["-arch", "arm64", src_path, "-o", obj_path.to_str().unwrap()])
        .output()
        .expect("failed to run assembler");
    assert!(
        output.status.success(),
        "assembler failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Link with -static -e _start (LC_UNIXTHREAD entry)
    // -headerpad 0x1000 ensures there is enough header space for the
    // syscall rewriter to inject the __LITEBOX trampoline segment.
    let output = std::process::Command::new("ld")
        .args([
            "-arch",
            "arm64",
            "-static",
            "-headerpad",
            "0x1000",
            "-e",
            "_start",
            obj_path.to_str().unwrap(),
            "-o",
            bin_path.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run linker");
    assert!(
        output.status.success(),
        "linker failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    bin_path
}

/// Compile a C source file to a static Mach-O binary using clang (no libc).
pub fn compile_macho_nolibc(src_path: &str, name: &str) -> PathBuf {
    let dir = std::env::var("OUT_DIR")
        .unwrap_or_else(|_| std::env::temp_dir().to_str().unwrap().to_string());
    let dir = Path::new(&dir);

    let bin_path = dir.join(name);

    let output = std::process::Command::new("clang")
        .args([
            "-arch",
            "arm64",
            "-static",
            "-nostdlib",
            "-Wl,-headerpad,0x1000",
            "-e",
            "__start",
            "-o",
            bin_path.to_str().unwrap(),
            src_path,
        ])
        .output()
        .expect("failed to run clang");
    assert!(
        output.status.success(),
        "clang failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    bin_path
}

/// Compile a C source file to a dynamically linked Mach-O binary using clang.
pub fn compile_macho_dynamic(src_path: &str, name: &str) -> PathBuf {
    let dir = std::env::var("OUT_DIR")
        .unwrap_or_else(|_| std::env::temp_dir().to_str().unwrap().to_string());
    let dir = Path::new(&dir);

    let bin_path = dir.join(name);

    let output = std::process::Command::new("clang")
        .args([
            "-arch",
            "arm64",
            "-Wl,-headerpad,0x1000",
            "-o",
            bin_path.to_str().unwrap(),
            src_path,
        ])
        .output()
        .expect("failed to run clang");
    assert!(
        output.status.success(),
        "clang failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    bin_path
}

/// Rewrite a Mach-O binary using the Mach-O syscall rewriter.
pub fn rewrite_macho(input: &Path) -> Vec<u8> {
    let data = std::fs::read(input).expect("read binary");
    litebox_syscall_rewriter_macho::hook_syscalls_in_macho(&data).expect("Mach-O rewriter failed")
}

/// Run a rewritten Mach-O binary through litebox, capturing stdout and exit code.
pub fn run_macho_binary(binary_data: &[u8], argv: &[&str]) -> (i32, Vec<u8>) {
    use litebox::fs::{FileSystem as _, Mode};

    // Serialize: only one test can use the platform + TLS table at a time.
    let _guard = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    ensure_platform();

    // Reset the global TLS table address so the new shim's loader can
    // allocate a fresh one. The old table (if any) belonged to a previous
    // test's PageManager which has since been dropped.
    litebox_common_linux::HOST_TLS_TABLE_ADDR.store(0, std::sync::atomic::Ordering::Release);

    let mut shim_builder =
        litebox_shim_macos::MacosShimBuilder::<litebox_shim_macos::DefaultFS>::new();
    let litebox = shim_builder.litebox();

    // Create a default layered file system
    let mut in_mem_fs = litebox::fs::in_mem::FileSystem::new(litebox);
    in_mem_fs.with_root_privileges(|fs| {
        let mode = Mode::RWXU | Mode::RWXG | Mode::RWXO;
        let _ = fs.mkdir("/tmp", mode);
    });
    let tar_ro_fs =
        litebox::fs::tar_ro::FileSystem::new(litebox, litebox::fs::tar_ro::EMPTY_TAR_FILE.into());
    let fs = shim_builder.default_fs(in_mem_fs, tar_ro_fs);
    shim_builder.set_fs(fs);
    let shim = shim_builder.build();

    let argv_cstrings: Vec<std::ffi::CString> = argv
        .iter()
        .map(|s| std::ffi::CString::new(*s).unwrap())
        .collect();
    let envp = vec![std::ffi::CString::new("PATH=/bin").unwrap()];

    let program = shim
        .load_program(binary_data, argv_cstrings, envp, None)
        .expect("load_program failed");

    let litebox_shim_macos::LoadedProgram {
        entrypoints,
        process,
        mut initial_ctx,
    } = program;

    unsafe {
        litebox_platform_macos_userland::run_thread(entrypoints, &mut initial_ctx);
    }

    let exit_code = process.wait();
    (exit_code, Vec::new())
}

/// Run a dynamically linked Mach-O binary through litebox with shared cache passthrough.
///
/// Unlike [`run_macho_binary`], this:
/// - Installs shared cache regions into guest address space
/// - Reads `/usr/lib/dyld` from the host and passes it to `load_program`
///
/// The guest runs in a `fork()`ed child process to isolate shared cache
/// __DATA corruption from the host.  dyld marks `PrebuiltLoader` state bytes
/// in shared cache __DATA pages; these COW writes corrupt the host's view
/// and crash it during exit cleanup.  Fork isolation ensures the corruption
/// dies with the child process.
pub fn run_macho_dynamic(
    binary_data: &[u8],
    argv: &[&str],
    cache: &shared_cache::CollectedCache,
    exe_name: &str,
) -> (i32, Vec<u8>) {
    // Serialize: only one test can use the platform + TLS table at a time.
    let _guard = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    // Resolve `_sigtramp` in the parent process before fork().
    // dlsym is NOT async-signal-safe and may deadlock or return NULL in a
    // forked child of a multi-threaded process.  The resolved address is
    // stored in a global AtomicUsize and inherited by the child via COW.
    litebox_platform_macos_userland::get_sigtramp_addr();

    // Set up a shared-memory region for the child to write the exit code.
    // We use mmap(MAP_SHARED|MAP_ANON) so both parent and child see the
    // same page.
    let exit_code_ptr: *mut i32 = unsafe {
        let ptr = libc::mmap(
            std::ptr::null_mut(),
            4,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANON,
            -1,
            0,
        );
        assert_ne!(ptr, libc::MAP_FAILED, "mmap for exit code failed");
        // Initialize to -999 sentinel value.
        *ptr.cast::<i32>() = -999;
        ptr.cast::<i32>()
    };

    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");

    if pid == 0 {
        // ---- Child process ----
        // Change CWD to "/" so that shared-cache libc calls like getcwd()
        // see the expected root directory (their SVCs go to the real kernel,
        // not through the shim).
        unsafe {
            let root = b"/\0";
            libc::chdir(root.as_ptr().cast());
        }
        let exit_code = run_macho_dynamic_inner(binary_data, argv, cache, exe_name);
        unsafe {
            core::ptr::write_volatile(exit_code_ptr, exit_code);
            // Use _exit to skip atexit handlers (which crash due to
            // corrupted shared cache __DATA).
            libc::_exit(0);
        }
    }

    // ---- Parent process ----
    let mut status: libc::c_int = 0;
    let waited = unsafe { libc::waitpid(pid, &raw mut status, 0) };
    assert_eq!(waited, pid, "waitpid failed");

    let exit_code = unsafe { *exit_code_ptr };
    unsafe {
        libc::munmap(exit_code_ptr.cast(), 4);
    }

    assert!(
        !libc::WIFSIGNALED(status),
        "dynamic test child killed by signal {} (guest exit code {})",
        libc::WTERMSIG(status),
        exit_code,
    );

    assert!(
        libc::WIFEXITED(status),
        "dynamic test child: unexpected wait status {status:#x}"
    );

    if exit_code == -999 {
        // The guest called exit() through the shared cache, which
        // eventually called the real kernel _exit(N).  The child
        // terminated before the inner function could return and
        // write the exit code.  The kernel preserved the guest's exit
        // code in the child's wait status, so WEXITSTATUS gives us
        // the correct value.
        (libc::WEXITSTATUS(status), Vec::new())
    } else {
        // Our shim handled exit — the child wrote the guest's exit code
        // to shared memory before calling _exit(0).
        (exit_code, Vec::new())
    }
}

/// Inner implementation of [`run_macho_dynamic`] — runs in the forked child.
fn run_macho_dynamic_inner(
    binary_data: &[u8],
    argv: &[&str],
    cache: &shared_cache::CollectedCache,
    exe_name: &str,
) -> i32 {
    use litebox::fs::{FileSystem as _, Mode, OFlags};

    // Re-initialize the platform in the child process.  macOS Hypervisor
    // framework state does not survive fork() — we must create a fresh one.
    // The parent's OnceRef is already set (inherited), so we must reset it
    // before creating a new platform.  The old Platform object is leaked —
    // we'll call _exit() to skip destructors.
    //
    // We also reset the exception-handler registration guard.  The parent's
    // `install_crash_handler()` may have overwritten SIGSEGV/SIGBUS handlers
    // with a crash handler.  Without re-registering, the child inherits
    // those crash handlers instead of the platform's exception handler, so
    // guest page faults are handled incorrectly.
    unsafe {
        litebox_platform_multiplex::reset_platform();
        litebox_platform_macos_userland::reset_exception_handler_once();
    }
    let platform = litebox_platform_macos_userland::MacosUserland::new(None);
    litebox_platform_multiplex::set_platform(platform);
    litebox_common_linux::HOST_TLS_TABLE_ADDR.store(0, std::sync::atomic::Ordering::Release);

    // Rewrite the guest binary through the syscall rewriter so that inline
    // SVCs in the guest's __TEXT are intercepted by the shim.  Without this,
    // SVCs compiled into the guest binary (e.g. mach_semaphore.c's inline
    // `svc #0x80`) pass straight through to the real kernel.
    //
    // If the binary has no SVC instructions (e.g. it only calls libc
    // functions from the shared cache), the rewriter returns
    // `NoSvcInstructionsFound` — in that case we use the original binary.
    //
    // System binaries (fat/universal Mach-Os, or other unsupported formats)
    // may fail to parse — this is fine because they only call libc from the
    // shared cache (whose SVCs pass through to the host kernel).
    let rewritten_data = litebox_syscall_rewriter_macho::hook_syscalls_in_macho(binary_data).ok();
    let effective_binary = rewritten_data.as_deref().unwrap_or(binary_data);

    let mut shim_builder =
        litebox_shim_macos::MacosShimBuilder::<litebox_shim_macos::DefaultFS>::new();
    let litebox = shim_builder.litebox();
    let mut in_mem_fs = litebox::fs::in_mem::FileSystem::new(litebox);
    in_mem_fs.with_root_privileges(|fs| {
        let mode = Mode::RWXU | Mode::RWXG | Mode::RWXO;
        let _ = fs.mkdir("/tmp", mode);
        let _ = fs.mkdir("/usr", mode);
        let _ = fs.mkdir("/usr/bin", mode);

        // Write the rewritten binary into the in-mem FS so dyld can open it.
        let exe_path = format!("/usr/bin/{exe_name}");
        let fd = fs
            .open(&exe_path, OFlags::CREAT | OFlags::WRONLY, mode)
            .expect("create executable in in-mem FS");
        fs.write(&fd, effective_binary, None)
            .expect("write executable data");
        fs.close(&fd).expect("close executable fd");
    });
    let tar_ro_fs =
        litebox::fs::tar_ro::FileSystem::new(litebox, litebox::fs::tar_ro::EMPTY_TAR_FILE.into());
    let fs = shim_builder.default_fs(in_mem_fs, tar_ro_fs);
    shim_builder.set_fs(fs);
    let shim = shim_builder.build();

    // Use absolute path for argv[0] so dyld can resolve executable_path.
    let exe_path = format!("/usr/bin/{exe_name}");
    let mut argv_cstrings: Vec<std::ffi::CString> = Vec::with_capacity(argv.len());
    argv_cstrings.push(std::ffi::CString::new(exe_path).unwrap());
    for s in &argv[1..] {
        argv_cstrings.push(std::ffi::CString::new(*s).unwrap());
    }
    let envp = vec![std::ffi::CString::new("PATH=/bin").unwrap()];

    // Read dyld from the host filesystem.  This MUST happen before
    // install_shared_cache, which patches libsystem_kernel's SVCs —
    // after that, libc calls (read/write/malloc/etc.) are intercepted
    // by the shim and would crash because no TLS entry or TCB exists
    // for the install thread.
    let dyld_data = std::fs::read("/usr/lib/dyld").expect("failed to read /usr/lib/dyld");

    // Load the program (parses Mach-O, allocates stack, etc.) before
    // install_shared_cache for the same reason: load_program uses the
    // allocator and libc internally.
    let program = shim
        .load_program(effective_binary, argv_cstrings, envp, Some(&dyld_data))
        .expect("load_program failed");

    let litebox_shim_macos::LoadedProgram {
        entrypoints,
        process,
        mut initial_ctx,
    } = program;

    // Install shared cache regions into guest address space.
    // Global mapping regions were already mmap'd at guest addresses by
    // collect_regions (MAP_FIXED).  Only heap-backed regions (dylib segments,
    // patched header) go through install_shared_cache for SVC patching.
    // The preinstalled extents are passed as reserved_extents so the
    // trampoline allocator avoids overlapping them.
    //
    // *** THIS MUST BE THE LAST STEP BEFORE run_thread. ***
    // Pass 3 patches libsystem_kernel's SVC stubs, so after this call
    // ANY libc call (malloc, write, read, etc.) will be intercepted by
    // the litebox gate.  The gate requires a valid TLS table entry and
    // TCB for the current thread, which only exist inside run_thread.
    let regions_for_shim: Vec<(u64, &[u8], bool)> = cache
        .regions
        .iter()
        .map(|r| {
            let is_exec = matches!(r.prot, shared_cache::Protection::ReadExecute);
            (r.guest_addr, r.data(), is_exec)
        })
        .collect();
    eprintln!(">>> about to install_shared_cache");
    shim.install_shared_cache(
        cache.host_cache_base,
        &regions_for_shim,
        &cache.preinstalled_extents,
        &cache.patch_in_place_text,
        &cache.reset_in_place_data,
        &cache.demand_page_sources,
        litebox_platform_macos_userland::get_sigtramp_addr() as u64,
    );

    // NO LIBC CALLS BETWEEN install_shared_cache AND run_thread.
    // libsystem_kernel's SVCs are now patched — any libc call would
    // go through the litebox gate, which has no TLS entry for this
    // thread and would hit BRK #1 → SIGTRAP → hang.
    //
    // Use raw inline asm write(2, ...) for any post-install diagnostics.
    unsafe {
        let msg = b">>> about to run_thread\n";
        core::arch::asm!(
            "mov x0, #2", "mov x1, {buf}", "mov x2, {len}",
            "mov x16, #0x4", "movk x16, #0x200, lsl #16", "svc #0x80",
            buf = in(reg) msg.as_ptr(), len = in(reg) msg.len(),
            out("x0") _, out("x1") _, out("x2") _, out("x16") _,
            clobber_abi("C"),
        );
    }
    unsafe {
        litebox_platform_macos_userland::run_thread(entrypoints, &mut initial_ctx);
    }
    unsafe {
        let msg = b">>> run_thread returned\n";
        core::arch::asm!(
            "mov x0, #2", "mov x1, {buf}", "mov x2, {len}",
            "mov x16, #0x4", "movk x16, #0x200, lsl #16", "svc #0x80",
            buf = in(reg) msg.as_ptr(), len = in(reg) msg.len(),
            out("x0") _, out("x1") _, out("x2") _, out("x16") _,
            clobber_abi("C"),
        );
    }

    process.wait()
}
