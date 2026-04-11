// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, Once};

use litebox::platform::SystemInfoProvider as _;

pub mod shared_cache;

/// Resolve a symbol from `libsystem_pthread.dylib` using `dlsym`.
///
/// Must be called before `fork()` — `dlsym` is not async-signal-safe.
fn resolve_pthread_symbol(name: &std::ffi::CStr) -> u64 {
    unsafe {
        let handle = libc::dlopen(
            c"/usr/lib/system/libsystem_pthread.dylib".as_ptr(),
            libc::RTLD_LAZY,
        );
        assert!(!handle.is_null(), "dlopen libsystem_pthread.dylib failed");
        let addr = libc::dlsym(handle, name.as_ptr());
        libc::dlclose(handle);
        assert!(!addr.is_null(), "dlsym({name:?}) returned NULL");
        addr as u64
    }
}

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

    // Print the host process base address for conflict detection.
    eprintln!(
        ">>> [static] host: run_macho_binary={:#x} main={:#x}",
        run_macho_binary as *const () as usize,
        ensure_platform as *const () as usize,
    );

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
        reserved_base,
        slide,
    } = program;

    let tls_table = litebox_common_linux::HOST_TLS_TABLE_ADDR.load(std::sync::atomic::Ordering::Acquire);
    let callback = litebox_platform_multiplex::platform().get_syscall_entry_point();
    eprintln!(
        ">>> [static] load_program done: entry_pc={:#x} sp={:#x} reserved_base={:#x} slide={:#x} binary_len={} tls_table={:#x} callback={:#x}",
        initial_ctx.pc, initial_ctx.sp, reserved_base, slide, binary_data.len(), tls_table, callback
    );

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
    run_macho_dynamic_with_utun(binary_data, argv, cache, exe_name, None)
}

/// Like [`run_macho_dynamic`] but optionally opens a utun device for inet networking.
///
/// When `tun_device_name` is `Some("utunN")`, the child process opens that utun
/// device, spawns a network-polling thread, and the **parent** process configures
/// the device with `ifconfig`/`route` (requires root).
pub fn run_macho_dynamic_with_utun(
    binary_data: &[u8],
    argv: &[&str],
    cache: &shared_cache::CollectedCache,
    exe_name: &str,
    tun_device_name: Option<&str>,
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

    // Resolve pthread thread-start symbols before fork() (dlsym is not
    // async-signal-safe).  These addresses are passed to the shim's
    // synthetic bsdthread_register so that bsdthread_create works even
    // though library initializers are skipped.
    let thread_start_addr = resolve_pthread_symbol(c"thread_start");
    let start_wqthread_addr = resolve_pthread_symbol(c"start_wqthread");

    // Set up a shared-memory region for the child to write the exit code
    // and diagnostic state.  Layout: [exit_code: i32, diag_state: i32]
    // diag_state values: 0=init, 1=entered_inner, 2=reset_platform,
    //   3=reset_exception_handler, 4=MacosUserland::new, 5=set_platform,
    //   6=about_to_rewrite, 7=rewriter_done, 8=shim_built, 9=dyld_read,
    //   10=load_program_done, 11=destructured, 12=register_pthread,
    //   13=regions_built, 52=run_thread_done, 53=wait_done, 54=about_to_exit
    let shared_page: *mut i32 = unsafe {
        let ptr = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANON,
            -1,
            0,
        );
        assert_ne!(ptr, libc::MAP_FAILED, "mmap for exit code failed");
        // Initialize to -999 sentinel value.
        *ptr.cast::<i32>() = -999;
        // diag_state = 0
        *ptr.cast::<i32>().add(1) = 0;
        ptr.cast::<i32>()
    };
    let exit_code_ptr: *mut i32 = shared_page;
    let diag_state_ptr: *mut i32 = unsafe { shared_page.add(1) };

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
        let exit_code = run_macho_dynamic_inner(
            binary_data,
            argv,
            cache,
            exe_name,
            thread_start_addr,
            start_wqthread_addr,
            diag_state_ptr,
            tun_device_name,
        );
        unsafe {
            core::ptr::write_volatile(diag_state_ptr, 54); // about_to_exit
            core::ptr::write_volatile(exit_code_ptr, exit_code);
            // Use a raw SVC to call _exit(0), bypassing the shared
            // cache whose __DATA is corrupted by guest execution.
            // Going through libc::_exit would hit the patched SVC
            // gate, which may misbehave when in_guest=0.
            core::arch::asm!(
                "mov x0, #0",
                "mov x16, #1",
                "movk x16, #0x200, lsl #16", // x16 = 0x2000001 (BSD exit)
                "svc #0x80",
                options(noreturn),
            );
        }
    }

    // ---- Parent process ----
    // If using utun, configure the device before waiting for child.
    // The child's MacosUserland::new() opens the utun device; we need
    // to wait for it to appear and configure IP routing on the host side.
    if let Some(device) = tun_device_name {
        let configured = configure_utun(device, "10.0.0.1", std::time::Duration::from_secs(10));
        assert!(configured, "Failed to configure utun device {device}");
    }

    let mut status: libc::c_int = 0;
    let waited = unsafe { libc::waitpid(pid, &raw mut status, 0) };
    assert_eq!(waited, pid, "waitpid failed");

    let exit_code = unsafe { *exit_code_ptr };
    let diag = unsafe { core::ptr::read_volatile(diag_state_ptr) };
    unsafe {
        libc::munmap(shared_page.cast(), 4096);
    }

    if exit_code != -999 {
        // The shim handled exit and wrote the guest's exit code to
        // shared memory.  The child then called libc::_exit(0), but
        // that goes through the shared cache whose __DATA may be
        // corrupted by guest execution — causing SIGABRT during
        // cleanup.  Since we already have the guest's exit code, we
        // can safely ignore the child's signal death.
        return (exit_code, Vec::new());
    }

    if libc::WIFSIGNALED(status) {
        let sig = libc::WTERMSIG(status);
        let coredump = libc::WCOREDUMP(status);
        panic!(
            "dynamic test child killed by signal {sig} (core={coredump}) (wait status={status:#x}) (guest exit code {exit_code}) (diag_state={diag})"
        );
    }

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
#[allow(clippy::too_many_arguments)]
fn run_macho_dynamic_inner(
    binary_data: &[u8],
    argv: &[&str],
    cache: &shared_cache::CollectedCache,
    exe_name: &str,
    thread_start_addr: u64,
    start_wqthread_addr: u64,
    diag_state_ptr: *mut i32,
    tun_device_name: Option<&str>,
) -> i32 {
    use litebox::fs::{FileSystem as _, Mode, OFlags};

    unsafe {
        core::ptr::write_volatile(diag_state_ptr, 1);
    } // entered_inner

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
    }
    unsafe { core::ptr::write_volatile(diag_state_ptr, 2); }

    unsafe {
        litebox_platform_macos_userland::reset_exception_handler_once();
    }
    unsafe { core::ptr::write_volatile(diag_state_ptr, 3); }

    let platform = litebox_platform_macos_userland::MacosUserland::new(tun_device_name);
    unsafe { core::ptr::write_volatile(diag_state_ptr, 4); }

    litebox_platform_multiplex::set_platform(platform);
    unsafe { core::ptr::write_volatile(diag_state_ptr, 5); }

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
    unsafe { core::ptr::write_volatile(diag_state_ptr, 6); }
    let rewritten_data = litebox_syscall_rewriter_macho::hook_syscalls_in_macho(binary_data).ok();
    let effective_binary = rewritten_data.as_deref().unwrap_or(binary_data);
    unsafe { core::ptr::write_volatile(diag_state_ptr, 7); }

    let mut shim_builder =
        litebox_shim_macos::MacosShimBuilder::<litebox_shim_macos::DefaultFS>::new();
    let litebox = shim_builder.litebox();
    let mut in_mem_fs = litebox::fs::in_mem::FileSystem::new(litebox);
    in_mem_fs.with_root_privileges(|fs| {
        let mode = Mode::RWXU | Mode::RWXG | Mode::RWXO;
        let _ = fs.mkdir("/tmp", mode);
        let _ = fs.mkdir("/usr", mode);
        let _ = fs.mkdir("/usr/bin", mode);
        // Populate /tmp with a few files so /bin/ls exercises a non-empty directory.
        for name in ["hello.txt", "world.txt", "data.bin"] {
            let path = format!("/tmp/{name}");
            let fd = fs
                .open(&path, OFlags::CREAT | OFlags::WRONLY, mode)
                .expect("create test file in /tmp");
            fs.write(
                &fd,
                b"test content
",
                None,
            )
            .expect("write test file data");
            fs.close(&fd).expect("close test file");
        }

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
    unsafe { core::ptr::write_volatile(diag_state_ptr, 8); }

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
    unsafe { core::ptr::write_volatile(diag_state_ptr, 9); }

    // Load the program (parses Mach-O, allocates stack, etc.) before
    // install_shared_cache for the same reason: load_program uses the
    // allocator and libc internally.
    let program = shim
        .load_program(effective_binary, argv_cstrings, envp, Some(&dyld_data))
        .expect("load_program failed");
    unsafe { core::ptr::write_volatile(diag_state_ptr, 10); } // load_program done

    eprintln!(
        ">>> [dynamic] load_program done: entry_pc={:#x} sp={:#x} reserved_base={:#x} slide={:#x} binary_len={}",
        program.initial_ctx.pc, program.initial_ctx.sp, program.reserved_base, program.slide, effective_binary.len()
    );

    let litebox_shim_macos::LoadedProgram {
        entrypoints,
        process,
        mut initial_ctx,
        reserved_base: _,
        slide: _,
    } = program;
    unsafe { core::ptr::write_volatile(diag_state_ptr, 11); } // destructured

    // Synthetically register pthread thread-start addresses.
    //
    // Normally libpthread's __pthread_init calls bsdthread_register during
    // library initialization.  We skip initializers (to avoid double-init
    // SIGKILL), so we must provide this data ourselves.
    //
    // pthsize = page_align(0x18E0) on 16K-page aarch64 = 0x4000
    // tsd_offset = 0xA0 (from disassembly of __pthread_bsdthread_init)
    process.register_pthread_info(thread_start_addr, start_wqthread_addr, 0x4000, 0xA0);
    unsafe { core::ptr::write_volatile(diag_state_ptr, 12); } // register_pthread_info done

    // Install shared cache regions into guest address space.
    // Global mapping regions were already mmap'd at guest addresses by
    // collect_regions (MAP_FIXED).  Only heap-backed regions (dylib segments,
    // patched header) go through install_shared_cache for SVC patching.
    // The preinstalled extents are passed as reserved_extents so the
    // trampoline allocator avoids overlapping them.
    //
    // Pass 3 patches libsystem_kernel's SVC stubs.  After this call,
    // any SVC goes through the trampoline.  Threads NOT in the TLS
    // table (this thread, the network thread) use the passthrough
    // path and execute real SVCs, so libc calls still work here.
    eprintln!(
        ">>> [dynamic] cache: host_base={:#x} regions={} preinstalled={}",
        cache.host_cache_base,
        cache.regions.len(),
        cache.preinstalled_extents.len(),
    );
    // Print first few region addresses
    for (i, r) in cache.regions.iter().enumerate().take(5) {
        eprintln!(
            ">>>   region[{}]: guest_addr={:#x} len={:#x} prot={:?}",
            i, r.guest_addr, r.data().len(), r.prot
        );
    }
    if cache.regions.len() > 5 {
        eprintln!(">>>   ... and {} more regions", cache.regions.len() - 5);
    }
    let regions_for_shim: Vec<(u64, &[u8], bool)> = cache
        .regions
        .iter()
        .map(|r| {
            let is_exec = matches!(r.prot, shared_cache::Protection::ReadExecute);
            (r.guest_addr, r.data(), is_exec)
        })
        .collect();
    unsafe { core::ptr::write_volatile(diag_state_ptr, 13); } // regions_for_shim built

    eprintln!(
        ">>> [dynamic] regions_for_shim: count={} preinstalled={} patch_text={} reset_data={} demand_pages={}",
        regions_for_shim.len(),
        cache.preinstalled_extents.len(),
        cache.patch_in_place_text.len(),
        cache.reset_in_place_data.len(),
        cache.demand_page_sources.len(),
    );
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

    // Spawn the network polling thread AFTER install_shared_cache.
    // The network thread is NOT registered in the TLS table, so when
    // it hits a patched SVC stub, the trampoline's scan hits the
    // sentinel and falls through to the passthrough path — executing
    // real SVCs.  This means the network thread's libc calls (poll,
    // read, write on the utun fd) go directly to the real kernel.
    //
    // IMPORTANT: This must be AFTER install_shared_cache.  Spawning
    // the thread before install causes a race: install_shared_cache
    // does mprotect(page, RW) on shared cache code pages to patch
    // SVC instructions, temporarily removing execute permission.
    // If the network thread is executing code on those pages, it
    // gets SIGBUS on the next instruction fetch.
    let net_shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let net_worker = if tun_device_name.is_some() {
        let shim_clone = shim.clone();
        let shutdown_clone = net_shutdown.clone();
        let child = std::thread::spawn(move || {
            const DEFAULT_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(5);
            while !shutdown_clone.load(std::sync::atomic::Ordering::Relaxed) {
                let timeout = loop {
                    match shim_clone.perform_network_interaction() {
                        litebox::net::PlatformInteractionReinvocationAdvice::CallAgainImmediately => {}
                        litebox::net::PlatformInteractionReinvocationAdvice::WaitOnDeviceOrSocketInteraction { timeout } => {
                            break timeout;
                        }
                    }
                };
                litebox_platform_multiplex::platform()
                    .wait_on_tun(Some(timeout.unwrap_or(DEFAULT_TIMEOUT)));
            }
            // Final flush
            while shim_clone
                .perform_network_interaction()
                .call_again_immediately()
            {}
        });
        Some(child)
    } else {
        None
    };

    // After install_shared_cache, all SVC stubs are patched.  Threads
    // not in the TLS table (this thread + the network thread) use the
    // passthrough path, so std::thread::spawn and libc calls work.
    //
    // Use raw inline asm write(2, ...) for post-install diagnostics.
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
        core::ptr::write_volatile(diag_state_ptr, 52);
    } // run_thread_done

    // Signal the network polling thread to shut down.  This is a pure
    // atomic store — no libc call — so it is safe after install_shared_cache.
    // We cannot join() the thread (that's a libc call), but _exit() in
    // the caller will terminate all threads in this child process.
    net_shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
    // Drop net_worker without joining — _exit will clean up.
    drop(net_worker);

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

    let exit_code = process.wait();
    unsafe {
        core::ptr::write_volatile(diag_state_ptr, 53);
    } // wait_done
    exit_code
}

/// Waits for a utun device to appear and configures it with the given IP.
///
/// Runs `ifconfig <device> <ip> <ip> netmask 255.255.255.0 up` and
/// `route -n add -net 10.0.0.0/24 -interface <device>`.
///
/// Returns `true` on success.
fn configure_utun(device: &str, ip: &str, timeout: std::time::Duration) -> bool {
    let start = std::time::Instant::now();
    let poll_interval = std::time::Duration::from_millis(200);

    // Wait for the utun device to appear.
    loop {
        let output = std::process::Command::new("ifconfig")
            .arg(device)
            .output()
            .expect("failed to run ifconfig");
        if output.status.success() {
            break;
        }
        if start.elapsed() > timeout {
            eprintln!("configure_utun: timeout waiting for {device} to appear");
            return false;
        }
        std::thread::sleep(poll_interval);
    }

    // Determine if we need sudo.
    let use_sudo = unsafe { libc::geteuid() != 0 };

    // Configure the interface.
    let ifconfig_status = if use_sudo {
        std::process::Command::new("sudo")
            .args([
                "-n",
                "ifconfig",
                device,
                ip,
                ip,
                "netmask",
                "255.255.255.0",
                "up",
            ])
            .status()
            .expect("failed to run sudo ifconfig")
    } else {
        std::process::Command::new("ifconfig")
            .args([device, ip, ip, "netmask", "255.255.255.0", "up"])
            .status()
            .expect("failed to run ifconfig")
    };
    if !ifconfig_status.success() {
        eprintln!("configure_utun: ifconfig failed with {ifconfig_status}");
        return false;
    }

    // Add route.
    let route_status = if use_sudo {
        std::process::Command::new("sudo")
            .args([
                "-n",
                "route",
                "-n",
                "add",
                "-net",
                "10.0.0.0/24",
                "-interface",
                device,
            ])
            .status()
            .expect("failed to run sudo route")
    } else {
        std::process::Command::new("route")
            .args(["-n", "add", "-net", "10.0.0.0/24", "-interface", device])
            .status()
            .expect("failed to run route")
    };
    if !route_status.success() {
        eprintln!("configure_utun: route add failed with {route_status}");
        return false;
    }

    true
}
