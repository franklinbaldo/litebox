// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

mod common;

#[test]
fn test_hello_nolibc_asm() {
    let bin_path = common::assemble_macho("./tests/hello_nolibc.s", "hello_nolibc_asm");
    let rewritten = common::rewrite_macho(&bin_path);
    let (exit_code, _stdout) = common::run_macho_binary(&rewritten, &["hello_nolibc_asm"]);
    assert_eq!(exit_code, 0, "process exited with non-zero code");
}

#[test]
fn test_hello_nolibc_c() {
    let bin_path = common::compile_macho_nolibc("./tests/hello_nolibc.c", "hello_nolibc_c");
    let rewritten = common::rewrite_macho(&bin_path);
    let (exit_code, _stdout) = common::run_macho_binary(&rewritten, &["hello_nolibc_c"]);
    assert_eq!(exit_code, 0, "process exited with non-zero code");
}

#[test]
fn test_exit_code_42() {
    let bin_path = common::assemble_macho("./tests/exit_42.s", "exit_42_asm");
    let rewritten = common::rewrite_macho(&bin_path);
    let (exit_code, _) = common::run_macho_binary(&rewritten, &["exit_42"]);
    assert_eq!(exit_code, 42, "expected exit code 42, got {exit_code}");
}

#[test]
#[allow(clippy::cast_precision_loss)]
fn test_hello_dynamic() {
    let cache_dir = std::path::Path::new("/System/Cryptexes/OS/System/Library/dyld");
    assert!(
        cache_dir.exists(),
        "Shared cache not found at {}. This test requires macOS with dyld shared cache.",
        cache_dir.display()
    );

    // Parse cache map and collect regions for system dylibs.
    // All addresses from the .map file are UNSLID (the kernel applies an ASLR
    // slide at boot). We map our own copy of the cache at the unslid base
    // (0x180000000) so we don't interfere with the host's slid cache.
    let map_path = cache_dir.join("dyld_shared_cache_arm64e.map");
    let map_text = std::fs::read_to_string(&map_path).unwrap();
    let cache_map = common::shared_cache::CacheMap::parse(&map_text);
    let system_dylibs = cache_map.system_dylib_paths();
    let dylib_refs: Vec<&str> = system_dylibs
        .iter()
        .map(std::string::String::as_str)
        .collect();
    let cache_result = common::shared_cache::collect_regions(cache_dir, &cache_map, &dylib_refs);

    eprintln!(
        "Loaded {} cache regions ({:.1} MB total)",
        cache_result.regions.len(),
        cache_result
            .regions
            .iter()
            .map(|r| r.data.len())
            .sum::<usize>() as f64
            / (1024.0 * 1024.0),
    );

    let bin_path = common::compile_macho_dynamic("./tests/hello.c", "hello_dynamic");
    let binary_data = std::fs::read(&bin_path).expect("read binary");

    // NOTE: We do NOT rewrite the main binary — dynamically linked binaries have
    // no SVC #0x80 instructions. All syscalls go through dyld/libSystem, which get
    // rewritten via install_shared_cache (dylibs) and the mmap-hook (dyld itself).
    let (exit_code, _stdout) = common::run_macho_dynamic(
        &binary_data,
        &["/usr/bin/hello_dynamic", "arg1", "arg2"],
        &cache_result,
        "hello_dynamic",
    );
    assert_eq!(exit_code, 0, "process exited with non-zero code");
}

#[test]
#[allow(clippy::cast_precision_loss)]
fn test_hello_thread() {
    let cache_dir = std::path::Path::new("/System/Cryptexes/OS/System/Library/dyld");
    assert!(
        cache_dir.exists(),
        "Shared cache not found at {}. This test requires macOS with dyld shared cache.",
        cache_dir.display()
    );

    let map_path = cache_dir.join("dyld_shared_cache_arm64e.map");
    let map_text = std::fs::read_to_string(&map_path).unwrap();
    let cache_map = common::shared_cache::CacheMap::parse(&map_text);
    let system_dylibs = cache_map.system_dylib_paths();
    let dylib_refs: Vec<&str> = system_dylibs
        .iter()
        .map(std::string::String::as_str)
        .collect();
    let cache_result = common::shared_cache::collect_regions(cache_dir, &cache_map, &dylib_refs);

    let bin_path = common::compile_macho_dynamic("./tests/thread.c", "hello_thread");
    let binary_data = std::fs::read(&bin_path).expect("read binary");

    let (exit_code, _stdout) = common::run_macho_dynamic(
        &binary_data,
        &["/usr/bin/hello_thread"],
        &cache_result,
        "hello_thread",
    );
    assert_eq!(exit_code, 0, "process exited with non-zero code");
}

#[test]
#[allow(clippy::cast_precision_loss)]
fn test_efault() {
    let cache_dir = std::path::Path::new("/System/Cryptexes/OS/System/Library/dyld");
    assert!(
        cache_dir.exists(),
        "Shared cache not found at {}. This test requires macOS with dyld shared cache.",
        cache_dir.display()
    );

    let map_path = cache_dir.join("dyld_shared_cache_arm64e.map");
    let map_text = std::fs::read_to_string(&map_path).unwrap();
    let cache_map = common::shared_cache::CacheMap::parse(&map_text);
    let system_dylibs = cache_map.system_dylib_paths();
    let dylib_refs: Vec<&str> = system_dylibs
        .iter()
        .map(std::string::String::as_str)
        .collect();
    let cache_result = common::shared_cache::collect_regions(cache_dir, &cache_map, &dylib_refs);

    let bin_path = common::compile_macho_dynamic("./tests/efault.c", "efault");
    let binary_data = std::fs::read(&bin_path).expect("read binary");

    let (exit_code, _stdout) =
        common::run_macho_dynamic(&binary_data, &["/usr/bin/efault"], &cache_result, "efault");
    assert_eq!(exit_code, 0, "process exited with non-zero code");
}

#[test]
#[allow(clippy::cast_precision_loss)]
fn test_signal() {
    let cache_dir = std::path::Path::new("/System/Cryptexes/OS/System/Library/dyld");
    assert!(
        cache_dir.exists(),
        "Shared cache not found at {}. This test requires macOS with dyld shared cache.",
        cache_dir.display()
    );

    let map_path = cache_dir.join("dyld_shared_cache_arm64e.map");
    let map_text = std::fs::read_to_string(&map_path).unwrap();
    let cache_map = common::shared_cache::CacheMap::parse(&map_text);
    let system_dylibs = cache_map.system_dylib_paths();
    let dylib_refs: Vec<&str> = system_dylibs
        .iter()
        .map(std::string::String::as_str)
        .collect();
    let cache_result = common::shared_cache::collect_regions(cache_dir, &cache_map, &dylib_refs);

    let bin_path = common::compile_macho_dynamic("./tests/signal.c", "signal");
    let binary_data = std::fs::read(&bin_path).expect("read binary");

    let (exit_code, _stdout) =
        common::run_macho_dynamic(&binary_data, &["/usr/bin/signal"], &cache_result, "signal");
    assert_eq!(
        exit_code, 0,
        "signal test: process exited with non-zero code (signal handler may have failed)"
    );
}

#[test]
#[allow(clippy::cast_precision_loss)]
fn test_pipe() {
    let cache_dir = std::path::Path::new("/System/Cryptexes/OS/System/Library/dyld");
    assert!(
        cache_dir.exists(),
        "Shared cache not found at {}. This test requires macOS with dyld shared cache.",
        cache_dir.display()
    );

    let map_path = cache_dir.join("dyld_shared_cache_arm64e.map");
    let map_text = std::fs::read_to_string(&map_path).unwrap();
    let cache_map = common::shared_cache::CacheMap::parse(&map_text);
    let system_dylibs = cache_map.system_dylib_paths();
    let dylib_refs: Vec<&str> = system_dylibs
        .iter()
        .map(std::string::String::as_str)
        .collect();
    let cache_result = common::shared_cache::collect_regions(cache_dir, &cache_map, &dylib_refs);

    let bin_path = common::compile_macho_dynamic("./tests/pipe.c", "pipe");
    let binary_data = std::fs::read(&bin_path).expect("read binary");

    let (exit_code, _stdout) =
        common::run_macho_dynamic(&binary_data, &["/usr/bin/pipe"], &cache_result, "pipe");
    assert_eq!(exit_code, 0, "pipe test failed with exit code {exit_code}");
}

#[test]
#[allow(clippy::cast_precision_loss)]
fn test_filesystem() {
    let cache_dir = std::path::Path::new("/System/Cryptexes/OS/System/Library/dyld");
    assert!(
        cache_dir.exists(),
        "Shared cache not found at {}. This test requires macOS with dyld shared cache.",
        cache_dir.display()
    );

    let map_path = cache_dir.join("dyld_shared_cache_arm64e.map");
    let map_text = std::fs::read_to_string(&map_path).unwrap();
    let cache_map = common::shared_cache::CacheMap::parse(&map_text);
    let system_dylibs = cache_map.system_dylib_paths();
    let dylib_refs: Vec<&str> = system_dylibs
        .iter()
        .map(std::string::String::as_str)
        .collect();
    let cache_result = common::shared_cache::collect_regions(cache_dir, &cache_map, &dylib_refs);

    let bin_path = common::compile_macho_dynamic("./tests/filesystem.c", "filesystem");
    let binary_data = std::fs::read(&bin_path).expect("read binary");

    let (exit_code, _stdout) = common::run_macho_dynamic(
        &binary_data,
        &["/usr/bin/filesystem"],
        &cache_result,
        "filesystem",
    );
    assert_eq!(
        exit_code, 0,
        "filesystem test failed with exit code {exit_code}"
    );
}

#[test]
#[allow(clippy::cast_precision_loss)]
fn test_thread_exit() {
    let cache_dir = std::path::Path::new("/System/Cryptexes/OS/System/Library/dyld");
    assert!(
        cache_dir.exists(),
        "Shared cache not found at {}. This test requires macOS with dyld shared cache.",
        cache_dir.display()
    );

    let map_path = cache_dir.join("dyld_shared_cache_arm64e.map");
    let map_text = std::fs::read_to_string(&map_path).unwrap();
    let cache_map = common::shared_cache::CacheMap::parse(&map_text);
    let system_dylibs = cache_map.system_dylib_paths();
    let dylib_refs: Vec<&str> = system_dylibs
        .iter()
        .map(std::string::String::as_str)
        .collect();
    let cache_result = common::shared_cache::collect_regions(cache_dir, &cache_map, &dylib_refs);

    let bin_path = common::compile_macho_dynamic("./tests/thread_exit.c", "thread_exit");
    let binary_data = std::fs::read(&bin_path).expect("read binary");

    let (exit_code, _stdout) = common::run_macho_dynamic(
        &binary_data,
        &["/usr/bin/thread_exit"],
        &cache_result,
        "thread_exit",
    );
    assert_eq!(
        exit_code, 0,
        "thread_exit test failed with exit code {exit_code}"
    );
}

#[test]
#[allow(clippy::cast_precision_loss)]
fn test_tcp_echo() {
    let cache_dir = std::path::Path::new("/System/Cryptexes/OS/System/Library/dyld");
    assert!(
        cache_dir.exists(),
        "Shared cache not found at {}. This test requires macOS with dyld shared cache.",
        cache_dir.display()
    );

    let map_path = cache_dir.join("dyld_shared_cache_arm64e.map");
    let map_text = std::fs::read_to_string(&map_path).unwrap();
    let cache_map = common::shared_cache::CacheMap::parse(&map_text);
    let system_dylibs = cache_map.system_dylib_paths();
    let dylib_refs: Vec<&str> = system_dylibs
        .iter()
        .map(std::string::String::as_str)
        .collect();
    let cache_result = common::shared_cache::collect_regions(cache_dir, &cache_map, &dylib_refs);

    let bin_path = common::compile_macho_dynamic("./tests/tcp_echo.c", "tcp_echo");
    let binary_data = std::fs::read(&bin_path).expect("read binary");

    let (exit_code, _stdout) = common::run_macho_dynamic(
        &binary_data,
        &["/usr/bin/tcp_echo"],
        &cache_result,
        "tcp_echo",
    );
    assert_eq!(
        exit_code, 0,
        "tcp_echo test failed with exit code {exit_code}"
    );
}

#[test]
#[allow(clippy::cast_precision_loss)]
fn test_udp_sendrecv() {
    let cache_dir = std::path::Path::new("/System/Cryptexes/OS/System/Library/dyld");
    assert!(
        cache_dir.exists(),
        "Shared cache not found at {}. This test requires macOS with dyld shared cache.",
        cache_dir.display()
    );

    let map_path = cache_dir.join("dyld_shared_cache_arm64e.map");
    let map_text = std::fs::read_to_string(&map_path).unwrap();
    let cache_map = common::shared_cache::CacheMap::parse(&map_text);
    let system_dylibs = cache_map.system_dylib_paths();
    let dylib_refs: Vec<&str> = system_dylibs
        .iter()
        .map(std::string::String::as_str)
        .collect();
    let cache_result = common::shared_cache::collect_regions(cache_dir, &cache_map, &dylib_refs);

    let bin_path = common::compile_macho_dynamic("./tests/udp_sendrecv.c", "udp_sendrecv");
    let binary_data = std::fs::read(&bin_path).expect("read binary");

    let (exit_code, _stdout) = common::run_macho_dynamic(
        &binary_data,
        &["/usr/bin/udp_sendrecv"],
        &cache_result,
        "udp_sendrecv",
    );
    assert_eq!(
        exit_code, 0,
        "udp_sendrecv test failed with exit code {exit_code}"
    );
}
