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
            .map(|r| r.data().len())
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
#[ignore = "requires root for utun IP configuration"]
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

    let (exit_code, _stdout) = common::run_macho_dynamic_with_utun(
        &binary_data,
        &["/usr/bin/tcp_echo"],
        &cache_result,
        "tcp_echo",
        Some("utun98"),
    );
    assert_eq!(
        exit_code, 0,
        "tcp_echo test failed with exit code {exit_code}"
    );
}

#[test]
#[ignore = "requires root for utun IP configuration"]
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

    let (exit_code, _stdout) = common::run_macho_dynamic_with_utun(
        &binary_data,
        &["/usr/bin/udp_sendrecv"],
        &cache_result,
        "udp_sendrecv",
        Some("utun97"),
    );
    assert_eq!(
        exit_code, 0,
        "udp_sendrecv test failed with exit code {exit_code}"
    );
}

#[test]
#[allow(clippy::cast_precision_loss)]
fn test_unix_stream() {
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

    let bin_path = common::compile_macho_dynamic("./tests/unix_stream.c", "unix_stream");
    let binary_data = std::fs::read(&bin_path).expect("read binary");

    let (exit_code, _stdout) = common::run_macho_dynamic(
        &binary_data,
        &["/usr/bin/unix_stream"],
        &cache_result,
        "unix_stream",
    );
    assert_eq!(
        exit_code, 0,
        "unix_stream test failed with exit code {exit_code}"
    );
}

#[test]
#[allow(clippy::cast_precision_loss)]
fn test_socketpair() {
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

    let bin_path = common::compile_macho_dynamic("./tests/socketpair.c", "socketpair_test");
    let binary_data = std::fs::read(&bin_path).expect("read binary");

    let (exit_code, _stdout) = common::run_macho_dynamic(
        &binary_data,
        &["/usr/bin/socketpair_test"],
        &cache_result,
        "socketpair_test",
    );
    assert_eq!(
        exit_code, 0,
        "socketpair test failed with exit code {exit_code}"
    );
}

#[test]
#[allow(clippy::cast_precision_loss)]
fn test_select() {
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

    let bin_path = common::compile_macho_dynamic("./tests/select.c", "select_test");
    let binary_data = std::fs::read(&bin_path).expect("read binary");

    let (exit_code, _stdout) = common::run_macho_dynamic(
        &binary_data,
        &["/usr/bin/select_test"],
        &cache_result,
        "select_test",
    );
    assert_eq!(
        exit_code, 0,
        "select test failed with exit code {exit_code}"
    );
}

#[test]
#[allow(clippy::cast_precision_loss)]
fn test_poll() {
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

    let bin_path = common::compile_macho_dynamic("./tests/poll.c", "poll_test");
    let binary_data = std::fs::read(&bin_path).expect("read binary");

    let (exit_code, _stdout) = common::run_macho_dynamic(
        &binary_data,
        &["/usr/bin/poll_test"],
        &cache_result,
        "poll_test",
    );
    assert_eq!(exit_code, 0, "poll test failed with exit code {exit_code}");
}

#[test]
#[allow(clippy::cast_precision_loss)]
fn test_kqueue() {
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

    let bin_path = common::compile_macho_dynamic("./tests/kqueue.c", "kqueue_test");
    let binary_data = std::fs::read(&bin_path).expect("read binary");

    let (exit_code, _stdout) = common::run_macho_dynamic(
        &binary_data,
        &["/usr/bin/kqueue_test"],
        &cache_result,
        "kqueue_test",
    );
    assert_eq!(
        exit_code, 0,
        "kqueue test failed with exit code {exit_code}"
    );
}

#[test]
#[ignore = "requires root for utun IP configuration"]
#[allow(clippy::cast_precision_loss)]
fn test_select_socket() {
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

    let bin_path = common::compile_macho_dynamic("./tests/select_socket.c", "select_socket_test");
    let binary_data = std::fs::read(&bin_path).expect("read binary");

    let (exit_code, _stdout) = common::run_macho_dynamic_with_utun(
        &binary_data,
        &["/usr/bin/select_socket_test"],
        &cache_result,
        "select_socket_test",
        Some("utun96"),
    );
    assert_eq!(
        exit_code, 0,
        "select_socket test failed with exit code {exit_code}"
    );
}

#[test]
#[allow(clippy::cast_precision_loss)]
fn test_getentropy() {
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

    let bin_path = common::compile_macho_dynamic("./tests/getentropy.c", "getentropy_test");
    let binary_data = std::fs::read(&bin_path).expect("read binary");

    let (exit_code, _stdout) = common::run_macho_dynamic(
        &binary_data,
        &["/usr/bin/getentropy_test"],
        &cache_result,
        "getentropy_test",
    );
    assert_eq!(
        exit_code, 0,
        "getentropy test failed with exit code {exit_code}"
    );
}

#[test]
#[allow(clippy::cast_precision_loss)]
fn test_gettimeofday() {
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

    let bin_path = common::compile_macho_dynamic("./tests/gettimeofday.c", "gettimeofday_test");
    let binary_data = std::fs::read(&bin_path).expect("read binary");

    let (exit_code, _stdout) = common::run_macho_dynamic(
        &binary_data,
        &["/usr/bin/gettimeofday_test"],
        &cache_result,
        "gettimeofday_test",
    );
    assert_eq!(
        exit_code, 0,
        "gettimeofday test failed with exit code {exit_code}"
    );
}

#[test]
#[allow(clippy::cast_precision_loss)]
fn test_readv_writev() {
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

    let bin_path = common::compile_macho_dynamic("./tests/readv_writev.c", "readv_writev_test");
    let binary_data = std::fs::read(&bin_path).expect("read binary");

    let (exit_code, _stdout) = common::run_macho_dynamic(
        &binary_data,
        &["/usr/bin/readv_writev_test"],
        &cache_result,
        "readv_writev_test",
    );
    assert_eq!(
        exit_code, 0,
        "readv_writev test failed with exit code {exit_code}"
    );
}

#[test]
#[allow(clippy::cast_precision_loss)]
fn test_getcwd() {
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

    let bin_path = common::compile_macho_dynamic("./tests/getcwd.c", "getcwd_test");
    let binary_data = std::fs::read(&bin_path).expect("read binary");

    let (exit_code, _stdout) = common::run_macho_dynamic(
        &binary_data,
        &["/usr/bin/getcwd_test"],
        &cache_result,
        "getcwd_test",
    );
    assert_eq!(
        exit_code, 0,
        "getcwd test failed with exit code {exit_code}"
    );
}

#[test]
#[allow(clippy::cast_precision_loss)]
fn test_mach_absolute_time() {
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

    let bin_path =
        common::compile_macho_dynamic("./tests/mach_absolute_time.c", "mach_absolute_time_test");
    let binary_data = std::fs::read(&bin_path).expect("read binary");

    let (exit_code, _stdout) = common::run_macho_dynamic(
        &binary_data,
        &["/usr/bin/mach_absolute_time_test"],
        &cache_result,
        "mach_absolute_time_test",
    );
    assert_eq!(
        exit_code, 0,
        "mach_absolute_time test failed with exit code {exit_code}"
    );
}

#[test]
#[allow(clippy::cast_precision_loss)]
fn test_mach_timebase_info() {
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

    let bin_path =
        common::compile_macho_dynamic("./tests/mach_timebase_info.c", "mach_timebase_info_test");
    let binary_data = std::fs::read(&bin_path).expect("read binary");

    let (exit_code, _stdout) = common::run_macho_dynamic(
        &binary_data,
        &["/usr/bin/mach_timebase_info_test"],
        &cache_result,
        "mach_timebase_info_test",
    );
    assert_eq!(
        exit_code, 0,
        "mach_timebase_info test failed with exit code {exit_code}"
    );
}

#[test]
#[allow(clippy::cast_precision_loss)]
fn test_mach_port_deallocate() {
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

    let bin_path = common::compile_macho_dynamic(
        "./tests/mach_port_deallocate.c",
        "mach_port_deallocate_test",
    );
    let binary_data = std::fs::read(&bin_path).expect("read binary");

    let (exit_code, _stdout) = common::run_macho_dynamic(
        &binary_data,
        &["/usr/bin/mach_port_deallocate_test"],
        &cache_result,
        "mach_port_deallocate_test",
    );
    assert_eq!(
        exit_code, 0,
        "mach_port_deallocate test failed with exit code {exit_code}"
    );
}

#[test]
#[allow(clippy::cast_precision_loss)]
fn test_mach_semaphore() {
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

    let bin_path = common::compile_macho_dynamic("./tests/mach_semaphore.c", "mach_semaphore_test");
    let binary_data = std::fs::read(&bin_path).expect("read binary");

    let (exit_code, _stdout) = common::run_macho_dynamic(
        &binary_data,
        &["/usr/bin/mach_semaphore_test"],
        &cache_result,
        "mach_semaphore_test",
    );
    assert_eq!(
        exit_code, 0,
        "mach_semaphore test failed with exit code {exit_code}"
    );
}

/// Attempt to run the real `/usr/bin/true` system binary under litebox.
///
/// This is an exploratory test: `/usr/bin/true` has zero imports and simply
/// returns 0, making it the simplest possible real macOS binary to attempt.
#[test]
#[allow(clippy::cast_precision_loss)]
fn test_run_system_true() {
    let true_path = std::path::Path::new("/usr/bin/true");
    assert!(true_path.exists(), "/usr/bin/true not found on this system");

    let cache_dir = std::path::Path::new("/System/Cryptexes/OS/System/Library/dyld");
    assert!(
        cache_dir.exists(),
        "Shared cache not found at {}",
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

    eprintln!(
        "Loaded {} cache regions ({:.1} MB total)",
        cache_result.regions.len(),
        cache_result
            .regions
            .iter()
            .map(|r| r.data().len())
            .sum::<usize>() as f64
            / (1024.0 * 1024.0),
    );

    // Read the real system binary (fat Mach-O with arm64e slice)
    let binary_data = std::fs::read(true_path).expect("read /usr/bin/true");
    eprintln!("Read /usr/bin/true: {} bytes", binary_data.len());

    let (exit_code, _stdout) =
        common::run_macho_dynamic(&binary_data, &["/usr/bin/true"], &cache_result, "true");
    assert_eq!(exit_code, 0, "/usr/bin/true exited with code {exit_code}");
}

/// Attempt to run the real `/bin/echo` system binary under litebox.
///
/// `/bin/echo` has ~10 imports and calls write(2) to produce output.
/// We verify it exits with code 0.
#[test]
#[allow(clippy::cast_precision_loss)]
fn test_run_system_echo() {
    let echo_path = std::path::Path::new("/bin/echo");
    assert!(echo_path.exists(), "/bin/echo not found on this system");

    let cache_dir = std::path::Path::new("/System/Cryptexes/OS/System/Library/dyld");
    assert!(
        cache_dir.exists(),
        "Shared cache not found at {}",
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

    let binary_data = std::fs::read(echo_path).expect("read /bin/echo");
    eprintln!("Read /bin/echo: {} bytes", binary_data.len());

    let (exit_code, _stdout) = common::run_macho_dynamic(
        &binary_data,
        &["/bin/echo", "hello", "litebox"],
        &cache_result,
        "echo",
    );
    assert_eq!(exit_code, 0, "/bin/echo exited with code {exit_code}");
}

/// Attempt to run the real `/bin/ls` system binary under litebox.
///
/// `/bin/ls` has many imports including FTS, ACL, ncurses, etc.
/// This is an exploratory test to see how far we get.
#[test]
#[allow(clippy::cast_precision_loss)]
fn test_run_system_ls() {
    let ls_path = std::path::Path::new("/bin/ls");
    assert!(ls_path.exists(), "/bin/ls not found on this system");

    let cache_dir = std::path::Path::new("/System/Cryptexes/OS/System/Library/dyld");
    assert!(
        cache_dir.exists(),
        "Shared cache not found at {}",
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

    let binary_data = std::fs::read(ls_path).expect("read /bin/ls");
    eprintln!("Read /bin/ls: {} bytes", binary_data.len());

    // Try to list /tmp — a directory we create in the in-mem FS.
    let (exit_code, _stdout) =
        common::run_macho_dynamic(&binary_data, &["/bin/ls", "/tmp"], &cache_result, "ls");
    // ls /tmp on an empty dir should exit 0
    eprintln!("/bin/ls exited with code {exit_code}");
    assert_eq!(exit_code, 0, "/bin/ls /tmp exited with code {exit_code}");
}
