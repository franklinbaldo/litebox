// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use anyhow::{Result, bail};
use fs_err as fs;
use std::collections::HashMap;
use std::collections::HashSet;

const PR38_ADDED_PREFIXES: &[&str] = &[
    "tools/litebox_desktop_host/",
    "tools/litebox_desktop_transport/",
    "tools/litebox_launcher/",
    "tools/desktop_acceptance/",
    "examples/desktop_pipe_probe/",
    "examples/linux_game/",
    "examples/sdl_probe/",
    "litebox_runner_linux_on_windows_userland/examples/",
];

const PR38_ADDED_EXACT_FILES: &[&str] = &[
    "litebox_runner_linux_on_windows_userland/tests/stdio.rs",
    "litebox_shim_linux/src/host_pipe.rs",
];

fn is_pr38_added_file(path: &std::path::Path) -> bool {
    let normalized = path.to_string_lossy().replace('\\', "/");
    PR38_ADDED_PREFIXES
        .iter()
        .any(|prefix| normalized.starts_with(prefix))
        || PR38_ADDED_EXACT_FILES
            .iter()
            .any(|exact| normalized == *exact)
}

fn is_valid_contributor_header(ext: &str, text: &str) -> bool {
    match ext {
        "rs" | "c" | "h" | "js" => {
            if let Some(rest) = text.strip_prefix("// Copyright (c) ") {
                if let Some((holder, after_holder)) = rest.split_once('\n') {
                    let trimmed = holder.trim().trim_end_matches('.');
                    if trimmed == "franklinbaldo"
                        && after_holder.starts_with("// Licensed under the MIT license.\n\n")
                    {
                        return true;
                    }
                }
            }
        }
        "py" => {
            if let Some(rest) = text.strip_prefix("#!/usr/bin/env python3\n\n# Copyright (c) ") {
                if let Some((holder, after_holder)) = rest.split_once('\n') {
                    let trimmed = holder.trim().trim_end_matches('.');
                    if trimmed == "franklinbaldo"
                        && after_holder.starts_with("# Licensed under the MIT license.\n")
                    {
                        return true;
                    }
                }
            }
        }
        "sh" => {
            if let Some(rest) = text.strip_prefix("#! /bin/bash\n\n# Copyright (c) ") {
                if let Some((holder, after_holder)) = rest.split_once('\n') {
                    let trimmed = holder.trim().trim_end_matches('.');
                    if trimmed == "franklinbaldo"
                        && after_holder.starts_with("# Licensed under the MIT license.\n\n")
                    {
                        return true;
                    }
                }
            }
        }
        _ => {}
    }
    false
}

fn validate_copyright_content(
    file: &std::path::Path,
    ext: &str,
    data: &[u8],
    expected: &str,
) -> bool {
    if expected.is_empty() {
        return true;
    }
    if data.starts_with(expected.as_bytes()) {
        return true;
    }
    if !is_pr38_added_file(file) {
        return false;
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return false;
    };
    is_valid_contributor_header(ext, text)
}

fn has_valid_copyright_header(file: &std::path::Path, ext: &str, expected: &str) -> Result<bool> {
    if expected.is_empty() {
        return Ok(true);
    }
    let data = fs::read(file)?;
    Ok(validate_copyright_content(file, ext, &data, expected))
}

#[test]
#[expect(clippy::needless_continue, reason = "consistency")]
fn copyright_header() -> Result<()> {
    let all_source_files = crate::all_source_files()?;
    let mut errors: Vec<String> = Vec::new();

    let required_headers: HashMap<&str, &str> = HEADERS_REQUIRED_PREFIX.iter().copied().collect();
    let skipped_files: HashSet<std::path::PathBuf> =
        SKIP_FILES.iter().map(std::path::PathBuf::from).collect();

    let auto_include_headers = std::env::var("AUTO_INCLUDE_HEADERS").is_ok();

    for file in all_source_files {
        if skipped_files.contains(&file) {
            continue;
        }
        let Some(ext) = file.extension() else {
            errors.push(format!("extension-less file {file:?}"));
            continue;
        };
        let ext = ext.to_str().unwrap();
        let Some(expected) = required_headers.get(ext) else {
            errors.push(format!(
                "unknown header requirements for .{ext} files (e.g., {file:?})"
            ));
            continue;
        };
        if !has_valid_copyright_header(&file, ext, expected)? {
            if auto_include_headers {
                errors.push(format!("auto-including header into {file:?}"));
                let data = fs::read_to_string(&file).unwrap();
                if data.contains(/*C*/ "opyright") || data.contains(/*L*/ "icensed") {
                    errors.push(format!("!!! Refusing to auto-include header for {file:?} since it already mentions licensing"));
                    continue;
                }
                let data = String::from(*expected) + &data;
                fs::write(&file, &data).unwrap();
            } else {
                errors.push(format!(
                    "expected prefix {expected:?} missing from {file:?}"
                ));
            }
            continue;
        }
        // Successfully matched on `file`
    }

    if !errors.is_empty() {
        let help = "Help: re-run this test with AUTO_INCLUDE_HEADERS env variable to automatically include headers wherever possible.";
        bail!(
            "Copyright headers test failed:\n\n{}\n\n{}",
            errors.join("\n\n"),
            help
        );
    }

    Ok(())
}

// Each particular file type has a common prefix, these prefixes are defined here. Please do NOT
// modify this unless you have a very compelling reason to.
const HEADERS_REQUIRED_PREFIX: &[(&str, &str)] = &[
    (
        "rs",
        "// Copyright (c) Microsoft Corporation.\n// Licensed under the MIT license.\n\n",
    ),
    (
        "h",
        "// Copyright (c) Microsoft Corporation.\n// Licensed under the MIT license.\n\n",
    ),
    (
        "c",
        "// Copyright (c) Microsoft Corporation.\n// Licensed under the MIT license.\n\n",
    ),
    (
        "sh",
        "#! /bin/bash\n\n# Copyright (c) Microsoft Corporation.\n# Licensed under the MIT license.\n\n",
    ),
    (
        "S",
        "/* Copyright (c) Microsoft Corporation.\n   Licensed under the MIT license. */\n\n",
    ),
    (
        "html",
        "<!-- Copyright (c) Microsoft Corporation.\n     Licensed under the MIT license. -->\n",
    ),
    (
        "css",
        "/* Copyright (c) Microsoft Corporation.\n   Licensed under the MIT license. */\n",
    ),
    (
        "js",
        "// Copyright (c) Microsoft Corporation.\n// Licensed under the MIT license.\n\n",
    ),
    (
        "py",
        "#!/usr/bin/env python3\n\n# Copyright (c) Microsoft Corporation.\n# Licensed under the MIT license.\n",
    ),
    ("2", ""),
    ("6", ""),
    ("elf", ""),
    ("hooked", ""),
    ("json", ""),
    ("ld", ""),
    ("lock", ""),
    ("md", ""),
    ("patch", ""),
    ("png", ""),
    ("ps1", ""),
    ("snap", ""),
    ("so", ""),
    ("svg", ""),
    ("tar", ""),
    ("toml", ""),
    ("txt", ""),
];

// Skipped files have their own custom requirements on why they are not checked via the regular
// tests. Please do NOT modify this unless you have a very compelling reason to.
const SKIP_FILES: &[&str] = &[
    "LICENSE",
    "litebox/src/sync/mutex.rs",
    "litebox/src/sync/rwlock.rs",
    "litebox_runner_linux_on_windows_userland/tests/test-bins/hello_exec_nolibc",
    "litebox_runner_linux_on_windows_userland/tests/test-bins/hello_thread",
    "litebox_runner_linux_on_windows_userland/tests/test-bins/hello_thread_static",
    "litebox_runner_linux_on_windows_userland/tests/test-bins/hello_world_dyn",
    "litebox_runner_linux_on_windows_userland/tests/test-bins/hello_world_static",
    "litebox_runner_linux_on_windows_userland/tests/test-bins/thread_static",
    "litebox_syscall_rewriter/tests/hello",
    "litebox_syscall_rewriter/tests/hello-32",
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const RS_EXPECTED: &str =
        "// Copyright (c) Microsoft Corporation.\n// Licensed under the MIT license.\n\n";
    const PY_EXPECTED: &str = "#!/usr/bin/env python3\n\n# Copyright (c) Microsoft Corporation.\n# Licensed under the MIT license.\n";

    #[test]
    fn test_accepts_upstream_microsoft_header() {
        let upstream = Path::new("litebox/src/lib.rs");
        let content = b"// Copyright (c) Microsoft Corporation.\n// Licensed under the MIT license.\n\npub fn foo() {}";
        assert!(validate_copyright_content(
            upstream,
            "rs",
            content,
            RS_EXPECTED
        ));
    }

    #[test]
    fn test_rejects_alternative_holder_on_upstream_file() {
        let upstream = Path::new("litebox/src/lib.rs");
        let content =
            b"// Copyright (c) franklinbaldo.\n// Licensed under the MIT license.\n\npub fn foo() {}";
        assert!(!validate_copyright_content(
            upstream,
            "rs",
            content,
            RS_EXPECTED
        ));
    }

    #[test]
    fn test_accepts_valid_franklinbaldo_on_pr38_files() {
        let pr38_host = Path::new("tools/litebox_desktop_host/src/main.rs");
        let content =
            b"// Copyright (c) franklinbaldo.\n// Licensed under the MIT license.\n\nfn main() {}";
        assert!(validate_copyright_content(
            pr38_host,
            "rs",
            content,
            RS_EXPECTED
        ));

        let pr38_host_pipe = Path::new("litebox_shim_linux/src/host_pipe.rs");
        assert!(validate_copyright_content(
            pr38_host_pipe,
            "rs",
            content,
            RS_EXPECTED
        ));

        let pr38_stdio = Path::new("litebox_runner_linux_on_windows_userland/tests/stdio.rs");
        assert!(validate_copyright_content(
            pr38_stdio,
            "rs",
            content,
            RS_EXPECTED
        ));

        let pr38_py = Path::new("examples/desktop_pipe_probe/run.py");
        let py_content = b"#!/usr/bin/env python3\n\n# Copyright (c) franklinbaldo.\n# Licensed under the MIT license.\nimport sys";
        assert!(validate_copyright_content(
            pr38_py,
            "py",
            py_content,
            PY_EXPECTED
        ));
    }

    #[test]
    fn test_rejects_empty_holder_on_pr38_file() {
        let pr38_file = Path::new("tools/litebox_desktop_host/src/main.rs");
        let empty_holder =
            b"// Copyright (c) .\n// Licensed under the MIT license.\n\nfn main() {}";
        assert!(!validate_copyright_content(
            pr38_file,
            "rs",
            empty_holder,
            RS_EXPECTED
        ));

        let no_holder = b"// Copyright (c) \n// Licensed under the MIT license.\n\nfn main() {}";
        assert!(!validate_copyright_content(
            pr38_file,
            "rs",
            no_holder,
            RS_EXPECTED
        ));
    }

    #[test]
    fn test_rejects_arbitrary_holder_on_pr38_file() {
        let pr38_file = Path::new("tools/litebox_desktop_host/src/main.rs");
        let arbitrary_holder =
            b"// Copyright (c) SomeoneElse.\n// Licensed under the MIT license.\n\nfn main() {}";
        assert!(!validate_copyright_content(
            pr38_file,
            "rs",
            arbitrary_holder,
            RS_EXPECTED
        ));
    }

    #[test]
    fn test_rejects_missing_or_invalid_license_line() {
        let pr38_file = Path::new("tools/litebox_desktop_host/src/main.rs");
        let bad_license =
            b"// Copyright (c) franklinbaldo.\n// Licensed under Apache-2.0.\n\nfn main() {}";
        assert!(!validate_copyright_content(
            pr38_file,
            "rs",
            bad_license,
            RS_EXPECTED
        ));
    }
}
