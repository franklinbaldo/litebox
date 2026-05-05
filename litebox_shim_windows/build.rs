// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::error::Error;
use std::ffi::{CStr, c_char};
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").ok_or("OUT_DIR is not set")?);
    fs::write(out_dir.join("nt_sysno.rs"), generate_nt_sysno()?)?;
    Ok(())
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn generate_nt_sysno() -> Result<String, Box<dyn Error>> {
    unsafe extern "system" {
        fn GetModuleHandleA(module_name: *const c_char) -> *const u8;
    }

    // SAFETY: This is a static NUL-terminated string, and GetModuleHandleA does not retain it.
    let ntdll = unsafe { GetModuleHandleA(c"ntdll.dll".as_ptr()) };
    if ntdll.is_null() {
        return Err("ntdll.dll is not loaded in the build process".into());
    }

    let syscalls = ntdll_syscalls(ntdll)?;
    if !syscalls.contains_key("NtTerminateProcess") {
        return Err("NtTerminateProcess syscall stub was not found in ntdll.dll".into());
    }

    Ok(render_nt_sysno(&syscalls))
}

#[cfg(not(all(windows, target_arch = "x86_64")))]
fn generate_nt_sysno() -> Result<String, Box<dyn Error>> {
    Ok(render_nt_sysno(&BTreeMap::new()))
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn ntdll_syscalls(ntdll: *const u8) -> Result<BTreeMap<String, u32>, Box<dyn Error>> {
    let pe_offset = read_u32(ntdll, 0x3c)?;
    let pe_offset = usize::try_from(pe_offset)?;
    if read_u32(ntdll, pe_offset)? != u32::from_le_bytes(*b"PE\0\0") {
        return Err("ntdll.dll has an invalid PE signature".into());
    }

    let optional_header_offset = pe_offset
        .checked_add(4 + 20)
        .ok_or("ntdll.dll PE header offset overflow")?;
    if read_u16(ntdll, optional_header_offset)? != 0x20b {
        return Err("ntdll.dll is not a PE32+ image".into());
    }

    let export_directory_rva = read_u32(ntdll, optional_header_offset + 112)?;
    let export_directory_size = read_u32(ntdll, optional_header_offset + 116)?;
    let export_directory_offset = usize::try_from(export_directory_rva)?;
    let export_directory_end = export_directory_rva
        .checked_add(export_directory_size)
        .ok_or("ntdll.dll export directory overflow")?;

    let number_of_names = usize::try_from(read_u32(ntdll, export_directory_offset + 24)?)?;
    let function_table_offset = usize::try_from(read_u32(ntdll, export_directory_offset + 28)?)?;
    let name_table_offset = usize::try_from(read_u32(ntdll, export_directory_offset + 32)?)?;
    let ordinal_table_offset = usize::try_from(read_u32(ntdll, export_directory_offset + 36)?)?;

    let mut syscalls = BTreeMap::new();
    for index in 0..number_of_names {
        let exported_name_offset = read_u32(ntdll, name_table_offset + index * 4)?;
        let name = read_c_string(ntdll, usize::try_from(exported_name_offset)?)?;
        if !name.starts_with("Nt") {
            continue;
        }

        let ordinal = usize::from(read_u16(ntdll, ordinal_table_offset + index * 2)?);
        let function_offset = read_u32(ntdll, function_table_offset + ordinal * 4)?;
        if (export_directory_rva..export_directory_end).contains(&function_offset) {
            continue;
        }

        let stub = read_slice(ntdll, usize::try_from(function_offset)?, 32)?;
        if let Some(syscall_number) = decode_syscall_number(stub) {
            syscalls.insert(name.to_owned(), syscall_number);
        }
    }

    Ok(syscalls)
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn decode_syscall_number(stub: &[u8]) -> Option<u32> {
    let syscall_offset = stub.windows(2).position(|bytes| bytes == [0x0f, 0x05])?;
    let mov_eax_offset = stub[..syscall_offset]
        .iter()
        .position(|byte| *byte == 0xb8)?;
    Some(u32::from_le_bytes(
        stub[mov_eax_offset + 1..mov_eax_offset + 5]
            .try_into()
            .ok()?,
    ))
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn read_u16(base: *const u8, offset: usize) -> Result<u16, Box<dyn Error>> {
    let bytes = read_slice(base, offset, 2)?;
    Ok(u16::from_le_bytes(bytes.try_into()?))
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn read_u32(base: *const u8, offset: usize) -> Result<u32, Box<dyn Error>> {
    let bytes = read_slice(base, offset, 4)?;
    Ok(u32::from_le_bytes(bytes.try_into()?))
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn read_c_string(base: *const u8, offset: usize) -> Result<&'static str, Box<dyn Error>> {
    // SAFETY: Export names are NUL-terminated strings inside the loaded ntdll image.
    let c_string = unsafe { CStr::from_ptr(base.add(offset).cast()) };
    Ok(c_string.to_str()?)
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn read_slice(base: *const u8, offset: usize, len: usize) -> Result<&'static [u8], Box<dyn Error>> {
    let end = offset
        .checked_add(len)
        .ok_or("ntdll.dll RVA range overflow")?;
    if end < offset {
        return Err("ntdll.dll RVA range overflow".into());
    }

    // SAFETY: The generator only reads headers, export tables, names, and syscall stubs from the loaded ntdll image.
    Ok(unsafe { std::slice::from_raw_parts(base.add(offset), len) })
}

fn render_nt_sysno(syscalls: &BTreeMap<String, u32>) -> String {
    let mut sysno_to_name = BTreeMap::<u32, &str>::new();
    for (name, number) in syscalls {
        sysno_to_name.entry(*number).or_insert(name);
    }
    if let Some(number) = syscalls.get("NtTerminateProcess") {
        sysno_to_name.insert(*number, "NtTerminateProcess");
    }

    let used_from_raw = sysno_to_name.values().copied().collect::<BTreeSet<_>>();
    let mut output = String::from(
        "// @generated by litebox_shim_windows/build.rs\n\n\
         #[allow(clippy::enum_variant_names)]\n\
         #[derive(Clone, Copy, Debug, Eq, PartialEq)]\n\
         pub(crate) enum NtSysno {\n",
    );

    for name in syscalls.keys() {
        let _ = writeln!(output, "    {name},");
    }

    output.push_str(
        "}\n\n\
         impl NtSysno {\n\
             pub(crate) fn from_raw(syscall_number: usize) -> Option<Self> {\n\
                 let syscall_number = u32::try_from(syscall_number).ok()?;\n\
                 match syscall_number {\n",
    );

    for (number, name) in &sysno_to_name {
        let _ = writeln!(output, "            {number:#x} => Some(Self::{name}),");
    }

    output.push_str(
        "            _ => None,\n\
                 }\n\
             }\n\
         }\n",
    );

    for name in syscalls.keys() {
        if !used_from_raw.contains(name.as_str()) {
            let _ = writeln!(output, "const _: Option<NtSysno> = Some(NtSysno::{name});");
        }
    }

    output
}
