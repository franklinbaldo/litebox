// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::mem::size_of;

use alloc::string::String;
use litebox::fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry};
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox_common_windows::nt_status::NtStatus;
use litebox_platform_multiplex::Platform;
use zerocopy::{FromBytes, Immutable};

use crate::loader::nt_types::UnicodeString;
use crate::{Handle, NtShimFS, Task, insert_raw_handle, raw_handle_entry, remove_raw_handle};

const KNOWN_OBJECT_DIRECTORIES: &[&str] = &[
    r"\",
    r"\??",
    r"\BaseNamedObjects",
    r"\Device",
    r"\Global??",
    r"\KnownDlls",
    r"\KnownDlls32",
    r"\RPC Control",
    r"\Sessions",
];

const KNOWN_SYMBOLIC_LINKS: &[(&str, &str)] = &[
    (r"\KnownDlls\KnownDllPath", r"C:\Windows\System32"),
    (r"\KnownDlls32\KnownDllPath", r"C:\Windows\SysWOW64"),
    (r"\??\C:", r"\Device\HarddiskVolume1"),
    (r"\Global??\C:", r"\Device\HarddiskVolume1"),
    (r"\??\NUL", r"\Device\Null"),
    (r"\Global??\NUL", r"\Device\Null"),
];

pub(crate) struct ObjectDirectorySubsystem;

impl FdEnabledSubsystem for ObjectDirectorySubsystem {
    type Entry = ObjectDirectoryObject;
}

impl FdEnabledSubsystemEntry for ObjectDirectoryObject {}

pub(crate) struct ObjectDirectoryObject {
    path: String,
}

impl ObjectDirectoryObject {
    pub(crate) fn path(&self) -> &str {
        &self.path
    }
}

pub(crate) struct SymbolicLinkSubsystem;

impl FdEnabledSubsystem for SymbolicLinkSubsystem {
    type Entry = SymbolicLinkObject;
}

impl FdEnabledSubsystemEntry for SymbolicLinkObject {}

pub(crate) struct SymbolicLinkObject {
    path: String,
    target: String,
}

impl SymbolicLinkObject {
    pub(crate) fn path(&self) -> &str {
        &self.path
    }

    pub(crate) fn target(&self) -> &str {
        &self.target
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable)]
pub(crate) struct ObjectAttributes {
    pub(crate) length: u32,
    pub(crate) root_directory: Handle,
    pub(crate) object_name: usize,
    pub(crate) attributes: u32,
    pub(crate) security_descriptor: usize,
    pub(crate) security_quality_of_service: usize,
}

pub(crate) fn read_object_attributes(
    object_attributes: <Platform as litebox::platform::RawPointerProvider>::RawConstPointer<
        ObjectAttributes,
    >,
) -> Result<ObjectAttributes, NtStatus> {
    let Some(object_attributes) = object_attributes.read_at_offset(0) else {
        return Err(NtStatus::ACCESS_VIOLATION);
    };
    if object_attributes.length as usize != size_of::<ObjectAttributes>() {
        return Err(NtStatus::INVALID_PARAMETER);
    }
    Ok(object_attributes)
}

pub(crate) fn read_unicode_string(unicode_string: usize) -> Result<String, NtStatus> {
    let unicode_string = <Platform as litebox::platform::RawPointerProvider>::RawConstPointer::<
        UnicodeString,
    >::from_usize(unicode_string);
    read_unicode_string_pointer(unicode_string)
}

pub(crate) fn read_unicode_string_pointer(
    unicode_string: <Platform as litebox::platform::RawPointerProvider>::RawConstPointer<
        UnicodeString,
    >,
) -> Result<String, NtStatus> {
    let Some(unicode_string) = unicode_string.read_at_offset(0) else {
        return Err(NtStatus::ACCESS_VIOLATION);
    };
    if unicode_string.length % 2 != 0 {
        return Err(NtStatus::INVALID_PARAMETER);
    }
    if unicode_string.length == 0 {
        return Ok(String::new());
    }
    if unicode_string.buffer == 0 {
        return Err(NtStatus::ACCESS_VIOLATION);
    }

    let chars = usize::from(unicode_string.length / 2);
    let buffer =
        <Platform as litebox::platform::RawPointerProvider>::RawConstPointer::<u16>::from_usize(
            unicode_string.buffer,
        );
    let mut string = String::new();
    let mut index = 0;
    while index < chars {
        let offset = isize::try_from(index).expect("UNICODE_STRING length fits in isize");
        let Some(unit) = buffer.read_at_offset(offset) else {
            return Err(NtStatus::ACCESS_VIOLATION);
        };
        if (0xd800..=0xdbff).contains(&unit) && index + 1 < chars {
            let next_offset =
                isize::try_from(index + 1).expect("UNICODE_STRING length fits in isize");
            let Some(next_unit) = buffer.read_at_offset(next_offset) else {
                return Err(NtStatus::ACCESS_VIOLATION);
            };
            if (0xdc00..=0xdfff).contains(&next_unit) {
                let high = u32::from(unit) - 0xd800;
                let low = u32::from(next_unit) - 0xdc00;
                if let Some(ch) = char::from_u32(0x1_0000 + ((high << 10) | low)) {
                    string.push(ch);
                    index += 2;
                    continue;
                }
            }
        }
        string.push(char::from_u32(u32::from(unit)).unwrap_or(char::REPLACEMENT_CHARACTER));
        index += 1;
    }
    Ok(string)
}

impl<FS: NtShimFS> Task<FS> {
    pub(crate) fn handle_nt_open_directory_object(
        &self,
        directory_handle: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<
            Handle,
        >,
        desired_access: u32,
        object_attributes: Option<
            <Platform as litebox::platform::RawPointerProvider>::RawConstPointer<ObjectAttributes>,
        >,
    ) -> NtStatus {
        let Some(object_attributes) = object_attributes else {
            return NtStatus::INVALID_PARAMETER;
        };
        let object_attributes = match read_object_attributes(object_attributes) {
            Ok(object_attributes) => object_attributes,
            Err(status) => return status,
        };
        if object_attributes.object_name == 0 {
            return NtStatus::INVALID_PARAMETER;
        }

        let name = match read_unicode_string(object_attributes.object_name) {
            Ok(name) => name,
            Err(status) => return status,
        };
        let path = match self.resolve_object_path(object_attributes.root_directory, &name) {
            Ok(path) => path,
            Err(status) => return status,
        };
        if !is_known_object_directory(&path) {
            return NtStatus::OBJECT_NAME_NOT_FOUND;
        }

        let mut descriptor_table = self.global.litebox.descriptor_table_mut();
        let typed = descriptor_table
            .insert::<ObjectDirectorySubsystem>(ObjectDirectoryObject { path: path.clone() });
        drop(descriptor_table);
        let handle = match insert_raw_handle(&self.global.litebox, &self.process.handles, typed) {
            Ok(handle) => handle,
            Err(status) => return status,
        };

        if directory_handle.write_at_offset(0, handle).is_none() {
            remove_raw_handle::<ObjectDirectorySubsystem>(
                &self.global.litebox,
                &self.process.handles,
                handle,
            );
            return NtStatus::ACCESS_VIOLATION;
        }

        litebox_util_log::debug!(
            handle:% = format_args!("{:#x}", handle.as_raw()),
            desired_access:% = format_args!("{desired_access:#x}"),
            root_directory:% = format_args!("{:#x}", object_attributes.root_directory.as_raw()),
            path:% = path;
            "Handled NtOpenDirectoryObject syscall"
        );

        NtStatus::SUCCESS
    }

    pub(crate) fn handle_nt_open_symbolic_link_object(
        &self,
        link_handle: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<Handle>,
        desired_access: u32,
        object_attributes: Option<
            <Platform as litebox::platform::RawPointerProvider>::RawConstPointer<ObjectAttributes>,
        >,
    ) -> NtStatus {
        let Some(object_attributes) = object_attributes else {
            return NtStatus::INVALID_PARAMETER;
        };
        let object_attributes = match read_object_attributes(object_attributes) {
            Ok(object_attributes) => object_attributes,
            Err(status) => return status,
        };
        if object_attributes.object_name == 0 {
            return NtStatus::INVALID_PARAMETER;
        }

        let name = match read_unicode_string(object_attributes.object_name) {
            Ok(name) => name,
            Err(status) => return status,
        };
        let path = match self.resolve_object_path(object_attributes.root_directory, &name) {
            Ok(path) => path,
            Err(status) => return status,
        };
        let Some(target) = known_symbolic_link_target(&path) else {
            return NtStatus::OBJECT_NAME_NOT_FOUND;
        };

        let link = SymbolicLinkObject {
            path: path.clone(),
            target: String::from(target),
        };
        let log_path = String::from(link.path());
        let log_target = String::from(link.target());
        let mut descriptor_table = self.global.litebox.descriptor_table_mut();
        let typed = descriptor_table.insert::<SymbolicLinkSubsystem>(link);
        drop(descriptor_table);
        let handle = match insert_raw_handle(&self.global.litebox, &self.process.handles, typed) {
            Ok(handle) => handle,
            Err(status) => return status,
        };

        if link_handle.write_at_offset(0, handle).is_none() {
            remove_raw_handle::<SymbolicLinkSubsystem>(
                &self.global.litebox,
                &self.process.handles,
                handle,
            );
            return NtStatus::ACCESS_VIOLATION;
        }

        litebox_util_log::debug!(
            handle:% = format_args!("{:#x}", handle.as_raw()),
            desired_access:% = format_args!("{desired_access:#x}"),
            root_directory:% = format_args!("{:#x}", object_attributes.root_directory.as_raw()),
            path:% = log_path,
            target:% = log_target;
            "Handled NtOpenSymbolicLinkObject syscall"
        );

        NtStatus::SUCCESS
    }

    pub(crate) fn handle_nt_query_symbolic_link_object(
        &self,
        link_handle: Handle,
        link_target: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<
            UnicodeString,
        >,
        returned_length: Option<
            <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<u32>,
        >,
    ) -> NtStatus {
        let Some(link) = raw_handle_entry::<SymbolicLinkSubsystem>(
            &self.global.litebox,
            &self.process.handles,
            link_handle,
        ) else {
            return NtStatus::INVALID_HANDLE;
        };
        let target = link.with_entry(|link| String::from(link.target()));
        let Ok(required_len) = u32::try_from(target.encode_utf16().count() * size_of::<u16>())
        else {
            return NtStatus::BUFFER_TOO_SMALL;
        };

        if let Some(returned_length) = returned_length
            && returned_length.write_at_offset(0, required_len).is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }

        let Some(mut link_target_value) = link_target.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        if u32::from(link_target_value.maximum_length) < required_len {
            return NtStatus::BUFFER_TOO_SMALL;
        }
        if required_len != 0 && link_target_value.buffer == 0 {
            return NtStatus::ACCESS_VIOLATION;
        }

        let buffer =
            <Platform as litebox::platform::RawPointerProvider>::RawMutPointer::<u16>::from_usize(
                link_target_value.buffer,
            );
        let target_units = target.encode_utf16().collect::<alloc::vec::Vec<_>>();
        if buffer.write_slice_at_offset(0, &target_units).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }
        let Ok(length) = u16::try_from(required_len) else {
            return NtStatus::BUFFER_TOO_SMALL;
        };
        link_target_value.length = length;
        if link_target.write_at_offset(0, link_target_value).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }

        litebox_util_log::debug!(
            handle:% = format_args!("{:#x}", link_handle.as_raw()),
            target:% = target,
            required_len = required_len;
            "Handled NtQuerySymbolicLinkObject syscall"
        );

        NtStatus::SUCCESS
    }

    fn resolve_object_path(&self, root_directory: Handle, name: &str) -> Result<String, NtStatus> {
        if name.starts_with('\\') {
            return Ok(normalize_absolute_object_path(name));
        }
        if root_directory.is_null() {
            return Err(NtStatus::OBJECT_PATH_INVALID);
        }

        let Some(root) = raw_handle_entry::<ObjectDirectorySubsystem>(
            &self.global.litebox,
            &self.process.handles,
            root_directory,
        ) else {
            return Err(NtStatus::INVALID_HANDLE);
        };
        Ok(root.with_entry(|root| relative_object_path(root.path(), name)))
    }
}

fn relative_object_path(root: &str, name: &str) -> String {
    let relative = normalize_relative_object_path(name);
    if relative.is_empty() {
        return String::from(root);
    }
    if root == r"\" {
        let mut path = String::from(r"\");
        path.push_str(&relative);
        return path;
    }
    let mut path = String::from(root);
    path.push('\\');
    path.push_str(&relative);
    path
}

fn normalize_absolute_object_path(name: &str) -> String {
    let relative = normalize_relative_object_path(name.trim_start_matches('\\'));
    if relative.is_empty() {
        return String::from(r"\");
    }
    let mut path = String::from(r"\");
    path.push_str(&relative);
    path
}

fn normalize_relative_object_path(name: &str) -> String {
    let mut path = String::new();
    for component in name.split('\\').filter(|component| !component.is_empty()) {
        if !path.is_empty() {
            path.push('\\');
        }
        path.push_str(component);
    }
    path
}

fn is_known_object_directory(path: &str) -> bool {
    KNOWN_OBJECT_DIRECTORIES
        .iter()
        .any(|known| path.eq_ignore_ascii_case(known))
}

fn known_symbolic_link_target(path: &str) -> Option<&'static str> {
    KNOWN_SYMBOLIC_LINKS
        .iter()
        .find_map(|(known_path, target)| path.eq_ignore_ascii_case(known_path).then_some(*target))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use litebox::platform::RawPointerProvider;
    use zerocopy::{FromBytes, IntoBytes};

    extern crate std;

    type MutPtr<T> = <Platform as RawPointerProvider>::RawMutPointer<T>;
    type ConstPtr<T> = <Platform as RawPointerProvider>::RawConstPointer<T>;

    fn mut_ptr<T: FromBytes + IntoBytes>(value: &mut T) -> MutPtr<T> {
        MutPtr::from_usize(core::ptr::from_mut(value).cast::<u8>() as usize)
    }

    fn const_ptr<T: FromBytes>(value: &T) -> ConstPtr<T> {
        ConstPtr::from_usize(core::ptr::from_ref(value).cast::<u8>() as usize)
    }

    fn unicode_string(value: &[u16]) -> UnicodeString {
        let byte_len = u16::try_from(core::mem::size_of_val(value)).unwrap();
        UnicodeString {
            length: byte_len,
            maximum_length: byte_len,
            padding_0: [0; 4],
            buffer: value.as_ptr() as usize,
        }
    }

    fn object_attributes(name: &UnicodeString) -> ObjectAttributes {
        ObjectAttributes {
            length: u32::try_from(size_of::<ObjectAttributes>()).unwrap(),
            root_directory: Handle::default(),
            object_name: core::ptr::from_ref(name) as usize,
            attributes: 0,
            security_descriptor: 0,
            security_quality_of_service: 0,
        }
    }

    fn open_known_dll_path_link(task: &Task<crate::DefaultFS>) -> Handle {
        let name_buffer = r"\KnownDlls\KnownDllPath"
            .encode_utf16()
            .collect::<Vec<_>>();
        let name = unicode_string(&name_buffer);
        let object_attributes = object_attributes(&name);
        let mut handle = Handle::default();
        assert_eq!(
            task.handle_nt_open_symbolic_link_object(
                mut_ptr(&mut handle),
                0,
                Some(const_ptr(&object_attributes)),
            ),
            NtStatus::SUCCESS
        );
        handle
    }

    fn output_unicode_string(buffer: &mut [u16]) -> UnicodeString {
        UnicodeString {
            length: 0,
            maximum_length: u16::try_from(core::mem::size_of_val(buffer)).unwrap(),
            padding_0: [0; 4],
            buffer: buffer.as_mut_ptr() as usize,
        }
    }

    #[test]
    fn nt_open_directory_object_opens_known_directory() {
        crate::tests::init_platform();
        let task = crate::tests::test_task();
        let name_buffer = r"\KnownDlls".encode_utf16().collect::<Vec<_>>();
        let name = unicode_string(&name_buffer);
        let object_attributes = object_attributes(&name);
        let mut handle = Handle::default();

        assert_eq!(
            task.handle_nt_open_directory_object(
                mut_ptr(&mut handle),
                0x0002,
                Some(const_ptr(&object_attributes)),
            ),
            NtStatus::SUCCESS
        );
        assert_ne!(handle, Handle::default());
        let directory = raw_handle_entry::<ObjectDirectorySubsystem>(
            &task.global.litebox,
            &task.process.handles,
            handle,
        )
        .unwrap();
        assert_eq!(
            directory.with_entry(|directory| String::from(directory.path())),
            r"\KnownDlls"
        );
    }

    #[test]
    fn nt_open_directory_object_resolves_relative_directory() {
        crate::tests::init_platform();
        let task = crate::tests::test_task();
        let root_name_buffer = r"\".encode_utf16().collect::<Vec<_>>();
        let root_name = unicode_string(&root_name_buffer);
        let root_attributes = object_attributes(&root_name);
        let mut root_handle = Handle::default();
        assert_eq!(
            task.handle_nt_open_directory_object(
                mut_ptr(&mut root_handle),
                0,
                Some(const_ptr(&root_attributes)),
            ),
            NtStatus::SUCCESS
        );

        let relative_name_buffer = "KnownDlls".encode_utf16().collect::<Vec<_>>();
        let relative_name = unicode_string(&relative_name_buffer);
        let mut relative_attributes = object_attributes(&relative_name);
        relative_attributes.root_directory = root_handle;
        let mut handle = Handle::default();

        assert_eq!(
            task.handle_nt_open_directory_object(
                mut_ptr(&mut handle),
                0,
                Some(const_ptr(&relative_attributes)),
            ),
            NtStatus::SUCCESS
        );
        let directory = raw_handle_entry::<ObjectDirectorySubsystem>(
            &task.global.litebox,
            &task.process.handles,
            handle,
        )
        .unwrap();
        assert_eq!(
            directory.with_entry(|directory| String::from(directory.path())),
            r"\KnownDlls"
        );
    }

    #[test]
    fn nt_open_directory_object_rejects_unknown_directory() {
        crate::tests::init_platform();
        let task = crate::tests::test_task();
        let name_buffer = r"\Missing".encode_utf16().collect::<Vec<_>>();
        let name = unicode_string(&name_buffer);
        let object_attributes = object_attributes(&name);
        let mut handle = Handle::default();

        assert_eq!(
            task.handle_nt_open_directory_object(
                mut_ptr(&mut handle),
                0,
                Some(const_ptr(&object_attributes)),
            ),
            NtStatus::OBJECT_NAME_NOT_FOUND
        );
        assert_eq!(handle, Handle::default());
    }

    #[test]
    fn nt_close_removes_directory_object_handle() {
        crate::tests::init_platform();
        let task = crate::tests::test_task();
        let name_buffer = r"\KnownDlls".encode_utf16().collect::<Vec<_>>();
        let name = unicode_string(&name_buffer);
        let object_attributes = object_attributes(&name);
        let mut handle = Handle::default();

        assert_eq!(
            task.handle_nt_open_directory_object(
                mut_ptr(&mut handle),
                0,
                Some(const_ptr(&object_attributes)),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(task.handle_nt_close(handle), NtStatus::SUCCESS);
        assert_eq!(task.handle_nt_close(handle), NtStatus::INVALID_HANDLE);
    }

    #[test]
    fn nt_open_symbolic_link_object_opens_known_link() {
        crate::tests::init_platform();
        let task = crate::tests::test_task();
        let name_buffer = r"\KnownDlls\KnownDllPath"
            .encode_utf16()
            .collect::<Vec<_>>();
        let name = unicode_string(&name_buffer);
        let object_attributes = object_attributes(&name);
        let mut handle = Handle::default();

        assert_eq!(
            task.handle_nt_open_symbolic_link_object(
                mut_ptr(&mut handle),
                0x0001,
                Some(const_ptr(&object_attributes)),
            ),
            NtStatus::SUCCESS
        );
        assert_ne!(handle, Handle::default());
        let link = raw_handle_entry::<SymbolicLinkSubsystem>(
            &task.global.litebox,
            &task.process.handles,
            handle,
        )
        .unwrap();
        assert_eq!(
            link.with_entry(|link| String::from(link.path())),
            r"\KnownDlls\KnownDllPath"
        );
        assert_eq!(
            link.with_entry(|link| String::from(link.target())),
            r"C:\Windows\System32"
        );
    }

    #[test]
    fn nt_open_symbolic_link_object_resolves_relative_link() {
        crate::tests::init_platform();
        let task = crate::tests::test_task();
        let root_name_buffer = r"\KnownDlls".encode_utf16().collect::<Vec<_>>();
        let root_name = unicode_string(&root_name_buffer);
        let root_attributes = object_attributes(&root_name);
        let mut root_handle = Handle::default();
        assert_eq!(
            task.handle_nt_open_directory_object(
                mut_ptr(&mut root_handle),
                0,
                Some(const_ptr(&root_attributes)),
            ),
            NtStatus::SUCCESS
        );

        let relative_name_buffer = "KnownDllPath".encode_utf16().collect::<Vec<_>>();
        let relative_name = unicode_string(&relative_name_buffer);
        let mut relative_attributes = object_attributes(&relative_name);
        relative_attributes.root_directory = root_handle;
        let mut handle = Handle::default();

        assert_eq!(
            task.handle_nt_open_symbolic_link_object(
                mut_ptr(&mut handle),
                0,
                Some(const_ptr(&relative_attributes)),
            ),
            NtStatus::SUCCESS
        );
        let link = raw_handle_entry::<SymbolicLinkSubsystem>(
            &task.global.litebox,
            &task.process.handles,
            handle,
        )
        .unwrap();
        assert_eq!(
            link.with_entry(|link| String::from(link.path())),
            r"\KnownDlls\KnownDllPath"
        );
    }

    #[test]
    fn nt_open_symbolic_link_object_rejects_unknown_link() {
        crate::tests::init_platform();
        let task = crate::tests::test_task();
        let name_buffer = r"\KnownDlls\Missing".encode_utf16().collect::<Vec<_>>();
        let name = unicode_string(&name_buffer);
        let object_attributes = object_attributes(&name);
        let mut handle = Handle::default();

        assert_eq!(
            task.handle_nt_open_symbolic_link_object(
                mut_ptr(&mut handle),
                0,
                Some(const_ptr(&object_attributes)),
            ),
            NtStatus::OBJECT_NAME_NOT_FOUND
        );
        assert_eq!(handle, Handle::default());
    }

    #[test]
    fn nt_close_removes_symbolic_link_object_handle() {
        crate::tests::init_platform();
        let task = crate::tests::test_task();
        let name_buffer = r"\KnownDlls\KnownDllPath"
            .encode_utf16()
            .collect::<Vec<_>>();
        let name = unicode_string(&name_buffer);
        let object_attributes = object_attributes(&name);
        let mut handle = Handle::default();

        assert_eq!(
            task.handle_nt_open_symbolic_link_object(
                mut_ptr(&mut handle),
                0,
                Some(const_ptr(&object_attributes)),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(task.handle_nt_close(handle), NtStatus::SUCCESS);
        assert_eq!(task.handle_nt_close(handle), NtStatus::INVALID_HANDLE);
    }

    #[test]
    fn nt_query_symbolic_link_object_writes_target() {
        crate::tests::init_platform();
        let task = crate::tests::test_task();
        let handle = open_known_dll_path_link(&task);
        let expected = r"C:\Windows\System32".encode_utf16().collect::<Vec<_>>();
        let mut buffer = [0u16; 64];
        let mut link_target = output_unicode_string(&mut buffer);
        let mut returned_length = 0u32;

        assert_eq!(
            task.handle_nt_query_symbolic_link_object(
                handle,
                mut_ptr(&mut link_target),
                Some(mut_ptr(&mut returned_length)),
            ),
            NtStatus::SUCCESS
        );
        let expected_bytes = u32::try_from(core::mem::size_of_val(&*expected)).unwrap();
        assert_eq!(returned_length, expected_bytes);
        assert_eq!(u32::from(link_target.length), expected_bytes);
        assert_eq!(&buffer[..expected.len()], &expected);
    }

    #[test]
    fn nt_query_symbolic_link_object_reports_small_buffer() {
        crate::tests::init_platform();
        let task = crate::tests::test_task();
        let handle = open_known_dll_path_link(&task);
        let mut buffer = [0u16; 2];
        let mut link_target = output_unicode_string(&mut buffer);
        let mut returned_length = 0u32;

        assert_eq!(
            task.handle_nt_query_symbolic_link_object(
                handle,
                mut_ptr(&mut link_target),
                Some(mut_ptr(&mut returned_length)),
            ),
            NtStatus::BUFFER_TOO_SMALL
        );
        assert_eq!(
            returned_length,
            u32::try_from(r"C:\Windows\System32".encode_utf16().count() * size_of::<u16>())
                .unwrap()
        );
        assert_eq!(link_target.length, 0);
    }

    #[test]
    fn nt_query_symbolic_link_object_rejects_non_link_handle() {
        crate::tests::init_platform();
        let task = crate::tests::test_task();
        let name_buffer = r"\KnownDlls".encode_utf16().collect::<Vec<_>>();
        let name = unicode_string(&name_buffer);
        let object_attributes = object_attributes(&name);
        let mut directory_handle = Handle::default();
        assert_eq!(
            task.handle_nt_open_directory_object(
                mut_ptr(&mut directory_handle),
                0,
                Some(const_ptr(&object_attributes)),
            ),
            NtStatus::SUCCESS
        );
        let mut buffer = [0u16; 64];
        let mut link_target = output_unicode_string(&mut buffer);

        assert_eq!(
            task.handle_nt_query_symbolic_link_object(
                directory_handle,
                mut_ptr(&mut link_target),
                None,
            ),
            NtStatus::INVALID_HANDLE
        );
    }
}
