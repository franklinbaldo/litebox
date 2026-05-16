// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::string::String;

use litebox::fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry};
use litebox::fs::{Mode, OFlags};
use litebox::platform::RawMutPointer as _;
use litebox_common_windows::nt_status::NtStatus;

use crate::syscalls::object::{ObjectAttributes, read_object_attributes, read_unicode_string};
use crate::{Handle, NtShimFS, Platform, Task, insert_raw_handle, remove_raw_handle};

pub(crate) struct SectionSubsystem;

impl FdEnabledSubsystem for SectionSubsystem {
    type Entry = SectionObject;
}

impl FdEnabledSubsystemEntry for SectionObject {}

pub(crate) struct SectionObject {
    object_path: String,
    fs_path: String,
}

impl SectionObject {
    fn object_path(&self) -> &str {
        &self.object_path
    }

    fn fs_path(&self) -> &str {
        &self.fs_path
    }
}

impl<FS: NtShimFS> Task<FS> {
    pub(crate) fn handle_nt_open_section(
        &self,
        section_handle: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<Handle>,
        desired_access: u32,
        object_attributes: Option<
            <Platform as litebox::platform::RawPointerProvider>::RawConstPointer<ObjectAttributes>,
        >,
    ) -> NtStatus {
        if section_handle
            .write_at_offset(0, Handle::default())
            .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }

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
        let object_path = match self.resolve_object_path(object_attributes.root_directory, &name) {
            Ok(path) => path,
            Err(status) => return status,
        };
        let Some(fs_path) = known_dll_section_fs_path(&object_path) else {
            return NtStatus::OBJECT_NAME_NOT_FOUND;
        };
        let Ok(fd) = self.fs.open(&fs_path, OFlags::RDONLY, Mode::empty()) else {
            return NtStatus::OBJECT_NAME_NOT_FOUND;
        };
        let _ = self.fs.close(&fd);

        let section = SectionObject {
            object_path: object_path.clone(),
            fs_path: fs_path.clone(),
        };
        let log_object_path = String::from(section.object_path());
        let log_fs_path = String::from(section.fs_path());
        let mut descriptor_table = self.global.litebox.descriptor_table_mut();
        let typed = descriptor_table.insert::<SectionSubsystem>(section);
        drop(descriptor_table);
        let handle = match insert_raw_handle(&self.global.litebox, &self.process.handles, typed) {
            Ok(handle) => handle,
            Err(status) => return status,
        };

        if section_handle.write_at_offset(0, handle).is_none() {
            remove_raw_handle::<SectionSubsystem>(
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
            object_path:% = log_object_path,
            fs_path:% = log_fs_path;
            "Handled NtOpenSection syscall"
        );

        NtStatus::SUCCESS
    }
}

fn known_dll_section_fs_path(object_path: &str) -> Option<String> {
    let dll_name = strip_case_insensitive_prefix(object_path, r"\KnownDlls\")
        .or_else(|| strip_case_insensitive_prefix(object_path, r"\KnownDlls32\"))?;
    if dll_name.contains(['\\', '/']) || !ends_with_ignore_ascii_case(dll_name, ".dll") {
        return None;
    }

    let mut fs_path = String::from("/Windows/System32/");
    fs_path.push_str(&dll_name.to_ascii_lowercase());
    Some(fs_path)
}

fn strip_case_insensitive_prefix<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    value
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
        .then(|| &value[prefix.len()..])
}

fn ends_with_ignore_ascii_case(value: &str, suffix: &str) -> bool {
    value
        .get(value.len().saturating_sub(suffix.len())..)
        .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use litebox::platform::RawConstPointer as _;
    use litebox_common_windows::nt_status::NtStatus;
    use zerocopy::FromBytes;

    use super::*;
    use crate::loader::nt_types::UnicodeString;

    type MutPtr<T> = <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<T>;
    type ConstPtr<T> = <Platform as litebox::platform::RawPointerProvider>::RawConstPointer<T>;

    fn mut_handle_ptr(value: &mut Handle) -> MutPtr<Handle> {
        MutPtr::from_usize(core::ptr::from_mut(value) as usize)
    }

    fn const_ptr<T: FromBytes>(value: &T) -> ConstPtr<T> {
        ConstPtr::from_usize(core::ptr::from_ref(value).cast::<u8>() as usize)
    }

    fn wide(value: &str) -> alloc::vec::Vec<u16> {
        value.encode_utf16().collect()
    }

    fn object_attributes_for_name(
        root_directory: Handle,
        object_name: &UnicodeString,
    ) -> ObjectAttributes {
        ObjectAttributes {
            length: u32::try_from(size_of::<ObjectAttributes>()).unwrap(),
            root_directory,
            object_name: core::ptr::from_ref(object_name) as usize,
            attributes: 0,
            security_descriptor: 0,
            security_quality_of_service: 0,
        }
    }

    #[test]
    fn nt_open_section_opens_known_dll_section() {
        let task =
            crate::tests::test_task_with_nls_files(&[("/Windows/System32/kernel32.dll", b"dll")]);
        let mut section_handle = Handle::from_raw(usize::MAX);
        let path = wide(r"\KnownDlls\kernel32.dll");
        let object_name = UnicodeString {
            length: u16::try_from(path.len() * size_of::<u16>()).unwrap(),
            maximum_length: u16::try_from(path.len() * size_of::<u16>()).unwrap(),
            padding_0: [0; 4],
            buffer: path.as_ptr() as usize,
        };
        let object_attributes = object_attributes_for_name(Handle::default(), &object_name);

        assert_eq!(
            task.handle_nt_open_section(
                mut_handle_ptr(&mut section_handle),
                0xf001f,
                Some(const_ptr(&object_attributes)),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(section_handle, Handle::from_raw_fd(0).unwrap());

        let section = crate::raw_handle_entry::<SectionSubsystem>(
            &task.global.litebox,
            &task.process.handles,
            section_handle,
        )
        .unwrap();
        section.with_entry(|section| {
            assert_eq!(section.object_path(), r"\KnownDlls\kernel32.dll");
            assert_eq!(section.fs_path(), "/Windows/System32/kernel32.dll");
        });
    }

    #[test]
    fn nt_open_section_resolves_relative_known_dll_name() {
        let task =
            crate::tests::test_task_with_nls_files(&[("/Windows/System32/kernel32.dll", b"dll")]);
        let mut directory_handle = Handle::from_raw(0);
        let directory_path = wide(r"\KnownDlls");
        let directory_name = UnicodeString {
            length: u16::try_from(directory_path.len() * size_of::<u16>()).unwrap(),
            maximum_length: u16::try_from(directory_path.len() * size_of::<u16>()).unwrap(),
            padding_0: [0; 4],
            buffer: directory_path.as_ptr() as usize,
        };
        let directory_attributes = object_attributes_for_name(Handle::default(), &directory_name);
        assert_eq!(
            task.handle_nt_open_directory_object(
                mut_handle_ptr(&mut directory_handle),
                0x3,
                Some(const_ptr(&directory_attributes)),
            ),
            NtStatus::SUCCESS
        );

        let mut section_handle = Handle::from_raw(usize::MAX);
        let path = wide("kernel32.dll");
        let object_name = UnicodeString {
            length: u16::try_from(path.len() * size_of::<u16>()).unwrap(),
            maximum_length: u16::try_from(path.len() * size_of::<u16>()).unwrap(),
            padding_0: [0; 4],
            buffer: path.as_ptr() as usize,
        };
        let object_attributes = object_attributes_for_name(directory_handle, &object_name);

        assert_eq!(
            task.handle_nt_open_section(
                mut_handle_ptr(&mut section_handle),
                0xf001f,
                Some(const_ptr(&object_attributes)),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(section_handle, Handle::from_raw_fd(1).unwrap());
    }

    #[test]
    fn nt_open_section_reports_missing_known_dll() {
        let task = crate::tests::test_task();
        let mut section_handle = Handle::from_raw(usize::MAX);
        let path = wide(r"\KnownDlls\missing.dll");
        let object_name = UnicodeString {
            length: u16::try_from(path.len() * size_of::<u16>()).unwrap(),
            maximum_length: u16::try_from(path.len() * size_of::<u16>()).unwrap(),
            padding_0: [0; 4],
            buffer: path.as_ptr() as usize,
        };
        let object_attributes = object_attributes_for_name(Handle::default(), &object_name);

        assert_eq!(
            task.handle_nt_open_section(
                mut_handle_ptr(&mut section_handle),
                0,
                Some(const_ptr(&object_attributes)),
            ),
            NtStatus::OBJECT_NAME_NOT_FOUND
        );
        assert_eq!(section_handle, Handle::default());
    }

    #[test]
    fn nt_close_removes_section_handle() {
        let task =
            crate::tests::test_task_with_nls_files(&[("/Windows/System32/kernel32.dll", b"dll")]);
        let mut section_handle = Handle::from_raw(0);
        let path = wide(r"\KnownDlls\kernel32.dll");
        let object_name = UnicodeString {
            length: u16::try_from(path.len() * size_of::<u16>()).unwrap(),
            maximum_length: u16::try_from(path.len() * size_of::<u16>()).unwrap(),
            padding_0: [0; 4],
            buffer: path.as_ptr() as usize,
        };
        let object_attributes = object_attributes_for_name(Handle::default(), &object_name);

        assert_eq!(
            task.handle_nt_open_section(
                mut_handle_ptr(&mut section_handle),
                0,
                Some(const_ptr(&object_attributes)),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(task.handle_nt_close(section_handle), NtStatus::SUCCESS);
        assert_eq!(
            task.handle_nt_close(section_handle),
            NtStatus::INVALID_HANDLE
        );
    }
}
