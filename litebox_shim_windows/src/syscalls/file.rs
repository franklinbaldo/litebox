// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::string::String;

use litebox::fs::{FileType, Mode, OFlags};
use litebox::platform::{RawMutPointer as _, RawPointerProvider};
use litebox_common_windows::nt_status::NtStatus;
use litebox_platform_multiplex::Platform;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::syscalls::object::{ObjectAttributes, read_object_attributes, read_unicode_string};
use crate::{Handle, NtShimFS, Task, insert_raw_handle, remove_raw_handle};

const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x20;
const FILE_OPENED: usize = 1;

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
pub(crate) struct IoStatusBlock {
    status: i32,
    _padding: u32,
    information: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
pub(crate) struct FileBasicInformation {
    creation_time: i64,
    last_access_time: i64,
    last_write_time: i64,
    change_time: i64,
    file_attributes: u32,
    _padding: u32,
}

impl<FS: NtShimFS> Task<FS> {
    pub(crate) fn handle_nt_open_file(
        &self,
        file_handle: <Platform as RawPointerProvider>::RawMutPointer<Handle>,
        desired_access: u32,
        object_attributes: Option<
            <Platform as RawPointerProvider>::RawConstPointer<ObjectAttributes>,
        >,
        io_status_block: <Platform as RawPointerProvider>::RawMutPointer<IoStatusBlock>,
        share_access: u32,
        open_options: u32,
    ) -> NtStatus {
        if file_handle.write_at_offset(0, Handle::default()).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }

        let Some(object_attributes) = object_attributes else {
            return write_io_status(io_status_block, NtStatus::INVALID_PARAMETER);
        };
        let object_attributes = match read_object_attributes(object_attributes) {
            Ok(object_attributes) => object_attributes,
            Err(status) => return write_io_status(io_status_block, status),
        };
        if object_attributes.object_name == 0 {
            return write_io_status(io_status_block, NtStatus::INVALID_PARAMETER);
        }

        let name = match read_unicode_string(object_attributes.object_name) {
            Ok(name) => name,
            Err(status) => return write_io_status(io_status_block, status),
        };
        let path = match self.resolve_object_path(object_attributes.root_directory, &name) {
            Ok(path) => path,
            Err(status) => return write_io_status(io_status_block, status),
        };
        let Some(fs_path) = nt_object_path_to_fs_path(&path) else {
            return write_io_status(io_status_block, NtStatus::OBJECT_NAME_NOT_FOUND);
        };
        let Ok(fd) = self.fs.open(&*fs_path, OFlags::RDONLY, Mode::empty()) else {
            return write_io_status(io_status_block, NtStatus::OBJECT_NAME_NOT_FOUND);
        };
        let handle = match insert_raw_handle(&self.global.litebox, &self.process.handles, fd) {
            Ok(handle) => handle,
            Err(status) => return write_io_status(io_status_block, status),
        };
        if file_handle.write_at_offset(0, handle).is_none() {
            remove_raw_handle::<FS>(&self.global.litebox, &self.process.handles, handle);
            return write_io_status(io_status_block, NtStatus::ACCESS_VIOLATION);
        }

        let status =
            write_io_status_with_information(io_status_block, NtStatus::SUCCESS, FILE_OPENED);
        if status == NtStatus::ACCESS_VIOLATION {
            remove_raw_handle::<FS>(&self.global.litebox, &self.process.handles, handle);
            let _ = file_handle.write_at_offset(0, Handle::default());
            return status;
        }
        litebox_util_log::debug!(
            handle:% = format_args!("{:#x}", handle.as_raw()),
            desired_access:% = format_args!("{desired_access:#x}"),
            share_access:% = format_args!("{share_access:#x}"),
            open_options:% = format_args!("{open_options:#x}"),
            root_directory:% = format_args!("{:#x}", object_attributes.root_directory.as_raw()),
            path:% = path,
            fs_path:% = fs_path,
            status:% = status;
            "Handled NtOpenFile syscall"
        );
        status
    }

    pub(crate) fn handle_nt_query_attributes_file(
        &self,
        object_attributes: <Platform as RawPointerProvider>::RawConstPointer<ObjectAttributes>,
        file_information: <Platform as RawPointerProvider>::RawMutPointer<FileBasicInformation>,
    ) -> NtStatus {
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
        let Some(fs_path) = nt_object_path_to_fs_path(&object_path) else {
            return NtStatus::OBJECT_PATH_NOT_FOUND;
        };
        let status = match self.fs.file_status(&*fs_path) {
            Ok(status) => {
                let file_attributes = match status.file_type {
                    FileType::Directory => FILE_ATTRIBUTE_DIRECTORY,
                    FileType::RegularFile => FILE_ATTRIBUTE_ARCHIVE,
                    _ => 0,
                };
                let information = FileBasicInformation {
                    creation_time: 0,
                    last_access_time: 0,
                    last_write_time: 0,
                    change_time: 0,
                    file_attributes,
                    _padding: 0,
                };
                if file_information.write_at_offset(0, information).is_none() {
                    return NtStatus::ACCESS_VIOLATION;
                }
                NtStatus::SUCCESS
            }
            Err(_) => NtStatus::OBJECT_NAME_NOT_FOUND,
        };

        litebox_util_log::debug!(
            root_directory:% = format_args!("{:#x}", object_attributes.root_directory.as_raw()),
            object_path:% = object_path,
            fs_path:% = fs_path,
            status:% = status;
            "Handled NtQueryAttributesFile syscall"
        );

        status
    }
}

fn nt_object_path_to_fs_path(object_path: &str) -> Option<String> {
    let dos_path = strip_case_insensitive_prefix(object_path, r"\??\C:")
        .or_else(|| strip_case_insensitive_prefix(object_path, r"\Device\HarddiskVolume1\"))?;
    let mut fs_path = String::from("/");
    for (index, component) in dos_path
        .split(['\\', '/'])
        .filter(|component| !component.is_empty())
        .enumerate()
    {
        if index != 0 {
            fs_path.push('/');
        }
        if component.eq_ignore_ascii_case("Windows") {
            fs_path.push_str("Windows");
        } else if component.eq_ignore_ascii_case("System32") {
            fs_path.push_str("System32");
        } else if ends_with_ignore_ascii_case(component, ".dll")
            || ends_with_ignore_ascii_case(component, ".nls")
        {
            fs_path.push_str(&component.to_ascii_lowercase());
        } else {
            fs_path.push_str(component);
        }
    }
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

fn write_io_status(
    io_status_block: <Platform as RawPointerProvider>::RawMutPointer<IoStatusBlock>,
    status: NtStatus,
) -> NtStatus {
    write_io_status_with_information(io_status_block, status, 0)
}

fn write_io_status_with_information(
    io_status_block: <Platform as RawPointerProvider>::RawMutPointer<IoStatusBlock>,
    status: NtStatus,
    information: usize,
) -> NtStatus {
    let io_status = IoStatusBlock {
        status: status.as_raw(),
        _padding: 0,
        information,
    };
    if io_status_block.write_at_offset(0, io_status).is_none() {
        return NtStatus::ACCESS_VIOLATION;
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::nt_types::UnicodeString;
    use core::mem::{align_of, size_of};
    use litebox::platform::{RawConstPointer as _, RawPointerProvider};
    use zerocopy::{FromBytes, IntoBytes};

    type MutPtr<T> = <Platform as RawPointerProvider>::RawMutPointer<T>;
    type ConstPtr<T> = <Platform as RawPointerProvider>::RawConstPointer<T>;

    fn mut_ptr<T: FromBytes + IntoBytes>(value: &mut T) -> MutPtr<T> {
        MutPtr::from_usize(core::ptr::from_mut(value).cast::<u8>() as usize)
    }

    fn const_ptr<T: FromBytes>(value: &T) -> ConstPtr<T> {
        ConstPtr::from_usize(core::ptr::from_ref(value).cast::<u8>() as usize)
    }

    #[test]
    fn io_status_block_matches_windows_x64_layout() {
        assert_eq!(size_of::<IoStatusBlock>(), 16);
        assert_eq!(align_of::<IoStatusBlock>(), 8);
    }

    #[test]
    fn file_basic_information_matches_windows_x64_layout() {
        assert_eq!(size_of::<FileBasicInformation>(), 40);
        assert_eq!(align_of::<FileBasicInformation>(), 8);
    }

    #[test]
    fn nt_open_file_reports_missing_object_path() {
        let task = crate::tests::test_task();
        let mut file_handle = Handle::from_raw(usize::MAX);
        let mut io_status = IoStatusBlock {
            status: NtStatus::SUCCESS.as_raw(),
            _padding: u32::MAX,
            information: usize::MAX,
        };
        let path = wide(r"\KnownDlls\kernel32.dll");
        let object_name = UnicodeString {
            length: u16::try_from(path.len() * size_of::<u16>()).unwrap(),
            maximum_length: u16::try_from(path.len() * size_of::<u16>()).unwrap(),
            padding_0: [0; 4],
            buffer: path.as_ptr() as usize,
        };
        let object_attributes = ObjectAttributes {
            length: u32::try_from(size_of::<ObjectAttributes>()).unwrap(),
            root_directory: Handle::default(),
            object_name: (&raw const object_name) as usize,
            attributes: 0,
            security_descriptor: 0,
            security_quality_of_service: 0,
        };

        assert_eq!(
            task.handle_nt_open_file(
                mut_ptr(&mut file_handle),
                0,
                Some(const_ptr(&object_attributes)),
                mut_ptr(&mut io_status),
                0,
                0,
            ),
            NtStatus::OBJECT_NAME_NOT_FOUND
        );
        assert_eq!(file_handle, Handle::default());
        assert_eq!(io_status.status, NtStatus::OBJECT_NAME_NOT_FOUND.as_raw());
        assert_eq!(io_status.information, 0);
    }

    #[test]
    fn nt_open_file_opens_dos_drive_root() {
        let task = crate::tests::test_task();
        let mut file_handle = Handle::default();
        let mut io_status = IoStatusBlock {
            status: NtStatus::OBJECT_NAME_NOT_FOUND.as_raw(),
            _padding: u32::MAX,
            information: 0,
        };
        let path = wide(r"\??\C:");
        let object_name = UnicodeString {
            length: u16::try_from(path.len() * size_of::<u16>()).unwrap(),
            maximum_length: u16::try_from(path.len() * size_of::<u16>()).unwrap(),
            padding_0: [0; 4],
            buffer: path.as_ptr() as usize,
        };
        let object_attributes = ObjectAttributes {
            length: u32::try_from(size_of::<ObjectAttributes>()).unwrap(),
            root_directory: Handle::default(),
            object_name: core::ptr::from_ref(&object_name) as usize,
            attributes: 0,
            security_descriptor: 0,
            security_quality_of_service: 0,
        };

        assert_eq!(
            task.handle_nt_open_file(
                mut_ptr(&mut file_handle),
                0x100020,
                Some(const_ptr(&object_attributes)),
                mut_ptr(&mut io_status),
                0x3,
                0x21,
            ),
            NtStatus::SUCCESS
        );
        assert_ne!(file_handle, Handle::default());
        assert_eq!(io_status.status, NtStatus::SUCCESS.as_raw());
        assert_eq!(io_status.information, FILE_OPENED);
        assert_eq!(task.handle_nt_close(file_handle), NtStatus::SUCCESS);
    }

    #[test]
    fn nt_query_attributes_file_reports_existing_system32_file() {
        let task =
            crate::tests::test_task_with_nls_files(&[("/Windows/System32/kernel32.dll", b"dll")]);
        let mut information = FileBasicInformation {
            creation_time: -1,
            last_access_time: -1,
            last_write_time: -1,
            change_time: -1,
            file_attributes: 0,
            _padding: u32::MAX,
        };
        let path = wide(r"\??\C:\Windows\System32\KERNEL32.DLL");
        let object_name = UnicodeString {
            length: u16::try_from(path.len() * size_of::<u16>()).unwrap(),
            maximum_length: u16::try_from(path.len() * size_of::<u16>()).unwrap(),
            padding_0: [0; 4],
            buffer: path.as_ptr() as usize,
        };
        let object_attributes = ObjectAttributes {
            length: u32::try_from(size_of::<ObjectAttributes>()).unwrap(),
            root_directory: Handle::default(),
            object_name: core::ptr::from_ref(&object_name) as usize,
            attributes: 0,
            security_descriptor: 0,
            security_quality_of_service: 0,
        };

        assert_eq!(
            task.handle_nt_query_attributes_file(
                const_ptr(&object_attributes),
                mut_ptr(&mut information),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(information.file_attributes, FILE_ATTRIBUTE_ARCHIVE);
    }

    fn wide(value: &str) -> alloc::vec::Vec<u16> {
        value.encode_utf16().collect()
    }
}
