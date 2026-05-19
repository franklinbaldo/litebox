// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::string::String;
use alloc::vec::Vec;

use int_enum::IntEnum;
use litebox::fs::{FileType, Mode, OFlags};
use litebox::platform::{RawConstPointer as _, RawMutPointer as _, RawPointerProvider};
use litebox_common_windows::nt_status::NtStatus;
use litebox_platform_multiplex::Platform;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::syscalls::object::{ObjectAttributes, read_object_attributes, read_unicode_string};
use crate::{Handle, NtShimFS, Task, insert_raw_handle, remove_raw_handle};

const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x20;
const FILE_OPENED: usize = 1;
const FILE_DEVICE_DISK: u32 = 0x7;
const FILE_DEVICE_IS_MOUNTED: u32 = 0x20;
const FILE_CASE_SENSITIVE_SEARCH: u32 = 0x1;
const FILE_CASE_PRESERVED_NAMES: u32 = 0x2;
const FILE_UNICODE_ON_DISK: u32 = 0x4;
const FILE_PERSISTENT_ACLS: u32 = 0x8;
const FILE_NAMED_STREAMS: u32 = 0x40000;
const LITEBOX_VOLUME_LABEL: &str = "LiteBox";
const LITEBOX_FILE_SYSTEM_NAME: &str = "NTFS";
const FILE_FS_VOLUME_INFORMATION_VOLUME_LABEL_OFFSET: usize = 18;
const FILE_FS_ATTRIBUTE_INFORMATION_FILE_SYSTEM_NAME_OFFSET: usize = 12;
const CONDRV_SERVER_DEVICE: &str = r"\Device\ConDrv\Server";
const CONDRV_REFERENCE_OBJECT: &str = r"\Reference";
const CONDRV_CONNECT_OBJECT: &str = r"\Connect";
const CONDRV_INPUT_OBJECT: &str = r"\Input";
const CONDRV_OUTPUT_OBJECT: &str = r"\Output";
const DEV_NULL: &str = "/dev/null";
const DEV_STDIN: &str = "/dev/stdin";
const DEV_STDOUT: &str = "/dev/stdout";

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, IntEnum)]
enum FsInformationClass {
    Volume = 1,
    Label = 2,
    Size = 3,
    Device = 4,
    Attribute = 5,
    Control = 6,
    FullSize = 7,
    ObjectId = 8,
    DriverPath = 9,
    VolumeFlags = 10,
    SectorSize = 11,
    DataCopy = 12,
    MetadataSize = 13,
    FullSizeEx = 14,
    Guid = 15,
    Maximum = 16,
}

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

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct FileFsVolumeInformation {
    volume_creation_time: i64,
    volume_serial_number: u32,
    volume_label_length: u32,
    supports_objects: u8,
    _padding0: u8,
    volume_label: [u16; 1],
    _padding1: [u8; 4],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct FileFsSizeInformation {
    total_allocation_units: i64,
    available_allocation_units: i64,
    sectors_per_allocation_unit: u32,
    bytes_per_sector: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct FileFsDeviceInformation {
    device_type: u32,
    characteristics: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct FileFsAttributeInformation {
    file_system_attributes: u32,
    maximum_component_name_length: i32,
    file_system_name_length: u32,
    file_system_name: [u16; 1],
    _padding: [u8; 2],
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
        if let Some((fs_path, flags)) = condrv_device_file(&path) {
            let Ok(fd) = self.fs.open(fs_path, flags, Mode::empty()) else {
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
                "Handled NtOpenFile syscall for ConDrv pseudo-device"
            );
            return status;
        }
        let Some(fs_path) = nt_object_path_to_fs_path(&path) else {
            litebox_util_log::debug!(
                desired_access:% = format_args!("{desired_access:#x}"),
                share_access:% = format_args!("{share_access:#x}"),
                open_options:% = format_args!("{open_options:#x}"),
                root_directory:% = format_args!("{:#x}", object_attributes.root_directory.as_raw()),
                path:% = path,
                status:% = NtStatus::OBJECT_NAME_NOT_FOUND;
                "Handled NtOpenFile syscall"
            );
            return write_io_status(io_status_block, NtStatus::OBJECT_NAME_NOT_FOUND);
        };
        let Ok(fd) = self.fs.open(&*fs_path, OFlags::RDONLY, Mode::empty()) else {
            litebox_util_log::debug!(
                desired_access:% = format_args!("{desired_access:#x}"),
                share_access:% = format_args!("{share_access:#x}"),
                open_options:% = format_args!("{open_options:#x}"),
                root_directory:% = format_args!("{:#x}", object_attributes.root_directory.as_raw()),
                path:% = path,
                fs_path:% = fs_path,
                status:% = NtStatus::OBJECT_NAME_NOT_FOUND;
                "Handled NtOpenFile syscall"
            );
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

    pub(crate) fn handle_nt_query_volume_information_file(
        &self,
        file_handle: Handle,
        io_status_block: <Platform as RawPointerProvider>::RawMutPointer<IoStatusBlock>,
        fs_information: <Platform as RawPointerProvider>::RawMutPointer<u8>,
        fs_information_length: u32,
        fs_information_class: u32,
    ) -> NtStatus {
        let Some(raw_fd) = file_handle.raw_fd() else {
            return write_io_status(io_status_block, NtStatus::INVALID_HANDLE);
        };
        let handle_is_valid = self
            .process
            .handles
            .read()
            .fd_from_raw_integer::<FS>(raw_fd)
            .is_ok();
        if !handle_is_valid {
            return write_io_status(io_status_block, NtStatus::INVALID_HANDLE);
        }

        let Some(information) = fs_volume_information(fs_information_class) else {
            return write_io_status(io_status_block, NtStatus::INVALID_INFO_CLASS);
        };
        let status = write_fs_information(
            fs_information,
            usize::try_from(fs_information_length).unwrap_or(usize::MAX),
            &information,
            io_status_block,
        );

        litebox_util_log::debug!(
            handle:% = format_args!("{:#x}", file_handle.as_raw()),
            fs_information_class,
            fs_information_length,
            returned_length = information.len(),
            status:% = status;
            "Handled NtQueryVolumeInformationFile syscall"
        );

        status
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn handle_nt_device_io_control_file(
        &self,
        file_handle: Handle,
        event: Handle,
        apc_routine: <Platform as RawPointerProvider>::RawMutPointer<u8>,
        apc_context: <Platform as RawPointerProvider>::RawMutPointer<u8>,
        io_status_block: <Platform as RawPointerProvider>::RawMutPointer<IoStatusBlock>,
        io_control_code: u32,
        input_buffer: <Platform as RawPointerProvider>::RawMutPointer<u8>,
        input_buffer_length: u32,
        output_buffer: <Platform as RawPointerProvider>::RawMutPointer<u8>,
        output_buffer_length: u32,
    ) -> NtStatus {
        let status = write_io_status_with_information(io_status_block, NtStatus::SUCCESS, 0);
        if status == NtStatus::SUCCESS {
            litebox_util_log::debug!(
                file_handle:% = format_args!("{:#x}", file_handle.as_raw()),
                event:% = format_args!("{:#x}", event.as_raw()),
                apc_routine:% = format_args!("{:#x}", apc_routine.as_usize()),
                apc_context:% = format_args!("{:#x}", apc_context.as_usize()),
                io_control_code:% = format_args!("{io_control_code:#x}"),
                input_buffer:% = format_args!("{:#x}", input_buffer.as_usize()),
                input_buffer_length = input_buffer_length,
                output_buffer:% = format_args!("{:#x}", output_buffer.as_usize()),
                output_buffer_length = output_buffer_length;
                "Handled NtDeviceIoControlFile syscall as local device sink"
            );
        }
        status
    }
}

fn fs_volume_information(fs_information_class: u32) -> Option<Vec<u8>> {
    let fs_information_class = FsInformationClass::try_from(fs_information_class).ok()?;
    match fs_information_class {
        FsInformationClass::Volume => Some(file_fs_volume_information()),
        FsInformationClass::Size => Some(
            FileFsSizeInformation {
                total_allocation_units: 1024 * 1024,
                available_allocation_units: 1024 * 1024,
                sectors_per_allocation_unit: 8,
                bytes_per_sector: 512,
            }
            .as_bytes()
            .to_vec(),
        ),
        FsInformationClass::Device => Some(
            FileFsDeviceInformation {
                device_type: FILE_DEVICE_DISK,
                characteristics: FILE_DEVICE_IS_MOUNTED,
            }
            .as_bytes()
            .to_vec(),
        ),
        FsInformationClass::Attribute => Some(file_fs_attribute_information()),
        _ => None,
    }
}

fn file_fs_volume_information() -> Vec<u8> {
    let label = utf16_bytes(LITEBOX_VOLUME_LABEL);
    let header = FileFsVolumeInformation {
        volume_creation_time: 0,
        volume_serial_number: 0x4c42_5856,
        volume_label_length: u32::try_from(label.len()).unwrap(),
        supports_objects: 0,
        _padding0: 0,
        volume_label: [0],
        _padding1: [0; 4],
    };
    let mut information =
        Vec::with_capacity(FILE_FS_VOLUME_INFORMATION_VOLUME_LABEL_OFFSET + label.len());
    information
        .extend_from_slice(&header.as_bytes()[..FILE_FS_VOLUME_INFORMATION_VOLUME_LABEL_OFFSET]);
    information.extend_from_slice(&label);
    information
}

fn file_fs_attribute_information() -> Vec<u8> {
    let name = utf16_bytes(LITEBOX_FILE_SYSTEM_NAME);
    let header = FileFsAttributeInformation {
        file_system_attributes: FILE_CASE_SENSITIVE_SEARCH
            | FILE_CASE_PRESERVED_NAMES
            | FILE_UNICODE_ON_DISK
            | FILE_PERSISTENT_ACLS
            | FILE_NAMED_STREAMS,
        maximum_component_name_length: 255,
        file_system_name_length: u32::try_from(name.len()).unwrap(),
        file_system_name: [0],
        _padding: [0; 2],
    };
    let mut information =
        Vec::with_capacity(FILE_FS_ATTRIBUTE_INFORMATION_FILE_SYSTEM_NAME_OFFSET + name.len());
    information.extend_from_slice(
        &header.as_bytes()[..FILE_FS_ATTRIBUTE_INFORMATION_FILE_SYSTEM_NAME_OFFSET],
    );
    information.extend_from_slice(&name);
    information
}

fn utf16_bytes(value: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(value.len() * size_of::<u16>());
    for unit in value.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes
}

fn write_fs_information(
    fs_information: <Platform as RawPointerProvider>::RawMutPointer<u8>,
    fs_information_length: usize,
    information: &[u8],
    io_status_block: <Platform as RawPointerProvider>::RawMutPointer<IoStatusBlock>,
) -> NtStatus {
    if fs_information_length < information.len() {
        return write_io_status(io_status_block, NtStatus::BUFFER_TOO_SMALL);
    }
    if fs_information.copy_from_slice(0, information).is_none() {
        return write_io_status(io_status_block, NtStatus::ACCESS_VIOLATION);
    }
    write_io_status_with_information(io_status_block, NtStatus::SUCCESS, information.len())
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

fn condrv_device_file(path: &str) -> Option<(&'static str, OFlags)> {
    if path.eq_ignore_ascii_case(CONDRV_INPUT_OBJECT) {
        return Some((DEV_STDIN, OFlags::RDONLY));
    }
    if path.eq_ignore_ascii_case(CONDRV_OUTPUT_OBJECT) {
        return Some((DEV_STDOUT, OFlags::WRONLY));
    }
    if path.eq_ignore_ascii_case(CONDRV_SERVER_DEVICE)
        || path.eq_ignore_ascii_case(CONDRV_REFERENCE_OBJECT)
        || path.eq_ignore_ascii_case(CONDRV_CONNECT_OBJECT)
    {
        return Some((DEV_NULL, OFlags::RDWR));
    }
    None
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
    use litebox::fs::FileSystem as _;
    use litebox::platform::RawPointerProvider;
    use zerocopy::{FromBytes, IntoBytes};

    const NULL_RDEV: usize = 0x103;
    const STDIO_RDEV: usize = 34_822;

    type MutPtr<T> = <Platform as RawPointerProvider>::RawMutPointer<T>;
    type ConstPtr<T> = <Platform as RawPointerProvider>::RawConstPointer<T>;

    fn mut_ptr<T: FromBytes + IntoBytes>(value: &mut T) -> MutPtr<T> {
        MutPtr::from_usize(core::ptr::from_mut(value).cast::<u8>() as usize)
    }

    fn mut_byte_ptr<T>(value: &mut T) -> MutPtr<u8> {
        MutPtr::<u8>::from_usize(core::ptr::from_mut(value).cast::<u8>() as usize)
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
    fn fs_information_class_matches_windows_values() {
        assert_eq!(u32::from(FsInformationClass::Volume), 1);
        assert_eq!(u32::from(FsInformationClass::Label), 2);
        assert_eq!(u32::from(FsInformationClass::Size), 3);
        assert_eq!(u32::from(FsInformationClass::Device), 4);
        assert_eq!(u32::from(FsInformationClass::Attribute), 5);
        assert_eq!(u32::from(FsInformationClass::Maximum), 16);
    }

    #[test]
    fn file_fs_volume_information_matches_windows_x64_layout() {
        assert_eq!(size_of::<FileFsVolumeInformation>(), 24);
        assert_eq!(align_of::<FileFsVolumeInformation>(), 8);
        assert_eq!(FILE_FS_VOLUME_INFORMATION_VOLUME_LABEL_OFFSET, 18);
    }

    #[test]
    fn file_fs_size_information_matches_windows_x64_layout() {
        assert_eq!(size_of::<FileFsSizeInformation>(), 24);
        assert_eq!(align_of::<FileFsSizeInformation>(), 8);
    }

    #[test]
    fn file_fs_device_information_matches_windows_x64_layout() {
        assert_eq!(size_of::<FileFsDeviceInformation>(), 8);
        assert_eq!(align_of::<FileFsDeviceInformation>(), 4);
    }

    #[test]
    fn file_fs_attribute_information_matches_windows_x64_layout() {
        assert_eq!(size_of::<FileFsAttributeInformation>(), 16);
        assert_eq!(align_of::<FileFsAttributeInformation>(), 4);
        assert_eq!(FILE_FS_ATTRIBUTE_INFORMATION_FILE_SYSTEM_NAME_OFFSET, 12);
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
    fn nt_open_file_maps_condrv_output_to_stdio_device() {
        let task = crate::tests::test_task();
        let (file_handle, io_status, status) = open_nt_file(&task, CONDRV_OUTPUT_OBJECT);

        assert_eq!(status, NtStatus::SUCCESS);
        assert_eq!(io_status.status, NtStatus::SUCCESS.as_raw());
        assert_eq!(io_status.information, FILE_OPENED);
        let status = file_status(&task, file_handle);
        assert_eq!(status.file_type, FileType::CharacterDevice);
        assert_eq!(
            status.node_info.rdev.map(|rdev| rdev.get()),
            Some(STDIO_RDEV)
        );
        assert_eq!(task.handle_nt_close(file_handle), NtStatus::SUCCESS);
    }

    #[test]
    fn nt_open_file_maps_condrv_control_to_null_device() {
        let task = crate::tests::test_task();
        let (file_handle, io_status, status) = open_nt_file(&task, CONDRV_SERVER_DEVICE);

        assert_eq!(status, NtStatus::SUCCESS);
        assert_eq!(io_status.status, NtStatus::SUCCESS.as_raw());
        assert_eq!(io_status.information, FILE_OPENED);
        let status = file_status(&task, file_handle);
        assert_eq!(status.file_type, FileType::CharacterDevice);
        assert_eq!(
            status.node_info.rdev.map(|rdev| rdev.get()),
            Some(NULL_RDEV)
        );
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

    #[test]
    fn nt_query_volume_information_file_reports_device_information() {
        let task = crate::tests::test_task();
        let mut file_handle = Handle::default();
        let mut open_io_status = IoStatusBlock {
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
                mut_ptr(&mut open_io_status),
                0x3,
                0x21,
            ),
            NtStatus::SUCCESS
        );

        let mut query_io_status = IoStatusBlock {
            status: NtStatus::OBJECT_NAME_NOT_FOUND.as_raw(),
            _padding: u32::MAX,
            information: usize::MAX,
        };
        let mut information = FileFsDeviceInformation {
            device_type: 0,
            characteristics: 0,
        };

        assert_eq!(
            task.handle_nt_query_volume_information_file(
                file_handle,
                mut_ptr(&mut query_io_status),
                mut_byte_ptr(&mut information),
                u32::try_from(size_of::<FileFsDeviceInformation>()).unwrap(),
                u32::from(FsInformationClass::Device),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(query_io_status.status, NtStatus::SUCCESS.as_raw());
        assert_eq!(
            query_io_status.information,
            size_of::<FileFsDeviceInformation>()
        );
        assert_eq!(information.device_type, FILE_DEVICE_DISK);
        assert_eq!(information.characteristics, FILE_DEVICE_IS_MOUNTED);
        assert_eq!(task.handle_nt_close(file_handle), NtStatus::SUCCESS);
    }

    #[test]
    fn nt_query_volume_information_file_rejects_invalid_handle() {
        let task = crate::tests::test_task();
        let mut io_status = IoStatusBlock {
            status: NtStatus::SUCCESS.as_raw(),
            _padding: u32::MAX,
            information: usize::MAX,
        };
        let mut information = FileFsDeviceInformation {
            device_type: 0,
            characteristics: 0,
        };

        assert_eq!(
            task.handle_nt_query_volume_information_file(
                Handle::from_raw(usize::MAX),
                mut_ptr(&mut io_status),
                mut_byte_ptr(&mut information),
                u32::try_from(size_of::<FileFsDeviceInformation>()).unwrap(),
                u32::from(FsInformationClass::Device),
            ),
            NtStatus::INVALID_HANDLE
        );
        assert_eq!(io_status.status, NtStatus::INVALID_HANDLE.as_raw());
        assert_eq!(io_status.information, 0);
    }

    fn wide(value: &str) -> alloc::vec::Vec<u16> {
        value.encode_utf16().collect()
    }

    fn open_nt_file(
        task: &Task<crate::DefaultFS>,
        path: &str,
    ) -> (Handle, IoStatusBlock, NtStatus) {
        let mut file_handle = Handle::default();
        let mut io_status = IoStatusBlock {
            status: NtStatus::OBJECT_NAME_NOT_FOUND.as_raw(),
            _padding: u32::MAX,
            information: 0,
        };
        let path = wide(path);
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

        let status = task.handle_nt_open_file(
            mut_ptr(&mut file_handle),
            0x12019f,
            Some(const_ptr(&object_attributes)),
            mut_ptr(&mut io_status),
            0x7,
            0x20,
        );
        (file_handle, io_status, status)
    }

    fn file_status(task: &Task<crate::DefaultFS>, handle: Handle) -> litebox::fs::FileStatus {
        let raw_fd = handle.raw_fd().unwrap();
        let fd = task
            .process
            .handles
            .read()
            .fd_from_raw_integer::<crate::DefaultFS>(raw_fd)
            .unwrap();
        task.fs.fd_file_status(&fd).unwrap()
    }
}
