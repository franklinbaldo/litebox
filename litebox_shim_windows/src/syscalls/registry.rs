// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use int_enum::IntEnum;
use litebox::LiteBox;
use litebox::fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry};
use litebox::fs::errors::{
    FileStatusError, MkdirError, OpenError, PathError, ReadError, WriteError,
};
use litebox::fs::{FileSystem as _, FileType, Mode, OFlags};
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox_common_windows::nt_status::NtStatus;
use litebox_platform_multiplex::Platform;

use crate::loader::nt_types::UnicodeString;
use crate::{Handle, NtShimFS, Task, insert_raw_handle, raw_handle_entry, remove_raw_handle};

use super::object::{ObjectAttributes, read_object_attributes};

pub(crate) struct RegistryKeySubsystem;

impl FdEnabledSubsystem for RegistryKeySubsystem {
    type Entry = RegistryKeyObject;
}

impl FdEnabledSubsystemEntry for RegistryKeyObject {}

pub(crate) struct RegistryKeyObject {
    path: String,
}

pub(crate) type RegistryFileSystem = litebox::fs::layered::FileSystem<
    Platform,
    litebox::fs::in_mem::FileSystem<Platform>,
    litebox::fs::tar_ro::FileSystem<Platform>,
>;

pub(crate) struct RegistryStore {
    fs: RegistryFileSystem,
}

const VALUES_DIR_NAME: &str = ".values";
const DEFAULT_CODE_PAGE_KEY: &str =
    "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Nls\\CodePage";
const DEFAULT_ACP_VALUE: &[u8] = &[b'1', 0, b'2', 0, b'5', 0, b'2', 0, 0, 0];
const DEFAULT_OEMCP_VALUE: &[u8] = &[b'4', 0, b'3', 0, b'7', 0, 0, 0];
const DEFAULT_MACCP_VALUE: &[u8] = &[b'1', 0, b'0', 0, b'0', 0, b'0', 0, b'0', 0, 0, 0];
const REG_SZ: u32 = 1;
const REGISTRY_VALUE_TYPE_SIZE: usize = core::mem::size_of::<u32>();
const KEY_VALUE_BASIC_INFORMATION_NAME_OFFSET: usize = 12;
const KEY_VALUE_FULL_INFORMATION_NAME_OFFSET: usize = 20;
const KEY_VALUE_PARTIAL_INFORMATION_DATA_OFFSET: usize = 12;

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, IntEnum)]
enum KeyValueInformationClass {
    Basic = 0,
    Full = 1,
    Partial = 2,
}

struct RegistryValue {
    value_type: u32,
    data: Vec<u8>,
}

impl RegistryStore {
    pub(crate) fn new(litebox: &LiteBox<Platform>) -> Self {
        let mut in_mem = litebox::fs::in_mem::FileSystem::new(litebox);
        in_mem.with_root_privileges(|fs| {
            write_value_in_fs(fs, DEFAULT_CODE_PAGE_KEY, "ACP", REG_SZ, DEFAULT_ACP_VALUE)
                .expect("default ACP registry value can be initialized");
            write_value_in_fs(
                fs,
                DEFAULT_CODE_PAGE_KEY,
                "OEMCP",
                REG_SZ,
                DEFAULT_OEMCP_VALUE,
            )
            .expect("default OEMCP registry value can be initialized");
            write_value_in_fs(
                fs,
                DEFAULT_CODE_PAGE_KEY,
                "MACCP",
                REG_SZ,
                DEFAULT_MACCP_VALUE,
            )
            .expect("default MACCP registry value can be initialized");
        });

        let fs = litebox::fs::layered::FileSystem::new(
            litebox,
            in_mem,
            litebox::fs::tar_ro::FileSystem::new(
                litebox,
                litebox::fs::tar_ro::EMPTY_TAR_FILE.into(),
            ),
            litebox::fs::layered::LayeringSemantics::LowerLayerReadOnly,
        );

        Self { fs }
    }

    fn key_exists(&self, path: &str) -> Result<bool, NtStatus> {
        match self.fs.file_status(path) {
            Ok(status) => Ok(status.file_type == FileType::Directory),
            Err(FileStatusError::PathError(
                PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
            )) => Ok(false),
            Err(FileStatusError::PathError(PathError::ComponentNotADirectory)) => {
                Err(NtStatus::NOT_A_DIRECTORY)
            }
            Err(FileStatusError::PathError(PathError::InvalidPathname)) => {
                Err(NtStatus::INVALID_PARAMETER)
            }
            Err(_) => Err(NtStatus::UNSUCCESSFUL),
        }
    }

    fn read_value(&self, key_path: &str, value_name: &str) -> Result<RegistryValue, NtStatus> {
        let value_path = value_path(key_path, value_name)?;
        let status = self
            .fs
            .file_status(&*value_path)
            .map_err(map_file_status_error)?;
        if status.file_type != FileType::RegularFile {
            return Err(NtStatus::OBJECT_TYPE_MISMATCH);
        }
        if status.size < REGISTRY_VALUE_TYPE_SIZE {
            return Err(NtStatus::END_OF_FILE);
        }

        let fd = self
            .fs
            .open(&*value_path, OFlags::RDONLY, Mode::empty())
            .map_err(map_open_error)?;
        let mut data = vec![0; status.size];
        let read = self
            .fs
            .read(&fd, &mut data, Some(0))
            .map_err(map_read_error)?;
        let _ = self.fs.close(&fd);
        if read != data.len() {
            return Err(NtStatus::END_OF_FILE);
        }

        let value_type = u32::from_le_bytes(
            data[..REGISTRY_VALUE_TYPE_SIZE]
                .try_into()
                .expect("registry value type is exactly u32-sized"),
        );
        let data = data.split_off(REGISTRY_VALUE_TYPE_SIZE);

        Ok(RegistryValue { value_type, data })
    }
}

impl<FS: NtShimFS> Task<FS> {
    pub(crate) fn handle_nt_open_key(
        &self,
        key_handle: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<Handle>,
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
        let path = if object_attributes.root_directory.is_null() || name.starts_with('\\') {
            match absolute_nt_key_name_to_fs_path(&name) {
                Ok(path) => path,
                Err(status) => return status,
            }
        } else {
            let Some(root_key) = raw_handle_entry::<RegistryKeySubsystem>(
                &self.global.litebox,
                &self.process.handles,
                object_attributes.root_directory,
            ) else {
                return NtStatus::INVALID_HANDLE;
            };
            match root_key
                .with_entry(|root_key| relative_nt_key_name_to_fs_path(&root_key.path, &name))
            {
                Ok(path) => path,
                Err(status) => return status,
            }
        };

        match self.global.registry.key_exists(&path) {
            Ok(true) => {}
            Ok(false) => return NtStatus::OBJECT_NAME_NOT_FOUND,
            Err(status) => return status,
        }

        let key = RegistryKeyObject { path: path.clone() };
        let mut descriptor_table = self.global.litebox.descriptor_table_mut();
        let typed = descriptor_table.insert::<RegistryKeySubsystem>(key);
        drop(descriptor_table);
        let handle = match insert_raw_handle(&self.global.litebox, &self.process.handles, typed) {
            Ok(handle) => handle,
            Err(status) => return status,
        };

        if key_handle.write_at_offset(0, handle).is_none() {
            remove_raw_handle::<RegistryKeySubsystem>(
                &self.global.litebox,
                &self.process.handles,
                handle,
            );
            return NtStatus::ACCESS_VIOLATION;
        }

        litebox_util_log::debug!(
            key_handle:% = format_args!("{:#x}", key_handle.as_usize()),
            desired_access:% = format_args!("{desired_access:#x}"),
            root_directory:% = format_args!("{:#x}", object_attributes.root_directory.as_raw()),
            path:% = path;
            "Handled NtOpenKey syscall"
        );

        NtStatus::SUCCESS
    }

    pub(crate) fn handle_nt_query_value_key(
        &self,
        key_handle: Handle,
        value_name: <Platform as litebox::platform::RawPointerProvider>::RawConstPointer<
            UnicodeString,
        >,
        key_value_information_class: u32,
        key_value_information: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<
            u8,
        >,
        length: u32,
        result_length: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<u32>,
    ) -> NtStatus {
        let Some(key) = raw_handle_entry::<RegistryKeySubsystem>(
            &self.global.litebox,
            &self.process.handles,
            key_handle,
        ) else {
            return NtStatus::INVALID_HANDLE;
        };

        let value_name = match read_unicode_string_pointer(value_name) {
            Ok(value_name) => value_name,
            Err(status) => return status,
        };
        let value =
            match key.with_entry(|key| self.global.registry.read_value(&key.path, &value_name)) {
                Ok(value) => value,
                Err(status) => return status,
            };
        let Ok(key_value_information_class) =
            KeyValueInformationClass::try_from(key_value_information_class)
        else {
            litebox_util_log::debug!(
                key_value_information_class = key_value_information_class;
                "Unsupported NtQueryValueKey class"
            );
            return NtStatus::INVALID_INFO_CLASS;
        };

        let name = utf16le(&value_name);
        let status = match key_value_information_class {
            KeyValueInformationClass::Basic => write_key_value_basic_information(
                key_value_information,
                length,
                result_length,
                value.value_type,
                &name,
            ),
            KeyValueInformationClass::Full => write_key_value_full_information(
                key_value_information,
                length,
                result_length,
                value.value_type,
                &name,
                &value.data,
            ),
            KeyValueInformationClass::Partial => write_key_value_partial_information(
                key_value_information,
                length,
                result_length,
                value.value_type,
                &value.data,
            ),
        };

        litebox_util_log::debug!(
            handle:% = format_args!("{:#x}", key_handle.as_raw()),
            value_name:% = value_name,
            key_value_information_class:? = key_value_information_class,
            length = length,
            status:? = status;
            "Handled NtQueryValueKey syscall"
        );

        status
    }
}

fn read_unicode_string(unicode_string: usize) -> Result<String, NtStatus> {
    let unicode_string = <Platform as litebox::platform::RawPointerProvider>::RawConstPointer::<
        UnicodeString,
    >::from_usize(unicode_string);
    read_unicode_string_pointer(unicode_string)
}

fn read_unicode_string_pointer(
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

fn write_key_value_basic_information(
    key_value_information: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<u8>,
    length: u32,
    result_length: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<u32>,
    value_type: u32,
    name: &[u8],
) -> NtStatus {
    let required_length = KEY_VALUE_BASIC_INFORMATION_NAME_OFFSET + name.len();
    let Ok(required_length) = u32::try_from(required_length) else {
        return NtStatus::UNSUCCESSFUL;
    };
    if result_length.write_at_offset(0, required_length).is_none() {
        return NtStatus::ACCESS_VIOLATION;
    }
    if length < required_length {
        return NtStatus::BUFFER_OVERFLOW;
    }

    write_output_u32(key_value_information, 0, 0)
        .and_then(|()| write_output_u32(key_value_information, 4, value_type))
        .and_then(|()| write_output_u32(key_value_information, 8, u32::try_from(name.len()).ok()?))
        .and_then(|()| {
            write_output_bytes(
                key_value_information,
                KEY_VALUE_BASIC_INFORMATION_NAME_OFFSET,
                name,
            )
        })
        .map_or(NtStatus::ACCESS_VIOLATION, |()| NtStatus::SUCCESS)
}

fn write_key_value_full_information(
    key_value_information: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<u8>,
    length: u32,
    result_length: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<u32>,
    value_type: u32,
    name: &[u8],
    data: &[u8],
) -> NtStatus {
    let data_offset = align_up(KEY_VALUE_FULL_INFORMATION_NAME_OFFSET + name.len(), 4);
    let Some(required_length) = data_offset.checked_add(data.len()) else {
        return NtStatus::UNSUCCESSFUL;
    };
    let Ok(required_length) = u32::try_from(required_length) else {
        return NtStatus::UNSUCCESSFUL;
    };
    if result_length.write_at_offset(0, required_length).is_none() {
        return NtStatus::ACCESS_VIOLATION;
    }
    if length < required_length {
        return NtStatus::BUFFER_OVERFLOW;
    }

    write_output_u32(key_value_information, 0, 0)
        .and_then(|()| write_output_u32(key_value_information, 4, value_type))
        .and_then(|()| write_output_u32(key_value_information, 8, u32::try_from(data_offset).ok()?))
        .and_then(|()| write_output_u32(key_value_information, 12, u32::try_from(data.len()).ok()?))
        .and_then(|()| write_output_u32(key_value_information, 16, u32::try_from(name.len()).ok()?))
        .and_then(|()| {
            write_output_bytes(
                key_value_information,
                KEY_VALUE_FULL_INFORMATION_NAME_OFFSET,
                name,
            )
        })
        .and_then(|()| write_output_bytes(key_value_information, data_offset, data))
        .map_or(NtStatus::ACCESS_VIOLATION, |()| NtStatus::SUCCESS)
}

fn write_key_value_partial_information(
    key_value_information: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<u8>,
    length: u32,
    result_length: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<u32>,
    value_type: u32,
    data: &[u8],
) -> NtStatus {
    let required_length = KEY_VALUE_PARTIAL_INFORMATION_DATA_OFFSET + data.len();
    let Ok(required_length) = u32::try_from(required_length) else {
        return NtStatus::UNSUCCESSFUL;
    };
    if result_length.write_at_offset(0, required_length).is_none() {
        return NtStatus::ACCESS_VIOLATION;
    }
    if length < required_length {
        return NtStatus::BUFFER_OVERFLOW;
    }

    write_output_u32(key_value_information, 0, 0)
        .and_then(|()| write_output_u32(key_value_information, 4, value_type))
        .and_then(|()| write_output_u32(key_value_information, 8, u32::try_from(data.len()).ok()?))
        .and_then(|()| {
            write_output_bytes(
                key_value_information,
                KEY_VALUE_PARTIAL_INFORMATION_DATA_OFFSET,
                data,
            )
        })
        .map_or(NtStatus::ACCESS_VIOLATION, |()| NtStatus::SUCCESS)
}

fn write_output_u32(
    output: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<u8>,
    offset: usize,
    value: u32,
) -> Option<()> {
    write_output_bytes(output, offset, &value.to_le_bytes())
}

fn write_output_bytes(
    output: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<u8>,
    offset: usize,
    bytes: &[u8],
) -> Option<()> {
    for (index, byte) in bytes.iter().copied().enumerate() {
        let offset = isize::try_from(offset.checked_add(index)?).ok()?;
        output.write_at_offset(offset, byte)?;
    }
    Some(())
}

fn utf16le(value: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for code_unit in value.encode_utf16() {
        bytes.extend_from_slice(&code_unit.to_le_bytes());
    }
    bytes
}

const fn align_up(value: usize, align: usize) -> usize {
    value.div_ceil(align) * align
}

fn absolute_nt_key_name_to_fs_path(name: &str) -> Result<String, NtStatus> {
    if !name.starts_with('\\') {
        return Err(NtStatus::INVALID_PARAMETER);
    }
    let mut path = String::from("/");
    append_registry_components(&mut path, name.trim_start_matches('\\'))?;
    Ok(path)
}

fn relative_nt_key_name_to_fs_path(root: &str, name: &str) -> Result<String, NtStatus> {
    if name.starts_with('\\') {
        return absolute_nt_key_name_to_fs_path(name);
    }
    let mut path = String::from(root);
    append_registry_components(&mut path, name)?;
    Ok(path)
}

fn append_registry_components(path: &mut String, name: &str) -> Result<(), NtStatus> {
    if name.is_empty() {
        return Err(NtStatus::INVALID_PARAMETER);
    }
    for component in name.split('\\') {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component == VALUES_DIR_NAME
            || component.contains('/')
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        if !path.ends_with('/') {
            path.push('/');
        }
        path.push_str(component);
    }
    Ok(())
}

fn write_value_in_fs<FS: litebox::fs::FileSystem>(
    fs: &FS,
    key_nt_path: &str,
    value_name: &str,
    value_type: u32,
    value: &[u8],
) -> Result<(), NtStatus> {
    let key_path = create_key_in_fs(fs, key_nt_path)?;
    let value_path = value_path(&key_path, value_name)?;
    let fd = fs
        .open(
            &*value_path,
            OFlags::CREAT | OFlags::WRONLY | OFlags::TRUNC,
            Mode::RUSR | Mode::WUSR | Mode::ROTH | Mode::WOTH,
        )
        .map_err(map_open_error)?;
    let written = fs
        .write(&fd, &value_type.to_le_bytes(), Some(0))
        .map_err(map_write_error)?;
    if written != REGISTRY_VALUE_TYPE_SIZE {
        return Err(NtStatus::DISK_FULL);
    }
    let written = fs
        .write(&fd, value, Some(REGISTRY_VALUE_TYPE_SIZE))
        .map_err(map_write_error)?;
    if written != value.len() {
        return Err(NtStatus::DISK_FULL);
    }
    let _ = fs.close(&fd);
    Ok(())
}

fn create_key_in_fs<FS: litebox::fs::FileSystem>(
    fs: &FS,
    nt_path: &str,
) -> Result<String, NtStatus> {
    let path = absolute_nt_key_name_to_fs_path(nt_path)?;
    create_key_path_in_fs(fs, &path)?;
    Ok(path)
}

fn create_key_path_in_fs<FS: litebox::fs::FileSystem>(fs: &FS, path: &str) -> Result<(), NtStatus> {
    let mut current = String::new();
    for component in path.trim_start_matches('/').split('/') {
        if component.is_empty() {
            continue;
        }
        current.push('/');
        current.push_str(component);
        ensure_directory_in_fs(fs, &current)?;

        let mut values_dir = current.clone();
        values_dir.push('/');
        values_dir.push_str(VALUES_DIR_NAME);
        ensure_directory_in_fs(fs, &values_dir)?;
    }
    Ok(())
}

fn ensure_directory_in_fs<FS: litebox::fs::FileSystem>(
    fs: &FS,
    path: &str,
) -> Result<(), NtStatus> {
    match fs.file_status(path) {
        Ok(status) if status.file_type == FileType::Directory => Ok(()),
        Ok(_) => Err(NtStatus::OBJECT_TYPE_MISMATCH),
        Err(FileStatusError::PathError(
            PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
        )) => match fs.mkdir(
            path,
            Mode::RUSR | Mode::WUSR | Mode::XUSR | Mode::ROTH | Mode::WOTH | Mode::XOTH,
        ) {
            Ok(()) | Err(MkdirError::AlreadyExists) => Ok(()),
            Err(error) => Err(map_mkdir_error(error)),
        },
        Err(FileStatusError::PathError(PathError::ComponentNotADirectory)) => {
            Err(NtStatus::NOT_A_DIRECTORY)
        }
        Err(FileStatusError::PathError(PathError::InvalidPathname)) => {
            Err(NtStatus::INVALID_PARAMETER)
        }
        Err(_) => Err(NtStatus::UNSUCCESSFUL),
    }
}

fn value_path(key_path: &str, value_name: &str) -> Result<String, NtStatus> {
    if value_name.is_empty()
        || value_name == "."
        || value_name == ".."
        || value_name.contains('/')
        || value_name.contains('\\')
    {
        return Err(NtStatus::INVALID_PARAMETER);
    }

    let mut path = String::from(key_path);
    if !path.ends_with('/') {
        path.push('/');
    }
    path.push_str(VALUES_DIR_NAME);
    path.push('/');
    path.push_str(value_name);
    Ok(path)
}

fn map_open_error(error: OpenError) -> NtStatus {
    match error {
        OpenError::PathError(PathError::NoSuchFileOrDirectory | PathError::MissingComponent) => {
            NtStatus::OBJECT_NAME_NOT_FOUND
        }
        OpenError::PathError(PathError::ComponentNotADirectory) => NtStatus::NOT_A_DIRECTORY,
        OpenError::PathError(PathError::InvalidPathname) => NtStatus::INVALID_PARAMETER,
        OpenError::AccessNotAllowed | OpenError::NoWritePerms | OpenError::ReadOnlyFileSystem => {
            NtStatus::ACCESS_DENIED
        }
        OpenError::AlreadyExists => NtStatus::OBJECT_NAME_COLLISION,
        _ => NtStatus::UNSUCCESSFUL,
    }
}

fn map_file_status_error(error: FileStatusError) -> NtStatus {
    match error {
        FileStatusError::PathError(
            PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
        ) => NtStatus::OBJECT_NAME_NOT_FOUND,
        FileStatusError::PathError(PathError::ComponentNotADirectory) => NtStatus::NOT_A_DIRECTORY,
        FileStatusError::PathError(PathError::InvalidPathname) => NtStatus::INVALID_PARAMETER,
        _ => NtStatus::UNSUCCESSFUL,
    }
}

fn map_mkdir_error(error: MkdirError) -> NtStatus {
    match error {
        MkdirError::AlreadyExists => NtStatus::OBJECT_NAME_COLLISION,
        MkdirError::PathError(PathError::NoSuchFileOrDirectory | PathError::MissingComponent) => {
            NtStatus::OBJECT_PATH_NOT_FOUND
        }
        MkdirError::PathError(PathError::ComponentNotADirectory) => NtStatus::NOT_A_DIRECTORY,
        MkdirError::PathError(PathError::InvalidPathname) => NtStatus::INVALID_PARAMETER,
        MkdirError::NoWritePerms | MkdirError::ReadOnlyFileSystem => NtStatus::ACCESS_DENIED,
        _ => NtStatus::UNSUCCESSFUL,
    }
}

fn map_write_error(error: WriteError) -> NtStatus {
    match error {
        WriteError::NotForWriting => NtStatus::ACCESS_DENIED,
        WriteError::NotAFile => NtStatus::OBJECT_TYPE_MISMATCH,
        _ => NtStatus::UNSUCCESSFUL,
    }
}

fn map_read_error(error: ReadError) -> NtStatus {
    match error {
        ReadError::NotForReading => NtStatus::ACCESS_DENIED,
        ReadError::NotAFile => NtStatus::OBJECT_TYPE_MISMATCH,
        _ => NtStatus::UNSUCCESSFUL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GlobalState, Process, WindowsHandleStore, WindowsPageManager};
    use alloc::sync::Arc;
    use core::marker::PhantomData;
    use core::mem::size_of;
    use core::sync::atomic::AtomicI32;
    use litebox::LiteBox;
    use litebox::fd::RawDescriptorStorage;
    use litebox::platform::{RawPointerProvider, TimeProvider as _};
    use litebox_common_windows::loader::MappingInfo;
    use zerocopy::{FromBytes, IntoBytes};

    extern crate std;

    type ConstPtr<T> = <Platform as RawPointerProvider>::RawConstPointer<T>;
    type MutPtr<T> = <Platform as RawPointerProvider>::RawMutPointer<T>;

    fn init_platform() {
        crate::tests::init_platform();
    }

    fn const_ptr<T: FromBytes>(value: &T) -> ConstPtr<T> {
        ConstPtr::from_usize(core::ptr::from_ref(value).cast::<u8>() as usize)
    }

    fn mut_ptr<T: FromBytes + IntoBytes>(value: &mut T) -> MutPtr<T> {
        MutPtr::from_usize(core::ptr::from_mut(value).cast::<u8>() as usize)
    }

    fn mut_byte_ptr<T>(value: &mut T) -> MutPtr<u8> {
        MutPtr::from_usize(core::ptr::from_mut(value).cast::<u8>() as usize)
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

    fn test_registry() -> (LiteBox<Platform>, RegistryStore) {
        init_platform();
        let litebox = LiteBox::new(litebox_platform_multiplex::platform());
        let registry = RegistryStore::new(&litebox);
        (litebox, registry)
    }

    fn test_task() -> Task<crate::DefaultFS> {
        init_platform();
        let platform = litebox_platform_multiplex::platform();
        let litebox = LiteBox::new(platform);
        let page_manager = WindowsPageManager::new(&litebox);
        Task {
            global: Arc::new(GlobalState {
                platform,
                registry: RegistryStore::new(&litebox),
                litebox,
                page_manager,
                qpc_boot_instant: platform.now(),
                _fs: PhantomData,
            }),
            process: Arc::new(Process {
                mapping: MappingInfo {
                    base_addr: 0,
                    image_size: 0,
                    entry_point: 0,
                },
                _ntdll_mapping: None,
                handles: WindowsHandleStore::new(RawDescriptorStorage::new()),
                peb_address: 0,
                cookie: 1,
                exit_code: AtomicI32::new(0),
            }),
            entry_point: 0,
            stack_top: 0,
            teb_address: 0,
        }
    }

    fn open_key(
        task: &Task<crate::DefaultFS>,
        handle: &mut Handle,
        object_attributes: &ObjectAttributes,
    ) -> NtStatus {
        task.handle_nt_open_key(mut_ptr(handle), 0x20019, Some(const_ptr(object_attributes)))
    }

    fn open_code_page_key(task: &Task<crate::DefaultFS>) -> Handle {
        let code_page_name: std::vec::Vec<u16> = DEFAULT_CODE_PAGE_KEY.encode_utf16().collect();
        let code_page_name = unicode_string(&code_page_name);
        let object_attributes = object_attributes(&code_page_name);
        let mut handle = Handle::default();
        assert_eq!(
            open_key(task, &mut handle, &object_attributes),
            NtStatus::SUCCESS
        );
        handle
    }

    fn class_value(class: KeyValueInformationClass) -> u32 {
        class as u32
    }

    fn read_u32(buffer: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(
            buffer[offset..offset + size_of::<u32>()]
                .try_into()
                .unwrap(),
        )
    }

    #[test]
    fn registry_store_separates_values_from_subkeys() {
        let (_litebox, registry) = test_registry();
        let key_path = absolute_nt_key_name_to_fs_path(DEFAULT_CODE_PAGE_KEY).unwrap();
        let value_path = value_path(&key_path, "ACP").unwrap();

        assert_eq!(registry.key_exists(&key_path), Ok(true));
        assert_eq!(
            registry.fs.file_status(&*value_path).unwrap().file_type,
            FileType::RegularFile
        );
        assert_eq!(
            registry.fs.file_status(&*value_path).unwrap().size,
            REGISTRY_VALUE_TYPE_SIZE + DEFAULT_ACP_VALUE.len()
        );
        let value = registry.read_value(&key_path, "ACP").unwrap();
        assert_eq!(value.value_type, REG_SZ);
        assert_eq!(value.data, DEFAULT_ACP_VALUE);

        let values_dir = absolute_nt_key_name_to_fs_path(
            "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Nls\\CodePage\\.values",
        );
        assert_eq!(values_dir, Err(NtStatus::INVALID_PARAMETER));
    }

    #[test]
    fn nt_open_key_opens_existing_absolute_and_relative_keys() {
        let task = test_task();
        let nls_name: std::vec::Vec<u16> =
            "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Nls"
                .encode_utf16()
                .collect();
        let nls_name = unicode_string(&nls_name);
        let nls_object_attributes = object_attributes(&nls_name);
        let mut nls_handle = Handle::default();

        assert_eq!(
            open_key(&task, &mut nls_handle, &nls_object_attributes,),
            NtStatus::SUCCESS
        );
        assert_ne!(nls_handle, Handle::default());

        let code_page_name: std::vec::Vec<u16> = "CodePage".encode_utf16().collect();
        let code_page_name = unicode_string(&code_page_name);
        let mut code_page_object_attributes = object_attributes(&code_page_name);
        code_page_object_attributes.root_directory = nls_handle;
        let mut code_page_handle = Handle::default();

        assert_eq!(
            open_key(&task, &mut code_page_handle, &code_page_object_attributes,),
            NtStatus::SUCCESS
        );
        assert_ne!(code_page_handle, Handle::default());
    }

    #[test]
    fn nt_open_key_reports_missing_absolute_key() {
        let task = test_task();
        let name: std::vec::Vec<u16> = "\\Registry\\Machine\\Software".encode_utf16().collect();
        let name = unicode_string(&name);
        let object_attributes = object_attributes(&name);
        let mut handle = Handle::default();

        assert_eq!(
            open_key(&task, &mut handle, &object_attributes,),
            NtStatus::OBJECT_NAME_NOT_FOUND
        );
        assert_eq!(handle, Handle::default());
    }

    #[test]
    fn nt_open_key_rejects_invalid_object_attributes() {
        let task = test_task();
        let name: std::vec::Vec<u16> = "\\Registry\\Machine".encode_utf16().collect();
        let name = unicode_string(&name);
        let mut object_attributes = object_attributes(&name);
        let mut handle = Handle::default();

        assert_eq!(
            task.handle_nt_open_key(mut_ptr(&mut handle), 0, None),
            NtStatus::INVALID_PARAMETER
        );

        object_attributes.length = 0;
        assert_eq!(
            task.handle_nt_open_key(mut_ptr(&mut handle), 0, Some(const_ptr(&object_attributes)),),
            NtStatus::INVALID_PARAMETER
        );
    }

    #[test]
    fn nt_open_key_rejects_invalid_relative_root() {
        let task = test_task();
        let name: std::vec::Vec<u16> = "Child".encode_utf16().collect();
        let name = unicode_string(&name);
        let mut object_attributes = object_attributes(&name);
        object_attributes.root_directory = Handle::from_raw(0x1234);
        let mut handle = Handle::default();

        assert_eq!(
            task.handle_nt_open_key(mut_ptr(&mut handle), 0, Some(const_ptr(&object_attributes)),),
            NtStatus::INVALID_HANDLE
        );
    }

    #[test]
    fn nt_query_value_key_reports_partial_information() {
        let task = test_task();
        let key_handle = open_code_page_key(&task);
        let value_name: std::vec::Vec<u16> = "ACP".encode_utf16().collect();
        let value_name = unicode_string(&value_name);
        let mut information = [0u8; 64];
        let mut result_length = 0;

        assert_eq!(
            task.handle_nt_query_value_key(
                key_handle,
                const_ptr(&value_name),
                class_value(KeyValueInformationClass::Partial),
                mut_byte_ptr(&mut information),
                u32::try_from(information.len()).unwrap(),
                mut_ptr(&mut result_length),
            ),
            NtStatus::SUCCESS
        );

        assert_eq!(result_length, 22);
        assert_eq!(read_u32(&information, 0), 0);
        assert_eq!(read_u32(&information, 4), REG_SZ);
        assert_eq!(
            read_u32(&information, 8),
            u32::try_from(DEFAULT_ACP_VALUE.len()).unwrap()
        );
        assert_eq!(
            &information[KEY_VALUE_PARTIAL_INFORMATION_DATA_OFFSET
                ..KEY_VALUE_PARTIAL_INFORMATION_DATA_OFFSET + DEFAULT_ACP_VALUE.len()],
            DEFAULT_ACP_VALUE
        );
    }

    #[test]
    fn nt_query_value_key_reports_basic_and_full_information() {
        let task = test_task();
        let key_handle = open_code_page_key(&task);
        let value_name: std::vec::Vec<u16> = "OEMCP".encode_utf16().collect();
        let value_name = unicode_string(&value_name);
        let mut basic_information = [0u8; 64];
        let mut full_information = [0u8; 64];
        let mut result_length = 0;

        assert_eq!(
            task.handle_nt_query_value_key(
                key_handle,
                const_ptr(&value_name),
                class_value(KeyValueInformationClass::Basic),
                mut_byte_ptr(&mut basic_information),
                u32::try_from(basic_information.len()).unwrap(),
                mut_ptr(&mut result_length),
            ),
            NtStatus::SUCCESS
        );
        let name = utf16le("OEMCP");
        assert_eq!(
            result_length,
            u32::try_from(KEY_VALUE_BASIC_INFORMATION_NAME_OFFSET + name.len()).unwrap()
        );
        assert_eq!(read_u32(&basic_information, 4), REG_SZ);
        assert_eq!(
            read_u32(&basic_information, 8),
            u32::try_from(name.len()).unwrap()
        );
        assert_eq!(
            &basic_information[KEY_VALUE_BASIC_INFORMATION_NAME_OFFSET
                ..KEY_VALUE_BASIC_INFORMATION_NAME_OFFSET + name.len()],
            name.as_slice()
        );

        assert_eq!(
            task.handle_nt_query_value_key(
                key_handle,
                const_ptr(&value_name),
                class_value(KeyValueInformationClass::Full),
                mut_byte_ptr(&mut full_information),
                u32::try_from(full_information.len()).unwrap(),
                mut_ptr(&mut result_length),
            ),
            NtStatus::SUCCESS
        );
        let data_offset = usize::try_from(read_u32(&full_information, 8)).unwrap();
        assert_eq!(read_u32(&full_information, 4), REG_SZ);
        assert_eq!(
            read_u32(&full_information, 12),
            u32::try_from(DEFAULT_OEMCP_VALUE.len()).unwrap()
        );
        assert_eq!(
            read_u32(&full_information, 16),
            u32::try_from(name.len()).unwrap()
        );
        assert_eq!(
            &full_information[KEY_VALUE_FULL_INFORMATION_NAME_OFFSET
                ..KEY_VALUE_FULL_INFORMATION_NAME_OFFSET + name.len()],
            name.as_slice()
        );
        assert_eq!(
            &full_information[data_offset..data_offset + DEFAULT_OEMCP_VALUE.len()],
            DEFAULT_OEMCP_VALUE
        );
    }

    #[test]
    fn nt_query_value_key_rejects_invalid_arguments() {
        let task = test_task();
        let key_handle = open_code_page_key(&task);
        let value_name: std::vec::Vec<u16> = "ACP".encode_utf16().collect();
        let value_name = unicode_string(&value_name);
        let missing_value_name: std::vec::Vec<u16> = "Missing".encode_utf16().collect();
        let missing_value_name = unicode_string(&missing_value_name);
        let mut information = [0u8; 64];
        let mut short_information = [0u8; KEY_VALUE_PARTIAL_INFORMATION_DATA_OFFSET - 1];
        let mut result_length = 0;

        assert_eq!(
            task.handle_nt_query_value_key(
                Handle::from_raw(0x1234),
                const_ptr(&value_name),
                class_value(KeyValueInformationClass::Partial),
                mut_byte_ptr(&mut information),
                u32::try_from(information.len()).unwrap(),
                mut_ptr(&mut result_length),
            ),
            NtStatus::INVALID_HANDLE
        );

        assert_eq!(
            task.handle_nt_query_value_key(
                key_handle,
                const_ptr(&missing_value_name),
                class_value(KeyValueInformationClass::Partial),
                mut_byte_ptr(&mut information),
                u32::try_from(information.len()).unwrap(),
                mut_ptr(&mut result_length),
            ),
            NtStatus::OBJECT_NAME_NOT_FOUND
        );

        assert_eq!(
            task.handle_nt_query_value_key(
                key_handle,
                const_ptr(&value_name),
                0xffff,
                mut_byte_ptr(&mut information),
                u32::try_from(information.len()).unwrap(),
                mut_ptr(&mut result_length),
            ),
            NtStatus::INVALID_INFO_CLASS
        );

        assert_eq!(
            task.handle_nt_query_value_key(
                key_handle,
                const_ptr(&value_name),
                class_value(KeyValueInformationClass::Partial),
                mut_byte_ptr(&mut short_information),
                u32::try_from(short_information.len()).unwrap(),
                mut_ptr(&mut result_length),
            ),
            NtStatus::BUFFER_OVERFLOW
        );
        assert_eq!(result_length, 22);
    }
}
