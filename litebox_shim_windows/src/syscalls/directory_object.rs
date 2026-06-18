// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows NT object directory syscalls.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::mem::size_of;

use litebox::fd::{ErrRawIntFd, FdEnabledSubsystem, FdEnabledSubsystemEntry};
use litebox::platform::{RawConstPointer as _, RawMutPointer as _, RawPointerProvider};
use litebox_common_windows::nt_status::NtStatus;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::nt_types::{AccessMask, ObjectAttributes, UnicodeString, read_object_attributes};
use crate::syscalls::Handle;
use crate::{
    ConstPtr, MutPtr, ShimFS, Task, insert_raw_handle, probe_guest_output_preserving_value,
    remove_raw_handle,
};

const OBJ_OPENLINK: u32 = 0x0000_0100;
const WCHAR_SIZE: usize = size_of::<u16>();
const WCHAR_SIZE_U16: u16 = 2;

const DIRECTORY_TYPE_NAME: &str = "Directory";
const SYMBOLIC_LINK_TYPE_NAME: &str = "SymbolicLink";
const PREDEFINED_SYMBOLIC_LINKS: &[(&str, &str)] = &[
    (r"\??\C:", r"\Device\HarddiskVolume1"),
    (r"\??\NUL", r"\Device\Null"),
    (r"\Global??\C:", r"\Device\HarddiskVolume1"),
    (r"\Global??\NUL", r"\Device\Null"),
    (r"\KnownDlls\KnownDllPath", r"C:\Windows\System32"),
    (r"\KnownDlls32\KnownDllPath", r"C:\Windows\SysWOW64"),
];
const PREDEFINED_DIRECTORIES: &[&str] = &[
    r"\",
    r"\??",
    r"\BaseNamedObjects",
    r"\Device",
    r"\Global??",
    r"\KnownDlls",
    r"\KnownDlls32",
    r"\KernelObjects",
    r"\NLS",
    r"\ObjectTypes",
    r"\RPC Control",
    r"\Sessions",
    r"\Sessions\0",
    r"\Sessions\0\BaseNamedObjects",
    r"\Sessions\0\DosDevices",
    r"\Sessions\0\Windows",
    r"\Sessions\0\Windows\WindowStations",
];

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct DirectoryObjectAccess: u32 {
        const QUERY = 0x0001;
        const TRAVERSE = 0x0002;
        const CREATE_OBJECT = 0x0004;
        const CREATE_SUBDIRECTORY = 0x0008;

        const READ = AccessMask::STANDARD_RIGHTS_READ.bits()
            | Self::QUERY.bits()
            | Self::TRAVERSE.bits();
        const WRITE = AccessMask::STANDARD_RIGHTS_WRITE.bits()
            | Self::CREATE_OBJECT.bits()
            | Self::CREATE_SUBDIRECTORY.bits();
        const EXECUTE = AccessMask::STANDARD_RIGHTS_EXECUTE.bits()
            | Self::QUERY.bits()
            | Self::TRAVERSE.bits();
        const ALL_ACCESS = AccessMask::DELETE.bits()
            | AccessMask::READ_CONTROL.bits()
            | AccessMask::WRITE_DAC.bits()
            | AccessMask::WRITE_OWNER.bits()
            | Self::QUERY.bits()
            | Self::TRAVERSE.bits()
            | Self::CREATE_OBJECT.bits()
            | Self::CREATE_SUBDIRECTORY.bits();

        const _ = !0;
    }
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct SymbolicLinkAccess: u32 {
        const QUERY = 0x0001;
        const SET = 0x0002;

        const READ = AccessMask::STANDARD_RIGHTS_READ.bits() | Self::QUERY.bits();
        const WRITE = AccessMask::STANDARD_RIGHTS_WRITE.bits() | Self::SET.bits();
        const EXECUTE = AccessMask::STANDARD_RIGHTS_EXECUTE.bits() | Self::QUERY.bits();
        const ALL_ACCESS = AccessMask::DELETE.bits()
            | AccessMask::READ_CONTROL.bits()
            | AccessMask::WRITE_DAC.bits()
            | AccessMask::WRITE_OWNER.bits()
            | Self::QUERY.bits()
            | Self::SET.bits();

        const _ = !0;
    }
}

impl DirectoryObjectAccess {
    fn from_desired_access(desired_access: u32) -> Self {
        let mut access = Self::from_bits_retain(desired_access);
        if desired_access & AccessMask::GENERIC_READ.bits() != 0 {
            access.insert(Self::READ);
        }
        if desired_access & AccessMask::GENERIC_WRITE.bits() != 0 {
            access.insert(Self::WRITE);
        }
        if desired_access & AccessMask::GENERIC_EXECUTE.bits() != 0 {
            access.insert(Self::EXECUTE);
        }
        if desired_access & AccessMask::GENERIC_ALL.bits() != 0 {
            access.insert(Self::ALL_ACCESS);
        }
        access.remove(Self::from_bits_retain(
            AccessMask::GENERIC_READ.bits()
                | AccessMask::GENERIC_WRITE.bits()
                | AccessMask::GENERIC_EXECUTE.bits()
                | AccessMask::GENERIC_ALL.bits(),
        ));
        access
    }

    fn require(self, required: Self) -> Result<(), NtStatus> {
        if self.contains(required) {
            Ok(())
        } else {
            Err(NtStatus::ACCESS_DENIED)
        }
    }
}

impl SymbolicLinkAccess {
    fn from_desired_access(desired_access: u32) -> Self {
        let mut access = Self::from_bits_retain(desired_access);
        if desired_access & AccessMask::GENERIC_READ.bits() != 0 {
            access.insert(Self::READ);
        }
        if desired_access & AccessMask::GENERIC_WRITE.bits() != 0 {
            access.insert(Self::WRITE);
        }
        if desired_access & AccessMask::GENERIC_EXECUTE.bits() != 0 {
            access.insert(Self::EXECUTE);
        }
        if desired_access & AccessMask::GENERIC_ALL.bits() != 0 {
            access.insert(Self::ALL_ACCESS);
        }
        access.remove(Self::from_bits_retain(
            AccessMask::GENERIC_READ.bits()
                | AccessMask::GENERIC_WRITE.bits()
                | AccessMask::GENERIC_EXECUTE.bits()
                | AccessMask::GENERIC_ALL.bits(),
        ));
        access
    }

    fn require(self, required: Self) -> Result<(), NtStatus> {
        if self.contains(required) {
            Ok(())
        } else {
            Err(NtStatus::ACCESS_DENIED)
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
pub(crate) struct ObjectDirectoryInformation {
    name: UnicodeString,
    type_name: UnicodeString,
}
pub(crate) fn initial_symbolic_link_namespace<Platform: crate::ShimPlatform>()
-> BTreeMap<String, Arc<SymbolicLinkObject<Platform>>> {
    PREDEFINED_SYMBOLIC_LINKS
        .iter()
        .map(|(path, target)| {
            let path =
                normalize_absolute_path(path).expect("predefined symbolic link path is valid");
            (
                directory_key(&path),
                Arc::new(SymbolicLinkObject::new(path, String::from(*target))),
            )
        })
        .collect()
}

const OBJECT_DIRECTORY_INFORMATION_SIZE_U32: u32 = 32;
const _: () = assert!(
    size_of::<ObjectDirectoryInformation>() == OBJECT_DIRECTORY_INFORMATION_SIZE_U32 as usize
);

pub(crate) struct DirectoryObjectSubsystem<Platform>(PhantomData<fn(Platform)>);

impl<Platform: crate::ShimPlatform> FdEnabledSubsystem for DirectoryObjectSubsystem<Platform> {
    type Entry = DirectoryObjectHandleObject<Platform>;
}

impl<Platform: crate::ShimPlatform> FdEnabledSubsystemEntry
    for DirectoryObjectHandleObject<Platform>
{
}

pub(crate) struct DirectoryObjectHandleObject<Platform: crate::ShimPlatform> {
    directory: Arc<DirectoryObject<Platform>>,
    granted_access: DirectoryObjectAccess,
}

pub(crate) struct DirectoryObject<Platform: crate::ShimPlatform> {
    path: Option<String>,
    _platform: PhantomData<fn(Platform)>,
}

impl<Platform: crate::ShimPlatform> DirectoryObject<Platform> {
    fn new(path: Option<String>) -> Self {
        Self {
            path,
            _platform: PhantomData,
        }
    }

    fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }
}

pub(crate) struct SymbolicLinkSubsystem<Platform>(PhantomData<fn(Platform)>);

impl<Platform: crate::ShimPlatform> FdEnabledSubsystem for SymbolicLinkSubsystem<Platform> {
    type Entry = SymbolicLinkHandleObject<Platform>;
}

impl<Platform: crate::ShimPlatform> FdEnabledSubsystemEntry for SymbolicLinkHandleObject<Platform> {}

pub(crate) struct SymbolicLinkHandleObject<Platform: crate::ShimPlatform> {
    link: Arc<SymbolicLinkObject<Platform>>,
    granted_access: SymbolicLinkAccess,
}

pub(crate) struct SymbolicLinkObject<Platform: crate::ShimPlatform> {
    path: String,
    target: String,
    _platform: PhantomData<fn(Platform)>,
}

impl<Platform: crate::ShimPlatform> SymbolicLinkObject<Platform> {
    fn new(path: String, target: String) -> Self {
        Self {
            path,
            target,
            _platform: PhantomData,
        }
    }
}

struct DirectoryName {
    path: String,
}

#[derive(Clone)]
struct DirectoryEntry {
    name: String,
    type_name: &'static str,
}

pub(crate) struct QueryDirectoryObjectParameters<Platform: crate::ShimPlatform> {
    pub(crate) directory_handle: Handle,
    pub(crate) buffer: MutPtr<Platform, u8>,
    pub(crate) length: u32,
    pub(crate) return_single_entry: u8,
    pub(crate) restart_scan: u8,
    pub(crate) context: MutPtr<Platform, u32>,
    pub(crate) return_length: Option<MutPtr<Platform, u32>>,
}

pub(crate) fn initial_directory_namespace<Platform: crate::ShimPlatform>()
-> BTreeMap<String, Arc<DirectoryObject<Platform>>> {
    PREDEFINED_DIRECTORIES
        .iter()
        .map(|path| {
            let path = normalize_absolute_path(path).expect("predefined object directory is valid");
            (
                directory_key(&path),
                Arc::new(DirectoryObject::new(Some(path))),
            )
        })
        .collect()
}

pub(crate) fn directory_key(path: &str) -> String {
    path.to_ascii_lowercase()
}

fn normalize_absolute_path(path: &str) -> Result<String, NtStatus> {
    if !path.starts_with('\\') {
        return Err(NtStatus::OBJECT_PATH_SYNTAX_BAD);
    }
    normalize_path(path)
}

fn normalize_path(path: &str) -> Result<String, NtStatus> {
    if path.is_empty() {
        return Err(NtStatus::OBJECT_NAME_INVALID);
    }
    if path != r"\" && path.as_bytes().windows(2).any(|pair| pair == b"\\\\") {
        return Err(NtStatus::OBJECT_NAME_INVALID);
    }
    let mut components = Vec::new();
    for component in path.split('\\') {
        if component.is_empty() {
            continue;
        }
        components.push(component);
    }
    if components.is_empty() {
        return Ok(String::from(r"\"));
    }
    let mut normalized = String::from(r"\");
    normalized.push_str(&components.join(r"\"));
    Ok(normalized)
}

fn join_directory_path(parent: &str, name: &str) -> Result<String, NtStatus> {
    if name.starts_with('\\') {
        return normalize_absolute_path(name);
    }
    if name.is_empty() || name.split('\\').any(str::is_empty) {
        return Err(NtStatus::OBJECT_NAME_INVALID);
    }
    if parent == r"\" {
        normalize_absolute_path(&alloc::format!(r"\{name}"))
    } else {
        normalize_absolute_path(&alloc::format!(r"{parent}\{name}"))
    }
}

fn parent_path(path: &str) -> Option<&str> {
    if path == r"\" {
        return None;
    }
    let index = path.rfind('\\')?;
    if index == 0 {
        Some(r"\")
    } else {
        Some(&path[..index])
    }
}

fn read_directory_name<Platform: RawPointerProvider>(
    object_name: usize,
) -> Result<String, NtStatus> {
    let unicode_string = ConstPtr::<Platform, UnicodeString>::from_usize(object_name)
        .read_at_offset(0)
        .ok_or(NtStatus::ACCESS_VIOLATION)?;
    if unicode_string.length == 0 || !unicode_string.length.is_multiple_of(2) {
        return Err(NtStatus::OBJECT_NAME_INVALID);
    }
    if unicode_string.buffer == 0 {
        return Err(NtStatus::ACCESS_VIOLATION);
    }
    let name = unicode_string.read_string::<Platform>()?;
    if name.is_empty() {
        return Err(NtStatus::OBJECT_NAME_INVALID);
    }
    Ok(name)
}

fn read_directory_object_attributes<Platform: RawPointerProvider>(
    object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
    require_name: bool,
) -> Result<(Option<ObjectAttributes>, Option<String>), NtStatus> {
    let Some(object_attributes_ptr) = object_attributes else {
        if require_name {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        return Ok((None, None));
    };
    let object_attributes = read_object_attributes::<Platform>(object_attributes_ptr)?;
    if object_attributes.attributes & OBJ_OPENLINK != 0 {
        return Err(NtStatus::INVALID_PARAMETER);
    }
    if object_attributes.object_name == 0 {
        if !object_attributes.root_directory.is_null() {
            return Err(NtStatus::OBJECT_NAME_INVALID);
        }
        if require_name {
            return Err(NtStatus::OBJECT_NAME_INVALID);
        }
        return Ok((Some(object_attributes), None));
    }
    let name = read_directory_name::<Platform>(object_attributes.object_name)?;
    Ok((Some(object_attributes), Some(name)))
}

fn entry_string_bytes(value: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(value.encode_utf16().count() * WCHAR_SIZE);
    for unit in value.encode_utf16() {
        bytes.extend_from_slice(&unit.to_ne_bytes());
    }
    bytes
}

fn checked_offset(value: usize) -> Result<isize, NtStatus> {
    isize::try_from(value).map_err(|_| NtStatus::BUFFER_TOO_SMALL)
}

impl<Platform: crate::ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    fn directory_object_entry(
        &self,
        handle: Handle,
    ) -> Result<litebox::fd::EntryHandle<Platform, DirectoryObjectSubsystem<Platform>>, NtStatus>
    {
        let Some(raw_fd) = handle.raw_fd() else {
            return Err(NtStatus::INVALID_HANDLE);
        };
        let typed = {
            let handles = self.process.handles.read();
            match handles.fd_from_raw_integer::<DirectoryObjectSubsystem<Platform>>(raw_fd) {
                Ok(typed) => typed,
                Err(ErrRawIntFd::NotFound) => return Err(NtStatus::INVALID_HANDLE),
                Err(ErrRawIntFd::InvalidSubsystem) => {
                    return Err(NtStatus::OBJECT_TYPE_MISMATCH);
                }
            }
        };
        self.global
            .litebox
            .descriptor_table()
            .entry_handle(&typed)
            .ok_or(NtStatus::INVALID_HANDLE)
    }

    fn insert_directory_object_handle(
        &self,
        directory: Arc<DirectoryObject<Platform>>,
        granted_access: DirectoryObjectAccess,
    ) -> Result<Handle, NtStatus> {
        let typed = self
            .global
            .litebox
            .descriptor_table_mut()
            .insert::<DirectoryObjectSubsystem<Platform>>(DirectoryObjectHandleObject {
                directory,
                granted_access,
            });
        insert_raw_handle::<Platform, DirectoryObjectSubsystem<Platform>>(
            &self.global.litebox,
            &self.process.handles,
            typed,
            drop,
        )
    }

    pub(crate) fn close_directory_object_handle(&self, handle: Handle) {
        remove_raw_handle::<Platform, DirectoryObjectSubsystem<Platform>>(
            &self.global.litebox,
            &self.process.handles,
            handle,
            drop,
        );
    }

    pub(crate) fn close_directory_object(directory: DirectoryObjectHandleObject<Platform>) {
        drop(directory);
    }

    fn symbolic_link_entry(
        &self,
        handle: Handle,
    ) -> Result<litebox::fd::EntryHandle<Platform, SymbolicLinkSubsystem<Platform>>, NtStatus> {
        let Some(raw_fd) = handle.raw_fd() else {
            return Err(NtStatus::INVALID_HANDLE);
        };
        let typed = {
            let handles = self.process.handles.read();
            match handles.fd_from_raw_integer::<SymbolicLinkSubsystem<Platform>>(raw_fd) {
                Ok(typed) => typed,
                Err(ErrRawIntFd::NotFound) => return Err(NtStatus::INVALID_HANDLE),
                Err(ErrRawIntFd::InvalidSubsystem) => {
                    return Err(NtStatus::OBJECT_TYPE_MISMATCH);
                }
            }
        };
        self.global
            .litebox
            .descriptor_table()
            .entry_handle(&typed)
            .ok_or(NtStatus::INVALID_HANDLE)
    }

    fn insert_symbolic_link_handle(
        &self,
        link: Arc<SymbolicLinkObject<Platform>>,
        granted_access: SymbolicLinkAccess,
    ) -> Result<Handle, NtStatus> {
        let typed = self
            .global
            .litebox
            .descriptor_table_mut()
            .insert::<SymbolicLinkSubsystem<Platform>>(SymbolicLinkHandleObject {
                link,
                granted_access,
            });
        insert_raw_handle::<Platform, SymbolicLinkSubsystem<Platform>>(
            &self.global.litebox,
            &self.process.handles,
            typed,
            drop,
        )
    }

    pub(crate) fn close_symbolic_link_handle(&self, handle: Handle) {
        remove_raw_handle::<Platform, SymbolicLinkSubsystem<Platform>>(
            &self.global.litebox,
            &self.process.handles,
            handle,
            drop,
        );
    }

    pub(crate) fn close_symbolic_link(link: SymbolicLinkHandleObject<Platform>) {
        drop(link);
    }

    fn resolve_directory_name(
        &self,
        object_attributes: &ObjectAttributes,
        name: &str,
    ) -> Result<DirectoryName, NtStatus> {
        if object_attributes.root_directory.is_null() {
            let path = if name.starts_with('\\') {
                normalize_absolute_path(name)?
            } else {
                normalize_absolute_path(&alloc::format!(r"\{name}"))?
            };
            return Ok(DirectoryName { path });
        }
        if name.starts_with('\\') {
            return Ok(DirectoryName {
                path: normalize_absolute_path(name)?,
            });
        }
        let root = self.directory_object_entry(object_attributes.root_directory)?;
        let Some(parent) = root.with_entry(|entry| entry.directory.path().map(String::from)) else {
            return Err(NtStatus::OBJECT_PATH_NOT_FOUND);
        };
        Ok(DirectoryName {
            path: join_directory_path(&parent, name)?,
        })
    }

    fn directory_namespace_lookup(&self, path: &str) -> Option<Arc<DirectoryObject<Platform>>> {
        self.process
            .directory_namespace
            .read()
            .get(&directory_key(path))
            .cloned()
    }

    fn symbolic_link_namespace_lookup(
        &self,
        path: &str,
    ) -> Option<Arc<SymbolicLinkObject<Platform>>> {
        self.process
            .symbolic_link_namespace
            .read()
            .get(&directory_key(path))
            .cloned()
    }

    pub(crate) fn directory_parent_exists(&self, path: &str) -> bool {
        parent_path(path).is_some_and(|parent| self.directory_namespace_lookup(parent).is_some())
    }

    pub(crate) fn sys_nt_create_directory_object(
        &self,
        directory_handle: MutPtr<Platform, Handle>,
        desired_access: u32,
        object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
    ) -> NtStatus {
        if let Err(status) = probe_guest_output_preserving_value::<Platform, _>(directory_handle) {
            return status;
        }
        let (object_attributes, name) =
            match read_directory_object_attributes::<Platform>(object_attributes, false) {
                Ok(value) => value,
                Err(status) => return status,
            };
        let granted_access = DirectoryObjectAccess::from_desired_access(desired_access);
        let directory = if let Some(name) = name {
            let Some(object_attributes) = object_attributes else {
                return NtStatus::INVALID_PARAMETER;
            };
            let directory_name = match self.resolve_directory_name(&object_attributes, &name) {
                Ok(directory_name) => directory_name,
                Err(status) => return status,
            };
            let key = directory_key(&directory_name.path);
            {
                let namespace = self.process.directory_namespace.read();
                if namespace.contains_key(&key) {
                    return NtStatus::OBJECT_NAME_COLLISION;
                }
            }
            if self
                .process
                .symbolic_link_namespace
                .read()
                .contains_key(&key)
            {
                return NtStatus::OBJECT_NAME_COLLISION;
            }
            if !self.directory_parent_exists(&directory_name.path) {
                return NtStatus::OBJECT_PATH_NOT_FOUND;
            }
            let directory = Arc::new(DirectoryObject::new(Some(directory_name.path)));
            self.process
                .directory_namespace
                .write()
                .insert(key, directory.clone());
            directory
        } else {
            Arc::new(DirectoryObject::new(None))
        };

        let Ok(handle) = self.insert_directory_object_handle(directory, granted_access) else {
            return NtStatus::QUOTA_EXCEEDED;
        };
        if directory_handle.write_at_offset(0, handle).is_none() {
            self.close_directory_object_handle(handle);
            return NtStatus::ACCESS_VIOLATION;
        }
        NtStatus::SUCCESS
    }

    pub(crate) fn sys_nt_create_directory_object_ex(
        &self,
        directory_handle: MutPtr<Platform, Handle>,
        desired_access: u32,
        object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
        shadow_directory_handle: Handle,
        flags: u32,
    ) -> NtStatus {
        if let Err(status) = probe_guest_output_preserving_value::<Platform, _>(directory_handle) {
            return status;
        }
        if flags != 0 {
            return NtStatus::INVALID_PARAMETER;
        }
        if !shadow_directory_handle.is_null() {
            match self.directory_object_entry(shadow_directory_handle) {
                Ok(_) => {}
                Err(status) => return status,
            }
        }
        self.sys_nt_create_directory_object(directory_handle, desired_access, object_attributes)
    }

    pub(crate) fn sys_nt_open_directory_object(
        &self,
        directory_handle: MutPtr<Platform, Handle>,
        desired_access: u32,
        object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
    ) -> NtStatus {
        if let Err(status) = probe_guest_output_preserving_value::<Platform, _>(directory_handle) {
            return status;
        }
        let (object_attributes, name) =
            match read_directory_object_attributes::<Platform>(object_attributes, true) {
                Ok(value) => value,
                Err(status) => return status,
            };
        let Some(object_attributes) = object_attributes else {
            return NtStatus::INVALID_PARAMETER;
        };
        let Some(name) = name else {
            return NtStatus::OBJECT_NAME_INVALID;
        };
        let directory_name = match self.resolve_directory_name(&object_attributes, &name) {
            Ok(directory_name) => directory_name,
            Err(status) => return status,
        };
        let Some(directory) = self.directory_namespace_lookup(&directory_name.path) else {
            if self.directory_parent_exists(&directory_name.path) {
                return NtStatus::OBJECT_NAME_NOT_FOUND;
            }
            return NtStatus::OBJECT_PATH_NOT_FOUND;
        };
        let Ok(handle) = self.insert_directory_object_handle(
            directory,
            DirectoryObjectAccess::from_desired_access(desired_access),
        ) else {
            return NtStatus::QUOTA_EXCEEDED;
        };
        if directory_handle.write_at_offset(0, handle).is_none() {
            self.close_directory_object_handle(handle);
            return NtStatus::ACCESS_VIOLATION;
        }
        NtStatus::SUCCESS
    }

    pub(crate) fn sys_nt_create_symbolic_link_object(
        &self,
        link_handle: MutPtr<Platform, Handle>,
        desired_access: u32,
        object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
        link_target: ConstPtr<Platform, UnicodeString>,
    ) -> NtStatus {
        if let Err(status) = probe_guest_output_preserving_value::<Platform, _>(link_handle) {
            return status;
        }
        let (object_attributes, name) =
            match read_directory_object_attributes::<Platform>(object_attributes, true) {
                Ok(value) => value,
                Err(status) => return status,
            };
        let Some(object_attributes) = object_attributes else {
            return NtStatus::INVALID_PARAMETER;
        };
        let Some(name) = name else {
            return NtStatus::OBJECT_NAME_INVALID;
        };
        let target = match link_target.read_at_offset(0) {
            Some(link_target) => match link_target.read_string::<Platform>() {
                Ok(target) if !target.is_empty() => target,
                Ok(_) => return NtStatus::OBJECT_NAME_INVALID,
                Err(status) => return status,
            },
            None => return NtStatus::ACCESS_VIOLATION,
        };
        let link_name = match self.resolve_directory_name(&object_attributes, &name) {
            Ok(link_name) => link_name,
            Err(status) => return status,
        };
        let key = directory_key(&link_name.path);
        if self.process.directory_namespace.read().contains_key(&key)
            || self
                .process
                .symbolic_link_namespace
                .read()
                .contains_key(&key)
        {
            return NtStatus::OBJECT_NAME_COLLISION;
        }
        if !self.directory_parent_exists(&link_name.path) {
            return NtStatus::OBJECT_PATH_NOT_FOUND;
        }
        let link = Arc::new(SymbolicLinkObject::new(link_name.path, target));
        self.process
            .symbolic_link_namespace
            .write()
            .insert(key, link.clone());
        let Ok(handle) = self.insert_symbolic_link_handle(
            link,
            SymbolicLinkAccess::from_desired_access(desired_access),
        ) else {
            return NtStatus::QUOTA_EXCEEDED;
        };
        if link_handle.write_at_offset(0, handle).is_none() {
            self.close_symbolic_link_handle(handle);
            return NtStatus::ACCESS_VIOLATION;
        }
        NtStatus::SUCCESS
    }

    pub(crate) fn sys_nt_open_symbolic_link_object(
        &self,
        link_handle: MutPtr<Platform, Handle>,
        desired_access: u32,
        object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
    ) -> NtStatus {
        if let Err(status) = probe_guest_output_preserving_value::<Platform, _>(link_handle) {
            return status;
        }
        let (object_attributes, name) =
            match read_directory_object_attributes::<Platform>(object_attributes, true) {
                Ok(value) => value,
                Err(status) => return status,
            };
        let Some(object_attributes) = object_attributes else {
            return NtStatus::INVALID_PARAMETER;
        };
        let Some(name) = name else {
            return NtStatus::OBJECT_NAME_INVALID;
        };
        let link_name = match self.resolve_directory_name(&object_attributes, &name) {
            Ok(link_name) => link_name,
            Err(status) => return status,
        };
        let Some(link) = self.symbolic_link_namespace_lookup(&link_name.path) else {
            if self.directory_parent_exists(&link_name.path) {
                return NtStatus::OBJECT_NAME_NOT_FOUND;
            }
            return NtStatus::OBJECT_PATH_NOT_FOUND;
        };
        let Ok(handle) = self.insert_symbolic_link_handle(
            link,
            SymbolicLinkAccess::from_desired_access(desired_access),
        ) else {
            return NtStatus::QUOTA_EXCEEDED;
        };
        if link_handle.write_at_offset(0, handle).is_none() {
            self.close_symbolic_link_handle(handle);
            return NtStatus::ACCESS_VIOLATION;
        }
        NtStatus::SUCCESS
    }

    pub(crate) fn sys_nt_query_symbolic_link_object(
        &self,
        link_handle: Handle,
        link_target: MutPtr<Platform, UnicodeString>,
        return_length: Option<MutPtr<Platform, u32>>,
    ) -> NtStatus {
        if let Some(return_length) = return_length
            && let Err(status) = probe_guest_output_preserving_value::<Platform, _>(return_length)
        {
            return status;
        }
        let Some(mut link_target_value) = link_target.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        let link = match self.symbolic_link_entry(link_handle) {
            Ok(link) => link,
            Err(status) => return status,
        };
        let query = link.with_entry(|entry| {
            entry
                .granted_access
                .require(SymbolicLinkAccess::QUERY)
                .map(|()| entry.link.clone())
        });
        let link = match query {
            Ok(link) => link,
            Err(status) => return status,
        };
        let target_bytes = entry_string_bytes(&link.target);
        let Ok(required_length) = u32::try_from(target_bytes.len() + WCHAR_SIZE) else {
            return NtStatus::BUFFER_TOO_SMALL;
        };
        if let Some(return_length) = return_length {
            let _ = return_length.write_at_offset(0, required_length);
        }
        if usize::from(link_target_value.maximum_length) < target_bytes.len() + WCHAR_SIZE {
            return NtStatus::BUFFER_TOO_SMALL;
        }
        if link_target_value.buffer == 0 {
            return NtStatus::ACCESS_VIOLATION;
        }
        let target_buffer = MutPtr::<Platform, u8>::from_usize(link_target_value.buffer);
        if target_buffer
            .write_slice_at_offset(0, &target_bytes)
            .is_none()
            || target_buffer
                .write_slice_at_offset(
                    match checked_offset(target_bytes.len()) {
                        Ok(offset) => offset,
                        Err(status) => return status,
                    },
                    &0u16.to_ne_bytes(),
                )
                .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        let Ok(target_length) = u16::try_from(target_bytes.len()) else {
            return NtStatus::BUFFER_TOO_SMALL;
        };
        link_target_value.length = target_length;
        if link_target.write_at_offset(0, link_target_value).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }
        NtStatus::SUCCESS
    }

    fn directory_entries(&self, directory: &DirectoryObject<Platform>) -> Vec<DirectoryEntry> {
        let Some(path) = directory.path() else {
            return Vec::new();
        };
        let prefix = if path == r"\" {
            String::from(r"\")
        } else {
            alloc::format!(r"{path}\")
        };
        let mut seen = BTreeSet::new();
        let namespace = self.process.directory_namespace.read();
        let mut entries = Vec::new();
        for object in namespace.values() {
            let Some(child_path) = object.path() else {
                continue;
            };
            if child_path == path || !child_path.starts_with(&prefix) {
                continue;
            }
            let remainder = &child_path[prefix.len()..];
            let Some(name) = remainder.split('\\').next() else {
                continue;
            };
            if name.is_empty() || !seen.insert(name.to_ascii_lowercase()) {
                continue;
            }
            entries.push(DirectoryEntry {
                name: String::from(name),
                type_name: DIRECTORY_TYPE_NAME,
            });
        }
        let links = self.process.symbolic_link_namespace.read();
        for link in links.values() {
            if !link.path.starts_with(&prefix) {
                continue;
            }
            let remainder = &link.path[prefix.len()..];
            let Some(name) = remainder.split('\\').next() else {
                continue;
            };
            if name.is_empty() || !seen.insert(name.to_ascii_lowercase()) {
                continue;
            }
            entries.push(DirectoryEntry {
                name: String::from(name),
                type_name: SYMBOLIC_LINK_TYPE_NAME,
            });
        }
        entries
    }

    pub(crate) fn sys_nt_query_directory_object(
        &self,
        parameters: QueryDirectoryObjectParameters<Platform>,
    ) -> NtStatus {
        let QueryDirectoryObjectParameters {
            directory_handle,
            buffer,
            length,
            return_single_entry,
            restart_scan,
            context,
            return_length,
        } = parameters;
        if let Err(status) = probe_guest_output_preserving_value::<Platform, _>(context) {
            return status;
        }
        if let Some(return_length) = return_length
            && let Err(status) = probe_guest_output_preserving_value::<Platform, _>(return_length)
        {
            return status;
        }
        if length != 0 && buffer.as_usize() == 0 {
            return NtStatus::ACCESS_VIOLATION;
        }
        let start_index = if restart_scan != 0 {
            0
        } else {
            match context.read_at_offset(0) {
                Some(context) => context as usize,
                None => return NtStatus::ACCESS_VIOLATION,
            }
        };
        let directory = match self.directory_object_entry(directory_handle) {
            Ok(directory) => directory,
            Err(status) => return status,
        };
        let query = directory.with_entry(|entry| {
            entry
                .granted_access
                .require(DirectoryObjectAccess::QUERY)
                .map(|()| entry.directory.clone())
        });
        let directory = match query {
            Ok(directory) => directory,
            Err(status) => return status,
        };
        let entries = self.directory_entries(&directory);
        let available = entries.get(start_index..).unwrap_or(&[]);
        if available.is_empty() {
            if let Some(return_length) = return_length {
                let _ = return_length.write_at_offset(0, OBJECT_DIRECTORY_INFORMATION_SIZE_U32);
            }
            return NtStatus::NO_MORE_ENTRIES;
        }

        let buffer_length = length as usize;
        let mut used_entries = Vec::new();
        let mut used_size = size_of::<ObjectDirectoryInformation>();
        for entry in available {
            let name_len = entry.name.encode_utf16().count() * WCHAR_SIZE;
            let type_len = entry.type_name.encode_utf16().count() * WCHAR_SIZE;
            let entry_size = size_of::<ObjectDirectoryInformation>()
                .saturating_add(name_len)
                .saturating_add(WCHAR_SIZE)
                .saturating_add(type_len)
                .saturating_add(WCHAR_SIZE);
            if used_size.saturating_add(entry_size) > buffer_length {
                if return_single_entry != 0 && used_entries.is_empty() {
                    if let Some(return_length) = return_length {
                        let required = 2 * size_of::<ObjectDirectoryInformation>()
                            + name_len
                            + type_len
                            + 2 * WCHAR_SIZE;
                        let Ok(required) = u32::try_from(required) else {
                            return NtStatus::BUFFER_TOO_SMALL;
                        };
                        let _ = return_length.write_at_offset(0, required);
                    }
                    return NtStatus::BUFFER_TOO_SMALL;
                }
                break;
            }
            used_size += entry_size;
            used_entries.push(entry.clone());
            if return_single_entry != 0 {
                break;
            }
        }

        let status = if used_entries.is_empty() || start_index + used_entries.len() < entries.len()
        {
            NtStatus::MORE_ENTRIES
        } else {
            NtStatus::SUCCESS
        };
        if used_entries.is_empty() {
            if let Some(return_length) = return_length {
                let _ = return_length.write_at_offset(0, OBJECT_DIRECTORY_INFORMATION_SIZE_U32);
            }
            return status;
        }

        let mut string_offset = size_of::<ObjectDirectoryInformation>() * (used_entries.len() + 1);
        let mut output_offset = 0isize;
        for entry in &used_entries {
            let name_bytes = entry_string_bytes(&entry.name);
            let type_bytes = entry_string_bytes(entry.type_name);
            let Ok(name_length) = u16::try_from(name_bytes.len()) else {
                return NtStatus::BUFFER_TOO_SMALL;
            };
            let Ok(type_length) = u16::try_from(type_bytes.len()) else {
                return NtStatus::BUFFER_TOO_SMALL;
            };
            let info = ObjectDirectoryInformation {
                name: UnicodeString {
                    length: name_length,
                    maximum_length: name_length.saturating_add(WCHAR_SIZE_U16),
                    padding_0: [0; 4],
                    buffer: buffer.as_usize() + string_offset,
                },
                type_name: UnicodeString {
                    length: type_length,
                    maximum_length: type_length.saturating_add(WCHAR_SIZE_U16),
                    padding_0: [0; 4],
                    buffer: buffer.as_usize() + string_offset + name_bytes.len() + WCHAR_SIZE,
                },
            };
            if buffer
                .write_slice_at_offset(output_offset, info.as_bytes())
                .is_none()
            {
                return NtStatus::ACCESS_VIOLATION;
            }
            if buffer
                .write_slice_at_offset(
                    match checked_offset(string_offset) {
                        Ok(offset) => offset,
                        Err(status) => return status,
                    },
                    &name_bytes,
                )
                .is_none()
                || buffer
                    .write_slice_at_offset(
                        match checked_offset(string_offset + name_bytes.len()) {
                            Ok(offset) => offset,
                            Err(status) => return status,
                        },
                        &0u16.to_ne_bytes(),
                    )
                    .is_none()
            {
                return NtStatus::ACCESS_VIOLATION;
            }
            string_offset += name_bytes.len() + WCHAR_SIZE;
            if buffer
                .write_slice_at_offset(
                    match checked_offset(string_offset) {
                        Ok(offset) => offset,
                        Err(status) => return status,
                    },
                    &type_bytes,
                )
                .is_none()
                || buffer
                    .write_slice_at_offset(
                        match checked_offset(string_offset + type_bytes.len()) {
                            Ok(offset) => offset,
                            Err(status) => return status,
                        },
                        &0u16.to_ne_bytes(),
                    )
                    .is_none()
            {
                return NtStatus::ACCESS_VIOLATION;
            }
            string_offset += type_bytes.len() + WCHAR_SIZE;
            output_offset += isize::try_from(size_of::<ObjectDirectoryInformation>())
                .expect("object directory information size fits in isize");
        }
        let terminator = ObjectDirectoryInformation {
            name: UnicodeString {
                length: 0,
                maximum_length: 0,
                padding_0: [0; 4],
                buffer: 0,
            },
            type_name: UnicodeString {
                length: 0,
                maximum_length: 0,
                padding_0: [0; 4],
                buffer: 0,
            },
        };
        if buffer
            .write_slice_at_offset(output_offset, terminator.as_bytes())
            .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        let Ok(next_context) = u32::try_from(start_index + used_entries.len()) else {
            return NtStatus::INVALID_PARAMETER;
        };
        if context.write_at_offset(0, next_context).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }
        if let Some(return_length) = return_length {
            let Ok(used_size) = u32::try_from(string_offset) else {
                return NtStatus::BUFFER_TOO_SMALL;
            };
            let _ = return_length.write_at_offset(0, used_size);
        }
        status
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::mem::{size_of, size_of_val};

    use crate::Task;
    use crate::nt_types::{ObjectAttributes, UnicodeString};
    use crate::syscalls::Handle;
    use crate::tests::{TestFS, TestPlatform, const_ptr, mut_byte_ptr, mut_ptr, test_task};

    use super::*;

    const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;

    fn unicode_string(value: &[u16]) -> UnicodeString {
        UnicodeString {
            length: u16::try_from(size_of_val(value)).unwrap(),
            maximum_length: u16::try_from(size_of_val(value) + WCHAR_SIZE).unwrap(),
            padding_0: [0; 4],
            buffer: value.as_ptr() as usize,
        }
    }

    fn object_attributes(name: &UnicodeString) -> ObjectAttributes {
        ObjectAttributes {
            length: u32::try_from(size_of::<ObjectAttributes>()).unwrap(),
            root_directory: Handle::from_raw(0),
            object_name: core::ptr::from_ref(name) as usize,
            attributes: OBJ_CASE_INSENSITIVE,
            security_descriptor: 0,
            security_quality_of_service: 0,
        }
    }

    fn open_directory(task: &Task<TestPlatform, TestFS>, path: &str, access: u32) -> Handle {
        let name_units = path.encode_utf16().collect::<Vec<_>>();
        let name = unicode_string(&name_units);
        let attrs = object_attributes(&name);
        let mut handle = Handle::from_raw(0);
        let status = task.sys_nt_open_directory_object(
            mut_ptr(&mut handle),
            access,
            Some(const_ptr(&attrs)),
        );
        assert_eq!(status, NtStatus::SUCCESS);
        handle
    }

    fn open_symbolic_link(task: &Task<TestPlatform, TestFS>, path: &str, access: u32) -> Handle {
        let name_units = path.encode_utf16().collect::<Vec<_>>();
        let name = unicode_string(&name_units);
        let attrs = object_attributes(&name);
        let mut handle = Handle::from_raw(0);
        let status = task.sys_nt_open_symbolic_link_object(
            mut_ptr(&mut handle),
            access,
            Some(const_ptr(&attrs)),
        );
        assert_eq!(status, NtStatus::SUCCESS);
        handle
    }

    fn query_symbolic_link(task: &Task<TestPlatform, TestFS>, handle: Handle) -> String {
        let mut buffer = [0u16; 128];
        let mut target = UnicodeString {
            length: 0,
            maximum_length: u16::try_from(size_of_val(&buffer)).unwrap(),
            padding_0: [0; 4],
            buffer: buffer.as_mut_ptr() as usize,
        };
        let mut return_length = 0u32;
        let status = task.sys_nt_query_symbolic_link_object(
            handle,
            mut_ptr(&mut target),
            Some(mut_ptr(&mut return_length)),
        );
        assert_eq!(status, NtStatus::SUCCESS);
        assert!(return_length >= u32::from(target.length));
        String::from_utf16(&buffer[..usize::from(target.length) / size_of::<u16>()]).unwrap()
    }

    #[test]
    fn opens_predefined_directory() {
        let task = test_task();
        let handle = open_directory(&task, r"\KnownDlls", DirectoryObjectAccess::QUERY.bits());
        assert!(!handle.is_null());
    }

    #[test]
    fn query_requires_directory_handle_type() {
        let task = test_task();
        let mut event_handle = Handle::from_raw(0);
        let status = task.sys_nt_create_event(mut_ptr(&mut event_handle), 0, None, 0, 0);
        assert_eq!(status, NtStatus::SUCCESS);
        let mut context = 0u32;
        let mut return_length = 0u32;
        let mut buffer = [0u8; 64];
        let status = task.sys_nt_query_directory_object(QueryDirectoryObjectParameters {
            directory_handle: event_handle,
            buffer: mut_byte_ptr(&mut buffer),
            length: u32::try_from(buffer.len()).unwrap(),
            return_single_entry: 0,
            restart_scan: 1,
            context: mut_ptr(&mut context),
            return_length: Some(mut_ptr(&mut return_length)),
        });
        assert_eq!(status, NtStatus::OBJECT_TYPE_MISMATCH);
    }

    #[test]
    fn query_root_returns_entries_and_updates_context() {
        let task = test_task();
        let root = open_directory(&task, r"\", DirectoryObjectAccess::QUERY.bits());
        let mut context = 0u32;
        let mut return_length = 0u32;
        let mut buffer = [0u8; 512];
        let status = task.sys_nt_query_directory_object(QueryDirectoryObjectParameters {
            directory_handle: root,
            buffer: mut_byte_ptr(&mut buffer),
            length: u32::try_from(buffer.len()).unwrap(),
            return_single_entry: 1,
            restart_scan: 1,
            context: mut_ptr(&mut context),
            return_length: Some(mut_ptr(&mut return_length)),
        });
        assert_eq!(status, NtStatus::MORE_ENTRIES);
        assert_eq!(context, 1);
        assert!(return_length as usize >= 2 * size_of::<ObjectDirectoryInformation>());
    }

    #[test]
    fn create_named_directory_can_be_opened() {
        let task = test_task();
        let name_units = r"\BaseNamedObjects\LiteBoxTestDir"
            .encode_utf16()
            .collect::<Vec<_>>();
        let name = unicode_string(&name_units);
        let attrs = object_attributes(&name);
        let mut created = Handle::from_raw(0);
        let status = task.sys_nt_create_directory_object(
            mut_ptr(&mut created),
            DirectoryObjectAccess::ALL_ACCESS.bits(),
            Some(const_ptr(&attrs)),
        );
        assert_eq!(status, NtStatus::SUCCESS);
        let opened = open_directory(&task, r"\BaseNamedObjects\LiteBoxTestDir", 0);
        assert!(!opened.is_null());
    }

    #[test]
    fn opens_and_queries_predefined_symbolic_link() {
        let task = test_task();
        let handle = open_symbolic_link(&task, r"\??\C:", SymbolicLinkAccess::QUERY.bits());
        assert_eq!(
            query_symbolic_link(&task, handle),
            r"\Device\HarddiskVolume1"
        );
    }

    #[test]
    fn create_symbolic_link_can_be_opened_and_queried() {
        let task = test_task();
        let name_units = r"\BaseNamedObjects\LiteBoxTestLink"
            .encode_utf16()
            .collect::<Vec<_>>();
        let target_units = r"\Device\Null".encode_utf16().collect::<Vec<_>>();
        let name = unicode_string(&name_units);
        let target = unicode_string(&target_units);
        let attrs = object_attributes(&name);
        let mut created = Handle::from_raw(0);
        let status = task.sys_nt_create_symbolic_link_object(
            mut_ptr(&mut created),
            SymbolicLinkAccess::ALL_ACCESS.bits(),
            Some(const_ptr(&attrs)),
            const_ptr(&target),
        );
        assert_eq!(status, NtStatus::SUCCESS);
        let opened = open_symbolic_link(
            &task,
            r"\BaseNamedObjects\LiteBoxTestLink",
            SymbolicLinkAccess::QUERY.bits(),
        );
        assert_eq!(query_symbolic_link(&task, opened), r"\Device\Null");
    }
}
