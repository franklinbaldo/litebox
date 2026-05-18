// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! PE loader-facing parser and mapper.
//!
//! This module parses PE metadata and maps images through platform-provided
//! traits. Resolving imports and initializing process state are shim
//! responsibilities that will be built on top of this parser.

use alloc::vec::Vec;
use core::cmp;
use core::mem::size_of;

use object::endian::LittleEndian as LE;
use object::pe::{self, ImageNtHeaders64};
use object::read::pe::{ImageNtHeaders as _, ImageOptionalHeader as _, PeFile64, Relocation};
use thiserror::Error;

/// The page size used by Windows x86-64 image mappings.
pub const PAGE_SIZE: usize = 4096;

/// The result of parsing a PE32+ file.
#[derive(Debug)]
pub struct PeParsedFile {
    /// Basic image metadata from the PE optional and COFF headers.
    pub image: PeImageInfo,
    /// Raw PE section headers in file order.
    pub sections: Vec<pe::ImageSectionHeader>,
    /// Data directory entries indexed by `IMAGE_DIRECTORY_ENTRY_*`.
    pub data_directories: Vec<PeDataDirectory>,
    /// Import lookup table entries grouped only by their source DLL name in each entry.
    pub imports: Vec<PeImport>,
    /// Named exports from the PE export directory.
    pub exports: Vec<PeExport>,
    /// Base relocation entries from the `.reloc` directory.
    pub relocations: Vec<Relocation>,
    trampoline: Option<PeTrampolineInfo>,
}

/// Basic PE image metadata needed by the Windows shim loader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeImageInfo {
    /// COFF machine type.
    pub machine: u16,
    /// COFF image characteristics.
    pub characteristics: u16,
    /// Preferred image base.
    pub image_base: usize,
    /// Entry point RVA.
    pub entry_point_rva: usize,
    /// Entry point virtual address at the preferred image base.
    pub entry_point: usize,
    /// Required image mapping size.
    pub size_of_image: usize,
    /// Header bytes that must be mapped at the start of the image.
    pub size_of_headers: usize,
    /// Section alignment in virtual memory.
    pub section_alignment: usize,
    /// File alignment for raw section data.
    pub file_alignment: usize,
    /// Windows subsystem value, such as `IMAGE_SUBSYSTEM_WINDOWS_CUI`.
    pub subsystem: u16,
    /// Major subsystem version from the PE optional header.
    pub major_subsystem_version: u16,
    /// Minor subsystem version from the PE optional header.
    pub minor_subsystem_version: u16,
    /// PE DLL characteristics flags.
    pub dll_characteristics: u16,
    /// Initial thread stack reservation size.
    pub size_of_stack_reserve: usize,
    /// Initial thread stack commit size.
    pub size_of_stack_commit: usize,
    /// Default process heap reservation size.
    pub size_of_heap_reserve: usize,
    /// Default process heap commit size.
    pub size_of_heap_commit: usize,
}

/// Information about the mapped PE image.
pub struct MappingInfo {
    /// The base address where the PE image is mapped.
    pub base_addr: usize,
    /// The image size reported to Windows image-information queries.
    pub image_size: usize,
    /// The mapped image size, including LiteBox-private trampoline pages.
    ///
    /// The loader also maps a trailing image-extension page at `base_addr + mapped_size`.
    pub mapped_size: usize,
    /// The entry point, where execution begins.
    pub entry_point: usize,
    /// Windows `MemoryImageInformation` flags for this image.
    pub image_flags: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PeTrampolineInfo {
    rva: usize,
    size: usize,
    file_offset: u64,
    syscall_entry_point: usize,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct TrampolineHeader64 {
    magic: [u8; 8],
    file_offset: u64,
    rva: u64,
    trampoline_size: u64,
}

const TRAMPOLINE_MAGIC: [u8; 8] = *b"LITEBOX0";
const IMAGE_FILE_DLL: u16 = 0x2000;
const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: usize = 10;
const MEMORY_IMAGE_EXTENSION_SIZE: usize = PAGE_SIZE;
const MEMORY_IMAGE_EXTENSION_HEADER: [u32; 6] = [0x40, 0xc0, 0x140, 0x1c0, 0x240, 0x2a4];
const MEMORY_IMAGE_EXTENSION_PADDING_RANGES: [(usize, usize); 6] = [
    (0x18, 0x40),
    (0x43, 0xc0),
    (0xc3, 0x140),
    (0x141, 0x1c0),
    (0x1c1, 0x240),
    (0x24d, 0x280),
];
const MEMORY_IMAGE_EXTENSION_JMP_RAX: [u8; 3] = [0x48, 0xff, 0xe0];
const MEMORY_IMAGE_EXTENSION_RET: [u8; 1] = [0xc3];
const MEMORY_IMAGE_EXTENSION_INVALID_CALL_TARGET: [u8; 13] = [
    0x49, 0xbb, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x49, 0xff, 0xe3,
];
const MEMORY_IMAGE_EXTENSION_VALIDATE_VERSION_OFFSET: usize = 0x280;
const MEMORY_IMAGE_EXTENSION_VALIDATE_VERSION: [u8; 23] = [
    0x81, 0x39, 0x06, 0x00, 0x00, 0xc0, 0x74, 0x0a, 0x33, 0xd2, 0xb9, 0x0a, 0x00, 0x00, 0x00, 0xcd,
    0x29, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3,
];
const MEMORY_IMAGE_EXTENSION_UNWIND_INFO_OFFSET: usize = 0x298;
const MEMORY_IMAGE_EXTENSION_UNWIND_INFO: [u32; 2] = [0x19, 0x280];
const MEMORY_IMAGE_EXTENSION_FUNCTION_TABLE_OFFSET: usize = 0x2a4;
const MEMORY_IMAGE_EXTENSION_RUNTIME_FUNCTION: [u32; 3] = [0, 0x280, 0x298];
const MEMORY_IMAGE_FLAGS_UNSIGNED_IMAGE: u32 = 0x08;
const MEMORY_IMAGE_FLAGS_SIGNED_IMAGE: u32 = 0x20;
const MEMORY_IMAGE_FLAGS_SYSTEM_DLL: u32 = 0x70;

/// A PE data directory entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeDataDirectory {
    /// Directory RVA.
    pub virtual_address: u32,
    /// Directory byte size.
    pub size: u32,
}

/// A PE import table entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeImport {
    /// DLL name from the import descriptor.
    pub library: Vec<u8>,
    /// Import lookup table slot RVA.
    pub lookup_rva: u32,
    /// Import address table slot RVA that the loader must patch.
    pub iat_rva: u32,
    /// Import target.
    pub target: PeImportTarget,
}

/// A PE import target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeImportTarget {
    /// Import by ordinal.
    Ordinal(u16),
    /// Import by name with the PE hint value.
    Name {
        /// Export name table hint.
        hint: u16,
        /// Imported symbol name.
        name: Vec<u8>,
    },
}

/// A named PE export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeExport {
    /// Export name.
    pub name: Vec<u8>,
    /// Export target RVA.
    pub rva: u32,
}

/// Errors that can occur when parsing a PE file.
#[derive(Debug, Error)]
pub enum PeParseError<E> {
    /// PE parsing error reported by the object parser.
    #[error("PE parsing error")]
    Pe(#[from] object::read::Error),
    /// The input file could not be read.
    #[error("I/O error")]
    Io(#[source] E),
    /// The file is not a supported Windows executable image.
    #[error("unsupported PE image")]
    UnsupportedImage,
    /// The LiteBox trampoline footer is malformed.
    #[error("bad LiteBox trampoline")]
    BadTrampoline,
    /// The LiteBox trampoline footer has an unsupported version.
    #[error("invalid LiteBox trampoline version")]
    BadTrampolineVersion,
    /// A PE field overflowed the host representation used by this parser.
    #[error("PE field overflow")]
    Overflow,
}

/// Errors that can occur when mapping a PE image into memory.
#[derive(Debug, Error)]
pub enum PeLoadError<E> {
    /// Memory mapping error.
    #[error("memory mapping error")]
    Map(#[source] E),
    /// The image contains inconsistent or overflowing fields.
    #[error("invalid PE image")]
    InvalidImage,
    /// The image had to be loaded away from its preferred base but has no base relocations.
    #[error("PE image requires base relocations")]
    RelocationRequired,
    /// The image contains a relocation type this loader does not support.
    #[error("unsupported PE base relocation type {0}")]
    UnsupportedRelocation(u16),
    /// A mapped memory access failed.
    #[error(transparent)]
    Fault(#[from] Fault),
}

impl PeParsedFile {
    /// Parse a PE32+ x86-64 image from the given file.
    pub fn parse<F: ReadAt>(file: &mut F) -> Result<Self, PeParseError<F::Error>> {
        let size = file.size().map_err(PeParseError::Io)?;
        let len: usize = size.try_into().map_err(|_| PeParseError::Overflow)?;
        let mut data = alloc::vec![0; len];
        file.read_at(0, &mut data).map_err(PeParseError::Io)?;
        parse_bytes(&data)
    }

    /// Parse a PE32+ x86-64 image from file bytes.
    pub fn parse_bytes(data: &[u8]) -> Result<Self, PeParseError<core::convert::Infallible>> {
        parse_bytes(data)
    }

    /// Returns whether the image has a parsed LiteBox syscall trampoline.
    #[must_use]
    pub fn has_trampoline(&self) -> bool {
        self.trampoline.is_some()
    }

    /// Load the PE image into memory.
    ///
    /// This maps PE headers and sections into their image locations,
    /// applies base relocations if the image was not loaded at its preferred base,
    /// and then applies section protections. Import resolution is left to the shim
    /// because it depends on the emulated Windows module environment.
    pub fn load<M: MapMemory>(
        &self,
        mapper: &mut M,
        mem: &mut impl AccessMemory,
    ) -> Result<MappingInfo, PeLoadError<M::Error>> {
        self.load_with_writable_sections(mapper, mem, &[])
    }

    /// Load the PE image into memory, keeping selected sections writable.
    ///
    /// This is intended for target-specific loader data such as ntdll's `.mrdata`.
    pub fn load_with_writable_sections<M: MapMemory>(
        &self,
        mapper: &mut M,
        mem: &mut impl AccessMemory,
        writable_section_names: &[&[u8]],
    ) -> Result<MappingInfo, PeLoadError<M::Error>> {
        let preferred_base = self.image.image_base;
        let image_size =
            page_align_up(self.image.size_of_image).ok_or(PeLoadError::InvalidImage)?;
        if image_size == 0 {
            return Err(PeLoadError::InvalidImage);
        }
        let mapping_size = self.mapping_size::<M::Error>(image_size)?;
        let reserved_size = mapping_size
            .checked_add(MEMORY_IMAGE_EXTENSION_SIZE)
            .ok_or(PeLoadError::InvalidImage)?;

        let base_addr = mapper
            .reserve(preferred_base, reserved_size, PAGE_SIZE)
            .map_err(PeLoadError::Map)?;
        let image_end = base_addr
            .checked_add(image_size)
            .ok_or(PeLoadError::InvalidImage)?;

        let headers_size = self.image.size_of_headers;

        if headers_size > image_size {
            return Err(PeLoadError::InvalidImage);
        }
        if headers_size != 0 {
            mapper
                .map_file(
                    base_addr,
                    headers_size,
                    0,
                    &Protection {
                        read: true,
                        write: false,
                        execute: false,
                    },
                )
                .map_err(PeLoadError::Map)?;
        }

        for section in &self.sections {
            let section_rva = section.virtual_address.get(LE) as usize;
            let virtual_size = section.virtual_size.get(LE) as usize;
            let raw_size = section.size_of_raw_data.get(LE) as usize;
            let raw_offset = section.pointer_to_raw_data.get(LE) as usize;
            let mapped_size =
                page_align_up(cmp::max(virtual_size, raw_size)).ok_or(PeLoadError::InvalidImage)?;

            if mapped_size == 0 {
                continue;
            }
            let section_start = base_addr
                .checked_add(section_rva)
                .ok_or(PeLoadError::InvalidImage)?;
            let section_end = section_start
                .checked_add(mapped_size)
                .ok_or(PeLoadError::InvalidImage)?;
            if section_end > image_end {
                return Err(PeLoadError::InvalidImage);
            }

            if raw_size != 0 {
                mapper
                    .map_file(
                        section_start,
                        raw_size,
                        raw_offset
                            .try_into()
                            .map_err(|_| PeLoadError::InvalidImage)?,
                        &Protection {
                            read: true,
                            write: true,
                            execute: false,
                        },
                    )
                    .map_err(PeLoadError::Map)?;
            }

            if mapped_size > raw_size {
                let zero_start = section_start
                    .checked_add(raw_size)
                    .ok_or(PeLoadError::InvalidImage)?;
                mapper
                    .map_zero(
                        zero_start,
                        mapped_size - raw_size,
                        &Protection {
                            read: true,
                            write: true,
                            execute: false,
                        },
                    )
                    .map_err(PeLoadError::Map)?;
            }
        }

        self.apply_base_relocations::<M::Error>(base_addr, mem)?;

        for section in &self.sections {
            let section_rva: usize = section.virtual_address.get(LE) as usize;
            let virtual_size: usize = section.virtual_size.get(LE) as usize;
            let raw_size: usize = section.size_of_raw_data.get(LE) as usize;
            let mapped_size =
                page_align_up(cmp::max(virtual_size, raw_size)).ok_or(PeLoadError::InvalidImage)?;
            if mapped_size == 0 {
                continue;
            }

            let protect_start = page_align_down(
                base_addr
                    .checked_add(section_rva)
                    .ok_or(PeLoadError::InvalidImage)?,
            );
            let protect_end = page_align_up(
                base_addr
                    .checked_add(section_rva)
                    .and_then(|address| address.checked_add(mapped_size))
                    .ok_or(PeLoadError::InvalidImage)?,
            )
            .ok_or(PeLoadError::InvalidImage)?;
            if protect_end > image_end || protect_end < protect_start {
                return Err(PeLoadError::InvalidImage);
            }

            mapper
                .protect(
                    protect_start,
                    protect_end - protect_start,
                    &Protection::from_section(section, writable_section_names),
                )
                .map_err(PeLoadError::Map)?;
        }

        if self.trampoline.is_some() {
            self.load_trampoline(mapper, mem, base_addr)?;
        }

        self.load_memory_image_extension(mapper, mem, base_addr, mapping_size)?;

        let entry_point = base_addr
            .checked_add(self.image.entry_point_rva)
            .ok_or(PeLoadError::InvalidImage)?;

        Ok(MappingInfo {
            base_addr,
            image_size,
            mapped_size: mapping_size,
            entry_point,
            image_flags: self.memory_image_flags(),
        })
    }

    fn memory_image_flags(&self) -> u32 {
        if self.image.characteristics & IMAGE_FILE_DLL != 0 {
            MEMORY_IMAGE_FLAGS_SYSTEM_DLL
        } else if self.has_load_config_directory() {
            MEMORY_IMAGE_FLAGS_SIGNED_IMAGE
        } else {
            MEMORY_IMAGE_FLAGS_UNSIGNED_IMAGE
        }
    }

    fn load_memory_image_extension<M: MapMemory>(
        &self,
        mapper: &mut M,
        mem: &mut impl AccessMemory,
        base_addr: usize,
        mapping_size: usize,
    ) -> Result<(), PeLoadError<M::Error>> {
        let image_extension_start = base_addr
            .checked_add(mapping_size)
            .ok_or(PeLoadError::InvalidImage)?;
        mapper
            .map_zero(
                image_extension_start,
                MEMORY_IMAGE_EXTENSION_SIZE,
                &Protection {
                    read: true,
                    write: true,
                    execute: false,
                },
            )
            .map_err(PeLoadError::Map)?;

        write_u32s(mem, image_extension_start, &MEMORY_IMAGE_EXTENSION_HEADER)?;
        write_extension_padding(mem, image_extension_start)?;
        write_slice(
            mem,
            image_extension_start
                .checked_add(MEMORY_IMAGE_EXTENSION_HEADER[0] as usize)
                .ok_or(PeLoadError::InvalidImage)?,
            &MEMORY_IMAGE_EXTENSION_JMP_RAX,
        )?;
        write_slice(
            mem,
            image_extension_start
                .checked_add(MEMORY_IMAGE_EXTENSION_HEADER[1] as usize)
                .ok_or(PeLoadError::InvalidImage)?,
            &MEMORY_IMAGE_EXTENSION_JMP_RAX,
        )?;
        write_slice(
            mem,
            image_extension_start
                .checked_add(MEMORY_IMAGE_EXTENSION_HEADER[2] as usize)
                .ok_or(PeLoadError::InvalidImage)?,
            &MEMORY_IMAGE_EXTENSION_RET,
        )?;
        write_slice(
            mem,
            image_extension_start
                .checked_add(MEMORY_IMAGE_EXTENSION_HEADER[3] as usize)
                .ok_or(PeLoadError::InvalidImage)?,
            &MEMORY_IMAGE_EXTENSION_RET,
        )?;
        write_slice(
            mem,
            image_extension_start
                .checked_add(MEMORY_IMAGE_EXTENSION_HEADER[4] as usize)
                .ok_or(PeLoadError::InvalidImage)?,
            &MEMORY_IMAGE_EXTENSION_INVALID_CALL_TARGET,
        )?;
        write_slice(
            mem,
            image_extension_start
                .checked_add(MEMORY_IMAGE_EXTENSION_VALIDATE_VERSION_OFFSET)
                .ok_or(PeLoadError::InvalidImage)?,
            &MEMORY_IMAGE_EXTENSION_VALIDATE_VERSION,
        )?;
        write_u32s(
            mem,
            image_extension_start
                .checked_add(MEMORY_IMAGE_EXTENSION_UNWIND_INFO_OFFSET)
                .ok_or(PeLoadError::InvalidImage)?,
            &MEMORY_IMAGE_EXTENSION_UNWIND_INFO,
        )?;

        let runtime_function_address = image_extension_start
            .checked_add(MEMORY_IMAGE_EXTENSION_FUNCTION_TABLE_OFFSET)
            .ok_or(PeLoadError::InvalidImage)?;
        write_u32s(
            mem,
            runtime_function_address,
            &MEMORY_IMAGE_EXTENSION_RUNTIME_FUNCTION,
        )?;

        mapper
            .protect(
                image_extension_start,
                MEMORY_IMAGE_EXTENSION_SIZE,
                &Protection {
                    read: true,
                    write: false,
                    execute: true,
                },
            )
            .map_err(PeLoadError::Map)
    }

    fn has_load_config_directory(&self) -> bool {
        self.data_directories
            .get(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)
            .is_some_and(|directory| directory.virtual_address != 0 && directory.size != 0)
    }

    /// Parse the LiteBox PE trampoline footer, if present.
    ///
    /// The trampoline RVA is relative to the image base. The first pointer-sized
    /// word of the mapped trampoline is patched with `syscall_entry_point` when
    /// the image is loaded.
    #[expect(
        clippy::missing_panics_doc,
        reason = "cannot panic: array slices are always the correct size"
    )]
    pub fn parse_trampoline<F: ReadAt>(
        &mut self,
        file: &mut F,
        syscall_entry_point: usize,
    ) -> Result<(), PeParseError<F::Error>> {
        if syscall_entry_point == 0 {
            return Ok(());
        }

        let file_size = file.size().map_err(PeParseError::Io)?;
        let header_size = size_of::<TrampolineHeader64>();
        if file_size < header_size as u64 {
            return Ok(());
        }

        let header_offset = file_size - header_size as u64;
        let mut header_buf = [0u8; size_of::<TrampolineHeader64>()];
        file.read_at(header_offset, &mut header_buf)
            .map_err(PeParseError::Io)?;

        let magic: [u8; 8] = header_buf[0..8].try_into().unwrap();
        if magic != TRAMPOLINE_MAGIC {
            if &header_buf[0..7] == b"LITEBOX" {
                return Err(PeParseError::BadTrampolineVersion);
            }
            return Ok(());
        }

        let file_offset = u64::from_le_bytes(header_buf[8..16].try_into().unwrap());
        let rva: usize = u64::from_le_bytes(header_buf[16..24].try_into().unwrap())
            .try_into()
            .map_err(|_| PeParseError::BadTrampoline)?;
        let trampoline_size: usize = u64::from_le_bytes(header_buf[24..32].try_into().unwrap())
            .try_into()
            .map_err(|_| PeParseError::BadTrampoline)?;
        let image_size =
            page_align_up(self.image.size_of_image).ok_or(PeParseError::BadTrampoline)?;

        if trampoline_size == 0
            || !file_offset.is_multiple_of(PAGE_SIZE as u64)
            || !rva.is_multiple_of(PAGE_SIZE)
            || rva < image_size
            || file_offset
                .checked_add(trampoline_size as u64)
                .ok_or(PeParseError::BadTrampoline)?
                != header_offset
        {
            return Err(PeParseError::BadTrampoline);
        }

        self.trampoline = Some(PeTrampolineInfo {
            rva,
            size: trampoline_size,
            file_offset,
            syscall_entry_point,
        });
        Ok(())
    }

    fn mapping_size<E>(&self, image_size: usize) -> Result<usize, PeLoadError<E>> {
        let Some(trampoline) = &self.trampoline else {
            return Ok(image_size);
        };

        trampoline
            .rva
            .checked_add(trampoline.size)
            .and_then(page_align_up)
            .map(|trampoline_end| image_size.max(trampoline_end))
            .ok_or(PeLoadError::InvalidImage)
    }

    fn load_trampoline<M: MapMemory>(
        &self,
        mapper: &mut M,
        mem: &mut impl AccessMemory,
        base_addr: usize,
    ) -> Result<(), PeLoadError<M::Error>> {
        let trampoline = self.trampoline.as_ref().unwrap();
        let trampoline_start = base_addr
            .checked_add(trampoline.rva)
            .ok_or(PeLoadError::InvalidImage)?;
        let trampoline_size = page_align_up(trampoline.size).ok_or(PeLoadError::InvalidImage)?;
        mapper
            .map_file(
                trampoline_start,
                trampoline_size,
                trampoline.file_offset,
                &Protection {
                    read: true,
                    write: true,
                    execute: false,
                },
            )
            .map_err(PeLoadError::Map)?;

        mem.write(
            trampoline_start,
            &trampoline.syscall_entry_point.to_ne_bytes(),
        )?;

        mapper
            .protect(
                trampoline_start,
                trampoline_size,
                &Protection {
                    read: true,
                    write: false,
                    execute: true,
                },
            )
            .map_err(PeLoadError::Map)
    }

    fn apply_base_relocations<E>(
        &self,
        base_addr: usize,
        mem: &mut impl AccessMemory,
    ) -> Result<(), PeLoadError<E>> {
        let delta = base_addr.wrapping_sub(self.image.image_base);
        if delta == 0 {
            return Ok(());
        }
        if self.relocations.is_empty() {
            return Err(PeLoadError::RelocationRequired);
        }

        let image_end = base_addr
            .checked_add(self.image.size_of_image)
            .ok_or(PeLoadError::InvalidImage)?;

        for relocation in &self.relocations {
            match relocation.typ {
                pe::IMAGE_REL_BASED_ABSOLUTE => {}
                pe::IMAGE_REL_BASED_DIR64 => {
                    // patch a 64-bit absolute address
                    let relocation_rva = relocation.virtual_address as usize;
                    let relocation_address = base_addr
                        .checked_add(relocation_rva)
                        .ok_or(PeLoadError::InvalidImage)?;
                    let relocation_end = relocation_address
                        .checked_add(size_of::<u64>())
                        .ok_or(PeLoadError::InvalidImage)?;
                    if relocation_end > image_end {
                        return Err(PeLoadError::InvalidImage);
                    }

                    let mut value = [0; size_of::<u64>()];
                    mem.read(relocation_address, &mut value)?;
                    let delta: u64 = delta.try_into().map_err(|_| PeLoadError::InvalidImage)?;
                    let relocated = u64::from_le_bytes(value).wrapping_add(delta);
                    mem.write(relocation_address, &relocated.to_le_bytes())?;
                }
                typ => return Err(PeLoadError::UnsupportedRelocation(typ)),
            }
        }

        Ok(())
    }
}

fn parse_bytes<E>(data: &[u8]) -> Result<PeParsedFile, PeParseError<E>> {
    let pe = PeFile64::parse(data)?;
    let nt_headers = pe.nt_headers();
    let file_header = nt_headers.file_header();
    let optional_header = nt_headers.optional_header();
    let machine = file_header.machine.get(LE);
    let characteristics = file_header.characteristics.get(LE);

    if machine != pe::IMAGE_FILE_MACHINE_AMD64
        || characteristics & pe::IMAGE_FILE_EXECUTABLE_IMAGE == 0
    {
        return Err(PeParseError::UnsupportedImage);
    }

    let image_base = usize_from_u64(optional_header.image_base())?;
    let entry_point_rva = usize_from_u32(optional_header.address_of_entry_point())?;
    let image = PeImageInfo {
        machine,
        characteristics,
        image_base,
        entry_point_rva,
        entry_point: image_base
            .checked_add(entry_point_rva)
            .ok_or(PeParseError::Overflow)?,
        size_of_image: usize_from_u32(optional_header.size_of_image())?,
        size_of_headers: usize_from_u32(optional_header.size_of_headers())?,
        section_alignment: usize_from_u32(optional_header.section_alignment())?,
        file_alignment: usize_from_u32(optional_header.file_alignment())?,
        subsystem: optional_header.subsystem(),
        major_subsystem_version: optional_header.major_subsystem_version(),
        minor_subsystem_version: optional_header.minor_subsystem_version(),
        dll_characteristics: optional_header.dll_characteristics(),
        size_of_stack_reserve: usize_from_u64(optional_header.size_of_stack_reserve())?,
        size_of_stack_commit: usize_from_u64(optional_header.size_of_stack_commit())?,
        size_of_heap_reserve: usize_from_u64(optional_header.size_of_heap_reserve())?,
        size_of_heap_commit: usize_from_u64(optional_header.size_of_heap_commit())?,
    };

    let sections = pe.section_table().iter().copied().collect();

    let data_directories = pe
        .data_directories()
        .iter()
        .map(|directory| {
            let virtual_address = directory.virtual_address.get(LE);
            let size = directory.size.get(LE);
            PeDataDirectory {
                virtual_address,
                size,
            }
        })
        .collect();

    let imports = parse_imports(&pe)?;
    let exports = parse_exports(&pe)?;
    let relocations = parse_relocations(&pe)?;

    Ok(PeParsedFile {
        image,
        sections,
        data_directories,
        imports,
        exports,
        relocations,
        trampoline: None,
    })
}

fn usize_from_u32<E>(value: u32) -> Result<usize, PeParseError<E>> {
    value.try_into().map_err(|_| PeParseError::Overflow)
}

fn usize_from_u64<E>(value: u64) -> Result<usize, PeParseError<E>> {
    value.try_into().map_err(|_| PeParseError::Overflow)
}

fn page_align_down(address: usize) -> usize {
    address & !(PAGE_SIZE - 1)
}

fn write_slice<E>(
    mem: &mut impl AccessMemory,
    address: usize,
    bytes: &[u8],
) -> Result<(), PeLoadError<E>> {
    mem.write(address, bytes)
        .map_err(|_| PeLoadError::InvalidImage)
}

fn write_extension_padding<E>(
    mem: &mut impl AccessMemory,
    image_extension_start: usize,
) -> Result<(), PeLoadError<E>> {
    const NOPS: [u8; 128] = [0x90; 128];

    for (start, end) in MEMORY_IMAGE_EXTENSION_PADDING_RANGES {
        let mut address = image_extension_start
            .checked_add(start)
            .ok_or(PeLoadError::InvalidImage)?;
        let mut remaining = end.checked_sub(start).ok_or(PeLoadError::InvalidImage)?;
        while remaining != 0 {
            let chunk_len = core::cmp::min(remaining, NOPS.len());
            write_slice(mem, address, &NOPS[..chunk_len])?;
            address = address
                .checked_add(chunk_len)
                .ok_or(PeLoadError::InvalidImage)?;
            remaining -= chunk_len;
        }
    }

    Ok(())
}

fn write_u32s<E>(
    mem: &mut impl AccessMemory,
    address: usize,
    values: &[u32],
) -> Result<(), PeLoadError<E>> {
    let mut bytes = Vec::with_capacity(values.len() * size_of::<u32>());
    for value in values {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    write_slice(mem, address, &bytes)
}

fn page_align_up(len: usize) -> Option<usize> {
    len.checked_add(PAGE_SIZE - 1).map(page_align_down)
}

/// Trait for reading PE binary data at specific offsets.
pub trait ReadAt {
    /// The error type for read operations.
    type Error;

    /// Read data at the specified offset into the provided buffer.
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), Self::Error>;

    /// Get the length of the PE file.
    fn size(&mut self) -> Result<u64, Self::Error>;
}

/// Trait for reserving, mapping, and protecting PE image memory.
pub trait MapMemory {
    /// The error type for mapping operations.
    type Error;

    /// Reserve a region of memory for the image, preferably at `preferred_base`.
    ///
    /// The returned address is the actual base address. If it differs from the
    /// preferred image base, [`PeParsedFile::load`] applies base relocations.
    fn reserve(
        &mut self,
        preferred_base: usize,
        len: usize,
        align: usize,
    ) -> Result<usize, Self::Error>;

    /// Map zero-filled memory, replacing any existing mappings in the range.
    fn map_zero(
        &mut self,
        address: usize,
        len: usize,
        prot: &Protection,
    ) -> Result<(), Self::Error>;

    /// Map file-backed data at the specified file offset.
    ///
    /// The mapper owns the backing file or equivalent byte source, including
    /// validating that the requested range exists.
    ///
    /// PE image sections are commonly file-aligned rather than page-aligned,
    /// so implementations may need to satisfy this by mapping pages and copying
    /// the requested file range into them.
    fn map_file(
        &mut self,
        address: usize,
        len: usize,
        offset: u64,
        prot: &Protection,
    ) -> Result<(), Self::Error>;

    /// Change protections of a memory region.
    fn protect(&mut self, address: usize, len: usize, prot: &Protection)
    -> Result<(), Self::Error>;
}

/// Trait for reading and writing memory that has been mapped via [`MapMemory`].
pub trait AccessMemory {
    /// Read from memory.
    fn read(&mut self, address: usize, buf: &mut [u8]) -> Result<(), Fault>;

    /// Write to memory.
    fn write(&mut self, address: usize, data: &[u8]) -> Result<(), Fault>;
}

/// An error indicating a memory access fault.
#[derive(Debug, Error)]
#[error("memory access fault")]
pub struct Fault;

/// Memory protection flags.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Protection {
    /// Read permission.
    pub read: bool,
    /// Write permission.
    pub write: bool,
    /// Execute permission.
    pub execute: bool,
}

impl Protection {
    fn from_section(section: &pe::ImageSectionHeader, writable_section_names: &[&[u8]]) -> Self {
        let characteristics = section.characteristics.get(LE);
        let mut protection = Self {
            read: characteristics & pe::IMAGE_SCN_MEM_READ != 0,
            write: characteristics & pe::IMAGE_SCN_MEM_WRITE != 0,
            execute: characteristics & pe::IMAGE_SCN_MEM_EXECUTE != 0,
        };
        if writable_section_names
            .iter()
            .any(|name| section_name_eq(section, name))
        {
            protection.write = true;
        }

        protection
    }
}

fn section_name_eq(section: &pe::ImageSectionHeader, name: &[u8]) -> bool {
    let end = section
        .name
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(section.name.len());
    &section.name[..end] == name
}

fn parse_imports(pe: &PeFile64<'_>) -> Result<Vec<PeImport>, object::read::Error> {
    let Some(import_table) = pe.import_table()? else {
        return Ok(Vec::new());
    };

    let mut imports = Vec::new();
    let mut descriptors = import_table.descriptors()?;
    while let Some(descriptor) = descriptors.next()? {
        let library = import_table.name(descriptor.name.get(LE))?.to_vec();
        let lookup_table_rva = match descriptor.original_first_thunk.get(LE) {
            0 => descriptor.first_thunk.get(LE),
            rva => rva,
        };
        let iat_rva = descriptor.first_thunk.get(LE);
        let mut thunks = import_table.thunks(lookup_table_rva)?;
        let mut index = 0u32;
        while let Some(thunk) = thunks.next::<ImageNtHeaders64>()? {
            let target = match import_table.import::<ImageNtHeaders64>(thunk)? {
                object::read::pe::Import::Ordinal(ordinal) => PeImportTarget::Ordinal(ordinal),
                object::read::pe::Import::Name(hint, name) => PeImportTarget::Name {
                    hint,
                    name: name.to_vec(),
                },
            };
            imports.push(PeImport {
                library: library.clone(),
                lookup_rva: lookup_table_rva + index * 8,
                iat_rva: iat_rva + index * 8,
                target,
            });
            index += 1;
        }
    }

    Ok(imports)
}

fn parse_exports(pe: &PeFile64<'_>) -> Result<Vec<PeExport>, object::read::Error> {
    let Some(export_table) = pe.export_table()? else {
        return Ok(Vec::new());
    };

    let mut exports = Vec::new();
    for (name_pointer, address_index) in export_table.name_iter() {
        let rva = export_table.address_by_index(u32::from(address_index))?;
        if export_table.is_forward(rva) {
            continue;
        }
        exports.push(PeExport {
            name: export_table.name_from_pointer(name_pointer)?.to_vec(),
            rva,
        });
    }

    Ok(exports)
}

fn parse_relocations(pe: &PeFile64<'_>) -> Result<Vec<Relocation>, object::read::Error> {
    let Some(mut blocks) = pe
        .data_directories()
        .relocation_blocks(pe.data(), &pe.section_table())?
    else {
        return Ok(Vec::new());
    };

    let mut relocations = Vec::new();
    while let Some(block) = blocks.next()? {
        relocations.extend(block);
    }

    Ok(relocations)
}
