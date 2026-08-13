#[derive(Debug, PartialEq)]
pub enum LoaderError {
    Malformed(String),
    EntryPointOutsideExecutable,
    Unknown,
}

#[derive(Debug, PartialEq)]
pub struct RelocatedImage {
    pub base_address: usize,
    pub entry_point: usize,
    pub size: usize,
}

/// M1: PE loader / relocator
///
/// Takes bytes of a .sys and either loads it or rejects it.
pub fn load_pe(pe_bytes: &[u8]) -> Result<RelocatedImage, LoaderError> {
    if pe_bytes.len() < 64 {
        return Err(LoaderError::Malformed("Too small for DOS header".into()));
    }

    // Check DOS magic (MZ)
    if pe_bytes[0] != b'M' || pe_bytes[1] != b'Z' {
        return Err(LoaderError::Unknown);
    }

    // e_lfanew is at offset 0x3C
    let e_lfanew = u32::from_le_bytes(pe_bytes[0x3C..0x40].try_into().unwrap()) as usize;

    if pe_bytes.len() < e_lfanew + 24 { // NT header + File header size
        return Err(LoaderError::Malformed("Too small for NT header".into()));
    }

    // Check PE magic (PE\0\0)
    if pe_bytes[e_lfanew] != b'P' || pe_bytes[e_lfanew+1] != b'E' || pe_bytes[e_lfanew+2] != 0 || pe_bytes[e_lfanew+3] != 0 {
        return Err(LoaderError::Unknown);
    }

    let size_of_optional_header = u16::from_le_bytes(pe_bytes[e_lfanew + 20..e_lfanew + 22].try_into().unwrap()) as usize;
    let number_of_sections = u16::from_le_bytes(pe_bytes[e_lfanew + 6..e_lfanew + 8].try_into().unwrap()) as usize;

    let optional_header_offset = e_lfanew + 24;

    if pe_bytes.len() < optional_header_offset + size_of_optional_header {
        return Err(LoaderError::Malformed("Too small for Optional header".into()));
    }

    // Optional header magic (PE32+ is 0x020B, PE32 is 0x010B)
    let opt_magic = u16::from_le_bytes(pe_bytes[optional_header_offset..optional_header_offset+2].try_into().unwrap());

    let (image_base, entry_point, size_of_image) = if opt_magic == 0x020B {
        let entry_point = u32::from_le_bytes(pe_bytes[optional_header_offset+16..optional_header_offset+20].try_into().unwrap()) as usize;
        let image_base = u64::from_le_bytes(pe_bytes[optional_header_offset+24..optional_header_offset+32].try_into().unwrap()) as usize;
        let size_of_image = u32::from_le_bytes(pe_bytes[optional_header_offset+56..optional_header_offset+60].try_into().unwrap()) as usize;
        (image_base, entry_point, size_of_image)
    } else if opt_magic == 0x010B {
        let entry_point = u32::from_le_bytes(pe_bytes[optional_header_offset+16..optional_header_offset+20].try_into().unwrap()) as usize;
        let image_base = u32::from_le_bytes(pe_bytes[optional_header_offset+28..optional_header_offset+32].try_into().unwrap()) as usize;
        let size_of_image = u32::from_le_bytes(pe_bytes[optional_header_offset+56..optional_header_offset+60].try_into().unwrap()) as usize;
        (image_base, entry_point, size_of_image)
    } else {
        return Err(LoaderError::Malformed("Unknown optional header magic".into()));
    };

    let section_headers_offset = optional_header_offset + size_of_optional_header;
    if pe_bytes.len() < section_headers_offset + (number_of_sections * 40) {
        return Err(LoaderError::Malformed("Too small for Section headers".into()));
    }

    let mut entry_point_valid = false;
    let mut last_section_end = 0;

    for i in 0..number_of_sections {
        let offset = section_headers_offset + (i * 40);
        let virtual_size = u32::from_le_bytes(pe_bytes[offset+8..offset+12].try_into().unwrap()) as usize;
        let virtual_address = u32::from_le_bytes(pe_bytes[offset+12..offset+16].try_into().unwrap()) as usize;
        let characteristics = u32::from_le_bytes(pe_bytes[offset+36..offset+40].try_into().unwrap());

        let section_end = virtual_address + virtual_size;

        if virtual_address < last_section_end {
            return Err(LoaderError::Malformed("Overlapping sections".into()));
        }
        last_section_end = section_end;

        if entry_point >= virtual_address && entry_point < section_end {
            let is_executable = (characteristics & 0x20000000) != 0;
            if is_executable {
                entry_point_valid = true;
            }
        }
    }

    if !entry_point_valid && entry_point != 0 {
        return Err(LoaderError::EntryPointOutsideExecutable);
    }

    Ok(RelocatedImage {
        base_address: image_base,
        entry_point,
        size: size_of_image,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_minimal_pe(entry_point_offset: u32, section_flags: u32, overlapping: bool) -> Vec<u8> {
        let mut pe = vec![0u8; 1024];

        // DOS Header
        pe[0] = b'M'; pe[1] = b'Z';
        pe[0x3C] = 0x80; // e_lfanew

        // NT Headers
        pe[0x80] = b'P'; pe[0x81] = b'E'; pe[0x82] = 0; pe[0x83] = 0;
        pe[0x86] = 2; // NumberOfSections = 2
        pe[0x94] = 0xF0; // SizeOfOptionalHeader = 240 (standard PE32+)

        // Optional Header (PE32+)
        pe[0x98] = 0x0B; pe[0x99] = 0x02; // Magic (0x020B)
        pe[0x98 + 16..0x98 + 20].copy_from_slice(&entry_point_offset.to_le_bytes()); // AddressOfEntryPoint
        pe[0x98 + 24..0x98 + 32].copy_from_slice(&0x10000u64.to_le_bytes()); // ImageBase
        pe[0x98 + 56..0x98 + 60].copy_from_slice(&0x2000u32.to_le_bytes()); // SizeOfImage

        let section_headers = 0x98 + 0xF0; // 0x188

        // Section 1 (.text)
        pe[section_headers + 8..section_headers + 12].copy_from_slice(&0x100u32.to_le_bytes()); // VirtualSize
        pe[section_headers + 12..section_headers + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
        pe[section_headers + 36..section_headers + 40].copy_from_slice(&section_flags.to_le_bytes()); // Characteristics

        // Section 2 (.data)
        pe[section_headers + 40 + 8..section_headers + 40 + 12].copy_from_slice(&0x100u32.to_le_bytes()); // VirtualSize

        if overlapping {
            pe[section_headers + 40 + 12..section_headers + 40 + 16].copy_from_slice(&0x1050u32.to_le_bytes()); // VirtualAddress (Overlaps with sec 1)
        } else {
            pe[section_headers + 40 + 12..section_headers + 40 + 16].copy_from_slice(&0x1100u32.to_le_bytes()); // VirtualAddress (Valid)
        }

        pe
    }

    #[test]
    fn test_sploit_malformed_pe_rejected() {
        let pe = create_minimal_pe(0x1000, 0x20000000, true); // Overlapping sections
        let result = load_pe(&pe);
        assert_eq!(result, Err(LoaderError::Malformed("Overlapping sections".into())));
    }

    #[test]
    fn test_clean_well_formed_pe_loaded() {
        let pe = create_minimal_pe(0x1010, 0x20000000, false); // Valid entry point in executable section
        let result = load_pe(&pe);
        assert_eq!(result, Ok(RelocatedImage {
            base_address: 0x10000,
            entry_point: 0x1010,
            size: 0x2000,
        }));
    }

    #[test]
    fn test_fail_closed_on_unknown() {
        let bad_entry_pe = create_minimal_pe(0x1200, 0x20000000, false); // Entry point outside executable section
        let result = load_pe(&bad_entry_pe);
        assert_eq!(result, Err(LoaderError::EntryPointOutsideExecutable));

        let mut unknown = vec![0u8; 1024];
        unknown[0..9].copy_from_slice(b"UNKNOWN  ");
        assert_eq!(load_pe(&unknown), Err(LoaderError::Unknown));

        let garbage = b"garbage";
        assert_eq!(load_pe(garbage), Err(LoaderError::Malformed("Too small for DOS header".into())));
    }
}
