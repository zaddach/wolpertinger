use goblin::Object;
use std::fs;
use std::io;
use std::collections::HashMap;
use crate::Architecture;
use crate::memory::Protection;
use crate::memory::MemoryManager;

#[derive(Debug)]
pub struct Section {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub permissions: Protection,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct ImportInfo {
    pub dll: String,
    pub name: Option<String>,
    pub ordinal: u16,
    pub iat_va: u64, // Virtual address where the IAT entry resides (image_base + rva)
    pub orig_iat: Option<u64>,
}

pub struct PeLoader {
    pub entry_point: Option<u64>,
    pub image_base: u64,
    pub image_size: u64,
    pub sections: Vec<Section>,
    pub import_symbols: HashMap<u64, ImportInfo>,
    pub api_hooks: Vec<(u64, String, String)>,
}

impl Default for PeLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl PeLoader {
    pub fn new() -> Self {
        Self {
            entry_point: None,
            image_base: 0x400000, // default
            image_size: 0,
            sections: Vec::new(),
            import_symbols: HashMap::new(),
            api_hooks: Vec::new(),
        }
    }

    pub fn parse(&mut self, path: &std::path::Path, _memory_manager: &mut MemoryManager) -> io::Result<Architecture> {
        let bytes = fs::read(path)?;
        let obj = Object::parse(&bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        match obj {
            Object::PE(pe) => {
                log::info!("Parsed PE binary: {} sections", pe.sections.len());

                // Get preferred image base
                let preferred_base = pe.header.optional_header.unwrap().windows_fields.image_base;
                self.image_size = pe.header.optional_header.unwrap().windows_fields.size_of_image as u64;

                // Use the preferred image base
                self.image_base = preferred_base;
                // Set entry point
                let entry_rva = pe.header.optional_header.unwrap().standard_fields.address_of_entry_point;
                self.entry_point = Some(self.image_base + entry_rva);

                log::info!("Image base: {:#x}, size: {:#x}, entry: {:#x}",
                          self.image_base, self.image_size, self.entry_point.unwrap());

                // Map PE headers into memory so code that reads the DOS/PE header at
                // image_base (e.g., checking for "MZ" / 'PE') can succeed.
                let size_of_headers = pe.header.optional_header.unwrap().windows_fields.size_of_headers as usize;
                if size_of_headers > 0 {
                    let mut hdr_data = vec![0u8; size_of_headers];
                    let copy_len = std::cmp::min(size_of_headers, bytes.len());
                    hdr_data[..copy_len].copy_from_slice(&bytes[..copy_len]);
                    // Use PROT_READ for headers
                    self.sections.insert(0, Section {
                        name: ".headers".to_string(),
                        virtual_address: self.image_base,
                        virtual_size: size_of_headers as u64,
                        permissions: crate::memory::PROT_READ,
                        data: hdr_data,
                    });
                    log::debug!("Added headers region: VA {:#x}, size {:#x}", self.image_base, size_of_headers);
                }

                // Parse sections
                for section in &pe.sections {
                    let name = String::from_utf8_lossy(&section.name).trim_end_matches('\0').to_string();
                    let va = self.image_base + section.virtual_address as u64;
                    let vsize = section.virtual_size as u64;
                    let perms = self.section_permissions(section.characteristics);

                    log::info!("Section {}: VA {:#x}, size {:#x}, perms {:?}", name, va, vsize, perms);

                    // Get section data
                    let offset = section.pointer_to_raw_data as usize;
                    let size = section.size_of_raw_data as usize;
                    let data = if offset + size <= bytes.len() {
                        bytes[offset..offset + size].to_vec()
                    } else {
                        vec![0; vsize as usize] // zero-fill if invalid
                    };

                    self.sections.push(Section {
                        name,
                        virtual_address: va,
                        virtual_size: vsize,
                        permissions: perms,
                        data,
                    });
                }

                // Apply relocations now that sections are parsed
                self.apply_relocations(&pe, preferred_base, self.image_base, &bytes)?;

                // Parse imports
                for import in &pe.imports {
                    log::info!("Import from {}: {:?}", import.dll, import.name);
                    let dll_name = import.dll.to_string();
                    let name = if import.name.is_empty() {
                        format!("ordinal_{}", import.ordinal)
                    } else {
                        import.name.to_string()
                    };
                    let rva = import.rva as u64;
                    let hook_addr = 0x10000000 + self.import_symbols.len() as u64 * 0x100;

                    // Write hook_addr to the IAT location and record iat_va
                    let va = self.image_base + rva;
                    if let Some(section) = self.sections.iter_mut().find(|s| va >= s.virtual_address && va < s.virtual_address + s.virtual_size) {
                        let offset_in_section = (va - section.virtual_address) as usize;

                        // Log original value at IAT (if available in section data)
                        if offset_in_section + 8 <= section.data.len() {
                            let orig = u64::from_le_bytes([
                                section.data[offset_in_section],
                                section.data[offset_in_section + 1],
                                section.data[offset_in_section + 2],
                                section.data[offset_in_section + 3],
                                section.data[offset_in_section + 4],
                                section.data[offset_in_section + 5],
                                section.data[offset_in_section + 6],
                                section.data[offset_in_section + 7],
                            ]);
                            log::debug!("Original IAT value at VA {:#x}: {:#x}", va, orig);

                            section.data[offset_in_section..offset_in_section + 8].copy_from_slice(&hook_addr.to_le_bytes());

                            log::debug!("Wrote hook {:#x} into IAT at VA {:#x} (section {} offset {:#x})", hook_addr, va, section.name, offset_in_section);

                            self.import_symbols.insert(hook_addr, ImportInfo {
                                dll: dll_name.clone(),
                                name: Some(name.clone()),
                                ordinal: import.ordinal,
                                iat_va: va,
                                orig_iat: Some(orig),
                            });
                        } else {
                            log::warn!("IAT entry out of bounds: section {} has {} bytes, offset {}", section.name, section.data.len(), offset_in_section);

                            self.import_symbols.insert(hook_addr, ImportInfo {
                                dll: dll_name.clone(),
                                name: Some(name.clone()),
                                ordinal: import.ordinal,
                                iat_va: va,
                                orig_iat: None,
                            });
                        }
                    } else {
                        log::warn!("Could not find section for IAT RVA {:#x}", rva);
                        // still insert so we can attempt to resolve later
                        self.import_symbols.insert(hook_addr, ImportInfo {
                            dll: dll_name.clone(),
                            name: Some(name.clone()),
                            ordinal: import.ordinal,
                            iat_va: va,
                            orig_iat: None,
                        });
                    }
                }

                match pe.header.coff_header.machine {
                    goblin::pe::header::COFF_MACHINE_X86 => Ok(Architecture::X86),
                    goblin::pe::header::COFF_MACHINE_X86_64 => Ok(Architecture::X86_64),
                    other => Err(io::Error::new(io::ErrorKind::InvalidData, format!("Unsupported PE machine type: {:#x}", other))),
                }
            }
            _ => {
                Err(io::Error::new(io::ErrorKind::InvalidData, "Not a PE file"))
            }
        }
    }

    fn section_permissions(&self, characteristics: u32) -> Protection {
        use crate::memory::*;
        let mut perms = PROT_READ; // minimum read
        if characteristics & 0x80000000 != 0 { // IMAGE_SCN_MEM_WRITE
            perms |= PROT_WRITE;
        }
        if characteristics & 0x20000000 != 0 { // IMAGE_SCN_MEM_EXECUTE
            perms |= PROT_EXEC;
        }
        perms
    }

    fn apply_relocations(&mut self, _pe: &goblin::pe::PE, old_base: u64, new_base: u64, _buffer: &[u8]) -> io::Result<()> {
        let delta = new_base.wrapping_sub(old_base);
        log::debug!("Applying relocations: old_base={:#x}, new_base={:#x}, delta={:#x}", old_base, new_base, delta);

        if delta == 0 {
            log::debug!("No relocation needed, delta is zero");
            return Ok(());
        }

        log::debug!("Processing relocations from PE");
        // TODO: Parse relocations from PE file
        // For now, skip since goblin doesn't expose relocations field

        Ok(())
    }
}
