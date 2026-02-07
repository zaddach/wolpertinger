use unicorn_engine::{Unicorn, MemType};

/// Context for the `fetch_unmapped_handler` callback to avoid long argument lists.
/// Holds owned data so it can be moved into a long-lived hook closure.
pub struct FetchContext {
    pub search_ranges: Vec<(u64, u64)>,
    pub imports_snapshot: Vec<(u64, crate::loader::pe::ImportInfo)>,
    pub image_base: u64,
}

/// Handler for MEM_FETCH_UNMAPPED and similar memory hooks.
pub fn fetch_unmapped_handler(
    uc: &mut Unicorn<'_, ()>,
    _mem_type: MemType,
    addr: u64,
    _size: usize,
    _value: i64,
    ctx: &FetchContext,
) -> bool {
    log::error!("FETCH_UNMAPPED at {:#x}", addr);
    log::error!("FETCH_UNMAPPED at {:#x}", addr);

    // try to dump 64 bytes around addr (page-aligned)
    let page = addr & !(0xfff);
    for i in 0..4u64 {
        let off = page + i * 16;
        let mut buf = vec![0u8; 16];
        match uc.mem_read(off, &mut buf) {
            Ok(()) => {
                let vals: Vec<String> = buf
                    .chunks(8)
                    .map(|c| format!("{:#x}", u64::from_le_bytes(c.try_into().unwrap_or([0u8; 8]))))
                    .collect();
                log::error!("mem {:#x}: {}", off, vals.join(", "));
            }
            Err(e) => {
                log::error!("mem {:#x}: read error: {:?}", off, e);
            }
        }
    }

    // Also check if hook-space is mapped
    let hook_base = 0x10000000u64;
    let mut hookbuf = vec![0u8; 16];
    match uc.mem_read(hook_base, &mut hookbuf) {
        Ok(()) => log::error!("hook-space {:#x}: {:x?}", hook_base, hookbuf),
        Err(e) => log::error!("hook-space read error: {:?}", e),
    }

    // Search mapped sections for occurrences of the target pointer (addr)
    let needle = addr.to_le_bytes();
    for (base, size) in &ctx.search_ranges {
        let mut offset = 0u64;
        while offset < *size {
            let read_addr = *base + offset;
            let mut buf = vec![0u8; 0x100];
            if uc.mem_read(read_addr, &mut buf).is_err() {
                break;
            }
            for i in 0..(buf.len() - 8) {
                if buf[i..i + 8] == needle {
                    let found_va = read_addr + i as u64;
                    log::error!("Found pointer {:#x} in section at VA {:#x}", addr, found_va);

                    // Interpret the referenced 8 bytes as a value
                    let mut raw = [0u8; 8];
                    raw.copy_from_slice(&buf[i..i + 8]);
                    let val = u64::from_le_bytes(raw);

                    // If this is a small value, treat as RVA and compute absolute
                    let threshold = 0x1000000u64;
                    let mut patched = false;
                    if val < threshold {
                        let target_va = ctx.image_base.wrapping_add(val);
                        log::error!("Pointer looks like RVA {:#x}, resolves to VA {:#x}", val, target_va);

                        // Try to patch the location directly so jmp will read the hook address
                        for (hook_addr, info) in &ctx.imports_snapshot {
                            if info.iat_va == target_va || info.orig_iat == Some(val) {
                                log::error!("Auto-patching referencing location {:#x} and IAT {:#x} to hook {:#x}", found_va, info.iat_va, hook_addr);
                                let hdata = (*hook_addr).to_le_bytes();
                                let _ = uc.mem_write(found_va, &hdata);
                                let _ = uc.mem_write(info.iat_va, &hdata);
                                patched = true;
                            }
                        }
                    }

                    // Fallback: if we didn't patch via RVA, try matching orig_iat == addr
                    if !patched {
                        for (hook_addr, info) in &ctx.imports_snapshot {
                            if let Some(orig) = info.orig_iat && orig == addr {
                                log::error!("Auto-patching IAT at {:#x} to hook {:#x}", info.iat_va, hook_addr);
                                let data = (*hook_addr).to_le_bytes();
                                if let Err(e) = uc.mem_write(info.iat_va, &data) {
                                    log::error!("Failed to write IAT at {:#x}: {:?}", info.iat_va, e);
                                }
                                //patched = true; // not used further
                            }
                        }
                    }
                }
            }
            offset += 0x100;
        }
    }

    true
}
