use anyhow::{Result, anyhow};
use log::{warn, debug, info};
use unicorn_engine::{Unicorn, Arch, Mode, RegisterX86};
use std::collections::HashMap;


use crate::config::{EmuConfig, Architecture};
use crate::ExportedFunction;
use crate::memory::{MemoryManager, PROT_READ, PROT_WRITE, PROT_EXEC, PROT_ALL};
use crate::loader::{PeLoader, DllLoader};
use crate::os::WindowsRuntime;

// Hook helpers moved into dedicated modules
use crate::hooks::{memory, api};

pub struct EmuCore {
    config: EmuConfig,
    memory_manager: MemoryManager,
    loader: PeLoader,
    dll_loader: DllLoader,
    windows_runtime: WindowsRuntime,
    unicorn: Option<Unicorn<'static, ()>>,

    /// Optional shared trace file writer (JSON lines). Present only if `--trace-file` was provided.
    trace_writer: Option<std::sync::Arc<std::sync::Mutex<std::fs::File>>>,

    /// Map of exported functions collected from `inventory`:
    /// dll -> (function -> pointer)
    exported_functions: crate::ExportMap,
}

impl EmuCore {
    pub fn new(config: EmuConfig) -> Result<Self> {
        info!("Creating emulator core for {:?}", config.binary);
        let dll_loader = DllLoader::new(config.rootfs.clone());

        // Build exported functions map from inventory
        let mut exported_functions: crate::ExportMap = HashMap::new();
        for ef in inventory::iter::<ExportedFunction> {
            let dll = ef.dll.to_lowercase();
            let name = ef.function.to_string();
            exported_functions.entry(dll).or_default().insert(name, ef.pointer);
        }

        Ok(Self {
            config,
            memory_manager: MemoryManager::new(),
            loader: PeLoader::new(),
            dll_loader,
            windows_runtime: WindowsRuntime::new(),
            unicorn: None,
            trace_writer: None,
            exported_functions,
        })
    }

    /// Allocate `size` bytes from the process heap, returning the pointer if successful.
    pub fn heap_alloc(&mut self, size: u64) -> Option<u64> {
        self.memory_manager.heap_alloc(size)
    }

    /// Set the return value register (RAX for x86_64, EAX for x86).
    pub fn set_return_u64(&mut self, val: u64) -> Result<()> {
        match self.config.architecture.unwrap() {
            Architecture::X86_64 => {
                if let Some(uc) = &mut self.unicorn {
                    uc.reg_write(RegisterX86::RAX, val)?;
                }
            }
            Architecture::X86 => {
                if let Some(uc) = &mut self.unicorn {
                    uc.reg_write(RegisterX86::EAX, val)?;
                }
            }
        }
        Ok(())
    }

    /// Read the first argument (pointer or size) depending on arch: RCX on x64, [ESP+4] on x86.
    pub fn first_arg_u64(&mut self) -> Option<u64> {
        if let Some(uc) = &mut self.unicorn {
            match self.config.architecture.unwrap() {
                Architecture::X86_64 => {
                    return uc.reg_read(RegisterX86::RCX).ok();
                }
                Architecture::X86 => {
                    if let Ok(esp) = uc.reg_read(RegisterX86::ESP) {
                        let addr = esp.wrapping_add(4);
                        let mut buf = [0u8; 4];
                        if uc.mem_read(addr, &mut buf).is_ok() {
                            return Some(u32::from_le_bytes(buf).into());
                        }
                    }
                }
            }
        }
        None
    }

    /// Convenience wrapper for `malloc` semantics kept for compatibility.
    pub fn malloc_arg(&mut self) -> Option<u64> {
        self.first_arg_u64()
    }

    /// Return pointer size in bytes for current architecture
    pub fn ptr_size(&self) -> u64 {
        match self.config.architecture.unwrap() {
            Architecture::X86_64 => 8,
            Architecture::X86 => 4,
        }
    }

    /// Write a pointer-sized value to memory (ptr-sized: 4 or 8 bytes depending on arch)
    pub fn write_ptr(&mut self, addr: u64, val: u64) -> Result<()> {
        let psz = self.ptr_size();
        if let Some(uc) = &mut self.unicorn {
            match psz {
                8 => self.memory_manager.write_u64(uc, addr, val)?,
                4 => self.memory_manager.write_u32(uc, addr, val as u32)?,
                _ => self.memory_manager.write_u64(uc, addr, val)?,
            }
            Ok(())
        } else {
            Err(anyhow!("Unicorn not initialized"))
        }
    }

    /// Stop the running emulation (calls Unicorn emu_stop)
    pub fn emu_stop(&mut self) {
        if let Some(uc) = &mut self.unicorn {
            let _ = uc.emu_stop();
        }
    }

    pub fn run(&mut self) -> Result<()> {
        info!("Bootstrapping runtime path {:?}", self.config.rootfs);

        // Parse the PE file
        let arch = self.loader.parse(&self.config.binary, &mut self.memory_manager)?;
        
        if let Some(specified) = self.config.architecture {
            if arch != specified {
                warn!("Warning: specified architecture {:?} does not match detected PE architecture {:?}", specified, arch);
            }
        } else {
            self.config.architecture = Some(arch);
            info!("Auto-detected architecture: {:?}", arch);
        }

        self.prepare_unicorn()?;

        // Map the PE sections
        if let Some(unicorn) = &mut self.unicorn {
            for section in &self.loader.sections {
                if section.virtual_size > 0 {
                    self.memory_manager.map(
                        unicorn,
                        section.virtual_address,
                        section.virtual_size,
                        section.permissions,
                        &section.name
                    )?;
                    self.memory_manager.write(unicorn, section.virtual_address, &section.data)?;
                }
            }

            // Add a memory hook to capture FETCH_UNMAPPED to aid debugging
            // (log nearby memory and IAT page when it happens)
            // Prepare section ranges to search for pointers in case we need to reverse-map an IAT
            let search_ranges: Vec<(u64,u64)> = self.loader.sections.iter().map(|s| (s.virtual_address, s.virtual_size)).collect();

            // Snapshot of imports so closure can attempt auto-fix
            use crate::loader::pe::ImportInfo;
            let imports_snapshot: Vec<(u64, ImportInfo)> = self.loader.import_symbols.iter().map(|(k,v)| (*k, v.clone())).collect();
            let image_base = self.loader.image_base;

            let fetch_ctx = memory::FetchContext { search_ranges, imports_snapshot, image_base };
            let hook_callback = move |uc: &mut Unicorn<'_, ()>, mem_type: unicorn_engine::MemType, addr: u64, size: usize, value: i64| -> bool {
                memory::fetch_unmapped_handler(uc, mem_type, addr, size, value, &fetch_ctx)
            };
            let _ = unicorn.add_mem_hook(unicorn_engine::HookType::MEM_FETCH_UNMAPPED, 0, u64::MAX, hook_callback)?;

            #[cfg(feature = "capstone")]
            {
                let arch = self.config.architecture.unwrap();
                let _ = unicorn.add_code_hook(0, u64::MAX, move |uc, _, _| crate::hooks::disasm::disasm_hook(uc, arch))?;
            }
        }

        // Load system DLLs and resolve imports
        self.load_system_dlls()?;
        self.resolve_imports()?;

        self.initialize_windows()?;
        self.initialize_syscall_hooks()?;

        // Start execution
        if let Some(unicorn) = &mut self.unicorn {
            if let Some(entry_point) = self.loader.entry_point {
                debug!("Starting execution at {:#x}", entry_point);
                
                // Set the program counter and stack pointer
                match self.config.architecture.unwrap() {
                    Architecture::X86 => {
                        unicorn.reg_write(RegisterX86::EIP, entry_point)?;
                        // Set up stack pointer (ESP) - use a reasonable stack address
                        let stack_top = 0x000F0000; // Near the stack base from TEB
                        unicorn.reg_write(RegisterX86::ESP, stack_top)?;
                    }
                    Architecture::X86_64 => {
                        unicorn.reg_write(RegisterX86::RIP, entry_point)?;
                        // Set up stack pointer (RSP)
                        let stack_top = 0x000F0000u64;
                        unicorn.reg_write(RegisterX86::RSP, stack_top)?;
                    }
                }

                // Determine end address - for now, run until timeout or exit
                let end_addr = 0; // Run until timeout or manual stop
                let timeout = self.config.timeout_ms.unwrap_or(5000); // Default 5 second timeout
                
                // Debug: dump memory layout
                debug!("Memory layout before execution:");
                for region in self.memory_manager.get_memory_layout() {
                    let mut perms_str = String::with_capacity(3);
                    perms_str.push(if region.perms & PROT_READ != 0 { 'r' } else { '-' });
                    perms_str.push(if region.perms & PROT_WRITE != 0 { 'w' } else { '-' });
                    perms_str.push(if region.perms & PROT_EXEC != 0 { 'x' } else { '-' });
                    debug!("  {:#010x}-{:#010x} {} {}", region.start, region.end, perms_str, region.label);
                }
                
                debug!("Starting emulation with {}ms timeout", timeout);
                match unicorn.emu_start(entry_point, end_addr, timeout * 1000, 0) {
                    Ok(()) => {
                        debug!("Emulation completed successfully");
                    }
                    Err(e) => {
                        // Check if this is an expected error (memory access issues are normal)
                        let err_str = format!("{:?}", e);
                        if err_str.contains("READ_UNMAPPED") || err_str.contains("WRITE_UNMAPPED") || err_str.contains("FETCH_UNMAPPED") {
                            debug!("Emulation started successfully but encountered unmapped memory access (expected for incomplete setup)");
                        } else {
                            return Err(anyhow!("Emulation failed: {:?}", e));
                        }
                    }
                }
            } else {
                return Err(anyhow!("No entry point found"));
            }
        }

        Ok(())
    }

    fn load_system_dlls(&mut self) -> Result<()> {
        // Load common system DLLs
        let system_dlls = vec!["kernel32.dll", "msvcrt.dll", "user32.dll"];
        
        for dll_name in system_dlls {
            self.dll_loader.load_system_dll(dll_name)?;
            log::info!("Loaded system DLL: {}", dll_name);
        }
        
        Ok(())
    }

    fn resolve_imports(&mut self) -> Result<()> {
        // precompute raw self pointer and master exports clone to avoid double-borrows of self
        let emu_raw = self as *mut EmuCore;
        let exports_master = self.exported_functions.clone();

        if let Some(unicorn) = &mut self.unicorn {
            // Ensure we reserve and map hook space for all imports
            let num_hooks = self.loader.import_symbols.len() as u64;
            if num_hooks > 0 {
                let hook_space_base = 0x10000000u64;
                let hook_space_size = (num_hooks * 0x100).div_ceil(0x1000) * 0x1000; // page aligned
                if self.memory_manager.is_region_free(hook_space_base, hook_space_size) {
                    log::debug!("Mapping hook space at {:#x}, size {:#x}", hook_space_base, hook_space_size);
                    self.memory_manager.map(unicorn, hook_space_base, hook_space_size, PROT_ALL, "[IAT_HOOKS]")?;
                }

                // Write simple trampoline (ret) at each hook address so fetch succeeds
                for &hook_addr in self.loader.import_symbols.keys() {
                    // one-byte RET (0xC3) is enough; pad rest with NOPs
                    let mut page = vec![0u8; 0x10];
                    page[0] = 0xC3; // ret
                    self.memory_manager.write(unicorn, hook_addr, &page)?;
                }
            }

            // Scan mapped sections for other references to the IAT (e.g., RVAs or other copies)
            // and patch them to point to the hook address. This prevents indirect jumps that read
            // small RVAs (like 0x8410) from being used directly as unmapped instruction pointers.
            for (&addr, info) in &self.loader.import_symbols {
                // Precompute patterns to search for: orig_iat (if present) and the RVA for the IAT
                let mut patterns: Vec<[u8;8]> = Vec::new();
                if let Some(orig) = info.orig_iat {
                    patterns.push(orig.to_le_bytes());
                }
                if info.iat_va >= self.loader.image_base {
                    let rva = info.iat_va.wrapping_sub(self.loader.image_base);
                    // Only treat small RVAs as likely stored as 64-bit pointers in the image
                    if rva < 0x1000000 {
                        patterns.push(rva.to_le_bytes());
                    }
                }

                if !patterns.is_empty() {
                    // Search each section in pages to avoid large reads
                    for section in &self.loader.sections {
                        if section.virtual_size == 0 { continue; }
                        let mut offset = 0u64;
                        let page_size = 0x1000u64;
                        while offset < section.virtual_size {
                            let read_len = std::cmp::min(page_size, section.virtual_size - offset) as usize;
                            let va = section.virtual_address + offset;
                            if let Ok(chunk) = self.memory_manager.read(unicorn, va, read_len) {
                                for i in 0..(chunk.len().saturating_sub(8)) {
                                    let mut raw = [0u8;8];
                                    raw.copy_from_slice(&chunk[i..i+8]);
                                    for pat in &patterns {
                                        if &raw == pat {
                                            let found_va = va + i as u64;
                                            log::debug!("Patching occurrence at {:#x} (section {}) to hook {:#x}", found_va, section.name, addr);
                                            self.memory_manager.write_u64(unicorn, found_va, addr)?;
                                        }
                                    }
                                }
                            }
                            offset += read_len as u64;
                        }
                    }
                }

                // Verify the IAT value in memory matches the hook address; if not, fix it
                let mut buf = vec![0u8; 8];
                if let Ok(read) = self.memory_manager.read(unicorn, info.iat_va, 8) {
                    buf.copy_from_slice(&read);
                    let existing = u64::from_le_bytes(buf.as_slice().try_into().unwrap());
                    if existing != addr {
                        log::warn!("IAT at {:#x} contains {:#x}, expected hook {:#x}. Overwriting.", info.iat_va, existing, addr);
                        self.memory_manager.write_u64(unicorn, info.iat_va, addr)?;
                    } else {
                        log::debug!("IAT at {:#x} already contains hook {:#x}", info.iat_va, addr);
                    }
                } else {
                    log::warn!("Failed to read IAT at {:#x}", info.iat_va);
                }

                let dll_name = info.dll.to_lowercase();
                let function_name = if let Some(name) = &info.name {
                    name.clone()
                } else {
                    format!("Ordinal{}", info.ordinal)
                };

                // use precomputed raw pointer and master export map
                let exports_clone = exports_master.clone();
                Self::setup_api_hook(unicorn, addr, &dll_name, &function_name, emu_raw, exports_clone)?;
                log::debug!("Set up hook for import {}!{} at {:#x}", dll_name, function_name, addr);
            }
        }
        
        Ok(())
    }

    fn setup_api_hook(unicorn: &mut Unicorn<'static, ()>, address: u64, dll_name: &str, function_name: &str, emu_raw: *mut EmuCore, exports: crate::ExportMap) -> Result<()> {
        // For now, log the call and, if an exported function exists for this API, call it.
        let dll = dll_name.to_string();
        let func = function_name.to_string();

        let hook_callback = move |uc: &mut Unicorn<'_, ()>, _addr: u64, _size: u32| {
            // SAFETY: `emu_raw` originates from a valid &mut EmuCore captured in setup
            unsafe { api::api_hook_handler(uc, &dll, &func, emu_raw, &exports); }
        };

        let _ = unicorn.add_code_hook(address, address, hook_callback)?;

        Ok(())
    }

    fn prepare_unicorn(&mut self) -> Result<()> {
        let unicorn = match self.config.architecture.unwrap() {
            Architecture::X86 => Unicorn::new(Arch::X86, Mode::MODE_32)?,
            Architecture::X86_64 => Unicorn::new(Arch::X86, Mode::MODE_64)?,
        };
        self.unicorn = Some(unicorn);

        // If tracing to a file was requested, open it now and keep a shared writer
        if let Some(ref trace_path) = self.config.trace_file {
            match std::fs::File::create(trace_path) {
                Ok(fh) => {
                    self.trace_writer = Some(std::sync::Arc::new(std::sync::Mutex::new(fh)));
                    debug!("Trace file opened: {:?}", trace_path);
                }
                Err(e) => {
                    log::error!("Failed to open trace file {:?}: {:?}", trace_path, e);
                }
            }
        }

        debug!("Unicorn backend prepared for {:?}", self.config.architecture);
        Ok(())
    }

    fn initialize_windows(&mut self) -> Result<()> {
        if let Some(unicorn) = &mut self.unicorn {
            self.windows_runtime.initialize(unicorn, &mut self.memory_manager, self.loader.image_base, self.config.architecture.unwrap())?;
        }
        debug!("Windows runtime initialized");
        Ok(())
    }

    fn initialize_syscall_hooks(&mut self) -> Result<()> {
        if let Some(unicorn) = &mut self.unicorn {
            // Pass trace mode and optional writer into the Windows runtime so hooks can emit JSON-lines traces
            let writer = self.trace_writer.clone();
            self.windows_runtime.initialize_hooks(unicorn, self.config.trace_mode, writer)?;
        }
        debug!("Syscall hooks initialized");
        Ok(())
    }
}

