pub mod handle;
pub mod registry;
pub mod thread;
mod dlls;

use crate::memory::MemoryManager;
use unicorn_engine::{Unicorn, RegisterX86, unicorn_const::X86Insn};

use anyhow::Result;
use log::{debug, trace};

#[cfg(feature = "capstone")]
use capstone::prelude::*;

// Windows structure definitions
#[repr(C)]
pub struct TEB {
    pub exception_list: u64,        // 0x00
    pub stack_base: u64,           // 0x08
    pub stack_limit: u64,          // 0x10
    pub sub_system_tib: u64,       // 0x18
    pub fiber_data: u64,           // 0x20
    pub version: u32,              // 0x28
    pub arbitrary_user_pointer: u64, // 0x30
    pub self_ptr: u64,             // 0x38
    // ... many more fields, simplified for now
}

#[repr(C)]
pub struct PEB {
    pub inherited_address_space: u8,    // 0x00
    pub read_image_file_exec_options: u8, // 0x01
    pub being_debugged: u8,            // 0x02
    pub spare_bool: u8,                // 0x03
    pub mutant: u64,                   // 0x04
    pub image_base_address: u64,       // 0x08
    pub ldr: u64,                      // 0x10
    pub process_parameters: u64,       // 0x18
    // ... many more fields, simplified for now
}

#[repr(C)]
pub struct RTL_USER_PROCESS_PARAMETERS {
    pub maximum_length: u32,
    pub length: u32,
    pub flags: u32,
    pub debug_flags: u32,
    pub console_handle: u32,
    pub console_flags: u32,
    pub standard_input: u32,
    pub standard_output: u32,
    pub standard_error: u32,
    pub current_directory: UNICODE_STRING,
    pub dll_path: UNICODE_STRING,
    pub image_path_name: UNICODE_STRING,
    pub command_line: UNICODE_STRING,
    pub environment: u32,
    // ... more fields
}

#[repr(C)]
pub struct UNICODE_STRING {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: u32,
}

pub struct WindowsRuntime {
    teb_address: Option<u64>,
    peb_address: Option<u64>,
    process_params_address: Option<u64>,
}

impl Default for WindowsRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowsRuntime {
    pub fn new() -> Self {
        Self {
            teb_address: None,
            peb_address: None,
            process_params_address: None,
        }
    }

    pub fn initialize(&mut self, unicorn: &mut Unicorn<'static, ()>, memory_manager: &mut MemoryManager, image_base: u64, arch: crate::Architecture) -> Result<()> {
        self.setup_teb_peb(unicorn, memory_manager, image_base, arch)?;
        self.setup_process_parameters(unicorn, memory_manager)?;
        Ok(())
    }

    fn setup_teb_peb(&mut self, unicorn: &mut Unicorn<'static, ()>, memory_manager: &mut MemoryManager, image_base: u64, arch: crate::Architecture) -> Result<()> {
        // Allocate memory for TEB and PEB
        let teb_addr = 0x60000000; // Use a different address range
        let peb_addr = 0x60001000; // PEB right after TEB

        // Map memory for TEB and PEB
        memory_manager.map(unicorn, peb_addr, 0x1000, crate::memory::PROT_READ | crate::memory::PROT_WRITE, "PEB")?;
        memory_manager.map(unicorn, teb_addr, 0x1000, crate::memory::PROT_READ | crate::memory::PROT_WRITE, "TEB")?;

        // Initialize PEB
        let peb = PEB {
            inherited_address_space: 0,
            read_image_file_exec_options: 0,
            being_debugged: 0,
            spare_bool: 0,
            mutant: 0,
            image_base_address: image_base,
            ldr: 0, // Will be set later
            process_parameters: 0, // Will be set later
        };

        // Write PEB to memory
        let peb_bytes = unsafe {
            std::slice::from_raw_parts(&peb as *const PEB as *const u8, std::mem::size_of::<PEB>())
        };
        memory_manager.write(unicorn, peb_addr, peb_bytes)?;

        // Initialize TEB
        let stack_base = 0x00100000;
        let stack_limit = 0x00010000;
        let stack_size = stack_base - stack_limit;

        let teb = TEB {
            exception_list: 0xFFFFFFFFFFFFFFFF,
            stack_base,
            stack_limit,
            sub_system_tib: 0,
            fiber_data: 0,
            version: 0,
            arbitrary_user_pointer: peb_addr,
            self_ptr: teb_addr,
        };

        // Allocate and map stack memory
        memory_manager.map(unicorn, stack_limit, stack_size, 
                          crate::memory::PROT_READ | crate::memory::PROT_WRITE, "Stack")?;

        // Create and map a simple process heap (used by msvcrt malloc)
        let heap_base = 0x7000_0000u64;
        let heap_size = 0x0100_0000u64; // 16MB
        if memory_manager.is_region_free(heap_base, heap_size) {
            memory_manager.map(unicorn, heap_base, heap_size, crate::memory::PROT_READ | crate::memory::PROT_WRITE, "Heap")?;
            memory_manager.set_heap(heap_base, heap_base + heap_size);
            log::info!("Initialized heap at {:#x} - {:#x}", heap_base, heap_base + heap_size);
        } else {
            log::warn!("Heap region {:#x}-{:#x} not free; skipping heap mapping", heap_base, heap_base + heap_size);
        }

        // Write TEB to memory
        let teb_bytes = unsafe {
            std::slice::from_raw_parts(&teb as *const TEB as *const u8, std::mem::size_of::<TEB>())
        };
        memory_manager.write(unicorn, teb_addr, teb_bytes)?;

        // Store addresses
        self.teb_address = Some(teb_addr);
        self.peb_address = Some(peb_addr);

        trace!("Setting segment base for TEB at {:#x} (arch={:?})", teb_addr, arch);

        // Use arch-aware behavior: x86_64 uses GS_BASE, x86 uses FS_BASE (segment selectors are different on x86)
        match arch {
            crate::Architecture::X86_64 => {
                // Set GS base to TEB for x64
                let _ = unicorn.reg_write(RegisterX86::GS_BASE, teb_addr);
            }
            crate::Architecture::X86 => {
                // For 32-bit, set FS base to TEB (truncate to 32-bit)
                let teb32 = teb_addr & 0xffff_ffff;
                let _ = unicorn.reg_write(RegisterX86::FS_BASE, teb32);
                // Optionally set the FS selector to a user-data selector (0x3B) if available
                // Note: If RegisterX86::FS exists it sets the selector, but not all Unicorn bindings may expose it.
                let _ = unicorn.reg_write(RegisterX86::FS, 0x3Bu64);
            }
        }

        log::info!("Initialized TEB at {:#x}, PEB at {:#x}", teb_addr, peb_addr);
        Ok(())
    }

    fn setup_process_parameters(&mut self, unicorn: &mut Unicorn<'static, ()>, memory_manager: &mut MemoryManager) -> Result<()> {
        // Allocate memory for process parameters
        let params_addr = 0x60002000; // Use a different address

        memory_manager.map(unicorn, params_addr, 0x1000, crate::memory::PROT_READ | crate::memory::PROT_WRITE, "ProcessParameters")?;

        // Create dummy command line
        let command_line = "tiny.exe\0";
        let cmd_line_addr = params_addr + 0x100;
        memory_manager.write(unicorn, cmd_line_addr, command_line.as_bytes())?;

        // Create dummy image path
        let image_path = "C:\\tiny.exe\0";
        let image_path_addr = params_addr + 0x200;
        memory_manager.write(unicorn, image_path_addr, image_path.as_bytes())?;

        // Initialize process parameters
        let params = RTL_USER_PROCESS_PARAMETERS {
            maximum_length: 0x1000,
            length: 0x1000,
            flags: 0,
            debug_flags: 0,
            console_handle: 0,
            console_flags: 0,
            standard_input: 0,
            standard_output: 0,
            standard_error: 0,
            current_directory: UNICODE_STRING {
                length: 0,
                maximum_length: 0,
                buffer: 0,
            },
            dll_path: UNICODE_STRING {
                length: 0,
                maximum_length: 0,
                buffer: 0,
            },
            image_path_name: UNICODE_STRING {
                length: (image_path.len() * 2) as u16, // Unicode length
                maximum_length: (image_path.len() * 2) as u16,
                buffer: image_path_addr as u32,
            },
            command_line: UNICODE_STRING {
                length: (command_line.len() * 2) as u16,
                maximum_length: (command_line.len() * 2) as u16,
                buffer: cmd_line_addr as u32,
            },
            environment: 0,
        };

        // Write process parameters to memory
        let params_bytes = unsafe {
            std::slice::from_raw_parts(&params as *const RTL_USER_PROCESS_PARAMETERS as *const u8, std::mem::size_of::<RTL_USER_PROCESS_PARAMETERS>())
        };
        memory_manager.write(unicorn, params_addr, params_bytes)?;

        // Update PEB to point to process parameters
        if let Some(peb_addr) = self.peb_address {
            memory_manager.write_u32(unicorn, peb_addr + 0x10, params_addr as u32)?;
        }

        self.process_params_address = Some(params_addr);
        log::info!("Initialized process parameters at {:#x}", params_addr);
        Ok(())
    }

    pub fn get_teb_address(&self) -> Option<u64> {
        self.teb_address
    }

    pub fn get_peb_address(&self) -> Option<u64> {
        self.peb_address
    }

    pub fn initialize_hooks(&self, unicorn: &mut Unicorn<'static, ()>, trace_mode: crate::cli::TraceMode, trace_writer: Option<std::sync::Arc<std::sync::Mutex<std::fs::File>>>) -> Result<()> {
        // Add interrupt hook for int 0x2e (Windows syscall)
        let _ = unicorn.add_intr_hook(|uc, intno| {
            if intno == 0x2e {
                Self::handle_syscall(uc);
            }
        })?;

        // Add syscall instruction hooks for sysenter and syscall
        let _ = unicorn.add_insn_sys_hook(X86Insn::SYSENTER, 0, 0, |uc| { Self::handle_syscall(uc); })?;
        let _ = unicorn.add_insn_sys_hook(X86Insn::SYSCALL, 0, 0, |uc| { Self::handle_syscall(uc); })?;

        // If a trace file was specified, set up appropriate hooks
        if let Some(writer) = trace_writer.clone() {
            use serde_json::json;
            use std::io::Write;
            // Helper to write a JSON value as one line
            let write_json = move |val: serde_json::Value| {
                if let Ok(mut fh) = writer.lock() {
                    let _ = writeln!(fh, "{}", val);
                }
            };

            match trace_mode {
                crate::cli::TraceMode::Block => {
                    // Record first instruction of executed block
                    let _ = unicorn.add_block_hook(0, u64::MAX, move |uc, addr, _size| {
                        let mut instruction: Option<String> = None;
                        #[cfg(feature = "capstone")]
                        {
                            let mut buf = [0u8; 16];
                            if uc.mem_read(addr, &mut buf).is_ok() {
                                let cs = Capstone::new()
                                    .x86()
                                    .mode(if uc.reg_read(RegisterX86::RIP).is_ok() { capstone::arch::x86::ArchMode::Mode64 } else { capstone::arch::x86::ArchMode::Mode32 })
                                    .syntax(capstone::arch::x86::ArchSyntax::Intel)
                                    .build();
                                if let Ok(cs) = cs
                                    && let Ok(insns) = cs.disasm_count(&buf, addr, 1)
                                    && let Some(insn) = insns.iter().next() {
                                    instruction = Some(format!("{} {}", insn.mnemonic().unwrap_or(""), insn.op_str().unwrap_or("")));
                                }
                            }
                        }

                        let obj = json!({
                            "address": addr,
                            "instruction": instruction,
                        });
                        write_json(obj);
                    })?;
                }
                crate::cli::TraceMode::Instruction => {
                    // Record every instruction address and instruction text (if enabled)
                    let _ = unicorn.add_code_hook(0, u64::MAX, move |uc, _addr, _size| {
                        let pc = uc.pc_read().unwrap_or(0);
                        let mut instruction: Option<String> = None;
                        #[cfg(feature = "capstone")]
                        {
                            let mut buf = [0u8; 16];
                            if uc.mem_read(pc, &mut buf).is_ok() {
                                let cs = Capstone::new()
                                    .x86()
                                    .mode(if uc.reg_read(RegisterX86::RIP).is_ok() { capstone::arch::x86::ArchMode::Mode64 } else { capstone::arch::x86::ArchMode::Mode32 })
                                    .syntax(capstone::arch::x86::ArchSyntax::Intel)
                                    .build();
                                if let Ok(cs) = cs
                                    && let Ok(insns) = cs.disasm_count(&buf, pc, 1)
                                    && let Some(insn) = insns.iter().next() {
                                    instruction = Some(format!("{} {}", insn.mnemonic().unwrap_or(""), insn.op_str().unwrap_or("")));
                                }
                            }
                        }
                        let obj = json!({
                            "address": pc,
                            "instruction": instruction,
                        });
                        write_json(obj);
                    })?;
                }
                crate::cli::TraceMode::Full => {
                    // Record every instruction and register state
                    let _ = unicorn.add_code_hook(0, u64::MAX, move |uc, _addr, _size| {
                        let pc = uc.pc_read().unwrap_or(0);
                        let mut instruction: Option<String> = None;
                        #[cfg(feature = "capstone")]
                        {
                            let mut buf = [0u8; 16];
                            if uc.mem_read(pc, &mut buf).is_ok() {
                                let cs = Capstone::new()
                                    .x86()
                                    .mode(if uc.reg_read(RegisterX86::RIP).is_ok() { capstone::arch::x86::ArchMode::Mode64 } else { capstone::arch::x86::ArchMode::Mode32 })
                                    .syntax(capstone::arch::x86::ArchSyntax::Intel)
                                    .build();
                                if let Ok(cs) = cs
                                    && let Ok(insns) = cs.disasm_count(&buf, pc, 1)
                                    && let Some(insn) = insns.iter().next() {
                                    instruction = Some(format!("{} {}", insn.mnemonic().unwrap_or(""), insn.op_str().unwrap_or("")));
                                }
                            }
                        }

                        // Read registers (attempt 64-bit registers first, fall back to 32-bit)
                        let regs = vec!["rax","rbx","rcx","rdx","rsi","rdi","r8","r9","rbp","rsp","rip"];
                        let mut regmap = serde_json::Map::new();
                        for r in regs {
                            let val = match r {
                                "rax" => uc.reg_read(RegisterX86::RAX).or_else(|_| uc.reg_read(RegisterX86::EAX)),
                                "rbx" => uc.reg_read(RegisterX86::RBX).or_else(|_| uc.reg_read(RegisterX86::EBX)),
                                "rcx" => uc.reg_read(RegisterX86::RCX).or_else(|_| uc.reg_read(RegisterX86::ECX)),
                                "rdx" => uc.reg_read(RegisterX86::RDX).or_else(|_| uc.reg_read(RegisterX86::EDX)),
                                "rsi" => uc.reg_read(RegisterX86::RSI).or_else(|_| uc.reg_read(RegisterX86::ESI)),
                                "rdi" => uc.reg_read(RegisterX86::RDI).or_else(|_| uc.reg_read(RegisterX86::EDI)),
                                "r8" => uc.reg_read(RegisterX86::R8).or(Ok(0)),
                                "r9" => uc.reg_read(RegisterX86::R9).or(Ok(0)),
                                "rbp" => uc.reg_read(RegisterX86::RBP).or_else(|_| uc.reg_read(RegisterX86::EBP)),
                                "rsp" => uc.reg_read(RegisterX86::RSP).or_else(|_| uc.reg_read(RegisterX86::ESP)),
                                "rip" => uc.pc_read(),
                                _ => Ok(0),
                            };
                            let v = val.unwrap_or(0);
                            regmap.insert(r.to_string(), serde_json::Value::Number(serde_json::Number::from(v)));
                        }

                        let obj = json!({
                            "address": pc,
                            "instruction": instruction,
                            "registers": serde_json::Value::Object(regmap),
                        });
                        write_json(obj);
                    })?;
                }
            }
        }

        // Add memory hook to trace memory accesses
        use unicorn_engine::HookType;
        let _ = unicorn.add_mem_hook(HookType::MEM_READ_UNMAPPED, 0, u64::MAX, |uc, mem_type, addr, size, _value| {
            let pc = uc.pc_read().unwrap_or(0);
            let edx = uc.reg_read(RegisterX86::EDX).unwrap_or(0);
            let eax = uc.reg_read(RegisterX86::EAX).unwrap_or(0);
            let ebx = uc.reg_read(RegisterX86::EBX).unwrap_or(0);
            let ecx = uc.reg_read(RegisterX86::ECX).unwrap_or(0);
            debug!("Memory access: {:?} at {:#x}, size {} (PC: {:#x}, EDX: {:#x}, EAX: {:#x}, EBX: {:#x}, ECX: {:#x})", mem_type, addr, size, pc, edx, eax, ebx, ecx);
            false // Don't continue execution
        })?;
        let _ = unicorn.add_mem_hook(HookType::MEM_WRITE_UNMAPPED, 0, u64::MAX, |_uc, mem_type, addr, size, _value| {
            debug!("Memory access: {:?} at {:#x}, size {}", mem_type, addr, size);
            false // Don't continue execution
        })?; 
        let _ = unicorn.add_mem_hook(HookType::MEM_FETCH_UNMAPPED, 0, u64::MAX, |_uc, mem_type, addr, size, _value| {
            debug!("Memory access: {:?} at {:#x}, size {}", mem_type, addr, size);
            false // Don't continue execution
        })?; 

        // Add code hook for the entire .text section to trace execution
        let _ = unicorn.add_code_hook(0x401000, 0x403000, |uc, _addr, _size| {
            let pc = uc.pc_read().unwrap_or(0);
            debug!("Code execution at {:#x}", pc);
        })?;

        debug!("Windows syscall hooks initialized");
        Ok(())
    }

    fn handle_syscall(uc: &mut Unicorn<'_, ()>) {
        // Get the syscall number from EAX
        let syscall_num = match uc.reg_read(RegisterX86::EAX) {
            Ok(num) => num as u32,
            Err(_) => {
                debug!("Failed to read syscall number from EAX");
                return;
            }
        };

        debug!("Syscall: {:#x} called", syscall_num);

        // Dispatch to appropriate handler
        let result = match syscall_num {
            0x15 => Self::handle_nt_allocate_virtual_memory(uc), // NtAllocateVirtualMemory
            0x1b => Self::handle_nt_free_virtual_memory(uc),     // NtFreeVirtualMemory
            0x25 => Self::handle_nt_create_file(uc),             // NtCreateFile
            0x3 => Self::handle_nt_read_file(uc),                // NtReadFile
            0x4 => Self::handle_nt_write_file(uc),               // NtWriteFile
            _ => {
                debug!("Unhandled syscall: {:#x}", syscall_num);
                // Return STATUS_NOT_IMPLEMENTED (0xC0000002)
                0xC0000002u32
            }
        };

        debug!("Syscall {:#x} returning {:#x}", syscall_num, result);

        // Set return value in EAX
        let _ = uc.reg_write(RegisterX86::EAX, result as u64);
    }

    fn handle_nt_allocate_virtual_memory(_uc: &mut Unicorn<'_, ()>) -> u32 {
        debug!("NtAllocateVirtualMemory called - not implemented");
        // STATUS_NOT_IMPLEMENTED
        0xC0000002
    }

    fn handle_nt_free_virtual_memory(_uc: &mut Unicorn<'_, ()>) -> u32 {
        debug!("NtFreeVirtualMemory called - not implemented");
        // STATUS_NOT_IMPLEMENTED
        0xC0000002
    }

    fn handle_nt_create_file(_uc: &mut Unicorn<'_, ()>) -> u32 {
        debug!("NtCreateFile called - not implemented");
        // STATUS_NOT_IMPLEMENTED
        0xC0000002
    }

    fn handle_nt_read_file(_uc: &mut Unicorn<'_, ()>) -> u32 {
        debug!("NtReadFile called - not implemented");
        // STATUS_NOT_IMPLEMENTED
        0xC0000002
    }

    fn handle_nt_write_file(_uc: &mut Unicorn<'_, ()>) -> u32 {
        debug!("NtWriteFile called - not implemented");
        // STATUS_NOT_IMPLEMENTED
        0xC0000002
    }
}
