use std::collections::HashMap;
use std::path::Path;
use anyhow::Result;
use goblin::Object;
use std::fs;

#[derive(Debug)]
pub struct DllExport {
    pub name: String,
    pub address: u64,
}

#[derive(Debug)]
pub struct DllInfo {
    pub name: String,
    pub base_address: u64,
    pub exports: HashMap<String, DllExport>,
}

pub struct DllLoader {
    loaded_dlls: HashMap<String, DllInfo>,
    next_dll_base: u64,
    rootfs: std::path::PathBuf,
}

impl DllLoader {
    pub fn new(rootfs: std::path::PathBuf) -> Self {
        Self {
            loaded_dlls: HashMap::new(),
            next_dll_base: 0x70000000, // Start DLLs at high addresses
            rootfs,
        }
    }

    pub fn load_system_dll(&mut self, name: &str) -> Result<&DllInfo> {
        if self.loaded_dlls.contains_key(name) {
            return Ok(&self.loaded_dlls[name]);
        }

        let base_address = self.next_dll_base;
        self.next_dll_base += 0x100000; // 1MB per DLL

        let mut exports = HashMap::new();
        
        // Try to load real DLL from rootfs first
        let dll_path = self.rootfs.join("windows").join("system32").join(name);
        if dll_path.exists() {
            log::info!("Loading real DLL: {}", dll_path.display());
            if let Err(e) = self.parse_dll_exports(&dll_path, base_address, &mut exports) {
                log::warn!("Failed to parse real DLL {}: {}, falling back to hardcoded exports", name, e);
                self.add_hardcoded_exports(name, &mut exports, base_address);
            }
        } else {
            log::info!("DLL {} not found at {}, using hardcoded exports", name, dll_path.display());
            self.add_hardcoded_exports(name, &mut exports, base_address);
        }

        let dll_info = DllInfo {
            name: name.to_string(),
            base_address,
            exports,
        };

        self.loaded_dlls.insert(name.to_string(), dll_info);
        Ok(&self.loaded_dlls[name])
    }

    pub fn resolve_import(&self, dll_name: &str, function_name: &str) -> Option<u64> {
        self.loaded_dlls.get(dll_name)
            .and_then(|dll| dll.exports.get(function_name).map(|export| export.address))
    }

    fn parse_dll_exports(&self, dll_path: &Path, base_address: u64, exports: &mut HashMap<String, DllExport>) -> Result<()> {
        let buffer = fs::read(dll_path)?;
        let obj = Object::parse(&buffer)?;
        
        match obj {
            Object::PE(pe) => {
                for export in &pe.exports {
                    let name = if let Some(name) = export.name {
                        name.to_string()
                    } else {
                        // For ordinal-only exports, create a name based on offset
                        format!("Ordinal{}", export.offset.unwrap_or(0))
                    };
                    
                    let address = base_address + export.rva as u64;
                    
                    exports.insert(name.clone(), DllExport {
                        name,
                        address,
                    });
                }
                log::info!("Parsed {} exports from {}", pe.exports.len(), dll_path.display());
                Ok(())
            }
            _ => {
                Err(anyhow::anyhow!("{} is not a valid PE file", dll_path.display()))
            }
        }
    }

    fn add_hardcoded_exports(&self, name: &str, exports: &mut HashMap<String, DllExport>, base: u64) {
        // Add common exports for system DLLs
        match name.to_lowercase().as_str() {
            "kernel32.dll" => {
                self.add_kernel32_exports(exports, base);
            }
            "msvcrt.dll" => {
                self.add_msvcrt_exports(exports, base);
            }
            "user32.dll" => {
                self.add_user32_exports(exports, base);
            }
            _ => {
                log::warn!("Unknown system DLL: {}", name);
            }
        }
    }

    fn add_kernel32_exports(&self, exports: &mut HashMap<String, DllExport>, base: u64) {
        let kernel32_functions = vec![
            "DeleteCriticalSection",
            "EnterCriticalSection", 
            "GetLastError",
            "InitializeCriticalSection",
            "LeaveCriticalSection",
            "SetUnhandledExceptionFilter",
            "Sleep",
            "TlsGetValue",
            "VirtualProtect",
            "VirtualQuery",
            "ExitProcess",
            "GetModuleHandleA",
            "GetModuleHandleW",
            "LoadLibraryA",
            "LoadLibraryW",
            "GetProcAddress",
        ];

        for (i, func) in kernel32_functions.iter().enumerate() {
            exports.insert(func.to_string(), DllExport {
                name: func.to_string(),
                address: base + (i as u64 * 8), // 8 bytes per function pointer
            });
        }
    }

    fn add_msvcrt_exports(&self, exports: &mut HashMap<String, DllExport>, base: u64) {
        let msvcrt_functions = vec![
            "__C_specific_handler",
            "__getmainargs",
            "__initenv",
            "__iob_func",
            "__set_app_type",
            "__setusermatherr",
            "_amsg_exit",
            "_cexit",
            "_commode",
            "_fmode",
            "_initterm",
            "_onexit",
            "abort",
            "calloc",
            "exit",
            "fprintf",
            "free",
            "fwrite",
            "malloc",
            "memcpy",
            "signal",
            "strlen",
            "strncmp",
            "vfprintf",
        ];

        for (i, func) in msvcrt_functions.iter().enumerate() {
            exports.insert(func.to_string(), DllExport {
                name: func.to_string(),
                address: base + (i as u64 * 8),
            });
        }
    }

    fn add_user32_exports(&self, exports: &mut HashMap<String, DllExport>, base: u64) {
        let user32_functions = vec![
            "MessageBoxW",
            "MessageBoxA",
            "CreateWindowExA",
            "CreateWindowExW",
            "ShowWindow",
            "UpdateWindow",
            "GetMessageA",
            "GetMessageW",
            "TranslateMessage",
            "DispatchMessageA",
            "DispatchMessageW",
        ];

        for (i, func) in user32_functions.iter().enumerate() {
            exports.insert(func.to_string(), DllExport {
                name: func.to_string(),
                address: base + (i as u64 * 8),
            });
        }
    }
}