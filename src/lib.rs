pub mod cli;
pub mod hooks;
pub mod image;

/// Exported functions collected via the `inventory` crate
pub struct ExportedFunction {
    pub dll: &'static str,
    pub function: &'static str,
    pub pointer: fn(&mut crate::EmuCore),
}

inventory::collect!(ExportedFunction);

/// Map type for exported functions: dll -> (function -> pointer)
pub type ExportMap = std::collections::HashMap<String, std::collections::HashMap<String, fn(&mut crate::EmuCore)>>;
pub mod error;
pub mod config;
pub mod emulator;
pub mod arch;
pub mod debug;
pub mod loader;
pub mod memory;
pub mod os;
pub mod util;

pub use config::{EmuConfig, Architecture};
pub use image::Image;
pub use emulator::EmuCore;