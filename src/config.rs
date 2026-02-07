use crate::cli::{ArchChoice, Cli};
use anyhow::Result;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    X86,
    X86_64,
}

impl From<ArchChoice> for Architecture {
    fn from(choice: ArchChoice) -> Self {
        match choice {
            ArchChoice::X86 => Architecture::X86,
            ArchChoice::X8664 => Architecture::X86_64,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EmuConfig {
    pub binary: PathBuf,
    pub rootfs: PathBuf,
    pub architecture: Option<Architecture>,
    pub entry_point: Option<u64>,
    pub exit_point: Option<u64>,
    pub timeout_ms: Option<u64>,
    pub instruction_count: Option<u64>,
    pub log_level: String,
    pub trace_mode: crate::cli::TraceMode,
    pub trace_file: Option<PathBuf>,
}

impl EmuConfig {
    pub fn from_cli(cli: &Cli) -> Result<Self> {
        let architecture = cli.arch.map(Architecture::from);

        Ok(Self {
            binary: cli.binary.clone(),
            rootfs: cli.rootfs.clone(),
            architecture,
            entry_point: cli.entry,
            exit_point: cli.exit,
            timeout_ms: cli.timeout,
            instruction_count: cli.count,
            log_level: cli.log_level.clone(),
            trace_mode: cli.trace_mode,
            trace_file: cli.trace_file.clone(),
        })
    }
}
