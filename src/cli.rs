use clap::{builder::ValueHint, Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "wolpertinger", about = "Run Windows binaries with a minimal Qiling-inspired Rust runtime")]
pub struct Cli {
    /// Path to the Windows PE binary to run (EXE or DLL)
    #[arg(value_name = "BINARY", value_hint = ValueHint::FilePath)]
    pub binary: PathBuf,

    /// Root filesystem directory used to resolve dependencies
    #[arg(short, long, value_name = "ROOTFS", value_hint = ValueHint::DirPath, default_value = ".")]
    pub rootfs: PathBuf,

    /// Architecture hint (x86, x86_64)
    #[arg(long, value_enum)]
    pub arch: Option<ArchChoice>,

    /// Override entry point for shellcode tests
    #[arg(long)]
    pub entry: Option<u64>,

    /// Override exit point for the emulation run
    #[arg(long)]
    pub exit: Option<u64>,

    /// Maximum milliseconds before emulation aborts
    #[arg(long)]
    pub timeout: Option<u64>,

    /// Maximum instruction count before the emulation stops
    #[arg(long)]
    pub count: Option<u64>,


    /// Logging verbosity (error, warn, info, debug, trace)
    #[arg(long, default_value = "info")]
    pub log_level: String,

    /// Trace mode: block (first instruction of block), instruction (all instructions), full (all instructions + registers)
    #[arg(long, value_enum, default_value = "block")]
    pub trace_mode: TraceMode,

    /// Path to write JSON-lines trace output. If omitted, no tracing occurs.
    #[arg(long, value_hint = ValueHint::FilePath)]
    pub trace_file: Option<PathBuf>,
}

#[derive(ValueEnum, Clone, Debug, Copy)]
pub enum TraceMode {
    #[value(alias = "block")]
    Block,
    #[value(alias = "instruction")]
    Instruction,
    #[value(alias = "full")]
    Full,
}

#[derive(ValueEnum, Clone, Debug, Copy)]
pub enum ArchChoice {
    #[value(alias = "x86", alias = "ia32")]
    X86,
    #[value(alias = "x64", alias = "x86_64")]
    X8664,
}
