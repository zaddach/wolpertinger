use wolpertinger::{EmuConfig, EmuCore, Architecture};
use wolpertinger::cli::TraceMode;
use std::path::PathBuf;
use env_logger;

#[test]
fn test_run_tiny_exe() {
    env_logger::init();
    
    // Look for a prebuilt tiny executable in standard build directories and copy it into tests/tiny/build
    let candidates = [
        (PathBuf::from("tests/programs/build_x86/message_box/tiny.exe"), Architecture::X86),
        (PathBuf::from("tests/programs/build_x86/message_box/tiny"), Architecture::X86),
        (PathBuf::from("tests/programs/build_x86_64/message_box/tiny.exe"), Architecture::X86_64),
        (PathBuf::from("tests/programs/build_x86_64/message_box/tiny"), Architecture::X86_64),
    ];

    let mut found: Option<(PathBuf, Architecture)> = None;
    for (p, a) in &candidates {
        if p.exists() {
            found = Some((p.to_path_buf(), *a));
            break;
        }
    }

    let (binary, arch_choice) = match found {
        Some((src, arch)) => (src, arch),
        None => {
            eprintln!("Skipping test: prebuilt tiny not found; run `cargo make build-tests` to prepare test programs");
            return;
        }
    };

    let rootfs = PathBuf::from("tests/programs/message_box");

    let config = EmuConfig {
        binary,
        rootfs,
        architecture: Some(arch_choice),
        entry_point: None,
        exit_point: None,
        timeout_ms: None,
        instruction_count: None,
        log_level: "info".to_string(),
        trace_mode: TraceMode::Block,
        trace_file: None,
    };

    let mut core = EmuCore::new(config).expect("Failed to create EmuCore");
    // Note: run() is currently a stub, so this may not fully emulate yet
    core.run().expect("Failed to run EmuCore");
}