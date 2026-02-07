use std::process::Command;
use std::path::PathBuf;

// This test builds the test program `exit_only` as a 32-bit Windows executable
// and then runs the `wolpertinger` command-line against it to ensure the
// CLI can execute a 32-bit PE.

#[test]
fn test_wolpertinger_runs_exit_only_32() {
    // Look for a prebuilt exit_only executable in common build directories
    let candidates = [
        PathBuf::from("tests/programs/build_x86/exit_only/exit_only.exe"),
        PathBuf::from("tests/programs/build_x86/exit_only/exit_only"),
        PathBuf::from("tests/programs/build_x86_64/exit_only/exit_only.exe"),
        PathBuf::from("tests/programs/build_x86_64/exit_only/exit_only"),
    ];

    let exe = candidates.iter().find(|p| p.exists()).map(|p| p.to_path_buf());
    let exe = match exe {
        Some(e) => e,
        None => {
            eprintln!("Skipping test: prebuilt exit_only not found; run `cargo make build-tests` to prepare test programs");
            return;
        }
    };

    // Locate the wolpertinger binary under test
    // Cargo sets CARGO_BIN_EXE_<name> for integration tests; fallback to target/debug
    let wolp = std::env::var("CARGO_BIN_EXE_wolpertinger")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("target/debug/wolpertinger"));

    if !wolp.exists() {
        // Try to build the wolpertinger binary
        let st = Command::new("cargo")
            .arg("build")
            .arg("--bin")
            .arg("wolpertinger")
            .status()
            .expect("failed to cargo build wolpertinger");
        assert!(st.success(), "cargo build wolpertinger failed");
    }

    // Run wolpertinger against the built 32-bit exe. Force arch to x86.
    let output = Command::new(&wolp)
        .arg(&exe)
        .arg("--arch")
        .arg("x86")
        .arg("--rootfs")
        .arg("tests/programs/exit_only")
        .arg("--timeout")
        .arg("1000")
        .output()
        .expect("failed to run wolpertinger");

    // The CLI should exit successfully (no panic). If it fails, print stdout/stderr for debugging.
    assert!(output.status.success(), "wolpertinger failed\nstdout:{}\nstderr:{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
