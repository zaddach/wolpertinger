use assert_cmd::cargo_bin;
use tempfile::NamedTempFile;
use std::fs::{read_to_string, create_dir_all};
use std::path::PathBuf;
use serde_json::Value;

fn ensure_tiny_built() -> Option<PathBuf> {
    // Ensure tests/tiny exists
    let tiny_root = PathBuf::from("tests/tiny");
    if !tiny_root.exists() {
        create_dir_all(&tiny_root).expect("failed to create tests/tiny");
    }

    // Look for prebuilt tiny in standard build directories
    let candidates = [
        PathBuf::from("tests/programs/build_x86/message_box/tiny.exe"),
        PathBuf::from("tests/programs/build_x86/message_box/tiny"),
        PathBuf::from("tests/programs/build_x86_64/message_box/tiny.exe"),
        PathBuf::from("tests/programs/build_x86_64/message_box/tiny"),
    ];

    let mut found = None;
    for p in &candidates {
        if p.exists() {
            found = Some(p.to_path_buf());
            break;
        }
    }

    let src = match found {
        Some(s) => s,
        None => {
            eprintln!("Skipping test: prebuilt tiny not found; run `cargo make build-tests` to prepare test programs");
            return None;
        }
    };

    Some(src)
}

// Ensure --trace-file with --trace-mode=block writes at least one JSON-line with address
#[test]
fn trace_block_writes_json_lines() {
    let bin = cargo_bin!("wolpertinger");

    let tmp = NamedTempFile::new().expect("temp file");

    let tiny = match ensure_tiny_built() {
        Some(p) => p,
        None => return, // skip test
    };

    let mut cmd = assert_cmd::Command::new(&bin);
    cmd.arg("--arch").arg("x86_64")
        .arg("--trace-mode").arg("block")
        .arg("--trace-file").arg(tmp.path())
        .arg("--rootfs").arg("tests/tiny")
        .arg(tiny)
        // keep run short
        .arg("--count").arg("1");

    cmd.assert().success();

    let contents = read_to_string(tmp.path()).expect("read trace file");
    let lines: Vec<&str> = contents.lines().collect();
    assert!(lines.len() >= 1, "expected at least one trace line");

    // parse first line as JSON and assert address exists
    let v: Value = serde_json::from_str(lines[0]).expect("valid json");
    assert!(v.get("address").is_some(), "address field present");
}

// Ensure --trace-file with --trace-mode=full includes registers object
#[test]
fn trace_full_includes_registers() {
    let bin = cargo_bin!("wolpertinger");

    let tmp = NamedTempFile::new().expect("temp file");

    let tiny = match ensure_tiny_built() {
        Some(p) => p,
        None => return, // skip test
    };

    let mut cmd = assert_cmd::Command::new(&bin);
    cmd.arg("--arch").arg("x86_64")
        .arg("--trace-mode").arg("full")
        .arg("--trace-file").arg(tmp.path())
        .arg("--rootfs").arg("tests/tiny")
        .arg(tiny)
        // keep run short
        .arg("--count").arg("1");

    cmd.assert().success();

    let contents = read_to_string(tmp.path()).expect("read trace file");
    let lines: Vec<&str> = contents.lines().collect();
    assert!(lines.len() >= 1, "expected at least one trace line");

    let v: Value = serde_json::from_str(lines[0]).expect("valid json");
    // For full mode, registers should be present (may be empty object if read failed)
    assert!(v.get("registers").is_some(), "registers field present");
}
