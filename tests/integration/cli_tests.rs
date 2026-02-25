//! Integration tests for the CLI binary.
//!
//! Verifies that the `aid` binary exists and responds to basic flags.
//!
//! This test is registered as a [[test]] in the agentic-identity-cli crate
//! so that CARGO_BIN_EXE_aid is available.

use std::process::Command;

/// Get a Command pointing to the `aid` binary.
fn aid_binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_aid"))
}

#[test]
fn cli_responds_to_help() {
    let output = aid_binary()
        .arg("--help")
        .output()
        .expect("failed to execute aid --help");

    assert!(
        output.status.success(),
        "aid --help should exit with success, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("aid") || stdout.contains("AgenticIdentity") || stdout.contains("Usage"),
        "aid --help output should contain usage information, got: {stdout}"
    );
}

#[test]
fn cli_responds_to_version() {
    let output = aid_binary()
        .arg("--version")
        .output()
        .expect("failed to execute aid --version");

    assert!(
        output.status.success(),
        "aid --version should exit with success, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("0.1") || stdout.contains("aid"),
        "aid --version should contain version info, got: {stdout}"
    );
}

#[test]
fn cli_exits_with_error_on_unknown_flag() {
    let output = aid_binary()
        .arg("--nonexistent-flag")
        .output()
        .expect("failed to execute aid");

    assert!(
        !output.status.success(),
        "aid with unknown flag should exit with error"
    );
}
