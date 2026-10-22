//! Binary-level tests that need no privileges.

use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_cortex9-tracer"))
}

#[test]
fn help_mentions_filters() {
    let out = bin().arg("--help").output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    for flag in ["--pid", "--comm", "--syscall", "--min-duration", "--failed"] {
        assert!(s.contains(flag), "missing {flag}");
    }
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[test]
fn list_syscalls() {
    let out = bin().arg("--list-syscalls").output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    let expected = if cfg!(target_arch = "x86_64") {
        "257\topenat"
    } else {
        "56\topenat"
    };
    assert!(s.lines().any(|l| l == expected), "{expected} not listed");
    assert!(s.lines().count() > 300);
}

#[cfg(target_arch = "x86_64")]
#[test]
fn print_config_reports_kernel_subset() {
    let out = bin()
        .args([
            "--print-config",
            "-p",
            "1,2",
            "-s",
            "openat,read",
            "-c",
            "nginx",
        ])
        .args(["--min-duration", "2ms", "--failed"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["arch"], "x86_64");
    assert_eq!(v["kernel"]["pids"], serde_json::json!([1, 2]));
    assert_eq!(v["kernel"]["syscalls"], serde_json::json!([0, 257]));
    assert_eq!(v["filter"]["comms"], serde_json::json!(["nginx"]));
    assert_eq!(v["filter"]["min_duration_ns"], 2_000_000);
    assert_eq!(v["filter"]["failed_only"], true);
    assert_eq!(v["exclude_self"], true);
}

#[test]
fn invalid_arguments_fail() {
    let out = bin()
        .args(["--print-config", "-s", "no_such_call"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("unknown syscall"));

    let out = bin().args(["--args", "9"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
}
