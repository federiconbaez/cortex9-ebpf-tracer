//! Real kernel test: loads the eBPF object, attaches the tracepoints and
//! checks that our own failed `openat` calls come back through the ring
//! buffer with the right PID, syscall and errno.
//!
//! Needs root (or CAP_BPF + CAP_PERFMON) and a built object, so it is
//! `#[ignore]`d. Run it with:
//!
//! ```sh
//! cargo xtask build-ebpf
//! CORTEX9_EBPF_OBJ=$PWD/cortex9-tracer-ebpf/target/bpfel-unknown-none/release/cortex9-tracer-ebpf \
//!   CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER='sudo -E' \
//!   cargo test --release -p cortex9-tracer --test load -- --ignored
//! ```

use std::io::{BufRead, BufReader, Read};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
#[ignore = "needs root and a built eBPF object"]
fn traces_own_failed_openat() {
    let me = std::process::id();
    let mut child = Command::new(env!("CARGO_BIN_EXE_cortex9-tracer"))
        .args([
            "-p",
            &me.to_string(),
            "-s",
            "openat",
            "--failed",
            "-f",
            "json",
        ])
        .args(["-n", "3", "-t", "20"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tracer");

    // Wait until both tracepoints are attached.
    let mut err = BufReader::new(child.stderr.take().unwrap());
    let mut line = String::new();
    err.read_line(&mut line).unwrap();
    assert!(line.contains("attached"), "tracer did not attach: {line}");

    // Generate matching syscalls until the tracer exits (-n 3).
    let deadline = Instant::now() + Duration::from_secs(15);
    while child.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "tracer did not exit in time");
        let _ = std::fs::File::open("/nonexistent/cortex9-probe");
        std::thread::sleep(Duration::from_millis(20));
    }
    let status = child.wait().unwrap();
    let mut rest = String::new();
    err.read_to_string(&mut rest).unwrap();
    assert!(status.success(), "tracer failed: {rest}");

    let mut out = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    let events: Vec<serde_json::Value> = out
        .lines()
        .map(|l| serde_json::from_str(l).expect("json line"))
        .collect();
    assert_eq!(events.len(), 3, "{out}");
    for e in &events {
        assert_eq!(e["pid"], me, "{e}");
        assert_eq!(e["syscall"], "openat", "{e}");
        assert_eq!(e["errno"], "ENOENT", "{e}");
        assert_eq!(e["in_pidns"], true, "{e}");
    }
}
