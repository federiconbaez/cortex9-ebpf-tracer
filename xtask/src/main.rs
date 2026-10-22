//! `cargo xtask <command>`
//!
//! - `build-ebpf [--debug]`: build `cortex9-tracer-ebpf` for
//!   `bpfel-unknown-none` (nightly + rust-src + bpf-linker, configured in
//!   `cortex9-tracer-ebpf/rust-toolchain.toml` and `.cargo/config.toml`).
//! - `build [--debug]`: `build-ebpf`, then the userspace binary with the
//!   object embedded (`CORTEX9_EBPF_OBJ`).
//! - `run [-- ARGS]`: `build`, then run the binary, through `sudo` when not
//!   root.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn status(cmd: &mut Command) -> Result<()> {
    let st = cmd.status().with_context(|| format!("spawning {cmd:?}"))?;
    if !st.success() {
        bail!("{cmd:?} failed with {st}");
    }
    Ok(())
}

fn build_ebpf(release: bool) -> Result<PathBuf> {
    let dir = root().join("cortex9-tracer-ebpf");
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&dir).arg("build");
    // Do not leak the host toolchain selection into the nightly build.
    for var in [
        "RUSTUP_TOOLCHAIN",
        "RUSTC",
        "RUSTC_WRAPPER",
        "CARGO_BUILD_TARGET",
    ] {
        cmd.env_remove(var);
    }
    if release {
        cmd.arg("--release");
    }
    status(&mut cmd)?;
    let profile = if release { "release" } else { "debug" };
    let obj = dir
        .join("target/bpfel-unknown-none")
        .join(profile)
        .join("cortex9-tracer-ebpf");
    if !obj.is_file() {
        bail!("expected eBPF object at {}", obj.display());
    }
    Ok(obj)
}

fn build(release: bool) -> Result<PathBuf> {
    let obj = build_ebpf(release)?;
    let mut cmd = Command::new("cargo");
    cmd.current_dir(root())
        .args(["build", "--package", "cortex9-tracer"])
        .env("CORTEX9_EBPF_OBJ", &obj);
    if release {
        cmd.arg("--release");
    }
    status(&mut cmd)?;
    let profile = if release { "release" } else { "debug" };
    Ok(root().join("target").join(profile).join("cortex9-tracer"))
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (cmd, rest) = args
        .split_first()
        .map_or(("help", &[][..]), |(c, r)| (c.as_str(), r));
    let release = !rest.iter().any(|a| a == "--debug");
    match cmd {
        "build-ebpf" => {
            let obj = build_ebpf(release)?;
            println!("{}", obj.display());
        }
        "build" => {
            let bin = build(release)?;
            println!("{}", bin.display());
        }
        "run" => {
            let bin = build(release)?;
            let passthrough: Vec<&String> =
                rest.iter().skip_while(|a| *a != "--").skip(1).collect();
            // SAFETY: geteuid has no preconditions.
            let is_root = unsafe { geteuid() } == 0;
            let mut c = if is_root {
                Command::new(&bin)
            } else {
                let mut c = Command::new("sudo");
                c.arg(&bin);
                c
            };
            status(c.args(passthrough))?;
        }
        _ => {
            eprintln!("usage: cargo xtask <build-ebpf|build|run> [--debug] [-- ARGS]");
            if cmd != "help" {
                std::process::exit(2);
            }
        }
    }
    Ok(())
}

extern "C" {
    fn geteuid() -> u32;
}
