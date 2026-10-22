//! If `CORTEX9_EBPF_OBJ` points to a built eBPF object at compile time, the
//! binary embeds it (`cfg(embedded_ebpf)`). Otherwise the object is read at
//! run time from `--object` or the default build path. This keeps
//! `cargo build`/`cargo test` working on stable without bpf-linker.
use std::path::Path;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(embedded_ebpf)");
    println!("cargo::rerun-if-env-changed=CORTEX9_EBPF_OBJ");
    if let Ok(path) = std::env::var("CORTEX9_EBPF_OBJ") {
        if Path::new(&path).is_file() {
            println!("cargo::rerun-if-changed={path}");
            println!("cargo::rustc-cfg=embedded_ebpf");
        } else {
            println!("cargo::warning=CORTEX9_EBPF_OBJ={path} does not exist; not embedding");
        }
    }
}
