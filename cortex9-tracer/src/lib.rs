//! Userspace half of `cortex9-ebpf-tracer`.
//!
//! Everything in this library is plain Rust with no BPF or privilege
//! requirements, so it is covered by ordinary unit tests:
//!
//! - [`event`]: safe decoding of ring buffer records.
//! - [`syscalls`] / [`errno`]: name tables for x86_64 and aarch64.
//! - [`filter`]: user filters and the subset pushed into kernel maps.
//! - [`format`]: text and JSON-lines output.
//! - [`stats`]: per-syscall summary.
//! - [`cli`]: command line definition and its translation to a [`filter::Filter`].
//!
//! The loader that talks to the kernel lives in the binary (`main.rs`).

pub mod cli;
pub mod errno;
pub mod event;
pub mod filter;
pub mod format;
pub mod stats;
pub mod syscalls;
