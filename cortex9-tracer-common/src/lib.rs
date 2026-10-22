//! Types shared between the eBPF program (`no_std`, `bpfel-unknown-none`)
//! and the userspace loader.
//!
//! Everything here is plain `#[repr(C)]` data with explicit padding so the
//! layout is identical on both sides. The userspace crate never casts ring
//! buffer bytes to [`SyscallEvent`] directly; it decodes field by field from
//! the offsets below, which keeps decoding safe and testable.
#![cfg_attr(not(test), no_std)]

/// Length of `task_struct::comm` (TASK_COMM_LEN).
pub const COMM_LEN: usize = 16;

/// Number of raw syscall arguments captured.
pub const ARG_COUNT: usize = 6;

/// Ring buffer size in bytes (must be a power of two and a multiple of the
/// page size).
pub const RING_BUF_BYTES: u32 = 1 << 20;

/// Max in-flight syscalls tracked between `sys_enter` and `sys_exit`.
pub const MAX_INFLIGHT: u32 = 16_384;

/// Max entries in each in-kernel filter map.
pub const MAX_FILTER_ENTRIES: u32 = 1_024;

/// Map names, as seen by the loader.
pub mod maps {
    /// `RingBuf` with [`super::SyscallEvent`] records.
    pub const EVENTS: &str = "EVENTS";
    /// `Array<u32>` with the [`super::config`] slots.
    pub const CONFIG: &str = "CONFIG";
    /// `HashMap<u32, u8>`: thread-group ids (process ids) to keep.
    pub const PID_FILTER: &str = "PID_FILTER";
    /// `HashMap<u32, u8>`: syscall numbers to keep.
    pub const SYSCALL_FILTER: &str = "SYSCALL_FILTER";
    /// `LruHashMap<u64, InFlight>`: pid_tgid -> pending `sys_enter` data.
    pub const INFLIGHT: &str = "INFLIGHT";
    /// `Array<u64>` (1 slot): events dropped because the ring buffer was full.
    pub const DROPPED: &str = "DROPPED";
    /// `Array<u64>` with [`super::pidns`] slots: the tracer's PID namespace.
    pub const PIDNS: &str = "PIDNS";
}

/// Program names, as seen by the loader.
pub mod programs {
    /// Tracepoint `raw_syscalls/sys_enter`.
    pub const SYS_ENTER: &str = "cortex9_sys_enter";
    /// Tracepoint `raw_syscalls/sys_exit`.
    pub const SYS_EXIT: &str = "cortex9_sys_exit";
}

/// Slots in the `CONFIG` array.
pub mod config {
    /// Bit flags, see [`FLAG_PID_FILTER`] and [`FLAG_SYSCALL_FILTER`].
    pub const FLAGS: u32 = 0;
    /// Thread-group id of the tracer itself; its syscalls are skipped.
    pub const SELF_TGID: u32 = 1;
    /// Number of slots.
    pub const LEN: u32 = 2;

    /// Only keep tgids present in `PID_FILTER`.
    pub const FLAG_PID_FILTER: u32 = 1 << 0;
    /// Only keep syscall numbers present in `SYSCALL_FILTER`.
    pub const FLAG_SYSCALL_FILTER: u32 = 1 << 1;
}

/// Slots in the `PIDNS` array. When `INO` is non-zero the eBPF program
/// reports PIDs as seen from that namespace (`bpf_get_ns_current_pid_tgid`),
/// so they match what the tracer's own `/proc` shows inside a container.
pub mod pidns {
    /// Kernel-encoded `dev_t` of the nsfs mount (`MKDEV(major, minor)`).
    pub const DEV: u32 = 0;
    /// Inode of `/proc/self/ns/pid`.
    pub const INO: u32 = 1;
    /// Number of slots.
    pub const LEN: u32 = 2;
}

/// [`SyscallEvent::flags`]: `pid`/`tid` are relative to the tracer's PID
/// namespace. When clear, they are init-namespace ids of a task outside it.
pub const EVENT_FLAG_IN_PIDNS: u32 = 1 << 0;

/// Data saved at `sys_enter` and consumed at `sys_exit`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InFlight {
    /// `bpf_ktime_get_ns()` at entry.
    pub start_ns: u64,
    /// Syscall number.
    pub nr: u64,
    /// Raw register arguments.
    pub args: [u64; ARG_COUNT],
}

/// One completed syscall, as written to the ring buffer.
///
/// Layout (little endian, 112 bytes, 8-byte aligned):
///
/// | offset | size | field         |
/// |-------:|-----:|---------------|
/// | 0      | 8    | `ts_ns`       |
/// | 8      | 8    | `duration_ns` |
/// | 16     | 8    | `ret`         |
/// | 24     | 48   | `args`        |
/// | 72     | 4    | `pid`         |
/// | 76     | 4    | `tid`         |
/// | 80     | 4    | `uid`         |
/// | 84     | 4    | `nr`          |
/// | 88     | 16   | `comm`        |
/// | 104    | 4    | `flags`       |
/// | 108    | 4    | `_pad`        |
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyscallEvent {
    /// `bpf_ktime_get_ns()` at syscall exit (CLOCK_MONOTONIC, ns).
    pub ts_ns: u64,
    /// Exit time minus entry time, in ns.
    pub duration_ns: u64,
    /// Raw return value (negative errno on failure for most syscalls).
    pub ret: i64,
    /// Raw register arguments captured at entry.
    pub args: [u64; ARG_COUNT],
    /// Thread-group id (what userspace calls the PID), see `flags`.
    pub pid: u32,
    /// Thread id, see `flags`.
    pub tid: u32,
    /// Real uid of the task.
    pub uid: u32,
    /// Syscall number (architecture specific).
    pub nr: u32,
    /// `comm` of the calling thread, NUL padded.
    pub comm: [u8; COMM_LEN],
    /// `EVENT_FLAG_*` bits.
    pub flags: u32,
    /// Padding, always zero. Keeps the size a multiple of 8.
    pub _pad: u32,
}

/// Size of a [`SyscallEvent`] record in bytes.
pub const EVENT_SIZE: usize = core::mem::size_of::<SyscallEvent>();

/// Byte offsets of each [`SyscallEvent`] field.
pub mod offsets {
    pub const TS_NS: usize = 0;
    pub const DURATION_NS: usize = 8;
    pub const RET: usize = 16;
    pub const ARGS: usize = 24;
    pub const PID: usize = 72;
    pub const TID: usize = 76;
    pub const UID: usize = 80;
    pub const NR: usize = 84;
    pub const COMM: usize = 88;
    pub const FLAGS: usize = 104;
}

/// Offsets inside the `raw_syscalls` tracepoint records (stable kernel ABI,
/// see `/sys/kernel/tracing/events/raw_syscalls/*/format`).
pub mod tp {
    /// `long id` in both `sys_enter` and `sys_exit`.
    pub const ID: usize = 8;
    /// `unsigned long args[6]` in `sys_enter`.
    pub const ARGS: usize = 16;
    /// `long ret` in `sys_exit`.
    pub const RET: usize = 16;
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    #[test]
    fn event_layout_is_stable() {
        assert_eq!(size_of::<SyscallEvent>(), 112);
        assert_eq!(align_of::<SyscallEvent>(), 8);
        assert_eq!(offset_of!(SyscallEvent, ts_ns), offsets::TS_NS);
        assert_eq!(offset_of!(SyscallEvent, duration_ns), offsets::DURATION_NS);
        assert_eq!(offset_of!(SyscallEvent, ret), offsets::RET);
        assert_eq!(offset_of!(SyscallEvent, args), offsets::ARGS);
        assert_eq!(offset_of!(SyscallEvent, pid), offsets::PID);
        assert_eq!(offset_of!(SyscallEvent, tid), offsets::TID);
        assert_eq!(offset_of!(SyscallEvent, uid), offsets::UID);
        assert_eq!(offset_of!(SyscallEvent, nr), offsets::NR);
        assert_eq!(offset_of!(SyscallEvent, comm), offsets::COMM);
        assert_eq!(offset_of!(SyscallEvent, flags), offsets::FLAGS);
    }

    #[test]
    fn inflight_layout() {
        assert_eq!(size_of::<InFlight>(), 64);
        assert_eq!(align_of::<InFlight>(), 8);
    }

    #[test]
    fn ring_buf_size_is_power_of_two() {
        assert!(RING_BUF_BYTES.is_power_of_two());
        assert_eq!(RING_BUF_BYTES % 4096, 0);
    }
}
