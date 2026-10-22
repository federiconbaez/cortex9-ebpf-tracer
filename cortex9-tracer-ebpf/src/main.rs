//! eBPF program: `raw_syscalls/sys_enter` stores the arguments and the entry
//! timestamp per thread; `raw_syscalls/sys_exit` joins them with the return
//! value and pushes one [`SyscallEvent`] to the `EVENTS` ring buffer.
//!
//! Filtering by process and by syscall number happens here, before anything
//! is stored, so unwanted syscalls cost one or two map lookups.
#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::bpf_pidns_info,
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid},
    macros::{map, tracepoint},
    maps::{Array, HashMap, LruHashMap, RingBuf},
    programs::TracePointContext,
};
use cortex9_tracer_common::{
    config, pidns, tp, InFlight, SyscallEvent, ARG_COUNT, COMM_LEN, EVENT_FLAG_IN_PIDNS,
    MAX_FILTER_ENTRIES, MAX_INFLIGHT, RING_BUF_BYTES,
};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(RING_BUF_BYTES, 0);

#[map]
static CONFIG: Array<u32> = Array::with_max_entries(config::LEN, 0);

#[map]
static PID_FILTER: HashMap<u32, u8> = HashMap::with_max_entries(MAX_FILTER_ENTRIES, 0);

#[map]
static SYSCALL_FILTER: HashMap<u32, u8> = HashMap::with_max_entries(MAX_FILTER_ENTRIES, 0);

#[map]
static INFLIGHT: LruHashMap<u64, InFlight> = LruHashMap::with_max_entries(MAX_INFLIGHT, 0);

#[map]
static DROPPED: Array<u64> = Array::with_max_entries(1, 0);

#[map]
static PIDNS: Array<u64> = Array::with_max_entries(pidns::LEN, 0);

/// Ids of the current task: `(tgid, tid, in_tracer_pidns)`.
///
/// Inside a container the global ids from `bpf_get_current_pid_tgid` do not
/// match the container's `/proc`, so when the loader configured `PIDNS` the
/// ids are translated to that namespace.
#[inline(always)]
fn task_ids(pid_tgid: u64) -> (u32, u32, bool) {
    let ino = PIDNS.get(pidns::INO).copied().unwrap_or(0);
    if ino != 0 {
        let dev = PIDNS.get(pidns::DEV).copied().unwrap_or(0);
        let mut info = bpf_pidns_info { pid: 0, tgid: 0 };
        // SAFETY: `info` is a valid, correctly sized out-parameter.
        let rc = unsafe {
            aya_ebpf::helpers::bpf_get_ns_current_pid_tgid(
                dev,
                ino,
                &mut info,
                core::mem::size_of::<bpf_pidns_info>() as u32,
            )
        };
        if rc == 0 {
            return (info.tgid, info.pid, true);
        }
        return ((pid_tgid >> 32) as u32, pid_tgid as u32, false);
    }
    ((pid_tgid >> 32) as u32, pid_tgid as u32, true)
}

#[inline(always)]
fn cfg(slot: u32) -> u32 {
    CONFIG.get(slot).copied().unwrap_or(0)
}

/// Process-level filter, applied at `sys_enter`.
#[inline(always)]
fn wanted_task(tgid: u32, in_ns: bool) -> bool {
    if in_ns && tgid == cfg(config::SELF_TGID) {
        return false;
    }
    if cfg(config::FLAGS) & config::FLAG_PID_FILTER != 0 {
        // PIDs given on the command line belong to the tracer's namespace.
        if !in_ns {
            return false;
        }
        // SAFETY: read-only lookup; the value is copied out immediately.
        return unsafe { PID_FILTER.get(&tgid) }.is_some();
    }
    true
}

#[inline(always)]
fn wanted_syscall(nr: u32) -> bool {
    if cfg(config::FLAGS) & config::FLAG_SYSCALL_FILTER != 0 {
        // SAFETY: as above.
        return unsafe { SYSCALL_FILTER.get(&nr) }.is_some();
    }
    true
}

#[tracepoint(category = "raw_syscalls", name = "sys_enter")]
pub fn cortex9_sys_enter(ctx: TracePointContext) -> u32 {
    let _ = try_sys_enter(&ctx);
    0
}

fn try_sys_enter(ctx: &TracePointContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let (tgid, _, in_ns) = task_ids(pid_tgid);
    if !wanted_task(tgid, in_ns) {
        return Ok(());
    }
    // SAFETY: offsets come from the stable raw_syscalls tracepoint format.
    let nr: i64 = unsafe { ctx.read_at(tp::ID) }.map_err(i64::from)?;
    if nr < 0 || !wanted_syscall(nr as u32) {
        return Ok(());
    }
    let args: [u64; ARG_COUNT] = unsafe { ctx.read_at(tp::ARGS) }.map_err(i64::from)?;
    let entry = InFlight {
        start_ns: unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() },
        nr: nr as u64,
        args,
    };
    INFLIGHT.insert(&pid_tgid, &entry, 0)?;
    Ok(())
}

#[tracepoint(category = "raw_syscalls", name = "sys_exit")]
pub fn cortex9_sys_exit(ctx: TracePointContext) -> u32 {
    let _ = try_sys_exit(&ctx);
    0
}

fn try_sys_exit(ctx: &TracePointContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    // SAFETY: the pointer is valid until the next map update for this key,
    // and only this thread touches its own key.
    let Some(entry) = (unsafe { INFLIGHT.get(&pid_tgid) }).copied() else {
        return Ok(());
    };
    let _ = INFLIGHT.remove(&pid_tgid);

    let ret: i64 = unsafe { ctx.read_at(tp::RET) }.map_err(i64::from)?;
    let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
    let comm = bpf_get_current_comm().unwrap_or([0u8; COMM_LEN]);
    let uid = bpf_get_current_uid_gid() as u32;
    let (tgid, tid, in_ns) = task_ids(pid_tgid);

    let event = SyscallEvent {
        ts_ns: now,
        duration_ns: now.saturating_sub(entry.start_ns),
        ret,
        args: entry.args,
        pid: tgid,
        tid,
        uid,
        nr: entry.nr as u32,
        comm,
        flags: if in_ns { EVENT_FLAG_IN_PIDNS } else { 0 },
        _pad: 0,
    };

    match EVENTS.reserve::<SyscallEvent>(0) {
        Some(mut slot) => {
            slot.write(event);
            slot.submit(0);
        }
        None => {
            if let Some(counter) = DROPPED.get_ptr_mut(0) {
                // SAFETY: single u64 slot; atomics are not needed for an
                // approximate counter.
                unsafe { *counter += 1 };
            }
        }
    }
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 4] = *b"GPL\0";
