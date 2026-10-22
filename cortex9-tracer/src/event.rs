//! Decoding of ring buffer records into owned [`Event`]s.
//!
//! Records are decoded field by field from fixed little-endian offsets
//! (see [`cortex9_tracer_common::offsets`]) instead of casting the raw bytes,
//! so a short or malformed record is an error rather than undefined
//! behaviour.

use cortex9_tracer_common::{offsets, ARG_COUNT, COMM_LEN, EVENT_FLAG_IN_PIDNS, EVENT_SIZE};
use std::fmt;

/// One completed syscall.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    pub ts_ns: u64,
    pub duration_ns: u64,
    pub ret: i64,
    pub args: [u64; ARG_COUNT],
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub nr: u32,
    /// `comm` up to the first NUL, lossily decoded as UTF-8.
    pub comm: String,
    /// `pid`/`tid` are relative to the tracer's PID namespace. `false` means
    /// a task outside it, reported with init-namespace ids.
    pub in_pidns: bool,
}

/// Why a record could not be decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The record is shorter than [`EVENT_SIZE`].
    TooShort { len: usize },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { len } => {
                write!(f, "record of {len} bytes, expected at least {EVENT_SIZE}")
            }
        }
    }
}

impl std::error::Error for DecodeError {}

fn u64_at(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().expect("8 bytes"))
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().expect("4 bytes"))
}

/// Decode `comm`: stop at the first NUL, replace invalid UTF-8.
pub fn decode_comm(raw: &[u8]) -> String {
    let end = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

impl Event {
    /// Decode one ring buffer record. Extra trailing bytes are ignored
    /// (the kernel may round records up).
    pub fn decode(b: &[u8]) -> Result<Self, DecodeError> {
        if b.len() < EVENT_SIZE {
            return Err(DecodeError::TooShort { len: b.len() });
        }
        let mut args = [0u64; ARG_COUNT];
        for (i, a) in args.iter_mut().enumerate() {
            *a = u64_at(b, offsets::ARGS + i * 8);
        }
        Ok(Self {
            ts_ns: u64_at(b, offsets::TS_NS),
            duration_ns: u64_at(b, offsets::DURATION_NS),
            ret: u64_at(b, offsets::RET) as i64,
            args,
            pid: u32_at(b, offsets::PID),
            tid: u32_at(b, offsets::TID),
            uid: u32_at(b, offsets::UID),
            nr: u32_at(b, offsets::NR),
            comm: decode_comm(&b[offsets::COMM..offsets::COMM + COMM_LEN]),
            in_pidns: u32_at(b, offsets::FLAGS) & EVENT_FLAG_IN_PIDNS != 0,
        })
    }

    /// Encode back to the wire layout. Used by tests and fixtures; `comm`
    /// is truncated to 15 bytes plus NUL like the kernel does.
    pub fn encode(&self) -> [u8; EVENT_SIZE] {
        let mut b = [0u8; EVENT_SIZE];
        b[offsets::TS_NS..][..8].copy_from_slice(&self.ts_ns.to_le_bytes());
        b[offsets::DURATION_NS..][..8].copy_from_slice(&self.duration_ns.to_le_bytes());
        b[offsets::RET..][..8].copy_from_slice(&self.ret.to_le_bytes());
        for (i, a) in self.args.iter().enumerate() {
            b[offsets::ARGS + i * 8..][..8].copy_from_slice(&a.to_le_bytes());
        }
        b[offsets::PID..][..4].copy_from_slice(&self.pid.to_le_bytes());
        b[offsets::TID..][..4].copy_from_slice(&self.tid.to_le_bytes());
        b[offsets::UID..][..4].copy_from_slice(&self.uid.to_le_bytes());
        b[offsets::NR..][..4].copy_from_slice(&self.nr.to_le_bytes());
        let comm = self.comm.as_bytes();
        let n = comm.len().min(COMM_LEN - 1);
        b[offsets::COMM..][..n].copy_from_slice(&comm[..n]);
        let flags = if self.in_pidns {
            EVENT_FLAG_IN_PIDNS
        } else {
            0
        };
        b[offsets::FLAGS..][..4].copy_from_slice(&flags.to_le_bytes());
        b
    }
}

/// Fixture user id for tests.
#[cfg(test)]
pub(crate) const TEST_USER: u32 = 1000;

#[cfg(test)]
pub(crate) fn sample() -> Event {
    Event {
        ts_ns: 1_000_000_000,
        duration_ns: 12_345,
        ret: 3,
        args: [0xffff_ff9c, 0x7ffd_0000_1000, 0x80000, 0, 0, 0],
        pid: 4242,
        tid: 4243,
        uid: TEST_USER,
        nr: 257,
        comm: "cat".into(),
        in_pidns: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cortex9_tracer_common::SyscallEvent;

    #[test]
    fn roundtrip() {
        let e = sample();
        assert_eq!(Event::decode(&e.encode()).unwrap(), e);
    }

    #[test]
    fn matches_repr_c_layout() {
        // Build the record exactly as the eBPF side does and decode it.
        let mut comm = [0u8; COMM_LEN];
        comm[..4].copy_from_slice(b"curl");
        let raw = SyscallEvent {
            ts_ns: 7,
            duration_ns: 8,
            ret: -2,
            args: [1, 2, 3, 4, 5, 6],
            pid: 10,
            tid: 11,
            uid: TEST_USER + 12,
            nr: 13,
            comm,
            flags: EVENT_FLAG_IN_PIDNS,
            _pad: 0,
        };
        // SAFETY: SyscallEvent is repr(C), Copy, with no padding holes
        // (checked in cortex9-tracer-common tests).
        let bytes: [u8; EVENT_SIZE] = unsafe { std::mem::transmute(raw) };
        let e = Event::decode(&bytes).unwrap();
        assert_eq!(e.ts_ns, 7);
        assert_eq!(e.duration_ns, 8);
        assert_eq!(e.ret, -2);
        assert_eq!(e.args, [1, 2, 3, 4, 5, 6]);
        assert_eq!((e.pid, e.tid, e.uid, e.nr), (10, 11, TEST_USER + 12, 13));
        assert_eq!(e.comm, "curl");
        assert!(e.in_pidns);
    }

    #[test]
    fn pidns_flag() {
        let mut e = sample();
        e.in_pidns = false;
        assert!(!Event::decode(&e.encode()).unwrap().in_pidns);
    }

    #[test]
    fn rejects_short_records() {
        let b = sample().encode();
        assert_eq!(
            Event::decode(&b[..EVENT_SIZE - 1]),
            Err(DecodeError::TooShort {
                len: EVENT_SIZE - 1
            })
        );
        assert!(Event::decode(&[]).is_err());
    }

    #[test]
    fn ignores_trailing_bytes() {
        let mut v = sample().encode().to_vec();
        v.extend_from_slice(&[0xAA; 8]);
        assert_eq!(Event::decode(&v).unwrap(), sample());
    }

    #[test]
    fn comm_handling() {
        assert_eq!(decode_comm(b"bash\0\0\0garbage"), "bash");
        assert_eq!(decode_comm(b"exactly16bytes!!"), "exactly16bytes!!");
        assert_eq!(decode_comm(&[0xff, b'x', 0]), "\u{fffd}x");
        let mut e = sample();
        e.comm = "a-very-long-command-name".into();
        assert_eq!(Event::decode(&e.encode()).unwrap().comm, "a-very-long-com");
    }
}
