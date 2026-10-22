//! User filters.
//!
//! Filters are split in two layers:
//!
//! - [`KernelFilter`]: PID and syscall-number sets, pushed into BPF hash
//!   maps so unwanted syscalls are dropped before they reach the ring buffer.
//! - [`Filter::matches`]: the full set (including `comm`, minimum duration
//!   and failed-only), applied in userspace to every decoded event. It
//!   re-checks the kernel conditions too, so it is correct on its own.

use crate::errno;
use crate::event::Event;
use crate::syscalls::Arch;
use std::collections::BTreeSet;
use std::fmt;

/// Error parsing a filter value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseError(pub String);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ParseError {}

/// Complete filter. Empty sets mean "no restriction".
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct Filter {
    pub pids: BTreeSet<u32>,
    pub comms: BTreeSet<String>,
    pub syscalls: BTreeSet<u32>,
    pub min_duration_ns: u64,
    pub failed_only: bool,
}

/// The part of [`Filter`] that the eBPF program enforces.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KernelFilter {
    pub pids: Option<Vec<u32>>,
    pub syscalls: Option<Vec<u32>>,
}

impl Filter {
    /// True if `e` passes every configured condition.
    pub fn matches(&self, e: &Event) -> bool {
        // PIDs on the command line are relative to the tracer's namespace,
        // so tasks outside it never match a PID filter.
        (self.pids.is_empty() || (e.in_pidns && self.pids.contains(&e.pid)))
            && (self.syscalls.is_empty() || self.syscalls.contains(&e.nr))
            && (self.comms.is_empty() || self.comms.contains(&e.comm))
            && e.duration_ns >= self.min_duration_ns
            && (!self.failed_only || errno::from_ret(e.ret).is_some())
    }

    /// Kernel-side subset. `max_entries` is the BPF map capacity; a set that
    /// does not fit is left to userspace instead of being truncated.
    pub fn kernel(&self, max_entries: usize) -> KernelFilter {
        let pick = |s: &BTreeSet<u32>| {
            (!s.is_empty() && s.len() <= max_entries).then(|| s.iter().copied().collect())
        };
        KernelFilter {
            pids: pick(&self.pids),
            syscalls: pick(&self.syscalls),
        }
    }
}

/// Parse a list of syscalls: names (`openat`, `sys_read`) or numbers,
/// separated by commas. Names are resolved with `arch`.
pub fn parse_syscalls(arch: Option<Arch>, spec: &str) -> Result<BTreeSet<u32>, ParseError> {
    let mut out = BTreeSet::new();
    for item in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if let Ok(n) = item.parse::<u32>() {
            out.insert(n);
            continue;
        }
        let arch = arch.ok_or_else(|| {
            ParseError(format!(
                "no syscall table for this architecture; use numbers instead of `{item}`"
            ))
        })?;
        let n = arch
            .number(item)
            .ok_or_else(|| ParseError(format!("unknown syscall `{item}` on {arch}")))?;
        out.insert(n);
    }
    if out.is_empty() {
        return Err(ParseError("empty syscall list".into()));
    }
    Ok(out)
}

/// Parse a duration such as `1500`, `1500ns`, `250us`, `2ms`, `1.5s`.
/// A bare number is microseconds.
pub fn parse_duration_ns(s: &str) -> Result<u64, ParseError> {
    let s = s.trim();
    let split = s
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let mult: f64 = match unit.trim() {
        "ns" => 1.0,
        "" | "us" | "µs" => 1e3,
        "ms" => 1e6,
        "s" => 1e9,
        other => return Err(ParseError(format!("unknown duration unit `{other}`"))),
    };
    let v: f64 = num
        .parse()
        .map_err(|_| ParseError(format!("invalid duration `{s}`")))?;
    if !v.is_finite() || v < 0.0 {
        return Err(ParseError(format!("invalid duration `{s}`")));
    }
    let ns = v * mult;
    if ns > u64::MAX as f64 {
        return Err(ParseError(format!("duration `{s}` too large")));
    }
    Ok(ns.round() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::sample;

    #[test]
    fn empty_filter_matches_everything() {
        assert!(Filter::default().matches(&sample()));
    }

    #[test]
    fn each_condition() {
        let e = sample(); // pid 4242, nr 257, comm cat, 12.345us, ret 3
        let f = |g: fn(&mut Filter)| {
            let mut f = Filter::default();
            g(&mut f);
            f.matches(&e)
        };
        assert!(f(|f| {
            f.pids.insert(4242);
        }));
        assert!(!f(|f| {
            f.pids.insert(1);
        }));
        assert!(f(|f| {
            f.comms.insert("cat".into());
        }));
        assert!(!f(|f| {
            f.comms.insert("ca".into());
        }));
        assert!(f(|f| {
            f.syscalls.insert(257);
        }));
        assert!(!f(|f| {
            f.syscalls.insert(0);
        }));
        assert!(f(|f| f.min_duration_ns = 12_345));
        assert!(!f(|f| f.min_duration_ns = 12_346));
        assert!(!f(|f| f.failed_only = true));
    }

    #[test]
    fn pid_filter_ignores_tasks_outside_pidns() {
        let mut f = Filter::default();
        f.pids.insert(4242);
        let mut e = sample();
        assert!(f.matches(&e));
        e.in_pidns = false;
        assert!(!f.matches(&e));
        assert!(Filter::default().matches(&e));
    }

    #[test]
    fn failed_only_uses_errno_range() {
        let f = Filter {
            failed_only: true,
            ..Default::default()
        };
        let mut e = sample();
        e.ret = -2;
        assert!(f.matches(&e));
        e.ret = -5000;
        assert!(!f.matches(&e));
    }

    #[test]
    fn kernel_subset() {
        let mut f = Filter::default();
        assert_eq!(f.kernel(8), KernelFilter::default());
        f.pids.extend([3, 1, 2]);
        f.syscalls.extend(0..10);
        f.comms.insert("x".into());
        let k = f.kernel(8);
        assert_eq!(k.pids, Some(vec![1, 2, 3]));
        // Too many for the map: userspace only.
        assert_eq!(k.syscalls, None);
    }

    #[test]
    fn syscall_lists() {
        let a = Some(Arch::X86_64);
        assert_eq!(
            parse_syscalls(a, "openat, read,59").unwrap(),
            BTreeSet::from([0, 59, 257])
        );
        assert_eq!(parse_syscalls(a, "sys_write").unwrap(), BTreeSet::from([1]));
        assert!(parse_syscalls(a, "nope").is_err());
        assert!(parse_syscalls(a, " , ").is_err());
        assert!(parse_syscalls(None, "openat").is_err());
        assert_eq!(parse_syscalls(None, "7").unwrap(), BTreeSet::from([7]));
        assert_eq!(
            parse_syscalls(Some(Arch::Aarch64), "openat").unwrap(),
            BTreeSet::from([56])
        );
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration_ns("1500ns"), Ok(1500));
        assert_eq!(parse_duration_ns("250us"), Ok(250_000));
        assert_eq!(parse_duration_ns("250µs"), Ok(250_000));
        assert_eq!(parse_duration_ns("250"), Ok(250_000));
        assert_eq!(parse_duration_ns("2ms"), Ok(2_000_000));
        assert_eq!(parse_duration_ns("1.5s"), Ok(1_500_000_000));
        assert_eq!(parse_duration_ns("0"), Ok(0));
        assert!(parse_duration_ns("2h").is_err());
        assert!(parse_duration_ns("ms").is_err());
        assert!(parse_duration_ns("1.2.3ms").is_err());
        assert!(parse_duration_ns("1e30s").is_err());
    }
}
