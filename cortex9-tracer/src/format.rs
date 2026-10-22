//! Output formats: human-readable text and JSON lines.

use crate::errno;
use crate::event::Event;
use crate::syscalls::{display_name, Arch};
use serde::Serialize;
use std::fmt::Write as _;

/// Output style.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    /// One aligned line per syscall.
    Text,
    /// One JSON object per line.
    Json,
}

/// Formatting context.
#[derive(Clone, Copy, Debug)]
pub struct Formatter {
    pub arch: Option<Arch>,
    /// Monotonic time (ns) the trace started; timestamps are relative to it.
    pub start_ns: u64,
    /// Number of raw arguments printed in text mode (0..=6).
    pub args: usize,
}

/// `-2` -> `-2 ENOENT`, `3` -> `3`; values beyond 32 bits (pointers from
/// `mmap`, `brk`) in hex.
pub fn format_ret(ret: i64) -> String {
    match errno::from_ret(ret) {
        Some(e) => match errno::name(e) {
            Some(n) => format!("-{e} {n}"),
            None => format!("-{e}"),
        },
        None if !(-0xffff_ffff..=0xffff_ffff).contains(&ret) => format!("{:#x}", ret as u64),
        None => ret.to_string(),
    }
}

/// `12345` -> `12.345us`.
pub fn format_duration(ns: u64) -> String {
    match ns {
        n if n < 1_000 => format!("{n}ns"),
        n if n < 1_000_000 => format!("{:.3}us", n as f64 / 1e3),
        n if n < 1_000_000_000 => format!("{:.3}ms", n as f64 / 1e6),
        n => format!("{:.3}s", n as f64 / 1e9),
    }
}

#[derive(Serialize)]
struct JsonEvent<'a> {
    ts_ns: u64,
    rel_ns: u64,
    pid: u32,
    tid: u32,
    uid: u32,
    comm: &'a str,
    nr: u32,
    syscall: String,
    args: [u64; 6],
    ret: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    errno: Option<&'static str>,
    duration_ns: u64,
    in_pidns: bool,
}

impl Formatter {
    /// Header line for text mode.
    pub fn text_header(&self) -> String {
        format!(
            "{:>14} {:>7} {:>7} {:<16} {:<20} {:>16} {}",
            "TIME(s)", "PID", "TID", "COMM", "SYSCALL", "RET", "DURATION"
        )
    }

    /// One event as text, without trailing newline.
    pub fn text(&self, e: &Event) -> String {
        let rel = e.ts_ns.saturating_sub(self.start_ns) as f64 / 1e9;
        let mut call = display_name(self.arch, e.nr);
        if self.args > 0 {
            call.push('(');
            for (i, a) in e.args.iter().take(self.args.min(6)).enumerate() {
                if i > 0 {
                    call.push_str(", ");
                }
                let _ = write!(call, "{a:#x}");
            }
            call.push(')');
        }
        // `*` marks init-namespace ids of a task outside the tracer's pidns.
        let mark = if e.in_pidns { "" } else { "*" };
        format!(
            "{:>14.6} {:>7} {:>7} {:<16} {:<20} {:>16} {}",
            rel,
            format!("{}{mark}", e.pid),
            format!("{}{mark}", e.tid),
            e.comm,
            call,
            format_ret(e.ret),
            format_duration(e.duration_ns)
        )
    }

    /// One event as a JSON object, without trailing newline.
    pub fn json(&self, e: &Event) -> String {
        let j = JsonEvent {
            ts_ns: e.ts_ns,
            rel_ns: e.ts_ns.saturating_sub(self.start_ns),
            pid: e.pid,
            tid: e.tid,
            uid: e.uid,
            comm: &e.comm,
            nr: e.nr,
            syscall: display_name(self.arch, e.nr),
            args: e.args,
            ret: e.ret,
            errno: errno::from_ret(e.ret).and_then(errno::name),
            duration_ns: e.duration_ns,
            in_pidns: e.in_pidns,
        };
        serde_json::to_string(&j).expect("serializable")
    }

    /// Dispatch on `format`.
    pub fn line(&self, format: Format, e: &Event) -> String {
        match format {
            Format::Text => self.text(e),
            Format::Json => self.json(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::sample;

    fn fmt(args: usize) -> Formatter {
        Formatter {
            arch: Some(Arch::X86_64),
            start_ns: 500_000_000,
            args,
        }
    }

    #[test]
    fn returns() {
        assert_eq!(format_ret(3), "3");
        assert_eq!(format_ret(0), "0");
        assert_eq!(format_ret(-2), "-2 ENOENT");
        assert_eq!(format_ret(-4000), "-4000");
        assert_eq!(format_ret(69_195), "69195");
        assert_eq!(format_ret(0x7f00_0000_0000), "0x7f0000000000");
    }

    #[test]
    fn durations() {
        assert_eq!(format_duration(999), "999ns");
        assert_eq!(format_duration(12_345), "12.345us");
        assert_eq!(format_duration(2_500_000), "2.500ms");
        assert_eq!(format_duration(3_000_000_000), "3.000s");
    }

    #[test]
    fn text_line() {
        let line = fmt(0).text(&sample());
        assert!(line.contains(" openat "), "{line}");
        assert!(line.contains(" 4242 "), "{line}");
        assert!(line.contains(" cat "), "{line}");
        assert!(line.trim_start().starts_with("0.500000"), "{line}");
        assert!(line.ends_with("12.345us"), "{line}");
        let with_args = fmt(2).text(&sample());
        assert!(
            with_args.contains("openat(0xffffff9c, 0x7ffd00001000)"),
            "{with_args}"
        );
        assert!(fmt(0).text_header().contains("SYSCALL"));
        let mut outside = sample();
        outside.in_pidns = false;
        assert!(fmt(0).text(&outside).contains(" 4242* "));
    }

    #[test]
    fn json_line() {
        let mut e = sample();
        e.ret = -13;
        let v: serde_json::Value = serde_json::from_str(&fmt(0).json(&e)).unwrap();
        assert_eq!(v["syscall"], "openat");
        assert_eq!(v["pid"], 4242);
        assert_eq!(v["comm"], "cat");
        assert_eq!(v["ret"], -13);
        assert_eq!(v["errno"], "EACCES");
        assert_eq!(v["rel_ns"], 500_000_000);
        assert_eq!(v["args"][2], 0x80000);
        let ok: serde_json::Value = serde_json::from_str(&fmt(0).json(&sample())).unwrap();
        assert!(ok.get("errno").is_none());
        assert_eq!(ok["in_pidns"], true);
    }

    #[test]
    fn unknown_arch_falls_back_to_numbers() {
        let f = Formatter {
            arch: None,
            ..fmt(0)
        };
        assert!(f.text(&sample()).contains("syscall_257"));
    }
}
