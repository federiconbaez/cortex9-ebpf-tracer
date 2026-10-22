//! Command line interface.

use crate::filter::{parse_duration_ns, parse_syscalls, Filter, ParseError};
use crate::format::Format;
use crate::syscalls::Arch;
use clap::Parser;
use std::path::PathBuf;

/// Trace Linux syscalls with eBPF (raw_syscalls tracepoints + ring buffer).
///
/// Loading the eBPF program needs root or CAP_BPF + CAP_PERFMON.
/// `--list-syscalls` and `--print-config` work without privileges.
#[derive(Debug, Parser)]
#[command(name = "cortex9-tracer", version)]
pub struct Cli {
    /// Only these process ids (tgid). Repeatable or comma separated.
    #[arg(short, long = "pid", value_delimiter = ',')]
    pub pids: Vec<u32>,

    /// Only these command names (exact `comm`, max 15 chars). Repeatable.
    #[arg(short, long = "comm")]
    pub comms: Vec<String>,

    /// Only these syscalls: names or numbers, comma separated. Repeatable.
    #[arg(short, long = "syscall")]
    pub syscalls: Vec<String>,

    /// Only syscalls that took at least this long (e.g. 500us, 2ms; bare
    /// numbers are microseconds).
    #[arg(long, value_name = "DURATION")]
    pub min_duration: Option<String>,

    /// Only failed syscalls (return value in -4095..-1).
    #[arg(long)]
    pub failed: bool,

    /// Output format.
    #[arg(short, long, value_enum, default_value_t = Format::Text)]
    pub format: Format,

    /// Raw arguments to print in text mode (0-6).
    #[arg(short, long, default_value_t = 0, value_parser = clap::value_parser!(u8).range(0..=6))]
    pub args: u8,

    /// Print a per-syscall summary on exit.
    #[arg(long)]
    pub summary: bool,

    /// Do not print individual events (useful with --summary).
    #[arg(short, long)]
    pub quiet: bool,

    /// Stop after this many seconds.
    #[arg(short, long, value_name = "SECONDS")]
    pub time: Option<f64>,

    /// Stop after this many matching events.
    #[arg(short = 'n', long)]
    pub max_events: Option<u64>,

    /// Also trace the tracer's own process.
    #[arg(long)]
    pub include_self: bool,

    /// eBPF object to load instead of the embedded / default one.
    #[arg(long, value_name = "PATH")]
    pub object: Option<PathBuf>,

    /// Print the syscall table for this architecture and exit.
    #[arg(long)]
    pub list_syscalls: bool,

    /// Print the effective filter (userspace and kernel parts) as JSON and
    /// exit without loading anything.
    #[arg(long)]
    pub print_config: bool,
}

impl Cli {
    /// Build the [`Filter`] for `arch`.
    pub fn filter(&self, arch: Option<Arch>) -> Result<Filter, ParseError> {
        let mut f = Filter {
            pids: self.pids.iter().copied().collect(),
            failed_only: self.failed,
            ..Default::default()
        };
        for c in &self.comms {
            if c.is_empty() || c.len() > 15 {
                return Err(ParseError(format!(
                    "comm `{c}` must be 1..=15 bytes (kernel TASK_COMM_LEN)"
                )));
            }
            f.comms.insert(c.clone());
        }
        for s in &self.syscalls {
            f.syscalls.extend(parse_syscalls(arch, s)?);
        }
        if let Some(d) = &self.min_duration {
            f.min_duration_ns = parse_duration_ns(d)?;
        }
        if let Some(t) = self.time {
            if !(t.is_finite() && t > 0.0) {
                return Err(ParseError(format!("--time must be > 0, got {t}")));
            }
        }
        Ok(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once("cortex9-tracer").chain(args.iter().copied())).unwrap()
    }

    #[test]
    fn defaults() {
        let c = parse(&[]);
        assert_eq!(c.format, Format::Text);
        assert_eq!(c.args, 0);
        assert_eq!(c.filter(Some(Arch::X86_64)).unwrap(), Filter::default());
    }

    #[test]
    fn full_filter() {
        let c = parse(&[
            "-p",
            "1,2",
            "--pid",
            "3",
            "-c",
            "nginx",
            "-s",
            "openat,read",
            "-s",
            "59",
            "--min-duration",
            "1ms",
            "--failed",
            "-f",
            "json",
            "-a",
            "3",
        ]);
        let f = c.filter(Some(Arch::X86_64)).unwrap();
        assert_eq!(f.pids, BTreeSet::from([1, 2, 3]));
        assert_eq!(f.comms, BTreeSet::from(["nginx".to_string()]));
        assert_eq!(f.syscalls, BTreeSet::from([0, 59, 257]));
        assert_eq!(f.min_duration_ns, 1_000_000);
        assert!(f.failed_only);
        assert_eq!(c.format, Format::Json);
        assert_eq!(c.args, 3);
    }

    #[test]
    fn rejects_bad_values() {
        assert!(Cli::try_parse_from(["x", "-a", "7"]).is_err());
        assert!(Cli::try_parse_from(["x", "-p", "abc"]).is_err());
        assert!(Cli::try_parse_from(["x", "-f", "xml"]).is_err());
        let a = Some(Arch::X86_64);
        assert!(parse(&["-c", "this-name-is-too-long"]).filter(a).is_err());
        assert!(parse(&["-s", "bogus"]).filter(a).is_err());
        assert!(parse(&["--min-duration", "3h"]).filter(a).is_err());
        assert!(parse(&["-t", "0"]).filter(a).is_err());
    }
}
