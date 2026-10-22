//! Syscall number <-> name tables.
//!
//! Tables are generated from Linux UAPI headers by `scripts/gen_tables.py`.
//! Numbers are architecture specific; the tracer uses the table of the
//! architecture it was compiled for.

use std::fmt;
use std::str::FromStr;

mod aarch64;
mod x86_64;

/// Supported syscall ABIs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arch {
    X86_64,
    Aarch64,
}

impl Arch {
    /// The ABI of the running binary, if it has a table.
    pub fn host() -> Option<Self> {
        if cfg!(target_arch = "x86_64") {
            Some(Self::X86_64)
        } else if cfg!(target_arch = "aarch64") {
            Some(Self::Aarch64)
        } else {
            None
        }
    }

    fn table(self) -> &'static [Option<&'static str>] {
        match self {
            Self::X86_64 => &x86_64::TABLE,
            Self::Aarch64 => &aarch64::TABLE,
        }
    }

    /// Name of syscall `nr`, if known.
    pub fn name(self, nr: u32) -> Option<&'static str> {
        self.table().get(nr as usize).copied().flatten()
    }

    /// Number of syscall `name` (exact, case sensitive, without `sys_`).
    pub fn number(self, name: &str) -> Option<u32> {
        let name = name.strip_prefix("sys_").unwrap_or(name);
        self.table()
            .iter()
            .position(|n| *n == Some(name))
            .map(|i| i as u32)
    }

    /// All known `(number, name)` pairs in ascending order.
    pub fn entries(self) -> impl Iterator<Item = (u32, &'static str)> {
        self.table()
            .iter()
            .enumerate()
            .filter_map(|(i, n)| n.map(|n| (i as u32, n)))
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        })
    }
}

impl FromStr for Arch {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "x86_64" | "amd64" => Ok(Self::X86_64),
            "aarch64" | "arm64" => Ok(Self::Aarch64),
            other => Err(format!("unknown arch `{other}` (x86_64, aarch64)")),
        }
    }
}

/// Display name for `nr`: the table name or `syscall_<nr>`.
pub fn display_name(arch: Option<Arch>, nr: u32) -> String {
    arch.and_then(|a| a.name(nr))
        .map(str::to_owned)
        .unwrap_or_else(|| format!("syscall_{nr}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x86_64_well_known_numbers() {
        let a = Arch::X86_64;
        assert_eq!(a.name(0), Some("read"));
        assert_eq!(a.name(1), Some("write"));
        assert_eq!(a.name(59), Some("execve"));
        assert_eq!(a.name(257), Some("openat"));
        assert_eq!(a.name(435), Some("clone3"));
        assert_eq!(a.number("openat"), Some(257));
        assert_eq!(a.number("sys_openat"), Some(257));
    }

    #[test]
    fn aarch64_well_known_numbers() {
        let a = Arch::Aarch64;
        assert_eq!(a.name(56), Some("openat"));
        assert_eq!(a.name(63), Some("read"));
        assert_eq!(a.name(64), Some("write"));
        assert_eq!(a.name(221), Some("execve"));
        assert_eq!(a.name(79), Some("newfstatat"));
        assert_eq!(a.number("openat"), Some(56));
        // asm-generic has no open(2).
        assert_eq!(a.number("open"), None);
    }

    #[test]
    fn unknown_numbers_and_names() {
        assert_eq!(Arch::X86_64.name(100_000), None);
        assert_eq!(Arch::X86_64.number("definitely_not_a_syscall"), None);
        assert_eq!(display_name(Some(Arch::X86_64), 100_000), "syscall_100000");
        assert_eq!(display_name(None, 1), "syscall_1");
    }

    #[test]
    fn tables_have_unique_names() {
        for arch in [Arch::X86_64, Arch::Aarch64] {
            let mut names: Vec<_> = arch.entries().map(|(_, n)| n).collect();
            let len = names.len();
            names.sort_unstable();
            names.dedup();
            assert_eq!(names.len(), len, "{arch}");
            assert!(len > 300, "{arch} table too small: {len}");
        }
    }

    #[test]
    fn arch_parse_and_display() {
        assert_eq!("amd64".parse::<Arch>(), Ok(Arch::X86_64));
        assert_eq!("arm64".parse::<Arch>(), Ok(Arch::Aarch64));
        assert!("riscv64".parse::<Arch>().is_err());
        assert_eq!(Arch::Aarch64.to_string(), "aarch64");
    }
}
