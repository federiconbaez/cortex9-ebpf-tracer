//! Per-syscall summary (`--summary`).

use crate::errno;
use crate::event::Event;
use crate::format::format_duration;
use crate::syscalls::{display_name, Arch};
use std::collections::HashMap;
use std::fmt::Write as _;

/// Aggregated numbers for one syscall.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Row {
    pub count: u64,
    pub errors: u64,
    pub total_ns: u64,
    pub max_ns: u64,
}

/// Accumulates [`Row`]s keyed by syscall number.
#[derive(Clone, Debug, Default)]
pub struct Stats {
    rows: HashMap<u32, Row>,
    pub events: u64,
}

impl Stats {
    pub fn record(&mut self, e: &Event) {
        self.events += 1;
        let r = self.rows.entry(e.nr).or_default();
        r.count += 1;
        r.total_ns = r.total_ns.saturating_add(e.duration_ns);
        r.max_ns = r.max_ns.max(e.duration_ns);
        if errno::from_ret(e.ret).is_some() {
            r.errors += 1;
        }
    }

    pub fn get(&self, nr: u32) -> Option<Row> {
        self.rows.get(&nr).copied()
    }

    /// Rows sorted by count (desc), then by number.
    pub fn sorted(&self) -> Vec<(u32, Row)> {
        let mut v: Vec<_> = self.rows.iter().map(|(k, r)| (*k, *r)).collect();
        v.sort_by(|a, b| b.1.count.cmp(&a.1.count).then(a.0.cmp(&b.0)));
        v
    }

    /// Render as a text table.
    pub fn render(&self, arch: Option<Arch>) -> String {
        let mut s = format!(
            "{:<20} {:>10} {:>8} {:>12} {:>12}\n",
            "SYSCALL", "COUNT", "ERRORS", "AVG", "MAX"
        );
        for (nr, r) in self.sorted() {
            let avg = r.total_ns.checked_div(r.count).unwrap_or(0);
            let _ = writeln!(
                s,
                "{:<20} {:>10} {:>8} {:>12} {:>12}",
                display_name(arch, nr),
                r.count,
                r.errors,
                format_duration(avg),
                format_duration(r.max_ns)
            );
        }
        let _ = write!(s, "{} events", self.events);
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::sample;

    #[test]
    fn aggregates_and_sorts() {
        let mut st = Stats::default();
        let mut e = sample();
        st.record(&e);
        e.duration_ns = 100;
        e.ret = -2;
        st.record(&e);
        e.nr = 0;
        st.record(&e);

        let open = st.get(257).unwrap();
        assert_eq!(open.count, 2);
        assert_eq!(open.errors, 1);
        assert_eq!(open.total_ns, 12_445);
        assert_eq!(open.max_ns, 12_345);
        assert_eq!(st.events, 3);
        assert_eq!(st.sorted()[0].0, 257);

        let table = st.render(Some(Arch::X86_64));
        assert!(table.lines().nth(1).unwrap().starts_with("openat"));
        assert!(table.contains("read"));
        assert!(table.ends_with("3 events"));
    }

    #[test]
    fn empty() {
        let st = Stats::default();
        assert!(st.sorted().is_empty());
        assert!(st.render(None).ends_with("0 events"));
    }
}
