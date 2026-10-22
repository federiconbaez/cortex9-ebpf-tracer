//! `cortex9-tracer` binary: parses the CLI, loads the eBPF object, programs
//! the kernel-side filters, attaches the `raw_syscalls` tracepoints and
//! prints events read from the ring buffer.

use anyhow::{bail, Context, Result};
use clap::Parser;
use cortex9_tracer::cli::Cli;
use cortex9_tracer::syscalls::Arch;
use std::io::Write;

fn main() -> Result<()> {
    let cli = Cli::parse();
    let arch = Arch::host();
    let filter = cli.filter(arch)?;

    if cli.list_syscalls {
        let Some(arch) = arch else {
            bail!("no syscall table for this architecture");
        };
        let mut out = std::io::stdout().lock();
        for (nr, name) in arch.entries() {
            writeln!(out, "{nr}\t{name}")?;
        }
        return Ok(());
    }

    if cli.print_config {
        let k = filter.kernel(cortex9_tracer_common::MAX_FILTER_ENTRIES as usize);
        let v = serde_json::json!({
            "arch": arch.map(|a| a.to_string()),
            "filter": filter,
            "kernel": { "pids": k.pids, "syscalls": k.syscalls },
            "exclude_self": !cli.include_self,
        });
        println!("{v}");
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        linux::run(&cli, arch, filter)
    }
    #[cfg(not(target_os = "linux"))]
    {
        bail!("tracing requires Linux")
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use aya::maps::{Array, HashMap, MapData, RingBuf};
    use aya::programs::TracePoint;
    use aya::Ebpf;
    use cortex9_tracer::event::Event;
    use cortex9_tracer::filter::Filter;
    use cortex9_tracer::format::{Format, Formatter};
    use cortex9_tracer::stats::Stats;
    use cortex9_tracer_common::{config, maps, pidns, programs, MAX_FILTER_ENTRIES};
    use std::io::{BufWriter, ErrorKind};
    use std::os::unix::fs::MetadataExt;
    use std::time::Duration;
    use tokio::io::unix::AsyncFd;
    use tokio::signal::unix::{signal, SignalKind};

    #[cfg(embedded_ebpf)]
    static EMBEDDED: Option<&[u8]> = Some(aya::include_bytes_aligned!(env!("CORTEX9_EBPF_OBJ")));
    #[cfg(not(embedded_ebpf))]
    static EMBEDDED: Option<&[u8]> = None;

    const DEFAULT_OBJECT: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../cortex9-tracer-ebpf/target/bpfel-unknown-none/release/cortex9-tracer-ebpf"
    );

    fn monotonic_ns() -> u64 {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: valid pointer to a timespec; CLOCK_MONOTONIC always exists.
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
        ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
    }

    fn bump_memlock() {
        // Only needed on kernels < 5.11 (before memcg accounting of BPF maps).
        let rlim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        // SAFETY: plain syscall with a valid pointer.
        let _ = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    }

    fn load(cli: &Cli) -> Result<Ebpf> {
        if let Some(path) = &cli.object {
            return Ebpf::load_file(path).with_context(|| format!("loading {}", path.display()));
        }
        if let Some(bytes) = EMBEDDED {
            return Ebpf::load(bytes).context("loading embedded eBPF object");
        }
        Ebpf::load_file(DEFAULT_OBJECT).with_context(|| {
            format!("loading {DEFAULT_OBJECT} (build it with `cargo xtask build-ebpf` or pass --object)")
        })
    }

    fn program_filters(ebpf: &mut Ebpf, cli: &Cli, filter: &Filter) -> Result<()> {
        let k = filter.kernel(MAX_FILTER_ENTRIES as usize);
        let mut flags = 0u32;
        if let Some(pids) = &k.pids {
            let mut m: HashMap<&mut MapData, u32, u8> =
                HashMap::try_from(ebpf.map_mut(maps::PID_FILTER).context("PID_FILTER map")?)?;
            for p in pids {
                m.insert(p, 1, 0)?;
            }
            flags |= config::FLAG_PID_FILTER;
        }
        if let Some(nrs) = &k.syscalls {
            let mut m: HashMap<&mut MapData, u32, u8> = HashMap::try_from(
                ebpf.map_mut(maps::SYSCALL_FILTER)
                    .context("SYSCALL_FILTER map")?,
            )?;
            for n in nrs {
                m.insert(n, 1, 0)?;
            }
            flags |= config::FLAG_SYSCALL_FILTER;
        }
        let mut cfg: Array<&mut MapData, u32> =
            Array::try_from(ebpf.map_mut(maps::CONFIG).context("CONFIG map")?)?;
        cfg.set(config::FLAGS, flags, 0)?;
        let me = if cli.include_self {
            0
        } else {
            std::process::id()
        };
        cfg.set(config::SELF_TGID, me, 0)?;
        Ok(())
    }

    /// `(kernel dev_t, inode)` of our PID namespace. The kernel compares the
    /// nsfs superblock's `s_dev` (`MKDEV(major, minor)` = `major << 20 |
    /// minor`), not the userspace `st_dev` encoding.
    fn own_pidns() -> Result<(u64, u64)> {
        let md = std::fs::metadata("/proc/self/ns/pid").context("stat /proc/self/ns/pid")?;
        let dev = md.dev();
        let (major, minor) = (libc::major(dev) as u64, libc::minor(dev) as u64);
        Ok(((major << 20) | minor, md.ino()))
    }

    fn program_pidns(ebpf: &mut Ebpf) -> Result<()> {
        let (dev, ino) = own_pidns()?;
        let mut a: Array<&mut MapData, u64> =
            Array::try_from(ebpf.map_mut(maps::PIDNS).context("PIDNS map")?)?;
        a.set(pidns::DEV, dev, 0)?;
        a.set(pidns::INO, ino, 0)?;
        Ok(())
    }

    fn attach(ebpf: &mut Ebpf, prog: &str, name: &str) -> Result<()> {
        let tp: &mut TracePoint = ebpf
            .program_mut(prog)
            .with_context(|| format!("program {prog}"))?
            .try_into()?;
        tp.load()
            .with_context(|| format!("verifier rejected {prog}"))?;
        tp.attach("raw_syscalls", name)
            .with_context(|| format!("attaching raw_syscalls/{name}"))?;
        Ok(())
    }

    fn dropped(ebpf: &Ebpf) -> u64 {
        ebpf.map(maps::DROPPED)
            .and_then(|m| Array::<_, u64>::try_from(m).ok())
            .and_then(|a| a.get(&0, 0).ok())
            .unwrap_or(0)
    }

    pub fn run(cli: &Cli, arch: Option<Arch>, filter: Filter) -> Result<()> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(trace(cli, arch, filter))
    }

    async fn trace(cli: &Cli, arch: Option<Arch>, filter: Filter) -> Result<()> {
        bump_memlock();
        let mut ebpf = load(cli)?;
        program_filters(&mut ebpf, cli, &filter)?;
        program_pidns(&mut ebpf)?;
        let ring = RingBuf::try_from(ebpf.take_map(maps::EVENTS).context("EVENTS map")?)?;
        let fmt = Formatter {
            arch,
            start_ns: monotonic_ns(),
            args: cli.args as usize,
        };
        attach(&mut ebpf, programs::SYS_EXIT, "sys_exit")?;
        attach(&mut ebpf, programs::SYS_ENTER, "sys_enter")?;
        eprintln!("cortex9-tracer: attached to raw_syscalls/sys_enter and sys_exit");

        // SAFETY: the RingBuf owns its map fd and keeps it open, unchanged,
        // for as long as the AsyncFd lives.
        let mut ring = unsafe { AsyncFd::register(ring)? };
        let mut out = BufWriter::new(std::io::stdout().lock());
        if cli.format == Format::Text && !cli.quiet {
            writeln!(out, "{}", fmt.text_header())?;
        }
        let mut stats = Stats::default();
        let mut matched = 0u64;
        let mut decode_errors = 0u64;
        let mut sigint = signal(SignalKind::interrupt())?;
        let mut sigterm = signal(SignalKind::terminate())?;
        let limit = Duration::from_secs_f64(cli.time.unwrap_or(365.0 * 24.0 * 3600.0));
        let deadline = tokio::time::sleep(limit);
        tokio::pin!(deadline);

        'outer: loop {
            tokio::select! {
                _ = sigint.recv() => break,
                _ = sigterm.recv() => break,
                _ = &mut deadline => break,
                guard = ring.readable_mut() => {
                    let mut guard = guard?;
                    let rb = guard.get_inner_mut();
                    while let Some(item) = rb.next() {
                        let e = match Event::decode(&item) {
                            Ok(e) => e,
                            Err(_) => { decode_errors += 1; continue; }
                        };
                        if !filter.matches(&e) {
                            continue;
                        }
                        matched += 1;
                        if cli.summary {
                            stats.record(&e);
                        }
                        if !cli.quiet {
                            if let Err(err) = writeln!(out, "{}", fmt.line(cli.format, &e)) {
                                if err.kind() == ErrorKind::BrokenPipe {
                                    break 'outer;
                                }
                                return Err(err.into());
                            }
                        }
                        if cli.max_events.is_some_and(|m| matched >= m) {
                            break 'outer;
                        }
                    }
                    guard.clear_ready();
                    if let Err(err) = out.flush() {
                        if err.kind() == ErrorKind::BrokenPipe {
                            break;
                        }
                        return Err(err.into());
                    }
                }
            }
        }
        let _ = out.flush();
        drop(out);

        if cli.summary {
            println!("{}", stats.render(arch));
        }
        eprintln!(
            "cortex9-tracer: {matched} events matched, {} dropped in kernel (ring buffer full), {decode_errors} undecodable",
            dropped(&ebpf)
        );
        Ok(())
    }
}
