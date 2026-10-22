# cortex9-ebpf-tracer

[![CI](https://github.com/federiconbaez/cortex9-ebpf-tracer/actions/workflows/ci.yml/badge.svg)](https://github.com/federiconbaez/cortex9-ebpf-tracer/actions/workflows/ci.yml)
![License](https://img.shields.io/badge/license-Apache--2.0-blue)

Tracer de syscalls para Linux escrito en Rust con [aya](https://aya-rs.dev): dos tracepoints `raw_syscalls`, un ring buffer BPF y un CLI con filtros por proceso, comando, syscall, duración y errores.

Linux syscall tracer in Rust built on [aya](https://aya-rs.dev): two `raw_syscalls` tracepoints, a BPF ring buffer and a CLI with process, command, syscall, duration and error filters.

> **ES** primero · **EN** below

---

## Español

### Qué es

```text
 kernel                                         userspace
 ┌──────────────────────────────┐               ┌───────────────────────────────┐
 │ raw_syscalls/sys_enter       │               │ cortex9-tracer                │
 │  filtro PID + nº syscall     │               │  decode (offsets fijos)       │
 │  INFLIGHT[pid_tgid] = args,t │               │  filtro completo              │
 │ raw_syscalls/sys_exit        │  EVENTS       │  texto / JSON lines           │
 │  join + ret + duración ──────┼─ ring buffer ─┼─▶ resumen por syscall         │
 └──────────────────────────────┘               └───────────────────────────────┘
```

| Crate | Qué tiene |
|---|---|
| `cortex9-tracer-common` | `no_std`: layout `#[repr(C)]` del evento (112 bytes), nombres de mapas/programas, offsets de los tracepoints. |
| `cortex9-tracer-ebpf` | Programa eBPF (`bpfel-unknown-none`, nightly + `bpf-linker`). Workspace propio. |
| `cortex9-tracer` | Biblioteca testeable sin root (decode, tablas, filtros, formato, resumen) + binario cargador. |
| `xtask` | `cargo xtask build-ebpf | build | run`. |

### Qué está implementado

- **Hooks**: tracepoints `raw_syscalls/sys_enter` y `raw_syscalls/sys_exit` (ABI estable, `/sys/kernel/tracing/events/raw_syscalls/*/format`). No usa kprobes.
- **Join enter/exit** en un `LruHashMap<u64, InFlight>` por `pid_tgid`: número, 6 argumentos crudos y timestamp; en la salida se agrega `ret`, duración, `comm` y uid real.
- **Ring buffer** (`BPF_MAP_TYPE_RINGBUF`, 1 MiB). Si se llena, el evento se cuenta en `DROPPED` y se informa al salir.
- **Filtros en kernel**: PIDs y números de syscall en hash maps (hasta 1024 cada uno); el propio tracer se excluye. **Filtros en userspace**: además `comm` exacto, duración mínima y `--failed` (ret en `-4095..-1`). El filtro de userspace vuelve a verificar todo, así que es correcto aunque un conjunto no entre en el mapa.
- **Namespaces de PID**: el loader pasa dev/inode de `/proc/self/ns/pid` y el programa usa `bpf_get_ns_current_pid_tgid`, así los PIDs coinciden con los del `/proc` del tracer dentro de un contenedor. Las tareas fuera de ese namespace salen con ids globales marcados con `*` (texto) o `"in_pidns": false` (JSON) y nunca matchean `--pid`.
- **Tablas** de syscalls x86_64 (`asm/unistd_64.h`) y aarch64 (`asm-generic/unistd.h`) y de errno, generadas con `scripts/gen_tables.py`.
- **Salida**: texto alineado (`-a N` imprime N argumentos en hex) o JSON lines; `--summary` agrega cuenta, errores, promedio y máximo por syscall.
- **Corte**: Ctrl-C, SIGTERM, `-t SEGUNDOS` o `-n EVENTOS`.

### Uso

Requisitos para compilar el programa eBPF: Rust nightly con `rust-src` (lo toma `cortex9-tracer-ebpf/rust-toolchain.toml`) y [`bpf-linker`](https://github.com/aya-rs/bpf-linker) en el `PATH`. Para cargarlo: root o `CAP_BPF` + `CAP_PERFMON`, kernel ≥ 5.8 (ring buffer).

```sh
cargo xtask build                     # eBPF + binario con el objeto embebido
sudo target/release/cortex9-tracer -c curl -s openat,connect -a 3
sudo target/release/cortex9-tracer -p 1234 --failed -f json
sudo target/release/cortex9-tracer --min-duration 5ms --summary -q -t 10

# sin privilegios
target/release/cortex9-tracer --list-syscalls
target/release/cortex9-tracer --print-config -p 1,2 -s read,write
```

`cargo build` normal (stable, sin `bpf-linker`) también funciona: el binario busca el objeto en `--object` o en la ruta de build por defecto. Para embeberlo, `CORTEX9_EBPF_OBJ=<ruta> cargo build`.

### Tests y verificación

- 38 tests: 30 unitarios en `cortex9-tracer` (decode, tablas, errno, filtros, formato, resumen, CLI), 3 de layout en `cortex9-tracer-common`, 4 de integración del binario sin root y 1 de carga real (`tests/load.rs`, `#[ignore]`).
- El test de carga lanza el tracer con `-p <pid propio> -s openat --failed`, hace `open()` de una ruta inexistente y verifica 3 eventos con PID, syscall y `ENOENT` correctos.
- Verificado localmente: compilación del objeto eBPF (nightly 1.101, LLVM 23, bpf-linker 0.12.0), carga por el verificador, attach y trazado real con `sudo` en una VM Linux 6.12 x86_64 dentro de un namespace de PID propio (ahí apareció y se corrigió el problema de PIDs globales). El test de carga pasa.
- CI (GitHub Actions): `check` (fmt, clippy `-D warnings`, tests sin root), `ebpf` (nightly + bpf-linker, sube el objeto) y `load` (descarga el objeto y corre el test de carga y un smoke run con `sudo` en el runner). El job `load` depende de que el runner permita cargar BPF; hasta que corra en GitHub no está verificado ahí.

### Limitaciones (honestas)

- Sólo tracepoints `raw_syscalls`; no hay kprobes, fentry ni `syscalls:sys_enter_*` por syscall. Con todo sin filtrar el costo es una entrada por syscall del sistema.
- Los argumentos son registros crudos: no se decodifican strings, structs ni flags (no lee memoria de usuario).
- El filtro por `comm`, duración y `--failed` es en userspace: esos eventos igual pasan por el ring buffer.
- Syscalls que no vuelven (`exit`, `exit_group`) o hilos que mueren entre enter y exit no generan evento; sus entradas en `INFLIGHT` quedan hasta que ese `pid_tgid` vuelve a entrar o el LRU (16384 entradas) las desaloja; con más de 16384 syscalls bloqueadas a la vez se pierden eventos de salida. Un `execve` exitoso sí genera evento, pero con el `comm` del programa nuevo.
- Sólo x86_64 y aarch64 tienen tabla de nombres (en otras arquitecturas se muestran números). La tabla aarch64 sale de `asm-generic` con las macros de arm64 y no se probó en hardware ARM. No se manejan syscalls compat de 32 bits.
- El tiempo es `CLOCK_MONOTONIC` relativo al inicio, no hora de pared.
- El build eBPF usa nightly sin fijar; un nightly con una versión de LLVM que `bpf-linker` no soporte puede romper el job `ebpf`.

### Licencia

Apache-2.0. Ver [LICENSE](LICENSE). El programa eBPF declara licencia `GPL` en su sección `license`, como exige el kernel para los helpers GPL-only que usa (`bpf_probe_read`).

---

## English

### What it is

Two tracepoints in the kernel record each syscall's number, raw arguments and entry time per thread, join them with the return value at exit and push one fixed-size record into a BPF ring buffer. The userspace binary decodes, filters and prints them.

| Crate | Contents |
|---|---|
| `cortex9-tracer-common` | `no_std`: `#[repr(C)]` event layout (112 bytes), map/program names, tracepoint offsets. |
| `cortex9-tracer-ebpf` | eBPF program (`bpfel-unknown-none`, nightly + `bpf-linker`). Own workspace. |
| `cortex9-tracer` | Library testable without root (decode, tables, filters, formatting, summary) + loader binary. |
| `xtask` | `cargo xtask build-ebpf | build | run`. |

### What is implemented

- **Hooks**: `raw_syscalls/sys_enter` and `raw_syscalls/sys_exit` tracepoints (stable ABI). No kprobes.
- **Enter/exit join** in an `LruHashMap<u64, InFlight>` keyed by `pid_tgid`: number, 6 raw arguments and timestamp; at exit, `ret`, duration, `comm` and real uid are added.
- **Ring buffer** (`BPF_MAP_TYPE_RINGBUF`, 1 MiB). When full, the event is counted in `DROPPED`, reported on exit.
- **Kernel filters**: PIDs and syscall numbers in hash maps (up to 1024 each); the tracer excludes itself. **Userspace filters**: also exact `comm`, minimum duration and `--failed` (ret in `-4095..-1`). The userspace filter re-checks everything, so it stays correct when a set does not fit in its map.
- **PID namespaces**: the loader passes dev/inode of `/proc/self/ns/pid` and the program uses `bpf_get_ns_current_pid_tgid`, so PIDs match the tracer's own `/proc` inside a container. Tasks outside that namespace are reported with global ids marked `*` (text) or `"in_pidns": false` (JSON) and never match `--pid`.
- **Tables** for x86_64 (`asm/unistd_64.h`) and aarch64 (`asm-generic/unistd.h`) syscalls and errno, generated by `scripts/gen_tables.py`.
- **Output**: aligned text (`-a N` prints N hex arguments) or JSON lines; `--summary` aggregates count, errors, average and max per syscall.
- **Stop**: Ctrl-C, SIGTERM, `-t SECONDS` or `-n EVENTS`.

### Usage

Building the eBPF program needs Rust nightly with `rust-src` (picked up from `cortex9-tracer-ebpf/rust-toolchain.toml`) and [`bpf-linker`](https://github.com/aya-rs/bpf-linker) on `PATH`. Loading needs root or `CAP_BPF` + `CAP_PERFMON`, kernel ≥ 5.8 (ring buffer).

```sh
cargo xtask build                     # eBPF + binary with the object embedded
sudo target/release/cortex9-tracer -c curl -s openat,connect -a 3
sudo target/release/cortex9-tracer -p 1234 --failed -f json
sudo target/release/cortex9-tracer --min-duration 5ms --summary -q -t 10

# unprivileged
target/release/cortex9-tracer --list-syscalls
target/release/cortex9-tracer --print-config -p 1,2 -s read,write
```

A plain `cargo build` (stable, no `bpf-linker`) also works: the binary then loads the object from `--object` or the default build path. To embed it, `CORTEX9_EBPF_OBJ=<path> cargo build`.

### Tests and verification

- 38 tests: 30 unit tests in `cortex9-tracer` (decode, tables, errno, filters, formatting, summary, CLI), 3 layout tests in `cortex9-tracer-common`, 4 unprivileged binary integration tests and 1 real load test (`tests/load.rs`, `#[ignore]`).
- The load test starts the tracer with `-p <own pid> -s openat --failed`, calls `open()` on a missing path and checks 3 events with the right PID, syscall and `ENOENT`.
- Verified locally: eBPF object build (nightly 1.101, LLVM 23, bpf-linker 0.12.0), verifier load, attach and real tracing with `sudo` on a Linux 6.12 x86_64 VM inside its own PID namespace (which is where the global-PID problem showed up and was fixed). The load test passes.
- CI (GitHub Actions): `check` (fmt, clippy `-D warnings`, unprivileged tests), `ebpf` (nightly + bpf-linker, uploads the object) and `load` (downloads the object, runs the load test and a smoke run with `sudo` on the runner). `load` depends on the runner allowing BPF; it is not verified there until it runs on GitHub.

### Limitations (honest)

- `raw_syscalls` tracepoints only; no kprobes, fentry or per-syscall `syscalls:sys_enter_*`. Unfiltered, the cost is one entry per system-wide syscall.
- Arguments are raw registers: no string, struct or flag decoding (user memory is not read).
- `comm`, duration and `--failed` filtering happens in userspace: those events still go through the ring buffer.
- Syscalls that do not return (`exit`, `exit_group`) or threads that die between enter and exit produce no event; their `INFLIGHT` entries stay until that `pid_tgid` enters again or the LRU (16384 entries) evicts them; with more than 16384 concurrently blocked syscalls, exit events are lost. A successful `execve` does produce an event, with the new program's `comm`.
- Only x86_64 and aarch64 have name tables (other architectures show numbers). The aarch64 table comes from `asm-generic` with the arm64 macros and has not been tested on ARM hardware. 32-bit compat syscalls are not handled.
- Time is `CLOCK_MONOTONIC` relative to start, not wall-clock time.
- The eBPF build uses an unpinned nightly; a nightly whose LLVM version `bpf-linker` does not support can break the `ebpf` job.

### License

Apache-2.0. See [LICENSE](LICENSE). The eBPF program declares `GPL` in its `license` section, as the kernel requires for the GPL-only helpers it uses (`bpf_probe_read`).
