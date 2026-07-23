# hp-thermal

**HP laptop thermal & performance control — without the 169 MB.**

A ~200 KB tray app + Windows service that switches HP's thermal/performance modes
(Performance · Balanced · Cool · Power Saver) and Smart Sense, replacing HP Command
Center (169 MB on disk, slow-launching, always-on background service) for the core of
what it's used for.

> ⚠️ **Supported hardware.** This talks to an **undocumented HP BIOS-WMI interface** that
> is *not* a stable or public API. It was reverse-engineered and validated on an
> **HP ENVY 16 (board `8BE5`, BIOS F.25)**. On any other HP model it will detect the
> difference and ask for explicit, remembered consent before doing anything — thermal
> control may not work or may behave differently on untested hardware. Non-HP machines
> are refused outright — before any elevation, install, or system change. See
> [Hardware support](#hardware-support).

## What it does

- **Thermal modes** — Performance / Balanced / Cool / Power Saver, from the tray menu.
- **Smart Sense** — HP's adaptive CoolSense toggle.
- **Fn+F12** — screen on/off (and optional sleep), since the "three-diamonds" key does
  nothing without HP's software.
- **Optional, experimental: Noise Adapt** (`--features noise-adapt`) — mic-based fan-noise
  measurement that picks a mode by how audible the fans are in your room. Off by default,
  and experimental.

It is a single `hp-thermal.exe`: the tray runs as your user, and a tiny Windows service
runs as SYSTEM and performs the privileged BIOS/WMI calls, talking over a hardened local
named pipe. See [SECURITY.md](SECURITY.md).

**Idle cost: zero, and measured.** Both halves are event-driven, not polling: at rest
**the tray and the service execute 0 CPU cycles** (verified with `QueryProcessCycleTime`
over repeated 20–30 s idle windows). The tray blocks in its message loop; the service waits
on a **push-based WMI event sink** for the Fn+F12 hotkey, so it wakes only when the key is
pressed — where the earlier poll-based build spent ~209k cycles/s.

## Measured footprint vs HP Command Center

Measured on the tested HP ENVY 16 (`8BE5`), Windows 11, on **2026-07-22**, against **HP
Command Center `AD2F1837.HPThermalControl` v1.11.60.0**. All runtime numbers come from a
single 30 s idle window (`QueryProcessCycleTime` + `Process(*)` performance counters), so
memory and CPU are internally consistent. Reproduce them yourself (run elevated):
[`scripts/measure-footprint-vs-hpcc.ps1`](scripts/measure-footprint-vs-hpcc.ps1).

| Metric (idle) | HP Command Center | hp-thermal | Ratio |
| --- | ---: | ---: | ---: |
| Install on disk | 168 MB | **0.19 MB** | ~885× |
| Persistent processes | 3 | 2 | — |
| **Private working set** (private resident; Win `Working Set - Private` ≈ Linux USS) | 141 MB | **3.2 MB** | **~44×** |
| Commit (private bytes; committed, may be paged out) | 266 MB | 4.2 MB | ~63× |
| CPU cycles/s | ~3–6 M (continuous) | **0** | ∞ |

**Notes on the numbers:**
- **Private working set is the metric to compare on** — it counts only pages unique to the process
  (Windows `Working Set - Private` ≈ Linux **USS**), so unlike raw RSS it doesn't
  double-count the shared system DLLs every process maps. Ours is **1.6 MB per process**;
  HP's mostly-private .NET/UWP heaps hold **~44× more**.
- **CPU:** `% Processor Time` sits below its own counter resolution at idle for both; the
  cycle counter is the sensitive metric. HP's `HpSystemManagement` daemon burns millions of
  cycles/s *continuously* (~0.1–0.2 % of one core); ours is a hard **0** — the event-driven
  design means the scheduler never wakes us.
- **Scope:** this compares the Command Center package only. HP's broader stack (its analytics
  service + HSA/display services, separate packages) adds roughly another 440 MB RSS at idle,
  which this tool does not touch and does not replace.

## Install

Download the release `hp-thermal.exe` and run it. It installs the background service
(one-time UAC prompt) and starts the tray. `hp-thermal uninstall` removes it cleanly.

```
hp-thermal              Launch the tray (installs the service if needed)
hp-thermal install      Install and start the background service
hp-thermal uninstall    Stop and remove the service
hp-thermal start|stop   Start / stop the service
hp-thermal --version    Version + build id
```

## Hardware support

| Tier | Behavior |
| --- | --- |
| **HP ENVY 16 (`8BE5`, tested)** | Full functionality, no prompt |
| **Other HP models** | Runs after a one-time, remembered consent prompt (thermal control is community-untested on your board) |
| **Non-HP** | Refused |

Because the underlying interface is undocumented and can change across firmware, the
consent is keyed to your exact board + BIOS + EC version — a firmware update re-asks.
Help expand support: see [Contributing](#contributing).

## Building from source

This is **not** a normal `cargo install` crate — it rebuilds `std` for a minimal binary,
so it needs a specific nightly toolchain and `rust-src`:

```sh
# toolchain is pinned by rust-toolchain.toml (nightly + rust-src) — rustup auto-installs it
cd app
cargo build --release                      # minimal build (~200 KB)
cargo build --release --features noise-adapt   # with the mic-based Noise Adapt engine
```

- Target: `x86_64-pc-windows-msvc` (Windows only).
- `cargo install hp-thermal` will **not** work — the `build-std` + custom-target setup
  requires building from the repo.

### Dev tooling

Cross-platform Rust tooling lives in `xtask/`:

```sh
cargo xtask ci --fast          # fmt, clippy -D warnings, tests — the PR + pre-commit tier
cargo xtask ci                 # + cargo-deny, cargo-auditable build, audit bin, verify-hardening
cargo xtask verify-hardening <exe>   # check the PE exploit-mitigation flags (CFG/ASLR/DEP)
```

## Security

Security is a first-class goal — a hardened IPC threat model, exploit-mitigated binary
(CFG + stack canaries + ASLR/DEP), and a fully-scanned, attested dependency surface. The
full posture and threat model are in **[SECURITY.md](SECURITY.md)**. Report vulnerabilities
via GitHub Security Advisories.

## Contributing

Expanding verified hardware coverage is especially welcome. If you run an HP model other
than the tested one, the planned **`hp-thermal export-info`** command (and a matching tray
menu item) will export a hardware/capability report you can attach to an issue — helping map
which models this interface actually supports.

## License

MIT © bgonz808. Not affiliated with or endorsed by HP.
