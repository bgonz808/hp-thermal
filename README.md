# hp-thermal

**HP laptop thermal & performance control — without the 169 MB.**

A ~180 KB tray app + Windows service that switches HP's thermal/performance modes
(Performance · Balanced · Cool · Power Saver) and Smart Sense, replacing HP Command
Center (169 MB install, 10 s+ launch, always-on background service) for the one thing
most people actually open it for.

> ⚠️ **Supported hardware.** This talks to an **undocumented HP BIOS-WMI interface** that
> is *not* a stable or public API. It was reverse-engineered and validated on an
> **HP ENVY 16 (board `8BE5`, BIOS F.25)**. On any other HP model it will detect the
> difference and ask for explicit, remembered consent before doing anything — thermal
> control may not work or may behave differently on untested hardware. Non-HP machines
> are refused. See [Hardware support](#hardware-support).

## What it does

- **Thermal modes** — Performance / Balanced / Cool / Power Saver, from the tray menu.
- **Smart Sense** — HP's adaptive CoolSense toggle.
- **Fn+F12** — screen on/off (and optional sleep), since the "three-diamonds" key does
  nothing without HP's software.
- **Optional: Noise Adapt** (`--features noise-adapt`) — mic-based fan-noise measurement
  that picks a mode by how audible the fans are in your room. Off by default.

It is a single `hp-thermal.exe`: the tray runs as your user, and a tiny Windows service
runs as SYSTEM and performs the privileged BIOS/WMI calls, talking over a hardened local
named pipe. See [SECURITY.md](SECURITY.md).

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
cargo build --release                      # minimal build (~180 KB)
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
