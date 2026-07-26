# hp-thermal

**Minimalist HP laptop thermal & performance control. Just that.**

A ~300 KB tray app + Windows service that reproduces the core of HP Command Center's
**System Control → Device Mode** — its thermal/performance/cooling presets
(Performance · Balanced · Cool · Power Saver) and Smart Sense. It accomplishes the same
critical feature of the heavyweight HP Command Center collateral without eating your
RAM or disk space.

> ⚠️ **Supported hardware.** This talks to an **undocumented HP BIOS-WMI interface** that
> is *not* a stable or public API. It was reverse-engineered and validated on an
> **HP ENVY 16 (board `8BE5`, BIOS F.25)**. On any other HP model it will detect the
> difference and ask for explicit, remembered consent before doing anything — thermal
> control may not work or may behave differently on untested hardware. Non-HP machines
> are refused outright — before any elevation, install, or system change. See
> [Hardware support](#hardware-support).

## Install

Download and run `hp-thermal.exe`. With your consent, it installs the background service
(one-time elevated UAC prompt) and starts the service and tray. SYSTEM service handles
the privileged BIOS/WMI operations, talking over a hardened local named pipe. The tray
client is reduced privilege, and handles the settings menu. See [SECURITY.md](SECURITY.md).

Every release is cryptographically verifiable (SLSA provenance + SBOM). To check a download
before running it, see [Verifying a release](SECURITY.md#verifying-a-release).
I am working towards Authenticode signing so SmartScreen and UAC don't look scary to new users.

Is easily uninstallable via **Settings → Apps** or `hp-thermal uninstall`

- **`C:\Program Files\HpThermal\hp-thermal.exe`** — the binary (admin-only-writable)
- **Windows service `HpThermalService`** — runs as SYSTEM, makes the BIOS/WMI calls,
  auto-starts at boot
- **`C:\ProgramData\HpThermal\`** — logs and the hardware-consent record (Users-writable)
- **Auto-start** — `HKLM\...\CurrentVersion\Run\HpThermal`, so the tray starts at logon
- **Apps entry** — `HKLM\...\CurrentVersion\Uninstall\HpThermal`, listing it in Settings → Apps
- **Start Menu** — `%ProgramData%\Microsoft\Windows\Start Menu\Programs\HP Thermal Control.lnk`

## What it does

- **Thermal modes** — Performance / Balanced / Cool / Power Saver, from the tray menu.
- **Smart Sense** — HP's adaptive CoolSense toggle. I don't use it, tbh.
- **Fn+F12** — screen on/off (and optional sleep), since the "three-diamonds" key does
  nothing without HP's software. Also minimum brightness in Windows is not **fully** dim.
- **Optional, experimental: Noise Adapt** (`--features noise-adapt`) — One-shot mic-based
  calibration checks environment vs fan noise levels. If Performance mode is perceptibly
  louder than Balanced, choose Balanced, else environment too loud to notice fans anyway,
  just use Performance.

**Scope.** NOT a full replacement for HPCC. Just what I care about, frustration-free
laptop thermals and performance. I might consider enhancements, if it achieves simplicity,
performance, convenience, and maybe more debloating?

## Measured footprint vs HP Command Center

**Idle cost: zero, and measured.** Both halves are event-driven, not polling.

Memory and disk measured on the tested HP ENVY 16 (`8BE5`), Windows 11,
against **HP Command Center `AD2F1837.HPThermalControl` v1.11.60.0**; reproducible with
[`scripts/measure-footprint-vs-hpcc.ps1`](scripts/measure-footprint-vs-hpcc.ps1) (run
elevated).

| Metric | HP Command Center | hp-thermal | Ratio |
| --- | ---: | ---: | ---: |
| Install on disk | 170 MB | **0.3 MB** | **~580×** |
| Private working set (Windows `Working Set - Private`) | 140 MB | **3 MB** | **~40×** |
| Commit (private bytes; committed, may be paged out) | 270 MB | **4 MB** | **~60×** |
| CPU cycles/s, at idle | 3M to 6M (continuous) | **0** | **∞** |
| CPU percentage, at idle | 0.1 to 0.2% (continuous) | **0%** | **∞** |
| Startup time | 11.5 seconds | **<0.30s** | **>>30×** |
| I/O usage, at idle | none | none | no change |

**Notes on the numbers:**

- Tested on a fairly powerful HP laptop: Intel i9-13900H, NVIDIA RTX 4060, Performance profile,
  NVMe SSD, DDR5 SODIMM, on AC power
- Power profile had no impact on HP Command Center startup time, equally slow to start whether
  Balanced or Performance
- Startup too fast to measure with a stopwatch on the Rust app (iykyk)
- The 0.3 MB is self-contained: the C runtime is statically linked, so it needs no Visual C++
  redistributable and just runs on any supported Windows

## Hardware support

| Tier | Behavior |
| --- | --- |
| **HP ENVY 16 (`8BE5`, tested)** | Full functionality, no prompt |
| **Other HP models** | Runs after a one-time, remembered consent prompt (thermal control is community-untested on your board) |
| **Non-HP** | Refused |

Because the underlying interface is undocumented and can change across firmware, the
consent is keyed to your exact board + BIOS + EC version. A firmware update re-asks.
Help expand support: see [Contributing](#contributing).

## Security

Security is a first-class goal — a hardened IPC threat model, exploit-mitigated binary
(CFG + stack canaries + ASLR/DEP), and a fully-scanned, attested dependency surface. The
full posture and threat model are in **[SECURITY.md](SECURITY.md)**. Report vulnerabilities
via GitHub Security Advisories.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for building from source, the dev tooling, and how to
submit changes. Expanding verified hardware coverage is especially welcome.

## License

MIT © bgonz808. Not affiliated with or endorsed by HP.
