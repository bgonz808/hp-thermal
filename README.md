# hp-thermal

**Thermal & performance control for HP laptops — a tiny tray app + Windows service.**

A single ~200 KB binary with the same core functionality as HP Command Center's 169 MB
package. **System Control → Device Mode** picks a performance profile that matches your
thermal, noise, and performance requirements.

> ⚠️ **Supported hardware.** This talks to an **undocumented HP BIOS-WMI interface** that
> is *not* a stable or public API. It was reverse-engineered from C# and validated on an
> **HP ENVY 16 (board `8BE5`, BIOS F.25)**. On any other HP model it will detect the
> difference and ask for explicit, remembered consent before doing anything. Thermal
> control may not work or may behave differently on untested hardware. Non-HP machines
> are refused outright before any elevation, install, or system change. See
> [Hardware support](#hardware-support).

## What it does

- **Thermal modes** — Performance / Balanced / Cool / Power Saver, from the tray menu.
- **Smart Sense** — HP's adaptive CoolSense toggle.
- **Fn+F12** — screen on/off (and optional sleep), since the "three-diamonds" key does
  nothing without HP's software.
- **Optional, experimental: Noise Adapt** (`--features noise-adapt`) — an acoustically
  informed read on whether you'd even hear the fans in Performance mode versus Balanced
  (quieter, but slower, and possibly hotter depending on workload or environment).

**Scope.** HP describes that page as adjusting "the performance, temperature, and cooling
preferences for your PC along with settings for Smart Sense and Focus Mode." hp-thermal
covers the thermal/cooling presets and Smart Sense — **not** Focus Mode, and not HP CC's
other pages (camera privacy, Network Booster, display controls, etc.). It neither replaces
nor disables those; they aren't thermal control. The Fn+F12 remap is a small extra of ours,
not part of HP's System Control, because on some machines 0% brightness in Windows still
isn't fully dark.

It is a single `hp-thermal.exe`: the tray runs as your user, and a tiny Windows service
runs as SYSTEM and performs the privileged BIOS/WMI calls, talking over a hardened local
named pipe. See [SECURITY.md](SECURITY.md).

**Idle cost: zero, and measured.** Both halves are event-driven, not polling. Over a 5-minute
audit, **the service and the tray each recorded 0 CPU cycles**. The tray blocks in its message
loop; the service waits on a **push-based WMI event sink** for the Fn+F12 hotkey, filtered
`WHERE EventId = 29` server-side, so an HP BIOS heartbeat never wakes the process. Compare
that to HP Command Center's continuously-active daemon, which does more than thermal
management.

## Measured footprint vs HP Command Center

Memory and disk measured on the tested HP ENVY 16 (`8BE5`), Windows 11, on **2026-07-22**,
against **HP Command Center `AD2F1837.HPThermalControl` v1.11.60.0** — from a single 30 s
idle window (`QueryProcessCycleTime` + `Process(*)` counters), reproducible with
[`scripts/measure-footprint-vs-hpcc.ps1`](scripts/measure-footprint-vs-hpcc.ps1) (run
elevated). Our idle-CPU **0** was verified separately (2026-07-24) with a dedicated
per-second cycle probe — separate by necessity; see the CPU note.

| Metric (idle) | HP Command Center | hp-thermal | Ratio |
| --- | ---: | ---: | ---: |
| Install on disk | 168 MB | **0.19 MB** | ~885× |
| Persistent processes | 3 | 2 | — |
| **Private working set** (private resident; Win `Working Set - Private` ≈ Linux USS) | 141 MB | **3.2 MB** | **~44×** |
| Commit (private bytes; committed, may be paged out) | 266 MB | 4.2 MB | ~63× |
| CPU cycles/s (idle) | ~3–6 M (continuous) | **0** † | ∞ |

**Notes on the numbers:**
- **Private working set is the metric to compare on** — it counts only pages unique to the process
  (Windows `Working Set - Private` ≈ Linux **USS**), so unlike raw RSS it doesn't
  double-count the shared system DLLs every process maps. Ours is **1.6 MB per process**;
  HP's mostly-private .NET/UWP heaps hold **~44× more**.
- **CPU (the † above):** at idle `% Processor Time` is below its counter resolution for both,
  so cycles are the sensitive metric. HP's `HpSystemManagement` daemon burns millions of
  cycles/s *continuously* (~0.1–0.2 % of one core). Ours is a literal **0** — over 5-minute
  per-second probes the service and tray each recorded 0 cycles in **300/300** one-second
  bins. The service gets there because its WMI subscription filters `WHERE EventId = 29`
  server-side, so WMI drops the BIOS provider's ~2 s heartbeat before it reaches our process.
  The footprint script itself *can't* show this: its own WMI enumeration perturbs our
  WMI-adjacent service to a few tens of thousands of cycles/s in-window — an observer effect,
  not real idle cost — which is why the true 0 comes from a clean, no-WMI probe.
- **Broader HP stack:** this compares the Command Center package only. HP's wider install (its
  analytics service + HSA/display services, separate packages) adds roughly another 440 MB
  RSS at idle, which this tool does not touch or replace.

## Install

Download the release `hp-thermal.exe` and run it. It installs the background service
(one-time UAC prompt) and starts the tray. `hp-thermal uninstall` stops and removes the
service, run it from a copy **outside** `C:\Program Files\HpThermal\` so it can delete the
installed files (Windows locks a running executable).

```
hp-thermal              Launch the tray (installs the service if needed)
hp-thermal install      Install and start the background service
hp-thermal uninstall    Stop and remove the service
hp-thermal start|stop   Start / stop the service
hp-thermal --version    Version + build id
```

## Verifying your download

Every release is built by a public GitHub Actions workflow and carries cryptographic
**build provenance** (SLSA) and an **SBOM** attestation, so you can prove the `.exe` was
built from this repo's source by that workflow and not tampered with in transit.

With the [GitHub CLI](https://cli.github.com), pinning the signer to this repo's release
workflow (the identity check is what makes verification meaningful):

```sh
gh attestation verify hp-thermal.exe \
  --repo bgonz808/hp-thermal \
  --signer-workflow bgonz808/hp-thermal/.github/workflows/release.yml
```

**Offline / air-gapped.** `gh` normally fetches the Sigstore trust root over the network,
so fetch the trust material *once* from a machine you trust, then verify with no network:

```sh
# on a trusted, networked machine — one time
gh attestation trusted-root > trusted_root.jsonl
gh attestation download hp-thermal.exe --repo bgonz808/hp-thermal   # writes the bundle

# on the air-gapped machine — no network
gh attestation verify hp-thermal.exe \
  --bundle <downloaded-bundle>.jsonl \
  --custom-trusted-root trusted_root.jsonl \
  --repo bgonz808/hp-thermal \
  --signer-workflow bgonz808/hp-thermal/.github/workflows/release.yml
```

The trust root comes from *your* `gh`, not from this release — an independent anchor, which
is what makes offline verification meaningful (a root shipped alongside the artifact it
vouches for proves nothing).

`SHA256SUMS` is also attached as a low-tech convenience, but a bare checksum only proves the
file matches *that* file — the attestation is the real anchor: it proves the file came from
*us*.

> Not yet Authenticode-signed, so Windows still shows "Publisher: Unknown" on the UAC
> prompt. Publisher signing is planned; until then, the attestation above is the
> cryptographic proof of origin.

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

Security is a first-class goal. I use a hardened IPC threat model, exploit-mitigated binary
(CFG + stack canaries + ASLR/DEP), and a fully-scanned, attested dependency surface. Dependencies
are as minimal as can be, with digest pinning for rust crates and GHA. The full posture and threat
model are in **[SECURITY.md](SECURITY.md)**.

Report vulnerabilities via GitHub Security Advisories.

## Contributing

Expanding verified hardware coverage is especially welcome. If you run an HP model other
than the tested one, the planned **`hp-thermal export-info`** command (and a matching tray
menu item) will export a hardware/capability report you can attach to an issue — helping map
which models this interface actually supports.

## License

MIT © bgonz808. Not affiliated with or endorsed by HP.
