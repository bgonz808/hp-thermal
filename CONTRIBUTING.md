# Contributing

Thanks for helping out. The most valuable contribution is **expanding verified hardware
coverage** (below), but fixes and improvements are welcome too.

## Expanding hardware coverage

`KNOWN_GOOD` (in `consent.rs`) lists hardware where the tool has confirmed it can **read and
write the HP BIOS thermal interface**, not just look-alike. To add yours:

1. Install and run the tool on your HP machine (the canonical consent flow).
2. Run `hp-thermal --hwinfo` (or, in the tray, shift-right-click → **Show hardware
   fingerprint...** — same check). It reads the current thermal mode, then does a
   minimally-invasive **write**: briefly switches to a different thermal mode at similar
   fan noise, confirms the read-back, then immediately restores the original, testing that
   the **HP BIOS thermal interface (via WMI)** is readable and writable.
3. If it reports **`VERIFIED`**, open an issue titled `hardware: <model>` and paste the
   `KNOWN_GOOD line` plus the `Verified by:` line (which chains your submission to the exact
   build). `--hwinfo --json` gives a machine-readable form.

The verdict tells you whether to submit:

| Verdict | Read? | Write? | Submit? | Meaning |
|---|:---:|:---:|:---:|---|
| `VERIFIED` | yes | yes | **yes** | Read + write to the HP BIOS thermal interface (WMI) confirmed. |
| `SKEW` | yes | skipped | no | Service is a different build, so the write test is skipped for safety. Reinstall to sync versions, then re-run to verify. |
| `READ-ONLY` | yes | failed | no | The interface reads, but the write test failed: not confirmed writable. |
| `UNVERIFIED` | no | — | no | No read from the interface (service not running, or unsupported hardware). |

Only `VERIFIED` should be submitted: a fingerprint that only *reads* isn't confirmed writable,
and adding it would mislead others.

### What a working toggle sounds like

Changing modes ramps the fan: Performance louder and higher-pitched, Balanced lower and quieter
(well under an octave of shift). You don't need to record or submit anything; `VERIFIED` is the
whole bar. [Hear a Balanced/Performance/Balanced capture](docs/fan-noise-bal-perf-bal.flac); the
same ramp visualized (HP ENVY 16, board 8BE5):

![The fan's harmonic stack ramps up to Performance and back down; time left-to-right, frequency
bottom-to-top, intensity as brightness.](docs/fan-noise-bal-perf-bal.png)

*Example fan-noise spectrogram, transitioning from Balanced to Performance to Balanced.*

## Building from source

This is **not** a normal `cargo install` crate. It rebuilds `std` for a minimal binary, so
it needs a specific nightly toolchain and `rust-src`, both pinned by `rust-toolchain.toml`
(rustup auto-installs them):

```sh
cd app
cargo build --release                          # minimal build (~300 KB)
cargo build --release --features noise-adapt   # with the mic-based Noise Adapt engine
```

- Target: `x86_64-pc-windows-msvc` (Windows only).
- `cargo install hp-thermal` will **not** work — the `build-std` + custom-target setup
  requires building from the repo.

### Build environment pin (MSVC toolset and Windows SDK)

Releases are rebuilt on two runners and must agree byte for byte, so the linker is pinned too.
`.cargo/config.toml` at the repo root sets `VCToolsVersion`, `WindowsSdkDir` and
`WindowsSDKVersion` for every rustc cargo spawns; rustc's MSVC detection honors them, and a
machine without that exact toolset fails to link instead of using another one. Check yours:

```sh
cargo xtask verify-build-env
```

It prints the pinned versus installed toolset, Spectre-mitigated CRT (build.rs links against it,
#385) and SDK and, on a mismatch, the install command. The toolset ships inside Visual Studio
2026 Build Tools; the point build follows the Visual Studio servicing release, so match the
release rather than hunting for a component:

```sh
winget install -e --id Microsoft.VisualStudio.BuildTools -v <release> \
  --override "--passive --wait --norestart --add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 --add Microsoft.VisualStudio.Component.VC.Runtimes.x86.x64.Spectre --add Microsoft.VisualStudio.Component.Windows11SDK.26100"
```

To add a component to an existing instance, use the installer's own `modify`. With `--passive`
it must start elevated (otherwise it exits 5007 without doing anything), so launch it as
administrator from pwsh:

```powershell
Start-Process -Verb RunAs -Wait -FilePath "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\setup.exe" `
  -ArgumentList 'modify','--installPath','"C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools"',
                '--add','Microsoft.VisualStudio.Component.VC.Runtimes.x86.x64.Spectre','--passive','--norestart'
```

It installs per machine, side by side with any Visual Studio 2022, and rustc then prefers the
newest instance for every Rust MSVC build on the machine. When the pin moves (a reviewed change
to `.cargo/config.toml`), `verify-build-env` names what to install.

## Dev tooling

Cross-platform Rust tooling lives in `xtask/`:

```sh
cargo xtask ci --fast                # fmt, clippy -D warnings, tests (the PR + pre-commit tier)
cargo xtask ci                       # + the release-attest tier below
cargo xtask release-attest           # production-artifact checks: cargo-deny, auditable build, audit bin, verify-artifact
cargo xtask verify-hardening <exe>   # check the PE exploit-mitigation flags (CFG/ASLR/DEP)
```

## Versioning

Semver, `0.x` while pre-1.0 (see CHANGELOG.md). The rules that are not obvious from semver alone:

- **Dependency-only change, no observable behaviour change: PATCH.** A security fix in a
  dependency is the canonical patch release; ship it, do not accumulate it.
- **Dependency change with an observable behaviour change** (root-store contents, platform or
  MSRV support, a protocol default): still PATCH in `0.x`, and the CHANGELOG entry names the
  behaviour, not just the crate.
- **MINOR is for the app's own features.** Never for dependencies alone.
- **Release candidates** (`-rc.N`) are the soak window before a tag.
- **Build metadata** (`+…`) records the build (commit), never the version. Tooling ignores it
  for version identity (`xtask explore`).
- A release with byte-identical source and a changed lock is a real release: the embedded
  dependency list (cargo-auditable) and the attestation change, so the version must move.

The same rules bind any automation that is ever allowed to cut a release: a strictly-better
rebuild (dependencies fixed, none added, nothing else changed) is a PATCH bump and nothing
higher, and it carries the certificate that proved it.

## Submitting changes

`main` is protected: no direct pushes. Work on a branch, open a PR, and let the required
checks go green before it merges.

1. Branch from `main`.
2. Run `cargo xtask ci --fast` locally (the pre-commit hook runs it too).
3. Open a PR. The required checks are **CI**, **scan** (security), and **CodeQL** — all must pass.
4. Merge once green.
