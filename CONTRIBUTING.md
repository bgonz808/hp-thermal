# Contributing

Thanks for helping out. The most valuable contribution is **expanding verified hardware
coverage** (see the end of this file), but fixes and improvements are welcome too.

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

## Dev tooling

Cross-platform Rust tooling lives in `xtask/`:

```sh
cargo xtask ci --fast                # fmt, clippy -D warnings, tests (the PR + pre-commit tier)
cargo xtask ci                       # + cargo-deny, cargo-auditable build, audit bin, verify-hardening
cargo xtask verify-hardening <exe>   # check the PE exploit-mitigation flags (CFG/ASLR/DEP)
```

## Submitting changes

`main` is protected: no direct pushes. Work on a branch, open a PR, and let the required
checks go green before it merges.

1. Branch from `main`.
2. Run `cargo xtask ci --fast` locally (the pre-commit hook runs it too).
3. Open a PR. The required checks are **CI**, **scan** (security), and **CodeQL** — all must pass.
4. Merge once green.

## Expanding hardware coverage

Especially welcome. `KNOWN_GOOD` (in `consent.rs`) lists hardware where the tool has confirmed
it can **read and write the HP BIOS thermal interface**, not just look-alike. To add yours:

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
