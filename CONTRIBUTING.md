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

Especially welcome. `KNOWN_GOOD` (in `consent.rs`) lists hardware where thermal control is
**confirmed working** — not just look-alike. To add yours:

1. Install and run the tool on your HP machine (the canonical consent flow).
2. Run `hp-thermal --hwinfo`. It runs the capability ladder — a thermal **read**, then a
   minimally-invasive **write** that nudges the mode one step and immediately restores it — to
   prove the tool actually *controls* your hardware, not just that the interface answers.
3. If it reports **`VERIFIED`**, open an issue titled `hardware: <model>` and paste the
   `KNOWN_GOOD line` plus the `Verified by:` line (which chains your submission to the exact
   build that proved it). `--hwinfo --json` gives a machine-readable form.

Only `VERIFIED` (write-proven) hardware should be submitted: a fingerprint that only *reads*
isn't confirmed controllable, and adding it would mislead other users. If `--hwinfo` reports
`READ-ONLY` or `UNVERIFIED`, please don't submit it.
