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

Especially welcome. If you run an HP model other than the tested one, the planned
**`hp-thermal export-info`** command (and a matching tray menu item) will export a
hardware/capability report you can attach to an issue, helping map which models this
interface actually supports.
