# Changelog

Notable changes to hp-thermal. Versions follow semver (0.x while pre-1.0).

## [Unreleased]

### Added
- HP thermal / performance mode control (Performance · Balanced · Cool · Power Saver)
  and Smart Sense, via a tray app + SYSTEM service over a hardened local named pipe.
- Optional mic-based Noise Adapt engine behind `--features noise-adapt`.
- Fn+F12 screen on/off.
- Consent gate for untested HP hardware, fingerprinted by board + BIOS + EC so a
  firmware update re-asks.
- Hardened binary: Control Flow Guard, stack canaries, ASLR/DEP; ~180 KB minimal.
- Attested dependencies: cargo-auditable release builds, cargo-deny + cargo-audit +
  Dependabot scanning, committed Cargo.lock with per-crate checksums.
