# Changelog

Notable changes to hp-thermal. Versions follow semver (0.x while pre-1.0).

## [Unreleased]

## [0.1.0] - 2026-07-26

First tagged release.

### Added
- HP thermal / performance mode control (Performance · Balanced · Cool · Power Saver)
  and Smart Sense, via a tray app + SYSTEM service over a hardened local named pipe.
- Optional mic-based Noise Adapt engine behind `--features noise-adapt`.
- Fn+F12 screen on/off.
- Consent gate for untested HP hardware, fingerprinted by board + BIOS + EC so a
  firmware update re-asks.
- Hardened binary: Control Flow Guard, stack canaries, ASLR/DEP; ~300 KB minimal
  (statically linked C runtime — no Visual C++ redistributable needed).
- SYSTEM service verifies at startup that it runs from the write-restricted install
  directory at system integrity, and refuses to operate otherwise.
- Uninstall from **Windows Settings → Apps** (Add/Remove Programs entry), in addition to
  `hp-thermal uninstall`.
- Launch from the **Start Menu** (all-users shortcut), created at install and removed at
  uninstall.
- The NVIDIA GPU library (NVML) loads only while its menu row is shown and unloads when
  idle, so it doesn't sit in memory.

### Supply chain & release integrity
- **Verifiable releases**: every artifact carries a SLSA build-provenance attestation
  and a CycloneDX SBOM attestation, verifiable with `gh attestation verify` — online, or
  fully offline against the `*.sigstore.jsonl` bundles attached to the release.
- **Fail-closed self-verification**: the release pipeline verifies its own attestations,
  identity-pinned to the release workflow, *before* publishing anything.
- **Source integrity**: `main` requires green CI + security scans (PR-only, no admin
  bypass), release tags are immutable, and a release only builds from a CI-green commit.
- **Attested dependencies**: cargo-auditable release builds, cargo-deny + cargo-audit +
  osv-scanner + Dependabot, committed Cargo.lock with per-crate checksums.
- **Reproducible**: build timestamp derives from the commit (`SOURCE_DATE_EPOCH`), so the
  same tag rebuilds to the same bytes.

[Unreleased]: https://github.com/bgonz808/hp-thermal/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/bgonz808/hp-thermal/releases/tag/v0.1.0
