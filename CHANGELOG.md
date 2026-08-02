# Changelog

Notable changes to hp-thermal. Versions follow semver (0.x while pre-1.0).

## [Unreleased]

## [0.2.2] - 2026-08-02

Proactive hardening and cleanup. No user-facing behavior change.

### Security
- **DLL search-order hardening.** `rstrtmgr` and `powrprof` are now delay-loaded: their non-KnownDLL dependencies (`ncrypt`, `umpdc`/`wmiclnt`) resolve from `System32` rather than the run directory, closing a DLL-planting path when the binary runs from a writable folder. Loading only on use also sharpens the single binary's roles, so the installer, tray, and service each pull only the DLLs they need. They stay *declared* imports; CI gates lock the surface (import-closure walk, plant test, exact-match allowlist). See SECURITY.md. [T1574.001](https://attack.mitre.org/techniques/T1574/001/)/[.002](https://attack.mitre.org/techniques/T1574/002/).
- **Deterministic build timestamp.** The PE `TimeDateStamp` pins to the commit date instead of the `/Brepro` content-hash, which decoded to a random year. This drops a timestomp heuristic with no effect on reproducibility, and a CI gate rejects an implausible timestamp. [T1070.006](https://attack.mitre.org/techniques/T1070/006/).

## [0.2.1] - 2026-07-31

Release-gate fix over 0.2.0 (which was tagged but never published). No user-facing behavior change.

### Security
- **The Windows Error Reporting opt-out writes its registry exclusion directly** now, dropping the `wer.dll` import so the shipped binary's golden import allowlist stays minimal (13 DLLs). The exclusion value is byte-identical to the WER API's own write, so the no-crash-dump-egress guarantee is unchanged.

## [0.2.0] - 2026-07-31

Core features the same. The privileged service process gained least-privilege and injection-contained enhancements, logging and hardware consent are file-less, and interactions are faster and more robust thanks to idempotency and splitting UI from event handling.

### Security
- **Least privilege.** The SYSTEM service runs on a write-restricted token (`SERVICE_SID_TYPE_RESTRICTED`, Windows Service Hardening L2/L3): even as LocalSystem it writes only where its own service identity is granted, so process stays confined under any circumstance. Backed by a per-service SID and a runtime self-assertion that drops every privilege the service doesn't use.
- **No child-process creation.** The service and the tray processes both refuse to launch other programs (`ProcessChildProcessPolicy`); the tray also stays at Medium integrity, refuses to run elevated, and sheds its unused privileges. The shell-out menu openers were removed so the tray needs no such capability.
- **No dynamic code, no legacy syscalls.** The service process enforces `ProcessDynamicCodePolicy` (no runtime-generated or modified executable memory — [CWE-94](https://cwe.mitre.org/data/definitions/94.html)) and disables win32k system calls, cutting a large kernel attack surface. The tray process relies on UI features and needs win32k, but is already a lower privilege process.
- **Hardened IPC.** The local named pipe rejects remote clients and enforces a kernel-level integrity check on callers; COM is locked down and service-side impersonation dropped, closing off remote RPC/COM access.
- **File-less logging and tracing.** Logging moved to the Windows Event Log with per-role, severity-tagged sources, plus per-message tracing (strictly) on demand over ETW — retiring the on-disk log ([CWE-59](https://cwe.mitre.org/data/definitions/59.html), [CWE-732](https://cwe.mitre.org/data/definitions/732.html)) and giving a standard, queryable surface. Read with `Get-WinEvent -ProviderName HpThermal-Service`.
- **No crash-dump egress.** The installed binaries opt out of Windows Error Reporting, so strictly no network.

### Changed
- **File-less consent.** Your hardware acknowledgement now lives in `HKCU` rather than a shared config file ([CWE-732](https://cwe.mitre.org/data/definitions/732.html)). Consent to run on your hardware is checked per Windows user. (As always, if not an HP, it will warn and exit.)
- **The menu opens instantly.** Likely unnoticeably faster, but profile state requested upon icon hover, awaiting the menu open. Also a single round trip now fetches thermal + Smart Sense together.

### Fixed
- **Fn+F12 sleep hotkey more robust.** Blanking the screen no longer freezes the tray. Rapid presses are debounced. Rapid presses no longer queue, and drained upon wake anyways, to avoid waking from sleep just to go back to sleep.
- **Fn+F12 listener isolated from the control path.** Listening for the Fn+F12 hardware event now uses its own dedicated WMI interface, separate from the one that sets and reads profiles — so it can't add latency to a profile change.
- **Installer UI/UX.** Cancelling the update dialog now exits immediately.

### Removed
- The shell-out menu items — logs are read via the Event Log now, so they're no longer needed. This was required to enable the `ProcessChildProcessPolicy`.

### Supply chain & release integrity
- **Stronger artifact verification.** `verify-artifact` enforces an import allowlist, flags high-risk APIs, and binds the exe to its PDB by CodeView GUID; a digest-chained job gates the release, and the PDB sidecar is reproducible.

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

[Unreleased]: https://github.com/bgonz808/hp-thermal/compare/v0.2.2...HEAD
[0.2.2]: https://github.com/bgonz808/hp-thermal/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/bgonz808/hp-thermal/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/bgonz808/hp-thermal/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/bgonz808/hp-thermal/releases/tag/v0.1.0
