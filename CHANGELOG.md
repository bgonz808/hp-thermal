# Changelog

Notable changes to hp-thermal. Versions follow semver (0.x while pre-1.0).

## [Unreleased]

## [0.3.2-rc.2] - 2026-08-25

Release-candidate cut to exercise two things before a real release depends on them:
the newly hardened build-tool fleet, and the toolchain A/B in #308.

**No binary source changed since 0.3.2-rc.1** — `app/src` and `app/Cargo.toml` are
byte-identical apart from this version bump. Everything below is supply-chain and
CI machinery, which is exactly what makes this a usable control: in the #308
comparison against rc.3, the Rust toolchain is the only variable.

### Security (supply chain)
- **Build tools are now hardened.** All five Windows tools are built with
  `-C control-flow-guard=checks` and `-C link-arg=/DEPENDENTLOADFLAG:0x800`
  (System32-only DLL resolution, which matters most for tools since they execute in
  CI from writable directories). Previously the producer set no flags at all, so
  every tool lacked Control Flow Guard — including `cargo-auditable`, the one tool
  that produces the shipped binary. (#300, #304, #306)
- **Codegen hardening is ratcheted, not merely floored.** Each binary's mitigation
  set is recorded in its capability manifest and enforced exactly: a lost mitigation
  is a regression, a gained one still requires review, and a manifest that declares
  none is unevaluated rather than exempt. A floor cannot notice a mitigation that was
  gained and then lost again. (#299)
- **Every produced binary is capability-gated.** The ELF64 walker closes the last
  gap: `cargo-acl` (linux) previously had no capability manifest and no hardening
  record while the producer's output read as fleet-wide coverage. (#245, #302, #303)
- **The toolchain is pinned by content and declared once.** `tools/TOOLCHAIN.lock`
  commits the channel manifest digest, verified before install — rustup verifies
  components against that manifest but never the manifest itself. It also replaces
  eleven hardcoded channel references, where a partial bump could have silently built
  with a toolchain other than the one declared. (#267, #309)
- **Toolchain vulnerabilities are now watched.** `cargo-audit` reads lockfiles, and
  std/rustc/cargo appear in none, so that axis was blind rather than clean. The
  watcher reads GitHub Security Advisories for `rust-lang/rust`; the RustSec `rust/`
  tree was evaluated and rejected as a source, its newest entry being from 2022-01-16
  and missing CVE-2024-24576 entirely. (#267, #298)
- **Gating tools must prove they still detect.** Negative-control canaries run a
  known-bad fixture through each checker; a checker that reports it clean has failed.
  Detection requires the advisory ID in the tool's own output, because a crashed
  checker is as blind as a sabotaged one and exits the same way. (#223, #297)
- **Advisory posture: 34 instances reduced to 6** across the tool fleet, of which
  four are provably absent from the built binaries and two have no upstream fix in
  any version. (#255, #273)

## [0.3.1] - 2026-08-19

A hardware-report command for contributing verified coverage, service hardening
in the binary, and a supply-chain pass in the release pipeline.

### Added (binary)
- **`--hwinfo` hardware report.** `hp-thermal --hwinfo` (and a matching tray
  **Show hardware fingerprint...** item, same code path) prints your machine's
  fingerprint and runs a capability check: it reads the HP BIOS thermal interface,
  then performs a minimally-invasive write (briefly switch to another mode at
  similar fan noise, confirm the read-back, restore the original) to prove the
  interface is writable, not just present. It reports a verdict (`VERIFIED` /
  `SKEW` / `READ-ONLY` / `UNVERIFIED`) and, on `VERIFIED`, emits the `KNOWN_GOOD`
  line to submit for coverage — unless the hardware is already listed, in which
  case it says so and skips the ask. `--hwinfo --json` gives a machine-readable
  form. See CONTRIBUTING.md. (#149)

### Security (binary)
- **Rate-limited BIOS writes, fail-closed client integrity.** The service throttles
  BIOS thermal writes, and the client-integrity check now fails closed: a caller it
  cannot integrity-verify is refused, not admitted. (#159)
- **Role→mitigation-profile dispatcher.** Each role the single binary serves
  (installer, tray, service, CLI) maps to an explicit process-mitigation profile:
  maximum by default, with narrow documented opt-outs. The mapping is matched
  exhaustively, so an unmapped role is a compile error, not a silent
  under-hardening. (#157)
- **Single-sourced BIOS selectors and token keep-sets.** The HP-BIOS WMI operation
  selectors and the service's privilege keep-sets are each defined once, with CI
  tests guarding them against drift. (#158)

### Supply chain & release integrity (pipeline; no runtime change)
- **BinSkim PE-hardening analysis.** A shared action runs BinSkim against the
  binary: a report-only early-warning on pull requests, and a release-gating scan
  on the signed bytes. Fail-closed: the scan must actually evaluate the target and
  log at least one pass, or the release fails. (#160, #167, #169, #185)
- **Attested, self-describing scan report.** The release BinSkim SARIF records its
  own provenance and is attested, digest-chained from scan to upload; a canonical
  release surfaces its posture on the default branch's Code-scanning tab. (#171,
  #172, #173, #174)
- **Faster, pinned tooling.** The `cargo-*` supply-chain tools are consumed by
  content digest rather than recompiled per release; cargo-deny and cargo-audit
  bumped; verify-artifact now also runs in PR CI. (#156, #145, #170, #175)

## [0.3.0] - 2026-08-18

First signed release. The binary's runtime behavior is unchanged from 0.2.2; what
is new is that the shipped artifact is Authenticode-signed, and the release
pipeline is hardened around producing and verifying that signature.

### Supply chain & release integrity (pipeline)
- **Authenticode signing.** Releases are signed, so a downloaded binary can be
  verified as originating from this project and unmodified since it was built:
  tamper-evidence and authenticity of origin. Signing is keyless via OIDC (no
  long-lived signing secret in CI). Verification is two-pass: the pipeline
  verifies the signature it just produced before publishing; checks the signer by
  raw `WinVerifyTrust` HRESULT against a durable identity OID rather than a
  mutable subject name; derives the trust expectation from the release ref, so a
  dry-run routes to an untrusted test profile and cannot masquerade as production;
  and refuses to sign under debug logging. (#21, #130, #136, #140, #141)
- **Prerelease handling and the reputation gap.** Pre-release tags publish as
  prerelease, never "Latest," and release notes reflect the build's actual signing
  state. A freshly-signed binary has no SmartScreen/AV reputation yet, so a warning
  wall is expected until reputation accrues; that is not a signature failure. (#146)
- **Tag↔binary coupling.** A release refuses to build unless the tag matches the
  version compiled into the binary; `SHA256SUMS` uses stable LF endings. (#147)
- **Prebuilt, digest-pinned tooling.** The four `cargo-*` tools are built once, off
  the release path, and consumed by content digest, so a release never compiles
  unvetted tool code on the hot path. (#138, #142)
- **cargo-vet gate + advisory monitor.** A `cargo-vet` audit gate plus a daily
  RustSec advisory monitor. (#143)
- **Robust manifest embedding.** The application manifest is embedded via the
  linker using a pinned canonical `rc.exe`, dropping the `embed-resource` build
  dependency. (#151)

### Changed (binary)
- KNOWN_GOOD: added BIOS F.26 on the dev ENVY, EC unchanged. (#150)

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

[Unreleased]: https://github.com/bgonz808/hp-thermal/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/bgonz808/hp-thermal/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/bgonz808/hp-thermal/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/bgonz808/hp-thermal/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/bgonz808/hp-thermal/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/bgonz808/hp-thermal/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/bgonz808/hp-thermal/releases/tag/v0.1.0
