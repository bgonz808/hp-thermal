# Changelog

Notable changes to hp-thermal. Versions follow semver (0.x while pre-1.0).

## [Unreleased]

## [0.3.2] - 2026-11-12

Patch release: the binary's runtime behaviour is unchanged since 0.3.2-rc.2; the shipped
bytes change through a toolchain adoption and a linked-CRT hardening, and the pipeline that
produces them is substantially stronger. `-rc.3` (2026-08-30) was the first candidate built by
the pinned-toolchain tool fleet; everything below landed after it.

**What changed in the app crate since 0.3.1, exactly:** `build.rs` (the Spectre-mitigated CRT
lookup), `Cargo.toml` (`find-msvc-tools` as a build dependency; version), `rust-toolchain.toml`
(nightly-2026-10-09), `.cargo/config.toml` (rustflags single-sourced), test-only changes in
`capability.rs` (a probe lock for parallel tests), `install.rs` and `tray.rs` (delay-load
resolution tests), and the cargo-vet import files. No runtime logic changed; the diff of
`app/src` outside `#[cfg(test)]` is empty. Everything else in this release is dependency and
tool-fleet maintenance and GitHub Actions pipeline work.

### Security (binary)
- **Spectre-mitigated C runtime.** The release links the MSVC `lib/spectre` CRT, discovered
  through the same `find-msvc-tools` lookup rustc uses for `link.exe`; a toolset without it is
  a build failure, never a silent fall-back to the unmitigated CRT. The BinSkim release gate
  independently checks the linked result (BA2024), and now counts SARIF results that carry no
  `kind`/`level` by applying the SARIF 2.1.0 defaults — BA2024 had read as nothing since
  2026-08-17. (#385, #392, #393)
- **Toolchain nightly-2026-10-09 adopted** after an A/B of every instrument on the candidate
  (caps, vuln, VT, BinSkim, verify-artifact): the fleet and the app move together, six tools
  blessed with zero sign-offs. Still pinned by content in `tools/TOOLCHAIN.lock`. (#308, #384)

### Supply chain & release integrity (pipeline; no runtime change)
- **Binary-vantage scans have a precondition.** `verify-auditable` refuses a binary without a
  `.dep-v0` section before `cargo audit bin` runs — on its own that scan recovers a partial
  dependency list from panic strings and exits 0, so a missing section read as cleaner. Gates
  release-attest and the Windows producer; the SBOM and `SHA256SUMS` are attestation subjects.
  (#386, #399)
- **The tool fleet is auditable, stamped and idempotent.** All seven blessed tool digests are
  built through cargo-auditable (a Linux cargo-auditable joins the fleet); Windows tools link
  with `/Brepro` and have every PE timestamp stamped to the pinned upstream rev's commit epoch,
  verified exactly (`verify-timestamp --expect`). Three consecutive producer runs reproduced all
  seven digests byte for byte. (#386, #401, #402, #403, #406, #407)
- **rustix 1.1.6 across the fleet** (RUSTSEC-2026-0486, unsound) via `xtask freeze
  --require-improvement` atop each frozen lock — fixed, not acknowledged; cargo-auditable's
  first frozen lock. (#404)
- **Capabilities measured as built, sandboxed.** cackle runs with Bubblewrap on ubuntu-26.04
  and with the producer's own build flags and a release-inheriting profile, so inventories
  describe the shipped package and record every `cargo:` directive a build script emits
  (31 directives on the fleet, all self-referential). A measured strict subset of the prior
  blessed inventory passes without a fresh signature; anything else needs one. (#50, #367,
  #381, #387, #388, #390, #391)
- **Absolute floors.** `supply-chain/policy/floors.json` names the states no sign-off admits:
  a critical-shape CVSS vector, a malware panel with too many malicious verdicts or a
  malicious sandbox verdict, a measured inventory newly granting process/network. HARD-STOP
  in the gate, FAIL in the monitors; a missing policy is unevaluated, never "no floors".
  (#369)
- **VirusTotal panels are read for completeness and sandbox state.** Fewer than 50
  verdict-bearing engines is an incomplete panel (not a verdict); each digest's sandbox state
  is recorded as ABSENT / NOT READY / ANALYZED rather than inferred; a `suspicious` sandbox
  verdict blocks until a per-item sign-off exists. Lookups are keyed by (tool, target) — a
  name-only key had dropped one digest. (#347, #408, #409)
- **Vulnerability statements follow OpenVEX / CycloneDX vocabulary.** An advisory RustSec
  withdraws or narrows away from a blessed binary is recorded `not_affected` /
  `vulnerable_code_not_present`, grounded in the advisory-DB commit it was observed absent at,
  and that statement is void the moment the DB reports it again; `fixed` is rejected for
  immutable bytes. Monitor guards: DB ordering, lock drift, raw-payload custody. (#251, #345,
  #395)
- **Maintainer commit signing.** The signing-key roster lives in
  `supply-chain/allowed_signers`; `main` requires signed commits. (#398)
- **cargo-acl** builds `--no-default-features` with `tui-input` optional (122 → 71 packages),
  on object 0.40 / ruzstd 0.9.1 (RUSTSEC-2026-0344 fixed). Per-tool RUSTFLAGS are
  single-sourced under `tools/rustflags/` and cross-checked. (#325, #361, #374, #375, #389)
- Versioning rule written down: dependency-only releases are PATCH. (#371)
- **Sign-offs name what they sign.** A caps ack carries the sha256 of the `caps.toml` it
  reviewed and covers nothing else; a malware ack covers one (engine, verdict) finding; and a
  change to a blessed digest's evidence with no TOOLS.lock change is evaluated against the base
  commit's record rather than waved through. The 43 existing caps acks were bound to the content
  each one signed at the time. (#380)
- **Build-script directives have a floor.** A measured inventory whose build script passes
  arbitrary linker flags, searches a link path outside its own OUT_DIR or registry source, emits
  a directive the evaluator cannot classify, or sets a `rustc-env`/`rustc-cfg` the prior
  inventory lacked is HARD-STOP; the inventory parser fails closed on anything it cannot read.
  (#382)
- **Runner-image and toolchain lifetimes are tracked as data**, as OpenEoX Core v1.0 documents
  (OASIS, CSD01) validated against a digest-pinned schema with the TC's own test vectors: every
  `runs-on` label must have a record, and a label within 120 days of its image's deprecation
  start fails CI; the weekly monitor cross-checks endoflife.date. The ubuntu-22.04 miss that
  motivated this is the first record. (#376)
- **Strictly-better lock fixes propose themselves.** A weekly job finds advisory instances with a
  RustSec patched version, runs `xtask freeze --require-improvement` for the lowest soaked
  non-yanked fix, soak-checks every transitive move, and opens one pull request with the frozen
  lock. It never bumps a rev, blesses a digest, or merges; a refusal opens no PR. (#405)
- **The gate's own test suite runs in PR CI.** The 150 unit tests that anchor every
  FAIL-DIRECTIONS row had been running only on developer machines. (#410)
- **xtask is lint-clean and tested in CI**; two LNK4199 warnings became delay-load tests;
  every xtask build in the workflows is `--locked`. (#413–#417, #433)
- **The tool fleet is caught up and at zero advisory instances.** cargo-auditable v0.7.7,
  cargo-vet v0.10.3 and cargo-cyclonedx 0.5.10 blessed, each lock frozen **against the prior
  blessed lock** (`--prior-lock --carry-forward`) so a rev bump never resolves below what
  shipped, with per-item checksum, source and publisher continuity checks; a new package name
  enters a frozen lock only with a committed lock-shape statement; the last two unmaintained
  crates (yaml-rust, number_prefix) were shed by bumping their dev-only chains rather than
  acknowledged. Instruments always come from the prior-blessed lock, never the branch under
  evaluation. The vuln baseline is written by a measured recorder that hashes its auditor.
  (#420–#426)
- **Release SBOM is CycloneDX 1.6** (the VDR floor, structured `authors`), asserted in-job;
  dry-run artifacts live one day, and the dispatch description states what a dry-run is and is
  not. (#428, #431)
- **Evidence lifecycle written down**: blessed evidence is immutable, never-blessed candidate
  evidence is retired with its candidate; caps measurements seed from main's blessed inventory;
  the bless cycle itself is `cargo xtask candidate-advance`, one idempotent fail-closed stage per
  step. (#429, #430, #432)

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
