# Security

Security is a first-class goal for hp-thermal: a privileged SYSTEM service that performs
BIOS/WMI calls, driven by an unprivileged tray over a local pipe, has to be built to be
safe by design.

## Reporting a vulnerability

Report privately via **GitHub Security Advisories** ("Report a vulnerability" on the
*Security* tab), not a public issue. Please state clearly if you believe a finding escapes
the bounded-impact ceiling described below — those are prioritized.

## Verifying a release

Every release is built by a public GitHub Actions workflow and carries a **[SLSA](https://slsa.dev) build
provenance** attestation and an **SBOM** attestation (CycloneDX 1.6), so you can prove the `.exe`
was built from this repo's source by that workflow and was not altered in transit. The SBOM's
`formulation` declares the build environment for rebuilders: rustc commit, MSVC toolset (checked
against the linker build recorded in the exe's Rich header), Windows SDK and runner image.

**SLSA v1.2 Build Level 3.** Build, Authenticode signing and attestation run in a reusable
workflow (`release-pipeline.yml`) that the calling release job cannot inject steps into, on
GitHub-hosted ephemeral runners with OIDC-only signing and no caches; provenance is signed by
that workflow's identity and verified before publish. The Source track has no formal level on
GitHub today (GitHub issues no Source VSA); `main` enforces signed commits from a committed key
roster, required checks, linear history and no force-push. `v*` tags and the `tools` store tag
cannot be updated or deleted by anyone, administrators included; creating a `v*` tag requires a
repository administrator and a commit that passed the required checks.

With the [GitHub CLI](https://cli.github.com), pinning the signer to the reusable pipeline (the
identity check is what makes verification meaningful):

```sh
gh attestation verify hp-thermal.exe \
  --repo bgonz808/hp-thermal \
  --signer-workflow bgonz808/hp-thermal/.github/workflows/release-pipeline.yml
```

Releases v0.3.0 through v0.3.2 predate the reusable pipeline: verify those with
`--signer-workflow bgonz808/hp-thermal/.github/workflows/release.yml`.

### What a release carries, and what each piece proves

Every attestation below is a Sigstore bundle whose subject is `hp-thermal.exe`; `gh attestation
verify hp-thermal.exe --repo bgonz808/hp-thermal` plus the listed `--predicate-type` and
`--signer-workflow` checks it offline against the bundle shipped beside the exe. Pin the signer
every time: the identity is the claim.

| asset | predicate type | signer workflow | what it proves |
|---|---|---|---|
| `hp-thermal.provenance.sigstore.jsonl` | `https://slsa.dev/provenance/v1` | `release-pipeline.yml` | These bytes were built by that workflow from this repository at the tagged commit (SLSA Build L3). |
| `hp-thermal.sbom.sigstore.jsonl` | `https://cyclonedx.org/bom` | `release-pipeline.yml` | The CycloneDX 1.6 SBOM bound to the exe: dependency set, and `formulation` naming the build environment (rustc commit, MSVC toolset checked against the exe's Rich header, Windows SDK, runner image). |
| `hp-thermal.vsa.sigstore.jsonl` (from the first release after v0.3.2) | `https://slsa.dev/verification_summary/v1` | `release.yml` | The release workflow's signed statement that it verified the provenance and SBOM attestations against this repository's policy at that commit and found Build L3 to hold. It is **self-issued**: the verifier is the same party as the builder, so it is a machine-readable record of what was checked, not an independent audit. |
| `hp-thermal.vdr.cdx.json` + `hp-thermal.vdr.sigstore.jsonl` (attached after release; later revisions attach beside it as `hp-thermal.vdr.vN.*`) | `https://cyclonedx.org/bom` | `release-vdr.yml` | The CycloneDX Vulnerability Disclosure Report for the shipped dependency set: every RustSec finding, with the maintainer's ruling where one is recorded. Issued once the release's evidence is recorded and reviewed, so it arrives days after the exe; the signer identity tells it apart from the SBOM. |
| `hp-thermal.build.jsonl` | none; a subject of the provenance attestation | `release-pipeline.yml` | cargo's own record of the build (`--message-format=json-render-diagnostics`): every compiled unit with its features and profile, and every build script's cfgs, env, and link directives. Two independent builds must record the same units, features, and cfgs. |
| `SHA256SUMS` | none | none | Convenience only. A checksum proves a file matches itself; the attestations prove where it came from. |

The same `gh attestation verify` command with `--predicate-type` set to a row's type and
`--signer-workflow` set to `bgonz808/hp-thermal/.github/workflows/<row's workflow>` checks that
row. The SBOM and the VDR share a predicate type because a VDR is a CycloneDX document; use the
signer workflow, or the `vulnerabilities` field in the verified statement, to pick the one you mean.
A VDR is revised as findings change: every revision keeps the release's one `serialNumber` and
takes a higher `version`, and earlier revisions stay attached and verifiable. The highest version
for the serial is the current report.

The attestation is the real integrity anchor. `SHA256SUMS` is attached as a convenience, but
a bare checksum only proves a file matches itself; the attestation proves it came from this
build. Since v0.3.0 releases are also [Authenticode](https://learn.microsoft.com/windows-hardware/drivers/install/authenticode)-signed
(keyless OIDC to an HSM-backed signing service; the pipeline verifies the signature before
publishing), so the UAC prompt shows a verified publisher. Note that SmartScreen *reputation*
is a separate system and accrues slowly: a warning wall on a fresh release is expected and is
not a signature failure.

## Threat model (tray ↔ service IPC)

The single `hp-thermal.exe` runs in two roles: a **tray** (interactive user, Medium
integrity) and a **service** (SYSTEM). They communicate over a local named pipe.

**Principle:** trust originates at the SYSTEM service (tamper-resistant to non-admins);
authentication is mutual; the service exposes only bounded-impact operations — so no
client, even a fully compromised one, can escalate. Security comes from making the pipe
*not worth tampering with*, not from making it un-tamperable.

### Defense layers

1. **Network** — `PIPE_REJECT_REMOTE_CLIENTS`: local-only.
2. **DACL** — pipe access limited to `BUILTIN\Users` + SYSTEM + Admins.
3. **First-instance** — `FILE_FLAG_FIRST_PIPE_INSTANCE`: the service refuses to run if the
   pipe name was already registered (anti-squat).
4. **Wire framing** — a 2-byte magic prefix. This is a *framing marker, not authentication*
   (it's published in the source and rejects accidental/scanning traffic); real
   authorization is the DACL + client validation, never these bytes.
5. **Client → server** — the tray confirms the pipe server is our exe in Program Files
   (admin-only-write, so a user-level impostor can't be there).
6. **Server → client** — the service confirms the caller's exe path *and* reads its token
   via `ImpersonateNamedPipeClient` to reject a confirmed below-Medium integrity level.
7. **Input allowlist** — a pure, `unsafe`-free, fixed-size parser; a closed command set with
   range-checked payloads; unknown commands rejected. Unit-tested.
8. **Anti-injection** — process mitigation policies (`ExtensionPointDisablePolicy`) on both
   roles.

Path/identity **and caller integrity-level** checks fail **closed** (#159): a wrong client
path, or a caller whose integrity level can't be confirmed, is denied. Only the client→server
check fails **open** (inability to determine the *server* ≠ rejection), so a transient API
failure never breaks the legitimate tray ↔ service path; the pipe's mandatory-label SACL is the
kernel backstop behind it.

### Privilege-escalation & tamper posture

- **Escalation through the pipe: no path by construction.** The most a fully compromised
  client can make SYSTEM do is toggle a thermal mode or brightness level — range-checked,
  no code execution, no dangerous parameter. And BIOS/EC writes are token-bucket rate-limited
  (#159), so a compromised Medium-IL tray can't flood the firmware with mode changes. (Stated
  as "no path by construction," not formally proven.)
- **Tamper-proof: no — and that's the correct posture.** The SYSTEM service is
  tamper-*resistant* to non-admins; the tray cannot be tamper-proofed against same-user
  injection, and the design does not depend on it.
- **Tampering the input allowlist requires the privilege it protects** — patching it on
  disk needs Program Files write (admin); in memory needs SYSTEM's memory. A non-admin
  can't; an admin gains nothing new.
- **Runtime integrity vs. load-time authenticity — two independent axes.** The self-checks
  (footing check, [CIG](https://learn.microsoft.com/windows/win32/secbp/mitigation-guard), image-load policy, pipe integrity-level checks, `require_hp`,
  anti-rollback) harden *runtime* integrity: they resist in-memory tampering of a genuine
  process, applied at startup before injected code could act. But they are **self-imposed**,
  so they hold only *assuming the as-built binary is what ran* — a tampered build omits them,
  and the footing check verifies location / ACL / privilege, not authenticity. That
  assumption — load-time authenticity — is discharged by Authenticode signing (in place since
  v0.3.0): the OS won't run a tampered image as our publisher. So the self-checks are
  tamper-*resistant*; signing is what makes them tamper-*evident*.

### Weaknesses addressed ([CWE](https://cwe.mitre.org))

Design decisions mapped to the weakness *classes* they hold down — illustrative, not exhaustive.
A CWE is a standing **invariant**, not a one-time fix: a new feature can reintroduce any of these,
so each is only as durable as what enforces it (by construction > CI lint > convention; see #28).
`Status` is current posture — `held` = "no known instances, mechanism in place," not "solved
forever"; a ticket points at a known open gap. Residual risk is bounded by the OS privilege
boundary and the pipe's blast radius (a compromised client can only toggle a thermal mode), so
reachability alone does not imply impact.

| Weakness | Closed by | Status |
| --- | --- | --- |
| [CWE-20](https://cwe.mitre.org/data/definitions/20.html) Improper input validation | Bounded 2-byte pipe command set, range-checked | held |
| [CWE-269](https://cwe.mitre.org/data/definitions/269.html) Improper privilege management | SYSTEM service + least-privilege tray; startup footing check | held |
| [CWE-367](https://cwe.mitre.org/data/definitions/367.html) TOCTOU race | Verify image path on the process handle, not the snapshot PID | held |
| [CWE-426](https://cwe.mitre.org/data/definitions/426.html) Untrusted search path | Absolute System32 paths for `sc` / `icacls` / `runas` | held |
| [CWE-427](https://cwe.mitre.org/data/definitions/427.html) Uncontrolled DLL search path | `SetDefaultDllDirectories(System32)` + image-load policy + `/DEPENDENTLOADFLAG` | held |
| [CWE-494](https://cwe.mitre.org/data/definitions/494.html) Download of code without integrity check | Build attestation; signing + verify-before-promote planned | [#21](https://github.com/bgonz808/hp-thermal/issues/21), [#23](https://github.com/bgonz808/hp-thermal/issues/23) |
| [CWE-732](https://cwe.mitre.org/data/definitions/732.html) Incorrect permission assignment | Program Files admin-only ACL + service SDDL; data-dir ACL | partial · [#27](https://github.com/bgonz808/hp-thermal/issues/27) |

*Open work per weakness class is tracked on issues — filter by the `CWE-###` label
(e.g. [`CWE-732`](https://github.com/bgonz808/hp-thermal/issues?q=is%3Aissue+label%3ACWE-732)).
The labels are the live ledger; this table is the curated class-level summary.*

## Binary hardening

Exploit-mitigation flags on the shipped `.exe` (verify with `cargo xtask verify-hardening`):

| Mitigation | Status |
| --- | --- |
| ASLR / high-entropy ASLR | ✅ |
| DEP / NX | ✅ |
| Control Flow Guard | ✅ (`-C control-flow-guard=checks`) |
| Stack canaries | ✅ (`-Z stack-protector=strong`) |

## DLL search-order integrity

Windows resolves a non-[KnownDLL](https://learn.microsoft.com/windows/win32/dlls/known-dlls) by
[search order](https://learn.microsoft.com/windows/win32/dlls/dynamic-link-library-search-order) —
**the application directory before `System32`** — so a DLL loaded *by name* from a writable run
directory can be **planted** and hijacked ([MITRE T1574.001](https://attack.mitre.org/techniques/T1574/001/)
/ [.002](https://attack.mitre.org/techniques/T1574/002/)). Installed to `Program Files` (admin-only
ACL) this is a non-issue; the surface that matters is the **portable/installer `.exe` run elevated
from a writable dir** (e.g. Downloads), where a standard user can pre-plant a DLL and escalate.

Controls (verify with `cargo xtask audit-dll-closure` / `audit-dll-planting`):

| Load | Control |
| --- | --- |
| Our **static** imports | `/DEPENDENTLOADFLAG:0x800` — the loader pins them to `System32` at process init |
| Runtime `LoadLibrary` (`nvml`, `uxtheme`) | explicit `LoadLibraryExW(…, LOAD_LIBRARY_SEARCH_SYSTEM32)` per call |
| Process-wide default | `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` as `main`'s first line |
| **Deferred** cold-path DLLs (`rstrtmgr`, `powrprof`) | delay-load (`build.rs /DELAYLOAD`) — load past the pin (measured +4.5 KB for `delayimp.lib`) |

The subtlety: `/DEPENDENTLOADFLAG` pins our *own* static imports but **not a dependency's own
resolution** ([docs](https://learn.microsoft.com/cpp/build/reference/dependentloadflag)). `rstrtmgr`
and `powrprof` (used only on the install and Fn+F12 cold paths) each pulled a non-KnownDLL
transitive dep (`ncrypt`; `umpdc`/`wmiclnt`) at process init — *before* the runtime pin — a real
pre-`main` window (confirmed exploitable for `rstrtmgr`→`ncrypt` by the plant harness). Both are now
**delay-loaded**, so they stay *declared* imports (honest, visible to static analysis — unlike a
manual `LoadLibrary`+`GetProcAddress`, which reads as dynamic-API-resolution obfuscation,
[T1027.007](https://attack.mitre.org/techniques/T1027/007/)) but load at first use, after the pin,
resolving from `System32`. Net: **zero pre-`main` plant surface.**

Gated in CI (`.github/workflows/dll-plant-audit.yml`):

- **`audit-dll-closure`** walks the regular + delay import closure and **fails on any new pre-`main`
  transitive dep** (allowlist empty); delay/runtime deps are reported, not gated (pinned).
- **`audit-dll-planting`** — a user-mode plant harness (no admin, no kernel driver): builds a proxy
  under a dependency's name beside a throwaway exe copy and detects a run-dir win via a load marker
  (dynamic load) or the startup `NTSTATUS` (static bind failure). Blocking; validated with a
  known-plantable and a known-fixed control.
- **`capabilities`** — the import allowlist is **exact-match**: it fails if the concrete-DLL surface
  grows *or* shrinks without updating `ALLOWED`, ratcheting the reduced surface so it can't silently
  regress.

Residual: a *system* DLL dynamically `LoadLibrary`-ing a non-KnownDLL pre-`main` is OS-level behavior
we can't close in-process for a parent we don't control (an elevated installer's parent is
`consent.exe`). Backstops: the `Program Files` ACL (installed app) and Authenticode signing
(roadmap); the plant harness surfaces any such case.

## Dependency & supply-chain posture

- **Runtime third-party surface = the Microsoft `windows` crate family only.** Build-only
  crates are not in the binary.
- **Source scanning:** Dependabot (GitHub Advisory Database, incl. RustSec) continuously and
  off-workflow; `cargo-deny` + `cargo-audit` (RustSec) in the release attestation; and
  `osv-scanner` (OSV.dev — RustSec-complete) in the CI `scan` job. Each scans the full pinned
  lockfile.
- **Artifact scanning:** release binaries are built with `cargo-auditable`, embedding the
  dependency manifest so the shipped `.exe` itself is scannable (`cargo audit bin`, trivy).
- **Pinning:** `Cargo.lock` is committed — exact version + SHA-256 checksum per crate;
  `cargo-deny` restricts sources to crates.io.

**On "0 CVEs":** we report *0 known advisories against the pinned `Cargo.lock`*, confirmed by
two independent databases — **RustSec** (`cargo-audit` / `cargo-deny`) and **OSV.dev**
(`osv-scanner`) — over the **crates.io / Cargo** ecosystem, every pinned crate (a superset of
what's shipped and reachable, so a clean superset implies clean at binary and reachability
scope). The shipped `.exe` is independently scannable via `cargo-auditable`. **Freshness &
scope:** the result is only as current as the advisory-DB snapshot at each run (re-scanned on
every push/PR; Dependabot re-checks continuously off-workflow), and it excludes the Rust
`std` / toolchain, native C libraries behind `*-sys` crates (not in `Cargo.lock` / RustSec —
only trivy's OS scan reaches those), and any not-yet-published vulnerability. So: "no *known*
advisories against these pinned versions," not "no vulnerabilities exist."

## Antivirus false positives

hp-thermal is a **signed but still low-reputation Rust binary that does legitimately privileged,
hardware-specific work** — the exact combination heuristic/ML antivirus engines and sandboxes
over-flag. As of v0.3.0 (first signed release) the "Unknown Publisher" root cause is gone and the
two most impactful engines have cleared; the residual detections are generic and decay with
download reputation. If a scanner flags it, here is what the detections are and are not.

**They are generic / reputation signals, not behavior.** Every detection to date has been a
*generic/ML* name — **no specific malware family** — and the count inflates because several
products license one engine's database. A no-argument run is the bare tray (Medium integrity)
doing **reads only** — no file writes, no persistence, no network; the privileged install
behaviors are gated behind `--install` and never fire in a bare detonation. Behavioral sandboxes
agree (**Zenbox: Non-Malicious**).

**Recorded runs (we track every release so the reputation trend is visible):**

| Release | Signed | Score | Engines (all generic/ML, no family) | Notable |
| --- | --- | --- | --- | --- |
| pre-0.3.0 (representative) | no | handful | `Gen:Variant.Yogi`, `Wacatac.B!ml`, `MalwareX-gen`, `…Agent` | Microsoft **and** BitDefender firing |
| **v0.3.0** — `add64e322…ec149dc` | **yes** | **5/71** | Avast/AVG `Win64:MalwareX-gen`, Avira/WithSecure `TR/W64.Agent`, ESET `Win64/Agent_AGen.PRN` | family label `misc`; **Microsoft + BitDefender now clean** |

The v0.3.0 five collapse to **three independent engines** (AVG re-uses Avast's engine; WithSecure
re-uses Avira's — identical detection strings prove the shared verdict), all generic. The decisive
signal: signing flipped **Microsoft** (`Wacatac.B!ml`) and **BitDefender** (`Yogi`) from *firing*
to *clean* on byte-identical code — detections that respond to signing metadata rather than code
are the mechanical signature of reputation FPs, not behavior. The VT sample hash was verified equal
to the published `SHA256SUMS` entry and the attested build digest, so the scoreboard describes the
real release, not a stray upload.

**What trips the heuristics, node by node:**

| Flag | Cause | Assessment |
| --- | --- | --- |
| ~~unsigned / "Unknown Publisher"~~ | *resolved in v0.3.0* — Azure Trusted Signing, WVT `S_OK`, durable-identity EKU | the root cause, now removed; Microsoft + BitDefender cleared as a direct result |
| reads `HKLM\...\BIOS\SystemManufacturer` / `SystemProductName` | HP-model detection (`hwinfo.rs`) — the tool is HP-specific | trips the **anti-VM heuristic** (the same read malware uses to detect sandboxes); irreducible for a hardware tool |
| `.dep-v0` / non-standard PE section names | `cargo-auditable` dependency manifest (enables `cargo audit bin`) | irreducible without dropping auditable |
| "requires command line arguments" | monolithic role-by-flag design (`--install` / `--service`) | benign; the risky paths are consent-gated, not evasion |
| dual-use API surface | service create ([T1543.003](https://attack.mitre.org/techniques/T1543/003/)), token adjust ([T1134](https://attack.mitre.org/techniques/T1134/)), WMI ([T1047](https://attack.mitre.org/techniques/T1047/)), WER opt-out ([T1562.001](https://attack.mitre.org/techniques/T1562/001/)) | legitimate *installer* behavior; a base-rate false positive |

**The fix is identity, not code.** These are the structural false positives of a low-reputation,
dual-use binary; changing code to lower the count is whack-a-mole against classifiers that can't
read intent. Signing supplied the identity half (removing "Unknown Publisher" and, with it,
Microsoft + BitDefender); the remaining half is **accrued download reputation**, which collapses
the residual generic cluster over days-to-weeks. We record every VirusTotal run above so the trend
is visible — and we do **not** alter behavior to game the number.

## SmartScreen reputation (the "Windows protected your PC" wall)

SmartScreen is a **separate system from both AV and Authenticode**, and this is the most
misunderstood part: **a valid signature does not clear the red warning.** SmartScreen gates on
*reputation* — the publisher identity's and the specific file hash's download prevalence — not on
signature validity. v0.3.0 verifies as `Valid` (WVT `S_OK`) and *still* shows the red
"Windows protected your PC" screen on first run, because the signing identity has not accrued
reputation yet. This is expected for a new publisher, not a defect.

**What does and does not move it:**

- **Do not buy an EV certificate to fix this.** EV code-signing certs used to grant *instant*
  SmartScreen reputation, but **Microsoft removed that behavior in 2024** and its docs (current as
  of mid-2026) state plainly it no longer exists. An EV cert would not clear the warning and would
  be wasted money; OV, EV, and Trusted Signing now all earn reputation the same way.
- **Reputation is earned by download volume + time (days to a few weeks).** It accrues to the
  **durable publisher identity** (the `1.3.6.1.4.1.311.97.*` EKU we pin), so it compounds across
  releases and survives the ~72 h cert rotation — one reason we pin the durable-identity EKU rather
  than a spoofable subject name.
- **Submit the binary to Microsoft for analysis** (Microsoft Security Intelligence, aka.ms/wdsi →
  "I believe this is clean"). Now that it is signed, Microsoft can attribute the file to the
  identity; this can pre-clear Defender and feed SmartScreen.
- **Sign every release with the same identity and drive legitimate downloads.** Consistency is the
  whole mechanism; re-signing obsessively does not help (a new hash resets *file* reputation,
  though *publisher* reputation carries).

**Known 2026 Trusted Signing caveat (may be amplifying our warning).** v0.3.0 chains through the
intermediate CA `Microsoft ID Verified CS EOC CA 03`. In ~March 2026 Microsoft silently migrated
Trusted Signing customers onto new intermediate CAs (`AOC` / `EOC CA 03`), which **reset or broke
SmartScreen reputation** for affected customers — identical publishers that were trusted under the
prior CA began tripping "Windows protected your PC," with some still warned weeks later. So part of
our red wall may be this Microsoft-side migration, not organic warm-up alone. Tracked via Microsoft
Q&A and the `Azure/artifact-signing-action` issue tracker; if reputation has not built after a few
weeks of real downloads, that CA issue is the likely cause and warrants a Microsoft
engineering-review request rather than any change on our side.

## Build & CI trust boundary

A CI runner is a privileged trust boundary: every action and installed tool executes with
the job's environment (token, secrets, source). We treat the runner as hostile-adjacent and
**bound the blast radius** rather than assume the toolchain is trustworthy.

- **Read-only, secret-less workflows.** Both `ci.yml` and `release.yml` set
  `permissions: contents: read` and expose no secrets — a compromised step cannot push,
  publish, reach other repos, or exfiltrate credentials.
- **The frequent path installs nothing third-party.** PR CI is toolchain-only
  (fmt / clippy / test via rustup). Continuous dependency scanning runs *off-workflow* via
  Dependabot — on GitHub's infrastructure, not a runner, not with our token.
- **Actions pinned by full commit SHA.** A tag can be re-pointed by an upstream compromise
  (cf. the `tj-actions/changed-files` incident, 2025); a SHA is immutable.
- **Attestation tools installed by immutable git-rev**, and only in the rare release
  workflow. A maintainer-account compromise can publish a new *version* but cannot rewrite
  history at a pinned commit.
- **Release publishing is isolated.** Uploading a GitHub Release needs `contents: write`;
  that would be a separate, elevated job — kept apart from the read-only build/attest job.

**Honest limit:** there is no self-verifiable digest pin for `cargo install` today, and
**Build tools are pinned by digest, not installed.** Every `cargo-*` tool CI executes is a
prebuilt binary named by sha256 in `tools/TOOLS.lock`, built by `build-tools-pipeline.yml`
(the same reusable-workflow shape as the release, so the fleet is SLSA Build L3 too) from a
pinned upstream commit and a frozen lockfile, and fetched only after the digest matches and its
provenance attestation verifies against that workflow's identity. No job runs `cargo install`.
A tool enters or changes only through a three-axis gate (advisories, measured capabilities,
malware panel) with content-bound sign-offs, and every producer run reproduces all digests byte
for byte before they are trusted. The remaining honest limit is upstream source integrity at the
pinned commit, addressed by review at each rev bump and by capability measurement of what the
built tool can actually do.

## Memory-safety discipline

- Every `unsafe` block carries a `// SAFETY:` justification, enforced by
  `#![deny(clippy::undocumented_unsafe_blocks)]`.
- The input parser and IPC framing are `unsafe`-free and unit-tested.
- (Miri UB-checking is not run today — the minimal-binary `build-std` config conflicts with
  Miri's sysroot build. See roadmap.)

## Out of scope

- Same-user in-memory tampering of the *tray* — Windows' security boundary is user +
  integrity level, not process-to-process within a user. Impact is bounded to the thermal
  command set, which is why this is acceptable.
- `std`/toolchain advisories (not in the lockfile) and unknown/unpublished vulnerabilities.

## Roadmap

`/CETCOMPAT`, formal (Kani) proof of the input parser, and Miri
UB-checking of the pure-logic tests — the last unblocked by extracting the
pure logic into a stable `core` crate (which also removes the `build-std` sysroot conflict).
