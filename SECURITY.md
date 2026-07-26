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
provenance** attestation and an **SBOM** attestation, so you can prove the `.exe` was built
from this repo's source by that workflow and was not altered in transit.

With the [GitHub CLI](https://cli.github.com), pinning the signer to this repo's release
workflow (the identity check is what makes verification meaningful):

```sh
gh attestation verify hp-thermal.exe \
  --repo bgonz808/hp-thermal \
  --signer-workflow bgonz808/hp-thermal/.github/workflows/release.yml
```

The attestation is the real integrity anchor. `SHA256SUMS` is attached as a convenience, but
a bare checksum only proves a file matches itself; the attestation proves it came from this
build. The binary is not yet [Authenticode](https://learn.microsoft.com/windows-hardware/drivers/install/authenticode)-signed, so Windows shows "Publisher: Unknown" on
the UAC prompt — until that lands (see Roadmap), the attestation is the proof of origin.

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

Path/identity checks fail **closed**; integrity-level and server-query checks fail **open**
(inability to determine ≠ rejection) so a transient API failure never breaks the legitimate
tray ↔ service path.

### Privilege-escalation & tamper posture

- **Escalation through the pipe: no path by construction.** The most a fully compromised
  client can make SYSTEM do is toggle a thermal mode or brightness level — range-checked,
  no code execution, no dangerous parameter. (Stated as "no path by construction," not
  formally proven.)
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
  assumption — load-time authenticity — is discharged only by Authenticode signing (Roadmap):
  the OS won't run a tampered image as our publisher. So the self-checks are
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

## Binary hardening

Exploit-mitigation flags on the shipped `.exe` (verify with `cargo xtask verify-hardening`):

| Mitigation | Status |
| --- | --- |
| ASLR / high-entropy ASLR | ✅ |
| DEP / NX | ✅ |
| Control Flow Guard | ✅ (`-C control-flow-guard=checks`) |
| Stack canaries | ✅ (`-Z stack-protector=strong`) |

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
building any tool from source executes its build scripts in the runner. `--locked --version`
(an immutable crates.io version) and `--git --rev` (an immutable commit) reduce *what* runs,
but neither is a digest we independently verify. The real defense is therefore not perfect
verification but **bounded reward**: least privilege + no secrets + minimal in-runner code.

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

Authenticode signing, `/CETCOMPAT`, formal (Kani) proof of the input parser, and Miri
UB-checking of the pure-logic tests — the last unblocked by extracting the
pure logic into a stable `core` crate (which also removes the `build-std` sysroot conflict).
