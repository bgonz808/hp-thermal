# Supply-chain vetting (cargo-vet) + advisory monitoring

Two axes of dependency safety. The rest of the pipeline (Dependabot + cooldown, cargo-deny,
cargo-audit on the shipped binary, osv-scanner, SBOM, `--locked`) already covers **known-bad
signals** — a filed CVE, a disallowed license, an unknown source. These two additions cover what
that structurally cannot:

| axis | question | tool | cadence |
|---|---|---|---|
| **proactive** | has a human vetted this crate's code? | **cargo-vet** (`.github/workflows/supply-chain.yml`) | per-PR gate |
| **continuous** | did a CVE appear *after* we merged/shipped this? | **rustsec/audit-check** (`.github/workflows/deps-audit.yml`) | daily |

cargo-vet catches the malicious-but-no-advisory-yet class (maintainer takeover, typosquat, slow
poison) *before* a CVE exists. The daily monitor catches an advisory published *after* a dep was
gated. Both operate on the full transitive `Cargo.lock` graph.

## Gate and baseline

The gate is **fail-closed** in the required `ci` check (`.github/workflows/ci.yml`), on every PR
and push, with the TOOLS.lock-pinned cargo-vet (never `cargo install`, #221). Any crate version
that is not audited, covered by an imported audit, or exempted **at that exact version** fails.

The baseline (2026-11-15) exempts the 14 crates no import covers, each at its exact version with
the note "Pending audit": the `windows` family (compiled into the exe), its proc-macros with
`syn`, `proc-macro2` and `unicode-ident` (run at compile time), and `find-msvc-tools` (the build
script). An exemption is recorded debt, not trust: a new version of any of them fails until it
is audited or explicitly exempted in a reviewed change.

## Paying down the debt

Audit the code, then record it; the exemption goes away with it:

```bash
cd app
cargo vet diff <crate> <audited-version> <our-version>      # review only the delta, or
cargo vet inspect <crate> <our-version>                     # review the whole crate
cargo vet certify <crate> [<audited-version>] <our-version>
cargo vet prune                                             # drop exemptions now covered
```

`cargo vet suggest` lists the cheapest audits first. Certifying records your authorship; nothing
certifies automatically. Publisher trust (`[[trusted]]`) is not used: who published a crate is
not a review of its code.

## Vetting a Dependabot bump

1. Dependabot opens the bump (after the 7-day cooldown). It re-resolves `Cargo.lock` (transitive).
2. CI runs the known-bad gates (deny/audit/osv) **and** the cargo-vet gate.
3. If cargo-vet flags an unvetted delta, review the actual source change — not the version number:
   ```bash
   cd app && cargo vet diff <crate> <old-version> <new-version>
   ```
4. If it's clean, record it:
   ```bash
   cd app && cargo vet certify <crate> <old-version> <new-version>   # audit only the delta
   ```
   Prefer certifying the **diff** over a full re-audit when only bumping. If the crate is covered
   by an imported audit set, no action is needed — the import already vouches for it.
5. Commit the updated `audits.toml`, merge.

## What this does NOT do

- It does not re-audit a crate whose code you haven't looked at just because it has no CVE — that
  is the point; `[[trusted]]` / imports are explicit, recorded trust decisions, not silence.
- It does not check licenses/sources (cargo-deny) or scan the shipped binary (cargo-audit bin) —
  those remain the release-path gates. This is the missing *vetting* layer, added alongside them.


## Why the store files carry no comments

`cargo-vet` **owns the format of its store** (`config.toml`, `audits.toml`,
`imports.lock`). It normalizes those files and treats anything it did not write as a
consistency error:

```
ERROR   x Your cargo-vet store (supply-chain) has consistency errors
Error:    x A file in the store is not correctly formatted
```

So the explanatory prose that used to live at the top of `config.toml` lives here
instead. The store files stay exactly as the tool writes them, which also means a diff
to them is always a real policy change rather than a formatting argument.

### What each file is

| file | meaning |
|---|---|
| `config.toml` | policy: which audit sets we import, plus `exemptions` (unreviewed crates we ship anyway) |
| `audits.toml` | audits **we** performed — the only entries that represent our own review |
| `imports.lock` | the pinned snapshot of imported third-party audits |

### The three trust mechanisms, and what each actually asserts

- **Audit** — a human read the code and certified it (`safe-to-run` for build-time-only,
  `safe-to-deploy` for anything reaching the shipped binary). This is assurance.
- **Import** — we delegate review to a named organisation (Mozilla, Google, Bytecode
  Alliance) whose audits are published, versioned, and diffable. This is delegation, and
  it is revocable: dropping the import re-exposes everything it covered.
- **Exemption** — we have *not* reviewed this crate and are shipping it regardless. This
  is recorded debt, not assurance, and should be described that way in any posture claim.

`cargo vet certify <crate> <old> <new>` records a **delta** audit — review of just the
diff between two versions. That is what makes the steady state affordable once a
baseline exists: bumps cost a diff review, not a full re-read.
