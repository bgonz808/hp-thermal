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

## Baseline (do this once, then make the gate blocking)

The cargo-vet gate ships **report-only** (`continue-on-error`) so it can't block work before the
current tree is baselined. To establish the baseline and turn it on:

```bash
cd app
cargo install cargo-vet --locked --version 0.10.0
cargo vet                        # fetches imports, lists unvetted crates
cargo vet regenerate exemptions  # grandfather the CURRENT tree as recorded exemptions
cargo vet suggest                # proposes [[trusted]] publishers — e.g. the windows-* family
                                 # (Microsoft) and proc-macro2/syn/quote (rust-lang)
cargo vet                        # should now pass
```

Review what `suggest` proposes, add `[[trusted]]` / audits you're comfortable with, commit the
updated `config.toml` / `audits.toml` / `imports.lock`, then in a reviewed PR **delete the
`continue-on-error: true` line** in `.github/workflows/supply-chain.yml` to make the gate enforce.

From then on, any *new* crate or version that isn't audited, imported-audited, or exempted fails
the PR.

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
