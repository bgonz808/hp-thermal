# `supply-chain/` — provenance & SCA policy + evidence

The repo's supply-chain assurance surface, split by concern (the split is the first-level
directory, so a reviewer knows which hat they're wearing from the path alone):

- **`policy/`** — what we *intend*: human-authored, reviewed declarations.
  - **`caps/<binary>.json`** — per-binary capability manifests (#245). What each binary
    we produce is *allowed* to import (allowlist, exact-match ratchet) and must *never*
    import (denylist of injection/exfil primitives). Enforced by `cargo xtask verify-caps`
    against the actual bytes. **Missing manifest = fail** (fail-secure; absence is never a
    skip). Authoring is a review, not a write: `verify-caps` on an un-manifested binary
    prints a proposed manifest (its measured surface) to commit.
  - **`eox/`** — lifecycle (EoX) records (#376): one OpenEoX Core v1.0 document per runner
    image / OS / toolchain channel in `records.json`; the schema copy they are validated
    against in `schema/`, pinned by digest in `SCHEMA.lock`. Enforced by `cargo xtask eox-check`
    (PR CI offline; the weekly monitor cross-checks endoflife.date).
  - `bump/` *(future)* — per-tool candidate-promotion policy (the bump pipeline).
- **`evidence/`** — what we *measured*: per-digest records the gate consumes.
  - `<tool>/<full-sha256>/{vuln.jsonl,mal.jsonl,caps.toml}` + `<tool>/acks.jsonl`.
  - See `evidence/…` history and #241 for the schema (in-toto-vulns / OpenVEX-aligned).

## Why this layout

Naming and structure follow the ecosystem's content-addressed / supply-chain conventions:

- **`supply-chain/`** echoes cargo-vet's own directory (we run cargo-vet in
  `app/supply-chain/`); the two are the same *domain* at two scopes — app dependency
  trust vs. the repo's binary/tool trust. (Don't confuse them: `app/supply-chain/` is
  cargo-vet's tool-owned config; this tree is our gate's.)
- **policy ≠ evidence** mirrors OPA/conftest (`policy/`) and in-toto (layout vs link):
  intent and measurement never share a file or a directory.
- **Full SHA-256 as identity** (dirs, ack subjects) — never a truncated prefix. A locator
  may abbreviate *only* when a full re-verify backs it (the #225 asset names); anything
  that *authorizes* (ack matching) uses the full digest. We keep SHA-256 (NIST SP
  800-131A / SLSA / in-toto) and borrow git/OCI's *unambiguous-resolution* discipline for
  locators — never git's SHA-1. See #244.

## Related build-input deviations (live in `tools/`, not here)

Committed deviations the producer consumes are build inputs and live beside `tools/TOOLS.lock`:
`tools/locks/<tool>.lock` (frozen resolutions) and `tools/patches/<tool>/` (downstream
manifest patches, Debian/nixpkgs model, fail-closed supersession via `git apply --check`).
Their *justification* — measured advisory deltas, acks, sign-offs — lives in this tree.

## Fail-direction matrix

[`FAIL-DIRECTIONS.md`](FAIL-DIRECTIONS.md) — what every enforcement mechanism does when it
fails or lacks data, and whether that direction is secure. Every row is anchored to a
pinning unit test or a tracked issue (unanchored rows are not accepted), and any PR that
changes a mechanism's failure behavior updates its row in the same diff. The OPEN rows are
the enforcement layer's own burn-down list.

## The gate engines (`cargo xtask …`, first-party Rust — no external tool, no interpreter)

- **`gate --base <TOOLS.lock>`** (#241) — 3-axis candidate evaluation (vuln/caps/mal)
  vs. `evidence/`, with recorded-ack sign-off. Consumes this tree.
- **caps strict-subset ALLOW** (#367) — a measured inventory (caps-measure.yml header: exit code,
  lock sha256) that is a complete strict subset of the prior blessed inventory passes without a
  fresh signature. Empty, partial, copied-forward, or any addition falls back to RAISE.
- **absolute floors** (`policy/floors.json`) — the state a signature cannot admit: a vulnerability
  with a critical-shape CVSS vector, a panel with too many malicious verdicts or a malicious sandbox
  verdict, a measured inventory newly granting `process`/`net`. HARD-STOP in `gate`, FAIL in the
  monitors, never ackable; a missing policy is UNEVALUATED, not "no floors".
- **`eox-check`** (#376) — OpenEoX Core "Validator Basic" over `policy/eox/records.json` against
  the digest-pinned schema (TC test vectors vendored under `xtask/testdata/openeox/`), plus the
  lifecycle windows: every `runs-on` label in `.github/workflows/` must have a record, and the
  check FAILS within 120 days of the image's deprecation start (announced or PROJECTED, labelled
  as such), WARNS within 180. An unknown or floating label, an unpinned schema copy, or a schema
  keyword outside the implemented subset fails closed; an unreachable endoflife.date is UNKNOWN.
- **`verify-caps <binary> [--manifest <p>]`** (#245) — the binary vantage of the caps
  axis: measures a binary's import surface against `policy/caps/<binary>.json`, fails
  closed on off-allowlist imports, stale allow entries (ratchet), denied functions, or
  undeclared dynamic resolution. One engine for every binary — tools and releases alike.
