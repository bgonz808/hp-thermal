# Per-digest evidence store (#241 §7)

Persisted baseline evidence for every blessed tool binary, keyed by content:
`<tool>/<sha256:0:12>/` holds the three-axis record for that exact digest; `<tool>/acks.jsonl`
holds the recorded residual-risk sign-offs. This store is what makes honest candidate
evaluation possible — a diff needs a recorded baseline — and it is deliberately **in-repo**:
every ack is an attributed commit, every baseline is reviewable history.

## Schema (adopted, #241 §7)

Records are **JSONL** — one JSON object per line — chosen over prose (not machine-readable),
whole-document JSON (noisy diffs, fumbled hand-edits), and CSV (can't hold alias arrays). JSONL
keeps line-diff and copy-paste-to-sign-off virtues while every line is structured and jq/serde
parseable. The schema borrows established vocabularies rather than inventing one:

- **vuln.jsonl** — line 1 is a scan header aligned to the **in-toto vulns v0.2** predicate
  (`scanner{uri, version, digest, db{uri, version, lastUpdate}}`, `scanFinishedOn`) — this is
  the recorded **instrument** (#241 §5). Each subsequent line is an advisory **instance tuple**:
  `{id, aliases[], package, version, kind}`. Never a bare ID — Cargo coexists semver-major
  versions, so one advisory can have multiple simultaneous instances and instance-count changes
  are signal (#241 §6). `aliases` carries CVE/GHSA/RUSTSEC for cross-scanner canonicalization.
- **mal.jsonl** — VirusTotal panel snapshot: `{subject, panelDate, detections{malicious,total},
  flags[{engine,result}], sandbox[{name,category,confidence}], …}`. Written from
  schedule/dispatch runs only — PR workflows never call VT.
- **caps.toml** — the cackle-generated capability inventory; its `[api.*]` sections ARE the
  instrument it was measured with, so it stays native TOML (converting would sever that
  identity). A `caps.UNEVALUATED` file in its place records *why* no data exists — fail-secure:
  absence of evidence is recorded, never implied clean.
- **acks.jsonl** — sign-offs aligned to **OpenVEX** (`status` ∈ not_affected/affected/fixed/
  under_investigation, `justification`, `impact_statement`/`status_notes`, `action_statement`,
  `author`, `timestamp`). Our records are an OpenVEX-*aligned profile* (a `schema` field names
  it), because OpenVEX permits no extension fields and mal/caps findings are not
  "vulnerabilities"; the vuln subset is cleanly exportable to conformant OpenVEX.

Raw scanner payloads (full `cargo audit --json`, full VT panels) are point-in-time and
non-reproducible; they go to the content-addressed `tools` release store referenced by hash
(#225 doctrine) rather than bloating the repo. Retention is **defined but unarmed**: keep raw
payloads for current-pinned digests + last N supersessions; prune only unreferenced payloads
older than the threshold, and only with a pruning-log entry (the ledger records its own
truncation). Triggered by store size, not calendar.

## Lifecycle — scan the live frontier only (#226/#241)

- **Evidence is written at bless time** and becomes the next bump's baseline.
- **The knowledge-delta rescan (surveillance) runs ONLY on the live frontier** — the digests
  currently pinned in `TOOLS.lock` (constant N) plus any candidate under evaluation. Superseded
  records are immutable audit trail, never re-scanned: no gate consumes a finding on a binary
  nobody runs, so scanning it is unactionable noise. This bounds VT quota + CI to O(pinned), flat.
- **Candidate scans are contemporaneous with the baseline rev** — same advisory-DB commit, same
  cackle instrument, same-era VT panels (#241 §5). Recorded baselines are audit trail and the
  knowledge-delta input, never the comparison input for gating.

## Rules

1. **Acks bind to instances, not classes** — a new digest, engine, or advisory instance is never
   covered by an old ack.
2. **Nothing here is deleted on supersession** — superseded digests keep their evidence
   (forensic history).
3. Consumer: `cargo xtask gate` (first-party Rust — no external pinned tool, no python runtime)
   diffs baseline↔candidate, applies the #241 verdict algebra, and fails a bump PR until every
   RAISE item is covered by a committed ack, printing the exact ack lines to add. Committing them
   **is** the sign-off; closing the PR is the reject.

## Known open items (bootstrap, 2026-08-21)

- `cargo-audit` (8), `cargo-cyclonedx` (5), `cargo-acl` (2) vuln instances are recorded but
  **unacked** — pending triage. Their next bump PR RAISEs on every unacked carried instance
  until triaged; that is the grandfathering guard (#241 §4) working as designed.
- `cargo-audit` caps axis is UNEVALUATED (instrument-poison follow-up, #50).
- The vuln baselines were text-mode scans; raw JSON not retained. `--json` mode + release-store
  retention begins with the `candidate-eval` workflow.
