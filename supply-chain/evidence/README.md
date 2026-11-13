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
  flags[{engine,result}], sandbox{state, verdicts[{name,category,confidence,classification[]}],
  firstSubmission, readOn}, timesSubmitted, source}`. `detections.total` counts verdict-bearing
  engines (malicious+suspicious+undetected+harmless); below `policy/floors.json`
  `mal.min_verdict_engines` the panel is INCOMPLETE and the record is UNEVALUATED (#347 step 1).
  `sandbox.state` is what the panel STATED when read: `ANALYZED` (≥1 sandbox verdict, each
  recorded) or `NOT READY` (none yet — sandbox analysis lags the AV panel and some files are
  never sandboxed; not "no behaviours"). Records written before #347 carry a bare `sandbox: []`
  and read as `UNSTATED`. A `malicious` sandbox verdict is a floor; `suspicious` is UNEVALUATED
  until #347's per-item sign-off exists. The monitor prints each pinned digest's line ready to
  append verbatim. Written from schedule/dispatch runs only — PR workflows never call VT.
- **caps.toml** — the cackle-generated capability inventory; its `[api.*]` sections ARE the
  instrument it was measured with, so it stays native TOML (converting would sever that
  identity). A `caps.UNEVALUATED` file in its place records *why* no data exists — fail-secure:
  absence of evidence is recorded, never implied clean.
- **acks.jsonl** — sign-offs aligned to **OpenVEX** (`status` ∈ not_affected/affected/fixed/
  under_investigation, `justification`, `impact_statement`/`status_notes`, `action_statement`,
  `author`, `timestamp`). Our records are an OpenVEX-*aligned profile* (a `schema` field names
  it), because OpenVEX permits no extension fields and mal/caps findings are not
  "vulnerabilities"; the vuln subset is cleanly exportable to conformant OpenVEX.
  Caps acks therefore carry `status: reviewed` (an inventory is signed, not a vulnerability status);
  mal acks keep `not_affected` for false positives, which is a real OpenVEX meaning.
  **An ack names what it signs (#380).** A caps ack carries `evidence_sha256`, the sha256 of the
  exact `caps.toml` bytes reviewed; it covers that content and nothing else, so a rewritten
  inventory under a blessed digest is RAISE-uncovered until signed again (the gate prints the
  template with the new hash). A mal ack covers one finding, `finding.engine` **and**
  `finding.result`: an engine renaming its verdict on the same bytes is a new detection. Acks
  lacking those fields fail the quality bar and are not counted. The 43 caps acks that predate the
  field were bound (2026-11-11) to the `caps.toml` content at the commit each ack first appeared in;
  five of them signed inventories the Bubblewrap refresh (#381) rewrote a day later, and each of
  those digests carries a fresh ack for the rewritten content.
  Statements are a sequence, never edited or deleted; the LAST statement for an instance is the
  one that counts (#251). When `monitor-vuln` classifies an instance as GONE (RustSec withdrew the
  advisory or narrowed its `[versions]`; the bytes did not change, so never `fixed`) it prints a
  `not_affected` / `vulnerable_code_not_present` statement to append, carrying the DB commit as a
  CycloneDX-style property `hp-thermal:observed-absent-at-db`. A statement grounded that way is
  void as coverage once the DB reports the instance again, so a reappearance is signed off afresh.
  `fixed` is rejected on the vuln axis; `not_affected` needs a `justification` (CISA VEX minimum
  requirements). Layout and file names here are repo-local; the vocabulary is OpenVEX / CycloneDX.
  `monitor-vuln` also checks each baseline's `rawPayload` against the `tools` release store (GitHub's
  asset digest vs the recorded sha256, no download); a missing or mismatched backing report makes
  the pin UNEVALUATED.

Raw scanner payloads (full `cargo audit --json`, full VT panels) are point-in-time and
non-reproducible; they go to the content-addressed `tools` release store referenced by hash
(#225 doctrine) rather than bloating the repo. Retention is **defined but unarmed**: keep raw
payloads for current-pinned digests + last N supersessions; prune only unreferenced payloads
older than the threshold, and only with a pruning-log entry (the ledger records its own
truncation). Triggered by store size, not calendar.

## Lifecycle — scan the live frontier only (#226/#241)

- **Evidence is written at bless time** and becomes the next bump's baseline.
- **The knowledge-delta rescan (supply-chain-monitor) runs ONLY on the live frontier** — the digests
  currently pinned in `TOOLS.lock` (constant N) plus any candidate under evaluation. Superseded
  records are immutable audit trail, never re-scanned: no gate consumes a finding on a binary
  nobody runs, so scanning it is unactionable noise. This bounds VT quota + CI to O(pinned), flat.
- **Candidate scans are contemporaneous with the baseline rev** — same advisory-DB commit, same
  cackle instrument, same-era VT panels (#241 §5). Recorded baselines are audit trail and the
  knowledge-delta input, never the comparison input for gating.

## Bless cycle — `cargo xtask candidate-advance`

The steps that turn a re-frozen candidate branch into a bless PR are stages of one command, run
on the maintainer's machine with the maintainer's `gh` session and signing key (CI gains nothing;
nothing merges): `digest --run <producer run>` (verifies the run built THIS branch's lock, writes
the digest, retires a superseded never-blessed digest per rule 2), `vuln --auditor … --lock-provenance …`
(record-vuln + raw payload upload, verified in the store), `caps` (dispatch, wait, verify the
header names this lock, commit), `mal` (VT lookup first, submit only if absent, re-read, record),
`summary [--pr N]` (title and body generated from this directory). `status` shows what is recorded
and what is missing. Each stage refuses to run without its precondition and commits what it wrote.

## Rules

1. **Acks bind to instances, not classes** — a new digest, engine, advisory instance, inventory
   content or verdict string is never covered by an old ack.
2. **Blessed evidence is immutable** — a digest that was ever pinned in `TOOLS.lock` on `main`
   keeps its evidence forever (forensic history), even after a later bless supersedes it.
   **Candidate evidence is retired with the candidate**: a digest that was measured on a
   candidate branch but never blessed (its lock was re-frozen, its producer run superseded)
   has its evidence directory, its stored raw payload and any ack bound to it removed on that
   branch before the bless PR merges, so `main` only ever records digests that were real. The
   candidate branch's commit history keeps the measurements; nothing on `main` refers to them.
3. Consumer: `cargo xtask gate` (first-party Rust — no external pinned tool, no python runtime)
   diffs baseline↔candidate, applies the #241 verdict algebra, and fails a bump PR until every
   RAISE item is covered by a committed ack, printing the exact ack lines to add. Committing them
   **is** the sign-off; closing the PR is the reject.
4. **Evidence edits on the live frontier are candidates too (#380).** A PR that changes a pinned
   digest's `caps.toml` / `caps.UNEVALUATED` / `mal.jsonl` without touching TOOLS.lock is evaluated
   on the axes it touched, against the base commit's record (the workflow extracts that tree). An
   edited `vuln.jsonl` under a pinned digest is UNEVALUATED: baselines are written by the bless
   flow and backed by a stored raw payload, never edited in place. Changed `acks.jsonl` files are
   quality-checked even when nothing else changed; edits under non-frontier digests are listed in
   the report and not evaluated.

## Known open items (bootstrap, 2026-08-21)

- `cargo-audit` (8), `cargo-cyclonedx` (5), `cargo-acl` (2) vuln instances are recorded but
  **unacked** — pending triage. Their next bump PR RAISEs on every unacked carried instance
  until triaged; that is the grandfathering guard (#241 §4) working as designed.
- `cargo-audit` caps axis is UNEVALUATED (instrument-poison follow-up, #50).
- The vuln baselines were text-mode scans; raw JSON not retained. `--json` mode + release-store
  retention begins with the `candidate-eval` workflow.

## Products

The store holds one directory per **product** named by the digest of the bytes it describes.
Products are the build tools (one per `TOOLS.lock` name) and `hp-thermal` itself: a release's
shipped `hp-thermal.exe` digest (from the Release's SHA256SUMS) gets the same `vuln.jsonl`
(app lock vantage, written by `record-vuln`) and `mal.jsonl` (VirusTotal panel, recorded from
the monitor's `release:hp-thermal.exe` lookup) as a tool, under the same floors and acks
semantics. Capabilities for the app are measured by `verify-caps`/BinSkim on the exe, not by
cackle (Windows-only crate tree), so there is no `caps.toml` for `hp-thermal`.
The app's records are written by `cargo xtask release-advance <status|vuln|mal> --tag vX.Y.Z` on an
`evidence/*` branch (digest from the Release's SHA256SUMS; lock from the tag; VT lookup first,
submit only if absent), the counterpart of `candidate-advance` for tools.
