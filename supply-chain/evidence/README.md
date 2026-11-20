# Per-digest evidence store (#241 §7)

Persisted baseline evidence for every blessed tool binary, keyed by content:
`<tool>/<sha256:0:12>/` holds the three-axis record and the build record for that exact digest; `<tool>/acks.jsonl`
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
  never sandboxed; not "no behaviors"). `NOT READY` means pending only for
  `policy/cadence.json` `sandbox_not_ready_days` after `firstSubmission`; past that bound the
  monitor says so, and the answer is a resubmission (vt-submit) or an ack that the digest ships
  unsandboxed. Records written before #347 carry a bare `sandbox: []`
  and read as `UNSTATED`. A `malicious` sandbox verdict is a floor; `suspicious` is UNEVALUATED
  until #347's per-item sign-off exists. The monitor prints each pinned digest's line ready to
  append verbatim. Written from schedule/dispatch runs only — PR workflows never call VT.
  Custody: a panel that would let a digest through counts only as the monitor's own line. Its
  `source` names one `supply-chain-monitor` run, scheduled or dispatched, on `main` or on a
  `candidate/*` branch whose monitor workflow at the run's commit is the base commit's; that
  run's `vt-monitor` log holds exactly one record line for the digest (a whole message, the
  monitor printing VT's own text one line per field), and the committed line is it, verbatim or
  as its canonical serialization. A line composed or edited by hand, or whose run log is gone, is
  UNEVALUATED until a fresh panel is appended. A panel that blocks keeps blocking regardless.
  The history moves forward: a change appends one panel, newer than every panel before it (a
  later monitor run, no earlier date), never a replay of one already recorded.
- **caps.toml** — the cackle-generated capability inventory; its `[api.*]` sections ARE the
  instrument it was measured with, so it stays native TOML (converting would sever that
  identity). A `caps.UNEVALUATED` file in its place records *why* no data exists — fail-secure:
  absence of evidence is recorded, never implied clean.
- **build.jsonl** — cargo's own record of the build that produced the digest. Line 1 is a header:
  `{schema, subject{name, sha256}, format, producerRun, rawRecord{sha256, store, asset}}`. Each
  further line is one message from cargo's documented JSON output
  (`--message-format=json-render-diagnostics`, The Cargo Book "JSON messages"), sorted:
  `compiler-artifact` (package_id, target kind/crate_types/name, profile, features) and
  `build-script-executed` (package_id, cfgs, env, linked_libs, linked_paths). Runner paths are
  dropped; nothing is added. The raw stdout is in the `tools` store, named
  `<binary asset without .exe>.build-<sha256:0:12>.jsonl`, and is a subject of the same producer
  provenance statement as the binary. `candidate-advance digest` writes it for a candidate;
  `build-record baseline --run <id>` writes it for every pin that producer run reproduced.
  The gate also holds the pin to the source the run built: the `TOOLS.lock` at the run's commit
  pins the same (name, target) to the same repo and rev.
- **acks.jsonl** — sign-offs aligned to **OpenVEX** (`status` ∈ not_affected/affected/fixed/
  under_investigation, `justification`, `impact_statement`/`status_notes`, `action_statement`,
  `author`, `timestamp`). Our records are an OpenVEX-*aligned profile* (a `schema` field names
  it), because OpenVEX permits no extension fields and mal/caps findings are not
  "vulnerabilities"; the vuln subset is cleanly exportable to conformant OpenVEX.
  Caps acks therefore carry `status: reviewed` (an inventory is signed, not a vulnerability status);
  mal acks keep `not_affected` for false positives, which is a real OpenVEX meaning.
  A vuln ack carries the ruling, OpenVEX status and the native `cyclonedx` object, with a
  one-line `status_notes`; measured facts live in the product's VDR fields, not in the notes.
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

Raw scanner payloads (full `cargo audit --json`, full VT panels) and raw build records are point-in-time and
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

## VDR — `cargo xtask vdr emit|check` (#396)

Each product digest's measurement record can be emitted as a CycloneDX 1.6 Vulnerability
Disclosure Report (`vdr.cdx.json`, pre-build lifecycle): components from the frozen lock (or the
release SBOM for the app), every RustSec finding from the custody-verified raw payload as a
`vulnerabilities[]` entry (RustSec source, alias references, CVSS or `severity: info` ratings,
`affects` by component bom-ref), the instruments in `metadata.tools.components` with hashes.
`analysis` is filled only from an ack's native `cyclonedx` ruling (state, justification,
response), never mapped from OpenVEX fields; acks without one are reported as burn-down.
`firstIssued` / `lastUpdated` are the earliest and latest ack for the instance. Each finding's
`affects[].versions` lists the measured version as `affected` and every patched or unaffected
requirement from the advisory as an `unaffected` Package URL `vers` range. Facts go in fields,
not prose: `analysis.detail` is a one-line summary, never a second copy of what the fields say. The
document is deterministic for the same inputs, so `vdr check` can regenerate and compare.
For a tool, each component's `scope` comes from the pinned binary itself: the emitter downloads
the content-addressed asset, checks it is the digest, reads the cargo-auditable `.dep-v0` list
(runtime and build kinds). That list is the RESOLVED graph, a superset of what was compiled:
on cargo-audit 5e1bf935c84c, 23 of 329 listed packages (defmt, quinn, ...) appear in no compile
line of the producer log. So only absence is decisive: a lock package missing from the list was
not built and is marked `excluded`; a listed one gets no scope. `evidence.identity` states the
method per component: manifest analysis always, the binary's list when it names the package.
"Code not present" is therefore measured in the report, not asserted in an ack; "code present"
is not claimed. Tool reports also carry the same resolved graph as `dependencies[]`, and a
package in the binary that the frozen lock does not list fails the emitter; both phases appear
in `metadata.lifecycles` (pre-build lock, post-build binary). The app's report links its release
SBOM by BOM-Link (`externalReferences` type `bom`, `urn:cdx:<serial>/<version>`) instead of
copying its graph. `serialNumber` is fixed per subject and `version` is the revision: identical
content keeps the committed version, changed content takes the next, so a published version
never changes meaning.
A `vdr.cdx.json` is committed beside the evidence of every live-frontier digest (each
`TOOLS.lock` pin and the latest release); the supply-chain workflow regenerates each pinned
tool's report and every release's report and fails on any difference, admitting the app's release
SBOM only after its provenance verifies. When a bless supersedes a tool digest, that digest's last
report stays committed as history and is no longer regenerated. A revision (rule 2) carries its
own report: the same `serialNumber`, the version after the superseded record's. The gate holds
every committed report to that ledger: never deleted, a changed one keeps its `serialNumber`
and takes a higher version, a new one is a current subject's, and each carries the
`serialNumber` derived from the digest directory it sits in.
A release's report is published by `release-vdr.yml` as an attestation to the shipped exe, never
as a release asset (a published release is immutable); `release-advance anchor` records each
revision's bundle beside the report as `vdr.v<version>.sigstore.jsonl`.

## Rules

1. **Acks bind to instances, not classes** — a new digest, engine, advisory instance, inventory
   content or verdict string is never covered by an old ack.
2. **Blessed evidence is immutable** — a digest that was ever pinned in `TOOLS.lock` on `main`
   keeps its evidence forever (forensic history), even after a later bless supersedes it. It is
   never edited: **a corrected measurement of a blessed digest is appended as a new revision
   bound to its lock, with reason and date** (`xtask/src/evidence_rev.rs`):

   ```text
   <tool>/<digest>/                     revision 1, the bless-time record
   <tool>/<digest>/rev/<lock-sha256>/   a later revision: revision.json, vuln.jsonl, caps.toml,
                                        build.jsonl, vdr.cdx.json
   ```

   Every reader of the lock-bound records (`vuln.jsonl`, `caps.toml`, `build.jsonl`,
   `vdr.cdx.json`) takes the one measured against the current `tools/locks/<tool>.lock`; none
   matching is an error, never a fallback. `mal.jsonl` stays at the digest: it describes bytes.
   A line whose digest the base commit already pins is a revision candidate whenever any of the
   tool's producer inputs changed (frozen lock, patches, build args, rustflags), and its upstream
   rev may not change. The gate admits a revision only when the new lock removes packages and
   changes nothing else, `revision.json` supersedes the base lock and names the patches the
   change carries, the build record is custody-verified from a producer run that rebuilt the same
   digest from exactly that lock and those patches and matches the superseded record message for
   message, and the vulnerability rows equal the raw payload, whose advisory-db commit is the
   header's and descends from the superseded record's, and a re-scan of the lock by the same
   scanner at that commit. A change that pins or revises a blessed digest leaves its root records
   byte for byte; an edit to them is its own PR (rule 4). Records under `rev/` are append-only and
   an admitted revision takes no new record; its `vdr.cdx.json` is re-emitted like any report.
   A revision only narrows: a lock never widens under one digest, so a narrowing is never undone,
   and a wider build is a new digest. A change that pins a digest anew may select only a revision
   the base commit already holds. `candidate-advance digest --reason …` writes one.
   **Candidate evidence is retired with the candidate**: a digest that was measured on a
   candidate branch but never blessed (its lock was re-frozen, its producer run superseded)
   has its evidence directory, its stored raw payload and any ack bound to it removed on that
   branch before the bless PR merges, so `main` only ever records digests that were real. The
   candidate branch's commit history keeps the measurements; nothing on `main` refers to them.
3. Consumer: `cargo xtask gate` (first-party Rust — no external pinned tool, no python runtime)
   diffs baseline↔candidate, applies the #241 verdict algebra, and fails a bump PR until every
   RAISE item is covered by a committed ack, printing the exact ack lines to add. Committing them
   **is** the sign-off; closing the PR is the reject. A change to `main` is judged by `main`:
   the workflow (`candidate-eval.yml`, on `pull_request_target`, which always runs `main`'s copy;
   it evaluates pull requests to `main` only), the gate's code and cargo configuration, and the
   floors
   (`supply-chain/policy/floors.json`), so a change to any of them takes effect for the changes
   after it, never for itself; a policy that does not load blocks every change. The change is
   GitHub's test merge into `main`'s current tip, checked out as data in its own directory, with
   no hooks and no filter drivers; nothing in it is built or run, and nothing it prints is a
   workflow command. The verdict is the commit status `candidate-eval/gate` on the pull
   request's head, taken from the event: `success` only when the gate exits 0 and the report's
   last line is the PASS line, `failure` on anything else. A head's status is shared by every
   pull request with that head, so each status names the pull request it judged and the run
   that posted it, and a verdict stands only while its pull request is open to `main` on that
   head. Every event of every pull request first withdraws (`failure`) what the pull request left,
   if its pending or pass is still that head's latest: the head it left on a push, and its head
   when it closes unmerged or is not, or no longer, to `main` (the workflow runs for every base for
   this). Then a pull request to `main` claims its head (`pending`) and its verdict follows,
   posted only while it is open and still that head on `main`, never from a cancelled run, and not
   over a newer run's status already there; a pass posted while the pull request closed, was
   pushed to or was retargeted is withdrawn by the verdict job itself, without reading the head
   again. No pull request defers to another: the latest evaluation of a head stands, whichever
   pull request it was for, so a later deny is never set aside for an earlier pass (and a pass got
   by evaluating again relies on every check failing closed, as they do). GitHub keeps at most
   1000 statuses per head and context and then accepts none, a withdrawal included: from 900 on,
   a head gets `failure` ("push a new commit") instead of `pending` or a pass, so a head that
   reaches the cap never ends on a pass; a withdrawal from a head that already shows a failure posts
   nothing. Posts are retried. A title or body edit runs nothing, and an event that is not
   evaluated has concurrency groups of its own, so it cancels no evaluation. The status is posted
   as a GitHub App only this workflow uses, allowed nothing but commit statuses; the required check
   names that App as its source, so a check run or status from anywhere else (a fork's own
   workflow posts as GitHub Actions) does not satisfy it. The App's key is a secret of the
   environment `gate`, which only `main` may use, and only the two jobs that post hold it, each on
   its own runner, taking nothing from the change but the verdict; the job that reads the change
   holds no key, can write nothing, and hands on only its verdict and report, which a third job,
   without the key, posts as the comment. A check run whose name is the context (ASCII case and
   spacing aside) is treated as an impersonation all the same, and the head gets `failure`. The
   report indents everything a change supplies, so no text from the change starts one of its
   lines; the comment names the head and base it judged. A maintainer dispatch reports in its run
   only. The scripts that post are tested as written in the workflow, against a fake GitHub API
   that keeps GitHub's cap, in the required `scan` check (`.github/tests/gate-status/test.py`;
   `mutate.py`, run by hand when the scripts change, breaks each guard and expects a failure);
   the trigger, the jobs' conditions and the
   concurrency groups are GitHub's to evaluate, and the scripts check the action, base and head
   themselves. This needs these repository settings: the status required on `main` with the App
   as its source, branches up to date before merging (a verdict is judged against `main`'s tip),
   squash merges only (a merge lands the tree the gate judged), auto-merge off, the environment
   `gate` limited to `main` (created before the workflow first runs: a run that names a missing
   environment creates it without rules), and an Actions policy that allows `pull_request_target`
   for this workflow, for every actor (GitHub blocks it by default in public repositories from
   2026-12-02). Approval before fork pull requests run workflows does not hold back this workflow
   (`pull_request_target` runs regardless); it delays a fork's own workflows, the ones that could
   create a check run named like the verdict or share a concurrency group with this one. What is
   left. A verdict is a status on the head, which every pull request with that head shares, and a
   pass leaves only when a later post lands on it; so a pass stays on a head its pull request left
   whenever that post does not land: an event that ran no workflow (GitHub Actions down, the
   policy missing), a post that failed all its retries, a verdict job stopped between its pass and
   its re-check (a fork's own workflow, once approved, can cancel it by sharing its concurrency
   group name), or posts starved on purpose: anyone can raise enough events (a pull request
   pushed back and forth) to exhaust the App's API quota, and while it lasts no post lands, a
   withdrawal included. A pull request opened from that head (anyone can: the commit is public)
   then shows the required check green, though its own evaluation fails. The status names the
   pull request it judged (`#<pr>: ...`), so a pass naming another pull request is not this one's
   pass: until merges are judged at merge time, merge only a pull request whose gate status names
   it. Besides: a pass is not judged again until an event on a pull request with that head, so
   advisories published after the evaluation are not seen until then; a verdict that reads the
   head just before a newer run posts lands after it, so the head shows the older verdict, for a
   pull request still open on it, until the newer run's verdict (or the next event, if that run
   posts none); and anyone who can open a pull request can make a head it shares show `failure`
   or `pending` (a failing evaluation, a head filled to 900 statuses, a fork workflow sharing a
   concurrency group name), which blocks.
4. **Evidence edits on the live frontier are candidates too (#380).** A PR that changes a pinned
   digest's `caps.toml` / `caps.UNEVALUATED` / `mal.jsonl` without touching TOOLS.lock is evaluated
   on the axes it touched, against the base commit's record (the workflow extracts that tree). An
   edited `vuln.jsonl` under a pinned digest is UNEVALUATED: baselines are written by the bless
   flow and backed by a stored raw payload, never edited in place. `mal.jsonl` history moves
   forward (above); a rewritten, removed or replayed panel is UNEVALUATED. Every product's
   changed `acks.jsonl` (the app's included) is quality-checked even when nothing else changed,
   and grows by lines: an edited or removed sign-off is UNEVALUATED (removing a later, narrower
   one would revive an earlier one). A sign-off is its signer's: the lines a change adds count
   only when the pull request was opened by a login the base's
   `supply-chain/policy/signers.json` lists, from a branch of this repository (a signed commit is
   public, and a withdrawn sign-off left on a branch could otherwise be carried into anyone's
   pull request), and every commit of the change whose diff against any parent touches an
   `acks.jsonl` is GitHub-verified and authored and committed by a listed login; an acks change
   with no such commit is refused. The `author` field inside a line is not the signature.
   "Verified" is GitHub's judgment of the signature, the trust boundary here. A web edit or an
   "update branch" merge is committed by GitHub, not a signer, and refused the same way.
   Edits under tool digests off the frontier are listed in the report and not evaluated. The
   app's records are judged as below (Products).
5. **Every reader reads the same input.** `tools/TOOLS.lock` has one grammar
   (`gate::tools_lock_problems`): every line, comments included, holds only ASCII graphic
   characters, spaces and tabs, so no locale or invisible character decides what a line says;
   the text before `#` is five fields; name and target are lowercase and every word starts and
   ends alphanumeric; one pin per (name, target); a digest names one pin; every target of a tool
   builds from one (repo, rev). Any other file is refused, never partly read. `fetch-tools`
   refuses the same files before any line is used (a test runs its bash against the gate's
   cases), and the workflows' `grep | sed | read` readers of the pins agree on a file that
   passes. A pin is unchanged only when the same (name, target) has the same repo, rev and
   digest; the same digest under another repo or rev is refused.
   The gate and `vdr check` read the working tree only when it is the index under `tools/` and
   `supply-chain/`: regular files whose bytes, unfiltered, are their blobs, nothing untracked.
   They refuse two spellings, differing only by case, of a path or of a name a reader opens
   (a pin's lock, patches, build args, rustflags, evidence records): the Windows checkout would
   read one through the other. `cargo-audit` reads `.cargo/audit.toml` from its working
   directory, so every xtask scan (`gate::audit_isolated`) and `deps-audit` scan a copy of the
   lock, or the binary by absolute path, in a fresh empty directory. The producer's pre-build
   posture scan (evidence, not a gate) does not yet.

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
The app's records are written by `cargo xtask release-advance <status|vuln|mal|anchor> --tag vX.Y.Z`
on an `evidence/*` branch (digest from the Release's SHA256SUMS; lock from the tag; VT lookup
first, submit only if absent), the counterpart of `candidate-advance` for tools.
The gate judges a change under an app digest as `release-advance` writes it. The digest carries
a provenance anchor. An anchor is added, never replaced or removed, and each line in it is, byte
for byte, the canonical serialization of a bundle GitHub's attestation store holds for the
digest, of the file's kind, with `hp-thermal.exe` at the digest among its subjects (provenance
from one of this repository's release workflows at a tag; `vdr.v<N>` the subject's own VDR at
version N). A first `vuln.jsonl` has the rows of its custody-verified raw payload, and those
rows are exactly what the pinned auditor finds re-scanning `app/Cargo.lock` at the commit the
release's provenance names, at the payload's advisory-db commit (a record made by another
scanner is not re-scanned and is refused). `mal.jsonl` moves forward under the monitor custody
above. `vdr.cdx.json` follows the report ledger. Anything else is UNEVALUATED.

`anchor` copies a release's original attestations, the Sigstore bundles GitHub stores for the
exe's digest, into `provenance.sigstore.jsonl`, `sbom.sigstore.jsonl`, and where the release has
them `sarif.sigstore.jsonl` and `vsa.sigstore.jsonl`. The digest is hashed from the published
exe. An original verifies against a release workflow at the tag's ref and commit, was made by
the tag push, and was logged before the release was published; every provenance subject must
still match its published file. Any other attestation signed at the tag stops the stage. VDR
revisions are anchored as `vdr.v<version>.sigstore.jsonl`: signed by `release-vdr.yml` at
`refs/heads/main`, dispatched, logged after the release was published, one serial. Each
bundle carries its Rekor inclusion proof, so the record checks against the public log without
GitHub's attestation store. Anchors are never replaced.
