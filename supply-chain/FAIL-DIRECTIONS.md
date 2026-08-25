# Fail-direction matrix

What each enforcement mechanism does **when it fails or lacks data** — and whether that
direction is secure. "Fail-closed" and "fail-secure" are not synonyms of "works": a
mechanism can fail *noisy* (secure, annoying), fail *silent-blocking* (secure, confusing),
or fail *open* (insecure — proceeds as if fine). This file is the honest inventory.

## Anti-staleness contract (read before editing anything this file describes)

Claims documents about enforcement behavior rot unless updates are structurally forced.
Two rules keep this one honest:

1. **Every row carries an anchor**: the pinning unit test that breaks if the behavior
   changes, or the tracked issue for open items, or the enforcing file:step for behavior
   that lives in workflow/action code. Rows without anchors are not accepted.
2. **Same-diff rule**: a PR that changes a listed mechanism's failure behavior updates its
   row in the same diff. Reviewers should treat a mechanism change without a matrix change
   as incomplete.

Verdict vocabulary: **CLOSED/secure** (failure blocks or pages), **OPEN/insecure**
(failure passes silently), **OPEN/deliberate** (advisory by design, accepted).

## Admission (change-triggered gates)

| mechanism | on failure / absence | direction | anchor |
|---|---|---|---|
| fetch-tools digest verify | abort before any tool executes; all-zero digest = not blessed = abort | CLOSED/secure | `.github/actions/fetch-tools/action.yml` (sha256sum -c, zero-digest guard) |
| fetch-tools attestation verify (opt-in) | abort on missing/invalid SLSA provenance | CLOSED/secure | `.github/actions/fetch-tools/action.yml` (gh attestation verify) |
| gate: UNEVALUATED (missing evidence, wrong-digest mal record, malformed acks) | blocks; cannot be acked away | CLOSED/secure | tests `mal_digest_mismatch_is_unevaluated`, `malformed_ack_file_is_hard_error` (gate.rs) |
| gate: unacked RAISE item | blocks until the ack line is committed | CLOSED/secure | test `vuln_unacked_carried_blocks` (gate.rs) |
| gate: ack quality (empty/TODO reason, missing author/timestamp) | ack does not count | CLOSED/secure | test `ack_quality_rejects_placeholder_and_missing_author` (gate.rs) |
| gate/monitor: lock resolution (#255 §5) | frozen lock overrides upstream; absence falls through to upstream, never retro-applied to base | CLOSED/secure | test `frozen_lock_overrides_upstream_and_absence_falls_through` (gate.rs) |
| freeze: yanked / unsoaked / nonexistent target | refuses before touching a repo | CLOSED/secure | `check_target` (freeze.rs; network path — code anchor) |
| freeze: genuinely-new advisory or grown instance count | refuses (override is explicit `--allow-added-advisories`) | CLOSED/secure | tests `new_advisory_key_is_genuine`, `grown_instance_count_is_genuine`, `newly_yanked_package_cannot_hide_behind_existing_yanked_findings` (freeze.rs) |
| freeze: unreachable target (resolver conflict) | refuses with escalation-ladder pointer | CLOSED/secure | run-path in freeze.rs; disambiguation gap tracked #255 |
| caps gate, PE tools + release exe | missing manifest / off-allowlist import / denied function / stale allow entry → no bless | CLOSED/secure | tests `off_allowlist_import_fails`, `stale_allow_entry_fails_ratchet`, `deny_cannot_be_weakened_below_baseline` (caps.rs); producer step in build-tools.yml |
| **caps gate, cargo-acl (linux/ELF)** | **no ELF walker → binary uploads ungated** | **OPEN/insecure** | tracked **#245** (ELF follow-up); caps evidence honestly UNEVALUATED meanwhile |
| dependency-review on PR diffs | flags high-severity additions | CLOSED once **required**; until then advisory | control-plane click tracked **#261** |
| **gate as a merge blocker** | red `evaluate` check blocks merge **only if required** in the ruleset | **OPEN until required** | control-plane click tracked **#261** |

## Continuous monitoring (scheduled)

| mechanism | on failure / absence | direction | anchor |
|---|---|---|---|
| vt-monitor: VT response parse failure | fails the run (never reads as 0 detections) | CLOSED/secure | supply-chain-monitor.yml (fail-closed jq parse) |
| vt-monitor: new unacked (hash, engine) detection | fails the run → pages | CLOSED/secure | supply-chain-monitor.yml (ack-lattice check) |
| **vt-monitor: digest not in VT corpus** | warns, does not page | **OPEN-ish (transitional)** | supply-chain-monitor.yml; bounded because the gate blocks bless without mal evidence, so blessed digests should already be in corpus |
| monitor-vuln: missing baseline / malformed acks / fetch or scan failure | UNEVALUATED → run fails | CLOSED/secure | test `missing_baseline_is_none_not_empty_set` (monitor.rs) |
| monitor-vuln: new unacked advisory instance | fails the run, prints the ack line | CLOSED/secure | monitor.rs run-path; classification pinned by `classify_splits_new_carried_gone` |
| pin-staleness / runner-family probe | warn-only | OPEN/deliberate | supply-chain-monitor.yml (advisory by design: staleness is not compromise) |
| **schedule liveness itself** | a dead schedule (GitHub 60-day auto-disable, trigger-level error) is silent — absence of signal reads as health | **OPEN/insecure** | tracked **#260** (dead-man's switch) |

## Process-level (not yet mechanized)

| rule | risk if skipped | direction | anchor |
|---|---|---|---|
| Evidence for a frozen-lock digest must be generated from the frozen lock | baseline poisoning: future knowledge-deltas inherit the wrong instrument | OPEN (process discipline) until evidence generation is mechanized | #255 §5 discussion; enforced by review until then |
| Freeze directive lists must be COMPLETE (lock = f(rev, directives)) | re-freezing without an earlier directive silently drops that fix | OPEN (documented trap) | candidate-freeze.yml docs; tools/locks/README.md |
| vt-monitor mal-ack lookup (#278) | oracle build/run failure, malformed or quality-rejected lattice entries | fail-secure: yields NO acked engines → every detection pages; problems surfaced as warnings | `mal_acks_tests` in xtask/src/gate.rs (quality-reject + missing-lattice cases) |
| caps axis epistemics (#245) | a binary acts via direct syscalls or dynamic resolution the import table never names | OVERSTATES safety if read as exhaustive: caps prove CHANGE DETECTION over a statically visible surface, not containment. Absent caps evidence is UNEVALUATED and fails closed (#241 s3); PRESENT caps evidence is a lower bound, not a guarantee | module docs in xtask/src/caps.rs; #223 negative-control canaries |
| checker integrity (#223) | a gating tool goes blind (sabotaged xdep, upstream regression, config rot) and reports CLEAN | fail-closed: the negative-control canary requires POSITIVE evidence (the planted advisory ID) in the tool's own output before any verdict from it is admissible; a bare non-zero exit is BROKEN, not detection | `xtask canary` + supply-chain/canaries/; unit tests in xtask/src/canary.rs |
| toolchain vuln axis (#267) | advisory fetch fails, is rate-limited, returns an empty array, or carries a version range we cannot parse | fail-closed: empty set is refused as a FETCH FAILURE (rust-lang/rust has known advisories, so zero cannot be a clean result), and an unparseable range counts as UNEVALUATED which is not a pass | `xtask toolchain-advisories` + unit tests; workflow re-checks non-emptiness before evaluating |
| codegen hardening posture (#267) | a toolchain bump silently changes emitted mitigations (CFG/ASLR/DEP/high-entropy) | fail-closed both directions: a LOST mitigation is a regression, a GAINED one still needs review so the manifest keeps describing the artifact, and a manifest with no `hardening` key is UNEVALUATED rather than exempt. HARDENING_FLOOR cannot be waived by any manifest | `hardening` in supply-chain/policy/caps/*.json; 6 unit tests in xtask/src/caps.rs |
| ELF caps + hardening (#245) | linux binary is unparseable, is ELF32, or the producer's linux glob matches nothing | fail-closed: an unwalkable image is refused rather than measured as empty; ELF32 is DECLINED rather than parsed with 64-bit offsets (a mis-parse reports a confident wrong answer); a glob matching zero binaries fails instead of reporting a pass | `xtask/src/elf.rs` tests; producer linux caps step `found` guard |
| toolchain pin (#267) | channel manifest re-published or tampered; TOOLCHAIN.lock and app/rust-toolchain.toml disagree; lock file missing | fail-closed on all three: digest mismatch refuses to install, drift between the two declarations is an error rather than a preference, and a missing lock fails because the pin IS the policy | `.github/actions/install-toolchain` (bash, since install precedes cargo) |

## How to update this file

Add a row when a new enforcement mechanism lands (same PR). Move a row between
CLOSED/OPEN when behavior changes (same PR). When an OPEN item's issue closes, update the
row to CLOSED and swap the issue anchor for the pinning test. Link issues inline — the
open rows are the working burn-down list for the enforcement layer itself.
