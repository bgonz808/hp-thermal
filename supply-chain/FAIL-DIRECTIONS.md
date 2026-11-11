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
| gate/monitor: absolute floors (vuln critical-shape vector, mal engine count / sandbox verdict, caps new `process`/`net` grant) | HARD-STOP in the gate, FAIL in the monitor — acks do not apply; missing or malformed `supply-chain/policy/floors.json` = UNEVALUATED for every candidate | CLOSED/secure | tests `critical_shape_trips_on_3x_and_4_0_but_not_on_dos_or_local`, `mal_floor_on_engine_count_and_sandbox_verdict`, `caps_floor_trips_only_on_a_new_shipping_grant_of_a_floor_class`, `missing_schema_or_bad_json_is_an_error_not_no_floors` (floors.rs); `.github/workflows/supply-chain-monitor.yml` (vt-monitor floor) |
| gate: caps strict-subset ALLOW (#367) | applies only to a MEASURED head whose header records `cackle exit 0` and the candidate lock's sha256, non-empty, no vanished section for a package in both locks, no addition of any section/key/value, instrument identical; ANY unmet condition falls back to RAISE (ack path), never ALLOW | CLOSED/secure | tests `empty_partial_or_unproven_measurements_are_not_subsets`, `vanished_section_is_a_gap_unless_the_package_left_the_lock`, `any_addition_or_instrument_change_refuses` (caps_subset.rs); `nist_vectors` (sha256.rs) |
| gate: ack quality (empty/TODO reason, missing author/timestamp) | ack does not count | CLOSED/secure | test `ack_quality_rejects_placeholder_and_missing_author` (gate.rs) |
| gate/monitor: lock resolution (#255 §5) | frozen lock overrides upstream; absence falls through to upstream, never retro-applied to base | CLOSED/secure | test `frozen_lock_overrides_upstream_and_absence_falls_through` (gate.rs) |
| freeze: yanked / unsoaked / nonexistent target | refuses before touching a repo | CLOSED/secure | `check_target` (freeze.rs; network path — code anchor) |
| freeze: genuinely-new advisory or grown instance count | refuses (override is explicit `--allow-added-advisories`) | CLOSED/secure | tests `new_advisory_key_is_genuine`, `grown_instance_count_is_genuine`, `newly_yanked_package_cannot_hide_behind_existing_yanked_findings` (freeze.rs) |
| freeze: unreachable target (resolver conflict) | refuses with escalation-ladder pointer | CLOSED/secure | run-path in freeze.rs; disambiguation gap tracked #255 |
| caps gate, PE tools + release exe | missing manifest / off-allowlist import / denied function / stale allow entry → no bless | CLOSED/secure | tests `off_allowlist_import_fails`, `stale_allow_entry_fails_ratchet`, `deny_cannot_be_weakened_below_baseline` (caps.rs); producer step in build-tools.yml |
| **caps gate, cargo-acl (linux/ELF)** | **no ELF walker → binary uploads ungated** | **OPEN/insecure** | tracked **#245** (ELF follow-up); caps evidence honestly UNEVALUATED meanwhile |
| dependency-review on PR diffs | flags high-severity additions | CLOSED once **required**; until then advisory | control-plane click tracked **#261** |
| **gate as a merge blocker** | red `evaluate` check blocks merge **only if required** in the ruleset | **OPEN until required** | control-plane click tracked **#261** |
| BinSkim release gate, SARIF result with no `kind`/`level` (#385) | counted as a finding: SARIF 2.1.0 defaults (kind fail, level warning) are applied before counting; a kind outside the enumeration also counts as fail; the gating scan then fails on it | CLOSED/secure (was OPEN/insecure 2026-08-17..2026-11-10: BA2024 on two releases counted as nothing) | `.github/actions/binskim-scan/sarif-triage.ps1`; self-test step on `fixtures/kindless-result.sarif` runs before every scan |
| Spectre-mitigated CRT selection (#385) | the toolset's `lib/spectre/<arch>` is missing or holds no libcmt.lib, or link.exe cannot be located | fail-closed: the build fails with the VS component to install, rather than linking the unmitigated CRT that the LIB default would silently supply; BinSkim BA2024 independently gates the release on the linked result | `app/build.rs` Spectre block (find-msvc-tools discovery, the crate rustc uses for link.exe); BinSkim release scan |
| vuln statement grounded in the DB's silence (#251) | an instance recorded `not_affected` with property `hp-thermal:observed-absent-at-db` is reported again | fail-closed: a statement grounded in absence is void as coverage once the DB reports the instance, so the reappearance is RAISE uncovered until signed afresh; `fixed` is rejected on the vuln axis (immutable subject) | `ack_covers_vuln` / `observed_absent_at_db`; test `observed_absent_statement_is_void_for_a_reported_instance_and_later_affected_restores_it` |
| monitor-vuln DB ordering (#251) | the fetched advisory DB is not a descendant of the baseline's recorded commit, or either commit is unknown | UNEVALUATED for the pin: GONE against an older or unrelated DB is meaningless | `db_descends` (`git merge-base --is-ancestor` in cargo-audit's clone) |
| monitor-vuln lock drift (#251) | a GONE instance's package@version is absent from the lock the monitor evaluated | UNEVALUATED, not GONE: the lock no longer matches the one the blessed bytes were built from | `lock_contains` |
| monitor-vuln mechanism (#251) | the advisory file for a GONE instance is not in the DB clone | UNEVALUATED; no statement template is printed (a justification that cannot be named is not asserted) | `gone_mechanism` |
| binary-vantage scan precondition (#386) | the shipped exe or a produced tool has no `.dep-v0` section, an empty one, or one that is not a zlib stream | fail-closed: `verify-auditable` refuses before `cargo audit bin` runs; on its own that scan recovers a PARTIAL list from panic strings and exits 0, so a missing section would read as cleaner | `auditable::verify` (in-tree PE/ELF section parsing); release-attest and build-tools.yml (Windows lane gates, Linux lane warns until a blessed cargo-auditable linux-x86_64 exists) |
| PE timestamp stamp (#104, fleet) | `stamp-time` or `verify-timestamp --expect` fails for a produced Windows tool (unparseable PE, bytes moved outside the timestamp fields, COFF stamp != the pinned rev's commit epoch, surviving REPRO marker) | that tool is a build failure: no digest, no attestation, no upload; an unstamped `/Brepro` hash never ships silently | build-tools.yml Windows lane, after link and before the digest; `--expect` is exact equality, so a wrong epoch cannot pass as plausible |
| linux lane bootstrap (#386 step 3) | TOOLS.lock holds no blessed `cargo-auditable linux-x86_64` (all-zero digest) | the lane builds plain, warns per binary, and the run is the bootstrap whose output becomes that member; once blessed, the lane builds through it and `verify-auditable` gates every linux tool | build-tools.yml steps `lx-aud` / `lx-aud-tool` |
| monitor-vuln rawPayload custody | a baseline's backing cargo-audit report is missing from the `tools` release store, its store digest differs from the recorded sha256, the header has no pointer, or the store cannot be listed | UNEVALUATED for the pin: the recorded instance set has no verifiable backing | `raw_payload_custody` / `store_digests` (GitHub asset digest, no download) |

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
