//! `cargo xtask gate` — the 3-axis candidate-evaluation gate (#241).
//!
//! Evaluates TOOLS.lock candidates (base vs head) against the per-digest evidence
//! store (`supply-chain/evidence/`, #241 §7). Per-axis verdicts: ALLOW / RAISE(covered) /
//! RAISE(uncovered) / UNEVALUATED / HARD-STOP. Combination is a lattice — no scores,
//! no cross-axis trades (#241 §2): any HARD-STOP blocks; all-ALLOW is sunny-day;
//! everything else needs each RAISE item covered by a committed ack in
//! `supply-chain/evidence/<tool>/acks.jsonl`. Committing the printed ack line IS the
//! sign-off; closing the PR is the reject. UNEVALUATED can never be acked away
//! (fail-secure, #241 §3) — fill the missing evidence instead.
//!
//! Point-in-time discipline (#241 §5): the vuln axis re-scans BOTH revs here, now,
//! against one advisory-DB state (first run fetches, second runs --no-fetch), so the
//! diff isolates the code delta from the knowledge delta. The recorded baseline in
//! the store is audit trail, never the comparison input.
//!
//! Policy lives HERE, in reviewed, unit-tested Rust — not in workflow bash. The
//! workflow is a thin invoker. JSON is parsed with serde_json (zero RustSec
//! advisories on record; adopted over a bespoke parser deliberately — see #241).

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

const ZERO_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

// ---------- TOOLS.lock ----------

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ToolLine {
    pub(crate) name: String,
    pub(crate) repo: String,
    pub(crate) rev: String,
    pub(crate) target: String,
    pub(crate) sha: String,
}

/// Parse TOOLS.lock: strip comments/blank lines, take the 5 whitespace-separated
/// columns (`name repo rev target sha256`), ignoring the trailing `# vX` comment.
pub(crate) fn parse_tools_lock(text: &str) -> Vec<ToolLine> {
    text.lines()
        .map(|l| l.find('#').map_or(l, |i| &l[..i]).trim())
        .filter(|l| !l.is_empty())
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() == 5).then(|| ToolLine {
                name: f[0].into(),
                repo: f[1].into(),
                rev: f[2].into(),
                target: f[3].into(),
                sha: f[4].into(),
            })
        })
        .collect()
}

/// Candidates = head entries that are new or whose rev/digest changed vs base. An entry is
/// identified by (name, target): one tool may be produced for several targets (#386 step 3,
/// cargo-auditable on both lanes), and each target's bytes are their own candidate.
///
/// Baseline for a target seen for the first time: the same tool's blessed entry on another
/// target. The compared inventories are properties of the tree + lock, not of the target —
/// caps is measured linux-natively for every lane, vuln scans the lock — so a cross-target
/// base is the true prior state and only the differences (none when the rev is the same) need
/// review. mal is per digest and never compared against a base.
fn candidates(base: &[ToolLine], head: &[ToolLine]) -> Vec<(Option<ToolLine>, ToolLine)> {
    head.iter()
        .filter_map(|h| {
            let b = base
                .iter()
                .find(|b| b.name == h.name && b.target == h.target)
                .or_else(|| base.iter().find(|b| b.name == h.name));
            match b {
                Some(b) if b.rev == h.rev && b.sha == h.sha => None,
                _ => Some((b.cloned(), h.clone())),
            }
        })
        .collect()
}

// ---------- advisory instances (#241 §6: identity is the instance tuple) ----------

/// (advisory-ID, package, resident-version). `kind` is display-only — matching uses
/// the triple, so an advisory reclassified vuln<->warning still pairs up.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Instance {
    pub(crate) id: String,
    pub(crate) package: String,
    pub(crate) version: String,
    pub(crate) kind: String,
}

/// Extract instance tuples from `cargo audit --json` output.
pub(crate) fn extract_instances(audit: &Value) -> BTreeSet<Instance> {
    let mut out = BTreeSet::new();
    if let Some(list) = audit
        .get("vulnerabilities")
        .and_then(|v| v.get("list"))
        .and_then(Value::as_array)
    {
        for e in list {
            if let Some(i) = entry_instance(e, "vulnerability") {
                out.insert(i);
            }
        }
    }
    if let Some(w) = audit.get("warnings").and_then(Value::as_object) {
        for (kind, arr) in w {
            for e in arr.as_array().into_iter().flatten() {
                if let Some(i) = entry_instance(e, kind) {
                    out.insert(i);
                }
            }
        }
    }
    out
}

fn entry_instance(e: &Value, kind: &str) -> Option<Instance> {
    let pkg = e.get("package")?;
    Some(Instance {
        // Warnings like `yanked` carry no advisory object — the kind itself is the id.
        id: e
            .get("advisory")
            .and_then(|a| a.get("id"))
            .and_then(Value::as_str)
            .unwrap_or(kind)
            .to_string(),
        package: pkg.get("name")?.as_str()?.to_string(),
        version: pkg.get("version")?.as_str()?.to_string(),
        kind: kind.to_string(),
    })
}

/// The paired diff: (added, fixed, carried) by instance triple (id, package, version).
fn diff_instances(
    base: &BTreeSet<Instance>,
    head: &BTreeSet<Instance>,
) -> (Vec<Instance>, Vec<Instance>, Vec<Instance>) {
    let key = |i: &Instance| (i.id.clone(), i.package.clone(), i.version.clone());
    let bk: BTreeSet<_> = base.iter().map(key).collect();
    let hk: BTreeSet<_> = head.iter().map(key).collect();
    let added = head
        .iter()
        .filter(|i| !bk.contains(&key(i)))
        .cloned()
        .collect();
    let fixed = base
        .iter()
        .filter(|i| !hk.contains(&key(i)))
        .cloned()
        .collect();
    let carried = head
        .iter()
        .filter(|i| bk.contains(&key(i)))
        .cloned()
        .collect();
    (added, fixed, carried)
}

// ---------- acks (OpenVEX-aligned JSONL; #241 §7) ----------

/// A loaded, QUALITY-CHECKED ack. Acks failing the quality bar (empty/TODO reason,
/// missing author or timestamp) are reported and DO NOT COUNT — a sign-off must
/// actually say who accepted what and why.
pub(crate) struct Acks {
    pub(crate) entries: Vec<Value>,
    pub(crate) rejected: Vec<String>,
}

pub(crate) fn load_acks(path: &Path) -> Result<Acks, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Acks {
                entries: Vec::new(),
                rejected: Vec::new(),
            });
        }
        Err(e) => return Err(format!("read {}: {e}", path.display())),
    };
    let mut entries = Vec::new();
    let mut rejected = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // A malformed ack line is a hard parse error, not a skip — fail-secure: a
        // silently-dropped ack could flip a verdict either direction.
        let v: Value = serde_json::from_str(line)
            .map_err(|e| format!("{}:{}: invalid JSON: {e}", path.display(), n + 1))?;
        match ack_quality(&v) {
            Ok(()) => entries.push(v),
            Err(why) => rejected.push(format!("{}:{}: {why}", path.display(), n + 1)),
        }
    }
    Ok(Acks { entries, rejected })
}

fn ack_quality(v: &Value) -> Result<(), String> {
    let notes = v.get("status_notes").and_then(Value::as_str).unwrap_or("");
    if notes.trim().is_empty() || notes.contains("TODO") {
        return Err("status_notes empty or placeholder — a sign-off must say why".into());
    }
    if v.get("author")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .is_empty()
    {
        return Err("author missing".into());
    }
    if v.get("timestamp")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .is_empty()
    {
        return Err("timestamp missing".into());
    }
    // #251: the subject of a vuln statement is an immutable blessed binary. OpenVEX `fixed`
    // ("these product versions contain a fix") can never be true of it; an advisory that stops
    // applying is recorded as `not_affected`. CISA's minimum requirements for VEX: a
    // `not_affected` statement MUST carry a `justification` or an `impact_statement`.
    if s(v, &["axis"]) == "vuln" {
        match s(v, &["status"]) {
            "fixed" => {
                return Err(
                    "status `fixed` is impossible for immutable blessed bytes (#251); record \
                     `not_affected` with a justification"
                        .into(),
                );
            }
            "not_affected"
                if s(v, &["justification"]).is_empty()
                    && s(v, &["impact_statement"]).is_empty() =>
            {
                return Err(
                    "not_affected without `justification` or `impact_statement` (CISA VEX minimum \
                     requirements)"
                        .into(),
                );
            }
            _ => {}
        }
    }
    // #380: a sign-off names WHAT it signs. A caps ack binds to the sha256 of the inventory
    // bytes; a mal ack binds to the engine AND its verdict string. Without those fields the
    // line is not a usable sign-off and is rejected (reported, never counted).
    match s(v, &["axis"]) {
        "caps" => {
            let h = s(v, &["evidence_sha256"]);
            if h.len() != 64
                || !h
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                return Err(
                    "caps ack without `evidence_sha256` (64 lowercase hex of the caps.toml it \
                     signs, #380) — it would cover any rewrite of that inventory"
                        .into(),
                );
            }
        }
        "lock-shape" if s(v, &["package", "name"]).is_empty() => {
            return Err(
                "lock-shape statement without `package.name` -- it must name the one package it                  accepts into the frozen lock"
                    .into(),
            );
        }
        "mal"
            if s(v, &["finding", "engine"]).is_empty()
                || s(v, &["finding", "result"]).is_empty() =>
        {
            return Err(
                "mal ack without `finding.engine` and `finding.result` (#380) — a finding is                  engine + verdict, not engine alone"
                    .into(),
            );
        }
        _ => {}
    }
    Ok(())
}

fn s<'a>(v: &'a Value, path: &[&str]) -> &'a str {
    let mut cur = v;
    for p in path {
        match cur.get(p) {
            Some(n) => cur = n,
            None => return "",
        }
    }
    cur.as_str().unwrap_or("")
}

/// The LAST quality-passing vuln statement for this instance, in file order. acks.jsonl is
/// append-only, so file order is statement order — the OpenVEX sequence model (#251): a later
/// statement supersedes an earlier one for the same product + vulnerability.
pub(crate) fn last_vuln_ack<'a>(acks: &'a Acks, inst: &Instance) -> Option<&'a Value> {
    acks.entries.iter().rev().find(|a| {
        s(a, &["axis"]) == "vuln"
            && s(a, &["vulnerability", "name"]) == inst.id
            && s(a, &["product", "package"]) == inst.package
            && s(a, &["product", "version"]) == inst.version
    })
}

/// CycloneDX-style property (`properties: [{name, value}]`) naming the advisory-DB commit at
/// which `monitor-vuln` observed the instance ABSENT. A statement carrying it is grounded in
/// that observation, not in a review of the code (#251). Dropped on OpenVEX export.
pub(crate) const OBSERVED_ABSENT_PROP: &str = "hp-thermal:observed-absent-at-db";

pub(crate) fn observed_absent_at_db(a: &Value) -> Option<&str> {
    a.get("properties")?
        .as_array()?
        .iter()
        .find(|p| s(p, &["name"]) == OBSERVED_ABSENT_PROP)
        .map(|p| s(p, &["value"]))
        .filter(|v| !v.is_empty())
}

/// Covered iff the instance's LAST statement is not grounded in the DB's silence. Coverage is
/// only ever asked about an instance the DB reports NOW, so a last statement that says "the DB
/// did not report it" is contradicted by the measurement and void: the reappearance is RAISE
/// uncovered until signed afresh (fail-closed, #251). Nothing is committed from CI for this.
pub(crate) fn ack_covers_vuln(acks: &Acks, inst: &Instance) -> bool {
    last_vuln_ack(acks, inst).is_some_and(|a| observed_absent_at_db(a).is_none())
}

/// A mal ack covers one FINDING: (digest, engine, result). The result string is part of the
/// finding's identity (#380): the same engine renaming its verdict — `Wacatac.B!ml` becoming a
/// named family — is a new claim about the bytes, not the one that was reviewed.
fn ack_covers_mal(acks: &Acks, digest: &str, engine: &str, result: &str) -> bool {
    acks.entries.iter().any(|a| {
        s(a, &["axis"]) == "mal"
            && s(a, &["product", "digest"]) == digest
            && s(a, &["finding", "engine"]) == engine
            && s(a, &["finding", "result"]) == result
    })
}

/// A caps ack covers one INVENTORY: (digest, sha256 of the caps.toml bytes it signed). #380:
/// before this, `(axis, digest)` alone matched, so rewriting a blessed digest's caps.toml with
/// new grants rode through under the old signature. An ack without `evidence_sha256` is
/// quality-rejected (see `ack_quality`) and never reaches here.
fn ack_covers_caps(acks: &Acks, digest: &str, caps_sha256: &str) -> bool {
    acks.entries.iter().any(|a| {
        s(a, &["axis"]) == "caps"
            && s(a, &["product", "digest"]) == digest
            && s(a, &["evidence_sha256"]) == caps_sha256
    })
}

/// Findings with a quality-passing mal ack for `digest`, as `engine<TAB>result` lines — the
/// ONE mal-ack semantics, shared by the gate (ack_covers_mal) and the weekly vt-monitor
/// (#278, result-bound since #380). Sorted, deduped.
pub(crate) fn mal_acked_findings(acks: &Acks, digest: &str) -> Vec<String> {
    let mut out: Vec<String> = acks
        .entries
        .iter()
        .filter(|a| s(a, &["axis"]) == "mal" && s(a, &["product", "digest"]) == digest)
        .map(|a| {
            format!(
                "{}\t{}",
                s(a, &["finding", "engine"]),
                s(a, &["finding", "result"])
            )
        })
        .filter(|e| !e.starts_with('\t'))
        .collect();
    out.sort();
    out.dedup();
    out
}

/// `xtask mal-acks --tool <name> --digest <sha256> [--evidence-dir <dir>]`
///
/// Prints the acked findings (`engine<TAB>result`, one per line) for the given product
/// digest, read from the SAME evidence lattice the gate consults
/// (supply-chain/evidence/<tool>/acks.jsonl). #278: retires the parallel flat-file lattice the
/// monitor used to read; #380: the result string is part of what was acked.
///
/// Fail direction (fail-SECURE for a monitor): any problem — unreadable lattice, malformed
/// JSONL, quality-rejected entries — yields FEWER acked engines, never more, so detections
/// page rather than silently pass. Problems are surfaced on stderr; exit is 0 unless the
/// arguments themselves are invalid.
pub(crate) fn mal_acks_run(args: &[String]) -> i32 {
    let mut tool: Option<&str> = None;
    let mut digest: Option<&str> = None;
    let mut dir = "supply-chain/evidence".to_string();
    let mut it = args.iter().skip(1); // skip the subcommand token
    while let Some(a) = it.next() {
        match a.as_str() {
            "--tool" => tool = it.next().map(String::as_str),
            "--digest" => digest = it.next().map(String::as_str),
            "--evidence-dir" => {
                if let Some(d) = it.next() {
                    dir = d.clone();
                }
            }
            other => {
                eprintln!("mal-acks: unknown argument '{other}'");
                return 2;
            }
        }
    }
    let (Some(tool), Some(digest)) = (tool, digest) else {
        eprintln!("usage: xtask mal-acks --tool <name> --digest <sha256> [--evidence-dir <dir>]");
        return 2;
    };
    if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        eprintln!(
            "mal-acks: --digest must be a full 64-hex sha256 (got {} chars)",
            digest.len()
        );
        return 2;
    }
    let path = Path::new(&dir).join(tool).join("acks.jsonl");
    match load_acks(&path) {
        Ok(acks) => {
            for r in &acks.rejected {
                eprintln!("warning: quality-rejected ack ignored (does not silence): {r}");
            }
            for e in mal_acked_findings(&acks, digest) {
                println!("{e}");
            }
            0
        }
        Err(e) => {
            eprintln!("warning: ack lattice unreadable ({e}) — treating as NO acks (fail-secure)");
            0
        }
    }
}

/// The exact line a maintainer commits to sign off — printed by the failing gate.
/// status_notes is deliberately empty: the quality bar refuses it until a human writes the
/// reason (no rubber-stamp path). The ack carries the RULING: the OpenVEX status and the native
/// CycloneDX `state` / `justification` / `response` the VDR copies. It starts at `in_triage`, the
/// one state that claims nothing. Measured facts (binary presence, version ranges, digests,
/// dependency paths) live in the VDR's own fields and are not restated in the notes. Caps acks use `reviewed`: a caps ack signs an inventory, not a
/// vulnerability status, so the OpenVEX statuses do not apply there. The gate reads `status` for
/// exactly one thing: a vuln statement whose status is `fixed` withdraws coverage (#251).
pub(crate) fn ack_template_vuln(tool: &str, inst: &Instance) -> String {
    serde_json::json!({
        "schema": "hp-thermal/evidence-ack/v1",
        "axis": "vuln",
        "vulnerability": {"name": inst.id},
        "product": {"name": tool, "package": inst.package, "version": inst.version},
        "status": "affected",
        "cyclonedx": {"state": "in_triage"},
        "status_notes": "",
        "author": "",
        "timestamp": "",
        "refs": []
    })
    .to_string()
}

/// Why RustSec stopped reporting an instance, read from the advisory file in the DB clone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GoneMechanism {
    /// `withdrawn = "<date>"` set on the advisory (CycloneDX `vulnerability.rejected`).
    Withdrawn(String),
    /// Advisory still published; its `[versions]` no longer cover this version.
    VersionsNarrowed,
}

/// OpenVEX `not_affected` statement for an instance the monitor classified as GONE (#251).
/// Justification `vulnerable_code_not_present` is the catalogue label for "component included,
/// vulnerable code not present" — which is what a withdrawal or a narrowed range asserts about
/// this version. The DB commit rides as a CycloneDX-style property so the gate can void the
/// statement if the DB reports the instance again. Author and timestamp stay blank so the
/// quality bar still demands a signer. Appended, never replacing — the sequence is the record.
pub(crate) fn ack_template_vuln_not_affected_observed(
    tool: &str,
    inst: &Instance,
    db: &str,
    how: &GoneMechanism,
) -> String {
    let mechanism = match how {
        GoneMechanism::Withdrawn(d) => format!("advisory withdrawn {d}"),
        GoneMechanism::VersionsNarrowed => format!(
            "advisory still published; its [versions] no longer cover {}",
            inst.version
        ),
    };
    serde_json::json!({
        "schema": "hp-thermal/evidence-ack/v1",
        "axis": "vuln",
        "vulnerability": {"name": inst.id},
        "product": {"name": tool, "package": inst.package, "version": inst.version},
        "status": "not_affected",
        "justification": "vulnerable_code_not_present",
        "status_notes": format!(
            "not reported by RustSec against {} {} at advisory DB {}: {mechanism} (monitor-vuln); supersedes the earlier statement for this instance",
            inst.package,
            inst.version,
            &db[..12.min(db.len())]
        ),
        "properties": [{"name": OBSERVED_ABSENT_PROP, "value": db}],
        "author": "",
        "timestamp": "",
        "refs": ["#251"]
    })
    .to_string()
}

fn ack_template_mal(tool: &str, digest: &str, engine: &str, result: &str) -> String {
    serde_json::json!({
        "schema": "hp-thermal/evidence-ack/v1",
        "axis": "mal",
        "finding": {"engine": engine, "result": result},
        "product": {"name": tool, "digest": digest},
        "status": "not_affected",
        "status_notes": "",
        "author": "",
        "timestamp": "",
        "refs": []
    })
    .to_string()
}

fn ack_template_caps(tool: &str, digest: &str, caps_sha256: &str) -> String {
    serde_json::json!({
        "schema": "hp-thermal/evidence-ack/v1",
        "axis": "caps",
        "product": {"name": tool, "digest": digest},
        "evidence_sha256": caps_sha256,
        "status": "reviewed",
        "status_notes": "",
        "author": "",
        "timestamp": "",
        "refs": []
    })
    .to_string()
}

// ---------- per-axis verdicts (#241 §2) ----------

#[derive(Debug, PartialEq)]
enum Verdict {
    Allow(String),
    /// RAISE with every item covered by a quality ack — mergeable; merge = sign-off.
    RaiseCovered(Vec<String>),
    /// RAISE with uncovered items — blocks; each String is a ready-to-commit ack line.
    RaiseUncovered {
        covered: Vec<String>,
        needed: Vec<String>,
    },
    /// Missing/failed/partial data — blocks, and CANNOT be acked (#241 §3).
    Unevaluated(String),
    /// Non-overridable (#241 §4).
    HardStop(String),
}

impl Verdict {
    fn passes(&self) -> bool {
        matches!(self, Verdict::Allow(_) | Verdict::RaiseCovered(_))
    }
    fn label(&self) -> &'static str {
        match self {
            Verdict::Allow(_) => "ALLOW",
            Verdict::RaiseCovered(_) => "RAISE (signed)",
            Verdict::RaiseUncovered { .. } => "RAISE (uncovered)",
            Verdict::Unevaluated(_) => "UNEVALUATED",
            Verdict::HardStop(_) => "HARD-STOP",
        }
    }
}

fn vuln_verdict(
    tool: &str,
    added: &[Instance],
    carried: &[Instance],
    fixed_count: usize,
    acks: &Acks,
) -> Verdict {
    let mut covered = Vec::new();
    let mut needed = Vec::new();
    for (label, set) in [("added", added), ("carried-unacked", carried)] {
        for i in set {
            if ack_covers_vuln(acks, i) {
                covered.push(format!("{label}: {} {} {}", i.id, i.package, i.version));
            } else {
                needed.push(ack_template_vuln(tool, i));
            }
        }
    }
    if !needed.is_empty() {
        return Verdict::RaiseUncovered { covered, needed };
    }
    if added.is_empty()
        && carried.iter().all(|i| ack_covers_vuln(acks, i))
        && covered.len() == carried.len()
    {
        // added = ∅ and every carried instance acked -> the §4 relative ∧ absolute ALLOW.
        return Verdict::Allow(format!(
            "no added instances; {} carried all acked; {fixed_count} fixed",
            carried.len()
        ));
    }
    Verdict::RaiseCovered(covered)
}

fn mal_verdict(
    tool: &str,
    evidence_dir: &Path,
    head: &ToolLine,
    acks: &Acks,
    floors: &crate::floors::Floors,
) -> Verdict {
    let digest = head.sha.as_str();
    let path = evidence_dir.join(tool).join(digest).join("mal.jsonl");
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => {
            return Verdict::Unevaluated(format!(
                "no mal evidence at {} — populate via a monitor/producer dispatch run \
                 (VT is never called from PR workflows)",
                path.display()
            ));
        }
    };
    // Panel history is append-only; the LAST record is current.
    let last = match text.lines().rev().find(|l| !l.trim().is_empty()) {
        Some(l) => l,
        None => return Verdict::Unevaluated(format!("{}: empty", path.display())),
    };
    let v: Value = match serde_json::from_str(last) {
        Ok(v) => v,
        Err(e) => return Verdict::Unevaluated(format!("{}: invalid JSON: {e}", path.display())),
    };
    // Evidence-for-the-wrong-digest guard: the record must be about THESE bytes.
    let rec_sha = s(&v, &["subject", "sha256"]);
    if rec_sha != head.sha {
        return Verdict::Unevaluated(format!(
            "mal evidence subject {rec_sha} != candidate digest {} — stale or misplaced record",
            head.sha
        ));
    }
    if let Some(why) = floors.mal_stop(&v) {
        return Verdict::HardStop(why);
    }
    // #347 step 1: completeness and readiness are PRECONDITIONS on reading the panel at all.
    // A short panel is not a verdict; a suspicious sandbox verdict has no per-item sign-off
    // yet (that is #347's verify-behavior step). Both are UNEVALUATED: they block and cannot
    // be acked away. NOT READY / UNSTATED are named in the verdict, not yet blocking.
    if let Some(why) = floors.mal_incomplete(&v) {
        return Verdict::Unevaluated(format!("{}: {why}", path.display()));
    }
    let sandbox = crate::floors::sandbox_state(&v);
    if let Some(sb) = crate::floors::sandbox_verdicts(&v).into_iter().find(|sb| {
        sb.get("category")
            .and_then(Value::as_str)
            .is_some_and(|c| c.eq_ignore_ascii_case("suspicious"))
    }) {
        let name = sb.get("name").and_then(Value::as_str).unwrap_or("?");
        return Verdict::Unevaluated(format!(
            "sandbox {name} verdict suspicious: per-item behaviour sign-off is #347's next \
             step; not readable as clean"
        ));
    }
    let total = v
        .pointer("/detections/total")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let malicious = v
        .get("detections")
        .and_then(|d| d.get("malicious"))
        .and_then(Value::as_u64);
    match malicious {
        Some(0) => Verdict::Allow(format!(
            "panel {}: 0 detections of {total} engines; sandbox {sandbox}",
            s(&v, &["panelDate"])
        )),
        Some(_) => {
            let mut covered = Vec::new();
            let mut needed = Vec::new();
            for f in v
                .get("flags")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let engine = s(f, &["engine"]);
                let result = s(f, &["result"]);
                if ack_covers_mal(acks, digest, engine, result) {
                    covered.push(format!("{engine}={result} (acked)"));
                } else {
                    needed.push(ack_template_mal(tool, digest, engine, result));
                }
            }
            if needed.is_empty() {
                Verdict::RaiseCovered(covered)
            } else {
                Verdict::RaiseUncovered { covered, needed }
            }
        }
        None => Verdict::Unevaluated(format!("{}: no detections.malicious field", path.display())),
    }
}

/// The prior blessed inventory for a TOOLS.lock candidate: the base entry's caps.toml.
fn base_caps_of(evidence_dir: &Path, tool: &str, base: Option<&ToolLine>) -> Option<String> {
    base.and_then(|b| {
        std::fs::read_to_string(evidence_dir.join(tool).join(&b.sha).join("caps.toml")).ok()
    })
}

fn caps_verdict(
    tool: &str,
    evidence_dir: &Path,
    base_caps: Option<String>,
    head: &ToolLine,
    acks: &Acks,
    floors: &crate::floors::Floors,
    locks: (Option<&Path>, Option<&Path>),
) -> Verdict {
    let (head_lock, base_lock) = locks;
    let digest = head.sha.as_str();
    let dir = evidence_dir.join(tool).join(digest);
    if dir.join("caps.toml").exists() {
        let head_bytes = std::fs::read(dir.join("caps.toml")).unwrap_or_default();
        // #380: an ack signs CONTENT. The hash of the exact bytes under review is what a
        // covering ack must name, so a rewritten inventory under a blessed digest has no
        // signature until it is signed again.
        let caps_sha = crate::sha256::sha256_hex(&head_bytes);
        let head_caps = String::from_utf8_lossy(&head_bytes).into_owned();
        if let Some(why) = floors.caps_stop(&head_caps, base_caps.as_deref()) {
            return Verdict::HardStop(why);
        }
        // #367: a complete, measured strict subset of the prior inventory is ALLOW. Every
        // precondition failure falls through to the RAISE/ack path below, never to ALLOW.
        if let (Some(base_caps), Some(hl), Some(bl)) = (&base_caps, head_lock, base_lock)
            && let (Ok(ht), Ok(bt)) = (std::fs::read_to_string(hl), std::fs::read_to_string(bl))
        {
            let head_sha = crate::sha256::sha256_hex(ht.as_bytes());
            match crate::caps_subset::subset_allow(
                &head_caps,
                base_caps,
                &head_sha,
                &crate::freeze::lock_package_names_from_str(&ht),
                &crate::freeze::lock_package_names_from_str(&bt),
            ) {
                Ok(desc) => return Verdict::Allow(desc),
                Err(why) => eprintln!("gate: caps subset rule not applicable for {tool}: {why}"),
            }
        }
        if ack_covers_caps(acks, digest, &caps_sha) {
            Verdict::RaiseCovered(vec![format!(
                "caps inventory {digest} (content sha256 {caps_sha}) reviewed + acked"
            )])
        } else {
            Verdict::RaiseUncovered {
                covered: Vec::new(),
                needed: vec![ack_template_caps(tool, digest, &caps_sha)],
            }
        }
    } else if dir.join("caps.UNEVALUATED").exists() {
        let why = std::fs::read_to_string(dir.join("caps.UNEVALUATED")).unwrap_or_default();
        Verdict::Unevaluated(format!("caps recorded UNEVALUATED: {}", why.trim()))
    } else {
        Verdict::Unevaluated(format!(
            "no caps evidence at {} — generate the cackle inventory (#50) and commit it",
            dir.display()
        ))
    }
}

// ---------- vuln-axis scanning (paired, single DB state; #241 §5) ----------

/// Invoke the PINNED cargo-audit (#221: absolute path from PINNED_TOOLS_DIR, env-scrubbed;
/// local-dev fallback `cargo audit`). Returns parsed JSON; audit exits non-zero when it
/// has findings, so exit status is NOT an error signal — parse failure is.
pub(crate) fn run_audit(lockfile: &Path, no_fetch: bool) -> Result<Value, String> {
    let (prog, mut args): (String, Vec<String>) = match std::env::var("PINNED_TOOLS_DIR") {
        Ok(dir) => (
            format!("{dir}/cargo-audit{}", std::env::consts::EXE_SUFFIX),
            vec!["audit".into()],
        ),
        Err(_) => ("cargo".into(), vec!["audit".into()]),
    };
    args.push("--json".into());
    if no_fetch {
        args.push("--no-fetch".into());
    }
    args.push("--file".into());
    args.push(lockfile.display().to_string());
    let out = Command::new(&prog)
        .args(&args)
        .env_remove("RUSTUP_TOOLCHAIN")
        .env_remove("CARGO")
        .env_remove("RUSTC")
        .output()
        .map_err(|e| format!("cannot run {prog}: {e}"))?;
    serde_json::from_slice(&out.stdout).map_err(|e| {
        format!(
            "cargo-audit output not parseable as JSON ({e}); stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

/// Fetch a rev's root Cargo.lock via curl (ambient like git/gh; std has no HTTP).
pub(crate) fn fetch_lockfile(repo: &str, rev: &str, dest: &Path) -> Result<(), String> {
    let url = format!("https://raw.githubusercontent.com/{repo}/{rev}/Cargo.lock");
    let st = Command::new("curl")
        .args(["-sSfL", &url, "-o"])
        .arg(dest)
        .status()
        .map_err(|e| format!("cannot run curl: {e}"))?;
    if st.success() {
        Ok(())
    } else {
        Err(format!(
            "curl {url} failed (no root Cargo.lock at that rev?)"
        ))
    }
}

/// The committed FROZEN lock for a tool, if one exists in `locks_dir` (#255 §5).
pub(crate) fn frozen_lock(locks_dir: &Path, tool: &str) -> Option<PathBuf> {
    let p = locks_dir.join(format!("{tool}.lock"));
    p.is_file().then_some(p)
}

/// Resolve THE lock a tool's binary is (or would be) built from — the only artifact whose
/// posture is honest to evaluate (#255 §5). A committed frozen lock (tools/locks/<name>.lock)
/// overrides upstream's resolution in the producer, so it must override here too; otherwise
/// the evaluation is systematically stale toward upstream's OLD versions — over-reporting
/// advisories we fixed, and (the fail-open direction) MISSING advisories that only apply to
/// the newer versions we froze forward to. Returns (path, source-label); the label goes into
/// the report so every evaluation names its instrument.
pub(crate) fn resolve_lock(
    tool: &str,
    repo: &str,
    rev: &str,
    locks_dir: Option<&Path>,
    dest: &Path,
) -> Result<(PathBuf, String), String> {
    if let Some(dir) = locks_dir
        && let Some(p) = frozen_lock(dir, tool)
    {
        return Ok((p, format!("frozen {}", dir.display())));
    }
    fetch_lockfile(repo, rev, dest)?;
    Ok((dest.to_path_buf(), "upstream".to_string()))
}

// ---------- evidence-only edits (#380 part 2) ----------

/// The per-digest evidence files whose change on the LIVE FRONTIER re-opens evaluation.
const EVIDENCE_FILES: &[&str] = &["caps.toml", "caps.UNEVALUATED", "mal.jsonl", "vuln.jsonl"];

fn read_opt(p: &Path) -> Option<Vec<u8>> {
    std::fs::read(p).ok()
}

/// Frontier entries that are NOT TOOLS.lock candidates but whose evidence directory differs
/// from the base commit's. Before #380 such a PR reached the gate as "evidence/ack-only edit"
/// and nothing was evaluated — so rewriting a blessed digest's caps.toml with new grants rode
/// through under the digest's existing signature. Returns each with the changed file names.
pub(crate) fn evidence_candidates(
    head: &[ToolLine],
    cands: &[(Option<ToolLine>, ToolLine)],
    evidence_dir: &Path,
    base_evidence_dir: &Path,
) -> Vec<(ToolLine, Vec<String>)> {
    let mut out = Vec::new();
    for h in head {
        if cands
            .iter()
            .any(|(_, c)| c.name == h.name && c.target == h.target)
        {
            continue;
        }
        if h.sha == ZERO_DIGEST || h.sha.len() != 64 {
            continue;
        }
        let changed: Vec<String> = EVIDENCE_FILES
            .iter()
            .filter(|f| {
                let rel = Path::new(&h.name).join(&h.sha).join(f);
                read_opt(&evidence_dir.join(&rel)) != read_opt(&base_evidence_dir.join(&rel))
            })
            .map(|f| f.to_string())
            .collect();
        if !changed.is_empty() {
            out.push((h.clone(), changed));
        }
    }
    out
}

/// Tools whose acks.jsonl differs from the base commit's — loaded and quality-checked even
/// when nothing else changed, so a malformed or placeholder sign-off cannot land unnoticed.
pub(crate) fn changed_ack_files(
    head: &[ToolLine],
    evidence_dir: &Path,
    base_evidence_dir: &Path,
) -> Vec<String> {
    let mut tools: Vec<String> = head.iter().map(|h| h.name.clone()).collect();
    tools.sort();
    tools.dedup();
    tools
        .into_iter()
        .filter(|t| {
            let rel = Path::new(t).join("acks.jsonl");
            read_opt(&evidence_dir.join(&rel)) != read_opt(&base_evidence_dir.join(&rel))
        })
        .collect()
}

/// Changed evidence files under digests that are NOT on the frontier: reported, not evaluated
/// (no gate consumes a record about bytes nobody runs — but a silent edit to history is still
/// worth a line in the report).
pub(crate) fn non_frontier_changes(
    head: &[ToolLine],
    evidence_dir: &Path,
    base_evidence_dir: &Path,
) -> Vec<String> {
    let frontier: BTreeSet<(String, String)> = head
        .iter()
        .map(|h| (h.name.clone(), h.sha.clone()))
        .collect();
    let mut seen = BTreeSet::new();
    for root in [evidence_dir, base_evidence_dir] {
        let Ok(tools) = std::fs::read_dir(root) else {
            continue;
        };
        for t in tools.filter_map(Result::ok).filter(|e| e.path().is_dir()) {
            let tool = t.file_name().to_string_lossy().into_owned();
            let Ok(digests) = std::fs::read_dir(t.path()) else {
                continue;
            };
            for d in digests.filter_map(Result::ok).filter(|e| e.path().is_dir()) {
                let digest = d.file_name().to_string_lossy().into_owned();
                if frontier.contains(&(tool.clone(), digest.clone())) {
                    continue;
                }
                for f in EVIDENCE_FILES {
                    let rel = Path::new(&tool).join(&digest).join(f);
                    if read_opt(&evidence_dir.join(&rel)) != read_opt(&base_evidence_dir.join(&rel))
                    {
                        seen.insert(format!("{tool}/{}/{f}", &digest[..12.min(digest.len())]));
                    }
                }
            }
        }
    }
    seen.into_iter().collect()
}

// ---------- the gate ----------

struct CandidateReport {
    /// Display identity: `name [target]`.
    name: String,
    /// Plain tool name: evidence directory and acks path.
    tool: String,
    summary: String,
    axes: Vec<(&'static str, Verdict)>,
}

pub fn run(args: &[String]) -> i32 {
    let mut base_path = None;
    let mut head_path = PathBuf::from("tools/TOOLS.lock");
    let mut evidence_dir = PathBuf::from("supply-chain/evidence");
    let mut report_path: Option<PathBuf> = None;
    // #255 §5: each side evaluates the lock its digest was built from. Head candidates use
    // the working tree's frozen locks; the base side needs the BASE COMMIT's frozen locks
    // (extracted by the workflow), because a frozen lock added in this very PR must not be
    // retro-applied to a baseline digest that was built from upstream's resolution.
    let mut locks_dir = PathBuf::from("tools/locks");
    let mut base_locks_dir: Option<PathBuf> = None;
    // #380 part 2: the BASE commit's evidence tree, so edits to a blessed digest's evidence
    // (no TOOLS.lock change) are evaluated rather than waved through as "evidence-only".
    let mut base_evidence_dir: Option<PathBuf> = None;
    let mut floors_path = PathBuf::from(crate::floors::DEFAULT_PATH);
    let mut it = args.iter().skip(1); // skip "gate"
    while let Some(a) = it.next() {
        match a.as_str() {
            "--base" => base_path = it.next().map(PathBuf::from),
            "--head" => {
                if let Some(v) = it.next() {
                    head_path = v.into();
                }
            }
            "--evidence" => {
                if let Some(v) = it.next() {
                    evidence_dir = v.into();
                }
            }
            "--report" => report_path = it.next().map(PathBuf::from),
            "--locks-dir" => {
                if let Some(v) = it.next() {
                    locks_dir = PathBuf::from(v);
                }
            }
            "--base-locks-dir" => base_locks_dir = it.next().map(PathBuf::from),
            "--base-evidence" => base_evidence_dir = it.next().map(PathBuf::from),
            "--floors" => {
                if let Some(v) = it.next() {
                    floors_path = PathBuf::from(v);
                }
            }
            other => {
                eprintln!("gate: unknown arg {other}");
                return 2;
            }
        }
    }
    let (Some(base_path), Some(base_evidence_dir)) = (base_path, base_evidence_dir) else {
        eprintln!(
            "usage: cargo xtask gate --base <base TOOLS.lock> --base-evidence <base evidence dir> \
             [--head <head TOOLS.lock>] [--evidence <dir>] [--report <md>] [--locks-dir <d>] \
             [--base-locks-dir <d>] [--floors <json>]"
        );
        eprintln!(
            "gate: --base-evidence is required (#380): without the base commit's evidence tree, \
             an evidence-only edit cannot be told from no edit, and that is the fail-open case"
        );
        return 2;
    };
    let read =
        |p: &Path| std::fs::read_to_string(p).map_err(|e| format!("read {}: {e}", p.display()));
    let (base_text, head_text) = match (read(&base_path), read(&head_path)) {
        (Ok(b), Ok(h)) => (b, h),
        (b, h) => {
            for r in [b, h].into_iter().filter_map(Result::err) {
                eprintln!("gate: {r}");
            }
            return 2;
        }
    };
    let base = parse_tools_lock(&base_text);
    let head = parse_tools_lock(&head_text);
    let cands = candidates(&base, &head);
    let ev_cands = evidence_candidates(&head, &cands, &evidence_dir, &base_evidence_dir);
    let changed_acks = changed_ack_files(&head, &evidence_dir, &base_evidence_dir);
    let historical = non_frontier_changes(&head, &evidence_dir, &base_evidence_dir);

    let mut reports = Vec::new();
    let mut db_stamp = String::new();
    let mut first_scan = true;

    // Absolute floors (#241 §4). A missing/malformed policy is UNEVALUATED for every
    // candidate: "no floors file" must never read as "no floors".
    let floors = match crate::floors::load(&floors_path) {
        Ok(f) => Some(f),
        Err(e) => {
            for (_, h) in &cands {
                reports.push(CandidateReport {
                    name: format!("{} [{}]", h.name, h.target),
                    tool: h.name.clone(),
                    summary: String::new(),
                    axes: vec![("floors", Verdict::Unevaluated(e.clone()))],
                });
            }
            None
        }
    };

    for (b, h) in floors.as_ref().map(|_| cands.as_slice()).unwrap_or(&[]) {
        let floors = floors.as_ref().expect("checked above");
        let acks = match load_acks(&evidence_dir.join(&h.name).join("acks.jsonl")) {
            Ok(a) => a,
            Err(e) => {
                // Malformed ack file: every axis that consults acks is unevaluable.
                reports.push(CandidateReport {
                    name: format!("{} [{}]", h.name, h.target),
                    tool: h.name.clone(),
                    summary: String::new(),
                    axes: vec![("acks", Verdict::Unevaluated(e))],
                });
                continue;
            }
        };
        let mut axes = Vec::new();
        let mut summary = String::new();

        // Preconditions (#241 §4): an unblessed digest cannot be evaluated OR acked.
        if h.sha == ZERO_DIGEST || h.sha.len() != 64 {
            axes.push((
                "preconditions",
                Verdict::HardStop(
                    "digest is unset/malformed — run build-tools.yml and commit the produced \
                     digest before evaluation"
                        .into(),
                ),
            ));
            reports.push(CandidateReport {
                name: format!("{} [{}]", h.name, h.target),
                tool: h.name.clone(),
                summary,
                axes,
            });
            continue;
        }

        // --- vuln: contemporaneous paired scan, one DB state, each side on the lock its
        //     digest is built from (#255 §5) ---
        let tmp = std::env::temp_dir();
        let head_dest = tmp.join(format!("gate-{}-head.lock", h.name));
        let head_res = resolve_lock(&h.name, &h.repo, &h.rev, Some(&locks_dir), &head_dest);
        let base_res = b.as_ref().map(|b| {
            let base_dest = tmp.join(format!("gate-{}-base.lock", h.name));
            resolve_lock(
                &b.name,
                &b.repo,
                &b.rev,
                base_locks_dir.as_deref(),
                &base_dest,
            )
        });
        let vuln = (|| -> Result<Verdict, String> {
            let (head_lock, head_src) = head_res.clone()?;
            let head_json = run_audit(&head_lock, !first_scan)?;
            first_scan = false;
            if db_stamp.is_empty() {
                db_stamp = format!(
                    "advisory-db {} ({})",
                    s(&head_json, &["database", "last-commit"]),
                    s(&head_json, &["database", "last-updated"]),
                );
            }
            let head_inst = extract_instances(&head_json);
            let stops = floors.vuln_stops(&head_inst, &crate::floors::extract_cvss(&head_json));
            let (added, fixed, carried, base_src) = match &base_res {
                Some(r) => {
                    let (base_lock, base_src) = r.clone()?;
                    let base_json = run_audit(&base_lock, true)?; // SAME DB: --no-fetch
                    let base_inst = extract_instances(&base_json);
                    let (a, f, c) = diff_instances(&base_inst, &head_inst);
                    (a, f, c, base_src)
                }
                // New tool: no baseline exists — every instance needs a sign-off.
                None => (
                    head_inst.iter().cloned().collect(),
                    Vec::new(),
                    Vec::new(),
                    "n/a (new tool)".to_string(),
                ),
            };
            let _ = write!(
                summary,
                "vuln: {} added / {} fixed / {} carried  [head lock: {head_src}; base lock: {base_src}]",
                added.len(),
                fixed.len(),
                carried.len()
            );
            if !stops.is_empty() {
                return Ok(Verdict::HardStop(stops.join("
  - ")));
            }
            Ok(vuln_verdict(&h.name, &added, &carried, fixed.len(), &acks))
        })()
        .unwrap_or_else(Verdict::Unevaluated);
        axes.push(("vuln", vuln));

        // --- caps + mal: consume the recorded evidence store ---
        let head_lock_path = head_res.as_ref().ok().map(|(p, _)| p.clone());
        let base_lock_path = base_res
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .map(|(p, _)| p.clone());
        axes.push((
            "caps",
            caps_verdict(
                &h.name,
                &evidence_dir,
                base_caps_of(&evidence_dir, &h.name, b.as_ref()),
                h,
                &acks,
                floors,
                (head_lock_path.as_deref(), base_lock_path.as_deref()),
            ),
        ));
        axes.push(("mal", mal_verdict(&h.name, &evidence_dir, h, &acks, floors)));

        if !acks.rejected.is_empty() {
            axes.push((
                "ack-quality",
                Verdict::Unevaluated(format!(
                    "{} ack line(s) failed the quality bar (empty/TODO reason, missing \
                     author/timestamp) and were NOT counted:\n    {}",
                    acks.rejected.len(),
                    acks.rejected.join("\n    ")
                )),
            ));
        }
        reports.push(CandidateReport {
            name: format!("{} [{}]", h.name, h.target),
            tool: h.name.clone(),
            summary,
            axes,
        });
    }

    // ---------- evidence-only candidates (#380 part 2) ----------
    // The bytes did not change, so the vuln axis is not re-scanned (it reads the lock, not a
    // file); the axes whose RECORD changed are evaluated against the base commit's record.
    if let Some(floors) = floors.as_ref() {
        for (h, changed) in &ev_cands {
            let acks = match load_acks(&evidence_dir.join(&h.name).join("acks.jsonl")) {
                Ok(a) => a,
                Err(e) => {
                    reports.push(CandidateReport {
                        name: format!("{} [{}] (evidence edit)", h.name, h.target),
                        tool: h.name.clone(),
                        summary: String::new(),
                        axes: vec![("acks", Verdict::Unevaluated(e))],
                    });
                    continue;
                }
            };
            let mut axes = Vec::new();
            let base_rec = base_evidence_dir.join(&h.name).join(&h.sha);
            if changed.iter().any(|f| f.starts_with("caps.")) {
                // Same rev on both sides: the lock the inventory was measured with is the lock
                // the digest was built from, on both sides of the comparison.
                let tmp = std::env::temp_dir();
                let head_dest = tmp.join(format!("gate-{}-ev-head.lock", h.name));
                let base_dest = tmp.join(format!("gate-{}-ev-base.lock", h.name));
                let head_lock =
                    resolve_lock(&h.name, &h.repo, &h.rev, Some(&locks_dir), &head_dest)
                        .ok()
                        .map(|(p, _)| p);
                let base_lock = resolve_lock(
                    &h.name,
                    &h.repo,
                    &h.rev,
                    base_locks_dir.as_deref(),
                    &base_dest,
                )
                .ok()
                .map(|(p, _)| p);
                let base_caps = std::fs::read_to_string(base_rec.join("caps.toml")).ok();
                axes.push((
                    "caps",
                    caps_verdict(
                        &h.name,
                        &evidence_dir,
                        base_caps,
                        h,
                        &acks,
                        floors,
                        (head_lock.as_deref(), base_lock.as_deref()),
                    ),
                ));
            }
            if changed.iter().any(|f| f == "mal.jsonl") {
                axes.push(("mal", mal_verdict(&h.name, &evidence_dir, h, &acks, floors)));
            }
            if changed.iter().any(|f| f == "vuln.jsonl") {
                axes.push((
                    "vuln",
                    Verdict::Unevaluated(
                        "vuln.jsonl edited under a blessed frontier digest: baselines are written \
                         by the bless flow and backed by a stored raw payload, never edited in \
                         place — regenerate through the producer instead"
                            .into(),
                    ),
                ));
            }
            if !acks.rejected.is_empty() {
                axes.push((
                    "ack-quality",
                    Verdict::Unevaluated(format!(
                        "{} ack line(s) failed the quality bar and were NOT counted:\n    {}",
                        acks.rejected.len(),
                        acks.rejected.join("\n    ")
                    )),
                ));
            }
            reports.push(CandidateReport {
                name: format!("{} [{}] (evidence edit)", h.name, h.target),
                tool: h.name.clone(),
                summary: format!(
                    "evidence-only edit under blessed digest {}: {} changed; bytes unchanged, vuln not re-scanned",
                    &h.sha[..12],
                    changed.join(", ")
                ),
                axes,
            });
        }
        // Ack-file edits with nothing else to evaluate: the quality bar still applies.
        for tool in &changed_acks {
            if ev_cands.iter().any(|(h, _)| &h.name == tool)
                || cands.iter().any(|(_, h)| &h.name == tool)
            {
                continue; // already loaded and reported above
            }
            match load_acks(&evidence_dir.join(tool).join("acks.jsonl")) {
                Ok(a) if a.rejected.is_empty() => reports.push(CandidateReport {
                    name: format!("{tool} (acks edit)"),
                    tool: tool.clone(),
                    summary: String::new(),
                    axes: vec![(
                        "ack-quality",
                        Verdict::Allow(format!(
                            "{} ack line(s) pass the quality bar; nothing to evaluate against",
                            a.entries.len()
                        )),
                    )],
                }),
                Ok(a) => reports.push(CandidateReport {
                    name: format!("{tool} (acks edit)"),
                    tool: tool.clone(),
                    summary: String::new(),
                    axes: vec![(
                        "ack-quality",
                        Verdict::Unevaluated(format!(
                            "{} ack line(s) failed the quality bar:\n    {}",
                            a.rejected.len(),
                            a.rejected.join("\n    ")
                        )),
                    )],
                }),
                Err(e) => reports.push(CandidateReport {
                    name: format!("{tool} (acks edit)"),
                    tool: tool.clone(),
                    summary: String::new(),
                    axes: vec![("acks", Verdict::Unevaluated(e))],
                }),
            }
        }
    }

    // ---------- report ----------
    let mut md =
        String::from("<!-- candidate-eval -->\n## Candidate evaluation (3-axis gate, #241)\n\n");
    if cands.is_empty() && ev_cands.is_empty() && changed_acks.is_empty() {
        md.push_str(
            "No TOOLS.lock candidates, no frontier evidence changes, no ack changes in this change.\n",
        );
    } else if cands.is_empty() {
        md.push_str("No TOOLS.lock candidates; evidence/ack edits on the live frontier evaluated below (#380).\n");
    } else if !db_stamp.is_empty() {
        let _ = writeln!(
            md,
            "*vuln instrument: {db_stamp} — both revs scanned at this single state*\n"
        );
    }
    let mut pass = true;
    for r in &reports {
        let _ = writeln!(md, "### `{}`  {}", r.name, r.summary);
        for (axis, v) in &r.axes {
            pass &= v.passes();
            let _ = writeln!(md, "- **{axis}: {}**", v.label());
            match v {
                Verdict::Allow(d) => {
                    let _ = writeln!(md, "  - {d}");
                }
                Verdict::RaiseCovered(items) => {
                    for i in items {
                        let _ = writeln!(md, "  - signed: {i}");
                    }
                }
                Verdict::RaiseUncovered { covered, needed } => {
                    for i in covered {
                        let _ = writeln!(md, "  - signed: {i}");
                    }
                    let _ = writeln!(
                        md,
                        "  - **{} item(s) need sign-off.** To accept the residual risk, fill in \
                         `status_notes` (why), `author`, `timestamp`, `refs`, and commit each \
                         line to `supply-chain/evidence/{}/acks.jsonl`:",
                        needed.len(),
                        r.tool
                    );
                    for n in needed {
                        let _ = writeln!(md, "\n    ```json\n    {n}\n    ```");
                    }
                }
                Verdict::Unevaluated(why) | Verdict::HardStop(why) => {
                    let _ = writeln!(md, "  - {why}");
                }
            }
        }
        md.push('\n');
    }
    if !historical.is_empty() {
        let _ = writeln!(
            md,
            "*Changed evidence under {} non-frontier digest file(s) — history, not evaluated (no gate consumes a record about bytes nobody runs): {}*\n",
            historical.len(),
            historical.join(", ")
        );
    }
    let _ = writeln!(
        md,
        "**Gate: {}** — {}",
        if pass { "PASS" } else { "BLOCKED" },
        if pass {
            "all axes ALLOW or signed; merging records the sign-off"
        } else {
            "uncovered RAISE / UNEVALUATED / HARD-STOP present (UNEVALUATED cannot be acked — \
             fill the missing evidence)"
        }
    );

    print!("{md}");
    if let Some(p) = report_path
        && let Err(e) = std::fs::write(&p, &md)
    {
        eprintln!("gate: write report {}: {e}", p.display());
        return 2;
    }
    i32::from(!pass)
}

// ---------- tests: the algebra is policy; policy gets tests ----------

#[cfg(test)]
mod tests {
    use super::*;

    fn inst(id: &str, pkg: &str, ver: &str) -> Instance {
        Instance {
            id: id.into(),
            package: pkg.into(),
            version: ver.into(),
            kind: "vulnerability".into(),
        }
    }
    fn ack(json: &str) -> Acks {
        Acks {
            entries: vec![serde_json::from_str(json).unwrap()],
            rejected: Vec::new(),
        }
    }
    fn good_vuln_ack(id: &str, pkg: &str, ver: &str) -> String {
        format!(
            r#"{{"schema":"hp-thermal/evidence-ack/v1","axis":"vuln","vulnerability":{{"name":"{id}"}},"product":{{"name":"t","package":"{pkg}","version":"{ver}"}},"status":"affected","status_notes":"reason","author":"a","timestamp":"2026-08-21","refs":[]}}"#
        )
    }

    #[test]
    fn tools_lock_parse_strips_comments() {
        let t = "# c\n\nname repo rev target sha  # v1.0\n";
        let p = parse_tools_lock(t);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].name, "name");
        assert_eq!(p[0].sha, "sha");
    }

    #[test]
    fn candidate_detection_rev_or_digest() {
        let mk = |rev: &str, sha: &str| ToolLine {
            name: "x".into(),
            repo: "r".into(),
            rev: rev.into(),
            target: "t".into(),
            sha: sha.into(),
        };
        assert_eq!(candidates(&[mk("a", "1")], &[mk("a", "1")]).len(), 0);
        assert_eq!(candidates(&[mk("a", "1")], &[mk("b", "1")]).len(), 1);
        assert_eq!(candidates(&[mk("a", "1")], &[mk("a", "2")]).len(), 1);
        assert_eq!(candidates(&[], &[mk("a", "1")]).len(), 1); // new tool
        // same name on a second target is its own candidate, compared against the other
        // target's blessed entry (tree-level inventories); the first target's unchanged line
        // is not re-evaluated (#386 step 3)
        let other_target_named = |n: &str| ToolLine {
            name: n.into(),
            repo: "r".into(),
            rev: "a".into(),
            target: "u".into(),
            sha: "9".into(),
        };
        let other_target = other_target_named("x");
        let c = candidates(&[mk("a", "1")], &[mk("a", "1"), other_target]);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].1.target, "u");
        let b = c[0].0.as_ref().expect("cross-target base");
        assert_eq!((b.name.as_str(), b.target.as_str()), ("x", "t"));
        // a genuinely new tool still has no base
        assert!(
            candidates(&[mk("a", "1")], &[other_target_named("y")])[0]
                .0
                .is_none()
        );
    }

    #[test]
    fn instance_diff_added_fixed_carried() {
        let base: BTreeSet<_> = [inst("A", "p", "1"), inst("B", "q", "2")].into();
        let head: BTreeSet<_> = [inst("B", "q", "2"), inst("C", "r", "3")].into();
        let (a, f, c) = diff_instances(&base, &head);
        assert_eq!(a, vec![inst("C", "r", "3")]);
        assert_eq!(f, vec![inst("A", "p", "1")]);
        assert_eq!(c, vec![inst("B", "q", "2")]);
    }

    #[test]
    fn same_id_new_instance_is_added() {
        // #241 §6: same advisory ID, second resident version -> a NEW instance (regression),
        // which bare-ID diffing would have hidden.
        let base: BTreeSet<_> = [inst("A", "p", "1.0")].into();
        let head: BTreeSet<_> = [inst("A", "p", "1.0"), inst("A", "p", "2.0")].into();
        let (a, _, c) = diff_instances(&base, &head);
        assert_eq!(a, vec![inst("A", "p", "2.0")]);
        assert_eq!(c, vec![inst("A", "p", "1.0")]);
    }

    #[test]
    fn vuln_allow_requires_added_empty_and_carried_acked() {
        let acks = ack(&good_vuln_ack("B", "q", "2"));
        let v = vuln_verdict("t", &[], &[inst("B", "q", "2")], 3, &acks);
        assert!(matches!(v, Verdict::Allow(_)));
    }

    #[test]
    fn vuln_added_acked_is_raise_covered_never_allow() {
        // No exchange rate: fixes never buy an addition; an acked addition is
        // signed-RAISE, not ALLOW.
        let acks = ack(&good_vuln_ack("C", "r", "3"));
        let v = vuln_verdict("t", &[inst("C", "r", "3")], &[], 99, &acks);
        assert!(matches!(v, Verdict::RaiseCovered(_)));
    }

    #[test]
    fn observed_absent_statement_is_void_for_a_reported_instance_and_later_affected_restores_it() {
        // #251: file order is statement order. affected -> grounded not_affected: NOT covered
        // (coverage is asked about an instance the DB reports now, which contradicts the
        // grounding). affected -> grounded not_affected -> affected: covered again.
        let affected = good_vuln_ack("B", "q", "2");
        let observed = ack_template_vuln_not_affected_observed(
            "t",
            &inst("B", "q", "2"),
            "0123456789abcdef0123",
            &GoneMechanism::VersionsNarrowed,
        )
        .replace("\"author\":\"\"", "\"author\":\"a\"")
        .replace("\"timestamp\":\"\"", "\"timestamp\":\"2026-11-10\"");
        let mut acks = ack(&affected);
        acks.entries.push(serde_json::from_str(&observed).unwrap());
        assert!(!ack_covers_vuln(&acks, &inst("B", "q", "2")));
        let v = vuln_verdict("t", &[], &[inst("B", "q", "2")], 0, &acks);
        assert!(matches!(v, Verdict::RaiseUncovered { .. }));
        acks.entries.push(serde_json::from_str(&affected).unwrap());
        assert!(ack_covers_vuln(&acks, &inst("B", "q", "2")));
        // a maintainer-reviewed not_affected (no grounding property) IS coverage
        let reviewed = affected.replace(
            "\"status\":\"affected\"",
            "\"status\":\"not_affected\",\"justification\":\"component_not_present\"",
        );
        assert!(ack_covers_vuln(&ack(&reviewed), &inst("B", "q", "2")));
        // a grounded statement for ANOTHER instance changes nothing
        let other = ack_template_vuln_not_affected_observed(
            "t",
            &inst("B", "q", "3"),
            "0123456789abcdef0123",
            &GoneMechanism::Withdrawn("2026-01-01".into()),
        );
        let mut acks2 = ack(&affected);
        acks2.entries.push(serde_json::from_str(&other).unwrap());
        assert!(ack_covers_vuln(&acks2, &inst("B", "q", "2")));
    }

    #[test]
    fn not_affected_observed_template_is_grounded_and_needs_a_signer() {
        let t = ack_template_vuln_not_affected_observed(
            "t",
            &inst("A", "p", "1"),
            "0123456789abcdef0123",
            &GoneMechanism::Withdrawn("2026-02-03".into()),
        );
        let v: Value = serde_json::from_str(&t).unwrap();
        assert_eq!(v["status"], "not_affected");
        assert_eq!(v["justification"], "vulnerable_code_not_present");
        assert_eq!(v["vulnerability"]["name"], "A");
        assert_eq!(observed_absent_at_db(&v), Some("0123456789abcdef0123"));
        let notes = v["status_notes"].as_str().unwrap();
        assert!(notes.contains("0123456789ab") && notes.contains("withdrawn 2026-02-03"));
        assert!(
            ack_quality(&v).is_err(),
            "blank author/timestamp must still fail the quality bar"
        );
    }

    #[test]
    fn vuln_fixed_and_bare_not_affected_fail_the_quality_bar() {
        let fixed =
            good_vuln_ack("A", "p", "1").replace("\"status\":\"affected\"", "\"status\":\"fixed\"");
        assert!(ack_quality(&serde_json::from_str(&fixed).unwrap()).is_err());
        let bare = good_vuln_ack("A", "p", "1")
            .replace("\"status\":\"affected\"", "\"status\":\"not_affected\"");
        assert!(ack_quality(&serde_json::from_str(&bare).unwrap()).is_err());
        let justified = bare.replace(
            "\"status\":\"not_affected\"",
            "\"status\":\"not_affected\",\"justification\":\"component_not_present\"",
        );
        assert!(ack_quality(&serde_json::from_str(&justified).unwrap()).is_ok());
    }

    #[test]
    fn vuln_unacked_carried_blocks() {
        let acks = Acks {
            entries: vec![],
            rejected: vec![],
        };
        let v = vuln_verdict("t", &[], &[inst("B", "q", "2")], 0, &acks);
        match v {
            Verdict::RaiseUncovered { needed, .. } => assert_eq!(needed.len(), 1),
            other => panic!("expected uncovered, got {other:?}"),
        }
    }

    #[test]
    fn ack_quality_rejects_placeholder_and_missing_author() {
        let bad: Value = serde_json::from_str(
            r#"{"axis":"vuln","status_notes":"TODO why","author":"a","timestamp":"t"}"#,
        )
        .unwrap();
        assert!(ack_quality(&bad).is_err());
        let no_author: Value =
            serde_json::from_str(r#"{"axis":"vuln","status_notes":"x","timestamp":"t"}"#).unwrap();
        assert!(ack_quality(&no_author).is_err());
    }

    #[test]
    fn malformed_ack_file_is_hard_error() {
        let dir = std::env::temp_dir().join(format!("gate-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("acks.jsonl");
        std::fs::write(&p, "{not json\n").unwrap();
        assert!(load_acks(&p).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn extract_instances_covers_vulns_and_warnings() {
        let j: Value = serde_json::from_str(
            r#"{"vulnerabilities":{"list":[{"advisory":{"id":"RUSTSEC-1"},"package":{"name":"a","version":"1"}}]},
                "warnings":{"unmaintained":[{"advisory":{"id":"RUSTSEC-2"},"package":{"name":"b","version":"2"}}],
                            "yanked":[{"package":{"name":"c","version":"3"}}]}}"#,
        )
        .unwrap();
        let set = extract_instances(&j);
        assert_eq!(set.len(), 3);
        assert!(set.iter().any(|i| i.id == "yanked" && i.package == "c"));
    }

    #[test]
    fn frozen_lock_overrides_upstream_and_absence_falls_through() {
        // #255 §5: a committed frozen lock is THE lock the producer builds from, so it must
        // be the lock evaluated; without one, resolution falls through to upstream fetch.
        let dir = std::env::temp_dir().join(format!("gate-locks-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("mytool.lock"),
            "# lock
",
        )
        .unwrap();
        assert!(frozen_lock(&dir, "mytool").is_some());
        assert!(
            frozen_lock(&dir, "othertool").is_none(),
            "absence must fall through"
        );
        // resolve_lock with a frozen lock present never needs the network:
        let dest = dir.join("dest.lock");
        let (path, src) = resolve_lock("mytool", "x/y", "deadbeef", Some(&dir), &dest).unwrap();
        assert_eq!(path, dir.join("mytool.lock"));
        assert!(
            src.starts_with("frozen"),
            "source label must say frozen, got {src}"
        );
        // and with NO locks dir at all (base side pre-freeze), the label must be upstream —
        // not silently reusing the head's frozen lock for a digest built without it.
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---------- #380: acks bind to content ----------

    fn tl(name: &str, sha: &str) -> ToolLine {
        ToolLine {
            name: name.into(),
            repo: "o/r".into(),
            rev: "v".into(),
            target: "x".into(),
            sha: sha.into(),
        }
    }
    fn floors() -> crate::floors::Floors {
        crate::floors::parse(include_str!("../../supply-chain/policy/floors.json")).unwrap()
    }
    fn caps_ack(digest: &str, evidence_sha: Option<&str>) -> String {
        let ev = evidence_sha
            .map(|h| format!(r#","evidence_sha256":"{h}""#))
            .unwrap_or_default();
        format!(
            r#"{{"schema":"hp-thermal/evidence-ack/v1","axis":"caps","product":{{"name":"t","digest":"{digest}"}}{ev},"status":"reviewed","status_notes":"reviewed","author":"a","timestamp":"2026-11-11","refs":[]}}"#
        )
    }

    #[test]
    fn caps_ack_covers_the_inventory_content_it_signed_and_nothing_else() {
        let dir = std::env::temp_dir().join(format!("gate-caps380-{}", std::process::id()));
        let full = "cccccccccccc000000000000000000000000000000000000000000000000000c";
        let rec = dir.join("t").join(full);
        std::fs::create_dir_all(&rec).unwrap();
        let signed =
            "# caps evidence — cackle-generated inventory\n[api.fs]\ninclude = [\"std::fs\"]\n";
        std::fs::write(rec.join("caps.toml"), signed).unwrap();
        let signed_sha = crate::sha256::sha256_hex(signed.as_bytes());
        let acks = ack(&caps_ack(full, Some(&signed_sha)));
        let h = tl("t", full);
        let v = caps_verdict("t", &dir, None, &h, &acks, &floors(), (None, None));
        assert!(
            matches!(v, Verdict::RaiseCovered(_)),
            "signed content is covered: {v:?}"
        );

        // The Bubblewrap-refresh shape: same digest, inventory gains a grant. The old ack
        // must NOT cover it, and the printed template must name the NEW content hash.
        let rewritten = format!(
            "{signed}\n[pkg.ring.build]\nallow_build_instructions = [\"cargo:rustc-link-lib=static=ring\"]\n"
        );
        std::fs::write(rec.join("caps.toml"), &rewritten).unwrap();
        let v = caps_verdict("t", &dir, None, &h, &acks, &floors(), (None, None));
        let Verdict::RaiseUncovered { needed, .. } = &v else {
            panic!("rewritten inventory must be uncovered: {v:?}")
        };
        let new_sha = crate::sha256::sha256_hex(rewritten.as_bytes());
        assert!(
            needed[0].contains(&new_sha) && !needed[0].contains(&signed_sha),
            "{needed:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn caps_ack_without_evidence_hash_and_mal_ack_without_result_fail_the_quality_bar() {
        let d = "d".repeat(64);
        let e = ack_quality(&serde_json::from_str(&caps_ack(&d, None)).unwrap()).unwrap_err();
        assert!(e.contains("evidence_sha256"), "{e}");
        let e =
            ack_quality(&serde_json::from_str(&caps_ack(&d, Some("ABC"))).unwrap()).unwrap_err();
        assert!(e.contains("evidence_sha256"), "{e}");
        ack_quality(&serde_json::from_str(&caps_ack(&d, Some(&"0".repeat(64)))).unwrap()).unwrap();
        let mal_no_result = format!(
            r#"{{"schema":"hp-thermal/evidence-ack/v1","axis":"mal","finding":{{"engine":"APEX"}},"product":{{"name":"t","digest":"{d}"}},"status":"not_affected","status_notes":"n","author":"a","timestamp":"t","refs":[]}}"#
        );
        let e = ack_quality(&serde_json::from_str(&mal_no_result).unwrap()).unwrap_err();
        assert!(e.contains("finding.result"), "{e}");
    }

    #[test]
    fn mal_ack_covers_engine_and_result_not_engine_alone() {
        let d = "e".repeat(64);
        let a = ack(&format!(
            r#"{{"schema":"hp-thermal/evidence-ack/v1","axis":"mal","finding":{{"engine":"Microsoft","result":"Trojan:Win32/Wacatac.B!ml"}},"product":{{"name":"t","digest":"{d}"}},"status":"not_affected","status_notes":"ml heuristic","author":"a","timestamp":"t","refs":[]}}"#
        ));
        assert!(ack_covers_mal(
            &a,
            &d,
            "Microsoft",
            "Trojan:Win32/Wacatac.B!ml"
        ));
        assert!(
            !ack_covers_mal(&a, &d, "Microsoft", "Trojan:Win32/Emotet"),
            "a renamed verdict is a new finding"
        );
        assert!(!ack_covers_mal(&a, &d, "APEX", "Trojan:Win32/Wacatac.B!ml"));
        assert_eq!(
            mal_acked_findings(&a, &d),
            vec!["Microsoft\tTrojan:Win32/Wacatac.B!ml".to_string()]
        );
    }

    #[test]
    fn evidence_only_edits_on_the_frontier_are_candidates_and_history_is_reported() {
        let root = std::env::temp_dir().join(format!("gate-ev380-{}", std::process::id()));
        let (head_ev, base_ev) = (root.join("head"), root.join("base"));
        let on = "f".repeat(64);
        let old = "0".repeat(64);
        for (r, caps, mal_old) in [
            (
                &head_ev,
                "[api.fs]\ninclude = [\"std::fs\", \"std::net\"]\n",
                "edited",
            ),
            (&base_ev, "[api.fs]\ninclude = [\"std::fs\"]\n", "orig"),
        ] {
            let d = r.join("t").join(&on);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("caps.toml"), caps).unwrap();
            std::fs::write(d.join("mal.jsonl"), "same\n").unwrap();
            std::fs::write(d.join("vuln.jsonl"), "same\n").unwrap();
            let h = r.join("t").join(&old);
            std::fs::create_dir_all(&h).unwrap();
            std::fs::write(h.join("mal.jsonl"), mal_old).unwrap();
            std::fs::write(r.join("t").join("acks.jsonl"), "").unwrap();
        }
        let head = vec![tl("t", &on)];
        let cands: Vec<(Option<ToolLine>, ToolLine)> = Vec::new();
        let ev = evidence_candidates(&head, &cands, &head_ev, &base_ev);
        assert_eq!(ev.len(), 1);
        assert_eq!(
            ev[0].1,
            vec!["caps.toml".to_string()],
            "only the changed file is named"
        );
        // a digest that IS a TOOLS.lock candidate is not double-reported
        let as_cand = vec![(None, tl("t", &on))];
        assert!(evidence_candidates(&head, &as_cand, &head_ev, &base_ev).is_empty());
        // identical trees: nothing
        assert!(evidence_candidates(&head, &cands, &head_ev, &head_ev).is_empty());
        // non-frontier change is listed, never evaluated
        let hist = non_frontier_changes(&head, &head_ev, &base_ev);
        assert_eq!(hist, vec![format!("t/{}/mal.jsonl", &old[..12])]);
        // acks unchanged -> no ack-file candidate; changed -> named
        assert!(changed_ack_files(&head, &head_ev, &base_ev).is_empty());
        std::fs::write(head_ev.join("t").join("acks.jsonl"), "{}\n").unwrap();
        assert_eq!(
            changed_ack_files(&head, &head_ev, &base_ev),
            vec!["t".to_string()]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn committed_ack_lattices_pass_the_quality_bar_after_the_380_migration() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../supply-chain/evidence");
        let mut caps = 0;
        let mut mal = 0;
        for e in std::fs::read_dir(&root).unwrap().filter_map(Result::ok) {
            let p = e.path().join("acks.jsonl");
            if !p.is_file() {
                continue;
            }
            let a = load_acks(&p).unwrap();
            assert!(a.rejected.is_empty(), "{}: {:?}", p.display(), a.rejected);
            caps += a
                .entries
                .iter()
                .filter(|x| s(x, &["axis"]) == "caps")
                .count();
            mal += a
                .entries
                .iter()
                .filter(|x| s(x, &["axis"]) == "mal")
                .count();
        }
        assert!(caps >= 43 && mal >= 9, "caps {caps} mal {mal}");
    }

    #[test]
    fn mal_digest_mismatch_is_unevaluated() {
        let dir = std::env::temp_dir().join(format!("gate-mal-{}", std::process::id()));
        // Dir is the FULL digest now (locator=authority, no truncation) — so the file IS
        // found and the subject-mismatch guard, not a missing file, drives UNEVALUATED.
        let full = "aaaaaaaaaaaa000000000000000000000000000000000000000000000000000a";
        let tool_dir = dir.join("t").join(full);
        std::fs::create_dir_all(&tool_dir).unwrap();
        std::fs::write(
            tool_dir.join("mal.jsonl"),
            r#"{"subject":{"sha256":"DIFFERENT"},"detections":{"malicious":0}}"#,
        )
        .unwrap();
        let h = ToolLine {
            name: "t".into(),
            repo: "r".into(),
            rev: "v".into(),
            target: "x".into(),
            sha: full.into(),
        };
        let acks = Acks {
            entries: vec![],
            rejected: vec![],
        };
        let floors =
            crate::floors::parse(include_str!("../../supply-chain/policy/floors.json")).unwrap();
        let v = mal_verdict("t", &dir, &h, &acks, &floors);
        assert!(matches!(v, Verdict::Unevaluated(_)), "got {v:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// One mal record on disk → its gate verdict (#347 step 1 cases).
    fn mal_verdict_for(tag: &str, record: &str) -> Verdict {
        let dir = std::env::temp_dir().join(format!("gate-mal-{tag}-{}", std::process::id()));
        let full = "bbbbbbbbbbbb000000000000000000000000000000000000000000000000000b";
        let tool_dir = dir.join("t").join(full);
        std::fs::create_dir_all(&tool_dir).unwrap();
        std::fs::write(tool_dir.join("mal.jsonl"), record.replace("DIGEST", full)).unwrap();
        let h = ToolLine {
            name: "t".into(),
            repo: "r".into(),
            rev: "v".into(),
            target: "x".into(),
            sha: full.into(),
        };
        let acks = Acks {
            entries: vec![],
            rejected: vec![],
        };
        let floors =
            crate::floors::parse(include_str!("../../supply-chain/policy/floors.json")).unwrap();
        let v = mal_verdict("t", &dir, &h, &acks, &floors);
        let _ = std::fs::remove_dir_all(&dir);
        v
    }

    #[test]
    fn incomplete_panel_is_unevaluated_not_allow() {
        let v = mal_verdict_for(
            "short",
            r#"{"subject":{"sha256":"DIGEST"},"detections":{"malicious":0,"total":9},"flags":[],"sandbox":{"state":"NOT READY","verdicts":[]}}"#,
        );
        assert!(
            matches!(v, Verdict::Unevaluated(ref w) if w.contains("INCOMPLETE")),
            "got {v:?}"
        );
        let v = mal_verdict_for(
            "nototal",
            r#"{"subject":{"sha256":"DIGEST"},"detections":{"malicious":0},"flags":[],"sandbox":[]}"#,
        );
        assert!(matches!(v, Verdict::Unevaluated(_)), "got {v:?}");
    }

    #[test]
    fn sandbox_state_is_named_and_suspicious_is_unevaluated() {
        let v = mal_verdict_for(
            "ready",
            r#"{"subject":{"sha256":"DIGEST"},"detections":{"malicious":0,"total":70},"flags":[],"sandbox":{"state":"NOT READY","verdicts":[]}}"#,
        );
        assert!(
            matches!(v, Verdict::Allow(ref w) if w.contains("sandbox NOT READY")),
            "got {v:?}"
        );
        let v = mal_verdict_for(
            "legacy",
            r#"{"subject":{"sha256":"DIGEST"},"detections":{"malicious":0,"total":70},"flags":[],"sandbox":[]}"#,
        );
        assert!(
            matches!(v, Verdict::Allow(ref w) if w.contains("UNSTATED")),
            "got {v:?}"
        );
        let v = mal_verdict_for(
            "susp",
            r#"{"subject":{"sha256":"DIGEST"},"detections":{"malicious":0,"total":70},"flags":[],"sandbox":{"state":"ANALYZED","verdicts":[{"name":"Zenbox","category":"suspicious"}]}}"#,
        );
        assert!(
            matches!(v, Verdict::Unevaluated(ref w) if w.contains("suspicious")),
            "got {v:?}"
        );
        let v = mal_verdict_for(
            "mal",
            r#"{"subject":{"sha256":"DIGEST"},"detections":{"malicious":0,"total":70},"flags":[],"sandbox":{"state":"ANALYZED","verdicts":[{"name":"Zenbox","category":"malicious"}]}}"#,
        );
        assert!(matches!(v, Verdict::HardStop(_)), "got {v:?}");
    }
}

#[cfg(test)]
mod mal_acks_tests {
    use super::*;

    fn ack(digest: &str, engine: &str, notes: &str) -> String {
        format!(
            r#"{{"schema":"hp-thermal/evidence-ack/v1","axis":"mal","finding":{{"engine":"{engine}","result":"Malicious"}},"product":{{"name":"t","digest":"{digest}"}},"status":"affected","status_notes":"{notes}","author":"a","timestamp":"2026-08-24"}}"#
        )
    }

    #[test]
    fn selects_only_matching_digest_and_axis() {
        let d1 = "a".repeat(64);
        let d2 = "b".repeat(64);
        let dir = std::env::temp_dir().join("malacks-t1");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("acks.jsonl");
        std::fs::write(
            &p,
            format!(
                "{}
{}
{}
",
                ack(&d1, "APEX", "reason one"),
                ack(&d2, "Zenbox", "other digest"),
                // vuln-axis entry with same digest field shape must NOT match
                r#"{"schema":"hp-thermal/evidence-ack/v1","axis":"vuln","vulnerability":{"name":"X"},"product":{"name":"t","package":"p","version":"1"},"status":"affected","status_notes":"n","author":"a","timestamp":"t"}"#
            ),
        )
        .unwrap();
        let acks = load_acks(&p).unwrap();
        assert_eq!(
            mal_acked_findings(&acks, &d1),
            vec!["APEX\tMalicious".to_string()]
        );
        assert_eq!(
            mal_acked_findings(&acks, &d2),
            vec!["Zenbox\tMalicious".to_string()]
        );
        assert!(mal_acked_findings(&acks, &"c".repeat(64)).is_empty());
    }

    #[test]
    fn quality_rejected_ack_does_not_silence() {
        let d = "d".repeat(64);
        let dir = std::env::temp_dir().join("malacks-t2");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("acks.jsonl");
        std::fs::write(
            &p,
            format!(
                "{}
",
                ack(&d, "APEX", "TODO")
            ),
        )
        .unwrap();
        let acks = load_acks(&p).unwrap();
        assert_eq!(
            acks.rejected.len(),
            1,
            "placeholder notes must be quality-rejected"
        );
        assert!(
            mal_acked_findings(&acks, &d).is_empty(),
            "a quality-rejected ack must NOT silence the engine"
        );
    }

    #[test]
    fn missing_lattice_means_no_acks() {
        let acks = load_acks(Path::new("does/not/exist/acks.jsonl")).unwrap();
        assert!(mal_acked_findings(&acks, &"e".repeat(64)).is_empty());
    }
}
