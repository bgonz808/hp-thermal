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
struct ToolLine {
    name: String,
    repo: String,
    rev: String,
    target: String,
    sha: String,
}

/// Parse TOOLS.lock: strip comments/blank lines, take the 5 whitespace-separated
/// columns (`name repo rev target sha256`), ignoring the trailing `# vX` comment.
fn parse_tools_lock(text: &str) -> Vec<ToolLine> {
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

/// Candidates = head entries that are new or whose rev/digest changed vs base.
fn candidates(base: &[ToolLine], head: &[ToolLine]) -> Vec<(Option<ToolLine>, ToolLine)> {
    head.iter()
        .filter_map(|h| {
            let b = base.iter().find(|b| b.name == h.name);
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
struct Instance {
    id: String,
    package: String,
    version: String,
    kind: String,
}

/// Extract instance tuples from `cargo audit --json` output.
fn extract_instances(audit: &Value) -> BTreeSet<Instance> {
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
struct Acks {
    entries: Vec<Value>,
    rejected: Vec<String>,
}

fn load_acks(path: &Path) -> Result<Acks, String> {
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

fn ack_covers_vuln(acks: &Acks, inst: &Instance) -> bool {
    acks.entries.iter().any(|a| {
        s(a, &["axis"]) == "vuln"
            && s(a, &["vulnerability", "name"]) == inst.id
            && s(a, &["product", "package"]) == inst.package
            && s(a, &["product", "version"]) == inst.version
    })
}

fn ack_covers_mal(acks: &Acks, digest: &str, engine: &str) -> bool {
    acks.entries.iter().any(|a| {
        s(a, &["axis"]) == "mal"
            && s(a, &["product", "digest"]) == digest
            && s(a, &["finding", "engine"]) == engine
    })
}

fn ack_covers_caps(acks: &Acks, digest: &str) -> bool {
    acks.entries
        .iter()
        .any(|a| s(a, &["axis"]) == "caps" && s(a, &["product", "digest"]) == digest)
}

/// The exact line a maintainer commits to sign off — printed by the failing gate.
/// status_notes is deliberately empty: the quality bar refuses it until a human
/// writes the reason (no rubber-stamp path).
fn ack_template_vuln(tool: &str, inst: &Instance) -> String {
    serde_json::json!({
        "schema": "hp-thermal/evidence-ack/v1",
        "axis": "vuln",
        "vulnerability": {"name": inst.id},
        "product": {"name": tool, "package": inst.package, "version": inst.version},
        "status": "affected",
        "status_notes": "",
        "author": "",
        "timestamp": "",
        "refs": []
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

fn ack_template_caps(tool: &str, digest: &str) -> String {
    serde_json::json!({
        "schema": "hp-thermal/evidence-ack/v1",
        "axis": "caps",
        "product": {"name": tool, "digest": digest},
        "status": "affected",
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

fn mal_verdict(tool: &str, evidence_dir: &Path, head: &ToolLine, acks: &Acks) -> Verdict {
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
    let malicious = v
        .get("detections")
        .and_then(|d| d.get("malicious"))
        .and_then(Value::as_u64);
    match malicious {
        Some(0) => Verdict::Allow(format!("panel {}: 0 detections", s(&v, &["panelDate"]))),
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
                if ack_covers_mal(acks, digest, engine) {
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

fn caps_verdict(tool: &str, evidence_dir: &Path, head: &ToolLine, acks: &Acks) -> Verdict {
    let digest = head.sha.as_str();
    let dir = evidence_dir.join(tool).join(digest);
    if dir.join("caps.toml").exists() {
        if ack_covers_caps(acks, digest) {
            Verdict::RaiseCovered(vec![format!("caps inventory {digest} reviewed + acked")])
        } else {
            Verdict::RaiseUncovered {
                covered: Vec::new(),
                needed: vec![ack_template_caps(tool, digest)],
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
fn run_audit(lockfile: &Path, no_fetch: bool) -> Result<Value, String> {
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
fn fetch_lockfile(repo: &str, rev: &str, dest: &Path) -> Result<(), String> {
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

// ---------- the gate ----------

struct CandidateReport {
    name: String,
    summary: String,
    axes: Vec<(&'static str, Verdict)>,
}

pub fn run(args: &[String]) -> i32 {
    let mut base_path = None;
    let mut head_path = PathBuf::from("tools/TOOLS.lock");
    let mut evidence_dir = PathBuf::from("supply-chain/evidence");
    let mut report_path: Option<PathBuf> = None;
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
            other => {
                eprintln!("gate: unknown arg {other}");
                return 2;
            }
        }
    }
    let Some(base_path) = base_path else {
        eprintln!(
            "usage: cargo xtask gate --base <base TOOLS.lock> [--head <head TOOLS.lock>] [--evidence <dir>] [--report <md>]"
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

    let mut reports = Vec::new();
    let mut db_stamp = String::new();
    let mut first_scan = true;

    for (b, h) in &cands {
        let acks = match load_acks(&evidence_dir.join(&h.name).join("acks.jsonl")) {
            Ok(a) => a,
            Err(e) => {
                // Malformed ack file: every axis that consults acks is unevaluable.
                reports.push(CandidateReport {
                    name: h.name.clone(),
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
                name: h.name.clone(),
                summary,
                axes,
            });
            continue;
        }

        // --- vuln: contemporaneous paired scan, one DB state ---
        let tmp = std::env::temp_dir();
        let head_lock = tmp.join(format!("gate-{}-head.lock", h.name));
        let vuln = (|| -> Result<Verdict, String> {
            fetch_lockfile(&h.repo, &h.rev, &head_lock)?;
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
            let (added, fixed, carried) = match b {
                Some(b) => {
                    let base_lock = tmp.join(format!("gate-{}-base.lock", h.name));
                    fetch_lockfile(&b.repo, &b.rev, &base_lock)?;
                    let base_json = run_audit(&base_lock, true)?; // SAME DB: --no-fetch
                    let base_inst = extract_instances(&base_json);
                    diff_instances(&base_inst, &head_inst)
                }
                // New tool: no baseline exists — every instance needs a sign-off.
                None => (head_inst.iter().cloned().collect(), Vec::new(), Vec::new()),
            };
            let _ = write!(
                summary,
                "vuln: {} added / {} fixed / {} carried",
                added.len(),
                fixed.len(),
                carried.len()
            );
            Ok(vuln_verdict(&h.name, &added, &carried, fixed.len(), &acks))
        })()
        .unwrap_or_else(Verdict::Unevaluated);
        axes.push(("vuln", vuln));

        // --- caps + mal: consume the recorded evidence store ---
        axes.push(("caps", caps_verdict(&h.name, &evidence_dir, h, &acks)));
        axes.push(("mal", mal_verdict(&h.name, &evidence_dir, h, &acks)));

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
            name: h.name.clone(),
            summary,
            axes,
        });
    }

    // ---------- report ----------
    let mut md =
        String::from("<!-- candidate-eval -->\n## Candidate evaluation (3-axis gate, #241)\n\n");
    if cands.is_empty() {
        md.push_str("No TOOLS.lock candidates in this change — evidence/ack-only edit.\n");
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
                        r.name
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
        let v = mal_verdict("t", &dir, &h, &acks);
        assert!(matches!(v, Verdict::Unevaluated(_)), "got {v:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
