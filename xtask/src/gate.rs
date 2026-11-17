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

use std::collections::{BTreeMap, BTreeSet};
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

/// The TOOLS.lock grammar every reader must agree on (`parse_tools_lock` here, the `grep | sed |
/// read` pipelines in the workflows; `fetch-tools`' `tools_lock_grammar` enforces it in bash, and
/// `fetch_tools_reads_the_lock_as_the_gate_does` holds the two to the same verdicts). Every line,
/// comments included, holds only ASCII graphic characters, spaces and tabs: no reader's locale,
/// and no invisible or bidirectional character, decides what a line says. A content line (the
/// text before `#`) is exactly five fields: name, owner/repo, 40-hex rev, target, 64-hex sha256.
/// Each word is `[A-Za-z0-9._-]`, starting and ending alphanumeric (no `.`, `..` or trailing-dot
/// path components); name and target are lowercase, so no case-insensitive comparison or file
/// system has a second spelling of them. One pin per (name, target); a digest names one pin (one
/// binary is not two); every target of a tool builds from one (repo, rev), the one frozen lock
/// `tools/locks/<name>.lock` describes. A line outside this is a problem, never skipped.
pub(crate) fn tools_lock_problems(text: &str) -> Vec<String> {
    let word = |s: &str, lower: bool| {
        let ok = |b: u8| {
            b.is_ascii_digit()
                || if lower {
                    b.is_ascii_lowercase()
                } else {
                    b.is_ascii_alphabetic()
                }
        };
        let b = s.as_bytes();
        b.first().is_some_and(|&c| ok(c))
            && b.last().is_some_and(|&c| ok(c))
            && b.iter().all(|&c| ok(c) || b"._-".contains(&c))
    };
    let hex = |s: &str, n: usize| {
        s.len() == n && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    };
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    let mut digests = BTreeSet::new();
    let mut source: BTreeMap<&str, (&str, &str)> = BTreeMap::new();
    for (i, line) in text.split('\n').enumerate() {
        let content = line.find('#').map_or(line, |j| &line[..j]);
        if let Some(c) = line
            .chars()
            .find(|c| !(c.is_ascii_graphic() || *c == ' ' || *c == '\t'))
        {
            out.push(format!(
                "line {}: U+{:04X} is outside the grammar",
                i + 1,
                c as u32
            ));
            continue;
        }
        let f: Vec<&str> = content
            .split([' ', '\t'])
            .filter(|s| !s.is_empty())
            .collect();
        if f.is_empty() {
            continue;
        }
        let ok = f.len() == 5
            && word(f[0], true)
            && f[1]
                .split_once('/')
                .is_some_and(|(o, r)| word(o, false) && word(r, false))
            && hex(f[2], 40)
            && word(f[3], true)
            && hex(f[4], 64);
        if !ok {
            out.push(format!(
                "line {}: not `name owner/repo <40-hex rev> target <64-hex sha256>`",
                i + 1
            ));
        } else if !seen.insert((f[0], f[3])) {
            out.push(format!("line {}: {} {} pinned twice", i + 1, f[0], f[3]));
        } else if f[4] != ZERO_DIGEST && !digests.insert(f[4]) {
            out.push(format!(
                "line {}: digest {} pinned twice",
                i + 1,
                &f[4][..12]
            ));
        } else if source.entry(f[0]).or_insert((f[1], f[2])) != &(f[1], f[2]) {
            out.push(format!(
                "line {}: {} names another source than its other targets; every target builds \
                 from one (repo, rev)",
                i + 1,
                f[0]
            ));
        }
    }
    out
}

/// cargo-audit takes configuration from `.cargo/audit.toml` under its working directory, and an
/// `ignore` there silences advisories. Every invocation therefore runs in a fresh, empty
/// directory: nothing in the checkout configures the instrument. Two forms: `audit … --file
/// <lock>` scans a copy of the lock made in that directory; `audit bin <path>…` scans binaries,
/// named by absolute path. The directory is created here, never reused: one that already exists
/// (left behind, or planted) is skipped.
pub(crate) fn audit_isolated(
    program: &str,
    args: &[String],
) -> Result<std::process::Output, String> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = (0..1000)
        .map(|_| {
            std::env::temp_dir().join(format!(
                "xtask-audit-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::SeqCst)
            ))
        })
        .find_map(|d| match std::fs::create_dir(&d) {
            Ok(()) => Some(Ok(d)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => None,
            Err(e) => Some(Err(format!("{}: {e}", d.display()))),
        })
        .unwrap_or_else(|| Err("audit: no fresh temporary directory".into()))?;
    let abs = |p: &str| {
        std::path::absolute(p)
            .map(|a| a.to_string_lossy().into_owned())
            .map_err(|e| format!("{p}: {e}"))
    };
    let run = || -> Result<std::process::Output, String> {
        let argv = isolated_argv(args, &dir)?;
        // A program named by path is resolved before the working directory changes.
        let prog = if Path::new(program).components().count() > 1 {
            PathBuf::from(abs(program)?)
        } else {
            PathBuf::from(program)
        };
        Command::new(&prog)
            .args(&argv)
            .current_dir(&dir)
            .env_remove("RUSTUP_TOOLCHAIN")
            .env_remove("CARGO")
            .env_remove("RUSTC")
            .output()
            .map_err(|e| format!("cannot run {program}: {e}"))
    };
    let out = run();
    let _ = std::fs::remove_dir_all(&dir);
    out
}

/// `audit_isolated`'s argv for a run in `dir`: binaries by absolute path, or the lock copied in.
fn isolated_argv(args: &[String], dir: &Path) -> Result<Vec<String>, String> {
    let abs = |p: &str| {
        std::path::absolute(p)
            .map(|a| a.to_string_lossy().into_owned())
            .map_err(|e| format!("{p}: {e}"))
    };
    let mut argv = args.to_vec();
    if args.get(1).map(String::as_str) == Some("bin") {
        for a in argv.iter_mut().skip(2).filter(|a| !a.starts_with('-')) {
            *a = abs(a)?;
        }
    } else {
        let i = args
            .iter()
            .position(|a| a == "--file")
            .ok_or("audit: neither `bin <path>` nor `--file <lock>`")?;
        let lock = args.get(i + 1).ok_or("audit: --file without a path")?;
        let copy = dir.join("Cargo.lock");
        std::fs::copy(lock, &copy).map_err(|e| format!("{lock}: {e}"))?;
        argv[i + 1] = copy.to_string_lossy().into_owned();
    }
    Ok(argv)
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
            let same = base
                .iter()
                .find(|b| b.name == h.name && b.target == h.target);
            // Unchanged only when the same (name, target) names the same source and bytes: the
            // repo is part of the pin, and a new target is always a candidate.
            if same.is_some_and(|b| b.repo == h.repo && b.rev == h.rev && b.sha == h.sha) {
                return None;
            }
            let b = same.or_else(|| base.iter().find(|b| b.name == h.name));
            Some((b.cloned(), h.clone()))
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
        axis @ ("caps" | "build") => {
            let file = if axis == "caps" {
                "caps.toml"
            } else {
                "build.jsonl"
            };
            let h = s(v, &["evidence_sha256"]);
            if h.len() != 64
                || !h
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                return Err(format!(
                    "{axis} ack without `evidence_sha256` (64 lowercase hex of the {file} it \
                     signs, #380) — it would cover any rewrite of that record"
                ));
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
    ack_covers_evidence(acks, "caps", digest, caps_sha256)
}

/// An ack on `axis` for `digest` that names the sha256 of the exact evidence bytes it signed.
fn ack_covers_evidence(acks: &Acks, axis: &str, digest: &str, evidence_sha256: &str) -> bool {
    acks.entries.iter().any(|a| {
        s(a, &["axis"]) == axis
            && s(a, &["product", "digest"]) == digest
            && s(a, &["evidence_sha256"]) == evidence_sha256
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
    ack_template_evidence("caps", tool, digest, caps_sha256)
}

fn ack_template_evidence(axis: &str, tool: &str, digest: &str, evidence_sha256: &str) -> String {
    serde_json::json!({
        "schema": "hp-thermal/evidence-ack/v1",
        "axis": axis,
        "product": {"name": tool, "digest": digest},
        "evidence_sha256": evidence_sha256,
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

/// Verifies that a committed mal record is the line a monitor run printed for (tool, digest).
type MalCustody<'a> = &'a dyn Fn(&str, &str, &str) -> Result<(), String>;

/// Custody of a mal record (the last line of `mal.jsonl`): its `source` names one run of
/// `supply-chain-monitor.yml` of this repository, scheduled or dispatched, on `main`, or on a
/// `candidate/*` branch whose monitor workflow at the run's commit is the base commit's
/// (`base_monitor`; none given, candidate runs are not accepted); and that run's `vt-monitor` log
/// holds exactly one record line for (tool, digest), which the committed line is, verbatim or as
/// its canonical serialization (`candidate-advance` and `release-advance` write that). A record
/// composed or edited by hand, or printed by a run anywhere else, is not the monitor's; a log
/// past its retention leaves the record unverifiable, and a fresh panel is recorded instead.
fn monitor_custody(
    tool: &str,
    digest: &str,
    line: &str,
    base_monitor: Option<&str>,
) -> Result<(), String> {
    let source = MonitorSource {
        run: &|id| {
            crate::advance::gh_json(&[
                "api",
                &format!("repos/{{owner}}/{{repo}}/actions/runs/{id}"),
            ])
        },
        workflow_at: &|sha| {
            crate::advance::gh(&[
                "api",
                &format!(
                    "repos/{{owner}}/{{repo}}/contents/.github/workflows/supply-chain-monitor.yml?ref={sha}"
                ),
                "-H",
                "Accept: application/vnd.github.raw+json",
            ])
        },
        log: &|id| crate::advance::gh(&["run", "view", id, "--log"]),
    };
    monitor_custody_from(&source, tool, digest, line, base_monitor)
}

/// Where `monitor_custody` reads a run: its metadata, the monitor workflow at a commit, its log.
struct MonitorSource<'a> {
    run: &'a dyn Fn(&str) -> Result<Value, String>,
    workflow_at: &'a dyn Fn(&str) -> Result<String, String>,
    log: &'a dyn Fn(&str) -> Result<String, String>,
}

fn monitor_custody_from(
    source: &MonitorSource,
    tool: &str,
    digest: &str,
    line: &str,
    base_monitor: Option<&str>,
) -> Result<(), String> {
    let id = monitor_run_id(line)?;
    let run = (source.run)(&id)?;
    if monitor_run_ok(&run)? {
        let sha = run.get("head_sha").and_then(Value::as_str).unwrap_or("");
        if sha.len() != 40 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("monitor run {id}: no head commit"));
        }
        if base_monitor != Some((source.workflow_at)(sha)?.as_str()) {
            return Err(format!(
                "monitor run {id} ran on a candidate branch whose monitor workflow is not the base's"
            ));
        }
    }
    let log = (source.log)(&id)
        .map_err(|e| format!("monitor run {id}: no log ({e}); record a fresh panel"))?;
    record_in_log(&log, tool, digest, line)
}

/// The monitor run a record names: `source` is exactly `supply-chain-monitor run <id> (lookup)`.
fn monitor_run_id(line: &str) -> Result<String, String> {
    let v: Value = serde_json::from_str(line).map_err(|e| format!("record: {e}"))?;
    let src = s(&v, &["source"]);
    src.strip_prefix("supply-chain-monitor run ")
        .and_then(|r| r.strip_suffix(" (lookup)"))
        .filter(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()))
        .map(str::to_string)
        .ok_or_else(|| format!("source `{src}` names no single supply-chain-monitor run"))
}

/// The run is this repository's monitor workflow, scheduled or dispatched, done, on `main` or a
/// `candidate/*` branch. `Ok(true)`: a candidate branch, whose monitor workflow must still be
/// shown to be the base's.
fn monitor_run_ok(run: &Value) -> Result<bool, String> {
    let field = |k: &str| run.get(k).and_then(Value::as_str).unwrap_or("");
    let repo = run.pointer("/repository/full_name").and_then(Value::as_str);
    let head_repo = run
        .pointer("/head_repository/full_name")
        .and_then(Value::as_str);
    let branch = field("head_branch");
    let candidate = branch
        .strip_prefix("candidate/")
        .is_some_and(|b| !b.is_empty());
    let checks = [
        (
            field("path") == ".github/workflows/supply-chain-monitor.yml",
            "not supply-chain-monitor.yml",
        ),
        (
            branch == "main" || candidate,
            "not on main or a candidate branch",
        ),
        (
            matches!(field("event"), "schedule" | "workflow_dispatch"),
            "not scheduled or dispatched",
        ),
        (field("status") == "completed", "not completed"),
        (
            repo.is_some() && repo == head_repo,
            "not this repository's own code",
        ),
    ];
    match checks.iter().find(|(ok, _)| !ok) {
        Some((_, why)) => Err(format!(
            "run {}: {why}",
            run.get("id").unwrap_or(&Value::Null)
        )),
        None => Ok(candidate),
    }
}

/// The run's log holds exactly one record line for (tool, digest), and the committed `line` is
/// it, verbatim or as its canonical serialization. A record line is a whole message of the
/// `vt-monitor` job (`gh run view --log`: job, step, then a timestamp and the message), the
/// record prefix at its start; two such lines would mean text posing as a record, and neither
/// is accepted.
fn record_in_log(log: &str, tool: &str, digest: &str, line: &str) -> Result<(), String> {
    let key = format!("record (mal.jsonl line for supply-chain/evidence/{tool}/{digest}/): ");
    let found: Vec<&str> = log
        .lines()
        .filter_map(|l| {
            let mut f = l.splitn(3, '\t');
            let (job, _step, rest) = (f.next()?, f.next()?, f.next()?);
            let message = rest.split_once(' ')?.1.trim_start();
            (job == "vt-monitor")
                .then(|| message.strip_prefix(key.as_str()))
                .flatten()
                .map(str::trim_end)
        })
        .collect();
    let committed = line.trim_end();
    let canonical = |printed: &str| {
        serde_json::from_str::<Value>(printed)
            .ok()
            .and_then(|v| serde_json::to_string(&v).ok())
    };
    match found.as_slice() {
        [one] if *one == committed || canonical(one).as_deref() == Some(committed) => Ok(()),
        [] => Err("the run's log holds no record line for this digest".into()),
        [_] => Err("the run printed another record for this digest than the committed one".into()),
        many => Err(format!(
            "the run's log holds {} record lines for this digest; one is expected",
            many.len()
        )),
    }
}

fn mal_verdict(
    tool: &str,
    evidence_dir: &Path,
    head: &ToolLine,
    acks: &Acks,
    floors: &crate::floors::Floors,
    custody: MalCustody,
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
    // A record that blocks needs no custody to block; one that would let the digest through
    // must be the monitor's own.
    if let Err(e) = custody(tool, digest, last) {
        return Verdict::Unevaluated(format!("{}: mal record custody: {e}", path.display()));
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

/// The base commit's record for its pinned digest, selected under the base commit's lock
/// (evidence README rule 2). `None` when it cannot be selected: the axes then have no prior,
/// which raises and never allows.
fn base_record_dir(
    base_evidence_dir: &Path,
    base_locks_dir: Option<&Path>,
    tool: &str,
    base: Option<&ToolLine>,
) -> Option<PathBuf> {
    let b = base?;
    let none = PathBuf::from("<no base locks dir>");
    crate::evidence_rev::current(
        base_evidence_dir,
        base_locks_dir.unwrap_or(&none),
        tool,
        &b.sha,
    )
    .map(|r| r.dir)
    .map_err(|e| eprintln!("gate: base record for {tool}: {e}"))
    .ok()
}

/// The prior blessed inventory for a candidate: the base record's caps.toml.
fn base_caps_of(base_dir: Option<&Path>) -> Option<String> {
    std::fs::read_to_string(base_dir?.join("caps.toml")).ok()
}

/// `dir` is the record the head selects under its lock (`evidence_rev::current`).
fn caps_verdict(
    tool: &str,
    dir: &Path,
    base_caps: Option<String>,
    head: &ToolLine,
    acks: &Acks,
    floors: &crate::floors::Floors,
    locks: (Option<&Path>, Option<&Path>),
) -> Verdict {
    let (head_lock, base_lock) = locks;
    let digest = head.sha.as_str();
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

/// The prior blessed build record for a TOOLS.lock candidate: the base entry's build.jsonl, read
/// from the BASE commit's evidence tree (a PR cannot rewrite the prior it is compared against),
/// and only for the same target (another target's build scripts emit other cfgs).
fn base_record_of(
    base_dir: Option<&Path>,
    base: Option<&ToolLine>,
    head: &ToolLine,
) -> Option<String> {
    base.filter(|b| b.target == head.target)?;
    std::fs::read_to_string(base_dir?.join(crate::build_record::FILE)).ok()
}

/// Custody of a committed build record, as the gate runs it: the raw record in the store, one
/// producer statement naming record and binary, the committed messages equal to the raw
/// record's, and the producer run made at a commit whose pipeline equals HEAD's.
fn record_custody(text: &str, h: &ToolLine) -> Result<Vec<Value>, String> {
    let v = crate::build_record::verify_custody(text, &h.name, &h.target, &h.sha)?;
    crate::build_record::same_producer(&v.source_commit, &h.name)?;
    source_custody(&v.source_commit, h)?;
    Ok(v.messages)
}

/// The pin names the source its producer built from: custody proves the bytes came from a
/// producer run at `commit`, and that run built the row its own `tools/TOOLS.lock` holds for
/// the pin's (name, target). That row's repo and rev must be the pin's.
fn source_custody(commit: &str, h: &ToolLine) -> Result<(), String> {
    let text = crate::advance::git(&["show", &format!("{commit}:tools/TOOLS.lock")])?;
    producer_source(&text, h)
}

fn producer_source(lock_at_commit: &str, h: &ToolLine) -> Result<(), String> {
    let row = parse_tools_lock(lock_at_commit)
        .into_iter()
        .find(|r| r.name == h.name && r.target == h.target)
        .ok_or_else(|| {
            format!(
                "the producer commit's TOOLS.lock pins no {} [{}]",
                h.name, h.target
            )
        })?;
    if row.repo != h.repo || row.rev != h.rev {
        return Err(format!(
            "the producer built {} [{}] from {}@{}; the pin names {}@{}",
            h.name,
            h.target,
            row.repo,
            &row.rev[..row.rev.len().min(12)],
            h.repo,
            &h.rev[..h.rev.len().min(12)]
        ));
    }
    Ok(())
}

/// Verifies a committed build record's custody; returns its messages.
type Custody<'a> = &'a dyn Fn(&str, &ToolLine) -> Result<Vec<Value>, String>;

/// The prior blessed state the build axis compares against: its build record and its
/// capability inventory (for the instrument reconciliation).
struct Prior {
    record: Option<String>,
    caps: Option<String>,
}

/// The build axis: cargo's record of the build that produced the digest (`build.jsonl`).
///   * missing, unparseable, or failing custody (`record_custody`): UNEVALUATED.
///   * a `rustc-env` the prior record lacks for the same package series, or a link search path
///     outside the package's own directories and the policy's pinned-toolset folders: HARD-STOP.
///   * a `rustc-cfg` or link library the prior record lacks, a new disagreement between the
///     record and the digest's capability inventory (`floors::reconcile`), no prior record to
///     compare, or a record added or rewritten under a digest already pinned (`evidence_edit`):
///     RAISE, signed by a `build` ack bound to the record's bytes. The template lists what is
///     new under `finding`.
///   * otherwise ALLOW.
///
/// `dir` is the record the head selects under its lock (`evidence_rev::current`).
fn build_verdict(
    dir: &Path,
    prior: Prior,
    head: &ToolLine,
    acks: &Acks,
    floors: &crate::floors::Floors,
    evidence_edit: bool,
    custody: Custody,
) -> Verdict {
    let tool = head.name.as_str();
    let path = dir.join(crate::build_record::FILE);
    let Ok(bytes) = std::fs::read(&path) else {
        return Verdict::Unevaluated(format!(
            "no build record at {} — `candidate-advance digest` records it from the producer run",
            path.display()
        ));
    };
    let text = String::from_utf8_lossy(&bytes);
    let (hdr, msgs) = match crate::build_record::read_evidence(&text) {
        Ok(x) => x,
        Err(e) => return Verdict::Unevaluated(format!("{}: {e}", path.display())),
    };
    if s(&hdr, &["subject", "sha256"]) != head.sha {
        return Verdict::Unevaluated(format!("{}: names another digest", path.display()));
    }
    match custody(&text, head) {
        Ok(verified) if verified == msgs => {}
        Ok(_) => {
            return Verdict::Unevaluated(format!(
                "{}: custody returned other messages",
                path.display()
            ));
        }
        Err(e) => return Verdict::Unevaluated(format!("{}: custody: {e}", path.display())),
    }
    let prior_caps = prior.caps;
    let prior = match prior
        .record
        .as_deref()
        .map(crate::build_record::read_evidence)
    {
        None => None,
        Some(Ok((_, m))) => Some(m),
        Some(Err(e)) => {
            return Verdict::Unevaluated(format!("prior build record not parseable: {e}"));
        }
    };
    if let Some(why) = floors.build_record_stop(&msgs, prior.as_deref()) {
        return Verdict::HardStop(why);
    }
    let toolset = std::fs::read_to_string(".cargo/config.toml")
        .ok()
        .and_then(|c| crate::build_env::pin(&c).ok())
        .map(|p| p.toolset);
    if let Some(why) = floors.record_link_search_stop(&msgs, toolset.as_deref()) {
        return Verdict::HardStop(why);
    }
    let sha = crate::sha256::sha256_hex(&bytes);
    let new_cfgs = prior
        .as_deref()
        .map(|p| crate::build_record::new_cfgs(&msgs, p))
        .unwrap_or_default();
    let new_libs = prior
        .as_deref()
        .map(|p| crate::build_record::new_link_libs(&msgs, p))
        .unwrap_or_default();
    // Instrument reconciliation: what this record and this digest's inventory disagree on, less
    // what the prior record and prior inventory already disagreed on (and were signed with).
    let head_caps = std::fs::read_to_string(dir.join("caps.toml")).ok();
    let disagree = |m: &[Value], c: &str| crate::floors::reconcile(m, c);
    let head_dis = match head_caps.as_deref().map(|c| disagree(&msgs, c)) {
        None => BTreeSet::new(),
        Some(Ok(d)) => d,
        Some(Err(e)) => {
            return Verdict::Unevaluated(format!(
                "inventory not parseable for reconciliation: {e}"
            ));
        }
    };
    let prior_dis = match (prior.as_deref(), prior_caps.as_deref()) {
        (Some(m), Some(c)) => match disagree(m, c) {
            Ok(d) => Some(d),
            Err(e) => {
                return Verdict::Unevaluated(format!(
                    "prior inventory not parseable for reconciliation: {e}"
                ));
            }
        },
        _ => None,
    };
    let new_dis: Vec<String> = match &prior_dis {
        Some(p) => head_dis.difference(p).cloned().collect(),
        None => head_dis.iter().cloned().collect(),
    };
    if prior.is_some()
        && !evidence_edit
        && new_cfgs.is_empty()
        && new_libs.is_empty()
        && (prior_dis.is_none() || new_dis.is_empty())
    {
        return Verdict::Allow(format!(
            "build record {}: no rustc-cfg, rustc-env, link library, or instrument disagreement beyond the prior record",
            &sha[..12]
        ));
    }
    let what = if evidence_edit {
        "added or rewritten under a pinned digest".to_string()
    } else if prior.is_none() {
        "no prior record to compare".to_string()
    } else {
        format!(
            "new against the prior record: {}",
            new_cfgs
                .iter()
                .chain(&new_libs)
                .chain(&new_dis)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    if ack_covers_evidence(acks, "build", &head.sha, &sha) {
        Verdict::RaiseCovered(vec![format!(
            "build record {} (content sha256 {sha}), {what}: reviewed + acked",
            head.sha
        )])
    } else {
        let mut template: Value =
            serde_json::from_str(&ack_template_evidence("build", tool, &head.sha, &sha))
                .expect("template is JSON");
        let mut finding = serde_json::Map::new();
        if !new_cfgs.is_empty() {
            finding.insert("new_rustc_cfg".into(), serde_json::json!(new_cfgs));
        }
        if !new_libs.is_empty() {
            finding.insert("new_link_lib".into(), serde_json::json!(new_libs));
        }
        if !new_dis.is_empty() {
            finding.insert("instrument_disagreement".into(), serde_json::json!(new_dis));
        }
        if !finding.is_empty() {
            template["finding"] = Value::Object(finding);
        }
        Verdict::RaiseUncovered {
            covered: Vec::new(),
            needed: vec![template.to_string()],
        }
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
    let out = audit_isolated(&prog, &args)?;
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
const EVIDENCE_FILES: &[&str] = &[
    "caps.toml",
    "caps.UNEVALUATED",
    "mal.jsonl",
    "vuln.jsonl",
    "build.jsonl",
];

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

/// Products (every directory of the store, either side: the tools and the app) whose
/// acks.jsonl differs from the base commit's — loaded and quality-checked even when nothing else
/// changed, so a malformed or placeholder sign-off cannot land unnoticed.
pub(crate) fn changed_ack_files(evidence_dir: &Path, base_evidence_dir: &Path) -> Vec<String> {
    let products: BTreeSet<String> = [evidence_dir, base_evidence_dir]
        .iter()
        .filter_map(|r| std::fs::read_dir(r).ok())
        .flat_map(|d| d.flatten())
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    products
        .into_iter()
        .filter(|t| {
            let rel = Path::new(t).join("acks.jsonl");
            read_opt(&evidence_dir.join(&rel)) != read_opt(&base_evidence_dir.join(&rel))
        })
        .collect()
}

/// A record that is history grows by lines: unchanged, new, or the base's complete lines
/// followed by more. Removed, edited, or extending the base's unfinished last line, it does not.
fn grows_by_lines(head: Option<&[u8]>, base: Option<&[u8]>) -> bool {
    match (head, base) {
        (None, _) => false,
        (Some(_), None) => true,
        (Some(h), Some(b)) => h == b || b.is_empty() || (b.ends_with(b"\n") && h.starts_with(b)),
    }
}

/// Panel history moves forward. Unchanged, or new, it stands as it is. Otherwise the change
/// appends exactly one panel to the base's complete lines, and that panel is newer than every
/// panel before it: a later monitor run, and no earlier panel date. A panel already recorded,
/// replayed after a later one, would read an old verdict as the current one.
fn mal_history(head: Option<&[u8]>, base: Option<&[u8]>) -> Result<(), String> {
    let head = head.ok_or("mal.jsonl removed; panel history is never removed")?;
    let Some(base) = base.filter(|b| !b.is_empty()) else {
        return Ok(());
    };
    if head == base {
        return Ok(());
    }
    // (A base without its final newline cannot be extended to one valid new panel line: what
    // follows it is either the rest of that line, which is no panel, or a newline and then more.)
    let added = head
        .strip_prefix(base)
        .ok_or("panel history is append-only; a panel is added, never rewritten or removed")?;
    let added = std::str::from_utf8(added).map_err(|e| e.to_string())?;
    let new = added.strip_suffix('\n').unwrap_or(added);
    if new.trim().is_empty() || new.contains('\n') {
        return Err("a change appends exactly one panel".into());
    }
    let prior = std::str::from_utf8(base).map_err(|e| e.to_string())?;
    let v: Value = serde_json::from_str(new).map_err(|e| format!("the new panel: {e}"))?;
    let (date, run) = (
        s(&v, &["panelDate"]).to_string(),
        monitor_run_id(new).ok().and_then(|r| r.parse::<u64>().ok()),
    );
    for p in prior.lines().filter(|l| !l.trim().is_empty()) {
        if p.trim_end() == new.trim_end() {
            return Err("the new panel is one already recorded".into());
        }
        let Ok(pv) = serde_json::from_str::<Value>(p) else {
            continue;
        };
        let pd = s(&pv, &["panelDate"]);
        if !pd.is_empty() && date.as_str() < pd {
            return Err(format!(
                "the new panel ({date}) is older than one before it ({pd})"
            ));
        }
        let pr = monitor_run_id(p).ok().and_then(|r| r.parse::<u64>().ok());
        if let (Some(n), Some(o)) = (run, pr)
            && n <= o
        {
            return Err(format!(
                "the new panel's monitor run {n} is not after an earlier panel's ({o})"
            ));
        }
    }
    Ok(())
}

/// A product's `mal.jsonl` (`tool/digest` from `h`): its history moves forward
/// (`mal_history`), and its last panel is judged as any panel is (`mal_verdict`).
fn mal_edit_verdict(
    evidence_dir: &Path,
    base_evidence_dir: &Path,
    h: &ToolLine,
    acks: &Acks,
    floors: &crate::floors::Floors,
    custody: MalCustody,
) -> Verdict {
    let rel = Path::new(&h.name).join(&h.sha).join("mal.jsonl");
    let (head, base) = (
        read_opt(&evidence_dir.join(&rel)),
        read_opt(&base_evidence_dir.join(&rel)),
    );
    if head.is_none() && base.is_none() {
        return mal_verdict(&h.name, evidence_dir, h, acks, floors, custody);
    }
    match mal_history(head.as_deref(), base.as_deref()) {
        Ok(()) => mal_verdict(&h.name, evidence_dir, h, acks, floors, custody),
        Err(e) => Verdict::Unevaluated(format!("mal.jsonl: {e}")),
    }
}

// ---------- the app's records (hp-thermal) ----------

/// The app product: its records describe a published release's exe, by digest
/// (`release-advance`).
const APP: &str = "hp-thermal";

/// A release's original attestations, by kind (`release_advance::anchor_file`).
const APP_ANCHORS: &[&str] = &[
    "provenance.sigstore.jsonl",
    "sbom.sigstore.jsonl",
    "sarif.sigstore.jsonl",
    "vsa.sigstore.jsonl",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Change {
    Added,
    Modified,
    Deleted,
}

/// The app's digest directories whose entries differ from the base commit's, each with what
/// changed. A directory inside a digest directory is listed as `<name>/`, added: the app's
/// records are files.
fn app_changes(
    evidence_dir: &Path,
    base_evidence_dir: &Path,
) -> BTreeMap<String, Vec<(String, Change)>> {
    let entries = |root: &Path| -> BTreeMap<String, BTreeMap<String, Option<Vec<u8>>>> {
        let mut out = BTreeMap::new();
        for d in std::fs::read_dir(root.join(APP))
            .into_iter()
            .flatten()
            .flatten()
        {
            if !d.path().is_dir() {
                continue;
            }
            let files = std::fs::read_dir(d.path())
                .into_iter()
                .flatten()
                .flatten()
                .map(|f| {
                    let name = f.file_name().to_string_lossy().into_owned();
                    if f.path().is_dir() {
                        (format!("{name}/"), None)
                    } else {
                        (name, std::fs::read(f.path()).ok())
                    }
                })
                .collect();
            out.insert(d.file_name().to_string_lossy().into_owned(), files);
        }
        out
    };
    let (head, base) = (entries(evidence_dir), entries(base_evidence_dir));
    let empty = BTreeMap::new();
    let mut out: BTreeMap<String, Vec<(String, Change)>> = BTreeMap::new();
    for d in head.keys().chain(base.keys()).collect::<BTreeSet<_>>() {
        let (h, b) = (head.get(d).unwrap_or(&empty), base.get(d).unwrap_or(&empty));
        for f in h.keys().chain(b.keys()).collect::<BTreeSet<_>>() {
            let change = match (h.get(f), b.get(f)) {
                (Some(_), None) => Change::Added,
                (None, Some(_)) => Change::Deleted,
                (Some(x), Some(y)) if f.ends_with('/') || x != y => Change::Modified,
                _ => continue,
            };
            out.entry(d.clone()).or_default().push((f.clone(), change));
        }
    }
    out
}

/// How each new app record proves itself (network-backed in the gate; injected in tests).
struct AppCustody<'a> {
    /// (digest, file, text): an anchor file's bundles (`store_anchor_custody`).
    anchors: &'a dyn Fn(&str, &str, &str) -> Result<String, String>,
    /// (digest directory, digest): a vulnerability record (`app_vuln_custody`).
    vuln: &'a dyn Fn(&Path, &str) -> Result<String, String>,
    mal: MalCustody<'a>,
}

/// `vdr.v<N>.sigstore.jsonl`: a VDR revision's anchor, N its version.
fn vdr_anchor_version(file: &str) -> Option<u64> {
    file.strip_prefix("vdr.v")?
        .strip_suffix(".sigstore.jsonl")
        .filter(|n| !n.is_empty() && !n.starts_with('0') && n.bytes().all(|b| b.is_ascii_digit()))?
        .parse()
        .ok()
}

/// Verdicts for one app digest directory's changes. The records are written once by
/// `release-advance` and only these change: an anchor is added (never replaced or removed), a
/// first `vuln.jsonl` is added, `mal.jsonl` grows by appended panels, `vdr.cdx.json` follows the
/// report ledger (`vdr_ledger`). The digest must be a release's: its provenance anchor is there.
/// Anything else is UNEVALUATED.
fn app_verdicts(
    evidence_dir: &Path,
    base_evidence_dir: &Path,
    digest: &str,
    changes: &[(String, Change)],
    acks: &Acks,
    floors: &crate::floors::Floors,
    c: &AppCustody,
) -> Vec<(&'static str, Verdict)> {
    let dir = evidence_dir.join(APP).join(digest);
    let mut axes = Vec::new();
    if !crate::advance::is_hex64(digest) || digest.bytes().any(|b| b.is_ascii_uppercase()) {
        axes.push((
            "release",
            Verdict::Unevaluated(format!("{digest}: not a lowercase sha256 digest directory")),
        ));
        return axes;
    }
    if !dir.join("provenance.sigstore.jsonl").is_file() {
        axes.push((
            "release",
            Verdict::Unevaluated(
                "no provenance anchor for this digest: the app's records describe a published \
                 release's exe"
                    .into(),
            ),
        ));
    }
    for (f, ch) in changes {
        let anchor = APP_ANCHORS.contains(&f.as_str()) || vdr_anchor_version(f).is_some();
        let text = || std::fs::read_to_string(dir.join(f)).map_err(|e| format!("{f}: {e}"));
        let (axis, v) = match (f.as_str(), *ch) {
            ("vdr.cdx.json", _) => continue, // the report ledger and `vdr check`
            (_, Change::Added) if anchor => (
                "anchor",
                match text().and_then(|t| (c.anchors)(digest, f, &t)) {
                    Ok(m) => Verdict::Allow(format!("{f}: {m}")),
                    Err(e) => Verdict::Unevaluated(format!("{f}: {e}")),
                },
            ),
            (_, ch) if anchor => (
                "anchor",
                Verdict::Unevaluated(format!(
                    "{f} {ch:?}: an anchor is never replaced or removed"
                )),
            ),
            ("vuln.jsonl", Change::Added) => (
                "vuln",
                match (c.vuln)(&dir, digest) {
                    Ok(m) => Verdict::Allow(m),
                    Err(e) => Verdict::Unevaluated(format!("vuln.jsonl: {e}")),
                },
            ),
            ("vuln.jsonl", ch) => (
                "vuln",
                Verdict::Unevaluated(format!(
                    "vuln.jsonl {ch:?}: written once by release-advance, never edited"
                )),
            ),
            ("mal.jsonl", _) => {
                let line = ToolLine {
                    name: APP.into(),
                    repo: String::new(),
                    rev: String::new(),
                    target: String::new(),
                    sha: digest.into(),
                };
                let v =
                    mal_edit_verdict(evidence_dir, base_evidence_dir, &line, acks, floors, c.mal);
                ("mal", v)
            }
            (f, ch) => (
                "record",
                Verdict::Unevaluated(format!("{f} {ch:?}: not one of the app's records")),
            ),
        };
        axes.push((axis, v));
    }
    axes
}

/// A DSSE bundle's in-toto statement.
fn bundle_statement(bundle: &Value) -> Option<Value> {
    let p = bundle.pointer("/dsseEnvelope/payload")?.as_str()?;
    serde_json::from_slice(&crate::release_advance::b64decode(p)?).ok()
}

/// Every line of an anchor file is a bundle GitHub's attestation store holds for the digest
/// (`stored`), and of the kind the file is named for. Each statement's subjects include
/// `hp-thermal.exe` at the digest. Provenance is SLSA v1 from one of this repository's release
/// workflows at a tag; sbom, sarif and vsa go by predicate type, and an sbom is not the
/// subject's VDR; `vdr.v<N>` is the subject's own VDR (its serialNumber) at version N.
fn anchors_in_store(
    digest: &str,
    file: &str,
    text: &str,
    stored: &[&Value],
    repo: &str,
) -> Result<String, String> {
    use crate::release_advance::{CYCLONEDX, PROVENANCE, RELEASE_SIGNERS, anchor_file};
    let serial = crate::vdr::serial_number(digest);
    let mut n = 0;
    for (i, l) in text
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty())
    {
        let at = |e: String| format!("line {}: {e}", i + 1);
        let b: Value = serde_json::from_str(l).map_err(|e| at(e.to_string()))?;
        // Byte for byte the store's bundle, canonically serialized (as release-advance writes
        // it): a line that only parses to it (a repeated key, another spelling) is not it.
        let line = l.trim_end();
        if !stored
            .iter()
            .any(|s| serde_json::to_string(s).is_ok_and(|c| c == line))
        {
            return Err(at(format!(
                "not a bundle GitHub's attestation store holds for {}",
                &digest[..12]
            )));
        }
        let st = bundle_statement(&b).ok_or_else(|| at("no in-toto statement".into()))?;
        let exe = st["subject"].as_array().is_some_and(|a| {
            a.iter().any(|x| {
                x["name"] == "hp-thermal.exe"
                    && x.pointer("/digest/sha256").and_then(Value::as_str) == Some(digest)
            })
        });
        if !exe {
            return Err(at(
                "its subjects do not include hp-thermal.exe at this digest".into(),
            ));
        }
        let pt = s(&st, &["predicateType"]);
        let pred_serial = st
            .pointer("/predicate/serialNumber")
            .and_then(Value::as_str);
        if let Some(v) = vdr_anchor_version(file) {
            let version = st.pointer("/predicate/version").and_then(Value::as_u64);
            if pt != CYCLONEDX || pred_serial != Some(serial.as_str()) || version != Some(v) {
                return Err(at(format!("not this subject's VDR at version {v}")));
            }
        } else if anchor_file(pt) != Some(file) {
            return Err(at(format!("predicate type {pt} is not {file}'s kind")));
        } else if file == "sbom.sigstore.jsonl" && pred_serial == Some(serial.as_str()) {
            return Err(at("the subject's VDR, not its SBOM".into()));
        } else if pt == PROVENANCE {
            let wf = st.pointer("/predicate/buildDefinition/externalParameters/workflow");
            let field = |k: &str| wf.and_then(|w| w.get(k)).and_then(Value::as_str);
            let path_ok = field("path").is_some_and(|p| {
                RELEASE_SIGNERS
                    .iter()
                    .any(|w| p == format!(".github/workflows/{w}"))
            });
            if field("repository") != Some(format!("https://github.com/{repo}").as_str())
                || !path_ok
                || !field("ref").is_some_and(|r| r.starts_with("refs/tags/"))
            {
                return Err(at(
                    "not provenance from this repository's release workflow at a tag".into(),
                ));
            }
        }
        n += 1;
    }
    if n == 0 {
        return Err("no bundle".into());
    }
    Ok(format!(
        "{n} bundle(s), each in GitHub's attestation store for this digest and of this file's kind"
    ))
}

/// `anchors_in_store` against the attestations GitHub stores for the digest.
fn store_anchor_custody(digest: &str, file: &str, text: &str) -> Result<String, String> {
    let list = crate::advance::gh_json(&[
        "api",
        &format!("repos/{{owner}}/{{repo}}/attestations/sha256:{digest}?per_page=100"),
    ])?;
    let atts = list["attestations"]
        .as_array()
        .ok_or("attestations API: no `attestations` array")?;
    if atts.len() >= 100 {
        return Err("100 or more attestations for one digest: the list may be truncated".into());
    }
    let stored: Vec<&Value> = atts.iter().map(|a| &a["bundle"]).collect();
    let repo = crate::advance::gh(&[
        "repo",
        "view",
        "--json",
        "nameWithOwner",
        "--jq",
        ".nameWithOwner",
    ])?;
    anchors_in_store(digest, file, text, &stored, repo.trim())
}

/// The commit a release's exe was built from: the source its provenance anchor resolved.
fn release_commit(dir: &Path) -> Result<String, String> {
    let text = std::fs::read_to_string(dir.join("provenance.sigstore.jsonl"))
        .map_err(|e| format!("provenance anchor: {e}"))?;
    let first = text
        .lines()
        .find(|l| !l.trim().is_empty())
        .ok_or("provenance anchor: empty")?;
    let st = serde_json::from_str::<Value>(first)
        .ok()
        .and_then(|b| bundle_statement(&b))
        .ok_or("provenance anchor: no statement")?;
    st.pointer("/predicate/buildDefinition/resolvedDependencies")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|d| {
            d["uri"]
                .as_str()
                .is_some_and(|u| u.starts_with("git+https://github.com/"))
        })
        .filter_map(|d| d.pointer("/digest/gitCommit").and_then(Value::as_str))
        .find(|c| c.len() == 40 && c.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(str::to_string)
        .ok_or_else(|| "provenance anchor: no resolved source commit".into())
}

/// A release's first vulnerability record: about this exe, its rows the custody-verified raw
/// payload's, measured at the advisory-db commit that payload names, and a scan of
/// `app/Cargo.lock` at the commit the release's provenance names: the pinned auditor, re-scanning
/// that lock at that commit, finds exactly the recorded rows (`evidence_rev::check_rescan`), so a
/// payload of another lock, however alike in size, does not stand in.
fn app_vuln_custody(dir: &Path, digest: &str) -> Result<String, String> {
    let rows: Vec<Value> = std::fs::read_to_string(dir.join("vuln.jsonl"))
        .map_err(|e| e.to_string())?
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;
    let header = rows.first().ok_or("no header")?;
    if s(header, &["subject", "name"]) != APP || s(header, &["subject", "sha256"]) != digest {
        return Err("the header's subject is not this exe".into());
    }
    let commit = release_commit(dir)?;
    let lock = crate::advance::git(&["show", &format!("{commit}:app/Cargo.lock")])?;
    let raw = crate::vdr::fetch_raw(header)?;
    crate::evidence_rev::record_db(header, &raw)?;
    crate::evidence_rev::check_vuln_rows(&rows[1..], &raw, &lock)?;
    let file = std::env::temp_dir().join(format!(
        "gate-app-lock-{}-{}.lock",
        std::process::id(),
        &digest[..12]
    ));
    std::fs::write(&file, &lock).map_err(|e| format!("{}: {e}", file.display()))?;
    let rescan = rescan_at(header, &file, None);
    let _ = std::fs::remove_file(&file);
    crate::evidence_rev::check_rescan(&rows[1..], &rescan?)?;
    Ok(format!(
        "{} row(s) equal raw payload {} and a re-scan of app/Cargo.lock at the release commit {}",
        rows.len() - 1,
        s(header, &["rawPayload", "asset"]),
        &commit[..12]
    ))
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
            if tool == APP {
                continue; // evaluated: `app_verdicts`
            }
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

// ---------- evidence revisions (evidence README rule 2) ----------

/// Where one side's per-tool producer inputs live: the frozen locks, and the `tools/` tree with
/// patches, build args and rustflags (`build_record::producer_inputs`, per-tool part).
#[derive(Clone, Copy)]
struct ToolInputs<'a> {
    locks: &'a Path,
    tools: Option<&'a Path>,
}

impl ToolInputs<'_> {
    fn of(&self, tool: &str) -> BTreeMap<String, Option<Vec<u8>>> {
        let mut m = BTreeMap::new();
        m.insert(
            "locks".to_string(),
            read_opt(&self.locks.join(format!("{tool}.lock"))),
        );
        if let Some(t) = self.tools {
            for d in ["build-args", "rustflags"] {
                m.insert(d.to_string(), read_opt(&t.join(d).join(tool)));
            }
            if let Ok(rd) = std::fs::read_dir(t.join("patches").join(tool)) {
                for e in rd.flatten() {
                    m.insert(
                        format!("patches/{}", e.file_name().to_string_lossy()),
                        read_opt(&e.path()),
                    );
                }
            }
        }
        m
    }
}

/// Pinned lines whose digest is unchanged while one of the tool's producer inputs (frozen lock,
/// patches, build args, rustflags) differs from the base commit's: the evidence they are gated on
/// must be a revision for the new inputs, or nothing admits them. Without the base commit's
/// inputs no change can be seen; CI always passes them.
fn revision_candidates(
    head: &[ToolLine],
    cands: &[(Option<ToolLine>, ToolLine)],
    head_in: ToolInputs,
    base_in: Option<ToolInputs>,
) -> Vec<ToolLine> {
    let Some(base_in) = base_in else {
        return Vec::new();
    };
    let head_in = ToolInputs {
        tools: base_in.tools.and(head_in.tools),
        ..head_in
    };
    head.iter()
        .filter(|h| h.sha != ZERO_DIGEST && h.sha.len() == 64)
        .filter(|h| {
            !cands
                .iter()
                .any(|(_, c)| c.name == h.name && c.target == h.target)
        })
        .filter(|h| head_in.of(&h.name) != base_in.of(&h.name))
        .cloned()
        .collect()
}

/// Root records of a digest the base commit holds evidence for, changed by this change. Blessed
/// evidence is never edited (rule 2); a change that re-pins or revises a digest leaves them byte
/// for byte, and an edit is its own PR, evaluated as an evidence edit (rule 4).
fn blessed_root_edits(
    evidence_dir: &Path,
    base_evidence_dir: &Path,
    h: &ToolLine,
    with_report: bool,
) -> Vec<&'static str> {
    if !base_evidence_dir.join(&h.name).join(&h.sha).is_dir() {
        return Vec::new();
    }
    let mut files = vec![
        "vuln.jsonl",
        "caps.toml",
        "caps.UNEVALUATED",
        crate::build_record::FILE,
    ];
    if with_report {
        files.push("vdr.cdx.json");
    }
    files
        .into_iter()
        .filter(|f| {
            let rel = Path::new(&h.name).join(&h.sha).join(f);
            read_opt(&evidence_dir.join(&rel)) != read_opt(&base_evidence_dir.join(&rel))
        })
        .collect()
}

/// Every committed `vdr.cdx.json` (a digest's, or a revision's) as one CycloneDX ledger per
/// serialNumber, across all its files:
///   * a report the base commit has is never deleted;
///   * only the current report of a subject (`is_current`: the record a pinned digest selects,
///     or an app release's) changes, and then keeps its serialNumber and takes a higher version;
///     a superseded or historical report is frozen;
///   * a (serialNumber, version) names one content, in the change and across base and change;
///   * a report the change adds is a current subject's, and takes a version above every
///     version its serial had;
///   * every report carries its own subject's serialNumber (`vdr::serial_number` of the digest
///     directory it sits in), so no report speaks for another subject's ledger.
fn vdr_ledger(
    evidence_dir: &Path,
    base_evidence_dir: &Path,
    is_current: &dyn Fn(&Path) -> bool,
) -> Vec<String> {
    fn reports(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        let dirs = |p: &Path| -> Vec<PathBuf> {
            std::fs::read_dir(p)
                .map(|r| {
                    r.flatten()
                        .map(|e| e.path())
                        .filter(|p| p.is_dir())
                        .collect()
                })
                .unwrap_or_default()
        };
        let mut out = BTreeMap::new();
        for t in dirs(root) {
            for d in dirs(&t) {
                let mut files = vec![d.join("vdr.cdx.json")];
                files.extend(
                    dirs(&d.join(crate::evidence_rev::REV_DIR))
                        .into_iter()
                        .map(|l| l.join("vdr.cdx.json")),
                );
                for f in files {
                    if let (Ok(rel), Ok(b)) = (f.strip_prefix(root), std::fs::read(&f)) {
                        out.insert(rel.to_path_buf(), b);
                    }
                }
            }
        }
        out
    }
    fn show(p: &Path) -> String {
        p.to_string_lossy().replace('\\', "/")
    }
    fn id(b: &[u8]) -> Option<(String, u64)> {
        let v: Value = serde_json::from_slice(b).ok()?;
        Some((
            v["serialNumber"].as_str()?.to_string(),
            v["version"].as_u64()?,
        ))
    }
    type Names<'a> = BTreeMap<(String, u64), (&'a PathBuf, &'a Vec<u8>)>;
    /// (serial, version) -> the one content naming it, per side.
    fn names<'a>(
        side: &'a BTreeMap<PathBuf, Vec<u8>>,
        label: &str,
        problems: &mut Vec<String>,
    ) -> Names<'a> {
        let mut m: Names<'a> = BTreeMap::new();
        for (p, b) in side {
            match id(b) {
                None => problems.push(format!("{} ({label}): no serialNumber/version", show(p))),
                Some(k) => match m.get(&k) {
                    Some((q, c)) if *c != b => problems.push(format!(
                        "{} and {} both claim {} version {} with different content",
                        show(q),
                        show(p),
                        k.0,
                        k.1
                    )),
                    _ => {
                        m.insert(k, (p, b));
                    }
                },
            }
        }
        m
    }
    let (base, head) = (reports(base_evidence_dir), reports(evidence_dir));
    let mut problems = Vec::new();
    let base_ids = names(&base, "base", &mut problems);
    // Implied by the rules below (one content per version within the change, history frozen,
    // no deletion, forward-only changes, new reports above the serial's maximum); stated
    // directly as the property it protects.
    let head_ids = names(&head, "change", &mut problems);
    for (k, (p, c)) in &head_ids {
        if let Some((_, bc)) = base_ids.get(k)
            && bc != c
        {
            problems.push(format!(
                "{}: {} version {} already named other content",
                show(p),
                k.0,
                k.1
            ));
        }
    }
    for (p, bb) in &base {
        let Some(hb) = head.get(p) else {
            problems.push(format!(
                "{}: deleted; a committed report is history",
                show(p)
            ));
            continue;
        };
        if hb == bb {
            continue;
        }
        let dir = evidence_dir.join(p.parent().unwrap_or(Path::new("")));
        if !is_current(&dir) {
            problems.push(format!(
                "{}: changed, but it is not the current report of a pinned subject; history is frozen",
                show(p)
            ));
            continue;
        }
        match (id(bb), id(hb)) {
            (Some((s0, v0)), Some((s1, v1))) if s0 == s1 && v1 > v0 => {}
            (o, n) => problems.push(format!(
                "{}: {:?} -> {:?}; a changed report keeps its serialNumber and takes a higher version",
                show(p),
                o,
                n
            )),
        }
    }
    for (p, b) in &head {
        // <tool>/<digest>/vdr.cdx.json or <tool>/<digest>/rev/<lock>/vdr.cdx.json
        let digest = p.iter().nth(1).map(|d| d.to_string_lossy().into_owned());
        let own = digest.as_deref().map(crate::vdr::serial_number);
        if let Some((s, _)) = id(b)
            && own.as_ref() != Some(&s)
        {
            problems.push(format!(
                "{}: serialNumber {s} is not its subject's ({})",
                show(p),
                own.unwrap_or_default()
            ));
        }
        if !base.contains_key(p) {
            let dir = evidence_dir.join(p.parent().unwrap_or(Path::new("")));
            if !is_current(&dir) {
                problems.push(format!(
                    "{}: added, but not the current report of a pinned subject",
                    show(p)
                ));
            }
        }
    }
    let max_base: BTreeMap<&String, u64> =
        base_ids.keys().fold(BTreeMap::new(), |mut m, (s, v)| {
            let e = m.entry(s).or_insert(0);
            *e = (*e).max(*v);
            m
        });
    for (p, b) in head.iter().filter(|(p, _)| !base.contains_key(*p)) {
        if let Some((s, v)) = id(b)
            && let Some(m) = max_base.get(&s)
            && v <= *m
        {
            problems.push(format!(
                "{}: new report {s} version {v}, but that serial already reached version {m}",
                show(p)
            ));
        }
    }
    problems
}

/// Record files a reader opens by name under a digest or revision directory.
const RECORD_FILES: &[&str] = &[
    "revision.json",
    "vuln.jsonl",
    "caps.toml",
    "caps.UNEVALUATED",
    "build.jsonl",
    "vdr.cdx.json",
    "mal.jsonl",
];

/// Paths, or directory prefixes of them, that differ only by case. On a case-insensitive
/// checkout (the gate runs on Windows) one spelling stands for the other, so the file the gate
/// reads need not be the file a case-sensitive reader (git, the Linux producer) reads. `paths`
/// is the index together with `opened_paths`: a file renamed by case is not a second index path,
/// but it is a second spelling of the name a reader opens.
pub(crate) fn case_collisions(paths: &[String]) -> Vec<String> {
    let mut by: BTreeMap<String, BTreeSet<&str>> = BTreeMap::new();
    for p in paths {
        for end in p.match_indices('/').map(|(i, _)| i).chain([p.len()]) {
            let pre = &p[..end];
            by.entry(pre.to_lowercase()).or_default().insert(pre);
        }
    }
    by.into_values()
        .filter(|v| v.len() > 1)
        .map(|v| v.into_iter().collect::<Vec<_>>().join(" / "))
        .collect()
}

/// Paths the gate and the workflows open by a name they build rather than one they list: the
/// fixed files, each pinned tool's producer inputs (`build_record::producer_inputs`: its lock,
/// patches, build args and rustflags, and the toolchain, cargo config and producer workflows
/// every build reads) and evidence, and the records under every digest and revision directory
/// the index holds.
pub(crate) fn opened_paths(locks: &[&[ToolLine]], index: &[String]) -> Vec<String> {
    let rev = crate::evidence_rev::REV_DIR;
    let mut out: Vec<String> = [
        "tools/TOOLS.lock",
        "tools/TOOLCHAIN.lock",
        "supply-chain/policy/floors.json",
    ]
    .map(String::from)
    .to_vec();
    let records =
        |d: &str| -> Vec<String> { RECORD_FILES.iter().map(|f| format!("{d}/{f}")).collect() };
    for l in locks.iter().flat_map(|l| l.iter()) {
        let (n, sha) = (&l.name, &l.sha);
        out.extend(crate::build_record::producer_inputs(n));
        out.push(format!("supply-chain/evidence/{n}/acks.jsonl"));
        out.extend(records(&format!("supply-chain/evidence/{n}/{sha}")));
    }
    // supply-chain/evidence/<tool>/<digest>/… and …/<digest>/rev/<lock>/…
    for p in index {
        let c: Vec<&str> = p.split('/').collect();
        if c.len() >= 5 && c[0] == "supply-chain" && c[1] == "evidence" {
            let digest = c[..4].join("/");
            out.push(format!("{digest}/{rev}"));
            out.extend(records(&digest));
            if c.len() >= 7 && c[4] == rev {
                out.extend(records(&c[..6].join("/")));
            }
        }
    }
    out
}

/// Under `roots`, the working tree is the index: every entry a regular file (mode 100644, stage
/// 0) whose bytes, hashed with no filters, are its blob, and no file the index does not hold.
/// Attributes (`eol`, `working-tree-encoding`, `filter`, `ident`), symlinks and stray files
/// would otherwise let a reader of the working tree judge bytes other than the bytes that merge.
pub(crate) fn checkout_problems(repo: &Path, roots: &[&str]) -> Result<Vec<String>, String> {
    let git = |args: &[&str]| -> Result<Vec<u8>, String> {
        let out = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .output()
            .map_err(|e| format!("git {}: {e}", args[0]))?;
        if !out.status.success() {
            return Err(format!(
                "git {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(out.stdout)
    };
    let z = |b: Vec<u8>| -> Vec<String> {
        b.split(|c| *c == 0)
            .filter(|p| !p.is_empty())
            .map(|p| String::from_utf8_lossy(p).into_owned())
            .collect()
    };
    let mut problems = Vec::new();
    let mut files = Vec::new();
    for e in z(git(&[&["ls-files", "-s", "-z", "--"], roots].concat())?) {
        let (meta, path) = e.split_once('\t').ok_or("git ls-files -s: no tab")?;
        let m: Vec<&str> = meta.split(' ').collect();
        if m.len() != 3 || m[0] != "100644" || m[2] != "0" {
            problems.push(format!(
                "{path}: index entry `{meta}`, not a regular file (100644, stage 0)"
            ));
        } else {
            files.push((path.to_string(), m[1].to_string()));
        }
    }
    for chunk in files.chunks(64) {
        let mut args = vec!["hash-object", "--no-filters", "--"];
        args.extend(chunk.iter().map(|(p, _)| p.as_str()));
        let got = String::from_utf8_lossy(&git(&args)?).into_owned();
        let got: Vec<&str> = got.lines().collect();
        if got.len() != chunk.len() {
            return Err("git hash-object: one id per path expected".into());
        }
        for ((p, want), have) in chunk.iter().zip(got) {
            if have != want {
                problems.push(format!(
                    "{p}: the working tree holds other bytes than the index ({}, blob {})",
                    &have[..have.len().min(12)],
                    &want[..want.len().min(12)]
                ));
            }
        }
    }
    for p in z(git(&[&["ls-files", "-o", "-z", "--"], roots].concat())?) {
        problems.push(format!("{p}: in the working tree, not in the index"));
    }
    Ok(problems)
}

/// The checkout the gate (or `vdr check`) reads is the one that merges: `checkout_problems`
/// under `tools/` and `supply-chain/`, and `refuse_case_collisions`. Refused on any.
pub(crate) fn refuse_checkout(lock_texts: &[&str]) -> Result<(), String> {
    let problems = checkout_problems(Path::new("."), &["tools", "supply-chain"])?;
    if !problems.is_empty() {
        return Err(problems.join("; "));
    }
    refuse_case_collisions(lock_texts)
}

/// No `case_collisions` among the index and the paths opened for the pins in `lock_texts`.
pub(crate) fn refuse_case_collisions(lock_texts: &[&str]) -> Result<(), String> {
    let out = Command::new("git")
        .args(["ls-files", "-z"])
        .output()
        .map_err(|e| format!("git ls-files: {e}"))?;
    if !out.status.success() {
        return Err("git ls-files failed: the tree cannot be checked for case collisions".into());
    }
    let index: Vec<String> = out
        .stdout
        .split(|b| *b == 0)
        .filter(|p| !p.is_empty())
        .map(|p| String::from_utf8_lossy(p).into_owned())
        .collect();
    let locks: Vec<Vec<ToolLine>> = lock_texts.iter().map(|t| parse_tools_lock(t)).collect();
    let refs: Vec<&[ToolLine]> = locks.iter().map(Vec::as_slice).collect();
    let mut all = index.clone();
    all.extend(opened_paths(&refs, &index));
    let c = case_collisions(&all);
    if c.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "paths differing only by case (a case-insensitive checkout keeps one): {}",
            c.join("; ")
        ))
    }
}

/// A head record that cannot be selected under the current lock. A recorded `caps.UNEVALUATED`
/// keeps its own reason.
fn unselected(evidence_dir: &Path, h: &ToolLine, why: &str) -> Verdict {
    let marker = evidence_dir
        .join(&h.name)
        .join(&h.sha)
        .join("caps.UNEVALUATED");
    match std::fs::read_to_string(marker) {
        Ok(r) => Verdict::Unevaluated(format!("caps recorded UNEVALUATED: {}", r.trim())),
        Err(_) => Verdict::Unevaluated(format!("no caps record under the current lock: {why}")),
    }
}

/// Custody of a revision's build record: `record_custody`, plus the producer run, and the lock
/// and patches it built from, bound to the revision (`evidence_rev::bind_producer`).
fn revision_custody(
    text: &str,
    h: &ToolLine,
    r: &crate::evidence_rev::Revision,
) -> Result<Vec<Value>, String> {
    let v = crate::build_record::verify_custody(text, &h.name, &h.target, &h.sha)?;
    crate::build_record::same_producer(&v.source_commit, &h.name)?;
    source_custody(&v.source_commit, h)?;
    let (hdr, _) = crate::build_record::read_evidence(text)?;
    let (lock, patches) =
        crate::evidence_rev::producer_tree(Path::new("."), &v.source_commit, &h.name)?;
    crate::evidence_rev::bind_producer(r, s(&hdr, &["producerRun"]), &lock, &patches)?;
    Ok(v.messages)
}

/// cargo-audit's advisory-db clone: `$CARGO_HOME/advisory-db`, else `~/.cargo/advisory-db`.
/// The gate's first paired scan fetched it.
fn advisory_db_dir() -> Option<PathBuf> {
    let home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("USERPROFILE")
                .or_else(|| std::env::var_os("HOME"))
                .map(|h| PathBuf::from(h).join(".cargo"))
        })?;
    let p = home.join("advisory-db");
    p.is_dir().then_some(p)
}

/// Re-scan `lock` with the pinned auditor at the advisory-database commit `header` names. The
/// header must name that auditor's digest: another scanner is another instrument, and its rows
/// are not this one's to reproduce. No pinned auditor, no database commit: refused.
fn rescan_at(header: &Value, lock: &Path, prior_db: Option<&str>) -> Result<Value, String> {
    let dir = std::env::var("PINNED_TOOLS_DIR")
        .map_err(|_| "PINNED_TOOLS_DIR is unset: no pinned auditor to re-scan with")?;
    let exe = PathBuf::from(format!("{dir}/cargo-audit{}", std::env::consts::EXE_SUFFIX));
    let have = crate::sha256::sha256_hex(
        &std::fs::read(&exe).map_err(|e| format!("{}: {e}", exe.display()))?,
    );
    let want = s(header, &["scanner", "digest"]);
    if have != want {
        return Err(format!(
            "vuln.jsonl was recorded by scanner {}, the pinned auditor is {}: re-measure with it",
            want.get(..12).unwrap_or(want),
            &have[..12]
        ));
    }
    let commit = s(header, &["scanner", "db", "version"]);
    if commit.len() != 40 || !commit.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("vuln.jsonl names no advisory-db commit".into());
    }
    let src = advisory_db_dir().ok_or("no advisory-db clone to re-scan from")?;
    let tmp = std::env::temp_dir().join(format!("gate-advisory-db-{}", &commit[..12]));
    let _ = std::fs::remove_dir_all(&tmp);
    let git = |args: &[&str]| -> Result<(), String> {
        let st = Command::new("git")
            .args(args)
            .status()
            .map_err(|e| format!("git: {e}"))?;
        st.success()
            .then_some(())
            .ok_or_else(|| format!("git {} failed", args.join(" ")))
    };
    let t = tmp.to_string_lossy().into_owned();
    git(&[
        "clone",
        "--quiet",
        "--no-checkout",
        &src.to_string_lossy(),
        &t,
    ])?;
    git(&[
        "-C",
        &t,
        "-c",
        "advice.detachedHead=false",
        "checkout",
        "--quiet",
        "--detach",
        commit,
    ])
    .map_err(|_| format!("advisory-db commit {} is not in the clone", &commit[..12]))?;
    if let Some(p) = prior_db {
        git(&["-C", &t, "merge-base", "--is-ancestor", p, commit]).map_err(|_| {
            format!(
                "advisory-db {} does not descend from the superseded record's {}: a revision is                  measured against advisory data at least as new",
                &commit[..12],
                &p[..12.min(p.len())]
            )
        })?;
    }
    let argv: Vec<String> = ["audit", "--db", &t, "--no-fetch", "--json", "--file"]
        .iter()
        .map(|a| a.to_string())
        .chain([lock.display().to_string()])
        .collect();
    let out = audit_isolated(&exe.to_string_lossy(), &argv)?;
    let _ = std::fs::remove_dir_all(&tmp);
    serde_json::from_slice(&out.stdout).map_err(|e| {
        format!(
            "re-scan output is not JSON ({e}); stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

/// A record's vulnerability rows are its custody-verified raw payload's, that payload is
/// consistent with `lock` (`evidence_rev::check_vuln_rows`), and the same scanner finds the same
/// rows in `lock` at the recorded advisory-db commit (`evidence_rev::check_rescan`).
///
/// `prior_db`: for a revision, the superseded record's advisory-db commit. The revision's must
/// descend from it: a correction is measured against advisory data at least as new.
pub(crate) fn verify_vuln_record(
    dir: &Path,
    lock: &Path,
    prior_db: Option<&str>,
) -> Result<String, String> {
    let read = |p: &Path| std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()));
    let lock_text = read(lock)?;
    let rows: Vec<Value> = read(&dir.join("vuln.jsonl"))?
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).map_err(|e| format!("vuln.jsonl: {e}")))
        .collect::<Result<_, _>>()?;
    let header = rows.first().ok_or("vuln.jsonl: no header")?;
    let raw = crate::vdr::fetch_raw(header)?;
    crate::evidence_rev::record_db(header, &raw)?;
    crate::evidence_rev::check_vuln_rows(&rows[1..], &raw, &lock_text)?;
    let rescan = rescan_at(header, lock, prior_db)?;
    crate::evidence_rev::check_rescan(&rows[1..], &rescan)?;
    Ok(format!(
        "{} vulnerability row(s) equal raw payload {} and a re-scan of the lock by the same \
         scanner at advisory-db {}",
        rows.len() - 1,
        s(header, &["rawPayload", "asset"]),
        &s(header, &["scanner", "db", "version"])[..12]
    ))
}

struct RevisionInputs<'a> {
    evidence_dir: &'a Path,
    base_evidence_dir: &'a Path,
    base_tools_lock: &'a str,
    locks_dir: &'a Path,
    base_locks_dir: Option<&'a Path>,
}

/// The revision axis: `evidence_rev::admit_offline`, and the revision's vulnerability rows
/// re-derived from its custody-verified raw payload (`evidence_rev::check_vuln_rows`). The build
/// record's binding to the revision is the build axis's custody (`revision_custody`). Anything
/// short of all of it is UNEVALUATED, never acked.
fn revision_verdict(
    h: &ToolLine,
    head_rec: &Result<crate::evidence_rev::Record, String>,
    i: RevisionInputs,
) -> Verdict {
    let res = (|| -> Result<String, String> {
        let rec = head_rec.as_ref().map_err(String::clone)?;
        let base_locks_dir = i
            .base_locks_dir
            .ok_or("no base locks dir: the superseded lock is unknown")?;
        let read =
            |p: PathBuf| std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()));
        let f = format!("{}.lock", h.name);
        let head_lock = read(i.locks_dir.join(&f))?;
        let base_lock = read(base_locks_dir.join(&f))?;
        let patches = crate::evidence_rev::patches_of(Path::new("."), &h.name)?;
        let added = crate::evidence_rev::Added {
            tool: h.name.clone(),
            digest: h.sha.clone(),
            lock: crate::sha256::sha256_hex(head_lock.as_bytes()),
        };
        let r = crate::evidence_rev::admit_offline(
            &added,
            &crate::evidence_rev::Inputs {
                root: i.evidence_dir,
                base_root: i.base_evidence_dir,
                base_tools_lock: i.base_tools_lock,
                base_lock: &base_lock,
                head_lock: &head_lock,
                head_patches: &patches,
            },
        )?;
        let removed = crate::evidence_rev::strict_subset(&base_lock, &head_lock)?.len();
        let prior =
            crate::evidence_rev::select(i.base_evidence_dir, &h.name, &h.sha, &r.supersedes)?;
        let prior_header: Value = std::fs::read_to_string(prior.dir.join("vuln.jsonl"))
            .ok()
            .and_then(|t| t.lines().next().and_then(|l| serde_json::from_str(l).ok()))
            .ok_or("superseded record: vuln.jsonl has no header")?;
        let prior_db = s(&prior_header, &["scanner", "db", "version"]);
        let vuln = verify_vuln_record(&rec.dir, &i.locks_dir.join(&f), Some(prior_db))?;
        Ok(format!(
            "revision {} supersedes lock {} ({}, {}): {removed} package(s) removed, nothing else \
             changed; {vuln}",
            &r.lock[..12],
            &r.supersedes[..12],
            r.date,
            r.reason,
        ))
    })();
    match res {
        Ok(m) => Verdict::Allow(m),
        Err(e) => Verdict::Unevaluated(e),
    }
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

/// Report text on one line: control characters (line breaks included) in text a change can
/// supply become spaces.
fn one_line(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// A report bullet, every further line of `d` indented under it: no text a change supplies
/// starts a line of the report. The verdict line the workflow enforces is the report's last line,
/// and a line starting `::` is a workflow command.
fn bullet(md: &mut String, prefix: &str, d: &str) {
    let mut lines = d.split('\n');
    let _ = writeln!(md, "  - {prefix}{}", one_line(lines.next().unwrap_or("")));
    for l in lines {
        let _ = writeln!(md, "    {}", one_line(l));
    }
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
    // Per-tool producer inputs beyond the lock (patches, build args, rustflags), both sides.
    let mut tools_dir = PathBuf::from("tools");
    let mut base_tools_dir: Option<PathBuf> = None;
    // The base commit's tree: the monitor workflow a candidate branch's run must have run.
    let mut base_root: Option<PathBuf> = None;
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
            "--tools-dir" => {
                if let Some(v) = it.next() {
                    tools_dir = PathBuf::from(v);
                }
            }
            "--base-tools-dir" => base_tools_dir = it.next().map(PathBuf::from),
            "--base-root" => base_root = it.next().map(PathBuf::from),
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
    for (side, t) in [("head", &head_text), ("base", &base_text)] {
        let p = tools_lock_problems(t);
        if !p.is_empty() {
            eprintln!("gate: {side} TOOLS.lock: {}", p.join("; "));
            return 2;
        }
    }
    let base = parse_tools_lock(&base_text);
    let head = parse_tools_lock(&head_text);
    let cands = candidates(&base, &head);
    // Evidence revisions (evidence README rule 2): a frozen lock that changed under an unchanged
    // pinned digest makes that digest a candidate again, gated on a revision measured against
    // the new lock and compared with the record the base selected.
    if let Err(e) = refuse_checkout(&[&head_text, &base_text]) {
        eprintln!("gate: {e}");
        return 2;
    }
    let rev_cands = revision_candidates(
        &head,
        &cands,
        ToolInputs {
            locks: &locks_dir,
            tools: Some(&tools_dir),
        },
        base_locks_dir.as_deref().map(|l| ToolInputs {
            locks: l,
            tools: base_tools_dir.as_deref(),
        }),
    );
    let (rev_added, mut rev_problems) =
        crate::evidence_rev::rev_changes(&evidence_dir, &base_evidence_dir);
    for a in &rev_added {
        let lock_now = read_opt(&locks_dir.join(format!("{}.lock", a.tool)))
            .map(|b| crate::sha256::sha256_hex(&b));
        let expected = rev_cands
            .iter()
            .any(|h| h.name == a.tool && h.sha == a.digest)
            && lock_now.as_deref() == Some(a.lock.as_str());
        if !expected {
            rev_problems.push(format!(
                "{}/{}/rev/{}: added, but this change does not make that lock current for a pinned digest whose lock it changes",
                a.tool,
                &a.digest[..12],
                &a.lock[..12]
            ));
        }
    }
    let cands: Vec<(Option<ToolLine>, ToolLine)> = cands
        .into_iter()
        .chain(rev_cands.iter().map(|h| (Some(h.clone()), h.clone())))
        .collect();
    let ev_cands = evidence_candidates(&head, &cands, &evidence_dir, &base_evidence_dir);
    let changed_acks = changed_ack_files(&evidence_dir, &base_evidence_dir);
    let app = app_changes(&evidence_dir, &base_evidence_dir);
    let historical = non_frontier_changes(&head, &evidence_dir, &base_evidence_dir);
    // A monitor run on a candidate branch counts only if that branch ran the base's monitor.
    let base_monitor = base_root.as_ref().and_then(|r| {
        std::fs::read_to_string(r.join(".github/workflows/supply-chain-monitor.yml")).ok()
    });
    let mal_custody = |t: &str, d: &str, l: &str| monitor_custody(t, d, l, base_monitor.as_deref());

    let mut reports = Vec::new();
    let mut db_stamp = String::new();
    let mut first_scan = true;

    // Absolute floors (#241 §4). A missing/malformed policy is UNEVALUATED for every
    // candidate: "no floors file" must never read as "no floors". It is also UNEVALUATED on its
    // own: evidence and ack edits are evaluated against the floors too, so with none loaded the
    // change has not been evaluated, whatever else it holds.
    let floors = match crate::floors::load(&floors_path) {
        Ok(f) => Some(f),
        Err(e) => {
            reports.push(CandidateReport {
                name: format!("policy ({})", floors_path.display()),
                tool: String::new(),
                summary: String::new(),
                axes: vec![("floors", Verdict::Unevaluated(e.clone()))],
            });
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
        // Same digest on both sides: only the lock changed (`revision_candidates`).
        // Same bytes as the base pins: the evidence it is gated on is the base's record or a
        // revision of it, whatever else the line says.
        let is_rev = b
            .as_ref()
            .is_some_and(|b| b.target == h.target && b.sha == h.sha);

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

        // --- caps + mal + build: consume the recorded evidence store. Lock-bound records are
        //     the ones each side selects under its own lock (evidence README rule 2). ---
        let head_rec = crate::evidence_rev::current(&evidence_dir, &locks_dir, &h.name, &h.sha);
        let base_dir = base_record_dir(
            &base_evidence_dir,
            base_locks_dir.as_deref(),
            &h.name,
            b.as_ref(),
        );
        let head_lock_path = head_res.as_ref().ok().map(|(p, _)| p.clone());
        let base_lock_path = base_res
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .map(|(p, _)| p.clone());
        axes.push((
            "caps",
            match &head_rec {
                Ok(r) => caps_verdict(
                    &h.name,
                    &r.dir,
                    base_caps_of(base_dir.as_deref()),
                    h,
                    &acks,
                    floors,
                    (head_lock_path.as_deref(), base_lock_path.as_deref()),
                ),
                Err(e) => unselected(&evidence_dir, h, e),
            },
        ));
        axes.push((
            "mal",
            mal_edit_verdict(
                &evidence_dir,
                &base_evidence_dir,
                h,
                &acks,
                floors,
                &mal_custody,
            ),
        ));
        let revision = head_rec.as_ref().ok().and_then(|r| r.revision.clone());
        let custody = |text: &str, line: &ToolLine| match &revision {
            Some(r) => revision_custody(text, line, r),
            None => record_custody(text, line),
        };
        axes.push((
            "build",
            match &head_rec {
                Ok(r) => build_verdict(
                    &r.dir,
                    Prior {
                        record: base_record_of(base_dir.as_deref(), b.as_ref(), h),
                        caps: base_caps_of(base_dir.as_deref()),
                    },
                    h,
                    &acks,
                    floors,
                    false,
                    &custody,
                ),
                Err(e) => {
                    Verdict::Unevaluated(format!("no build record under the current lock: {e}"))
                }
            },
        ));
        let edited = blessed_root_edits(&evidence_dir, &base_evidence_dir, h, is_rev);
        if !edited.is_empty() {
            axes.push((
                "evidence",
                Verdict::Unevaluated(format!(
                    "{} of {} changed: blessed evidence is never edited in a change that pins \
                     or revises it (evidence README rules 2 and 4)",
                    edited.join(", "),
                    &h.sha[..12]
                )),
            ));
        }
        if is_rev
            && b.as_ref()
                .is_some_and(|b| b.rev != h.rev || b.repo != h.repo)
        {
            axes.push((
                "revision",
                Verdict::Unevaluated(
                    "the upstream source (repo, rev) changed but the digest did not: the same \
                     bytes cannot come from another source without a producer run proving it; \
                     re-bless"
                        .into(),
                ),
            ));
        } else if is_rev {
            axes.push((
                "revision",
                revision_verdict(
                    h,
                    &head_rec,
                    RevisionInputs {
                        evidence_dir: &evidence_dir,
                        base_evidence_dir: &base_evidence_dir,
                        base_tools_lock: &base_text,
                        locks_dir: &locks_dir,
                        base_locks_dir: base_locks_dir.as_deref(),
                    },
                ),
            ));
        } else if revision.is_some()
            && !head_rec
                .as_ref()
                .ok()
                .and_then(|r| r.dir.strip_prefix(&evidence_dir).ok())
                .is_some_and(|rel| base_evidence_dir.join(rel).is_dir())
        {
            axes.push((
                "revision",
                Verdict::Unevaluated(
                    "a revision is selected for a digest this change pins anew: a candidate is \
                     measured in place, a revision is only for a digest the base commit pins"
                        .into(),
                ),
            ));
        }

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
            let root = evidence_dir.join(&h.name).join(&h.sha);
            let head_cur = crate::evidence_rev::current(&evidence_dir, &locks_dir, &h.name, &h.sha);
            let base_cur = base_locks_dir
                .as_deref()
                .map(|l| crate::evidence_rev::current(&base_evidence_dir, l, &h.name, &h.sha));
            // Superseded if either side selects a revision: an edit that breaks the head's
            // selection must not make revision 1 look current again.
            let superseded = matches!(&base_cur, Some(Ok(r)) if r.dir != base_rec)
                || matches!(&head_cur, Ok(r) if r.dir != root);
            if let Err(e) = &head_cur {
                axes.push((
                    "record",
                    Verdict::Unevaluated(format!(
                        "after this change no record matches the current lock: {e}"
                    )),
                ));
            }
            if superseded && changed.iter().any(|f| f != "mal.jsonl") {
                axes.push((
                    "revision",
                    Verdict::Unevaluated(format!(
                        "{} changed under revision 1 of {}, which a revision supersedes: blessed \
                         evidence is never edited (evidence README rule 2)",
                        changed.join(", "),
                        &h.sha[..12]
                    )),
                ));
            }
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
                        &root,
                        base_caps,
                        h,
                        &acks,
                        floors,
                        (head_lock.as_deref(), base_lock.as_deref()),
                    ),
                ));
            }
            if changed.iter().any(|f| f == "mal.jsonl") {
                axes.push((
                    "mal",
                    mal_edit_verdict(
                        &evidence_dir,
                        &base_evidence_dir,
                        h,
                        &acks,
                        floors,
                        &mal_custody,
                    ),
                ));
            }
            if changed.iter().any(|f| f == crate::build_record::FILE) {
                let prior = Prior {
                    record: std::fs::read_to_string(base_rec.join(crate::build_record::FILE)).ok(),
                    caps: std::fs::read_to_string(base_rec.join("caps.toml")).ok(),
                };
                axes.push((
                    "build",
                    build_verdict(&root, prior, h, &acks, floors, true, &record_custody),
                ));
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
        // The app's records: a published release's exe, by digest (`app_verdicts`).
        let custody = AppCustody {
            anchors: &store_anchor_custody,
            vuln: &app_vuln_custody,
            mal: &mal_custody,
        };
        for (digest, changes) in &app {
            let axes = match load_acks(&evidence_dir.join(APP).join("acks.jsonl")) {
                Ok(acks) => app_verdicts(
                    &evidence_dir,
                    &base_evidence_dir,
                    digest,
                    changes,
                    &acks,
                    floors,
                    &custody,
                ),
                Err(e) => vec![("acks", Verdict::Unevaluated(e))],
            };
            if axes.is_empty() {
                continue; // only the report changed: the ledger above judges it
            }
            reports.push(CandidateReport {
                name: format!(
                    "{APP} {} (release records)",
                    digest.get(..12).unwrap_or(digest)
                ),
                tool: APP.into(),
                summary: changes
                    .iter()
                    .map(|(f, c)| format!("{f} {c:?}"))
                    .collect::<Vec<_>>()
                    .join(", "),
                axes,
            });
        }
        // Sign-offs are history: an acks.jsonl grows by lines, never edited or removed (removing
        // a later, narrower sign-off would revive an earlier one).
        let rewritten: Vec<&str> = changed_acks
            .iter()
            .filter(|t| {
                let rel = Path::new(t.as_str()).join("acks.jsonl");
                let (h, b) = (
                    read_opt(&evidence_dir.join(&rel)),
                    read_opt(&base_evidence_dir.join(&rel)),
                );
                !grows_by_lines(h.as_deref(), b.as_deref())
            })
            .map(String::as_str)
            .collect();
        if !rewritten.is_empty() {
            reports.push(CandidateReport {
                name: "acks history".into(),
                tool: String::new(),
                summary: String::new(),
                axes: vec![(
                    "acks",
                    Verdict::Unevaluated(format!(
                        "acks.jsonl of {} edited or removed: sign-offs are added, never rewritten",
                        rewritten.join(", ")
                    )),
                )],
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

    let is_current = |dir: &Path| -> bool {
        let Ok(rel) = dir.strip_prefix(&evidence_dir) else {
            return false;
        };
        let mut parts = rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned());
        let (Some(tool), Some(digest)) = (parts.next(), parts.next()) else {
            return false;
        };
        // App reports are per release; each stays current (its release is published).
        if tool == "hp-thermal" {
            return parts.next().is_none();
        }
        head.iter().any(|l| l.name == tool && l.sha == digest)
            && crate::evidence_rev::current(&evidence_dir, &locks_dir, &tool, &digest)
                .is_ok_and(|r| r.dir == dir)
    };
    let ledger = vdr_ledger(&evidence_dir, &base_evidence_dir, &is_current);
    if !ledger.is_empty() {
        reports.push(CandidateReport {
            name: "VDR ledger".into(),
            tool: String::new(),
            summary: String::new(),
            axes: vec![(
                "vdr",
                Verdict::Unevaluated(format!(
                    "committed reports only move forward:\n    {}",
                    ledger.join("\n    ")
                )),
            )],
        });
    }
    if !rev_problems.is_empty() {
        reports.push(CandidateReport {
            name: "evidence revisions".into(),
            tool: String::new(),
            summary: String::new(),
            axes: vec![(
                "revision",
                Verdict::Unevaluated(format!(
                    "revisions are append-only and only for a lock this change makes current:\n    {}",
                    rev_problems.join("\n    ")
                )),
            )],
        });
    }

    // ---------- report ----------
    let mut md =
        String::from("<!-- candidate-eval -->\n## Candidate evaluation (3-axis gate, #241)\n\n");
    if cands.is_empty() && ev_cands.is_empty() && changed_acks.is_empty() && app.is_empty() {
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
        let _ = writeln!(md, "### `{}`  {}", one_line(&r.name), one_line(&r.summary));
        for (axis, v) in &r.axes {
            pass &= v.passes();
            let _ = writeln!(md, "- **{axis}: {}**", v.label());
            match v {
                Verdict::Allow(d) => bullet(&mut md, "", d),
                Verdict::RaiseCovered(items) => {
                    for i in items {
                        bullet(&mut md, "signed: ", i);
                    }
                }
                Verdict::RaiseUncovered { covered, needed } => {
                    for i in covered {
                        bullet(&mut md, "signed: ", i);
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
                        let _ = writeln!(md, "\n    ```json\n    {}\n    ```", one_line(n));
                    }
                }
                Verdict::Unevaluated(why) | Verdict::HardStop(why) => bullet(&mut md, "", why),
            }
        }
        md.push('\n');
    }
    if !historical.is_empty() {
        let _ = writeln!(
            md,
            "*Changed evidence under {} non-frontier digest file(s) — history, not evaluated (no gate consumes a record about bytes nobody runs): {}*\n",
            historical.len(),
            one_line(&historical.join(", "))
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
        let v = caps_verdict("t", &rec, None, &h, &acks, &floors(), (None, None));
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
        let v = caps_verdict("t", &rec, None, &h, &acks, &floors(), (None, None));
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
    fn build_axis_baseline_floor_allow_and_rewrite() {
        let dir = std::env::temp_dir().join(format!("gate-build-{}", std::process::id()));
        let head = "e".repeat(64);
        let rec = dir.join("t").join(&head);
        std::fs::create_dir_all(&rec).unwrap();
        let h = tl("t", &head);
        let none = Acks {
            entries: Vec::new(),
            rejected: Vec::new(),
        };
        let record = |cfgs: &str| {
            let raw = format!(
                "{}\n{}\n",
                format_args!(
                    r#"{{"reason":"build-script-executed","package_id":"registry+https://github.com/rust-lang/crates.io-index#serde_json@1.0.154","linked_libs":[],"linked_paths":[],"cfgs":[{cfgs}],"env":[],"out_dir":"o"}}"#
                ),
                r#"{"reason":"build-finished","success":true}"#
            );
            let msgs = crate::build_record::parse(&raw).unwrap();
            let raw_sha = "f".repeat(64);
            crate::build_record::evidence(
                &crate::build_record::Anchor {
                    tool: "t",
                    digest: &head,
                    run_url: "u",
                    raw_sha256: &raw_sha,
                    asset: "a",
                },
                &msgs,
            )
        };
        // Custody needs the store and Sigstore; offline, the committed messages stand in.
        let offline = |text: &str, _: &ToolLine| -> Result<Vec<Value>, String> {
            Ok(crate::build_record::read_evidence(text)?.1)
        };
        let verdict = |prior: Option<String>, acks: &Acks, edit: bool| {
            build_verdict(
                &rec,
                Prior {
                    record: prior,
                    caps: None,
                },
                &h,
                acks,
                &floors(),
                edit,
                &offline,
            )
        };

        // Custody failing is unevaluated, never a pass.
        let tmp_base = record(r#""a""#);
        std::fs::write(rec.join(crate::build_record::FILE), &tmp_base).unwrap();
        let refused = |_: &str, _: &ToolLine| -> Result<Vec<Value>, String> {
            Err("raw record missing from the store".into())
        };
        assert!(matches!(
            build_verdict(
                &rec,
                Prior {
                    record: None,
                    caps: None,
                },
                &h,
                &none,
                &floors(),
                false,
                &refused,
            ),
            Verdict::Unevaluated(_)
        ));
        std::fs::remove_file(rec.join(crate::build_record::FILE)).unwrap();

        // No record at all: unevaluated, never a pass.
        assert!(matches!(
            verdict(None, &none, false),
            Verdict::Unevaluated(_)
        ));

        let base = record(r#""a""#);
        std::fs::write(rec.join(crate::build_record::FILE), &base).unwrap();
        let sha = crate::sha256::sha256_hex(base.as_bytes());

        // No prior record: the baseline asks for a build ack bound to these bytes.
        let Verdict::RaiseUncovered { needed, .. } = verdict(None, &none, false) else {
            panic!("baseline must ask for a sign-off")
        };
        assert!(needed[0].contains(r#""axis":"build""#) && needed[0].contains(&sha));
        let signed = ack(&format!(
            r#"{{"schema":"hp-thermal/evidence-ack/v1","axis":"build","product":{{"name":"t","digest":"{head}"}},"evidence_sha256":"{sha}","status":"reviewed","status_notes":"reviewed","author":"a","timestamp":"t","refs":[]}}"#
        ));
        assert!(matches!(
            verdict(None, &signed, false),
            Verdict::RaiseCovered(_)
        ));

        // A prior with the same cfgs: allow. A new cfg against the prior: RAISE, the template
        // naming it, covered once a build ack names these bytes.
        assert!(matches!(
            verdict(Some(base.clone()), &none, false),
            Verdict::Allow(_)
        ));
        let more = record(r#""a","b""#);
        std::fs::write(rec.join(crate::build_record::FILE), &more).unwrap();
        let Verdict::RaiseUncovered { needed, .. } = verdict(Some(base.clone()), &signed, false)
        else {
            panic!("a new cfg must ask for a sign-off")
        };
        assert!(
            needed[0].contains(r#""new_rustc_cfg":["serde_json@1: b"]"#),
            "{}",
            needed[0]
        );
        let more_sha = crate::sha256::sha256_hex(more.as_bytes());
        let signed_more = ack(&format!(
            r#"{{"schema":"hp-thermal/evidence-ack/v1","axis":"build","product":{{"name":"t","digest":"{head}"}},"evidence_sha256":"{more_sha}","status":"reviewed","status_notes":"reviewed","author":"a","timestamp":"t","refs":[]}}"#
        ));
        assert!(matches!(
            verdict(Some(base.clone()), &signed_more, false),
            Verdict::RaiseCovered(_)
        ));

        // Instrument reconciliation: a disagreement the prior record and inventory already had
        // passes; a new one is raised and named.
        let caps = "[pkg.serde_json]\nbuild.allow_build_instructions = [\n    \"cargo:rustc-link-lib=z\",\n]\n";
        std::fs::write(rec.join(crate::build_record::FILE), &base).unwrap();
        std::fs::write(rec.join("caps.toml"), caps).unwrap();
        let with_caps = |record: &str, c: &str| Prior {
            record: Some(record.to_string()),
            caps: Some(c.to_string()),
        };
        assert!(matches!(
            build_verdict(
                &rec,
                with_caps(&base, caps),
                &h,
                &none,
                &floors(),
                false,
                &offline
            ),
            Verdict::Allow(_)
        ));
        let quiet = "[pkg.serde_json]\nbuild.allow_build_instructions = [\n]\n";
        let Verdict::RaiseUncovered { needed, .. } = build_verdict(
            &rec,
            with_caps(&base, quiet),
            &h,
            &none,
            &floors(),
            false,
            &offline,
        ) else {
            panic!("a new disagreement must ask for a sign-off")
        };
        assert!(
            needed[0].contains("instrument_disagreement")
                && needed[0].contains("serde_json: rustc-link-lib=z (inventory only)"),
            "{}",
            needed[0]
        );
        std::fs::remove_file(rec.join("caps.toml")).unwrap();

        // Rewritten under a pinned digest: signed again even without a new cfg.
        std::fs::write(rec.join(crate::build_record::FILE), &base).unwrap();
        assert!(matches!(
            verdict(Some(base.clone()), &none, true),
            Verdict::RaiseUncovered { .. }
        ));
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
        assert!(changed_ack_files(&head_ev, &base_ev).is_empty());
        std::fs::write(head_ev.join("t").join("acks.jsonl"), "{}\n").unwrap();
        assert_eq!(changed_ack_files(&head_ev, &base_ev), vec!["t".to_string()]);
        // a product TOOLS.lock does not name (the app) is checked too
        std::fs::create_dir_all(head_ev.join(APP)).unwrap();
        std::fs::write(head_ev.join(APP).join("acks.jsonl"), "x\n").unwrap();
        assert_eq!(
            changed_ack_files(&head_ev, &base_ev),
            vec![APP.to_string(), "t".to_string()]
        );
        // the app's records are evaluated, not listed as history
        std::fs::create_dir_all(head_ev.join(APP).join(&old)).unwrap();
        std::fs::write(head_ev.join(APP).join(&old).join("mal.jsonl"), "x\n").unwrap();
        assert_eq!(non_frontier_changes(&head, &head_ev, &base_ev), hist);
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
        let v = mal_verdict("t", &dir, &h, &acks, &floors, &|_, _, _| Ok(()));
        assert!(matches!(v, Verdict::Unevaluated(_)), "got {v:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// One mal record on disk → its gate verdict (#347 step 1 cases), its custody granted.
    fn mal_verdict_for(tag: &str, record: &str) -> Verdict {
        mal_verdict_with(tag, record, &|_, _, _| Ok(()))
    }

    fn mal_verdict_with(tag: &str, record: &str, custody: MalCustody) -> Verdict {
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
        let v = mal_verdict("t", &dir, &h, &acks, &floors, custody);
        let _ = std::fs::remove_dir_all(&dir);
        v
    }

    /// A clean panel lets a digest through only as the monitor's own line; a panel that blocks
    /// keeps blocking whatever its custody.
    #[test]
    fn a_clean_panel_counts_only_as_the_monitors_own_line() {
        let clean = r#"{"subject":{"sha256":"DIGEST"},"detections":{"malicious":0,"total":70},"flags":[],"sandbox":{"state":"ANALYZED","verdicts":[]}}"#;
        let refused: MalCustody = &|_, _, _| Err("hand-composed".into());
        assert!(matches!(mal_verdict_for("c-ok", clean), Verdict::Allow(_)));
        let v = mal_verdict_with("c-no", clean, refused);
        assert!(
            matches!(v, Verdict::Unevaluated(ref w) if w.contains("custody")),
            "got {v:?}"
        );
        let bad = r#"{"subject":{"sha256":"DIGEST"},"detections":{"malicious":9,"total":70},"flags":[],"sandbox":{"state":"ANALYZED","verdicts":[]}}"#;
        assert!(matches!(
            mal_verdict_with("c-bad", bad, refused),
            Verdict::HardStop(_)
        ));
    }

    fn b64(bytes: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for c in bytes.chunks(3) {
            let n = (c[0] as u32) << 16
                | (*c.get(1).unwrap_or(&0) as u32) << 8
                | *c.get(2).unwrap_or(&0) as u32;
            for i in 0..4 {
                if i <= c.len() {
                    out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    /// A DSSE bundle carrying `statement`, as the attestation store returns it.
    fn bundle(statement: Value) -> Value {
        serde_json::json!({"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "dsseEnvelope": {"payloadType": "application/vnd.in-toto+json",
                             "payload": b64(statement.to_string().as_bytes()), "signatures": []}})
    }

    fn statement(digest: &str, pt: &str, predicate: Value) -> Value {
        serde_json::json!({"_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "hp-thermal.exe", "digest": {"sha256": digest}}],
            "predicateType": pt, "predicate": predicate})
    }

    #[test]
    fn an_anchor_is_a_stored_bundle_of_its_files_kind() {
        use crate::release_advance::{CYCLONEDX, PROVENANCE};
        let d = "d".repeat(64);
        let wf = |path: &str, r: &str| {
            serde_json::json!({"buildDefinition": {"externalParameters": {"workflow": {
                "ref": r, "repository": "https://github.com/o/r", "path": path}}}})
        };
        let prov = bundle(statement(
            &d,
            PROVENANCE,
            wf(".github/workflows/release.yml", "refs/tags/v1"),
        ));
        let serial = crate::vdr::serial_number(&d);
        let vdr1 = bundle(statement(
            &d,
            CYCLONEDX,
            serde_json::json!({"serialNumber": serial, "version": 1}),
        ));
        let sbom = bundle(statement(
            &d,
            CYCLONEDX,
            serde_json::json!({"serialNumber": "urn:uuid:other", "version": 1}),
        ));
        let stored = [&prov, &vdr1, &sbom];
        let check = |file: &str, b: &Value, stored: &[&Value]| {
            anchors_in_store(&d, file, &format!("{b}\n"), stored, "o/r")
        };
        assert!(check("provenance.sigstore.jsonl", &prov, &stored).is_ok());
        assert!(check("vdr.v1.sigstore.jsonl", &vdr1, &stored).is_ok());
        assert!(check("sbom.sigstore.jsonl", &sbom, &stored).is_ok());
        // the same statement, judged for a repository whose workflow did not make it
        let prov_line = format!("{prov}\n");
        assert!(
            anchors_in_store(
                &d,
                "provenance.sigstore.jsonl",
                &prov_line,
                &stored,
                "evil/r"
            )
            .is_err(),
            "another repository's release workflow"
        );
        // the same bundle spelled another way (spacing, a repeated key): not the store's bytes
        let spaced = serde_json::to_string_pretty(&prov)
            .unwrap()
            .replace('\n', "");
        assert!(
            anchors_in_store(&d, "provenance.sigstore.jsonl", &spaced, &stored, "o/r").is_err(),
            "another spelling"
        );
        let canonical = serde_json::to_string(&prov).unwrap();
        let repeated = format!(r#"{{"mediaType":"x",{}"#, &canonical[1..]);
        assert!(
            anchors_in_store(&d, "provenance.sigstore.jsonl", &repeated, &stored, "o/r").is_err(),
            "a repeated key"
        );
        let other_subject = bundle(statement(
            &"e".repeat(64),
            PROVENANCE,
            wf(".github/workflows/release.yml", "refs/tags/v1"),
        ));
        let other_workflow = bundle(statement(
            &d,
            PROVENANCE,
            wf(".github/workflows/ci.yml", "refs/tags/v1"),
        ));
        let branch = bundle(statement(
            &d,
            PROVENANCE,
            wf(".github/workflows/release.yml", "refs/heads/main"),
        ));
        let every = [
            &prov,
            &vdr1,
            &sbom,
            &other_subject,
            &other_workflow,
            &branch,
        ];
        for (what, file, b, stored) in [
            (
                "not in the store",
                "provenance.sigstore.jsonl",
                &prov,
                &[&vdr1][..],
            ),
            (
                "another exe",
                "provenance.sigstore.jsonl",
                &other_subject,
                &every[..],
            ),
            (
                "not a release workflow",
                "provenance.sigstore.jsonl",
                &other_workflow,
                &every[..],
            ),
            (
                "not at a tag",
                "provenance.sigstore.jsonl",
                &branch,
                &every[..],
            ),
            (
                "the VDR filed as the SBOM",
                "sbom.sigstore.jsonl",
                &vdr1,
                &every[..],
            ),
            (
                "the SBOM filed as a VDR",
                "vdr.v1.sigstore.jsonl",
                &sbom,
                &every[..],
            ),
            (
                "a VDR at another version",
                "vdr.v2.sigstore.jsonl",
                &vdr1,
                &every[..],
            ),
            (
                "provenance filed as a sarif",
                "sarif.sigstore.jsonl",
                &prov,
                &every[..],
            ),
        ] {
            assert!(check(file, b, stored).is_err(), "{what}");
        }
        assert!(
            anchors_in_store(&d, "sbom.sigstore.jsonl", "\n", &stored, "o/r").is_err(),
            "empty"
        );
        assert_eq!(vdr_anchor_version("vdr.v12.sigstore.jsonl"), Some(12));
        for f in [
            "vdr.v.sigstore.jsonl",
            "vdr.v01.sigstore.jsonl",
            "vdr.v1.json",
            "vdr.vx.sigstore.jsonl",
        ] {
            assert_eq!(vdr_anchor_version(f), None, "{f}");
        }
    }

    /// The app's records change only as release-advance writes them; each new one proves itself.
    #[test]
    fn the_apps_records_change_only_as_release_advance_writes_them() {
        let root = std::env::temp_dir().join(format!("gate-app-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (he, be) = (root.join("head"), root.join("base"));
        let d = "a".repeat(64);
        let put = |side: &Path, f: &str, body: &str| {
            let p = side.join(APP).join(&d).join(f);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
        };
        let panel = format!(
            r#"{{"subject":{{"sha256":"{d}"}},"detections":{{"malicious":0,"total":70}},"flags":[],"sandbox":{{"state":"ANALYZED","verdicts":[]}}}}"#
        );
        for side in [&he, &be] {
            put(side, "provenance.sigstore.jsonl", "p\n");
            put(side, "mal.jsonl", &format!("{panel}\n"));
            put(side, "vuln.jsonl", "v\n");
        }
        let floors =
            crate::floors::parse(include_str!("../../supply-chain/policy/floors.json")).unwrap();
        let acks = Acks {
            entries: vec![],
            rejected: vec![],
        };
        let ok = AppCustody {
            anchors: &|_, _, _| Ok("ok".into()),
            vuln: &|_, _| Ok("ok".into()),
            mal: &|_, _, _| Ok(()),
        };
        let refused = AppCustody {
            anchors: &|_, _, _| Err("no".into()),
            vuln: &|_, _| Err("no".into()),
            mal: &|_, _, _| Err("no".into()),
        };
        let verdicts = |c: &AppCustody| {
            let changes = app_changes(&he, &be);
            let ch = changes.get(&d).cloned().unwrap_or_default();
            app_verdicts(&he, &be, &d, &ch, &acks, &floors, c)
        };
        let blocked = |v: &[(&str, Verdict)]| v.iter().any(|(_, v)| !v.passes());
        assert!(app_changes(&he, &be).is_empty());
        // a new anchor, proved; then unproved
        put(&he, "vdr.v1.sigstore.jsonl", "x\n");
        assert!(!blocked(&verdicts(&ok)));
        assert!(blocked(&verdicts(&refused)), "an unproved anchor");
        put(&be, "vdr.v1.sigstore.jsonl", "x\n");
        // the report alone changed: the ledger judges it
        put(&he, "vdr.cdx.json", "{}");
        assert!(verdicts(&ok).is_empty());
        // a later panel appended: evaluated, and only the monitor's own line counts
        let later = panel.replace(r#""flags":[]"#, r#""flags":[],"panelDate":"2099-01-01""#);
        put(&he, "mal.jsonl", &format!("{panel}\n{later}\n"));
        assert!(!blocked(&verdicts(&ok)));
        assert!(blocked(&verdicts(&refused)), "an unproved panel");
        // a valid, clean, custody-granted panel that replaces the history instead of growing it
        let rewritten = format!(
            "{}\n",
            panel.replace(r#""flags":[]"#, r#""flags":[],"x":1"#)
        );
        for (what, f, body) in [
            ("an anchor replaced", "provenance.sigstore.jsonl", "q\n"),
            ("a panel rewritten", "mal.jsonl", rewritten.as_str()),
            ("the vuln record edited", "vuln.jsonl", "w\n"),
            ("a file that is no record", "notes.txt", "hi\n"),
            ("a directory inside", "sub/x", "x\n"),
        ] {
            let before = std::fs::read(he.join(APP).join(&d).join(f)).ok();
            put(&he, f, body);
            assert!(blocked(&verdicts(&ok)), "{what}");
            let p = he.join(APP).join(&d).join(f);
            match before {
                Some(b) => std::fs::write(&p, b).unwrap(),
                None => {
                    let _ = std::fs::remove_dir_all(he.join(APP).join(&d).join("sub"));
                    let _ = std::fs::remove_file(&p);
                }
            }
        }
        // removing an anchor or the panels
        std::fs::remove_file(he.join(APP).join(&d).join("vdr.v1.sigstore.jsonl")).unwrap();
        assert!(blocked(&verdicts(&ok)), "an anchor removed");
        put(&he, "vdr.v1.sigstore.jsonl", "x\n");
        // a new digest whose records arrive without a provenance anchor
        let fresh = |name: &str, panel_digest: &str| {
            let p = he.join(APP).join(name);
            std::fs::create_dir_all(&p).unwrap();
            std::fs::write(
                p.join("mal.jsonl"),
                format!("{}\n", panel.replace(&d, panel_digest)),
            )
            .unwrap();
            let changes = app_changes(&he, &be);
            let v = app_verdicts(&he, &be, name, &changes[name], &acks, &floors, &ok);
            std::fs::remove_dir_all(&p).unwrap();
            v
        };
        let e = "e".repeat(64);
        assert!(blocked(&fresh(&e, &e)), "no provenance");
        // a directory that is no lowercase sha256, its records otherwise in order
        let z = "z".repeat(64);
        let p = he.join(APP).join(&z);
        std::fs::create_dir_all(&p).unwrap();
        std::fs::write(p.join("provenance.sigstore.jsonl"), "p\n").unwrap();
        assert!(blocked(&fresh(&z, &z)), "not a digest");
        let upper = "B".repeat(64);
        let p = he.join(APP).join(&upper);
        std::fs::create_dir_all(&p).unwrap();
        std::fs::write(p.join("provenance.sigstore.jsonl"), "p\n").unwrap();
        assert!(blocked(&fresh(&upper, &upper)), "a digest in capitals");
        // and the tools' panels follow the same rule
        let tool = ToolLine {
            name: APP.into(),
            repo: String::new(),
            rev: String::new(),
            target: String::new(),
            sha: d.clone(),
        };
        let mal = |body: &str| {
            put(&he, "mal.jsonl", body);
            mal_edit_verdict(&he, &be, &tool, &acks, &floors, &|_, _, _| Ok(()))
        };
        assert!(mal(&format!("{panel}\n{later}\n")).passes(), "appended");
        assert!(!mal(&format!("{panel}\n{panel}\n")).passes(), "replayed");
        assert!(!mal(&rewritten).passes(), "rewritten");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Network (gh, GitHub's attestation store, the tools release): every committed app record
    /// passes the custody a new one is held to. `cargo test -- --ignored committed_app_records`.
    #[test]
    #[ignore]
    fn committed_app_records_pass_their_custody() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../supply-chain/evidence")
            .join(APP);
        let mut failures = Vec::new();
        let mut checked = 0;
        let mut skipped: Vec<String> = Vec::new();
        for d in std::fs::read_dir(&root)
            .unwrap()
            .flatten()
            .filter(|d| d.path().is_dir())
        {
            let digest = d.file_name().to_string_lossy().into_owned();
            for f in std::fs::read_dir(d.path()).unwrap().flatten() {
                let name = f.file_name().to_string_lossy().into_owned();
                let r = if APP_ANCHORS.contains(&name.as_str())
                    || vdr_anchor_version(&name).is_some()
                {
                    let text = std::fs::read_to_string(f.path()).unwrap();
                    store_anchor_custody(&digest, &name, &text)
                } else if name == "vuln.jsonl" {
                    // The re-scan is the scanner the record names; PINNED_TOOLS_DIR holds one.
                    let header: Value = std::fs::read_to_string(f.path())
                        .ok()
                        .and_then(|t| t.lines().next().and_then(|l| serde_json::from_str(l).ok()))
                        .unwrap_or_default();
                    let have = std::env::var("PINNED_TOOLS_DIR").ok().and_then(|p| {
                        std::fs::read(format!("{p}/cargo-audit{}", std::env::consts::EXE_SUFFIX))
                            .ok()
                            .map(|b| crate::sha256::sha256_hex(&b))
                    });
                    if have.as_deref() != Some(s(&header, &["scanner", "digest"])) {
                        skipped.push(format!("{}/{name}", &digest[..12]));
                        continue;
                    }
                    app_vuln_custody(&d.path(), &digest)
                } else {
                    continue;
                };
                checked += 1;
                if let Err(e) = r {
                    failures.push(format!("{}/{name}: {e}", &digest[..12]));
                }
            }
        }
        eprintln!(
            "{checked} checked; recorded by another scanner than PINNED_TOOLS_DIR's: {skipped:?}"
        );
        assert!(checked > 0);
        assert!(
            failures.is_empty(),
            "{checked} checked:\n{}",
            failures.join("\n")
        );
    }

    #[test]
    fn a_monitor_record_names_its_run_and_is_in_its_log_once() {
        let line = |src: &str| {
            format!(
                r#"{{"schema":"hp-thermal/evidence-mal/v1","subject":{{"name":"t","sha256":"d"}},"source":"{src}"}}"#
            )
        };
        let ok = line("supply-chain-monitor run 123 (lookup)");
        assert_eq!(monitor_run_id(&ok).unwrap(), "123");
        for src in [
            "vt-submit run 1 (lookup-first; first panel) + monitor run 2 (lookup)",
            "supply-chain-monitor run (lookup)",
            "supply-chain-monitor run 12a (lookup)",
            "supply-chain-monitor run 1 (lookup) ",
            "",
        ] {
            assert!(monitor_run_id(&line(src)).is_err(), "{src}");
        }
        let run = serde_json::json!({
            "id": 123, "path": ".github/workflows/supply-chain-monitor.yml", "head_branch": "main",
            "event": "schedule", "status": "completed",
            "repository": {"full_name": "o/r"}, "head_repository": {"full_name": "o/r"}
        });
        assert_eq!(monitor_run_ok(&run), Ok(false));
        // a candidate branch's run counts, its monitor workflow still to be shown to be the base's
        let mut cand = run.clone();
        cand["head_branch"] = Value::from("candidate/x");
        assert_eq!(monitor_run_ok(&cand), Ok(true));
        for (k, v) in [
            ("/path", ".github/workflows/vt-submit.yml"),
            ("/head_branch", "feature/x"),
            ("/head_branch", "candidate/"),
            ("/head_branch", "x/candidate/y"),
            ("/event", "pull_request"),
            ("/status", "in_progress"),
            ("/head_repository/full_name", "fork/r"),
        ] {
            let mut r = run.clone();
            *r.pointer_mut(k).unwrap() = Value::from(v);
            assert!(monitor_run_ok(&r).is_err(), "{k}={v}");
        }
        let key = "record (mal.jsonl line for supply-chain/evidence/t/d/): ";
        let at =
            |job: &str, msg: &str| format!("{job}\tUNKNOWN STEP\t2026-11-17T00:00:00.0Z {msg}\n");
        let log = format!("{}other\n", at("vt-monitor", &format!("      {key}{ok}\r")));
        assert!(record_in_log(&log, "t", "d", &ok).is_ok());
        // the canonical serialization of the printed line (what candidate-advance writes)
        let printed = r#"{"source":"supply-chain-monitor run 123 (lookup)","b":1,"a":2}"#;
        let canonical =
            serde_json::to_string(&serde_json::from_str::<Value>(printed).unwrap()).unwrap();
        assert_ne!(printed, canonical);
        let log2 = at("vt-monitor", &format!("      {key}{printed}"));
        assert!(record_in_log(&log2, "t", "d", printed).is_ok(), "verbatim");
        assert!(
            record_in_log(&log2, "t", "d", &canonical).is_ok(),
            "canonical"
        );
        let respelled = r#"{"a":2,"b":1, "source":"supply-chain-monitor run 123 (lookup)"}"#;
        assert!(
            record_in_log(&log2, "t", "d", respelled).is_err(),
            "another spelling"
        );
        assert!(
            record_in_log(&log, "t", "e", &ok).is_err(),
            "another digest"
        );
        assert!(record_in_log(&log, "u", "d", &ok).is_err(), "another tool");
        let edited = ok.replace("123", "124");
        assert!(
            record_in_log(&log, "t", "d", &edited).is_err(),
            "an edited line"
        );
        let twice = format!("{log}{}", at("vt-monitor", &format!("      {key}{ok}")));
        assert!(
            record_in_log(&twice, "t", "d", &ok).is_err(),
            "a second record line"
        );
        // only a whole message of the vt-monitor job is a record line
        for (what, l) in [
            ("another job", at("toolchain", &format!("      {key}{ok}"))),
            (
                "text before the prefix",
                at("vt-monitor", &format!("E [malicious] {key}{ok}")),
            ),
            ("no log framing", format!("      {key}{ok}\n")),
        ] {
            assert!(record_in_log(&l, "t", "d", &ok).is_err(), "{what}");
        }
    }

    /// A run on a candidate branch counts only if it ran the base's monitor workflow; a run on
    /// main is not asked.
    #[test]
    fn a_candidate_branch_run_must_have_run_the_bases_monitor() {
        let line = r#"{"source":"supply-chain-monitor run 7 (lookup)"}"#;
        let key = "record (mal.jsonl line for supply-chain/evidence/t/d/): ";
        let log = format!("vt-monitor\tS\t2026-11-17T00:00:00Z       {key}{line}\n");
        let run_on = |branch: &str| {
            serde_json::json!({"id": 7, "path": ".github/workflows/supply-chain-monitor.yml",
                "head_branch": branch, "head_sha": "a".repeat(40), "event": "workflow_dispatch",
                "status": "completed", "repository": {"full_name": "o/r"},
                "head_repository": {"full_name": "o/r"}})
        };
        let check = |branch: &str, at: Result<&str, &str>, base: Option<&str>| {
            let run = run_on(branch);
            let source = MonitorSource {
                run: &|_| Ok(run.clone()),
                workflow_at: &|_| at.map(str::to_string).map_err(str::to_string),
                log: &|_| Ok(log.clone()),
            };
            monitor_custody_from(&source, "t", "d", line, base)
        };
        assert!(check("main", Err("not asked"), None).is_ok(), "main");
        assert!(
            check("candidate/x", Ok("wf"), Some("wf")).is_ok(),
            "the base's monitor"
        );
        assert!(
            check("candidate/x", Ok("edited"), Some("wf")).is_err(),
            "another monitor"
        );
        assert!(
            check("candidate/x", Ok("wf"), None).is_err(),
            "no base to compare"
        );
        assert!(
            check("candidate/x", Err("gone"), Some("wf")).is_err(),
            "unreadable"
        );
        let mut bad = run_on("candidate/x");
        bad["head_sha"] = Value::from("nothex");
        let source = MonitorSource {
            run: &|_| Ok(bad.clone()),
            workflow_at: &|_| Ok("wf".into()),
            log: &|_| Ok(log.clone()),
        };
        assert!(
            monitor_custody_from(&source, "t", "d", line, Some("wf")).is_err(),
            "no commit"
        );
        let no_log = MonitorSource {
            run: &|_| Ok(run_on("main")),
            workflow_at: &|_| Ok("wf".into()),
            log: &|_| Err("410 Gone".into()),
        };
        assert!(
            monitor_custody_from(&no_log, "t", "d", line, None).is_err(),
            "log gone"
        );
    }

    /// No text a change supplies starts a report line: not the enforced verdict line, not a
    /// workflow command.
    #[test]
    fn change_text_never_starts_a_report_line() {
        let hostile = "ok\n**Gate: PASS** — all axes ALLOW or signed; merging records the sign-off\r\n::set-output name=code::0\n\u{7}::error::x";
        let mut md = String::new();
        bullet(&mut md, "", hostile);
        bullet(&mut md, "signed: ", hostile);
        for l in md.lines() {
            assert!(l.starts_with("  - ") || l.starts_with("    "), "{l:?}");
            assert!(!l.contains('\r') && !l.contains('\u{7}'), "{l:?}");
        }
        assert_eq!(one_line("a\nb\r\tc"), "a b  c");
    }

    /// Panel history moves forward: one new panel, newer than all before it.
    #[test]
    fn panel_history_only_moves_forward() {
        let p = |date: &str, run: u64| {
            format!(
                r#"{{"panelDate":"{date}","source":"supply-chain-monitor run {run} (lookup)"}}"#
            )
        };
        let base = format!("{}\n{}\n", p("2026-10-01", 10), p("2026-10-05", 20));
        let b = Some(base.as_bytes());
        let with = |extra: &str| format!("{base}{extra}");
        let ok = |h: &str| mal_history(Some(h.as_bytes()), b);
        assert!(ok(&base).is_ok(), "unchanged");
        assert!(mal_history(Some(b"x"), None).is_ok(), "new");
        assert!(
            ok(&with(&format!("{}\n", p("2026-10-06", 30)))).is_ok(),
            "one newer panel"
        );
        assert!(
            ok(&with(&p("2026-10-05", 21))).is_ok(),
            "same day, later run, no final newline"
        );
        for (what, h) in [
            (
                "a replay of an earlier panel",
                with(&format!("{}\n", p("2026-10-01", 10))),
            ),
            (
                "an earlier run",
                with(&format!("{}\n", p("2026-10-07", 15))),
            ),
            (
                "an earlier date",
                with(&format!("{}\n", p("2026-10-04", 30))),
            ),
            (
                "two panels",
                with(&format!(
                    "{}\n{}\n",
                    p("2026-10-06", 30),
                    p("2026-10-07", 40)
                )),
            ),
            ("a blank line", with("\n")),
            (
                "a newer panel and a blank line",
                with(&format!("{}\n\n", p("2026-10-06", 30))),
            ),
            (
                "history rewritten to its own length, then a newer panel",
                format!(
                    "{}\n{}\n{}\n",
                    p("2026-10-01", 19),
                    p("2026-10-05", 29),
                    p("2026-10-06", 30)
                ),
            ),
            ("a rewrite", format!("{}\n", p("2026-10-06", 30))),
            (
                "an earlier panel removed",
                format!("{}\n", p("2026-10-05", 20)),
            ),
        ] {
            assert!(ok(&h).is_err(), "{what}");
        }
        assert!(mal_history(None, b).is_err(), "removed");
        let unfinished = p("2026-10-01", 10);
        assert!(
            mal_history(
                Some(format!("{unfinished}x\n").as_bytes()),
                Some(unfinished.as_bytes())
            )
            .is_err(),
            "extending an unfinished last line"
        );
        // sign-off history grows by lines too
        assert!(grows_by_lines(Some(b"a\nb\n"), Some(b"a\n")));
        assert!(grows_by_lines(Some(b"a\n"), Some(b"a\n")));
        assert!(!grows_by_lines(Some(b"b\n"), Some(b"a\n")), "edited");
        assert!(!grows_by_lines(None, Some(b"a\n")), "removed");
        assert!(
            !grows_by_lines(Some(b"ab\n"), Some(b"a")),
            "extending an unfinished line"
        );
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
    #[test]
    fn a_producer_input_change_under_an_unchanged_digest_is_a_revision_candidate() {
        let d = std::env::temp_dir().join(format!("gate-revcand-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let (head, base) = (d.join("head"), d.join("base"));
        for (root, acl) in [(&head, "narrow"), (&base, "wide")] {
            std::fs::create_dir_all(root.join("locks")).unwrap();
            std::fs::create_dir_all(root.join("patches/cargo-deny")).unwrap();
            std::fs::write(root.join("locks/cargo-acl.lock"), acl).unwrap();
            std::fs::write(root.join("locks/cargo-deny.lock"), "same").unwrap();
            std::fs::write(root.join("patches/cargo-deny/0001.patch"), "p").unwrap();
        }
        let side = |r: &PathBuf| ToolInputs {
            locks: Box::leak(r.join("locks").into_boxed_path()),
            tools: Some(Box::leak(r.clone().into_boxed_path())),
        };
        let (hi, bi) = (side(&head), side(&base));
        let acl = tl("cargo-acl", &"a".repeat(64));
        let deny = tl("cargo-deny", &"b".repeat(64));
        let lines = vec![acl.clone(), deny.clone()];
        let names = |v: Vec<ToolLine>| v.into_iter().map(|t| t.name).collect::<Vec<_>>();
        assert_eq!(
            names(revision_candidates(&lines, &[], hi, Some(bi))),
            vec!["cargo-acl"],
            "only the tool whose lock changed"
        );
        // a digest the change re-pins is a TOOLS.lock candidate, not also a revision
        let cands = vec![(Some(acl.clone()), acl.clone())];
        assert!(revision_candidates(&lines, &cands, hi, Some(bi)).is_empty());
        // a patch, build-args or rustflags change is a producer input change too
        for (what, path) in [
            ("patch edited", head.join("patches/cargo-deny/0001.patch")),
            ("patch added", head.join("patches/cargo-deny/0002.patch")),
            ("build-args", head.join("build-args/cargo-deny")),
            ("rustflags", head.join("rustflags/cargo-deny")),
        ] {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let before = std::fs::read(&path).ok();
            std::fs::write(&path, "changed").unwrap();
            assert_eq!(
                revision_candidates(&lines, &[], hi, Some(bi)).len(),
                2,
                "{what} not seen"
            );
            match before {
                Some(b) => std::fs::write(&path, b).unwrap(),
                None => std::fs::remove_file(&path).unwrap(),
            }
        }
        // without the base tools tree only the lock can be compared
        let lock_only = ToolInputs { tools: None, ..bi };
        std::fs::write(head.join("patches/cargo-deny/0001.patch"), "x").unwrap();
        assert_eq!(
            revision_candidates(&lines, &[], hi, Some(lock_only)).len(),
            1
        );
        // a lock removed in the change counts as changed; unset digests never are revisions
        std::fs::remove_file(base.join("locks/cargo-deny.lock")).unwrap();
        assert_eq!(
            revision_candidates(&lines, &[], hi, Some(lock_only)).len(),
            2
        );
        let zero = vec![tl("cargo-acl", ZERO_DIGEST)];
        assert!(revision_candidates(&zero, &[], hi, Some(bi)).is_empty());
        assert!(revision_candidates(&lines, &[], hi, None).is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn blessed_root_records_are_not_edited_by_a_change_that_pins_them() {
        let d = std::env::temp_dir().join(format!("gate-rootedit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let sha = "c".repeat(64);
        let h = tl("t", &sha);
        for side in ["head", "base"] {
            let r = d.join(side).join("t").join(&sha);
            std::fs::create_dir_all(&r).unwrap();
            for f in ["vuln.jsonl", "caps.toml", "build.jsonl", "vdr.cdx.json"] {
                std::fs::write(r.join(f), "x").unwrap();
            }
        }
        let (he, be) = (d.join("head"), d.join("base"));
        assert!(blessed_root_edits(&he, &be, &h, true).is_empty());
        for f in ["vuln.jsonl", "caps.toml", "build.jsonl"] {
            std::fs::write(he.join("t").join(&sha).join(f), "y").unwrap();
            assert_eq!(blessed_root_edits(&he, &be, &h, false), vec![f]);
            std::fs::write(he.join("t").join(&sha).join(f), "x").unwrap();
        }
        // a marker added under a blessed digest is an edit too
        std::fs::write(he.join("t").join(&sha).join("caps.UNEVALUATED"), "why").unwrap();
        assert_eq!(
            blessed_root_edits(&he, &be, &h, false),
            vec!["caps.UNEVALUATED"]
        );
        std::fs::remove_file(he.join("t").join(&sha).join("caps.UNEVALUATED")).unwrap();
        // the report is frozen only for a revision's admission
        std::fs::write(he.join("t").join(&sha).join("vdr.cdx.json"), "v2").unwrap();
        assert!(blessed_root_edits(&he, &be, &h, false).is_empty());
        assert_eq!(blessed_root_edits(&he, &be, &h, true), vec!["vdr.cdx.json"]);
        // a digest the base holds no evidence for is a new candidate: nothing is blessed yet
        assert!(blessed_root_edits(&he, &be, &tl("t", &"e".repeat(64)), true).is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn committed_reports_only_move_forward() {
        let d = std::env::temp_dir().join(format!("gate-ledger-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let sha = "c".repeat(64);
        let lock = "f".repeat(64);
        let serial = crate::vdr::serial_number(&sha);
        let doc = |v: u64, k: u64| {
            serde_json::json!({"serialNumber": serial, "version": v, "k": k}).to_string()
        };
        let root = PathBuf::from("t").join(&sha).join("vdr.cdx.json");
        let rev = PathBuf::from("t")
            .join(&sha)
            .join("rev")
            .join(&lock)
            .join("vdr.cdx.json");
        let (he, be) = (d.join("head"), d.join("base"));
        let put = |side: &Path, p: &Path, body: String| {
            let f = side.join(p);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(f, body).unwrap();
        };
        // base: revision 1's report at v5 (superseded), the revision's at v6 (current)
        for side in [&he, &be] {
            put(side, &root, doc(5, 1));
            put(side, &rev, doc(6, 2));
        }
        let newer = PathBuf::from("t")
            .join(&sha)
            .join("rev")
            .join("e".repeat(64))
            .join("vdr.cdx.json");
        let other = PathBuf::from("u").join(&sha).join("vdr.cdx.json");
        // The revision's report is current; `newer` and `other` stand for reports a change adds
        // for a current subject.
        let current = [
            he.join("t").join(&sha).join("rev").join(&lock),
            he.join(newer.parent().unwrap()),
            he.join(other.parent().unwrap()),
        ];
        let is_current = |dir: &Path| current.iter().any(|c| c == dir);
        assert!(vdr_ledger(&he, &be, &is_current).is_empty());
        // the current report re-emitted forward: fine
        put(&he, &rev, doc(7, 3));
        assert!(
            vdr_ledger(&he, &be, &is_current).is_empty(),
            "a forward re-emit"
        );
        for (what, body) in [
            ("lowered", doc(5, 3)),
            ("used version, new content", doc(6, 3)),
            (
                "another serial",
                serde_json::json!({"serialNumber": "urn:uuid:y", "version": 9}).to_string(),
            ),
        ] {
            put(&he, &rev, body);
            assert!(!vdr_ledger(&he, &be, &is_current).is_empty(), "{what}");
        }
        put(&he, &rev, doc(6, 2));
        // the superseded report is frozen, even moving "forward", even to a fresh version
        for body in [doc(6, 9), doc(8, 9), doc(4, 1)] {
            put(&he, &root, body);
            assert!(
                !vdr_ledger(&he, &be, &is_current).is_empty(),
                "history rewritten"
            );
        }
        put(&he, &root, doc(5, 1));
        // deleting either is refused
        std::fs::remove_file(he.join(&rev)).unwrap();
        assert!(!vdr_ledger(&he, &be, &is_current).is_empty(), "deleted");
        put(&he, &rev, doc(6, 2));
        // a new report for the same serial takes a version above all it had
        put(&he, &newer, doc(6, 9));
        assert!(
            !vdr_ledger(&he, &be, &is_current).is_empty(),
            "a new report reusing v6"
        );
        put(&he, &newer, doc(4, 9));
        assert!(
            !vdr_ledger(&he, &be, &is_current).is_empty(),
            "a new report below v6, unused v4"
        );
        // a copy of the current report: one content per version holds, the version does not move
        put(&he, &newer, doc(6, 2));
        assert!(
            !vdr_ledger(&he, &be, &is_current).is_empty(),
            "a new report copying v6"
        );
        put(&he, &newer, doc(7, 9));
        assert!(
            vdr_ledger(&he, &be, &is_current).is_empty(),
            "a new report at v7"
        );
        // a new report for the subject at a fresh version, but in a directory that is not current
        let stale = PathBuf::from("t")
            .join(&sha)
            .join("rev")
            .join("d".repeat(64))
            .join("vdr.cdx.json");
        put(&he, &stale, doc(8, 9));
        assert!(
            !vdr_ledger(&he, &be, &is_current).is_empty(),
            "a new report, not current"
        );
        std::fs::remove_file(he.join(&stale)).unwrap();
        // a report under another digest claiming this subject's serial, far ahead
        let planted = PathBuf::from("t").join("a".repeat(64)).join("vdr.cdx.json");
        put(&he, &planted, doc(999, 9));
        assert!(
            !vdr_ledger(&he, &be, &is_current).is_empty(),
            "another subject's serial"
        );
        std::fs::remove_dir_all(he.join(planted.parent().unwrap())).unwrap();
        // a current subject's new report under its own directory, but another subject's serial
        let foreign = serde_json::json!({
            "serialNumber": crate::vdr::serial_number(&"a".repeat(64)), "version": 8, "k": 9
        });
        put(&he, &newer, foreign.to_string());
        assert!(
            !vdr_ledger(&he, &be, &is_current).is_empty(),
            "a report naming another subject"
        );
        put(&he, &newer, doc(7, 9));
        assert!(vdr_ledger(&he, &be, &is_current).is_empty(), "restored");
        // two files in the change claiming one (serial, version) with different content
        put(&he, &other, doc(7, 10));
        assert!(
            !vdr_ledger(&he, &be, &is_current).is_empty(),
            "two contents, one version"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// TOOLS.lock files and whether the grammar accepts them, as bytes: the gate reads the file
    /// as UTF-8, and a file that is not is refused before any line is looked at.
    fn grammar_cases() -> Vec<(&'static str, Vec<u8>, bool)> {
        let rev = "e7109a3174378976ea881f1883439ba82524f061";
        let sha = "87c159d397e93e88bddbfc76f2549936a09f65e8274564c7eb5d7bd23efdbfa7";
        let pin = format!("cargo-acl cackle-rs/cackle {rev} linux-x86_64 {sha}");
        let (rev2, sha2, zero) = ("f".repeat(40), "e".repeat(64), ZERO_DIGEST);
        let s = |t: String| t.into_bytes();
        vec![
            (
                "good",
                s(format!(
                    "# header -- any comment\ncargo-acl  cackle-rs/cackle  {rev}  linux-x86_64  {sha}  # note\n\n"
                )),
                true,
            ),
            (
                "tabs, indent",
                s(format!(
                    "\tcargo-acl\tcackle-rs/cackle\t{rev}\tlinux-x86_64\t{sha}\t# x\n"
                )),
                true,
            ),
            ("no final newline", s(pin.clone()), true),
            (
                "bad last line, no final newline",
                s(format!("{pin}\nx")),
                false,
            ),
            ("comment touching", s(format!("{pin}#x\n")), true),
            ("blank lines", s(format!("   \n\t\n{pin}\n#\n")), true),
            (
                "two targets",
                s(format!(
                    "{pin}\ncargo-acl cackle-rs/cackle {rev} windows-x86_64 {sha2}\n"
                )),
                true,
            ),
            ("empty", Vec::new(), true),
            (
                "mixed-case owner/repo",
                s(format!(
                    "cargo-x Cackle-RS/Cackle {rev} linux-x86_64 {sha}\n"
                )),
                true,
            ),
            (
                "two unset digests",
                s(format!(
                    "{pin}\na o/r {rev} t {zero}\nb o/r {rev} t {zero}\n"
                )),
                true,
            ),
            (
                "uppercase name",
                s(format!(
                    "Cargo-acl cackle-rs/cackle {rev} linux-x86_64 {sha}\n"
                )),
                false,
            ),
            (
                "uppercase target",
                s(format!(
                    "cargo-acl cackle-rs/cackle {rev} Linux-x86_64 {sha}\n"
                )),
                false,
            ),
            ("dot name", s(format!(". o/r {rev} t {sha}\n")), false),
            ("dot-dot name", s(format!(".. o/r {rev} t {sha}\n")), false),
            (
                "trailing-dot name",
                s(format!("cargo-acl. o/r {rev} t {sha}\n")),
                false,
            ),
            (
                "leading-hyphen target",
                s(format!("x o/r {rev} -t {sha}\n")),
                false,
            ),
            ("dot-dot repo", s(format!("x o/.. {rev} t {sha}\n")), false),
            (
                "leading-dot owner",
                s(format!("x .o/r {rev} t {sha}\n")),
                false,
            ),
            (
                "one digest, two pins",
                s(format!(
                    "{pin}\ncargo-x cackle-rs/cackle {rev} linux-x86_64 {sha}\n"
                )),
                false,
            ),
            (
                "two targets, two revs",
                s(format!(
                    "{pin}\ncargo-acl cackle-rs/cackle {rev2} windows-x86_64 {sha2}\n"
                )),
                false,
            ),
            (
                "two targets, two repos",
                s(format!(
                    "{pin}\ncargo-acl evil/cackle {rev} windows-x86_64 {sha2}\n"
                )),
                false,
            ),
            (
                "nbsp",
                s(format!(
                    "cargo-acl cackle-rs/cackle\u{a0}x {rev} linux-x86_64 {sha}\n"
                )),
                false,
            ),
            (
                "form feed",
                s(format!(
                    "cargo-acl cackle-rs/cackle\u{c}x {rev} linux-x86_64 {sha}\n"
                )),
                false,
            ),
            (
                "vertical tab",
                s(format!(
                    "cargo-acl\u{b}cackle-rs/cackle {rev} linux-x86_64 {sha}\n"
                )),
                false,
            ),
            ("form feed line", s(format!("\u{c}\n{pin}\n")), false),
            ("cr", s(format!("{pin}\r\n")), false),
            ("cr in a comment", s(format!("{pin} # c\r\n")), false),
            (
                "form feed before a comment",
                s(format!("{pin}\u{c}# c\n")),
                false,
            ),
            (
                "non-ascii comment",
                s(format!("# caf\u{e9}\n{pin}\n")),
                false,
            ),
            (
                "bidi control in a comment",
                s(format!("{pin} # \u{202e}x\n")),
                false,
            ),
            ("nul in a comment", s(format!("{pin} # a\0b\n")), false),
            (
                "nul in a field",
                s(format!(
                    "cargo-acl\0 cackle-rs/cackle {rev} linux-x86_64 {sha}\n"
                )),
                false,
            ),
            ("not utf-8", [pin.as_bytes(), b" # \xff\n"].concat(), false),
            (
                "six fields",
                s(format!(
                    "cargo-acl cackle-rs/cackle x {rev} linux-x86_64 {sha}\n"
                )),
                false,
            ),
            ("trailing field", s(format!("{pin} extra\n")), false),
            (
                "four fields",
                s(format!("cargo-acl cackle-rs/cackle {rev} {sha}\n")),
                false,
            ),
            ("one field", s("cargo-acl\n".into()), false),
            (
                "short rev",
                s(format!(
                    "cargo-acl cackle-rs/cackle e7109a3 linux-x86_64 {sha}\n"
                )),
                false,
            ),
            (
                "upper sha",
                s(format!(
                    "cargo-acl cackle-rs/cackle {rev} linux-x86_64 {}\n",
                    sha.to_uppercase()
                )),
                false,
            ),
            (
                "no owner",
                s(format!("cargo-acl cackle {rev} linux-x86_64 {sha}\n")),
                false,
            ),
            (
                "two slashes",
                s(format!("cargo-acl a/b/c {rev} linux-x86_64 {sha}\n")),
                false,
            ),
            (
                "odd char",
                s(format!(
                    "cargo;acl cackle-rs/cackle {rev} linux-x86_64 {sha}\n"
                )),
                false,
            ),
            (
                "pinned twice",
                s(format!("{pin}\ncargo-acl o/r {rev} linux-x86_64 {sha}\n")),
                false,
            ),
        ]
    }

    fn gate_accepts(bytes: &[u8]) -> bool {
        std::str::from_utf8(bytes).is_ok_and(|t| tools_lock_problems(t).is_empty())
    }

    #[test]
    fn tools_lock_lines_follow_one_grammar() {
        let real = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../tools/TOOLS.lock"),
        )
        .unwrap();
        assert!(
            tools_lock_problems(&real).is_empty(),
            "{:?}",
            tools_lock_problems(&real)
        );
        for (what, bytes, ok) in grammar_cases() {
            assert_eq!(gate_accepts(&bytes), ok, "{what}");
        }
        // The field checks would refuse some of these too; the character check is what names
        // the code point, so a reviewer sees which invisible character a line carries.
        let rev = "e7109a3174378976ea881f1883439ba82524f061";
        let sha = "87c159d397e93e88bddbfc76f2549936a09f65e8274564c7eb5d7bd23efdbfa7";
        let nbsp = format!("cargo-acl cackle-rs/cackle\u{a0}x {rev} linux-x86_64 {sha}");
        assert!(tools_lock_problems(&nbsp)[0].contains("U+00A0"));
        let twice = format!(
            "cargo-acl a/b {rev} linux-x86_64 {sha}\ncargo-acl o/r {rev} linux-x86_64 {sha}\n"
        );
        assert!(tools_lock_problems(&twice)[0].contains("pinned twice"));
    }

    /// `fetch-tools` refuses exactly what the gate refuses: its `tools_lock_grammar`, taken from
    /// the action itself and run by bash the way the action runs it, against every case above
    /// and the committed lock. On Windows, Git's bash by path: `bash` on PATH can be WSL's.
    #[test]
    fn fetch_tools_reads_the_lock_as_the_gate_does() {
        let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let action =
            std::fs::read_to_string(repo.join(".github/actions/fetch-tools/action.yml")).unwrap();
        let (b, e) = (
            action
                .find("# BEGIN tools-lock-grammar")
                .expect("BEGIN marker"),
            action.find("# END tools-lock-grammar").expect("END marker"),
        );
        let bash = if cfg!(windows) {
            PathBuf::from(std::env::var_os("ProgramFiles").expect("ProgramFiles"))
                .join("Git")
                .join("bin")
                .join("bash.exe")
        } else {
            PathBuf::from("bash")
        };
        let d = std::env::temp_dir().join(format!("gate-grammar-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let script = d.join("grammar.sh");
        std::fs::write(
            &script,
            format!(
                "set -euo pipefail\nexport LC_ALL=C\n{}\nif ! problem=$(tools_lock_grammar \"$1\"); \
                 then echo \"$problem\"; exit 1; fi\n",
                &action[b..e]
            ),
        )
        .unwrap();
        let fwd = |p: &Path| p.to_string_lossy().replace('\\', "/");
        let bash_accepts = |bytes: &[u8]| {
            let lock = d.join("TOOLS.lock");
            std::fs::write(&lock, bytes).unwrap();
            let out = std::process::Command::new(&bash)
                .arg(fwd(&script))
                .arg(fwd(&lock))
                .output()
                .unwrap_or_else(|e| panic!("{}: {e}", bash.display()));
            let err = String::from_utf8_lossy(&out.stderr).into_owned();
            assert!(err.is_empty(), "bash wrote to stderr: {err}");
            out.status.success()
        };
        let real = std::fs::read(repo.join("tools/TOOLS.lock")).unwrap();
        assert!(bash_accepts(&real), "the committed TOOLS.lock");
        for (what, bytes, ok) in grammar_cases() {
            assert_eq!(bash_accepts(&bytes), ok, "{what}");
            assert_eq!(gate_accepts(&bytes), ok, "{what}");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn paths_differing_only_by_case_are_found() {
        let p = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(case_collisions(&p(&["tools/TOOLS.lock", "tools/locks/a.lock"])).is_empty());
        assert_eq!(
            case_collisions(&p(&["tools/TOOLS.lock", "tools/tools.lock", "x"])),
            vec!["tools/TOOLS.lock / tools/tools.lock"]
        );
        // the directory and the file both collide
        assert_eq!(case_collisions(&p(&["A/b", "a/B"])).len(), 2);
        // two files in one directory spelled two ways: the directories collide
        assert_eq!(
            case_collisions(&p(&[
                "tools/patches/cargo-acl/a.patch",
                "tools/patches/Cargo-Acl/b.patch"
            ])),
            vec!["tools/patches/Cargo-Acl / tools/patches/cargo-acl"]
        );
    }

    /// A name a reader builds (from a pin, or a record name under a digest directory) and an
    /// index path that spells it another way: on Windows the gate reads the index path through
    /// the built name; git and the Linux producer do not.
    #[test]
    fn a_second_spelling_of_a_name_a_reader_opens_is_found() {
        let sha = "c".repeat(64);
        let lock = parse_tools_lock(&format!(
            "cargo-acl cackle-rs/cackle {} linux-x86_64 {sha}\n",
            "a".repeat(40)
        ));
        let found = |index: &[String]| {
            let mut all = index.to_vec();
            all.extend(opened_paths(&[&lock], index));
            case_collisions(&all)
        };
        let ev = format!("supply-chain/evidence/cargo-acl/{sha}");
        let clean = vec![
            "tools/TOOLS.lock".to_string(),
            "tools/locks/cargo-acl.lock".into(),
            "tools/patches/cargo-acl/a.patch".into(),
            format!("{ev}/vuln.jsonl"),
            format!("{ev}/caps.UNEVALUATED"),
            format!("{ev}/rev/{}/vuln.jsonl", "f".repeat(64)),
        ];
        assert!(found(&clean).is_empty(), "{:?}", found(&clean));
        // A rename replaces the path: the index alone then has one spelling, and only the name
        // a reader builds is the second.
        let rv = format!("{ev}/rev/{}", "f".repeat(64));
        for (what, gone, path) in [
            (
                "lock renamed",
                vec!["tools/locks/cargo-acl.lock".to_string()],
                "tools/locks/CARGO-ACL.lock".to_string(),
            ),
            (
                "build args added respelled",
                vec![],
                "tools/build-args/Cargo-Acl".into(),
            ),
            (
                "cargo config respelled",
                vec![],
                ".cargo/Config.toml".into(),
            ),
            (
                "toolchain pin respelled",
                vec![],
                "app/Rust-Toolchain.toml".into(),
            ),
            (
                "rustflags added respelled",
                vec![],
                "tools/rustflags/cargo-ACL".into(),
            ),
            (
                "patches renamed",
                vec!["tools/patches/cargo-acl/a.patch".into()],
                "tools/patches/Cargo-Acl/a.patch".into(),
            ),
            (
                "record renamed",
                vec![format!("{ev}/vuln.jsonl")],
                format!("{ev}/VULN.jsonl"),
            ),
            (
                "marker respelled",
                vec![format!("{ev}/caps.UNEVALUATED")],
                format!("{ev}/caps.unevaluated"),
            ),
            (
                "digest in capitals",
                vec![
                    format!("{ev}/vuln.jsonl"),
                    format!("{ev}/caps.UNEVALUATED"),
                    format!("{rv}/vuln.jsonl"),
                ],
                format!(
                    "supply-chain/evidence/cargo-acl/{}/vuln.jsonl",
                    sha.to_uppercase()
                ),
            ),
            (
                "rev dir respelled",
                vec![format!("{rv}/vuln.jsonl")],
                format!("{ev}/REV/{}/vuln.jsonl", "f".repeat(64)),
            ),
            (
                "revision record renamed",
                vec![format!("{rv}/vuln.jsonl")],
                format!("{rv}/Vuln.jsonl"),
            ),
            (
                "historical digest's rev dir respelled",
                vec![],
                format!(
                    "supply-chain/evidence/cargo-acl/{}/REV/{}/vuln.jsonl",
                    "b".repeat(64),
                    "f".repeat(64)
                ),
            ),
            (
                "historical digest record renamed",
                vec![],
                format!(
                    "supply-chain/evidence/cargo-acl/{}/Mal.jsonl",
                    "b".repeat(64)
                ),
            ),
            (
                "lock file renamed",
                vec!["tools/TOOLS.lock".into()],
                "tools/tools.lock".into(),
            ),
        ] {
            let mut index: Vec<String> = clean
                .iter()
                .filter(|p| !gone.contains(p))
                .cloned()
                .collect();
            index.push(path);
            assert!(
                case_collisions(&index).is_empty(),
                "{what}: the index alone collides"
            );
            assert!(!found(&index).is_empty(), "{what}");
        }
        // The committed index and lock have none.
        let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let out = Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(["ls-files", "-z"])
            .output()
            .unwrap();
        let index: Vec<String> = out
            .stdout
            .split(|b| *b == 0)
            .filter(|p| !p.is_empty())
            .map(|p| String::from_utf8_lossy(p).into_owned())
            .collect();
        let real =
            parse_tools_lock(&std::fs::read_to_string(repo.join("tools/TOOLS.lock")).unwrap());
        let mut all = index.clone();
        all.extend(opened_paths(&[&real], &index));
        assert!(
            case_collisions(&all).is_empty(),
            "{:?}",
            case_collisions(&all)
        );
    }

    /// The working tree under the gate's roots is the index, byte for byte.
    #[test]
    fn the_checkout_is_the_index() {
        let d = std::env::temp_dir().join(format!("gate-checkout-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("tools")).unwrap();
        let git = |args: &[&str]| {
            let o = Command::new("git")
                .arg("-C")
                .arg(&d)
                .args([
                    "-c",
                    "core.autocrlf=false",
                    "-c",
                    "user.name=t",
                    "-c",
                    "user.email=t@t",
                ])
                .args(args)
                .output()
                .unwrap();
            assert!(
                o.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&o.stderr)
            );
        };
        git(&["init", "-q"]);
        git(&["config", "core.autocrlf", "false"]);
        std::fs::write(d.join("tools/a.txt"), "one\ntwo\n").unwrap();
        std::fs::write(d.join("tools/b.txt"), "b\n").unwrap();
        std::fs::write(d.join("other.txt"), "x\n").unwrap();
        git(&["add", "-A"]);
        git(&["commit", "-q", "-m", "c"]);
        let problems = || checkout_problems(&d, &["tools"]).unwrap();
        assert!(problems().is_empty(), "{:?}", problems());
        // outside the roots: not this check's
        std::fs::write(d.join("other.txt"), "y\n").unwrap();
        std::fs::write(d.join("loose.txt"), "y\n").unwrap();
        assert!(problems().is_empty(), "{:?}", problems());
        // other bytes than the blob
        std::fs::write(d.join("tools/a.txt"), "one\ntwo!\n").unwrap();
        assert!(problems()[0].contains("tools/a.txt"));
        git(&["checkout", "-q", "--", "tools/a.txt"]);
        assert!(problems().is_empty());
        // a file the index does not hold
        std::fs::write(d.join("tools/c.txt"), "c\n").unwrap();
        assert!(problems()[0].contains("tools/c.txt"));
        std::fs::remove_file(d.join("tools/c.txt")).unwrap();
        // an attribute that makes the checkout differ from the blob
        std::fs::write(d.join(".gitattributes"), "tools/a.txt eol=crlf\n").unwrap();
        git(&["add", ".gitattributes"]);
        git(&["commit", "-q", "-m", "attr"]);
        std::fs::remove_file(d.join("tools/a.txt")).unwrap();
        git(&["checkout", "-q", "--", "tools/a.txt"]);
        assert!(problems()[0].contains("tools/a.txt"), "{:?}", problems());
        git(&["rm", "-q", ".gitattributes"]);
        git(&["commit", "-q", "-m", "no attr"]);
        std::fs::remove_file(d.join("tools/a.txt")).unwrap();
        git(&["checkout", "-q", "--", "tools/a.txt"]);
        assert!(problems().is_empty(), "{:?}", problems());
        // not a regular file
        git(&["update-index", "--chmod=+x", "tools/b.txt"]);
        assert!(problems()[0].contains("tools/b.txt"));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A pin names the source its producer run built: the producer commit's row for the same
    /// (name, target) has the pin's repo and rev.
    #[test]
    fn a_pin_names_the_source_its_producer_built() {
        let (r, s) = ("a".repeat(40), "c".repeat(64));
        let at_commit = format!(
            "# producer commit\nt o/r {r} linux-x86_64 {}\nt o/r {r} windows-x86_64 {s}\n",
            ZERO_DIGEST
        );
        let pin = |repo: &str, rev: &str, target: &str| ToolLine {
            name: "t".into(),
            repo: repo.into(),
            rev: rev.into(),
            target: target.into(),
            sha: s.clone(),
        };
        // the digest is the one the run produced; the commit's row may still be unset
        assert!(producer_source(&at_commit, &pin("o/r", &r, "linux-x86_64")).is_ok());
        assert!(producer_source(&at_commit, &pin("o/r", &r, "windows-x86_64")).is_ok());
        for (what, p) in [
            ("another repo", pin("evil/r", &r, "linux-x86_64")),
            ("another rev", pin("o/r", &"b".repeat(40), "linux-x86_64")),
            (
                "a target the commit does not pin",
                pin("o/r", &r, "macos-aarch64"),
            ),
        ] {
            assert!(producer_source(&at_commit, &p).is_err(), "{what}");
        }
    }

    #[test]
    fn a_pin_is_unchanged_only_when_every_field_is() {
        let line = |name: &str, repo: &str, rev: &str, target: &str, sha: &str| ToolLine {
            name: name.into(),
            repo: repo.into(),
            rev: rev.into(),
            target: target.into(),
            sha: sha.into(),
        };
        let (r, s) = ("a".repeat(40), "c".repeat(64));
        let base = vec![line("t", "o/r", &r, "linux-x86_64", &s)];
        assert!(candidates(&base, &base).is_empty());
        for (what, h) in [
            ("repo", line("t", "evil/r", &r, "linux-x86_64", &s)),
            ("rev", line("t", "o/r", &"b".repeat(40), "linux-x86_64", &s)),
            (
                "digest",
                line("t", "o/r", &r, "linux-x86_64", &"d".repeat(64)),
            ),
            (
                "a new target with the same source and bytes",
                line("t", "o/r", &r, "windows-x86_64", &s),
            ),
        ] {
            let c = candidates(&base, &[h]);
            assert_eq!(c.len(), 1, "{what}");
        }
        // the baseline for a new target is the tool's pin on another target
        let c = candidates(
            &base,
            &[line("t", "o/r", &r, "windows-x86_64", &"e".repeat(64))],
        );
        assert_eq!(
            c[0].0.as_ref().map(|b| b.target.as_str()),
            Some("linux-x86_64")
        );
    }

    #[test]
    fn the_isolated_scanner_gets_absolute_binaries_or_a_copied_lock() {
        let d = std::env::temp_dir().join(format!("gate-argv-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let bin = isolated_argv(&v(&["audit", "bin", "target/x.exe", "--json"]), &d).unwrap();
        assert!(
            Path::new(&bin[2]).is_absolute() && bin[2].ends_with("x.exe"),
            "{bin:?}"
        );
        assert_eq!(bin[3], "--json");
        let lock = d.join("in.lock");
        std::fs::write(&lock, "x").unwrap();
        let f = isolated_argv(
            &v(&["audit", "--json", "--file", &lock.to_string_lossy()]),
            &d,
        )
        .unwrap();
        assert_eq!(Path::new(&f[3]), d.join("Cargo.lock"));
        assert_eq!(std::fs::read(d.join("Cargo.lock")).unwrap(), b"x");
        assert!(isolated_argv(&v(&["audit", "--json"]), &d).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The gate judges the app's records: a change under a release's digest that is not one of
    /// its records blocks, with no TOOLS.lock change at all.
    #[test]
    fn the_gate_judges_the_apps_records() {
        let d = std::env::temp_dir().join(format!("gate-app-run-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let digest = "a".repeat(64);
        for side in ["ev", "bev"] {
            let rel = d.join(side).join(APP).join(&digest);
            std::fs::create_dir_all(&rel).unwrap();
            std::fs::write(rel.join("provenance.sigstore.jsonl"), "p\n").unwrap();
        }
        for sub in ["locks", "blocks", "tools", "btools"] {
            std::fs::create_dir_all(d.join(sub)).unwrap();
        }
        std::fs::write(
            d.join("TOOLS.lock"),
            format!("t o/r {} linux-x86_64 {}\n", "a".repeat(40), "c".repeat(64)),
        )
        .unwrap();
        let floors =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../supply-chain/policy/floors.json");
        let run_it = || {
            let p = |x: &str| d.join(x).to_string_lossy().into_owned();
            let args: Vec<String> = [
                "gate",
                "--base",
                &p("TOOLS.lock"),
                "--head",
                &p("TOOLS.lock"),
                "--evidence",
                &p("ev"),
                "--base-evidence",
                &p("bev"),
                "--locks-dir",
                &p("locks"),
                "--base-locks-dir",
                &p("blocks"),
                "--tools-dir",
                &p("tools"),
                "--base-tools-dir",
                &p("btools"),
                "--floors",
                &floors.to_string_lossy(),
                "--report",
                &p("report.md"),
            ]
            .map(String::from)
            .to_vec();
            run(&args)
        };
        assert_eq!(run_it(), 0);
        std::fs::write(d.join("ev").join(APP).join(&digest).join("notes.txt"), "x").unwrap();
        assert_eq!(run_it(), 1);
        let report = std::fs::read_to_string(d.join("report.md")).unwrap();
        assert!(report.contains("not one of the app's records"), "{report}");
        std::fs::remove_file(d.join("ev").join(APP).join(&digest).join("notes.txt")).unwrap();
        // sign-offs are history: quality-passing ack lines, one of them removed
        let real = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../supply-chain/evidence/cargo-vet/acks.jsonl"),
        )
        .unwrap();
        let lines: Vec<&str> = real
            .lines()
            .filter(|l| !l.trim().is_empty())
            .take(2)
            .collect();
        let acks = |side: &str, body: String| {
            std::fs::write(d.join(side).join(APP).join("acks.jsonl"), body).unwrap()
        };
        acks("bev", format!("{}\n{}\n", lines[0], lines[1]));
        acks("ev", format!("{}\n{}\n", lines[0], lines[1]));
        assert_eq!(run_it(), 0, "unchanged");
        acks("ev", format!("{}\n", lines[0]));
        assert_eq!(run_it(), 1, "a sign-off removed");
        let report = std::fs::read_to_string(d.join("report.md")).unwrap();
        assert!(
            report.contains("sign-offs are added, never rewritten"),
            "{report}"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// No policy, no verdict: a broken floors file blocks a change even when nothing else in it
    /// is evaluated.
    #[test]
    fn a_broken_policy_blocks_a_change_with_nothing_to_evaluate() {
        let d = std::env::temp_dir().join(format!("gate-floors-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        for sub in ["ev", "bev", "locks", "blocks", "tools", "btools"] {
            std::fs::create_dir_all(d.join(sub)).unwrap();
        }
        let lock = d.join("TOOLS.lock");
        std::fs::write(
            &lock,
            format!("t o/r {} linux-x86_64 {}\n", "a".repeat(40), "c".repeat(64)),
        )
        .unwrap();
        std::fs::write(d.join("bad.json"), r#"{"schema":"nope"}"#).unwrap();
        let good = Path::new(env!("CARGO_MANIFEST_DIR")).join("../supply-chain/policy/floors.json");
        let run_with = |floors: &Path| {
            let p = |x: &str| d.join(x).to_string_lossy().into_owned();
            let args: Vec<String> = [
                "gate",
                "--base",
                &p("TOOLS.lock"),
                "--head",
                &p("TOOLS.lock"),
                "--evidence",
                &p("ev"),
                "--base-evidence",
                &p("bev"),
                "--locks-dir",
                &p("locks"),
                "--base-locks-dir",
                &p("blocks"),
                "--tools-dir",
                &p("tools"),
                "--base-tools-dir",
                &p("btools"),
                "--floors",
                &floors.to_string_lossy(),
                "--report",
                &p("report.md"),
            ]
            .map(String::from)
            .to_vec();
            run(&args)
        };
        // The workflow enforces a written PASS line as the report's last line, not only the exit
        // status: it is the line a passing run ends with, and a blocked run does not.
        let wf = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../.github/workflows/candidate-eval.yml"),
        )
        .unwrap();
        let required = wf
            .lines()
            .find_map(|l| {
                l.trim_start()
                    .strip_prefix("pass='")
                    .and_then(|r| r.split_once('\''))
            })
            .map(|(line, _)| line.to_string())
            .expect("candidate-eval enforces a PASS line");
        let has = || {
            std::fs::read_to_string(d.join("report.md"))
                .unwrap()
                .lines()
                .last()
                .is_some_and(|l| l == required)
        };
        assert_eq!(run_with(&good), 0);
        assert!(has(), "a passing report carries `{required}`");
        assert_eq!(run_with(&d.join("bad.json")), 1);
        assert!(!has(), "a blocked report does not");
        assert_eq!(run_with(&d.join("missing.json")), 1);
        let _ = std::fs::remove_dir_all(&d);
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
