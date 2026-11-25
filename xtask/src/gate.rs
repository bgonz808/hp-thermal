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
    if is_placeholder(notes) {
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
        if v.get("product").and_then(|p| p.get("digest")).is_some() {
            vuln_bound_quality(v)?;
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

/// A digest-bound vuln statement is a claim about one binary's bytes: it names the digest, an
/// OpenVEX status that can be true of immutable bytes, and the native CycloneDX ruling the VDR
/// copies, pointing the same way. Lines without a digest govern nothing (`last_vuln_ack`); the
/// record is append-only, so they are not re-judged here.
fn vuln_bound_quality(v: &Value) -> Result<(), String> {
    let d = s(v, &["product", "digest"]);
    if d.len() != 64
        || !d
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err("vuln ack `product.digest` is not 64 lowercase hex".into());
    }
    let status = s(v, &["status"]);
    let state = s(v, &["cyclonedx", "state"]);
    // `affected` is a decision (OpenVEX: actions are recommended); `in_triage` says the
    // investigation is open, which is `under_investigation`.
    let agree: &[&str] = match status {
        "not_affected" => &["not_affected", "false_positive"],
        "affected" => &["exploitable"],
        "under_investigation" => &["in_triage"],
        other => {
            return Err(format!(
                "vuln ack status `{other}`: a digest-bound statement is not_affected, affected \
                 or under_investigation"
            ));
        }
    };
    if !agree.contains(&state) {
        return Err(format!(
            "vuln ack status `{status}` with cyclonedx.state `{state}`: the CycloneDX ruling the \
             VDR publishes must agree ({})",
            agree.join(" | ")
        ));
    }
    if status == "not_affected" {
        let j = s(v, &["justification"]);
        let cj = s(v, &["cyclonedx", "justification"]);
        let Some((_, allowed)) = JUSTIFICATIONS.iter().find(|(o, _)| *o == j) else {
            return Err(format!(
                "vuln ack justification `{j}`: a digest-bound not_affected names one of OpenVEX's five"
            ));
        };
        // `false_positive` may carry no CycloneDX justification; one it carries must agree.
        if !(allowed.contains(&cj) || state == "false_positive" && cj.is_empty()) {
            return Err(format!(
                "vuln ack justification `{j}` with cyclonedx.justification `{cj}`: they must say \
                 the same thing ({})",
                allowed.join(" | ")
            ));
        }
    }
    if status != "not_affected"
        && (!s(v, &["justification"]).is_empty()
            || !s(v, &["cyclonedx", "justification"]).is_empty())
    {
        return Err(format!(
            "vuln ack status `{status}` carries a not_affected justification"
        ));
    }
    // OpenVEX: an `affected` statement MUST include an `action_statement` (the VDR publishes it
    // as the vulnerability's `recommendation`), and only `affected` carries one. CycloneDX: a
    // `response` is strongly encouraged where the state is `exploitable` (here, required); any
    // response is from CycloneDX's own values.
    let action = v.get("action_statement");
    if status == "affected" && is_placeholder(action.and_then(Value::as_str).unwrap_or("")) {
        return Err(
            "vuln ack status `affected` without `action_statement` (OpenVEX: an affected \
             statement MUST say what is done to remediate or mitigate)"
                .into(),
        );
    }
    if status != "affected" && action.is_some() {
        return Err(format!(
            "vuln ack status `{status}` carries `action_statement`; only an affected statement \
             does"
        ));
    }
    let response = v.get("cyclonedx").and_then(|c| c.get("response"));
    if let Some(r) = response {
        let items: Vec<&str> = r
            .as_array()
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let distinct: BTreeSet<&str> = items.iter().copied().collect();
        let valid = r
            .as_array()
            .is_some_and(|a| !a.is_empty() && a.len() == items.len())
            && distinct.len() == items.len()
            && items.iter().all(|i| RESPONSES.contains(i));
        if !valid {
            return Err(format!(
                "vuln ack cyclonedx.response `{r}`: distinct values from {}",
                RESPONSES.join(" | ")
            ));
        }
    }
    if state == "exploitable" && response.is_none() {
        return Err(
            "vuln ack cyclonedx.state `exploitable` without `response` (what is done about it)"
                .into(),
        );
    }
    Ok(())
}

/// Text that says nothing: empty, or a placeholder in any case (`todo`, `TBD`, `n/a`, ...).
/// Sign-off text is published (VDR `detail` / `recommendation`), so a stub never passes.
fn is_placeholder(t: &str) -> bool {
    let u = t.trim().to_ascii_uppercase();
    u.is_empty()
        || ["TODO", "TBD", "FIXME", "XXX"]
            .iter()
            .any(|p| u.contains(p))
        || ["N/A", "NA", "NONE", "-", ".", "...", "?"].contains(&u.as_str())
}

/// CycloneDX 1.6 `vulnerability.analysis.response` values.
pub(crate) const RESPONSES: &[&str] = &[
    "can_not_fix",
    "will_not_fix",
    "update",
    "rollback",
    "workaround_available",
];

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

/// The LAST quality-passing vuln statement for this instance in the binary `digest`, in file
/// order. acks.jsonl is append-only, so file order is statement order — the OpenVEX sequence
/// model (#251): a later statement supersedes an earlier one for the same product +
/// vulnerability. The product is the binary: a statement names the digest it was made about and
/// governs nothing else, so a new build of the same package version is judged afresh.
pub(crate) fn last_vuln_ack<'a>(
    acks: &'a Acks,
    inst: &Instance,
    digest: &str,
) -> Option<&'a Value> {
    last_vuln_statement(&acks.entries, inst, digest)
}

pub(crate) fn last_vuln_statement<'a>(
    entries: &'a [Value],
    inst: &Instance,
    digest: &str,
) -> Option<&'a Value> {
    entries
        .iter()
        .rev()
        .find(|a| is_vuln_statement(a, inst, digest))
}

/// A vuln statement about this instance in the binary `digest`.
pub(crate) fn is_vuln_statement(a: &Value, inst: &Instance, digest: &str) -> bool {
    s(a, &["axis"]) == "vuln"
        && !digest.is_empty()
        && s(a, &["product", "digest"]) == digest
        && s(a, &["vulnerability", "name"]) == inst.id
        && s(a, &["product", "package"]) == inst.package
        && s(a, &["product", "version"]) == inst.version
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

/// Statement selection only (tests): the instance's LAST statement exists and is not grounded in
/// the DB's silence. Coverage is only ever asked about an instance the DB reports NOW, so a last
/// statement that says "the DB did not report it" is contradicted by the measurement and void:
/// the reappearance is RAISE uncovered until signed afresh (fail-closed, #251). Whether the
/// selected statement covers is `coverage`'s call (its record, measurement or status).
#[cfg(test)]
pub(crate) fn ack_covers_vuln(acks: &Acks, inst: &Instance, digest: &str) -> bool {
    governing_vuln_ack(acks, inst, digest).is_some()
}

/// OpenVEX `not_affected` justifications, each with the CycloneDX justifications that say the
/// same thing. A digest-bound statement's two rulings must correspond (the VDR publishes the
/// CycloneDX one, the gate reads the OpenVEX one).
pub(crate) const JUSTIFICATIONS: &[(&str, &[&str])] = &[
    ("component_not_present", &["code_not_present"]),
    ("vulnerable_code_not_present", &["code_not_present"]),
    (
        "vulnerable_code_not_in_execute_path",
        &["code_not_reachable"],
    ),
    (
        "vulnerable_code_cannot_be_controlled_by_adversary",
        &[
            "requires_configuration",
            "requires_dependency",
            "requires_environment",
            "protected_at_perimeter",
        ],
    ),
    (
        "inline_mitigations_already_exist",
        &[
            "protected_by_compiler",
            "protected_at_runtime",
            "protected_at_perimeter",
            "protected_by_mitigating_control",
        ],
    ),
];

/// The statement's claim rests on a reachability record (#520): every `not_affected` except
/// `component_not_present`, which claims the package is absent (the VDR measures that from the
/// binary). Anything else, including a missing or unknown justification, needs the record.
pub(crate) fn needs_record(a: &Value) -> bool {
    s(a, &["status"]) == "not_affected" && s(a, &["justification"]) != "component_not_present"
}

/// Whether an instance in a binary is covered.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Cover {
    Yes,
    /// Not covered; the reason when a statement exists but cannot cover.
    No(Option<String>),
    /// Cannot be told (a record that does not reproduce, a fetch that failed): never acked past.
    Unknown(String),
}

/// Coverage of `inst` in `digest`: the governing statement, and for every `not_affected` the
/// evidence under it, judged by `record`: the reachability record a claim about the code names,
/// or the binary's own measurement for `component_not_present`.
pub(crate) fn coverage(
    acks: &Acks,
    inst: &Instance,
    digest: &str,
    record: &mut dyn FnMut(&Value, &Instance) -> Cover,
) -> Cover {
    match governing_vuln_ack(acks, inst, digest) {
        None => Cover::No(None),
        // A claim about the code rests on its record; `component_not_present` on the binary's
        // own measurement. Neither is taken on the statement's word.
        Some(a) if s(a, &["status"]) == "not_affected" => record(a, inst),
        // `affected` is a decision with an action (`vuln_bound_quality`).
        Some(a) if s(a, &["status"]) == "affected" => Cover::Yes,
        // `under_investigation` records that no decision is made yet: it covers nothing.
        Some(a) => Cover::No(Some(format!(
            "{} {} {}: the statement is `{}`; an open investigation is not a decision",
            inst.id,
            inst.package,
            inst.version,
            s(a, &["status"])
        ))),
    }
}

/// Coverage without regenerating records (monitor, explore): a claim about the code needs its
/// record committed in `dir`, hashing to the statement and named for the advisory as `audit`
/// states it now; `component_not_present` needs the binary's measurement.
pub(crate) fn coverage_at_rest(
    acks: &Acks,
    inst: &Instance,
    tool: &str,
    digest: &str,
    dir: &Result<PathBuf, String>,
    audit: &Value,
) -> Cover {
    coverage(acks, inst, digest, &mut |a, inst| match dir {
        Ok(dir) if needs_record(a) => record_cover(a, inst, audit, dir, None),
        Ok(dir) => measured_absent(tool, digest, dir, inst),
        Err(e) => Cover::Unknown(e.clone()),
    })
}

/// Rebuilds a record's bytes from the checkout for a query (affected functions).
pub(crate) type Regenerate<'a> =
    &'a mut dyn FnMut(&BTreeMap<String, Vec<String>>) -> Result<String, String>;

/// The gate's record check: the record named for this instance and the scan's query must be
/// committed in `dir`, hash to the statement's `evidence_sha256`, and reproduce byte for byte
/// from the checkout (`regenerate`). A record that is there and does not reproduce cannot be
/// acked past.
pub(crate) fn record_cover(
    a: &Value,
    inst: &Instance,
    scan: &Value,
    dir: &Path,
    regenerate: Option<Regenerate<'_>>,
) -> Cover {
    let functions =
        match crate::reach::affected_functions(scan, &inst.id, &inst.package, &inst.version) {
            Ok(f) => f,
            Err(e) => return Cover::Unknown(e),
        };
    let name = match crate::reach::record_name(&inst.id, &inst.package, &inst.version, &functions) {
        Ok(n) => n,
        Err(e) => return Cover::No(Some(format!("{}: {e}", inst.id))),
    };
    let path = dir.join("reach").join(&name);
    let Ok(bytes) = std::fs::read(&path) else {
        return Cover::No(Some(format!(
            "{} {} {}: the statement's claim needs reachability record `reach/{name}`, not committed \
             (`cargo xtask reach emit`)",
            inst.id, inst.package, inst.version
        )));
    };
    let sha = crate::sha256::sha256_hex(&bytes);
    if s(a, &["evidence_sha256"]) != sha {
        return Cover::No(Some(format!(
            "{} {} {}: the statement's `evidence_sha256` is not the sha256 of `reach/{name}` ({sha})",
            inst.id, inst.package, inst.version
        )));
    }
    let Some(regenerate) = regenerate else {
        return Cover::Yes;
    };
    match regenerate(&functions) {
        Ok(text) if text.as_bytes() == bytes.as_slice() => Cover::Yes,
        Ok(_) => Cover::Unknown(format!(
            "reach/{name} does not reproduce from the checkout: a record that does not reproduce \
             cannot be acked past"
        )),
        Err(e) => Cover::Unknown(format!("reach/{name}: {e}")),
    }
}

/// The statement that covers this instance in `digest`, if one does: the gate, the monitor and
/// the VDR's `analysis` all read coverage through here.
pub(crate) fn governing_vuln_ack<'a>(
    acks: &'a Acks,
    inst: &Instance,
    digest: &str,
) -> Option<&'a Value> {
    governing_vuln_statement(&acks.entries, inst, digest)
}

/// `governing_vuln_ack` over quality-passing entries already loaded.
pub(crate) fn governing_vuln_statement<'a>(
    entries: &'a [Value],
    inst: &Instance,
    digest: &str,
) -> Option<&'a Value> {
    last_vuln_statement(entries, inst, digest).filter(|a| observed_absent_at_db(a).is_none())
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
/// CycloneDX `state` / `justification` / `response` the VDR copies. It starts as `affected` with
/// an empty `action_statement` and `response`, refused until a human says what is done about it,
/// or replaces it with a `not_affected` and its evidence. Measured facts (binary presence, version ranges, digests,
/// dependency paths) live in the VDR's own fields and are not restated in the notes. Caps acks use `reviewed`: a caps ack signs an inventory, not a
/// vulnerability status, so the OpenVEX statuses do not apply there. The statement names the
/// binary it is about (`product.digest`) and covers that binary only; the quality bar holds the
/// OpenVEX status and the CycloneDX state to the same direction (`vuln_bound_quality`).
pub(crate) fn ack_template_vuln(tool: &str, digest: &str, inst: &Instance) -> String {
    serde_json::json!({
        "schema": "hp-thermal/evidence-ack/v1",
        "axis": "vuln",
        "vulnerability": {"name": inst.id},
        "product": {"name": tool, "digest": digest, "package": inst.package, "version": inst.version},
        "status": "affected",
        "action_statement": "",
        "cyclonedx": {"state": "exploitable", "response": []},
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
    digest: &str,
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
        "product": {"name": tool, "digest": digest, "package": inst.package, "version": inst.version},
        "status": "not_affected",
        "justification": "vulnerable_code_not_present",
        "cyclonedx": {"state": "not_affected", "justification": "code_not_present"},
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
        /// Why an item that has a statement is still uncovered (e.g. its record is missing).
        notes: Vec<String>,
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
    digest: &str,
    added: &[Instance],
    carried: &[Instance],
    fixed_count: usize,
    acks: &Acks,
    record: &mut dyn FnMut(&Value, &Instance) -> Cover,
) -> Verdict {
    let mut covered = Vec::new();
    let mut needed = Vec::new();
    let mut notes = Vec::new();
    let mut unknown = Vec::new();
    for (label, set) in [("added", added), ("carried-unacked", carried)] {
        for i in set {
            match coverage(acks, i, digest, record) {
                Cover::Yes => {
                    covered.push(format!("{label}: {} {} {}", i.id, i.package, i.version))
                }
                Cover::No(why) => {
                    notes.extend(why);
                    needed.push(ack_template_vuln(tool, digest, i));
                }
                Cover::Unknown(why) => {
                    unknown.push(format!("{} {} {}: {why}", i.id, i.package, i.version))
                }
            }
        }
    }
    if !unknown.is_empty() {
        return Verdict::Unevaluated(unknown.join("\n  - "));
    }
    if !needed.is_empty() {
        return Verdict::RaiseUncovered {
            covered,
            needed,
            notes,
        };
    }
    if added.is_empty() && covered.len() == carried.len() {
        // added = ∅ and every carried instance acked -> the §4 relative ∧ absolute ALLOW.
        return Verdict::Allow(format!(
            "no added instances; {} carried all acked; {fixed_count} fixed",
            carried.len()
        ));
    }
    Verdict::RaiseCovered(covered)
}

/// The gate's record judge for one pinned or candidate row (#520): the record directory the
/// checkout selects for (tool, digest), and regeneration from the checkout's inputs — the frozen
/// lock, the row's repo and rev, the tool's patches — with the query from the asking scan.
fn gate_record_judge<'a>(
    row: &'a ToolLine,
    evidence_dir: &'a Path,
    locks_dir: &'a Path,
) -> impl FnMut(&Value, &Instance, &Value) -> Cover + 'a {
    move |a, inst, scan| {
        let dir = match crate::evidence_rev::current(evidence_dir, locks_dir, &row.name, &row.sha) {
            Ok(r) => r.dir,
            Err(e) => return Cover::Unknown(e),
        };
        if !needs_record(a) {
            return measured_absent(&row.name, &row.sha, &dir, inst);
        }
        let lock = locks_dir.join(format!("{}.lock", row.name));
        let mut regen = |functions: &BTreeMap<String, Vec<String>>| -> Result<String, String> {
            let i = crate::reach::Inputs {
                tool: row.name.clone(),
                digest: row.sha.clone(),
                repo: row.repo.clone(),
                rev: row.rev.clone(),
                lock: std::fs::read_to_string(&lock).map_err(|e| {
                    format!("{}: {e} (a record needs the frozen lock)", lock.display())
                })?,
                patches: crate::reach::patches_for(&row.name)?,
                id: inst.id.clone(),
                package: inst.package.clone(),
                version: inst.version.clone(),
                functions: functions.clone(),
            };
            Ok(crate::reach::generate(&i)?.1)
        };
        record_cover(a, inst, scan, &dir, Some(&mut regen))
    }
}

/// A `component_not_present` statement against the binary itself (#520): the package must be
/// `excluded` by the same measurement the VDR's scope comes from (the pinned binary's `.dep-v0`
/// and its custody-verified build record). A record directory without a build record cannot
/// tell a standard-library copy apart, so it cannot be judged. One measurement per digest per run.
pub(crate) fn measured_absent(tool: &str, digest: &str, dir: &Path, inst: &Instance) -> Cover {
    use std::sync::{Arc, Mutex, OnceLock};
    type Scoped = Arc<Result<Vec<Value>, String>>;
    static SCOPES: OnceLock<Mutex<BTreeMap<String, Scoped>>> = OnceLock::new();
    if !dir.join(crate::build_record::FILE).is_file() {
        return Cover::Unknown(format!(
            "{} {}: no build record under {}; presence cannot be measured",
            inst.package,
            inst.version,
            dir.display()
        ));
    }
    let key = format!("{tool}@{digest}@{}", dir.display());
    let cache = SCOPES.get_or_init(|| Mutex::new(BTreeMap::new()));
    let cached = cache.lock().ok().and_then(|c| c.get(&key).cloned());
    let comps = match cached {
        Some(c) => c,
        None => {
            let c: Scoped =
                Arc::new(crate::vdr::tool_components(tool, digest, dir).map(|(c, _)| c));
            if let Ok(mut m) = cache.lock() {
                m.insert(key, c.clone());
            }
            c
        }
    };
    let comps = match comps.as_ref() {
        Ok(c) => c,
        Err(e) => {
            return Cover::Unknown(format!(
                "presence of {} {}: {e}",
                inst.package, inst.version
            ));
        }
    };
    let scope = comps
        .iter()
        .find(|c| s(c, &["name"]) == inst.package && s(c, &["version"]) == inst.version)
        .map(|c| s(c, &["scope"]));
    match scope {
        Some("excluded") => Cover::Yes,
        Some(other) => Cover::No(Some(format!(
            "{} {} {}: the statement says the component is not present; the binary's measurement \
             scopes it `{}`",
            inst.id,
            inst.package,
            inst.version,
            if other.is_empty() { "listed" } else { other }
        ))),
        None => Cover::Unknown(format!(
            "{} {} is not among the lock's components",
            inst.package, inst.version
        )),
    }
}

/// The pinned rows of `tool` an acks edit re-judges (#519): every row TOOLS.lock pins for it,
/// except one the candidate path judges with the same statements (same name, target, digest).
/// Evidence-edit rows and a multi-target tool's other targets are included.
fn rows_to_rejudge<'a>(
    tool: &str,
    head: &'a [ToolLine],
    cands: &[(Option<ToolLine>, ToolLine)],
) -> Vec<&'a ToolLine> {
    head.iter()
        .filter(|l| {
            l.name == tool
                && !cands
                    .iter()
                    .any(|(_, h)| h.name == l.name && h.target == l.target && h.sha == l.sha)
        })
        .collect()
}

/// The vuln axis of one pinned row whose statements changed (#519): its current instances are
/// judged with the edited statements. Instances in the row's recorded baseline are carried; any
/// other is added (signed RAISE when covered, never ALLOW). Without a baseline every instance
/// is added. A row the bless flow has not produced cannot be judged.
fn judge_pinned_row(
    row: &ToolLine,
    acks: &Acks,
    baseline: Option<&BTreeSet<Instance>>,
    scan: &mut dyn FnMut(&ToolLine) -> Result<Value, String>,
    floors: &crate::floors::Floors,
    record: &mut dyn FnMut(&Value, &Instance, &Value) -> Cover,
) -> Verdict {
    if row.sha == ZERO_DIGEST || row.sha.len() != 64 {
        return Verdict::Unevaluated(format!(
            "{} [{}]: digest is unset/malformed — nothing blessed to judge",
            row.name, row.target
        ));
    }
    let json = match scan(row) {
        Ok(j) => j,
        Err(e) => return Verdict::Unevaluated(e),
    };
    let inst = extract_instances(&json);
    let stops = floors.vuln_stops(&inst, &crate::floors::extract_cvss(&json));
    if !stops.is_empty() {
        return Verdict::HardStop(stops.join("\n  - "));
    }
    let (added, carried) = match baseline {
        Some(b) => {
            let (new, carried, _gone) = crate::monitor::classify(b, &inst);
            (new, carried)
        }
        None => (inst.into_iter().collect(), Vec::new()),
    };
    vuln_verdict(
        &row.name,
        &row.sha,
        &added,
        &carried,
        0,
        acks,
        &mut |a, i| record(a, i, &json),
    )
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
                Verdict::RaiseUncovered {
                    covered,
                    needed,
                    notes: Vec::new(),
                }
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
                notes: Vec::new(),
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
    Ok(v.messages)
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
            notes: Vec::new(),
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
        .args(["-q", "-sSfL", &url, "-o"])
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

/// Every entry of every `reach/` directory under `root` (a digest's, or a revision's), by path
/// relative to `root`: a file's bytes, or `None` for anything that is not a regular file.
fn reach_entries(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    let mut out = BTreeMap::new();
    let subdirs = |p: &Path| -> Vec<PathBuf> {
        std::fs::read_dir(p)
            .map(|r| {
                r.flatten()
                    .map(|e| e.path())
                    .filter(|p| p.is_dir())
                    .collect()
            })
            .unwrap_or_default()
    };
    for tool in subdirs(root) {
        for digest in subdirs(&tool) {
            let mut dirs = vec![digest.join("reach")];
            dirs.extend(
                subdirs(&digest.join(crate::evidence_rev::REV_DIR))
                    .into_iter()
                    .map(|r| r.join("reach")),
            );
            for d in dirs {
                for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
                    let path = e.path();
                    let Ok(rel) = path.strip_prefix(root) else {
                        continue;
                    };
                    let bytes = path.is_file().then(|| std::fs::read(&path).ok()).flatten();
                    out.insert(rel.to_path_buf(), bytes);
                }
            }
        }
    }
    out
}

/// `RUSTSEC-YYYY-NNNN-<12 hex>.sarif`, the only name a record has (`reach::record_name`).
fn is_record_name(name: &str) -> bool {
    name.len() == 17 + 1 + 12 + 6
        && crate::reach::is_rustsec_id(&name[..17])
        && name.as_bytes()[17] == b'-'
        && name[18..30]
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        && name.ends_with(".sarif")
}

/// Reachability records (#520) this change touches. Records are add-only: an edited or deleted
/// record, or anything in a `reach/` directory that is not a record file, is refused. Returns the
/// added records (relative to the evidence root) and the refusals.
pub(crate) fn reach_changes(
    evidence_dir: &Path,
    base_evidence_dir: &Path,
) -> (Vec<PathBuf>, Vec<String>) {
    let head = reach_entries(evidence_dir);
    let base = reach_entries(base_evidence_dir);
    let mut refused = Vec::new();
    for (rel, b) in &base {
        // Pruning a digest's whole evidence directory takes its records with it.
        let digest_dir: PathBuf = rel.iter().take(2).collect();
        match head.get(rel) {
            None if !evidence_dir.join(&digest_dir).is_dir() => {}
            None => refused.push(format!("{}: a committed record was deleted", rel.display())),
            Some(h) if h != b => {
                refused.push(format!("{}: a committed record was edited", rel.display()))
            }
            _ => {}
        }
    }
    let mut added = Vec::new();
    for (rel, h) in &head {
        if base.contains_key(rel) {
            continue;
        }
        let name = rel
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if h.is_none() || !is_record_name(&name) {
            refused.push(format!(
                "{}: not a record file (reach/ holds only RUSTSEC-YYYY-NNNN-<h12>.sarif)",
                rel.display()
            ));
        } else {
            added.push(rel.clone());
        }
    }
    (added, refused)
}

/// An added record must be what the checkout reproduces: it sits in the record directory the
/// checkout selects for its (tool, digest), its name is the one its stated instance and query
/// give, and regenerating it from the checkout's inputs with that query gives the same bytes.
fn verify_added_record(
    rel: &Path,
    evidence_dir: &Path,
    locks_dir: &Path,
    head: &[ToolLine],
    scan: &mut dyn FnMut(&str) -> Result<Value, String>,
) -> Result<String, String> {
    let bytes =
        std::fs::read(evidence_dir.join(rel)).map_err(|e| format!("{}: {e}", rel.display()))?;
    let v: Value = serde_json::from_slice(&bytes).map_err(|e| format!("not JSON: {e}"))?;
    let props = &v["runs"][0]["properties"];
    let (tool, digest) = (s(props, &["tool"]), s(props, &["digest"]));
    let functions: BTreeMap<String, Vec<String>> = serde_json::from_value(
        v["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["functions"].clone(),
    )
    .map_err(|e| format!("no query: {e}"))?;
    let (id, package, version) = (
        s(props, &["advisory"]),
        s(props, &["package"]),
        s(props, &["version"]),
    );
    let row = head
        .iter()
        .find(|l| l.name == tool && l.sha == digest)
        .ok_or_else(|| format!("states {tool} {digest}, which TOOLS.lock does not pin"))?;
    // The query is the advisory's as the gate's own scan states it, not the record's word.
    let now =
        crate::reach::affected_functions(&scan(tool)?, id, package, version).map_err(|e| {
            format!("{e}: a record can only be checked for an instance the scan reports")
        })?;
    if now != functions {
        return Err(format!(
            "states a query other than the advisory's affected functions in the scan ({})",
            now.keys().cloned().collect::<Vec<_>>().join(", ")
        ));
    }
    let dir = crate::evidence_rev::current(evidence_dir, locks_dir, tool, digest)?
        .dir
        .join("reach");
    let name = crate::reach::record_name(id, package, version, &functions)?;
    if evidence_dir.join(rel) != dir.join(&name) {
        return Err(format!(
            "its instance and query name it {}/{name}",
            dir.strip_prefix(evidence_dir).unwrap_or(&dir).display()
        ));
    }
    let i = crate::reach::Inputs {
        tool: tool.into(),
        digest: digest.into(),
        repo: row.repo.clone(),
        rev: row.rev.clone(),
        lock: std::fs::read_to_string(locks_dir.join(format!("{tool}.lock")))
            .map_err(|e| format!("frozen lock: {e}"))?,
        patches: crate::reach::patches_for(tool)?,
        id: id.into(),
        package: package.into(),
        version: version.into(),
        functions,
    };
    let (_, text) = crate::reach::generate(&i)?;
    if text.as_bytes() != bytes.as_slice() {
        return Err("does not reproduce from the checkout".into());
    }
    Ok(format!(
        "{id} {package} {version}: reproduces from the checkout (sha256 {})",
        crate::sha256::sha256_hex(&bytes)
    ))
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
    let changed_acks = changed_ack_files(&head, &evidence_dir, &base_evidence_dir);
    let (reach_added, reach_refused) = reach_changes(&evidence_dir, &base_evidence_dir);
    let historical = non_frontier_changes(&head, &evidence_dir, &base_evidence_dir);

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
            let mut judge = gate_record_judge(h, &evidence_dir, &locks_dir);
            Ok(vuln_verdict(
                &h.name,
                &h.sha,
                &added,
                &carried,
                fixed.len(),
                &acks,
                &mut |a, i| judge(a, i, &head_json),
            ))
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
        axes.push(("mal", mal_verdict(&h.name, &evidence_dir, h, &acks, floors)));
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
                axes.push(("mal", mal_verdict(&h.name, &evidence_dir, h, &acks, floors)));
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
        // A statement edit changes what covers the pinned binaries (#519): every pinned row of a
        // tool whose acks.jsonl changed is judged again with the edited statements, except a row
        // the candidate path above already judged with them (same name, target and digest). An
        // evidence-edit row is judged here: that path does not re-scan.
        for tool in &changed_acks {
            let reported = ev_cands.iter().any(|(h, _)| &h.name == tool)
                || cands.iter().any(|(_, h)| &h.name == tool);
            let acks = match load_acks(&evidence_dir.join(tool).join("acks.jsonl")) {
                Ok(a) => a,
                Err(e) => {
                    if !reported {
                        reports.push(CandidateReport {
                            name: format!("{tool} (acks edit)"),
                            tool: tool.clone(),
                            summary: String::new(),
                            axes: vec![("acks", Verdict::Unevaluated(e))],
                        });
                    }
                    continue;
                }
            };
            if !acks.rejected.is_empty() {
                if !reported {
                    reports.push(CandidateReport {
                        name: format!("{tool} (acks edit)"),
                        tool: tool.clone(),
                        summary: String::new(),
                        axes: vec![(
                            "ack-quality",
                            Verdict::Unevaluated(format!(
                                "{} ack line(s) failed the quality bar:\n    {}",
                                acks.rejected.len(),
                                acks.rejected.join("\n    ")
                            )),
                        )],
                    });
                }
                continue;
            }
            for row in rows_to_rejudge(tool, &head, &cands) {
                // The baseline only splits added from carried (signed RAISE vs ALLOW, both
                // passing); coverage is required for every instance either way.
                let baseline = crate::monitor::load_baseline(&evidence_dir, &row.name, &row.sha)
                    .map(|(set, _db)| set);
                let mut scan = |r: &ToolLine| -> Result<Value, String> {
                    let dest = std::env::temp_dir()
                        .join(format!("gate-{}-{}-acks.lock", r.name, r.target));
                    let (lock, _src) =
                        resolve_lock(&r.name, &r.repo, &r.rev, Some(&locks_dir), &dest)?;
                    let json = run_audit(&lock, !first_scan)?;
                    first_scan = false;
                    if db_stamp.is_empty() {
                        db_stamp = format!(
                            "advisory-db {} ({})",
                            s(&json, &["database", "last-commit"]),
                            s(&json, &["database", "last-updated"]),
                        );
                    }
                    Ok(json)
                };
                let mut judge = gate_record_judge(row, &evidence_dir, &locks_dir);
                let vuln =
                    judge_pinned_row(row, &acks, baseline.as_ref(), &mut scan, floors, &mut judge);
                let mut axes = Vec::new();
                if !reported {
                    axes.push((
                        "ack-quality",
                        Verdict::Allow(format!(
                            "{} ack line(s) pass the quality bar",
                            acks.entries.len()
                        )),
                    ));
                }
                axes.push(("vuln", vuln));
                reports.push(CandidateReport {
                    name: format!("{tool} [{}] (acks edit)", row.target),
                    tool: tool.clone(),
                    summary: format!(
                        "statement edit: pinned digest {} judged with the edited statements{}",
                        &row.sha[..12.min(row.sha.len())],
                        if baseline.is_some() {
                            ""
                        } else {
                            " (no recorded baseline: every instance added)"
                        }
                    ),
                    axes,
                });
            }
        }
    }

    // ---------- reachability records (#520): add-only, and each added one reproduces ----------
    if !reach_refused.is_empty() {
        reports.push(CandidateReport {
            name: "reachability records".into(),
            tool: String::new(),
            summary: String::new(),
            axes: vec![(
                "reach",
                Verdict::HardStop(format!(
                    "records are add-only (#520):\n    {}",
                    reach_refused.join("\n    ")
                )),
            )],
        });
    }
    let mut tool_scans: BTreeMap<String, Value> = BTreeMap::new();
    for rel in &reach_added {
        let mut scan = |tool: &str| -> Result<Value, String> {
            if let Some(v) = tool_scans.get(tool) {
                return Ok(v.clone());
            }
            let json = run_audit(&locks_dir.join(format!("{tool}.lock")), !first_scan)?;
            first_scan = false;
            if db_stamp.is_empty() {
                db_stamp = format!(
                    "advisory-db {} ({})",
                    s(&json, &["database", "last-commit"]),
                    s(&json, &["database", "last-updated"]),
                );
            }
            tool_scans.insert(tool.to_string(), json.clone());
            Ok(json)
        };
        let verdict = match verify_added_record(rel, &evidence_dir, &locks_dir, &head, &mut scan) {
            Ok(m) => Verdict::Allow(m),
            Err(e) => Verdict::Unevaluated(format!("{}: {e}", rel.display())),
        };
        reports.push(CandidateReport {
            name: format!(
                "reach/{}",
                rel.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()
            ),
            tool: rel
                .iter()
                .next()
                .map(|c| c.to_string_lossy().into_owned())
                .unwrap_or_default(),
            summary: format!("record added: {}", rel.display()),
            axes: vec![("reach", verdict)],
        });
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
    if cands.is_empty()
        && ev_cands.is_empty()
        && changed_acks.is_empty()
        && reach_added.is_empty()
        && reach_refused.is_empty()
    {
        md.push_str(
            "No TOOLS.lock candidates, no frontier evidence changes, no ack changes in this change.\n",
        );
    } else if cands.is_empty() {
        md.push_str("No TOOLS.lock candidates; evidence/ack edits on the live frontier evaluated below (#380).\n");
        if !db_stamp.is_empty() {
            let _ = writeln!(md, "*vuln instrument: {db_stamp}*\n");
        }
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
                Verdict::RaiseUncovered {
                    covered,
                    needed,
                    notes,
                } => {
                    for i in covered {
                        let _ = writeln!(md, "  - signed: {i}");
                    }
                    for n in notes {
                        let _ = writeln!(md, "  - {n}");
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
    /// The binary the vuln tests' statements are about.
    const D: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    /// The base fixture's CycloneDX ruling and action: an `affected` decision.
    const RULING: &str = r#"{"state":"exploitable","response":["update"]}"#;
    const ACTION: &str = r#","action_statement":"act""#;
    fn good_vuln_ack(id: &str, pkg: &str, ver: &str) -> String {
        format!(
            r#"{{"schema":"hp-thermal/evidence-ack/v1","axis":"vuln","vulnerability":{{"name":"{id}"}},"product":{{"name":"t","digest":"{D}","package":"{pkg}","version":"{ver}"}},"status":"affected"{ACTION},"cyclonedx":{RULING},"status_notes":"reason","author":"a","timestamp":"2026-08-21","refs":[]}}"#
        )
    }
    /// `line` (a `good_vuln_ack`) restated as `not_affected` with OpenVEX justification `j` and
    /// CycloneDX ruling `cdx`.
    fn as_not_affected(line: &str, j: &str, cdx: &str) -> String {
        line.replace(ACTION, "")
            .replace(
                "\"status\":\"affected\"",
                &format!("\"status\":\"not_affected\",\"justification\":\"{j}\""),
            )
            .replace(RULING, cdx)
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
        let v = vuln_verdict(
            "t",
            D,
            &[],
            &[inst("B", "q", "2")],
            3,
            &acks,
            &mut |_, _| Cover::Unknown("no record judge".into()),
        );
        assert!(matches!(v, Verdict::Allow(_)));
    }

    #[test]
    fn vuln_added_acked_is_raise_covered_never_allow() {
        // No exchange rate: fixes never buy an addition; an acked addition is
        // signed-RAISE, not ALLOW.
        let acks = ack(&good_vuln_ack("C", "r", "3"));
        let v = vuln_verdict(
            "t",
            D,
            &[inst("C", "r", "3")],
            &[],
            99,
            &acks,
            &mut |_, _| Cover::Unknown("no record judge".into()),
        );
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
            D,
            &inst("B", "q", "2"),
            "0123456789abcdef0123",
            &GoneMechanism::VersionsNarrowed,
        )
        .replace("\"author\":\"\"", "\"author\":\"a\"")
        .replace("\"timestamp\":\"\"", "\"timestamp\":\"2026-11-10\"");
        let mut acks = ack(&affected);
        acks.entries.push(serde_json::from_str(&observed).unwrap());
        assert!(!ack_covers_vuln(&acks, &inst("B", "q", "2"), D));
        let v = vuln_verdict(
            "t",
            D,
            &[],
            &[inst("B", "q", "2")],
            0,
            &acks,
            &mut |_, _| Cover::Unknown("no record judge".into()),
        );
        assert!(matches!(v, Verdict::RaiseUncovered { .. }));
        acks.entries.push(serde_json::from_str(&affected).unwrap());
        assert!(ack_covers_vuln(&acks, &inst("B", "q", "2"), D));
        // a maintainer-reviewed not_affected (no grounding property) IS coverage
        let reviewed = as_not_affected(
            &affected,
            "component_not_present",
            r#"{"state":"not_affected","justification":"code_not_present"}"#,
        );
        assert!(ack_covers_vuln(&ack(&reviewed), &inst("B", "q", "2"), D));
        // a grounded statement for ANOTHER instance changes nothing
        let other = ack_template_vuln_not_affected_observed(
            "t",
            D,
            &inst("B", "q", "3"),
            "0123456789abcdef0123",
            &GoneMechanism::Withdrawn("2026-01-01".into()),
        );
        let mut acks2 = ack(&affected);
        acks2.entries.push(serde_json::from_str(&other).unwrap());
        assert!(ack_covers_vuln(&acks2, &inst("B", "q", "2"), D));
    }

    #[test]
    fn not_affected_observed_template_is_grounded_and_needs_a_signer() {
        let t = ack_template_vuln_not_affected_observed(
            "t",
            D,
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
            .replace(ACTION, "")
            .replace("\"status\":\"affected\"", "\"status\":\"not_affected\"")
            .replace(RULING, r#"{"state":"not_affected"}"#);
        assert!(ack_quality(&serde_json::from_str(&bare).unwrap()).is_err());
        let justified = as_not_affected(
            &good_vuln_ack("A", "p", "1"),
            "component_not_present",
            r#"{"state":"not_affected","justification":"code_not_present"}"#,
        );
        assert!(ack_quality(&serde_json::from_str(&justified).unwrap()).is_ok());
    }

    #[test]
    fn a_vuln_statement_covers_only_the_binary_it_names() {
        let i = inst("B", "q", "2");
        let other = "e".repeat(64);
        let mut acks = ack(&good_vuln_ack("B", "q", "2"));
        assert!(ack_covers_vuln(&acks, &i, D));
        assert!(
            !ack_covers_vuln(&acks, &i, &other),
            "a new build is judged afresh"
        );
        assert!(!ack_covers_vuln(&acks, &i, ""), "no binary, no coverage");
        // a statement without a digest governs nothing, before or after a bound one
        let legacy = good_vuln_ack("B", "q", "2").replace(&format!("\"digest\":\"{D}\","), "");
        assert!(!ack_covers_vuln(&ack(&legacy), &i, D));
        // a later statement about another binary does not supersede this binary's
        let observed_other = ack_template_vuln_not_affected_observed(
            "t",
            &other,
            &i,
            "0123456789abcdef0123",
            &GoneMechanism::VersionsNarrowed,
        );
        acks.entries
            .push(serde_json::from_str(&observed_other).unwrap());
        assert!(ack_covers_vuln(&acks, &i, D));
        assert!(!ack_covers_vuln(&acks, &i, &other));
        // the template names the binary
        let t: Value = serde_json::from_str(&ack_template_vuln("t", D, &i)).unwrap();
        assert_eq!(t["product"]["digest"], D);
    }

    #[test]
    fn digest_bound_vuln_statements_must_agree_with_their_cyclonedx_ruling() {
        let ok = |j: &str| ack_quality(&serde_json::from_str(j).unwrap()).is_ok();
        let base = good_vuln_ack("A", "p", "1");
        assert!(ok(&base));
        // affected is a decision: it publishes neither a not_affected nor an in_triage ruling
        assert!(!ok(&base.replace(RULING, r#"{"state":"not_affected"}"#)));
        assert!(!ok(&base.replace(RULING, r#"{"state":"in_triage"}"#)));
        assert!(!ok(&base.replace(
            RULING,
            r#"{"state":"in_triage","response":["update"]}"#
        )));
        // not_affected cannot ride an in_triage / exploitable ruling
        let na = |cdx: &str| as_not_affected(&base, "component_not_present", cdx);
        assert!(!ok(&na(r#"{"state":"in_triage"}"#)));
        assert!(!ok(&na(RULING)));
        let ruled = |cj: &str| {
            na(&format!(
                r#"{{"state":"not_affected","justification":"{cj}"}}"#
            ))
        };
        assert!(ok(&ruled("code_not_present")));
        // the two rulings must say the same thing, and the OpenVEX one is from the five
        assert!(
            !ok(&na(r#"{"state":"not_affected"}"#)),
            "no CycloneDX justification"
        );
        assert!(!ok(&ruled("code_not_reachable")));
        let reach = ruled("code_not_reachable").replace(
            "component_not_present",
            "vulnerable_code_not_in_execute_path",
        );
        assert!(ok(&reach));
        assert!(!ok(&reach.replace(
            "vulnerable_code_not_in_execute_path",
            "not_reachable_really"
        )));
        assert!(!ok(&reach.replace(
            ",\"justification\":\"vulnerable_code_not_in_execute_path\"",
            ",\"impact_statement\":\"x\""
        )));
        // a ruling is required, and the status must be one immutable bytes can carry
        assert!(!ok(&base.replace(&format!(",\"cyclonedx\":{RULING}"), "")));
        assert!(!ok(
            &base.replace("\"status\":\"affected\"", "\"status\":\"reviewed\"")
        ));
        // affected carries no not_affected justification
        assert!(!ok(&base.replace(
            "\"status\":\"affected\"",
            "\"status\":\"affected\",\"justification\":\"component_not_present\""
        )));
        // the digest is 64 lowercase hex
        assert!(!ok(&base.replace(D, &D.to_uppercase())));
        assert!(!ok(&base.replace(D, "dd")));
        // a false_positive ruling still names one of the five, and any CycloneDX justification
        // it carries must agree
        let fp = |j: &str, cj: &str| {
            as_not_affected(
                &base,
                j,
                &if cj.is_empty() {
                    "{\"state\":\"false_positive\"}".to_string()
                } else {
                    format!("{{\"state\":\"false_positive\",\"justification\":\"{cj}\"}}")
                },
            )
        };
        assert!(ok(&fp("component_not_present", "")));
        assert!(ok(&fp("component_not_present", "code_not_present")));
        assert!(!ok(&fp("component_not_present", "code_not_reachable")));
        assert!(!ok(&fp("made_up", "")));
        // under_investigation is in_triage, and carries no action statement
        let ui = base
            .replace(ACTION, "")
            .replace(
                "\"status\":\"affected\"",
                "\"status\":\"under_investigation\"",
            )
            .replace(RULING, r#"{"state":"in_triage"}"#);
        assert!(ok(&ui));
        assert!(!ok(&ui.replace("in_triage", "exploitable")));
        assert!(!ok(&ui.replace(
            "\"status\":\"under_investigation\"",
            "\"status\":\"under_investigation\",\"action_statement\":\"act\""
        )));
        // a line without a digest is not re-judged (append-only history): it passes, inert
        let legacy = base
            .replace(&format!("\"digest\":\"{D}\","), "")
            .replace(&format!(",\"cyclonedx\":{RULING}"), "");
        assert!(ok(&legacy));
        // the monitor's observation template passes once signed
        let obs = ack_template_vuln_not_affected_observed(
            "t",
            D,
            &inst("A", "p", "1"),
            "0123456789abcdef0123",
            &GoneMechanism::Withdrawn("2026-02-03".into()),
        )
        .replace("\"author\":\"\"", "\"author\":\"a\"")
        .replace("\"timestamp\":\"\"", "\"timestamp\":\"2026-11-24\"");
        assert!(ok(&obs));
    }

    #[test]
    fn an_open_investigation_covers_nothing() {
        let i = inst("A", "p", "1");
        let ui = good_vuln_ack("A", "p", "1")
            .replace(ACTION, "")
            .replace(
                "\"status\":\"affected\"",
                "\"status\":\"under_investigation\"",
            )
            .replace(RULING, r#"{"state":"in_triage"}"#);
        assert!(ack_quality(&serde_json::from_str(&ui).unwrap()).is_ok());
        let c = coverage(&ack(&ui), &i, D, &mut |_, _| panic!("nothing to judge"));
        assert!(matches!(c, Cover::No(Some(_))), "{c:?}");
        // a decision with an action covers; the verdict raises the open investigation
        let decided = ack(&good_vuln_ack("A", "p", "1"));
        assert_eq!(
            coverage(&decided, &i, D, &mut |_, _| panic!("nothing to judge")),
            Cover::Yes
        );
        let v = vuln_verdict(
            "t",
            D,
            std::slice::from_ref(&i),
            &[],
            0,
            &ack(&ui),
            &mut |_, _| panic!("nothing to judge"),
        );
        assert!(matches!(v, Verdict::RaiseUncovered { .. }), "{v:?}");
    }

    #[test]
    fn an_affected_statement_says_what_is_done_about_it() {
        let ok = |j: &str| ack_quality(&serde_json::from_str(j).unwrap()).is_ok();
        let base = good_vuln_ack("A", "p", "1");
        assert!(ok(&base));
        // OpenVEX: affected MUST carry an action statement; a placeholder is none
        assert!(!ok(&base.replace(",\"action_statement\":\"act\"", "")));
        assert!(!ok(&base.replace("\"act\"", "\" \"")));
        for stub in ["TODO", "todo", "Tbd", "n/a", "None", "fixme later", "..."] {
            assert!(
                !ok(&base.replace("\"act\"", &format!("\"{stub}\""))),
                "{stub}"
            );
        }
        // CycloneDX: an exploitable ruling carries a response, from its own values, each once
        let ruling = |r: &str| base.replace(RULING, r);
        assert!(!ok(&ruling("{\"state\":\"exploitable\"}")));
        assert!(ok(&ruling(
            "{\"state\":\"exploitable\",\"response\":[\"update\"]}"
        )));
        assert!(ok(&ruling(
            "{\"state\":\"exploitable\",\"response\":[\"can_not_fix\",\"workaround_available\"]}"
        )));
        for bad in [
            "[]",
            "[\"upgrade\"]",
            "[\"update\",\"update\"]",
            "\"update\"",
            "[\"update\",1]",
            "null",
        ] {
            assert!(
                !ok(&ruling(&format!(
                    "{{\"state\":\"exploitable\",\"response\":{bad}}}"
                ))),
                "{bad}"
            );
        }
        // any status's response is held to the same values
        let na_ruling = |r: &str| {
            as_not_affected(
                &base,
                "component_not_present",
                &format!(
                    "{{\"state\":\"not_affected\",\"justification\":\"code_not_present\"{r}}}"
                ),
            )
        };
        assert!(ok(&na_ruling("")), "not_affected needs no action statement");
        assert!(ok(&na_ruling(",\"response\":[\"will_not_fix\"]")));
        assert!(!ok(&na_ruling(",\"response\":[\"ignore\"]")));
        assert!(!ok(&na_ruling(",\"response\":null")));
        // only an affected statement carries an action statement (the VDR publishes it)
        let with_action = na_ruling("").replace(
            "\"status\":\"not_affected\"",
            "\"status\":\"not_affected\",\"action_statement\":\"TODO\"",
        );
        assert!(!ok(&with_action));
        assert!(!ok(&with_action.replace("TODO", "a real sentence")));
        // the template the gate and monitor print is refused until a human fills it
        let t = ack_template_vuln("t", D, &inst("A", "p", "1"))
            .replace("\"status_notes\":\"\"", "\"status_notes\":\"reason\"")
            .replace("\"author\":\"\"", "\"author\":\"a\"")
            .replace("\"timestamp\":\"\"", "\"timestamp\":\"2026-11-25\"");
        assert!(!ok(&t), "no action statement or response yet");
        let t = t.replace("\"action_statement\":\"\"", "\"action_statement\":\"act\"");
        assert!(!ok(&t), "no response yet");
        assert!(ok(
            &t.replace("\"response\":[]", "\"response\":[\"update\"]")
        ));
    }

    #[test]
    fn vuln_unacked_carried_blocks() {
        let acks = Acks {
            entries: vec![],
            rejected: vec![],
        };
        let v = vuln_verdict(
            "t",
            D,
            &[],
            &[inst("B", "q", "2")],
            0,
            &acks,
            &mut |_, _| Cover::Unknown("no record judge".into()),
        );
        match v {
            Verdict::RaiseUncovered { needed, .. } => assert_eq!(needed.len(), 1),
            other => panic!("expected uncovered, got {other:?}"),
        }
    }

    #[test]
    fn an_acks_edit_judges_each_pinned_row_with_the_edited_statements() {
        let floors =
            crate::floors::parse(include_str!("../../supply-chain/policy/floors.json")).unwrap();
        let row = ToolLine {
            name: "t".into(),
            repo: "r".into(),
            rev: "a".into(),
            target: "x".into(),
            sha: D.into(),
        };
        let audit = serde_json::json!({"vulnerabilities": {"list": [
            {"advisory": {"id": "B"}, "package": {"name": "q", "version": "2"}},
            {"advisory": {"id": "C"}, "package": {"name": "r", "version": "3"}}
        ]}});
        let mut scan = |_: &ToolLine| -> Result<Value, String> { Ok(audit.clone()) };
        let mut both = ack(&good_vuln_ack("B", "q", "2"));
        both.entries
            .push(serde_json::from_str(&good_vuln_ack("C", "r", "3")).unwrap());
        let baseline: BTreeSet<Instance> = [inst("B", "q", "2"), inst("C", "r", "3")].into();
        let judge = |r: &ToolLine,
                     a: &Acks,
                     b: Option<&BTreeSet<Instance>>,
                     s: &mut dyn FnMut(&ToolLine) -> Result<Value, String>| {
            judge_pinned_row(r, a, b, s, &floors, &mut |_, _, _| {
                Cover::Unknown("no record judge".into())
            })
        };
        // every instance carried and covered in this digest: ALLOW
        assert!(matches!(
            judge(&row, &both, Some(&baseline), &mut scan),
            Verdict::Allow(_)
        ));
        // an instance that appeared since bless, covered: signed RAISE, never ALLOW
        let only_b: BTreeSet<Instance> = [inst("B", "q", "2")].into();
        assert!(matches!(
            judge(&row, &both, Some(&only_b), &mut scan),
            Verdict::RaiseCovered(_)
        ));
        // no recorded baseline: every instance is added
        assert!(matches!(
            judge(&row, &both, None, &mut scan),
            Verdict::RaiseCovered(_)
        ));
        // a statement withdrawn by the edit: uncovered
        let one = ack(&good_vuln_ack("B", "q", "2"));
        assert!(matches!(
            judge(&row, &one, Some(&baseline), &mut scan),
            Verdict::RaiseUncovered { .. }
        ));
        // statements about another binary cover nothing here
        let other = ToolLine {
            sha: "e".repeat(64),
            ..row.clone()
        };
        assert!(matches!(
            judge(&other, &both, Some(&baseline), &mut scan),
            Verdict::RaiseUncovered { .. }
        ));
        // an unblessed row, or a scan that failed, cannot be judged
        let zero = ToolLine {
            sha: ZERO_DIGEST.into(),
            ..row.clone()
        };
        assert!(matches!(
            judge(&zero, &both, Some(&baseline), &mut scan),
            Verdict::Unevaluated(_)
        ));
        let mut broken = |_: &ToolLine| -> Result<Value, String> { Err("no DB".into()) };
        assert!(matches!(
            judge(&row, &both, Some(&baseline), &mut broken),
            Verdict::Unevaluated(_)
        ));
    }

    #[test]
    fn an_added_record_states_a_pinned_digest_and_the_scans_query() {
        let root = std::env::temp_dir().join(format!("gate-reach-added-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let d = "d".repeat(64);
        let rel = PathBuf::from("t")
            .join(&d)
            .join("reach")
            .join("RUSTSEC-2026-0001-0123456789ab.sarif");
        std::fs::create_dir_all(root.join(rel.parent().unwrap())).unwrap();
        let record = |tool: &str, f: &str| {
            serde_json::json!({"runs": [{
                "tool": {"driver": {"rules": [{"id": "RUSTSEC-2026-0001", "properties": {"functions": {f: ["< 2"]}}}]}},
                "properties": {"tool": tool, "digest": d, "advisory": "RUSTSEC-2026-0001", "package": "p", "version": "1.0.0"}
            }]})
            .to_string()
        };
        let head = [ToolLine {
            name: "t".into(),
            repo: "o/r".into(),
            rev: "a".repeat(40),
            target: "x".into(),
            sha: d.clone(),
        }];
        let scan_json = serde_json::json!({"vulnerabilities": {"list": [{
            "advisory": {"id": "RUSTSEC-2026-0001"},
            "package": {"name": "p", "version": "1.0.0"},
            "affected": {"functions": {"p::f": ["< 2"]}}
        }]}});
        let mut scan = |_: &str| -> Result<Value, String> { Ok(scan_json.clone()) };
        let check = |body: &str, scan: &mut dyn FnMut(&str) -> Result<Value, String>| {
            std::fs::write(root.join(&rel), body).unwrap();
            verify_added_record(&rel, &root, &root.join("locks"), &head, scan).unwrap_err()
        };
        assert!(check("not json", &mut scan).contains("not JSON"));
        assert!(check(&record("other", "p::f"), &mut scan).contains("does not pin"));
        let e = check(&record("t", "p::g"), &mut scan);
        assert!(e.contains("query other than"), "{e}");
        let mut silent = |_: &str| -> Result<Value, String> { Ok(serde_json::json!({})) };
        let e = check(&record("t", "p::f"), &mut silent);
        assert!(e.contains("an instance the scan reports"), "{e}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn records_are_add_only_and_only_records_live_in_reach() {
        let root = std::env::temp_dir().join(format!("gate-reach-ledger-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (base, head) = (root.join("base"), root.join("head"));
        let d = "d".repeat(64);
        let l = "1".repeat(64);
        let rec = |r: &Path, sub: &str, name: &str, body: &str| {
            let dir = r.join("t").join(&d).join(sub).join("reach");
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(name), body).unwrap();
        };
        let a = "RUSTSEC-2026-0001-0123456789ab.sarif";
        let b = "RUSTSEC-2026-0002-0123456789ab.sarif";
        for r in [&base, &head] {
            rec(r, "", a, "{}\n");
        }
        // unchanged: nothing to report
        assert_eq!(reach_changes(&head, &base), (Vec::new(), Vec::new()));
        // an addition at the digest and under a revision
        rec(&head, "", b, "{}\n");
        rec(&head, &format!("rev/{l}"), a, "{}\n");
        let (added, refused) = reach_changes(&head, &base);
        assert!(refused.is_empty(), "{refused:?}");
        assert_eq!(added.len(), 2);
        // an edit, and a file that is not a record
        rec(&head, "", a, "{\"edited\": 1}\n");
        rec(&head, "", "notes.txt", "x");
        let (_, refused) = reach_changes(&head, &base);
        assert_eq!(refused.len(), 2, "{refused:?}");
        // a deletion
        std::fs::remove_file(head.join("t").join(&d).join("reach").join(a)).unwrap();
        let (_, refused) = reach_changes(&head, &base);
        assert!(refused.iter().any(|r| r.contains("deleted")), "{refused:?}");
        // pruning the digest's whole evidence directory takes its records with it
        std::fs::remove_dir_all(head.join("t").join(&d)).unwrap();
        let (added, refused) = reach_changes(&head, &base);
        assert!(
            refused.is_empty() && added.is_empty(),
            "{refused:?} {added:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
        // names
        assert!(is_record_name(a));
        for bad in [
            "RUSTSEC-2026-0001-0123456789AB.sarif",
            "RUSTSEC-2026-0001-0123456789a.sarif",
            "yanked-0123456789ab.sarif",
            "RUSTSEC-2026-0001-0123456789ab.json",
        ] {
            assert!(!is_record_name(bad), "{bad}");
        }
    }

    #[test]
    fn an_acks_edit_rejudges_every_pinned_row_the_candidate_path_did_not() {
        let tl = |name: &str, target: &str, sha: &str| ToolLine {
            name: name.into(),
            repo: "r".into(),
            rev: "a".into(),
            target: target.into(),
            sha: sha.into(),
        };
        let (win, lin) = ("1".repeat(64), "2".repeat(64));
        let head = vec![
            tl("t", "windows", &win),
            tl("t", "linux", &lin),
            tl("u", "windows", &"3".repeat(64)),
        ];
        let picked = |c: &[(Option<ToolLine>, ToolLine)]| -> Vec<String> {
            rows_to_rejudge("t", &head, c)
                .iter()
                .map(|r| r.target.clone())
                .collect()
        };
        // no candidate (acks-only, or evidence-only edit): every pinned row of the tool
        assert_eq!(picked(&[]), ["windows", "linux"]);
        // one target is a candidate: the other target is still judged, the candidate is not
        // judged twice
        assert_eq!(picked(&[(None, tl("t", "windows", &win))]), ["linux"]);
        // a candidate with another digest on the same target does not shield the pinned row
        assert_eq!(
            picked(&[(None, tl("t", "windows", &"9".repeat(64)))]),
            ["windows", "linux"]
        );
        // another tool's candidate changes nothing
        assert_eq!(
            picked(&[(None, tl("u", "windows", &"3".repeat(64)))]),
            ["windows", "linux"]
        );
    }

    #[test]
    fn a_claim_about_the_code_is_covered_only_by_a_record_that_reproduces() {
        let i = Instance {
            id: "RUSTSEC-2026-0592".into(),
            package: "url".into(),
            version: "2.5.8".into(),
            kind: "vulnerability".into(),
        };
        let scan = serde_json::json!({"vulnerabilities": {"list": [{
            "advisory": {"id": "RUSTSEC-2026-0592"},
            "package": {"name": "url", "version": "2.5.8"},
            "affected": {"functions": {"url::Url::origin": ["<=2.5.8"]}}
        }]}});
        let functions =
            crate::reach::affected_functions(&scan, &i.id, &i.package, &i.version).unwrap();
        let name = crate::reach::record_name(&i.id, &i.package, &i.version, &functions).unwrap();
        let dir = std::env::temp_dir().join(format!("gate-reach-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("reach")).unwrap();
        let record = "{\"record\": 1}\n";
        let sha = crate::sha256::sha256_hex(record.as_bytes());
        let ack = |e: &str| -> Value {
            serde_json::json!({"axis": "vuln", "status": "not_affected",
                "justification": "vulnerable_code_not_in_execute_path", "evidence_sha256": e})
        };
        let same =
            |_: &BTreeMap<String, Vec<String>>| -> Result<String, String> { Ok(record.into()) };
        // not committed yet
        assert!(matches!(
            record_cover(&ack(&sha), &i, &scan, &dir, Some(&mut { same })),
            Cover::No(Some(_))
        ));
        std::fs::write(dir.join("reach").join(&name), record).unwrap();
        assert_eq!(
            record_cover(&ack(&sha), &i, &scan, &dir, Some(&mut { same })),
            Cover::Yes
        );
        // the statement names other bytes
        assert!(matches!(
            record_cover(&ack(&"0".repeat(64)), &i, &scan, &dir, Some(&mut { same })),
            Cover::No(Some(_))
        ));
        // committed and named, but the checkout does not reproduce it: cannot be acked past
        let other =
            |_: &BTreeMap<String, Vec<String>>| -> Result<String, String> { Ok("{}\n".into()) };
        assert!(matches!(
            record_cover(&ack(&sha), &i, &scan, &dir, Some(&mut { other })),
            Cover::Unknown(_)
        ));
        let down =
            |_: &BTreeMap<String, Vec<String>>| -> Result<String, String> { Err("offline".into()) };
        assert!(matches!(
            record_cover(&ack(&sha), &i, &scan, &dir, Some(&mut { down })),
            Cover::Unknown(_)
        ));
        // the advisory's function list changed: another file is expected
        let changed = serde_json::json!({"vulnerabilities": {"list": [{
            "advisory": {"id": "RUSTSEC-2026-0592"},
            "package": {"name": "url", "version": "2.5.8"},
            "affected": {"functions": {"url::Url::origin": ["<=2.5.8"], "url::quirks::origin": ["<=2.5.8"]}}
        }]}});
        assert!(matches!(
            record_cover(&ack(&sha), &i, &changed, &dir, Some(&mut { same })),
            Cover::No(Some(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_verdict_carries_why_a_signed_claim_does_not_cover_and_never_passes_an_unknown() {
        let reach = as_not_affected(
            &good_vuln_ack("B", "q", "2"),
            "vulnerable_code_not_in_execute_path",
            r#"{"state":"not_affected","justification":"code_not_reachable"}"#,
        );
        let acks = ack(&reach);
        assert!(needs_record(&acks.entries[0]));
        let v = vuln_verdict(
            "t",
            D,
            &[],
            &[inst("B", "q", "2")],
            0,
            &acks,
            &mut |_, _| Cover::No(Some("record missing".into())),
        );
        match v {
            Verdict::RaiseUncovered { needed, notes, .. } => {
                assert_eq!(needed.len(), 1);
                assert_eq!(notes, ["record missing"]);
            }
            other => panic!("expected uncovered, got {other:?}"),
        }
        let v = vuln_verdict(
            "t",
            D,
            &[],
            &[inst("B", "q", "2")],
            0,
            &acks,
            &mut |_, _| Cover::Unknown("does not reproduce".into()),
        );
        assert!(matches!(v, Verdict::Unevaluated(_)));
        let v = vuln_verdict(
            "t",
            D,
            &[],
            &[inst("B", "q", "2")],
            0,
            &acks,
            &mut |_, _| Cover::Yes,
        );
        assert!(matches!(v, Verdict::Allow(_)));
        // a claim about the component needs no record, but is still judged (measured), never
        // taken on its word; an accepted risk is not judged
        let absent = reach.replace(
            "vulnerable_code_not_in_execute_path",
            "component_not_present",
        );
        assert!(!needs_record(&serde_json::from_str(&absent).unwrap()));
        let v = vuln_verdict(
            "t",
            D,
            &[],
            &[inst("B", "q", "2")],
            0,
            &ack(&absent),
            &mut |_, _| Cover::No(Some("measured present".into())),
        );
        assert!(matches!(v, Verdict::RaiseUncovered { .. }));
        let mut judged = false;
        let v = vuln_verdict(
            "t",
            D,
            &[],
            &[inst("B", "q", "2")],
            0,
            &ack(&good_vuln_ack("B", "q", "2")),
            &mut |_, _| {
                judged = true;
                Cover::No(None)
            },
        );
        assert!(matches!(v, Verdict::Allow(_)) && !judged);
        // without a build record, presence cannot be measured
        let empty = std::env::temp_dir().join(format!("gate-noabsent-{}", std::process::id()));
        std::fs::create_dir_all(&empty).unwrap();
        assert!(matches!(
            measured_absent("t", D, &empty, &inst("B", "q", "2")),
            Cover::Unknown(_)
        ));
        let _ = std::fs::remove_dir_all(&empty);
        assert!(!needs_record(
            &serde_json::from_str(&good_vuln_ack("B", "q", "2")).unwrap()
        ));
    }

    #[test]
    fn a_vuln_digest_that_is_not_a_digest_fails_the_quality_bar() {
        let base = good_vuln_ack("A", "p", "1");
        for bad in ["null", "\"\"", "7", "[]"] {
            let line = base.replace(&format!("\"{D}\""), bad);
            assert!(
                ack_quality(&serde_json::from_str(&line).unwrap()).is_err(),
                "digest {bad} must fail"
            );
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
        // The workflow enforces a written PASS line, not only the exit status: it is the line a
        // passing run writes, and a blocked run does not.
        let wf = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../.github/workflows/candidate-eval.yml"),
        )
        .unwrap();
        let required = wf
            .lines()
            .find_map(|l| {
                l.split_once("grep -qxF '")
                    .and_then(|(_, r)| r.split_once('\''))
            })
            .map(|(line, _)| line.to_string())
            .expect("candidate-eval enforces a PASS line");
        let has = || {
            std::fs::read_to_string(d.join("report.md"))
                .unwrap()
                .lines()
                .any(|l| l == required)
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
