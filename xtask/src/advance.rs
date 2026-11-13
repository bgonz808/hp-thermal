//! `cargo xtask candidate-advance <stage> --tool <name> [...]` — the bless cycle as stages.
//!
//! A candidate branch (`candidate/<tool>-<ref>`) carries a re-frozen lock; turning it into a
//! bless PR is a fixed sequence that was run by hand until 2026-11-12: read the producer's
//! digest into TOOLS.lock, record the vuln baseline, measure caps, read the VT panel, write
//! the PR text. Every step is deterministic, every step has a precondition the previous one
//! established, and every hand-run of it produced at least one slip (a defaulted seed, a stale
//! PR title, an orphaned raw payload). This module makes the sequence a program.
//!
//! Privilege model: unchanged. The command runs on the maintainer's machine with the
//! maintainer's `gh` session and signing key, exactly as the hand-run steps did. CI gains
//! nothing. It never merges, never touches `main`, and never bypasses the gate — the gate still
//! evaluates the branch this produced.
//!
//! Stages (each refuses to run when its precondition is missing; each commits what it wrote):
//!   status   — what the branch records for the tool's current digest, what is missing.
//!   digest   — `--run <producer run>`: verify the run built THIS branch's lock, read the
//!              digest from its TOOLS.lock-format table, write it into TOOLS.lock. A superseded
//!              never-blessed digest is retired per supply-chain/evidence/README.md rule 2.
//!   vuln     — record-vuln with the digest-pinned auditor, upload the raw payload, verify it.
//!   caps     — dispatch caps-measure (seed = main's blessed inventory unless `--seed`), wait,
//!              verify the header names THIS lock, commit the inventory.
//!   mal      — VT lookup first; submit only if absent; re-read after the panel; record.
//!   summary  — PR title and body generated from the evidence; `--pr N` edits the PR.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::gate::{ToolLine, parse_tools_lock};

const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const TOOLS_LOCK: &str = "tools/TOOLS.lock";
const STORE_TAG: &str = "tools";

// ---------- process helpers ----------

fn run_capture(prog: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(prog)
        .args(args)
        .output()
        .map_err(|e| format!("cannot run {prog}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "{prog} {} failed ({}): {}",
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

pub(crate) fn git(args: &[&str]) -> Result<String, String> {
    run_capture("git", args)
}

pub(crate) fn gh(args: &[&str]) -> Result<String, String> {
    run_capture("gh", args)
}

pub(crate) fn gh_json(args: &[&str]) -> Result<Value, String> {
    let s = gh(args)?;
    serde_json::from_str(&s).map_err(|e| format!("gh {}: unparseable JSON ({e})", args.join(" ")))
}

pub(crate) fn s(v: &Value, path: &[&str]) -> String {
    let mut cur = v;
    for p in path {
        cur = &cur[*p];
    }
    match cur {
        Value::String(x) => x.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

pub(crate) fn is_hex64(x: &str) -> bool {
    x.len() == 64 && x.bytes().all(|b| b.is_ascii_hexdigit())
}

pub(crate) fn short(d: &str) -> &str {
    &d[..d.len().min(12)]
}

// ---------- branch / lock context ----------

struct Ctx {
    tool: String,
    target: String,
    branch: String,
    no_commit: bool,
}

impl Ctx {
    fn evidence_dir(&self, digest: &str) -> PathBuf {
        PathBuf::from("supply-chain/evidence")
            .join(&self.tool)
            .join(digest)
    }
    fn acks_path(&self) -> PathBuf {
        PathBuf::from("supply-chain/evidence")
            .join(&self.tool)
            .join("acks.jsonl")
    }
    fn lock_path(&self) -> PathBuf {
        PathBuf::from("tools/locks").join(format!("{}.lock", self.tool))
    }
    fn entry(&self) -> Result<ToolLine, String> {
        let text = std::fs::read_to_string(TOOLS_LOCK).map_err(|e| format!("{TOOLS_LOCK}: {e}"))?;
        tools_lock_entry(&text, &self.tool, &self.target)
    }
    fn lock_sha(&self) -> Result<String, String> {
        let b = std::fs::read(self.lock_path())
            .map_err(|e| format!("{}: {e}", self.lock_path().display()))?;
        Ok(crate::sha256::sha256_hex(&b))
    }
    fn commit(&self, paths: &[&Path], msg: &str) -> Result<(), String> {
        if self.no_commit {
            println!("  (--no-commit) left staged: {msg}");
            for p in paths {
                git(&["add", "-A", &p.to_string_lossy()])?;
            }
            return Ok(());
        }
        for p in paths {
            git(&["add", "-A", &p.to_string_lossy()])?;
        }
        let staged = git(&["diff", "--cached", "--name-only"])?;
        if staged.trim().is_empty() {
            println!("  nothing to commit (already recorded)");
            return Ok(());
        }
        git(&["commit", "-q", "-S", "-m", msg])?;
        let head = git(&["log", "-1", "--format=%h %G?"])?;
        println!("  committed {} — {msg}", head.trim());
        Ok(())
    }
}

fn current_branch() -> Result<String, String> {
    let b = git(&["rev-parse", "--abbrev-ref", "HEAD"])?
        .trim()
        .to_string();
    if !b.starts_with("candidate/") {
        return Err(format!(
            "candidate-advance runs on a candidate/* branch, not `{b}` — it never writes to main"
        ));
    }
    Ok(b)
}

pub(crate) fn tools_lock_entry(text: &str, tool: &str, target: &str) -> Result<ToolLine, String> {
    let all = parse_tools_lock(text);
    let mine: Vec<&ToolLine> = all.iter().filter(|t| t.name == tool).collect();
    if mine.is_empty() {
        return Err(format!("{TOOLS_LOCK}: no entry for {tool}"));
    }
    mine.iter()
        .find(|t| t.target == target)
        .map(|t| (*t).clone())
        .ok_or_else(|| {
            format!(
                "{TOOLS_LOCK}: {tool} has no {target} entry (targets: {})",
                mine.iter()
                    .map(|t| t.target.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
}

/// Rewrite one tool's digest and trailing comment in TOOLS.lock, re-aligning the data rows to
/// the two-space column layout the file documents. Comment and blank lines are untouched.
pub(crate) fn rewrite_tools_lock(
    text: &str,
    tool: &str,
    target: &str,
    new_sha: &str,
    new_comment: &str,
) -> Result<String, String> {
    struct Row {
        fields: Vec<String>,
        comment: String,
    }
    let mut rows: Vec<Option<Row>> = Vec::new();
    let mut hit = 0usize;
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            rows.push(None);
            continue;
        }
        let (data, comment) = match line.find('#') {
            Some(i) => (&line[..i], line[i..].trim_end().to_string()),
            None => (line, String::new()),
        };
        let mut fields: Vec<String> = data.split_whitespace().map(str::to_string).collect();
        if fields.len() != 5 {
            return Err(format!("{TOOLS_LOCK}: malformed row `{line}`"));
        }
        let mut comment = comment;
        if fields[0] == tool && fields[3] == target {
            fields[4] = new_sha.to_string();
            comment = format!("# {new_comment}");
            hit += 1;
        }
        rows.push(Some(Row { fields, comment }));
    }
    if hit != 1 {
        return Err(format!(
            "{TOOLS_LOCK}: expected exactly one {tool} {target} row, found {hit}"
        ));
    }
    let mut widths = [0usize; 4];
    for r in rows.iter().flatten() {
        for (i, w) in widths.iter_mut().enumerate() {
            *w = (*w).max(r.fields[i].len());
        }
    }
    let mut out = String::new();
    let lines: Vec<&str> = text.lines().collect();
    for (i, r) in rows.iter().enumerate() {
        match r {
            None => out.push_str(lines[i]),
            Some(r) => {
                for (j, w) in widths.iter().enumerate() {
                    out.push_str(&format!("{:<w$}  ", r.fields[j], w = *w));
                }
                out.push_str(&r.fields[4]);
                if !r.comment.is_empty() {
                    out.push_str("  ");
                    out.push_str(&r.comment);
                }
            }
        }
        out.push('\n');
    }
    Ok(out)
}

// ---------- run logs ----------

/// `gh run view --log` lines are `job\tstep\t<timestamp> <message>` with the step's ANSI
/// colouring embedded; return just the message.
pub(crate) fn log_message(line: &str) -> String {
    let msg = line.rsplit('\t').next().unwrap_or(line);
    let msg = strip_ansi(msg);
    let msg = msg.trim_start_matches('\u{feff}');
    match msg.split_once(' ') {
        Some((ts, rest)) if ts.len() >= 20 && ts.ends_with('Z') && ts.contains('T') => {
            rest.to_string()
        }
        _ => msg.to_string(),
    }
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for d in chars.by_ref() {
                if d.is_ascii_alphabetic() {
                    break;
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

/// The producer prints each tool's TOOLS.lock-format row (`name repo rev target sha256`). The
/// digest for (tool, target) must agree with the branch's repo and rev — a row for another rev
/// is another build — and must be unique.
pub(crate) fn producer_digest(log: &str, entry: &ToolLine) -> Result<String, String> {
    let mut found: Vec<String> = Vec::new();
    for line in log.lines() {
        let m = log_message(line);
        let f: Vec<&str> = m.split_whitespace().collect();
        if f.len() >= 5 && f[0] == entry.name && f[3] == entry.target && is_hex64(f[4]) {
            if f[1] != entry.repo || f[2] != entry.rev {
                return Err(format!(
                    "producer row is for {} @ {}, the branch pins {} @ {} — wrong run or stale branch",
                    f[1], f[2], entry.repo, entry.rev
                ));
            }
            if !found.iter().any(|x| x == f[4]) {
                found.push(f[4].to_string());
            }
        }
    }
    match found.as_slice() {
        [one] => Ok(one.clone()),
        [] => Err(format!(
            "no TOOLS.lock-format row for {} {} in the run log",
            entry.name, entry.target
        )),
        many => Err(format!(
            "conflicting digests in the run log: {}",
            many.join(", ")
        )),
    }
}

/// The monitor prints `record (mal.jsonl line for <evidence dir>/): {json}` for each frontier
/// digest it read, and `... not in VT corpus ...` for one VT has never seen.
pub(crate) fn mal_record_line(log: &str, tool: &str, digest: &str) -> Option<Value> {
    let key = format!("record (mal.jsonl line for supply-chain/evidence/{tool}/{digest}/): ");
    log.lines()
        .map(log_message)
        .filter_map(|m| m.find(&key).map(|i| m[i + key.len()..].trim().to_string()))
        .filter_map(|j| serde_json::from_str::<Value>(&j).ok())
        .find(|v| s(v, &["subject", "sha256"]) == digest)
}

pub(crate) fn mal_absent(log: &str, digest: &str) -> bool {
    log.lines()
        .map(log_message)
        .any(|m| m.contains(digest) && m.contains("not in VT corpus"))
}

// ---------- GitHub Actions ----------

pub(crate) fn wait_run(id: &str, timeout: Duration) -> Result<String, String> {
    let start = Instant::now();
    loop {
        let v = gh_json(&["run", "view", id, "--json", "status,conclusion"])?;
        if s(&v, &["status"]) == "completed" {
            return Ok(s(&v, &["conclusion"]));
        }
        if start.elapsed() > timeout {
            return Err(format!(
                "run {id} still {} after {:?}",
                s(&v, &["status"]),
                timeout
            ));
        }
        std::thread::sleep(Duration::from_secs(30));
    }
}

/// Dispatch a workflow on the branch and return the id of the run it created: the newest run of
/// that workflow on the branch created at or after the dispatch instant. A run that predates the
/// dispatch is someone else's and is never adopted.
pub(crate) fn dispatch(
    workflow: &str,
    branch: &str,
    inputs: &[(&str, &str)],
) -> Result<String, String> {
    let before = gh_json(&[
        "run",
        "list",
        "--workflow",
        workflow,
        "--branch",
        branch,
        "--limit",
        "1",
        "--json",
        "databaseId",
    ])?;
    let prev = before[0]["databaseId"].as_u64();
    let mut args: Vec<String> = vec![
        "workflow".into(),
        "run".into(),
        workflow.into(),
        "--ref".into(),
        branch.into(),
    ];
    for (k, v) in inputs {
        args.push("-f".into());
        args.push(format!("{k}={v}"));
    }
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    gh(&argv)?;
    let start = Instant::now();
    loop {
        std::thread::sleep(Duration::from_secs(15));
        let v = gh_json(&[
            "run",
            "list",
            "--workflow",
            workflow,
            "--branch",
            branch,
            "--limit",
            "1",
            "--json",
            "databaseId,status",
        ])?;
        if let Some(id) = v[0]["databaseId"].as_u64()
            && Some(id) != prev
        {
            return Ok(id.to_string());
        }
        if start.elapsed() > Duration::from_secs(180) {
            return Err(format!(
                "{workflow}: dispatched on {branch} but no new run appeared in 3 minutes"
            ));
        }
    }
}

pub(crate) fn run_log(id: &str) -> Result<String, String> {
    gh(&["run", "view", id, "--log"])
}

pub(crate) fn download_artifact(id: &str, name: &str) -> Result<PathBuf, String> {
    let dir = std::env::temp_dir().join(format!("candidate-advance-{name}-{id}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    gh(&[
        "run",
        "download",
        id,
        "-n",
        name,
        "-D",
        &dir.to_string_lossy(),
    ])?;
    Ok(dir)
}

pub(crate) fn find_file(dir: &Path, name: &str) -> Option<PathBuf> {
    let rd = std::fs::read_dir(dir).ok()?;
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            if let Some(f) = find_file(&p, name) {
                return Some(f);
            }
        } else if p.file_name().is_some_and(|n| n == name) {
            return Some(p);
        }
    }
    None
}

// ---------- evidence helpers ----------

pub(crate) fn read_jsonl(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .map(|t| {
            t.lines()
                .filter(|l| !l.trim().is_empty())
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect()
        })
        .unwrap_or_default()
}

/// Ack lines not bound to `digest` (any axis). Lines that do not parse are kept verbatim —
/// this never silently drops a statement it cannot read.
pub(crate) fn acks_without_digest(text: &str, digest: &str) -> (String, usize) {
    let mut kept = String::new();
    let mut dropped = 0usize;
    for l in text.lines() {
        if l.trim().is_empty() {
            continue;
        }
        let bound = serde_json::from_str::<Value>(l)
            .map(|v| s(&v, &["product", "digest"]) == digest)
            .unwrap_or(false);
        if bound {
            dropped += 1;
        } else {
            kept.push_str(l);
            kept.push('\n');
        }
    }
    (kept, dropped)
}

fn caps_header(caps: &str, key: &str) -> Option<String> {
    let prefix = format!("# {key}: ");
    caps.lines()
        .find(|l| l.starts_with(&prefix))
        .map(|l| l[prefix.len()..].to_string())
}

pub(crate) fn caps_sections(caps: &str) -> Vec<String> {
    caps.lines()
        .filter(|l| l.starts_with("[pkg."))
        .map(|l| {
            l.trim_matches(|c| c == '[' || c == ']')
                .trim_start_matches("pkg.")
                .to_string()
        })
        .collect()
}

fn blessed_on_main(ctx: &Ctx, digest: &str) -> Result<bool, String> {
    git(&["fetch", "--quiet", "origin", "main"])?;
    let spec = format!("origin/main:supply-chain/evidence/{}/{digest}", ctx.tool);
    Ok(Command::new("git")
        .args(["cat-file", "-e", &spec])
        .status()
        .map(|st| st.success())
        .unwrap_or(false))
}

fn main_entry(ctx: &Ctx) -> Result<Option<ToolLine>, String> {
    git(&["fetch", "--quiet", "origin", "main"])?;
    let text = git(&["show", &format!("origin/main:{TOOLS_LOCK}")])?;
    Ok(tools_lock_entry(&text, &ctx.tool, &ctx.target).ok())
}

// ---------- stages ----------

fn stage_status(ctx: &Ctx) -> Result<(), String> {
    let e = ctx.entry()?;
    println!("{} [{}] on {}", ctx.tool, ctx.target, ctx.branch);
    println!("  rev     {}", e.rev);
    if e.sha == ZERO {
        println!("  digest  ZERO — run `digest --run <producer run id>` first");
        return Ok(());
    }
    println!("  digest  {}", e.sha);
    let dir = ctx.evidence_dir(&e.sha);
    let lock_sha = ctx.lock_sha()?;
    for f in ["vuln.jsonl", "caps.toml", "mal.jsonl"] {
        let p = dir.join(f);
        if !p.exists() {
            println!("  {f:<10} MISSING");
            continue;
        }
        match f {
            "vuln.jsonl" => {
                let rows = read_jsonl(&p);
                println!(
                    "  {f:<10} {} instance(s); {}",
                    rows.len().saturating_sub(1),
                    rows.first()
                        .map(|h| s(h, &["lockProvenance"]))
                        .unwrap_or_default()
                );
            }
            "caps.toml" => {
                let t = std::fs::read_to_string(&p).unwrap_or_default();
                let subj = caps_header(&t, "subject").unwrap_or_default();
                let ok = subj.contains(&lock_sha);
                println!(
                    "  {f:<10} {} sections; header lock {}",
                    caps_sections(&t).len(),
                    if ok {
                        "matches the branch lock"
                    } else {
                        "DOES NOT MATCH the branch lock — re-measure"
                    }
                );
                if let Some(seed) = caps_header(&t, "seed") {
                    println!("             seed {seed}");
                }
            }
            _ => {
                let rows = read_jsonl(&p);
                if let Some(last) = rows.last() {
                    println!(
                        "  {f:<10} {} record(s); last: {}/{} on {}, sandbox {}",
                        rows.len(),
                        s(last, &["detections", "malicious"]),
                        s(last, &["detections", "total"]),
                        s(last, &["panelDate"]),
                        s(last, &["sandbox", "state"])
                    );
                }
            }
        }
    }
    let acks = read_jsonl(&ctx.acks_path());
    let bound = acks
        .iter()
        .filter(|a| s(a, &["product", "digest"]) == e.sha)
        .count();
    println!("  acks       {bound} bound to this digest");
    Ok(())
}

fn stage_digest(ctx: &Ctx, run_id: &str) -> Result<(), String> {
    let e = ctx.entry()?;
    let v = gh_json(&[
        "run",
        "view",
        run_id,
        "--json",
        "conclusion,headBranch,headSha,workflowName,url",
    ])?;
    if s(&v, &["conclusion"]) != "success" {
        return Err(format!(
            "run {run_id} concluded `{}`, not success",
            s(&v, &["conclusion"])
        ));
    }
    if s(&v, &["headBranch"]) != ctx.branch {
        return Err(format!(
            "run {run_id} built branch `{}`, this is `{}`",
            s(&v, &["headBranch"]),
            ctx.branch
        ));
    }
    let head_sha = s(&v, &["headSha"]);
    if Command::new("git")
        .args(["cat-file", "-e", &head_sha])
        .status()
        .map(|x| !x.success())
        .unwrap_or(true)
    {
        git(&["fetch", "--quiet", "origin", &head_sha])?;
    }
    let lock = ctx.lock_path().to_string_lossy().into_owned();
    let same_lock = Command::new("git")
        .args(["diff", "--quiet", &head_sha, "HEAD", "--", &lock])
        .status()
        .map(|x| x.success())
        .unwrap_or(false);
    if !same_lock {
        return Err(format!(
            "{lock} differs between the run's commit {} and HEAD — the digest would not be this lock's",
            short(&head_sha)
        ));
    }
    println!(
        "  run {run_id} ({}) built {} at {}",
        s(&v, &["workflowName"]),
        ctx.branch,
        short(&head_sha)
    );
    let log = run_log(run_id)?;
    let new = producer_digest(&log, &e)?;
    println!("  producer digest {new}");
    if new == e.sha {
        println!("  TOOLS.lock already records it");
    } else {
        if e.sha != ZERO {
            retire_superseded(ctx, &e.sha)?;
        }
        let text = std::fs::read_to_string(TOOLS_LOCK).map_err(|e| e.to_string())?;
        let comment = format!(
            "{}, producer run {run_id}",
            ctx.branch.trim_start_matches("candidate/")
        );
        let out = rewrite_tools_lock(&text, &ctx.tool, &ctx.target, &new, &comment)?;
        std::fs::write(TOOLS_LOCK, out).map_err(|e| e.to_string())?;
    }
    ctx.commit(
        &[
            Path::new(TOOLS_LOCK),
            &PathBuf::from("supply-chain/evidence").join(&ctx.tool),
        ],
        &format!(
            "candidate: {} digest {} (producer run {run_id})",
            ctx.tool,
            short(&new)
        ),
    )
}

/// supply-chain/evidence/README.md rule 2: a digest ever pinned on main keeps its evidence;
/// a never-blessed candidate digest is retired with the candidate — evidence directory, stored
/// raw payload, and any ack bound to it.
fn retire_superseded(ctx: &Ctx, old: &str) -> Result<(), String> {
    if blessed_on_main(ctx, old)? {
        println!(
            "  prior digest {} is blessed on main — evidence kept (immutable)",
            short(old)
        );
        return Ok(());
    }
    let dir = ctx.evidence_dir(old);
    if !dir.exists() {
        println!(
            "  prior digest {} has no evidence on this branch",
            short(old)
        );
        return Ok(());
    }
    let header = read_jsonl(&dir.join("vuln.jsonl")).into_iter().next();
    if let Some(h) = header {
        let asset = s(&h, &["rawPayload", "asset"]);
        let store = s(&h, &["rawPayload", "store"]);
        if store == "tools release" && !asset.is_empty() {
            match gh(&["release", "delete-asset", STORE_TAG, &asset, "-y"]) {
                Ok(_) => println!("  retired raw payload {asset} from the {STORE_TAG} release"),
                Err(e) => println!("  raw payload {asset}: {e} (already gone?)"),
            }
        }
    }
    git(&["rm", "-r", "-q", &dir.to_string_lossy()])?;
    println!("  retired evidence {}", dir.display());
    let acks = ctx.acks_path();
    if let Ok(text) = std::fs::read_to_string(&acks) {
        let (kept, dropped) = acks_without_digest(&text, old);
        if dropped > 0 {
            std::fs::write(&acks, kept).map_err(|e| e.to_string())?;
            println!("  retired {dropped} ack(s) bound to {}", short(old));
        }
    }
    Ok(())
}

fn stage_vuln(ctx: &Ctx, auditor: &Path, provenance: &str) -> Result<(), String> {
    let e = ctx.entry()?;
    if e.sha == ZERO {
        return Err("digest is ZERO — run the digest stage first".into());
    }
    let raw_dir = std::env::temp_dir().join(format!("candidate-advance-raw-{}", ctx.tool));
    let _ = std::fs::remove_dir_all(&raw_dir);
    let args: Vec<String> = [
        "record-vuln",
        "--tool",
        &ctx.tool,
        "--digest",
        &e.sha,
        "--auditor",
        &auditor.to_string_lossy(),
        "--lock",
        &ctx.lock_path().to_string_lossy(),
        "--out-raw",
        &raw_dir.to_string_lossy(),
        "--lock-provenance",
        provenance,
    ]
    .iter()
    .map(|x| x.to_string())
    .collect();
    if crate::record_vuln::run(&args) != 0 {
        return Err("record-vuln failed".into());
    }
    let header = read_jsonl(&ctx.evidence_dir(&e.sha).join("vuln.jsonl"))
        .into_iter()
        .next()
        .ok_or("vuln.jsonl has no header")?;
    let asset = s(&header, &["rawPayload", "asset"]);
    let want = s(&header, &["rawPayload", "sha256"]);
    let file = raw_dir.join(&asset);
    gh(&[
        "release",
        "upload",
        STORE_TAG,
        &file.to_string_lossy(),
        "--clobber",
    ])?;
    let store = crate::monitor::store_digests(STORE_TAG)?;
    match store.get(&asset) {
        Some(got) if *got == want => println!(
            "  raw payload {asset} stored and verified ({})",
            short(&want)
        ),
        Some(got) => return Err(format!("stored {asset} has sha {got}, header says {want}")),
        None => {
            return Err(format!(
                "{asset} not visible in the {STORE_TAG} release after upload"
            ));
        }
    }
    ctx.commit(
        &[&ctx.evidence_dir(&e.sha)],
        &format!(
            "candidate: {} {} vuln baseline (record-vuln, measured)",
            ctx.tool,
            short(&e.sha)
        ),
    )
}

fn stage_caps(
    ctx: &Ctx,
    seed: Option<&str>,
    existing_run: Option<&str>,
    wait: Duration,
) -> Result<(), String> {
    let e = ctx.entry()?;
    if e.sha == ZERO {
        return Err("digest is ZERO — run the digest stage first".into());
    }
    let id = match existing_run {
        Some(id) => id.to_string(),
        None => {
            let mut inputs = vec![("tool", ctx.tool.as_str())];
            if let Some(sd) = seed {
                inputs.push(("seed_digest", sd));
            }
            let id = dispatch("caps-measure.yml", &ctx.branch, &inputs)?;
            println!(
                "  caps-measure run {id} dispatched (seed: {})",
                seed.unwrap_or("main's blessed inventory")
            );
            id
        }
    };
    let c = wait_run(&id, wait)?;
    if c != "success" {
        return Err(format!("caps-measure run {id} concluded `{c}`"));
    }
    let dir = download_artifact(&id, &format!("caps-measure-{}", ctx.tool))?;
    let f = find_file(&dir, "caps.toml").ok_or("artifact has no caps.toml")?;
    let text = std::fs::read_to_string(&f).map_err(|e| e.to_string())?;
    let lock_sha = ctx.lock_sha()?;
    let subject = caps_header(&text, "subject").unwrap_or_default();
    if !subject.contains(&lock_sha) {
        return Err(format!(
            "caps.toml header names another lock ({subject}); the branch lock is {lock_sha} — not recorded"
        ));
    }
    let dest = ctx.evidence_dir(&e.sha).join("caps.toml");
    std::fs::create_dir_all(dest.parent().unwrap()).map_err(|e| e.to_string())?;
    std::fs::copy(&f, &dest).map_err(|e| e.to_string())?;
    let seed_line = caps_header(&text, "seed").unwrap_or_default();
    println!(
        "  caps.toml: {} sections; seed {seed_line}",
        caps_sections(&text).len()
    );
    let seed12 = seed_line
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .chars()
        .take(12)
        .collect::<String>();
    ctx.commit(
        &[&ctx.evidence_dir(&e.sha)],
        &format!(
            "candidate: {} {} caps measured (run {id}, seed {seed12})",
            ctx.tool,
            short(&e.sha)
        ),
    )
}

fn stage_mal(
    ctx: &Ctx,
    no_submit: bool,
    panel_wait: Duration,
    wait: Duration,
) -> Result<(), String> {
    let e = ctx.entry()?;
    if e.sha == ZERO {
        return Err("digest is ZERO — run the digest stage first".into());
    }
    // 1. lookup — never upload before asking.
    let m1 = dispatch("supply-chain-monitor.yml", &ctx.branch, &[])?;
    println!("  monitor (lookup) run {m1}");
    let _ = wait_run(&m1, wait)?; // the monitor's exit code is its own contract; the log decides
    let mut log = run_log(&m1)?;
    let mut record = mal_record_line(&log, &ctx.tool, &e.sha);
    let mut source_run = m1.clone();
    if record.is_none() {
        if !mal_absent(&log, &e.sha) {
            return Err(format!(
                "monitor run {m1} neither recorded {} nor reported it absent — read the run before deciding",
                short(&e.sha)
            ));
        }
        if no_submit {
            return Err("digest is not in the VT corpus and --no-submit was given".into());
        }
        // 2. absent -> one submission, lookup-first inside the workflow too.
        let sub = dispatch("vt-submit.yml", &ctx.branch, &[("only", ctx.tool.as_str())])?;
        println!("  vt-submit run {sub}");
        let c = wait_run(&sub, wait)?;
        if c != "success" {
            return Err(format!("vt-submit run {sub} concluded `{c}`"));
        }
        println!("  waiting {:?} for the panel", panel_wait);
        std::thread::sleep(panel_wait);
        // 3. re-read.
        let m2 = dispatch("supply-chain-monitor.yml", &ctx.branch, &[])?;
        println!("  monitor (record) run {m2}");
        let _ = wait_run(&m2, wait)?;
        log = run_log(&m2)?;
        record = mal_record_line(&log, &ctx.tool, &e.sha);
        source_run = m2;
    }
    let rec = record.ok_or_else(|| {
        format!(
            "monitor run {source_run} printed no record line for {} — not recorded",
            short(&e.sha)
        )
    })?;
    if s(&rec, &["schema"]) != "hp-thermal/evidence-mal/v1" {
        return Err(format!("record line has schema `{}`", s(&rec, &["schema"])));
    }
    let path = ctx.evidence_dir(&e.sha).join("mal.jsonl");
    let line = serde_json::to_string(&rec).map_err(|e| e.to_string())?;
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    if existing.lines().any(|l| l == line) {
        println!("  identical record already present");
    } else {
        std::fs::create_dir_all(path.parent().unwrap()).map_err(|e| e.to_string())?;
        let mut out = existing;
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&line);
        out.push('\n');
        std::fs::write(&path, out).map_err(|e| e.to_string())?;
    }
    let (m, t, st) = (
        s(&rec, &["detections", "malicious"]),
        s(&rec, &["detections", "total"]),
        s(&rec, &["sandbox", "state"]),
    );
    println!("  VT {m}/{t}, sandbox {st}");
    ctx.commit(
        &[&ctx.evidence_dir(&e.sha)],
        &format!(
            "candidate: {} {} mal record (VT {m}/{t}, sandbox {st}; monitor run {source_run})",
            ctx.tool,
            short(&e.sha)
        ),
    )
}

fn stage_summary(ctx: &Ctx, pr: Option<&str>) -> Result<(), String> {
    let e = ctx.entry()?;
    if e.sha == ZERO {
        return Err("digest is ZERO — nothing to summarise".into());
    }
    let dir = ctx.evidence_dir(&e.sha);
    let vuln = read_jsonl(&dir.join("vuln.jsonl"));
    let caps = std::fs::read_to_string(dir.join("caps.toml")).unwrap_or_default();
    let mal = read_jsonl(&dir.join("mal.jsonl"));
    let prior = main_entry(ctx)?;
    let header = vuln.first().cloned().unwrap_or(Value::Null);
    let instances: Vec<String> = vuln
        .iter()
        .skip(1)
        .map(|i| {
            format!(
                "{} ({} {})",
                s(i, &["id"]),
                s(i, &["package"]),
                s(i, &["version"])
            )
        })
        .collect();
    let tools_text = std::fs::read_to_string(TOOLS_LOCK).unwrap_or_default();
    let producer = tools_text
        .lines()
        .find(|l| l.split_whitespace().next() == Some(ctx.tool.as_str()) && l.contains(&e.sha))
        .and_then(|l| l.split("producer run ").nth(1))
        .map(|r| {
            r.split(|c: char| !c.is_ascii_digit())
                .next()
                .unwrap_or("")
                .to_string()
        })
        .unwrap_or_default();
    let prior_caps = prior
        .as_ref()
        .and_then(|p| {
            git(&[
                "show",
                &format!(
                    "origin/main:supply-chain/evidence/{}/{}/caps.toml",
                    ctx.tool, p.sha
                ),
            ])
            .ok()
        })
        .unwrap_or_default();
    let (before, after) = (caps_sections(&prior_caps), caps_sections(&caps));
    let added: Vec<&String> = after.iter().filter(|x| !before.contains(x)).collect();
    let removed: Vec<&String> = before.iter().filter(|x| !after.contains(x)).collect();
    let patches: Vec<String> = std::fs::read_dir(format!("tools/patches/{}", ctx.tool))
        .map(|rd| {
            rd.flatten()
                .map(|x| x.file_name().to_string_lossy().into_owned())
                .filter(|n| n.ends_with(".patch"))
                .collect()
        })
        .unwrap_or_default();
    let last_mal = mal.last().cloned().unwrap_or(Value::Null);
    let rev_from = prior
        .as_ref()
        .map(|p| short(&p.rev)[..8].to_string())
        .unwrap_or("none".into());
    let title = format!(
        "bless: {} {} -> {} — {} advisory instance(s), caps {} -> {} sections, VT {}/{}",
        ctx.tool,
        rev_from,
        &e.rev[..8],
        instances.len(),
        before.len(),
        after.len(),
        s(&last_mal, &["detections", "malicious"]),
        s(&last_mal, &["detections", "total"]),
    );
    let mut body = String::new();
    body.push_str(&format!(
        "`{}` {} -> {} on `{}`.\n\n",
        ctx.tool,
        prior
            .as_ref()
            .map(|p| p.rev.clone())
            .unwrap_or("none".into()),
        e.rev,
        ctx.branch
    ));
    body.push_str(&format!(
        "- **Lock:** {}\n",
        s(&header, &["lockProvenance"])
    ));
    if !patches.is_empty() {
        body.push_str(&format!(
            "- **Patches:** `tools/patches/{}/` — {}\n",
            ctx.tool,
            patches.join(", ")
        ));
    }
    body.push_str(&format!(
        "- **Digest:** `{}` (producer run {producer}).\n",
        e.sha
    ));
    body.push_str(&format!(
        "- **caps:** {}; {} -> {} sections; added: {}; removed: {}.\n",
        caps_header(&caps, "seed").unwrap_or("no caps.toml".into()),
        before.len(),
        after.len(),
        if added.is_empty() {
            "none".to_string()
        } else {
            added
                .iter()
                .map(|x| format!("`{x}`"))
                .collect::<Vec<_>>()
                .join(", ")
        },
        if removed.is_empty() {
            "none".to_string()
        } else {
            removed
                .iter()
                .map(|x| format!("`{x}`"))
                .collect::<Vec<_>>()
                .join(", ")
        },
    ));
    body.push_str(&format!(
        "- **vuln:** {} instance(s){} — scanner {} {} @ advisory-db {}.\n",
        instances.len(),
        if instances.is_empty() {
            String::new()
        } else {
            format!(": {}", instances.join("; "))
        },
        s(&header, &["scanner", "version"]),
        short(&s(&header, &["scanner", "digest"])),
        short(&s(&header, &["scanner", "db", "version"])),
    ));
    body.push_str(&format!(
        "- **mal:** VT {}/{} on {}, sandbox {} ({}).\n",
        s(&last_mal, &["detections", "malicious"]),
        s(&last_mal, &["detections", "total"]),
        s(&last_mal, &["panelDate"]),
        s(&last_mal, &["sandbox", "state"]),
        s(&last_mal, &["source"]),
    ));
    body.push_str("\nGenerated by `cargo xtask candidate-advance summary` from the evidence directory; the gate table on this PR is the verdict.\n");
    println!("{title}\n\n{body}");
    if let Some(n) = pr {
        let tmp = std::env::temp_dir().join(format!("candidate-advance-pr-{n}.md"));
        std::fs::write(&tmp, &body).map_err(|e| e.to_string())?;
        gh(&[
            "pr",
            "edit",
            n,
            "--title",
            &title,
            "--body-file",
            &tmp.to_string_lossy(),
        ])?;
        println!("PR #{n} title and body updated");
    }
    Ok(())
}

// ---------- entry ----------

pub fn run(args: &[String]) -> i32 {
    let usage = "usage: cargo xtask candidate-advance <status|digest|vuln|caps|mal|summary> --tool <name> [--target windows-x86_64] [--no-commit]\n\
                 \x20 digest  --run <producer run id>\n\
                 \x20 vuln    --auditor <digest-pinned cargo-audit exe> --lock-provenance <text>\n\
                 \x20 caps    [--seed <digest>] [--run <existing caps-measure run>] [--wait-minutes N]\n\
                 \x20 mal     [--no-submit] [--panel-wait-seconds N] [--wait-minutes N]\n\
                 \x20 summary [--pr <number>]";
    let Some(stage) = args.get(1).map(String::as_str) else {
        eprintln!("{usage}");
        return 2;
    };
    let mut tool = String::new();
    let mut target = "windows-x86_64".to_string();
    let mut no_commit = false;
    let mut run_id: Option<String> = None;
    let mut auditor: Option<PathBuf> = None;
    let mut provenance = String::new();
    let mut seed: Option<String> = None;
    let mut no_submit = false;
    let mut panel_wait = 540u64;
    let mut wait_minutes = 60u64;
    let mut pr: Option<String> = None;
    let mut it = args.iter().skip(2);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--tool" => tool = it.next().cloned().unwrap_or_default(),
            "--target" => target = it.next().cloned().unwrap_or(target),
            "--no-commit" => no_commit = true,
            "--run" => run_id = it.next().cloned(),
            "--auditor" => auditor = it.next().map(PathBuf::from),
            "--lock-provenance" => provenance = it.next().cloned().unwrap_or_default(),
            "--seed" => seed = it.next().cloned(),
            "--no-submit" => no_submit = true,
            "--panel-wait-seconds" => {
                panel_wait = it.next().and_then(|v| v.parse().ok()).unwrap_or(panel_wait)
            }
            "--wait-minutes" => {
                wait_minutes = it
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(wait_minutes)
            }
            "--pr" => pr = it.next().cloned(),
            other => {
                eprintln!("candidate-advance: unknown argument {other}\n{usage}");
                return 2;
            }
        }
    }
    if tool.is_empty() {
        eprintln!("candidate-advance: --tool is required\n{usage}");
        return 2;
    }
    let branch = match current_branch() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("candidate-advance: {e}");
            return 2;
        }
    };
    let ctx = Ctx {
        tool,
        target,
        branch,
        no_commit,
    };
    let wait = Duration::from_secs(wait_minutes * 60);
    let res = match stage {
        "status" => stage_status(&ctx),
        "digest" => match run_id {
            Some(id) => stage_digest(&ctx, &id),
            None => Err("digest needs --run <producer run id>".into()),
        },
        "vuln" => match auditor {
            Some(a) if !provenance.is_empty() => stage_vuln(&ctx, &a, &provenance),
            _ => Err("vuln needs --auditor <exe> and --lock-provenance <text>".into()),
        },
        "caps" => stage_caps(&ctx, seed.as_deref(), run_id.as_deref(), wait),
        "mal" => stage_mal(&ctx, no_submit, Duration::from_secs(panel_wait), wait),
        "summary" => stage_summary(&ctx, pr.as_deref()),
        other => Err(format!("unknown stage `{other}`\n{usage}")),
    };
    match res {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("candidate-advance {stage}: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCK: &str = "# TOOLS.lock\n#   name repo rev target sha256\n\
cargo-deny   EmbarkStudios/cargo-deny  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  windows-x86_64  1111111111111111111111111111111111111111111111111111111111111111  # v0.18\n\
cargo-vet mozilla/cargo-vet bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb windows-x86_64 0000000000000000000000000000000000000000000000000000000000000000 # candidate\n\
cargo-auditable  rust-secure-code/cargo-auditable  cccccccccccccccccccccccccccccccccccccccc  linux-x86_64  2222222222222222222222222222222222222222222222222222222222222222  # v0.7.7\n";

    #[test]
    fn rewrite_replaces_one_row_and_realigns_the_table() {
        let new = "e".repeat(64);
        let out = rewrite_tools_lock(
            LOCK,
            "cargo-vet",
            "windows-x86_64",
            &new,
            "v0.10.3, producer run 42",
        )
        .unwrap();
        let rows = parse_tools_lock(&out);
        assert_eq!(rows.len(), 3);
        let vet = rows.iter().find(|r| r.name == "cargo-vet").unwrap();
        assert_eq!(vet.sha, new);
        assert_eq!(rows[0].sha, "1".repeat(64), "other rows untouched");
        assert!(
            out.lines()
                .any(|l| l.ends_with("# v0.10.3, producer run 42"))
        );
        assert!(
            out.starts_with("# TOOLS.lock\n#   name"),
            "comment lines kept verbatim"
        );
        // aligned: every data row's repo column starts at the same byte offset
        let offs: Vec<usize> = out
            .lines()
            .filter(|l| !l.starts_with('#'))
            .zip(rows.iter())
            .map(|(l, r)| l.find(r.repo.as_str()).unwrap())
            .collect();
        assert!(offs.iter().all(|o| *o == offs[0]), "{out}");
        assert!(
            rewrite_tools_lock(LOCK, "cargo-vet", "linux-x86_64", &new, "x").is_err(),
            "no such target"
        );
        assert!(rewrite_tools_lock(LOCK, "nope", "windows-x86_64", &new, "x").is_err());
    }

    #[test]
    fn producer_digest_requires_matching_repo_and_rev_and_uniqueness() {
        let e = ToolLine {
            name: "cargo-vet".into(),
            repo: "mozilla/cargo-vet".into(),
            rev: "b".repeat(40),
            target: "windows-x86_64".into(),
            sha: ZERO.into(),
        };
        let good = format!(
            "build\tTable\t2026-11-12T18:00:00.0000000Z cargo-vet  mozilla/cargo-vet  {}  windows-x86_64  {}  # v0.10.3\n",
            "b".repeat(40),
            "e".repeat(64)
        );
        assert_eq!(producer_digest(&good, &e).unwrap(), "e".repeat(64));
        let dup = format!("{good}{good}");
        assert_eq!(
            producer_digest(&dup, &e).unwrap(),
            "e".repeat(64),
            "same row twice is one digest"
        );
        let other_rev = good.replace(&"b".repeat(40), &"c".repeat(40));
        assert!(
            producer_digest(&other_rev, &e)
                .unwrap_err()
                .contains("wrong run")
        );
        let two = format!("{good}{}", good.replace(&"e".repeat(64), &"f".repeat(64)));
        assert!(
            producer_digest(&two, &e)
                .unwrap_err()
                .contains("conflicting")
        );
        assert!(producer_digest("nothing here\n", &e).is_err());
    }

    #[test]
    fn log_message_strips_job_step_timestamp_and_ansi() {
        let l = "evaluate\tGate\t\u{feff}2026-11-12T18:09:43.3743940Z \u{1b}[36;1mecho hi\u{1b}[0m";
        assert_eq!(log_message(l), "echo hi");
        assert_eq!(log_message("plain text"), "plain text");
    }

    #[test]
    fn mal_record_and_absence_are_read_from_the_monitor_log() {
        let d = "d".repeat(64);
        let rec = format!(
            "monitor\tLookup\t2026-11-12T19:00:00.0000000Z       record (mal.jsonl line for supply-chain/evidence/cargo-vet/{d}/): {{\"schema\":\"hp-thermal/evidence-mal/v1\",\"subject\":{{\"name\":\"cargo-vet\",\"sha256\":\"{d}\"}},\"detections\":{{\"malicious\":0,\"total\":71}}}}\n"
        );
        let v = mal_record_line(&rec, "cargo-vet", &d).unwrap();
        assert_eq!(v["detections"]["total"], 71);
        assert!(
            mal_record_line(&rec, "cargo-deny", &d).is_none(),
            "another tool's line is not ours"
        );
        let absent = format!(
            "monitor\tLookup\t2026-11-12T19:00:00.0000000Z ##[warning]tool:cargo-vet:windows-x86_64 ({d}): not in VT corpus - dispatch vt-submit.yml\n"
        );
        assert!(mal_absent(&absent, &d));
        assert!(!mal_absent(&rec, &d));
    }

    #[test]
    fn acks_bound_to_a_digest_are_dropped_and_unparseable_lines_kept() {
        let d = "d".repeat(64);
        let text = format!(
            "{{\"axis\":\"caps\",\"product\":{{\"name\":\"t\",\"digest\":\"{d}\"}}}}\n\
             {{\"axis\":\"vuln\",\"product\":{{\"name\":\"t\",\"package\":\"x\"}}}}\n\
             not json at all\n\
             {{\"axis\":\"mal\",\"product\":{{\"name\":\"t\",\"digest\":\"{}\"}}}}\n",
            "a".repeat(64)
        );
        let (kept, dropped) = acks_without_digest(&text, &d);
        assert_eq!(dropped, 1);
        assert_eq!(kept.lines().count(), 3);
        assert!(kept.contains("not json at all"));
    }

    #[test]
    fn caps_sections_and_headers() {
        let caps = "# subject: x; frozen tools/locks/x.lock sha256 abc\n# seed: def; cackle exit 0\n[common]\n[pkg.a]\nallow_unsafe = true\n[pkg.b-c]\n[api.net]\n";
        assert_eq!(
            caps_sections(caps),
            vec!["a".to_string(), "b-c".to_string()]
        );
        assert_eq!(caps_header(caps, "seed").unwrap(), "def; cackle exit 0");
        assert!(caps_header(caps, "generated").is_none());
    }
}
