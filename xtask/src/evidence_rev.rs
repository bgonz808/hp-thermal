//! Evidence revisions (evidence README rule 2). A blessed digest's evidence is never edited: a
//! corrected measurement is appended as a new revision bound to its lock, with reason and date.
//!
//! ```text
//! supply-chain/evidence/<tool>/<digest>/                     revision 1: the bless-time record
//! supply-chain/evidence/<tool>/<digest>/rev/<lock-sha256>/   a later revision
//!     revision.json  vuln.jsonl  caps.toml  build.jsonl  [vdr.cdx.json]
//! ```
//!
//! `mal.jsonl` stays at the digest: a panel reads bytes, not a lock. Every consumer of the
//! lock-bound records (`vuln.jsonl`, `caps.toml`, `build.jsonl`, `vdr.cdx.json`) selects the
//! record whose lock is the current one via [`select`]; when none matches, it fails.
//!
//! Admission runs in the gate on the PR that adds a revision ([`admit_offline`], the build
//! record's custody bound by [`bind_producer`], [`check_vuln_rows`], and the paired scan and
//! capability comparison against the superseded record). A revision may only narrow the lock
//! (packages removed, nothing else changed), only for a digest already blessed, only for the
//! lock that PR makes current, never for revision 1's own lock, and only with a build record
//! from a producer run that rebuilt the same digest from exactly that lock and those patches.

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub const REV_DIR: &str = "rev";
pub const REVISION_FILE: &str = "revision.json";
pub const SCHEMA: &str = "hp-thermal/evidence-revision/v1";
/// Records a revision must carry. `vdr.cdx.json` is derived and checked by `vdr check`.
pub const REV_RECORDS: &[&str] = &["vuln.jsonl", "caps.toml", "build.jsonl"];

pub fn lock_rel(tool: &str) -> String {
    format!("tools/locks/{tool}.lock")
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Every lowercase 64-hex run in `s`, in order.
fn hex64s(s: &str) -> Vec<String> {
    let b = s.as_bytes();
    let hex = |c: u8| matches!(c, b'0'..=b'9' | b'a'..=b'f');
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if hex(b[i]) {
            let start = i;
            while i < b.len() && hex(b[i]) {
                i += 1;
            }
            if i - start == 64 {
                out.push(s[start..i].to_string());
            }
        } else {
            i += 1;
        }
    }
    out
}

fn exactly_one(found: Vec<String>, what: &str) -> Result<String, String> {
    let set: BTreeSet<String> = found.into_iter().collect();
    match set.len() {
        1 => Ok(set.into_iter().next().unwrap_or_default()),
        0 => Err(format!("{what}: names no lock sha256")),
        n => Err(format!(
            "{what}: names {n} different sha256 values; ambiguous"
        )),
    }
}

fn read(p: &Path) -> Result<String, String> {
    std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))
}

fn first_line_json(p: &Path) -> Result<Value, String> {
    let text = read(p)?;
    let line = text.lines().next().unwrap_or_default();
    serde_json::from_str(line).map_err(|e| format!("{}: header is not JSON ({e})", p.display()))
}

/// The lock a `vuln.jsonl` header was measured against: the structured `lock.sha256` when
/// present (revisions), else the one sha256 in `lockProvenance` (records before revisions).
pub fn vuln_lock(header: &Value) -> Result<String, String> {
    if let Some(l) = header.get("lock") {
        let s = l
            .get("sha256")
            .and_then(Value::as_str)
            .filter(|s| is_hex64(s))
            .ok_or("vuln.jsonl header: `lock.sha256` is not a sha256")?;
        let prose = header
            .get("lockProvenance")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if hex64s(prose).iter().any(|h| h != s) {
            return Err("vuln.jsonl header: lockProvenance names a different lock".into());
        }
        return Ok(s.to_string());
    }
    let prose = header
        .get("lockProvenance")
        .and_then(Value::as_str)
        .ok_or("vuln.jsonl header: no lockProvenance")?;
    exactly_one(hex64s(prose), "vuln.jsonl lockProvenance")
}

/// The lock named on the `# subject:` line of a caps.toml header.
pub fn caps_lock(caps: &str) -> Result<String, String> {
    let subject: Vec<&str> = caps
        .lines()
        .take_while(|l| l.starts_with('#'))
        .filter(|l| l.starts_with("# subject:"))
        .collect();
    let [line] = subject.as_slice() else {
        return Err(format!(
            "caps.toml: expected one `# subject:` header line, found {}",
            subject.len()
        ));
    };
    exactly_one(hex64s(line), "caps.toml subject")
}

fn subject_is(header: &Value, tool: &str, digest: &str) -> bool {
    header["subject"]["name"].as_str() == Some(tool)
        && header["subject"]["sha256"].as_str() == Some(digest)
}

/// The lock a record directory (revision 1 or a revision) was measured against. `vuln.jsonl`
/// and `caps.toml` must both name it and agree; `vuln.jsonl` and `build.jsonl` must name the
/// digest the directory is filed under.
pub fn record_lock(dir: &Path, tool: &str, digest: &str) -> Result<String, String> {
    let vh = first_line_json(&dir.join("vuln.jsonl"))?;
    if !subject_is(&vh, tool, digest) {
        return Err(format!(
            "{}: vuln.jsonl subject is not {tool} {digest}",
            dir.display()
        ));
    }
    let bh = first_line_json(&dir.join("build.jsonl"))?;
    if !subject_is(&bh, tool, digest) {
        return Err(format!(
            "{}: build.jsonl subject is not {tool} {digest}",
            dir.display()
        ));
    }
    let v = vuln_lock(&vh)?;
    let c = caps_lock(&read(&dir.join("caps.toml"))?)?;
    if v != c {
        return Err(format!(
            "{}: vuln.jsonl names lock {} but caps.toml names {}",
            dir.display(),
            &v[..12],
            &c[..12]
        ));
    }
    Ok(v)
}

/// A parsed, validated `revision.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revision {
    pub lock: String,
    pub supersedes: String,
    pub reason: String,
    pub date: String,
    pub producer_run: String,
    pub patches: BTreeMap<String, String>,
}

pub fn parse_revision(text: &str, tool: &str, digest: &str) -> Result<Revision, String> {
    let v: Value =
        serde_json::from_str(text).map_err(|e| format!("revision.json is not JSON ({e})"))?;
    let str_at = |path: &[&str]| -> Option<String> {
        let mut cur = &v;
        for p in path {
            cur = cur.get(*p)?;
        }
        cur.as_str().map(str::to_string)
    };
    if str_at(&["schema"]).as_deref() != Some(SCHEMA) {
        return Err(format!("revision.json: schema is not {SCHEMA}"));
    }
    if !subject_is(&v, tool, digest) {
        return Err(format!("revision.json: subject is not {tool} {digest}"));
    }
    if str_at(&["lock", "path"]) != Some(lock_rel(tool)) {
        return Err(format!(
            "revision.json: lock.path is not {}",
            lock_rel(tool)
        ));
    }
    let lock = str_at(&["lock", "sha256"])
        .filter(|s| is_hex64(s))
        .ok_or("revision.json: lock.sha256 is not a sha256")?;
    let supersedes = str_at(&["supersedes", "lock"])
        .filter(|s| is_hex64(s))
        .ok_or("revision.json: supersedes.lock is not a sha256")?;
    let reason = str_at(&["reason"])
        .filter(|s| !s.trim().is_empty())
        .ok_or("revision.json: reason is required")?;
    let date = str_at(&["date"])
        .filter(|d| {
            d.len() == 10
                && d.bytes().enumerate().all(|(i, b)| {
                    if i == 4 || i == 7 {
                        b == b'-'
                    } else {
                        b.is_ascii_digit()
                    }
                })
        })
        .ok_or("revision.json: date is not YYYY-MM-DD")?;
    let producer_run = str_at(&["producer", "run"])
        .filter(|r| r.starts_with("https://github.com/") && r.contains("/actions/runs/"))
        .ok_or("revision.json: producer.run is not a GitHub Actions run url")?;
    let mut patches = BTreeMap::new();
    for p in v
        .get("patches")
        .and_then(Value::as_array)
        .ok_or("revision.json: patches must be an array (empty when there are none)")?
    {
        let (Some(path), Some(sha)) = (p["path"].as_str(), p["sha256"].as_str()) else {
            return Err("revision.json: a patch needs path and sha256".into());
        };
        if !is_hex64(sha) || patches.insert(path.to_string(), sha.to_string()).is_some() {
            return Err(format!(
                "revision.json: patch {path} is malformed or repeated"
            ));
        }
    }
    if lock == supersedes {
        return Err("revision.json: supersedes its own lock".into());
    }
    Ok(Revision {
        lock,
        supersedes,
        reason,
        date,
        producer_run,
        patches,
    })
}

/// The record of `tool`@`digest` measured against lock `lock_sha`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub dir: PathBuf,
    pub lock: String,
    /// `None` for revision 1.
    pub revision: Option<Revision>,
}

/// Select the record whose lock is `lock_sha`. Revision 1 when its lock matches, else
/// `rev/<lock_sha>/`, validated. No match fails: a measurement under another lock is never
/// read as this one's.
pub fn select(root: &Path, tool: &str, digest: &str, lock_sha: &str) -> Result<Record, String> {
    if !is_hex64(digest) || !is_hex64(lock_sha) {
        return Err("select: digest and lock must be lowercase sha256".into());
    }
    let base = root.join(tool).join(digest);
    let base_lock = record_lock(&base, tool, digest)?;
    let rev = base.join(REV_DIR).join(lock_sha);
    if base_lock == lock_sha {
        if rev.exists() {
            return Err(format!(
                "{}: a revision for revision 1's own lock; ambiguous",
                rev.display()
            ));
        }
        return Ok(Record {
            dir: base,
            lock: base_lock,
            revision: None,
        });
    }
    if !rev.is_dir() {
        return Err(format!(
            "{tool} {}: no evidence measured against lock {} (revision 1 is lock {}); \
             record a revision or re-bless",
            &digest[..12],
            &lock_sha[..12],
            &base_lock[..12]
        ));
    }
    let r = parse_revision(&read(&rev.join(REVISION_FILE))?, tool, digest)?;
    if r.lock != lock_sha {
        return Err(format!(
            "{}: revision.json names lock {}, not its directory",
            rev.display(),
            &r.lock[..12]
        ));
    }
    for f in REV_RECORDS {
        if !rev.join(f).is_file() {
            return Err(format!("{}: missing {f}", rev.display()));
        }
    }
    let measured = record_lock(&rev, tool, digest)?;
    if measured != lock_sha {
        return Err(format!(
            "{}: records were measured against lock {}, not {}",
            rev.display(),
            &measured[..12],
            &lock_sha[..12]
        ));
    }
    Ok(Record {
        dir: rev,
        lock: measured,
        revision: Some(r),
    })
}

// ---------- strict subset of a Cargo.lock ----------

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Pkg {
    pub(crate) source: Option<String>,
    pub(crate) checksum: Option<String>,
    pub(crate) deps: BTreeSet<String>,
    /// Any key other than name/version/source/checksum/dependencies, verbatim.
    other: Vec<String>,
}

/// A lock package's identity: (name, version).
pub(crate) type Key = (String, String);
pub(crate) type Pkgs = BTreeMap<Key, Pkg>;

/// `[[package]]` entries by (name, version), plus every line outside them, verbatim.
pub(crate) fn parse_lock(text: &str) -> Result<(Pkgs, Vec<String>), String> {
    let mut pkgs = BTreeMap::new();
    let mut outside = Vec::new();
    let mut cur: Option<(Option<String>, Option<String>, Pkg)> = None;
    let mut in_deps = false;
    let mut flush =
        |cur: &mut Option<(Option<String>, Option<String>, Pkg)>| -> Result<(), String> {
            if let Some((n, v, p)) = cur.take() {
                let (Some(n), Some(v)) = (n, v) else {
                    return Err("a [[package]] without name or version".into());
                };
                if pkgs.insert((n.clone(), v.clone()), p).is_some() {
                    return Err(format!("{n}@{v} appears twice"));
                }
            }
            Ok(())
        };
    let q = |s: &str| -> Option<String> {
        let s = s.trim().trim_end_matches(',');
        s.strip_prefix('"')?.strip_suffix('"').map(str::to_string)
    };
    for raw in text.lines() {
        let l = raw.trim_end_matches('\r');
        let t = l.trim();
        if in_deps {
            if t == "]" {
                in_deps = false;
            } else if let (Some((_, _, p)), Some(d)) = (cur.as_mut(), q(t)) {
                p.deps.insert(d);
            } else {
                return Err(format!("unparseable dependency line `{t}`"));
            }
            continue;
        }
        if t == "[[package]]" {
            flush(&mut cur)?;
            cur = Some((None, None, Pkg::default()));
            continue;
        }
        if t.starts_with('[') {
            flush(&mut cur)?;
            outside.push(l.to_string());
            continue;
        }
        let Some((name, version, p)) = cur.as_mut() else {
            outside.push(l.to_string());
            continue;
        };
        let Some((k, val)) = t.split_once(" = ") else {
            if !t.is_empty() {
                p.other.push(t.to_string());
            }
            continue;
        };
        match k {
            "name" | "version" | "source" | "checksum" => {
                // Cargo writes basic strings. A literal string ('...') or anything else would
                // read as absent and compare equal to a missing field: refused.
                let v = q(val).ok_or_else(|| format!("`{t}`: not a double-quoted string"))?;
                match k {
                    "name" => *name = Some(v),
                    "version" => *version = Some(v),
                    "source" => p.source = Some(v),
                    _ => p.checksum = Some(v),
                }
            }
            "dependencies" if val.trim() == "[" => in_deps = true,
            "dependencies" => {
                let inner = val
                    .trim()
                    .strip_prefix('[')
                    .and_then(|s| s.strip_suffix(']'))
                    .ok_or_else(|| format!("unparseable dependencies `{val}`"))?;
                for d in inner.split(',').filter(|s| !s.trim().is_empty()) {
                    p.deps
                        .insert(q(d).ok_or_else(|| format!("unparseable dependency `{d}`"))?);
                }
            }
            _ => p.other.push(t.to_string()),
        }
    }
    if in_deps {
        return Err("unterminated dependencies array".into());
    }
    flush(&mut cur)?;
    Ok((pkgs, outside))
}

/// A lock's dependency strings resolved to (name, version): Cargo writes `"name"` when one
/// version is in the lock and `"name version"` (or `"name version (source)"`) when several are,
/// so the same edge is spelled differently once a narrowing removes the other version.
fn resolve_deps(pkgs: &Pkgs) -> Result<BTreeMap<Key, BTreeSet<Key>>, String> {
    let mut by_name: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (n, v) in pkgs.keys() {
        by_name.entry(n).or_default().push(v);
    }
    let mut out = BTreeMap::new();
    for (k, p) in pkgs {
        let mut set = BTreeSet::new();
        for d in &p.deps {
            let mut parts = d.splitn(3, ' ');
            let name = parts.next().unwrap_or_default();
            let version = match parts.next() {
                Some(v) => v.to_string(),
                None => match by_name.get(name).map(Vec::as_slice) {
                    Some([v]) => (*v).to_string(),
                    _ => {
                        return Err(format!(
                            "{}@{}: dependency `{d}` is ambiguous or missing",
                            k.0, k.1
                        ));
                    }
                },
            };
            let Some(dep) = pkgs.get(&(name.to_string(), version.clone())) else {
                return Err(format!(
                    "{}@{}: dependency `{d}` is not in the lock",
                    k.0, k.1
                ));
            };
            // `"name version (source)"`: the source names which package; it must be that one's.
            if let Some(src) = parts.next() {
                let named = src.strip_prefix('(').and_then(|x| x.strip_suffix(')'));
                if named.is_none() || named != dep.source.as_deref() {
                    return Err(format!(
                        "{}@{}: dependency `{d}` names another source than the package's",
                        k.0, k.1
                    ));
                }
            }
            set.insert((name.to_string(), version));
        }
        out.insert(k.clone(), set);
    }
    Ok(out)
}

/// `head` only removes packages from `base`: every remaining package keeps its source and
/// checksum, its dependency list only shrinks, and nothing outside the packages changes.
/// Returns the removed (name, version) pairs; none removed is an error (not a narrowing).
pub fn strict_subset(base: &str, head: &str) -> Result<Vec<(String, String)>, String> {
    let (b, b_out) = parse_lock(base).map_err(|e| format!("base lock: {e}"))?;
    let (h, h_out) = parse_lock(head).map_err(|e| format!("new lock: {e}"))?;
    let strip = |v: &[String]| -> Vec<String> {
        v.iter().filter(|l| !l.trim().is_empty()).cloned().collect()
    };
    if strip(&b_out) != strip(&h_out) {
        return Err("the lock changed outside its [[package]] entries".into());
    }
    let b_deps = resolve_deps(&b).map_err(|e| format!("base lock: {e}"))?;
    let h_deps = resolve_deps(&h).map_err(|e| format!("new lock: {e}"))?;
    let mut problems = Vec::new();
    for (k, hp) in &h {
        let Some(bp) = b.get(k) else {
            problems.push(format!("{}@{} is new", k.0, k.1));
            continue;
        };
        if hp.source != bp.source || hp.checksum != bp.checksum || hp.other != bp.other {
            problems.push(format!(
                "{}@{} changed source, checksum or fields",
                k.0, k.1
            ));
        }
        if !h_deps[k].is_subset(&b_deps[k]) {
            problems.push(format!("{}@{} gained a dependency", k.0, k.1));
        }
    }
    if !problems.is_empty() {
        return Err(format!("not a narrowing: {}", problems.join("; ")));
    }
    let removed: Vec<(String, String)> =
        b.keys().filter(|k| !h.contains_key(*k)).cloned().collect();
    if removed.is_empty() {
        return Err("no package removed: not a narrowing".into());
    }
    Ok(removed)
}

// ---------- the current record, and where a writer puts a new one ----------

/// The record of `tool`@`digest` under the frozen lock in `locks_dir`. A tool with no frozen
/// lock has only revision 1, and only while no revision exists.
pub fn current(root: &Path, locks_dir: &Path, tool: &str, digest: &str) -> Result<Record, String> {
    let lock = locks_dir.join(format!("{tool}.lock"));
    match std::fs::read(&lock) {
        Ok(b) => select(root, tool, digest, &crate::sha256::sha256_hex(&b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let base = root.join(tool).join(digest);
            if base.join(REV_DIR).exists() {
                return Err(format!(
                    "{tool} {}: revisions exist but {} does not; which record applies is unknown",
                    &digest[..12.min(digest.len())],
                    lock.display()
                ));
            }
            Ok(Record {
                dir: base,
                lock: String::new(),
                revision: None,
            })
        }
        Err(e) => Err(format!("{}: {e}", lock.display())),
    }
}

/// Where a writer records `tool`@`digest` measured against `lock_sha`, and whether that is a
/// revision. An unblessed candidate is measured in place. A blessed digest whose revision 1 was
/// measured against another lock gets `rev/<lock_sha>/`. A blessed digest whose lock is
/// revision 1's has nothing to revise: its evidence is never edited (rule 2).
pub fn write_dir(
    root: &Path,
    tool: &str,
    digest: &str,
    lock_sha: &str,
    blessed: bool,
) -> Result<(PathBuf, bool), String> {
    let base = root.join(tool).join(digest);
    if !blessed {
        return Ok((base, false));
    }
    let rev1 = record_lock(&base, tool, digest).map_err(|e| format!("revision 1: {e}"))?;
    if rev1 == lock_sha {
        return Err(format!(
            "{tool} {} is blessed and its lock is revision 1's: blessed evidence is never edited \
             (supply-chain/evidence/README.md rule 2)",
            &digest[..12]
        ));
    }
    Ok((base.join(REV_DIR).join(lock_sha), true))
}

/// `revision.json` text. The parser ([`parse_revision`]) is the contract; this is its writer.
#[allow(clippy::too_many_arguments)]
pub fn revision_json(
    tool: &str,
    digest: &str,
    lock: &str,
    supersedes: &str,
    reason: &str,
    date: &str,
    producer_run: &str,
    patches: &BTreeMap<String, String>,
) -> String {
    let patches: Vec<Value> = patches
        .iter()
        .map(|(p, s)| serde_json::json!({"path": p, "sha256": s}))
        .collect();
    let v = serde_json::json!({
        "schema": SCHEMA,
        "subject": {"name": tool, "sha256": digest},
        "lock": {"path": lock_rel(tool), "sha256": lock},
        "supersedes": {"lock": supersedes},
        "patches": patches,
        "reason": reason,
        "date": date,
        "producer": {"run": producer_run},
    });
    serde_json::to_string_pretty(&v).unwrap_or_default() + "\n"
}

/// sha256 of every file under `tools/patches/<tool>/` in the working tree, by repo path. The
/// producer applies them before the lock overlay; none is an empty map.
pub fn patches_of(repo: &Path, tool: &str) -> Result<BTreeMap<String, String>, String> {
    let rel = format!("tools/patches/{tool}");
    let dir = repo.join(&rel);
    let mut out = BTreeMap::new();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Ok(out);
    };
    for e in entries {
        let e = e.map_err(|e| format!("{}: {e}", dir.display()))?;
        let name = e.file_name().to_string_lossy().into_owned();
        if !e.path().is_file() {
            return Err(format!("{rel}/{name}: not a file; patches are flat"));
        }
        out.insert(format!("{rel}/{name}"), sha256_file(&e.path())?);
    }
    Ok(out)
}

/// The lock sha256 and patch set the producer saw at `commit` (any tree-ish), read from the git
/// objects of the repository at `repo`.
pub fn producer_tree(
    repo: &Path,
    commit: &str,
    tool: &str,
) -> Result<(String, BTreeMap<String, String>), String> {
    let repo_s = repo.to_string_lossy().into_owned();
    let show = |path: &str| -> Result<Vec<u8>, String> {
        let out = std::process::Command::new("git")
            .args(["-C", &repo_s, "show", &format!("{commit}:{path}")])
            .output()
            .map_err(|e| format!("git show: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "{path} is not in commit {}",
                &commit[..12.min(commit.len())]
            ));
        }
        Ok(out.stdout)
    };
    let lock = crate::sha256::sha256_hex(&show(&lock_rel(tool))?);
    let listed = crate::advance::git(&[
        "-C",
        &repo_s,
        "ls-tree",
        "-r",
        "--name-only",
        commit,
        "--",
        &format!("tools/patches/{tool}/"),
    ])?;
    let mut patches = BTreeMap::new();
    for p in listed.lines().filter(|l| !l.trim().is_empty()) {
        patches.insert(p.to_string(), crate::sha256::sha256_hex(&show(p)?));
    }
    Ok((lock, patches))
}

/// The producer run a revision names is the one whose record it carries, and that run built
/// from exactly the revision's lock and patches. Stated here, not inherited from
/// `build_record::producer_inputs`: that list happening to include the lock is not a contract.
pub fn bind_producer(
    r: &Revision,
    record_run: &str,
    lock_at_commit: &str,
    patches_at_commit: &BTreeMap<String, String>,
) -> Result<(), String> {
    let norm = |u: &str| u.trim_end_matches('/').to_string();
    if norm(record_run) != norm(&r.producer_run) {
        return Err(format!(
            "build.jsonl names producer run {record_run}, revision.json names {}",
            r.producer_run
        ));
    }
    if lock_at_commit != r.lock {
        return Err(format!(
            "the producer built from lock {}, not the revision's {}",
            &lock_at_commit[..12.min(lock_at_commit.len())],
            &r.lock[..12]
        ));
    }
    if patches_at_commit != &r.patches {
        return Err("the producer applied other patches than the revision names".into());
    }
    Ok(())
}

// ---------- admission (PR time) ----------

/// A revision directory added by the change under review.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Added {
    pub tool: String,
    pub digest: String,
    pub lock: String,
}

/// Files a revision directory may hold.
const REV_FILES: &[&str] = &[
    REVISION_FILE,
    "vuln.jsonl",
    "caps.toml",
    "build.jsonl",
    "vdr.cdx.json",
];

/// Every file under `<tool>/<digest>/rev/` in an evidence tree, by path relative to the tree,
/// plus paths that are not `<tool>/<digest>/rev/<lock>/<file>`.
fn rev_files(root: &Path) -> (BTreeMap<String, Vec<u8>>, Vec<String>) {
    let mut files = BTreeMap::new();
    let mut odd = Vec::new();
    let dirs = |p: &Path| -> Vec<std::fs::DirEntry> {
        std::fs::read_dir(p)
            .map(|r| r.filter_map(Result::ok).collect())
            .unwrap_or_default()
    };
    for t in dirs(root).into_iter().filter(|e| e.path().is_dir()) {
        for d in dirs(&t.path()).into_iter().filter(|e| e.path().is_dir()) {
            let rev = d.path().join(REV_DIR);
            if !rev.exists() {
                continue;
            }
            let rel_rev = format!(
                "{}/{}/{REV_DIR}",
                t.file_name().to_string_lossy(),
                d.file_name().to_string_lossy()
            );
            for l in dirs(&rev) {
                let lname = l.file_name().to_string_lossy().into_owned();
                if !l.path().is_dir() {
                    odd.push(format!("{rel_rev}/{lname}"));
                    continue;
                }
                for f in dirs(&l.path()) {
                    // Reachability records are add-only on their own terms (gate::reach_changes,
                    // #520); they arrive after a revision is admitted.
                    if f.file_name() == "reach" && f.path().is_dir() {
                        continue;
                    }
                    let rel = format!("{rel_rev}/{lname}/{}", f.file_name().to_string_lossy());
                    match std::fs::read(f.path()) {
                        Ok(b) if f.path().is_file() => {
                            files.insert(rel, b);
                        }
                        _ => odd.push(rel),
                    }
                }
            }
        }
    }
    (files, odd)
}

/// The derived report: re-emitted when an ack adds a ruling (`vdr check` regenerates it from the
/// records), so it may change; the gate's VDR ledger rule keeps its versions moving forward.
const REV_DERIVED: &str = "vdr.cdx.json";

/// Revisions are append-only (rule 2). Every measured record under a `rev/` directory in the
/// base tree is byte-identical in the change, and none is deleted; the derived `vdr.cdx.json` may
/// be re-emitted, never deleted. A revision directory the base already has takes no new record
/// but its report. Returns the revision directories the change adds, and every violation.
pub fn rev_changes(head_root: &Path, base_root: &Path) -> (BTreeSet<Added>, Vec<String>) {
    let (head, odd) = rev_files(head_root);
    let (base, _) = rev_files(base_root);
    let mut problems: Vec<String> = odd
        .into_iter()
        .map(|p| format!("{p}: not <tool>/<digest>/rev/<lock-sha256>/<file>"))
        .collect();
    let dir_of = |rel: &str| {
        rel.rsplit_once('/')
            .map_or(String::new(), |(d, _)| d.to_string())
    };
    let base_dirs: BTreeSet<String> = base.keys().map(|r| dir_of(r)).collect();
    for (rel, b) in &base {
        match head.get(rel) {
            Some(h) if h == b => {}
            Some(_) if rel.ends_with(&format!("/{REV_DERIVED}")) => {}
            Some(_) => problems.push(format!(
                "{rel}: modified; revisions are append-only (rule 2)"
            )),
            None => problems.push(format!(
                "{rel}: deleted; revisions are append-only (rule 2)"
            )),
        }
    }
    let mut added = BTreeSet::new();
    for rel in head.keys().filter(|r| !base.contains_key(*r)) {
        let parts: Vec<&str> = rel.split('/').collect();
        let [tool, digest, _, lock, file] = parts.as_slice() else {
            problems.push(format!(
                "{rel}: not <tool>/<digest>/rev/<lock-sha256>/<file>"
            ));
            continue;
        };
        if !is_hex64(digest) || !is_hex64(lock) || !REV_FILES.contains(file) {
            problems.push(format!(
                "{rel}: not <tool>/<digest>/rev/<lock-sha256>/<one of {}>",
                REV_FILES.join(", ")
            ));
            continue;
        }
        if base_dirs.contains(&dir_of(rel)) {
            // An admitted revision is complete; only its report may arrive later.
            if *file != REV_DERIVED {
                problems.push(format!(
                    "{rel}: added to a revision already admitted; a revision is not amended (rule 2)"
                ));
            }
            continue;
        }
        added.insert(Added {
            tool: (*tool).to_string(),
            digest: (*digest).to_string(),
            lock: (*lock).to_string(),
        });
    }
    (added, problems)
}

/// What admission compares, read from the base commit and the change.
pub struct Inputs<'a> {
    /// Evidence tree of the change.
    pub root: &'a Path,
    /// Evidence tree of the base commit: the superseded record is read from here, where the
    /// change cannot rewrite it.
    pub base_root: &'a Path,
    /// `tools/TOOLS.lock` at the base commit: a revision is only for a digest blessed there.
    pub base_tools_lock: &'a str,
    /// `tools/locks/<tool>.lock` at the base commit and in the change.
    pub base_lock: &'a str,
    pub head_lock: &'a str,
    /// sha256 of each file under `tools/patches/<tool>/` in the change ([`patches_of`]).
    pub head_patches: &'a BTreeMap<String, String>,
}

/// Admission of one revision, the part that needs no network. The rest runs on the gate's
/// other axes: the build record's custody bound to this revision ([`bind_producer`]), the raw
/// vulnerability payload re-derived ([`check_vuln_rows`]), the paired vulnerability scan and
/// the capability comparison against the superseded record.
pub fn admit_offline(a: &Added, i: &Inputs) -> Result<Revision, String> {
    let blessed = crate::gate::parse_tools_lock(i.base_tools_lock)
        .iter()
        .any(|l| l.name == a.tool && l.sha == a.digest);
    if !blessed {
        return Err(format!(
            "{} {}: not pinned in the base TOOLS.lock; a candidate is re-measured in place, a \
             revision is only for a blessed digest",
            a.tool,
            &a.digest[..12]
        ));
    }
    let head_sha = crate::sha256::sha256_hex(i.head_lock.as_bytes());
    if head_sha != a.lock {
        return Err(format!(
            "revision {} is not the lock this change makes current ({})",
            &a.lock[..12],
            &head_sha[..12]
        ));
    }
    let base_sha = crate::sha256::sha256_hex(i.base_lock.as_bytes());
    let rec = select(i.root, &a.tool, &a.digest, &a.lock)?;
    let r = rec
        .revision
        .ok_or("the current lock selects revision 1; nothing to admit")?;
    if r.supersedes != base_sha {
        return Err(format!(
            "revision supersedes lock {}, but the base lock is {}",
            &r.supersedes[..12],
            &base_sha[..12]
        ));
    }
    // The superseded record, as the base commit holds it: the chain never skips a lock.
    let prior = select(i.base_root, &a.tool, &a.digest, &base_sha)
        .map_err(|e| format!("superseded record: {e}"))?;
    strict_subset(i.base_lock, i.head_lock)?;
    if &r.patches != i.head_patches {
        return Err("revision.json patches differ from tools/patches in this change".into());
    }
    // Same bytes, same build: cargo's record of the rebuild (every unit, feature, profile and
    // build-script directive kept) is the superseded record's, message for message.
    let messages = |dir: &Path| -> Result<BTreeSet<String>, String> {
        let p = dir.join(crate::build_record::FILE);
        let (_, msgs) = crate::build_record::read_evidence(&read(&p)?)
            .map_err(|e| format!("{}: {e}", p.display()))?;
        Ok(msgs.iter().map(Value::to_string).collect())
    };
    let (now, before) = (messages(&rec.dir)?, messages(&prior.dir)?);
    if now != before {
        return Err(format!(
            "the rebuild's cargo record differs from the superseded record's ({} message(s) only              in the rebuild, {} only in the superseded): not the same build",
            now.difference(&before).count(),
            before.difference(&now).count()
        ));
    }
    Ok(r)
}

/// A revision's `vuln.jsonl` rows are what its raw scanner payload says, and that payload is a
/// scan of the revision's lock: the dependency count is the lock's package count and every
/// finding names a package in it. `rows` excludes the header.
pub fn check_vuln_rows(rows: &[Value], raw: &Value, lock: &str) -> Result<(), String> {
    let want = crate::record_vuln::instance_rows(raw);
    if rows != want.as_slice() {
        return Err(format!(
            "vuln.jsonl rows ({}) are not the raw payload's instances ({})",
            rows.len(),
            want.len()
        ));
    }
    let (pkgs, _) = parse_lock(lock)?;
    let count = raw
        .pointer("/lockfile/dependency-count")
        .and_then(Value::as_u64);
    if count != Some(pkgs.len() as u64) {
        return Err(format!(
            "the raw payload scanned {} package(s); the lock has {}",
            count.map_or("an unknown number of".into(), |c| c.to_string()),
            pkgs.len()
        ));
    }
    for r in &want {
        let key = (
            r["package"].as_str().unwrap_or_default().to_string(),
            r["version"].as_str().unwrap_or_default().to_string(),
        );
        if !pkgs.contains_key(&key) {
            return Err(format!(
                "the raw payload reports {}@{}, which the lock does not list",
                key.0, key.1
            ));
        }
    }
    Ok(())
}

/// The advisory-db commit a vulnerability record was measured at. The header is written by the
/// change; the raw payload is custody-verified. They must name the same commit, or the header's
/// claim is unbacked and a re-scan at it proves nothing about this payload.
pub fn record_db(header: &Value, raw: &Value) -> Result<String, String> {
    let h = header
        .pointer("/scanner/db/version")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let r = raw
        .pointer("/database/last-commit")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if h.len() != 40 || !h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err("vuln.jsonl names no advisory-db commit".into());
    }
    if h != r {
        return Err(format!(
            "vuln.jsonl names advisory-db {}, its raw payload {}: the header's claim is unbacked",
            &h[..12],
            if r.is_empty() {
                "none (a --no-fetch scan?)"
            } else {
                r
            }
        ));
    }
    Ok(h.to_string())
}

/// Rows a re-scan must reproduce: all but `yanked`, which reads crates.io's state at scan time,
/// not the advisory database.
fn db_rows(rows: &[Value]) -> BTreeSet<String> {
    rows.iter()
        .filter(|r| r["kind"] != "yanked")
        .map(|r| {
            format!(
                "{} {}@{} {}",
                r["id"].as_str().unwrap_or("?"),
                r["package"].as_str().unwrap_or("?"),
                r["version"].as_str().unwrap_or("?"),
                r["kind"].as_str().unwrap_or("?")
            )
        })
        .collect()
}

/// The recorded rows are what the same scanner finds in the revision's lock at the recorded
/// advisory-database commit: `rescan` is that scan, made by the gate. Proves the payload is a
/// scan of this lock, where [`check_vuln_rows`] only shows it is consistent with one.
pub fn check_rescan(rows: &[Value], rescan: &Value) -> Result<(), String> {
    let have = db_rows(rows);
    let want = db_rows(&crate::record_vuln::instance_rows(rescan));
    if have == want {
        return Ok(());
    }
    let missing: Vec<&String> = want.difference(&have).collect();
    let extra: Vec<&String> = have.difference(&want).collect();
    Err(format!(
        "the recorded rows are not a scan of this lock at the recorded advisory-db commit:          re-scan finds {missing:?} the record lacks, record has {extra:?} the re-scan does not"
    ))
}

// ---------- CLI ----------

fn sha256_file(p: &Path) -> Result<String, String> {
    let b = std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?;
    Ok(crate::sha256::sha256_hex(&b))
}

/// `xtask evidence-rev subset <base.lock> <new.lock>` | `select --tool T --digest D
/// [--lock P] [--evidence DIR]`.
pub fn run(args: &[String]) -> i32 {
    let usage = || {
        eprintln!(
            "usage: xtask evidence-rev subset <base.lock> <new.lock>\n       \
             xtask evidence-rev select --tool T --digest D [--lock P] [--evidence DIR]
                    xtask evidence-rev verify --tool T --digest D   (online; needs PINNED_TOOLS_DIR)"
        );
        2
    };
    match args.get(1).map(String::as_str) {
        Some("subset") => {
            let (Some(b), Some(h)) = (args.get(2), args.get(3)) else {
                return usage();
            };
            match read(Path::new(b)).and_then(|b| Ok((b, read(Path::new(h))?))) {
                Ok((b, h)) => match strict_subset(&b, &h) {
                    Ok(removed) => {
                        println!(
                            "narrowing: {} package(s) removed, nothing else changed",
                            removed.len()
                        );
                        for (n, v) in removed {
                            println!("  - {n}@{v}");
                        }
                        0
                    }
                    Err(e) => {
                        eprintln!("NOT A NARROWING: {e}");
                        1
                    }
                },
                Err(e) => {
                    eprintln!("evidence-rev: {e}");
                    1
                }
            }
        }
        Some("verify") => {
            // The online half a writer can run before pushing: the selected record's
            // vulnerability rows against the raw payload and a re-scan of the lock.
            let (mut tool, mut digest) = (None, None);
            let mut it = args.iter().skip(2);
            while let Some(a) = it.next() {
                match a.as_str() {
                    "--tool" => tool = it.next().cloned(),
                    "--digest" => digest = it.next().cloned(),
                    _ => return usage(),
                }
            }
            let (Some(tool), Some(digest)) = (tool, digest) else {
                return usage();
            };
            let locks = Path::new("tools/locks");
            match current(Path::new("supply-chain/evidence"), locks, &tool, &digest).and_then(|r| {
                crate::gate::verify_vuln_record(&r.dir, &locks.join(format!("{tool}.lock")), None)
                    .map(|m| (r.dir, m))
            }) {
                Ok((dir, m)) => {
                    println!("{}: {m}", dir.display());
                    0
                }
                Err(e) => {
                    eprintln!("evidence-rev verify: {e}");
                    1
                }
            }
        }
        Some("select") => {
            let (mut tool, mut digest, mut lock, mut root) =
                (None, None, None, PathBuf::from("supply-chain/evidence"));
            let mut it = args.iter().skip(2);
            while let Some(a) = it.next() {
                match a.as_str() {
                    "--tool" => tool = it.next().cloned(),
                    "--digest" => digest = it.next().cloned(),
                    "--lock" => lock = it.next().map(PathBuf::from),
                    "--evidence" => root = it.next().map(PathBuf::from).unwrap_or(root),
                    _ => return usage(),
                }
            }
            let (Some(tool), Some(digest)) = (tool, digest) else {
                return usage();
            };
            let lock = lock.unwrap_or_else(|| PathBuf::from(lock_rel(&tool)));
            match sha256_file(&lock).and_then(|l| select(&root, &tool, &digest, &l)) {
                Ok(r) => {
                    // `/`-separated: workflows compare it with paths they glob.
                    println!("{}", r.dir.to_string_lossy().replace('\\', "/"));
                    0
                }
                Err(e) => {
                    eprintln!("evidence-rev: {e}");
                    1
                }
            }
        }
        _ => usage(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const T: &str = "cargo-acl";
    const D: &str = "87c159d397e93e88bddbfc76f2549936a09f65e8274564c7eb5d7bd23efdbfa7";
    const L1: &str = "237ed6c17345789ac8a3c751f9a19aa05144808a395ac4ca058fc35c5d5b1d6c";
    const L2: &str = "bd8b6bf7902c00000000000000000000000000000000000000000000000000aa";
    const L3: &str = "cccccccccccc00000000000000000000000000000000000000000000000000cc";

    fn root() -> PathBuf {
        static N: AtomicUsize = AtomicUsize::new(0);
        let d = std::env::temp_dir().join(format!(
            "xtask-evrev-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&d);
        d
    }
    fn vuln(tool: &str, digest: &str, lock: &str, structured: bool) -> String {
        let mut h = serde_json::json!({
            "schema": "hp-thermal/evidence-vuln/v1",
            "subject": {"name": tool, "sha256": digest},
            "lockProvenance": format!("frozen tools/locks/{tool}.lock sha256 {lock}"),
        });
        if structured {
            h["lock"] = serde_json::json!({"path": lock_rel(tool), "sha256": lock});
        }
        format!("{h}\n")
    }
    fn caps(tool: &str, lock: &str) -> String {
        format!(
            "# caps evidence\n# subject: {tool} @ x; frozen tools/locks/{tool}.lock sha256 {lock}\n[api.fs]\n"
        )
    }
    fn build(tool: &str, digest: &str) -> String {
        format!(
            "{}\n",
            serde_json::json!({"schema": "hp-thermal/evidence-build/v1", "subject": {"name": tool, "sha256": digest}})
        )
    }
    fn revision(tool: &str, digest: &str, lock: &str, supersedes: &str) -> String {
        serde_json::json!({
            "schema": SCHEMA,
            "subject": {"name": tool, "sha256": digest},
            "lock": {"path": lock_rel(tool), "sha256": lock},
            "supersedes": {"lock": supersedes},
            "patches": [],
            "reason": "drop UI dependencies",
            "date": "2026-11-15",
            "producer": {"run": "https://github.com/o/r/actions/runs/1"},
        })
        .to_string()
    }
    fn write_record(dir: &Path, tool: &str, digest: &str, lock: &str, structured: bool) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("vuln.jsonl"), vuln(tool, digest, lock, structured)).unwrap();
        std::fs::write(dir.join("caps.toml"), caps(tool, lock)).unwrap();
        std::fs::write(dir.join("build.jsonl"), build(tool, digest)).unwrap();
    }
    /// Revision 1 under L1 plus a valid revision under L2.
    fn store() -> PathBuf {
        let r = root();
        let base = r.join(T).join(D);
        write_record(&base, T, D, L1, false);
        let rev = base.join(REV_DIR).join(L2);
        write_record(&rev, T, D, L2, true);
        std::fs::write(rev.join(REVISION_FILE), revision(T, D, L2, L1)).unwrap();
        r
    }

    #[test]
    fn selects_revision_1_or_the_revision_for_the_current_lock() {
        let r = store();
        let one = select(&r, T, D, L1).unwrap();
        assert!(one.revision.is_none() && one.lock == L1);
        let two = select(&r, T, D, L2).unwrap();
        assert_eq!(two.dir, r.join(T).join(D).join(REV_DIR).join(L2));
        assert_eq!(two.revision.unwrap().supersedes, L1);
    }

    #[test]
    fn no_record_for_the_current_lock_fails() {
        let r = store();
        let e = select(&r, T, D, L3).unwrap_err();
        assert!(e.contains("no evidence measured against lock"), "{e}");
    }

    #[test]
    fn a_revision_for_revision_1s_own_lock_is_refused() {
        let r = store();
        let rev = r.join(T).join(D).join(REV_DIR).join(L1);
        write_record(&rev, T, D, L1, true);
        std::fs::write(rev.join(REVISION_FILE), revision(T, D, L1, L2)).unwrap();
        assert!(select(&r, T, D, L1).unwrap_err().contains("ambiguous"));
    }

    #[test]
    fn directory_revision_and_headers_must_name_the_same_lock() {
        // revision.json names another lock than its directory
        let r = store();
        let rev = r.join(T).join(D).join(REV_DIR).join(L2);
        std::fs::write(rev.join(REVISION_FILE), revision(T, D, L3, L1)).unwrap();
        assert!(select(&r, T, D, L2).is_err());
        // records measured against another lock than the directory
        for f in ["vuln.jsonl", "caps.toml"] {
            let r = store();
            let rev = r.join(T).join(D).join(REV_DIR).join(L2);
            let body = if f == "vuln.jsonl" {
                vuln(T, D, L3, true)
            } else {
                caps(T, L3)
            };
            std::fs::write(rev.join(f), body).unwrap();
            assert!(
                select(&r, T, D, L2).is_err(),
                "{f} under another lock was accepted"
            );
        }
        // records that agree with each other, but on another lock than the directory's
        let r = store();
        let rev = r.join(T).join(D).join(REV_DIR).join(L2);
        std::fs::write(rev.join("vuln.jsonl"), vuln(T, D, L3, true)).unwrap();
        std::fs::write(rev.join("caps.toml"), caps(T, L3)).unwrap();
        let e = select(&r, T, D, L2).unwrap_err();
        assert!(e.contains("measured against lock"), "{e}");
        // structured lock and prose disagree inside one header
        let mut h: Value = serde_json::from_str(vuln(T, D, L2, true).trim()).unwrap();
        h["lockProvenance"] = Value::String(format!("sha256 {L3}"));
        assert!(vuln_lock(&h).is_err());
    }

    #[test]
    fn cross_tool_or_cross_digest_replay_is_refused() {
        let other = "1111111111110000000000000000000000000000000000000000000000000011";
        for (tool, digest) in [("cargo-deny", D), (T, other)] {
            let r = store();
            let rev = r.join(T).join(D).join(REV_DIR).join(L2);
            std::fs::write(rev.join(REVISION_FILE), revision(tool, digest, L2, L1)).unwrap();
            assert!(
                select(&r, T, D, L2).is_err(),
                "revision for {tool} {digest} replayed"
            );
            let r = store();
            let rev = r.join(T).join(D).join(REV_DIR).join(L2);
            write_record(&rev, tool, digest, L2, true);
            assert!(
                select(&r, T, D, L2).is_err(),
                "records for {tool} {digest} replayed"
            );
        }
    }

    #[test]
    fn a_revision_missing_a_record_or_metadata_fails() {
        for f in ["vuln.jsonl", "caps.toml", "build.jsonl", REVISION_FILE] {
            let r = store();
            std::fs::remove_file(r.join(T).join(D).join(REV_DIR).join(L2).join(f)).unwrap();
            assert!(select(&r, T, D, L2).is_err(), "{f} missing was accepted");
        }
        let base = revision(T, D, L2, L1);
        for (k, bad) in [
            ("reason", Value::String(" ".into())),
            ("date", Value::String("15/11/2026".into())),
            ("schema", Value::String("other".into())),
            ("patches", Value::Null),
        ] {
            let mut v: Value = serde_json::from_str(&base).unwrap();
            v[k] = bad;
            assert!(
                parse_revision(&v.to_string(), T, D).is_err(),
                "bad {k} accepted"
            );
        }
        let mut v: Value = serde_json::from_str(&base).unwrap();
        v["producer"]["run"] = Value::String("https://evil.example/actions/runs/1".into());
        assert!(parse_revision(&v.to_string(), T, D).is_err());
        assert!(
            parse_revision(&revision(T, D, L2, L2), T, D).is_err(),
            "self-supersession"
        );
    }

    #[test]
    fn revision_1_must_be_internally_consistent() {
        let r = store();
        std::fs::write(r.join(T).join(D).join("caps.toml"), caps(T, L3)).unwrap();
        assert!(select(&r, T, D, L1).unwrap_err().contains("names"));
        // two different shas in prose is ambiguous, not "the first one"
        let h = serde_json::json!({"subject": {"name": T, "sha256": D},
            "lockProvenance": format!("{L1} then {L2}")});
        assert!(vuln_lock(&h).is_err());
        let two = format!("# subject: {L1}\n# subject: {L1}\n");
        assert!(caps_lock(&two).is_err());
    }

    const BASE_LOCK: &str = "# header\nversion = 4\n\n\
        [[package]]\nname = \"app\"\nversion = \"1.0.0\"\ndependencies = [\n \"obj 0.39.1\",\n \"obj 0.40.0\",\n \"ui\",\n]\n\n\
        [[package]]\nname = \"obj\"\nversion = \"0.39.1\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"aa\"\n\n\
        [[package]]\nname = \"obj\"\nversion = \"0.40.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"bb\"\n\n\
        [[package]]\nname = \"ui\"\nversion = \"2.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"cc\"\n";

    fn narrowed() -> String {
        // drop ui and obj 0.39.1; cargo now spells the remaining edge `"obj"`
        "# header\nversion = 4\n\n\
        [[package]]\nname = \"app\"\nversion = \"1.0.0\"\ndependencies = [\n \"obj\",\n]\n\n\
        [[package]]\nname = \"obj\"\nversion = \"0.40.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"bb\"\n"
            .to_string()
    }

    #[test]
    fn a_narrowing_passes_even_when_cargo_respells_an_edge() {
        let removed = strict_subset(BASE_LOCK, &narrowed()).unwrap();
        assert_eq!(
            removed,
            vec![
                ("obj".into(), "0.39.1".into()),
                ("ui".into(), "2.0.0".into())
            ]
        );
    }

    #[test]
    fn keeping_the_older_version_is_still_only_a_narrowing() {
        // Lock-level, dropping 0.40.0 and keeping 0.39.1 removes packages and changes nothing
        // else, so it passes here. What binds it is admission: the blessed digest must
        // reproduce from this exact lock, which a build that linked 0.40.0 cannot.
        let head = narrowed()
            .replace("version = \"0.40.0\"", "version = \"0.39.1\"")
            .replace("checksum = \"bb\"", "checksum = \"aa\"");
        assert_eq!(strict_subset(BASE_LOCK, &head).unwrap().len(), 2);
    }

    #[test]
    fn anything_but_removal_is_not_a_narrowing() {
        let n = narrowed();
        let cases = [
            (
                "checksum",
                n.replace("checksum = \"bb\"", "checksum = \"bx\""),
            ),
            (
                "source",
                n.replace(
                    "crates.io-index\"\nchecksum = \"bb\"",
                    "crates.io-index-evil\"\nchecksum = \"bb\"",
                ),
            ),
            (
                "new package",
                format!(
                    "{n}\n[[package]]\nname = \"evil\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"ee\"\n"
                ),
            ),
            (
                "version swap",
                n.replace("version = \"0.40.0\"", "version = \"0.40.1\""),
            ),
            (
                "gained edge",
                n.replace(" \"obj\",\n]", " \"obj\",\n \"obj\",\n]")
                    .replace(
                        "dependencies = [\n \"obj\",\n \"obj\",",
                        "dependencies = [\n \"obj\",\n \"ui 2.0.0\",",
                    ),
            ),
            ("outside change", n.replace("version = 4", "version = 3")),
            ("metadata", format!("{n}\n[metadata]\nx = \"y\"\n")),
            (
                "extra field",
                n.replace(
                    "checksum = \"bb\"\n",
                    "checksum = \"bb\"\nreplace = \"z\"\n",
                ),
            ),
            (
                "duplicate",
                format!("{n}\n[[package]]\nname = \"obj\"\nversion = \"0.40.0\"\n"),
            ),
            ("nothing removed", BASE_LOCK.to_string()),
        ];
        for (what, head) in cases {
            assert!(
                strict_subset(BASE_LOCK, &head).is_err(),
                "{what} was accepted"
            );
        }
    }

    #[test]
    fn hex_scanning_takes_whole_runs_only() {
        let s = format!("x{L1}y {L2}0");
        // the second run is 65 chars, not a sha256
        assert_eq!(hex64s(&s), vec![L1.to_string()]);
    }

    // ---------- admission: every way a revision could be smuggled in ----------

    fn sha(t: &str) -> String {
        crate::sha256::sha256_hex(t.as_bytes())
    }
    fn artifact(pkg: &str, ver: &str, features: &[&str]) -> Value {
        serde_json::json!({
            "reason": "compiler-artifact",
            "package_id": format!("registry+https://github.com/rust-lang/crates.io-index#{pkg}@{ver}"),
            "target": {"kind": ["lib"], "crate_types": ["lib"], "name": pkg},
            "profile": {"opt_level": "3"},
            "features": features,
        })
    }
    fn build_with(tool: &str, digest: &str, run: &str, msgs: &[Value]) -> String {
        let mut out = serde_json::json!({
            "schema": "hp-thermal/evidence-build/v1",
            "subject": {"name": tool, "sha256": digest},
            "producerRun": run,
        })
        .to_string();
        out.push('\n');
        for m in msgs {
            out.push_str(&m.to_string());
            out.push('\n');
        }
        out
    }
    fn msgs() -> Vec<Value> {
        vec![
            artifact("obj", "0.40.0", &["std"]),
            artifact("cargo-acl", "0.8.0", &[]),
        ]
    }
    const RUN1: &str = "https://github.com/o/r/actions/runs/1";
    const RUN2: &str = "https://github.com/o/r/actions/runs/2";

    /// The base commit pins D under BASE_LOCK (revision 1); the change narrows the lock and
    /// adds a revision rebuilt by run 2.
    struct Case {
        head: PathBuf,
        base: PathBuf,
        tools_lock: String,
        base_lock: String,
        head_lock: String,
        patches: BTreeMap<String, String>,
    }
    impl Case {
        fn new() -> Case {
            let (base_lock, head_lock) = (BASE_LOCK.to_string(), narrowed());
            let (l1, l2) = (sha(&base_lock), sha(&head_lock));
            let mk = |root: &Path| {
                let d = root.join(T).join(D);
                write_record(&d, T, D, &l1, false);
                std::fs::write(d.join("build.jsonl"), build_with(T, D, RUN1, &msgs())).unwrap();
            };
            let (head, base) = (root(), root());
            mk(&head);
            mk(&base);
            let c = Case {
                head,
                base,
                tools_lock: format!(
                    "# name repo rev target sha\n{T} o/r abc linux-x86_64 {D} # v1\n"
                ),
                base_lock,
                head_lock,
                patches: BTreeMap::new(),
            };
            c.write_rev(&l2, &l1, &c.patches.clone(), &msgs());
            c
        }
        fn rev_dir(&self, lock: &str) -> PathBuf {
            self.head.join(T).join(D).join(REV_DIR).join(lock)
        }
        fn write_rev(
            &self,
            lock: &str,
            supersedes: &str,
            p: &BTreeMap<String, String>,
            m: &[Value],
        ) {
            let d = self.rev_dir(lock);
            write_record(&d, T, D, lock, true);
            std::fs::write(d.join("build.jsonl"), build_with(T, D, RUN2, m)).unwrap();
            let rj = revision_json(T, D, lock, supersedes, "drop UI", "2026-11-16", RUN2, p);
            std::fs::write(d.join(REVISION_FILE), rj).unwrap();
        }
        fn added(&self) -> Added {
            Added {
                tool: T.into(),
                digest: D.into(),
                lock: sha(&self.head_lock),
            }
        }
        fn admit(&self) -> Result<Revision, String> {
            self.admit_as(&self.added())
        }
        fn admit_as(&self, a: &Added) -> Result<Revision, String> {
            admit_offline(
                a,
                &Inputs {
                    root: &self.head,
                    base_root: &self.base,
                    base_tools_lock: &self.tools_lock,
                    base_lock: &self.base_lock,
                    head_lock: &self.head_lock,
                    head_patches: &self.patches,
                },
            )
        }
    }

    #[test]
    fn admits_a_narrowing_of_a_pinned_digest_rebuilt_identically() {
        let c = Case::new();
        let r = c.admit().unwrap();
        assert_eq!(
            (r.lock.as_str(), r.supersedes.as_str()),
            (sha(&c.head_lock).as_str(), sha(&c.base_lock).as_str())
        );
        // and the reader agrees with the writer: the current lock selects the revision
        let rec = select(&c.head, T, D, &sha(&c.head_lock)).unwrap();
        assert_eq!(rec.dir, c.rev_dir(&sha(&c.head_lock)));
    }

    #[test]
    fn refuses_a_digest_the_base_does_not_pin() {
        for tl in [
            format!("{T} o/r abc linux-x86_64 {}\n", "e".repeat(64)),
            format!("# {T} o/r abc linux-x86_64 {D}\n"),
            format!("cargo-deny o/r abc linux-x86_64 {D}\n"),
        ] {
            let mut c = Case::new();
            c.tools_lock = tl.clone();
            assert!(c.admit().unwrap_err().contains("not pinned"), "{tl}");
        }
    }

    #[test]
    fn refuses_a_revision_for_a_lock_the_change_does_not_make_current() {
        let c = Case::new();
        let mut a = c.added();
        a.lock = L3.into();
        assert!(
            c.admit_as(&a)
                .unwrap_err()
                .contains("not the lock this change makes current")
        );
    }

    #[test]
    fn refuses_when_the_lock_did_not_change() {
        let mut c = Case::new();
        c.head_lock = c.base_lock.clone();
        let e = c.admit().unwrap_err();
        assert!(e.contains("revision 1"), "{e}");
    }

    #[test]
    fn refuses_a_revision_that_skips_or_forges_its_predecessor() {
        // claims to supersede a lock that is not the base's
        let c = Case::new();
        let l2 = sha(&c.head_lock);
        c.write_rev(&l2, L3, &BTreeMap::new(), &msgs());
        assert!(c.admit().unwrap_err().contains("supersedes lock"));
        // the superseded record exists only in the change, not in the base commit
        let c = Case::new();
        std::fs::remove_dir_all(c.base.join(T)).unwrap();
        assert!(c.admit().unwrap_err().contains("superseded record"));
        // the base's record was measured against another lock than the base lock
        let c = Case::new();
        write_record(&c.base.join(T).join(D), T, D, L3, false);
        assert!(c.admit().unwrap_err().contains("superseded record"));
    }

    #[test]
    fn refuses_a_lock_that_is_not_a_strict_narrowing() {
        let mut c = Case::new();
        // widened: a package the base never had, under a lock the revision duly names
        c.head_lock = format!(
            "{}\n[[package]]\nname = \"evil\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"ee\"\n",
            narrowed()
        );
        let l = sha(&c.head_lock);
        c.write_rev(&l, &sha(&c.base_lock), &BTreeMap::new(), &msgs());
        assert!(c.admit().unwrap_err().contains("not a narrowing"));
    }

    #[test]
    fn refuses_patches_other_than_the_revision_names() {
        let mut c = Case::new();
        c.patches
            .insert("tools/patches/cargo-acl/0001.patch".into(), "a".repeat(64));
        assert!(c.admit().unwrap_err().contains("patches"));
        // and a revision naming a patch the change does not carry
        let c = Case::new();
        let mut p = BTreeMap::new();
        p.insert(
            "tools/patches/cargo-acl/0001.patch".to_string(),
            "a".repeat(64),
        );
        c.write_rev(&sha(&c.head_lock), &sha(&c.base_lock), &p, &msgs());
        assert!(c.admit().unwrap_err().contains("patches"));
    }

    #[test]
    fn refuses_a_rebuild_whose_cargo_record_differs() {
        for m in [
            vec![
                artifact("obj", "0.40.0", &["std", "write"]),
                artifact("cargo-acl", "0.8.0", &[]),
            ],
            vec![artifact("obj", "0.40.0", &["std"])],
            vec![
                artifact("obj", "0.40.0", &["std"]),
                artifact("cargo-acl", "0.8.0", &[]),
                artifact("ui", "2.0.0", &[]),
            ],
        ] {
            let c = Case::new();
            c.write_rev(&sha(&c.head_lock), &sha(&c.base_lock), &BTreeMap::new(), &m);
            assert!(c.admit().unwrap_err().contains("not the same build"));
        }
    }

    #[test]
    fn revisions_are_append_only_and_well_formed() {
        let c = Case::new();
        // the base already holds a revision; the change carries a new one
        let l2 = sha(&c.head_lock);
        let old = "f".repeat(64);
        for root in [&c.head, &c.base] {
            let d = root.join(T).join(D).join(REV_DIR).join(&old);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("vuln.jsonl"), "x\n").unwrap();
        }
        let (added, problems) = rev_changes(&c.head, &c.base);
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!(
            added.into_iter().map(|a| a.lock).collect::<Vec<_>>(),
            vec![l2.clone()]
        );

        let old_file = c
            .head
            .join(T)
            .join(D)
            .join(REV_DIR)
            .join(&old)
            .join("vuln.jsonl");
        std::fs::write(&old_file, "edited\n").unwrap();
        assert!(
            rev_changes(&c.head, &c.base)
                .1
                .iter()
                .any(|p| p.contains("modified"))
        );
        std::fs::remove_file(&old_file).unwrap();
        assert!(
            rev_changes(&c.head, &c.base)
                .1
                .iter()
                .any(|p| p.contains("deleted"))
        );
        std::fs::write(&old_file, "x\n").unwrap();

        let rev = c.head.join(T).join(D).join(REV_DIR);
        for (what, path) in [
            ("unknown file", rev.join(&l2).join("mal.jsonl")),
            ("file under rev/", rev.join("notes.txt")),
            ("non-sha dir", rev.join("latest").join("vuln.jsonl")),
            ("nested dir", rev.join(&l2).join("sub").join("vuln.jsonl")),
        ] {
            let fresh = !path.parent().unwrap().exists();
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, "x").unwrap();
            assert!(
                !rev_changes(&c.head, &c.base).1.is_empty(),
                "{what} accepted"
            );
            std::fs::remove_file(&path).unwrap();
            if fresh {
                std::fs::remove_dir(path.parent().unwrap()).unwrap();
            }
        }
        assert!(rev_changes(&c.head, &c.base).1.is_empty());
    }

    #[test]
    fn the_producer_binding_names_the_run_lock_and_patches() {
        let c = Case::new();
        let r = c.admit().unwrap();
        let none = BTreeMap::new();
        assert!(bind_producer(&r, RUN2, &r.lock, &none).is_ok());
        assert!(bind_producer(&r, &format!("{RUN2}/"), &r.lock, &none).is_ok());
        // revision 1's record replayed: its run built the old lock
        assert!(
            bind_producer(&r, RUN1, &r.lock, &none)
                .unwrap_err()
                .contains("names producer run")
        );
        assert!(
            bind_producer(&r, RUN2, &r.supersedes, &none)
                .unwrap_err()
                .contains("built from lock")
        );
        let mut p = BTreeMap::new();
        p.insert(
            "tools/patches/cargo-acl/0001.patch".to_string(),
            "a".repeat(64),
        );
        assert!(
            bind_producer(&r, RUN2, &r.lock, &p)
                .unwrap_err()
                .contains("patches")
        );
    }

    #[test]
    fn producer_tree_reads_the_lock_and_patches_from_git_objects() {
        let repo = root();
        std::fs::create_dir_all(repo.join("tools/locks")).unwrap();
        std::fs::create_dir_all(repo.join("tools/patches/t")).unwrap();
        std::fs::write(repo.join("tools/locks/t.lock"), "lock-v2\n").unwrap();
        std::fs::write(repo.join("tools/patches/t/0001.patch"), "p1\n").unwrap();
        std::fs::write(repo.join("tools/patches/other.txt"), "not t's\n").unwrap();
        let git = |args: &[&str]| -> String {
            let out = std::process::Command::new("git")
                .arg("-C")
                .arg(&repo)
                .args(["-c", "core.autocrlf=false"])
                .args(args)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        git(&["init", "--quiet"]);
        git(&["add", "-A"]);
        let tree = git(&["write-tree"]);
        let (lock, patches) = producer_tree(&repo, &tree, "t").unwrap();
        assert_eq!(lock, sha("lock-v2\n"));
        assert_eq!(patches.len(), 1);
        assert_eq!(patches["tools/patches/t/0001.patch"], sha("p1\n"));
        assert!(
            producer_tree(&repo, &tree, "absent").is_err(),
            "no lock at the commit is an error"
        );
    }

    fn audit(
        vulns: &[(&str, &str, &str)],
        warn: &[(&str, &str, &str, &str)],
        count: Option<u64>,
    ) -> Value {
        let mut w = serde_json::Map::new();
        for (kind, id, p, v) in warn {
            w.entry(kind.to_string()).or_insert_with(|| Value::Array(vec![])).as_array_mut().unwrap().push(
                serde_json::json!({"kind": kind, "advisory": {"id": id, "aliases": []}, "package": {"name": p, "version": v}}),
            );
        }
        let mut a = serde_json::json!({
            "vulnerabilities": {"list": vulns.iter().map(|(id, p, v)| serde_json::json!({"advisory": {"id": id, "aliases": []}, "package": {"name": p, "version": v}})).collect::<Vec<_>>()},
            "warnings": w,
        });
        if let Some(n) = count {
            a["lockfile"] = serde_json::json!({"dependency-count": n});
        }
        a
    }

    #[test]
    fn vuln_rows_must_be_the_raw_payloads_and_the_payload_this_locks() {
        let lock = narrowed(); // app 1.0.0, obj 0.40.0
        let raw = audit(&[("RUSTSEC-1", "obj", "0.40.0")], &[], Some(2));
        let rows = crate::record_vuln::instance_rows(&raw);
        assert!(check_vuln_rows(&rows, &raw, &lock).is_ok());
        assert!(
            check_vuln_rows(&[], &raw, &lock).is_err(),
            "a dropped finding"
        );
        let mut extra = rows.clone();
        extra.push(serde_json::json!({"id": "RUSTSEC-2", "aliases": [], "package": "obj", "version": "0.40.0", "kind": "vulnerability"}));
        assert!(
            check_vuln_rows(&extra, &raw, &lock).is_err(),
            "an invented finding"
        );
        // a payload that scanned the wider base lock
        let wide = audit(&[("RUSTSEC-1", "obj", "0.40.0")], &[], Some(4));
        assert!(check_vuln_rows(&crate::record_vuln::instance_rows(&wide), &wide, &lock).is_err());
        let gone = audit(&[("RUSTSEC-3", "ui", "2.0.0")], &[], Some(2));
        assert!(check_vuln_rows(&crate::record_vuln::instance_rows(&gone), &gone, &lock).is_err());
        let uncounted = audit(&[], &[], None);
        assert!(check_vuln_rows(&[], &uncounted, &lock).is_err());
    }

    #[test]
    fn a_rescan_must_reproduce_every_database_finding() {
        let rec = audit(
            &[("RUSTSEC-1", "obj", "0.40.0")],
            &[("yanked", "yanked", "obj", "0.40.0")],
            Some(2),
        );
        let rows = crate::record_vuln::instance_rows(&rec);
        // yanked reads crates.io at scan time; an offline re-scan cannot reproduce it
        let rescan = audit(&[("RUSTSEC-1", "obj", "0.40.0")], &[], Some(2));
        assert!(check_rescan(&rows, &rescan).is_ok());
        let more = audit(
            &[("RUSTSEC-1", "obj", "0.40.0")],
            &[("unsound", "RUSTSEC-9", "obj", "0.40.0")],
            Some(2),
        );
        assert!(
            check_rescan(&rows, &more)
                .unwrap_err()
                .contains("RUSTSEC-9"),
            "an omitted finding"
        );
        let fewer = audit(&[], &[], Some(2));
        assert!(check_rescan(&rows, &fewer).is_err(), "a fabricated finding");
    }

    #[test]
    fn writers_put_a_revision_where_readers_select_it() {
        let c = Case::new();
        let (l1, l2) = (sha(&c.base_lock), sha(&c.head_lock));
        let r = root();
        write_record(&r.join(T).join(D), T, D, &l1, false);
        std::fs::write(r.join(T).join(D).join("build.jsonl"), build(T, D)).unwrap();
        assert_eq!(
            write_dir(&r, T, D, &l2, false).unwrap(),
            (r.join(T).join(D), false),
            "candidate: in place"
        );
        assert!(
            write_dir(&r, T, D, &l1, true)
                .unwrap_err()
                .contains("never edited")
        );
        let (dir, is_rev) = write_dir(&r, T, D, &l2, true).unwrap();
        assert!(is_rev);
        write_record(&dir, T, D, &l2, true);
        std::fs::write(
            dir.join(REVISION_FILE),
            revision_json(T, D, &l2, &l1, "x", "2026-11-16", RUN2, &BTreeMap::new()),
        )
        .unwrap();
        assert_eq!(select(&r, T, D, &l2).unwrap().dir, dir);
        // current(): the frozen lock decides; without one, only revision 1 and only alone
        let locks = root();
        std::fs::create_dir_all(&locks).unwrap();
        std::fs::write(locks.join(format!("{T}.lock")), &c.head_lock).unwrap();
        assert_eq!(current(&r, &locks, T, D).unwrap().dir, dir);
        assert!(
            current(&r, &root(), T, D)
                .unwrap_err()
                .contains("revisions exist")
        );
        let lone = root();
        write_record(&lone.join(T).join(D), T, D, &l1, false);
        assert_eq!(
            current(&lone, &root(), T, D).unwrap().dir,
            lone.join(T).join(D)
        );
    }

    #[test]
    fn revision_json_round_trips_through_its_parser() {
        let mut p = BTreeMap::new();
        p.insert(
            "tools/patches/cargo-acl/0001.patch".to_string(),
            "a".repeat(64),
        );
        let text = revision_json(T, D, L2, L1, "drop UI", "2026-11-16", RUN2, &p);
        let r = parse_revision(&text, T, D).unwrap();
        assert_eq!(
            r,
            Revision {
                lock: L2.into(),
                supersedes: L1.into(),
                reason: "drop UI".into(),
                date: "2026-11-16".into(),
                producer_run: RUN2.into(),
                patches: p,
            }
        );
    }

    #[test]
    fn patches_are_hashed_flat() {
        let repo = root();
        let d = repo.join("tools/patches/t");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("0001.patch"), "p\n").unwrap();
        std::fs::write(d.join("patch.json"), "{}").unwrap();
        let p = patches_of(&repo, "t").unwrap();
        assert_eq!(
            p.keys().cloned().collect::<Vec<_>>(),
            vec!["tools/patches/t/0001.patch", "tools/patches/t/patch.json"]
        );
        assert!(patches_of(&repo, "none").unwrap().is_empty());
        std::fs::create_dir_all(d.join("sub")).unwrap();
        assert!(patches_of(&repo, "t").is_err());
    }

    #[test]
    fn a_revisions_report_may_move_forward_its_records_may_not() {
        let c = Case::new();
        let old = "f".repeat(64);
        for root in [&c.head, &c.base] {
            let d = root.join(T).join(D).join(REV_DIR).join(&old);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("vuln.jsonl"), "x\n").unwrap();
            std::fs::write(d.join("vdr.cdx.json"), "v1\n").unwrap();
        }
        let d = c.head.join(T).join(D).join(REV_DIR).join(&old);
        std::fs::write(d.join("vdr.cdx.json"), "v2\n").unwrap();
        assert!(
            rev_changes(&c.head, &c.base).1.is_empty(),
            "a re-emitted report"
        );
        std::fs::remove_file(d.join("vdr.cdx.json")).unwrap();
        assert!(
            rev_changes(&c.head, &c.base)
                .1
                .iter()
                .any(|p| p.contains("deleted"))
        );
        std::fs::write(d.join("vdr.cdx.json"), "v1\n").unwrap();
        // an admitted revision takes no new record, and its arrival is not a new revision
        std::fs::write(d.join("caps.toml"), "x").unwrap();
        let (added, problems) = rev_changes(&c.head, &c.base);
        assert!(
            problems.iter().any(|p| p.contains("already admitted")),
            "{problems:?}"
        );
        assert!(added.iter().all(|a| a.lock != old));
        std::fs::remove_file(d.join("caps.toml")).unwrap();
        // a report arriving later for an admitted revision is fine and adds no revision
        let late = c.head.join(T).join(D).join(REV_DIR).join("e".repeat(64));
        let late_base = c.base.join(T).join(D).join(REV_DIR).join("e".repeat(64));
        std::fs::create_dir_all(&late_base).unwrap();
        std::fs::write(late_base.join("vuln.jsonl"), "x\n").unwrap();
        std::fs::create_dir_all(&late).unwrap();
        std::fs::write(late.join("vuln.jsonl"), "x\n").unwrap();
        std::fs::write(late.join("vdr.cdx.json"), "v\n").unwrap();
        let (added, problems) = rev_changes(&c.head, &c.base);
        assert!(problems.is_empty(), "{problems:?}");
        assert!(added.iter().all(|a| a.lock != "e".repeat(64)));
    }

    #[test]
    fn lock_values_are_cargos_basic_strings_and_sources_bind() {
        // A literal string reads as no value; it must not compare equal to an absent field.
        let sneaky = narrowed().replace(
            "name = \"app\"\nversion = \"1.0.0\"\n",
            "name = \"app\"\nversion = \"1.0.0\"\nsource = 'registry+https://evil.example/index'\n",
        );
        assert!(
            strict_subset(BASE_LOCK, &sneaky)
                .unwrap_err()
                .contains("double-quoted")
        );
        let literal_sum = narrowed().replace("checksum = \"bb\"", "checksum = 'bb'");
        assert!(strict_subset(BASE_LOCK, &literal_sum).is_err());
        // `"name version (source)"` must name the package's own source
        let good = narrowed().replace(
            " \"obj\",\n]",
            " \"obj 0.40.0 (registry+https://github.com/rust-lang/crates.io-index)\",\n]",
        );
        assert!(strict_subset(BASE_LOCK, &good).is_ok());
        let bad = good.replace(
            "(registry+https://github.com/rust-lang/crates.io-index)",
            "(registry+https://evil.example/index)",
        );
        assert!(
            strict_subset(BASE_LOCK, &bad)
                .unwrap_err()
                .contains("another source")
        );
    }

    #[test]
    fn the_headers_advisory_db_is_the_raw_payloads() {
        let commit = "a".repeat(40);
        let h = serde_json::json!({"scanner": {"db": {"version": commit}}});
        let raw = |c: Option<&str>| serde_json::json!({"database": {"last-commit": c}});
        assert_eq!(record_db(&h, &raw(Some(&commit))).unwrap(), commit);
        assert!(
            record_db(&h, &raw(Some(&"b".repeat(40))))
                .unwrap_err()
                .contains("unbacked")
        );
        assert!(
            record_db(&h, &raw(None))
                .unwrap_err()
                .contains("--no-fetch")
        );
        let short = serde_json::json!({"scanner": {"db": {"version": "abc"}}});
        assert!(record_db(&short, &raw(Some("abc"))).is_err());
    }
}
