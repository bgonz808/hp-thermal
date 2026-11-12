//! `cargo xtask freeze` — turn an explored candidate into a REPRODUCIBLE build input (#241).
//!
//! The promotion pipeline's trust boundary. Exploration reasons about un-vetted newer
//! versions; freezing captures one specific resolution as a committed artifact, after which
//! the candidate is 100% pinned and every later build is `--locked` against THIS lock. Put
//! precisely: **non-`--locked` is a discovery property, never a build-output property.** We
//! never bless a floating build — we bless the frozen resolution that discovery proposed.
//!
//! `--base tools/locks/<tool>.lock` applies the directives atop an EXISTING frozen
//! resolution instead of upstream's lock. A curated lock's history is not replayable as
//! precise-updates (cargo-audit's rand 0.9->0.10 crossing came through the explorer's
//! escalation ladder), so incremental fixes need the curated tree as their starting point;
//! "before" is then the posture we actually ship. The lockfile SHAPE invariant runs in both
//! modes: directives may move versions and prune, never introduce a package name.
//!
//! `--patches tools/patches/<tool>` stages the tool's patches onto the checkout before the
//! lock, in the producer's order, `git apply --check`ed first (fail-closed supersession).
//! `--require-improvement` refuses a run that fixes zero instances: with "no regression"
//! already enforced, that is the other half of the strictly-better certificate the autonomous
//! path needs. Every directive is attempted and every refusal reported before failing; on any
//! refusal nothing is written and no delta is computed -- a partial set is not the reviewed set.
//!
//! Output is `tools/locks/<tool>.lock`: a resolved Cargo.lock that the producer builds with
//! INSTEAD of upstream's. Deliberately a convention-based path rather than a 6th TOOLS.lock
//! column — `gate::parse_tools_lock` requires exactly 5 fields, so a 6-column line would be
//! SILENTLY SKIPPED (a tool left unverified), and bash `read -r name repo rev target sha`
//! would fold the extra field into `sha` and break digest verification. Adding a file breaks
//! no parser; changing the format breaks several.
//!
//! Safety properties, all enforced here rather than assumed:
//!   * every target version is checked NON-YANKED and PAST SOAK on crates.io before use;
//!   * the advisory delta is computed at ONE DB state (before vs after, same instrument);
//!   * a freeze that introduces a GENUINELY NEW advisory — a new (advisory, package) key, or
//!     a second vulnerable resident version — is refused by default (#255 §4). The same
//!     advisory carried onto a bumped version is reported as UNFIXED but never blocks:
//!     refusal keys on risk, not version movement. Trading one advisory for another
//!     remains a human decision (--allow-added-advisories records it deliberately);
//!   * nothing is blessed: the digest still comes from a producer run over this lock, and the
//!     #241 gate still evaluates it. This only makes the candidate reproducible.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::explore::{age_days, line_of, parse_ver};
use crate::gate::{Instance, extract_instances, run_audit};

/// One `pkg=version` (or `pkg@current=version`) promotion directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directive {
    pub package: String,
    pub version: String,
    /// The CURRENT resident version to move, for multi-version crates (#255 §2). Cargo
    /// coexists semver-incompatible versions of one crate (e.g. getrandom 0.2.7 AND
    /// 0.3.3), making a bare `-p pkg` spec ambiguous; `pkg@current` selects exactly one
    /// copy, leaving the others untouched.
    pub at: Option<String>,
}

impl Directive {
    /// The cargo package spec: `pkg@current` when disambiguated, else the bare name.
    pub fn spec(&self) -> String {
        match &self.at {
            Some(cur) => format!("{}@{cur}", self.package),
            None => self.package.clone(),
        }
    }
}

/// Enumerate `*.patch` files under an ABSOLUTE patches dir, sorted (producer order). Every
/// returned path is absolute so it survives a `git apply` whose cwd is the staged checkout.
pub fn patch_files(abs_dir: &std::path::Path) -> std::io::Result<Vec<PathBuf>> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(abs_dir)?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "patch"))
        .collect();
    files.sort();
    Ok(files)
}

/// Parse `pkg=version` / `pkg@current=version`. Rejects empty halves and non-semver
/// versions on BOTH sides of `@` — a directive names concrete crates.io releases,
/// never ranges or tags.
pub fn parse_directive(s: &str) -> Result<Directive, String> {
    let (left, v) = s
        .split_once('=')
        .ok_or_else(|| format!("directive '{s}' must be <package>[@current]=<version>"))?;
    let (p, at) = match left.split_once('@') {
        Some((p, cur)) => {
            if parse_ver(cur.trim()).is_none() {
                return Err(format!(
                    "directive '{s}': current version '{cur}' is not concrete MAJOR.MINOR.PATCH"
                ));
            }
            (p, Some(cur.trim().to_string()))
        }
        None => (left, None),
    };
    if p.trim().is_empty() || v.trim().is_empty() {
        return Err(format!("directive '{s}' has an empty package or version"));
    }
    if parse_ver(v.trim()).is_none() {
        return Err(format!(
            "directive '{s}': '{v}' is not a concrete MAJOR.MINOR.PATCH release"
        ));
    }
    Ok(Directive {
        package: p.trim().to_string(),
        version: v.trim().to_string(),
        at,
    })
}

/// Verify a directive's target is safe to adopt: exists, not yanked, and past soak.
/// Returns the version's age in days.
/// The set of package NAMES in a Cargo.lock. Names, not (name, version): the shape invariant
/// asks "did anything new enter the tree", and a version move is not entry. Parses the
/// `[[package]]` / `name = "..."` lines directly -- xtask carries one dependency by design,
/// and this is the only field the invariant needs.
pub fn lock_package_names(path: &Path) -> Result<BTreeSet<String>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(lock_package_names_from_str(&text))
}

/// Pure form of `lock_package_names`, so the invariant is testable without a filesystem.
pub fn lock_package_names_from_str(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut in_pkg = false;
    for line in text.lines() {
        let l = line.trim();
        if l == "[[package]]" {
            in_pkg = true;
            continue;
        }
        if l.starts_with('[') {
            in_pkg = false;
            continue;
        }
        if in_pkg
            && let Some(rest) = l.strip_prefix("name = \"")
            && let Some(end) = rest.find('"')
        {
            out.insert(rest[..end].to_string());
        }
    }
    out
}

/// `name -> resident versions` of a Cargo.lock (several when semver-incompatible copies coexist).
pub fn lock_package_versions(text: &str) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut in_pkg = false;
    let mut name: Option<String> = None;
    for line in text.lines() {
        let l = line.trim();
        if l == "[[package]]" {
            in_pkg = true;
            name = None;
            continue;
        }
        if l.starts_with('[') {
            in_pkg = false;
            continue;
        }
        if !in_pkg {
            continue;
        }
        if let Some(rest) = l.strip_prefix("name = \"") {
            name = rest.split('"').next().map(str::to_string);
        } else if let Some(rest) = l.strip_prefix("version = \"")
            && let Some(n) = &name
            && let Some(v) = rest.split('"').next()
        {
            out.entry(n.clone()).or_default().push(v.to_string());
        }
    }
    out
}

/// Highest resident version by canonical semver (`parse_ver`); unparseable versions sort last.
fn max_version(vs: &[String]) -> Option<&String> {
    vs.iter().max_by_key(|v| parse_ver(v))
}

/// Resident versions grouped by semver LINE (major, or 0.minor): Cargo coexists lines, and a
/// dependent switching from `syn ^3` to `syn ^2` is upstream choosing a line, not a rollback.
fn by_line(vs: &[String]) -> BTreeMap<(u64, u64), Vec<String>> {
    let mut m: BTreeMap<(u64, u64), Vec<String>> = BTreeMap::new();
    for v in vs {
        if let Some(pv) = parse_ver(v) {
            m.entry(line_of(pv)).or_default().push(v.clone());
        }
    }
    m
}

/// Rollbacks WITHIN a semver line: for every (package, line) resident on both sides, the
/// highest `after` version is lower than the highest `prior` version. `(name, prior, after)`.
/// A line present only in `prior` is not a downgrade (see `dropped_lines`): upstream's manifest
/// no longer resolves that line, and a directive cannot cross lines without a manifest change.
pub fn downgrades(
    after: &BTreeMap<String, Vec<String>>,
    prior: &BTreeMap<String, Vec<String>>,
) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for (n, pv) in prior {
        let Some(av) = after.get(n) else { continue };
        let (pl, al) = (by_line(pv), by_line(av));
        for (line, pvs) in &pl {
            let Some(avs) = al.get(line) else { continue };
            if let (Some(p), Some(a)) = (max_version(pvs), max_version(avs))
                && let (Some(pp), Some(aa)) = (parse_ver(p), parse_ver(a))
                && aa < pp
            {
                out.push((n.clone(), p.clone(), a.clone()));
            }
        }
    }
    out
}

/// Semver lines we shipped that the new resolution no longer contains at all (`name line-max`):
/// reported, never auto-restored — that is upstream's dependency choice, reviewed through the
/// caps and vuln axes like any other change to the tree.
pub fn dropped_lines(
    after: &BTreeMap<String, Vec<String>>,
    prior: &BTreeMap<String, Vec<String>>,
) -> Vec<String> {
    let mut out = Vec::new();
    for (n, pv) in prior {
        let al = after.get(n).map(|v| by_line(v)).unwrap_or_default();
        for (line, pvs) in by_line(pv) {
            if !al.contains_key(&line)
                && let Some(p) = max_version(&pvs)
            {
                out.push(format!("{n} {p}"));
            }
        }
    }
    out
}

/// Directives that lift every within-line rollback back to the prior blessed version, skipping
/// packages the explicit directives already name. `at` is the resident version in that line, so
/// the spec stays unambiguous when several lines coexist.
pub fn carry_forward_directives(
    start: &BTreeMap<String, Vec<String>>,
    prior: &BTreeMap<String, Vec<String>>,
    explicit: &[Directive],
) -> Vec<Directive> {
    downgrades(start, prior)
        .into_iter()
        .filter(|(n, _, _)| !explicit.iter().any(|d| &d.package == n))
        .map(|(n, p, a)| Directive {
            package: n,
            version: p,
            at: Some(a),
        })
        .collect()
}

/// The `cargo update -p` spec for a directive against the lock AS IT STANDS: bare when exactly
/// one version of the package is resident (unambiguous, and immune to an earlier directive
/// having moved it), `pkg@current` when several coexist.
pub fn spec_for(resident: &BTreeMap<String, Vec<String>>, d: &Directive) -> String {
    match resident.get(&d.package) {
        Some(vs) if vs.len() == 1 => d.package.clone(),
        Some(vs) => match &d.at {
            Some(cur) if vs.contains(cur) => format!("{}@{cur}", d.package),
            _ => d.package.clone(),
        },
        None => d.spec(),
    }
}

/// Names present after the directives that were not present before. Non-empty means the
/// change was not a drop-in, whatever the advisory delta says.
pub fn added_package_names(before: &BTreeSet<String>, after: &BTreeSet<String>) -> Vec<String> {
    after.difference(before).cloned().collect()
}

pub fn check_target(d: &Directive, now_epoch: i64, soak_days: i64) -> Result<i64, String> {
    let url = format!(
        "https://crates.io/api/v1/crates/{}/{}",
        d.package, d.version
    );
    let out = Command::new("curl")
        .args(["-sSfL", "-H", "User-Agent: hp-thermal-freeze", &url])
        .output()
        .map_err(|e| format!("curl: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "{} {} not found on crates.io",
            d.package, d.version
        ));
    }
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).map_err(|e| format!("crates.io JSON: {e}"))?;
    if v.pointer("/version/yanked")
        .and_then(|y| y.as_bool())
        .unwrap_or(false)
    {
        return Err(format!(
            "{} {} is YANKED — never a promotion target",
            d.package, d.version
        ));
    }
    let created = v
        .pointer("/version/created_at")
        .and_then(|c| c.as_str())
        .ok_or_else(|| format!("{} {}: no publish date", d.package, d.version))?;
    let age = age_days(created, now_epoch)
        .ok_or_else(|| format!("{} {}: unparseable publish date", d.package, d.version))?;
    if age < soak_days {
        return Err(format!(
            "{} {} is {age}d old — has not soaked ({soak_days}d required)",
            d.package, d.version
        ));
    }
    Ok(age)
}

/// A quality-passing `lock-shape` statement accepting package `name` for `tool`.
pub fn lock_shape_accepted(acks: &crate::gate::Acks, tool: &str, name: &str) -> bool {
    acks.entries.iter().any(|a| {
        a.get("axis").and_then(|v| v.as_str()) == Some("lock-shape")
            && a.pointer("/product/name").and_then(|v| v.as_str()) == Some(tool)
            && a.pointer("/package/name").and_then(|v| v.as_str()) == Some(name)
    })
}

/// The statement a maintainer commits to accept a new package name. `status_notes` is empty on
/// purpose: the quality bar refuses it until the review is written down.
pub fn lock_shape_template(tool: &str, name: &str) -> String {
    serde_json::json!({
        "schema": "hp-thermal/evidence-ack/v1",
        "axis": "lock-shape",
        "product": {"name": tool},
        "package": {"name": name},
        "status": "reviewed",
        "status_notes": "",
        "author": "",
        "timestamp": "",
        "refs": []
    })
    .to_string()
}

/// Instances present after the freeze but not before — the thing a freeze must never add.
pub fn added_instances(before: &BTreeSet<Instance>, after: &BTreeSet<Instance>) -> Vec<Instance> {
    let key = |i: &Instance| (i.id.clone(), i.package.clone(), i.version.clone());
    let before_keys: BTreeSet<_> = before.iter().map(key).collect();
    after
        .iter()
        .filter(|i| !before_keys.contains(&key(i)))
        .cloned()
        .collect()
}

/// Instances removed by the freeze — the improvement being claimed.
pub fn removed_instances(before: &BTreeSet<Instance>, after: &BTreeSet<Instance>) -> Vec<Instance> {
    let key = |i: &Instance| (i.id.clone(), i.package.clone(), i.version.clone());
    let after_keys: BTreeSet<_> = after.iter().map(key).collect();
    before
        .iter()
        .filter(|i| !after_keys.contains(&key(i)))
        .cloned()
        .collect()
}

/// Instances present, unchanged, on both sides (same id, package, version): the residue a
/// certified change leaves for the maintainer. Listed by name so the output IS the queue.
pub fn carried_instances(before: &BTreeSet<Instance>, after: &BTreeSet<Instance>) -> Vec<Instance> {
    let key = |i: &Instance| (i.id.clone(), i.package.clone(), i.version.clone());
    let bk: BTreeSet<_> = before.iter().map(key).collect();
    after
        .iter()
        .filter(|i| bk.contains(&key(i)))
        .cloned()
        .collect()
}

/// Split the instance-level "added" set into what actually matters for REFUSAL (#255 §4).
///
/// Instance tuples (id, package, version) stay the identity for evidence and acks
/// (#241 §6), but the refusal rule must key on RISK, not on version movement: a bump
/// that carries the SAME advisory onto the new version (h2 0.3.13 -> 0.3.27, both
/// hit by RUSTSEC-2026-0258) did not fix that advisory — but it introduced no new
/// risk either, and refusing it blocks a batch that is otherwise a pure improvement.
///
/// Per (advisory-id, package) key:
///   * key absent before, present after            -> GENUINE regression (refuse);
///   * key present in both, instance COUNT grew    -> GENUINE regression (a second
///     vulnerable resident version doubles exposure — the #241 §6 case);
///   * key present in both, count same/shrunk, but
///     the version moved                           -> UNFIXED-carried (report, allow).
///
/// The (id, package) pair — not the bare id — is the key because warning kinds
/// without an advisory id (`yanked`) use the kind as the id: bare-id keying would
/// let a NEWLY-yanked package hide behind any pre-existing yanked finding.
pub fn split_regressions(
    before: &BTreeSet<Instance>,
    after: &BTreeSet<Instance>,
) -> (Vec<Instance>, Vec<Instance>) {
    use std::collections::BTreeMap;
    let count_by_key = |set: &BTreeSet<Instance>| -> BTreeMap<(String, String), usize> {
        let mut m = BTreeMap::new();
        for i in set {
            *m.entry((i.id.clone(), i.package.clone())).or_insert(0) += 1;
        }
        m
    };
    let before_counts = count_by_key(before);
    let after_counts = count_by_key(after);
    let mut genuine = Vec::new();
    let mut unfixed = Vec::new();
    for inst in added_instances(before, after) {
        let k = (inst.id.clone(), inst.package.clone());
        let was = before_counts.get(&k).copied().unwrap_or(0);
        let now = after_counts.get(&k).copied().unwrap_or(0);
        if was == 0 || now > was {
            genuine.push(inst);
        } else {
            unfixed.push(inst);
        }
    }
    (genuine, unfixed)
}

fn git(args: &[&str], cwd: Option<&Path>) -> Result<(), String> {
    let mut c = Command::new("git");
    c.args(args);
    if let Some(d) = cwd {
        c.current_dir(d);
    }
    let st = c.status().map_err(|e| format!("git: {e}"))?;
    st.success()
        .then_some(())
        .ok_or_else(|| format!("git {:?} failed", args))
}

pub fn run(args: &[String]) -> i32 {
    let mut tool = String::new();
    let mut repo = String::new();
    let mut rev = String::new();
    let mut directives: Vec<String> = Vec::new();
    let mut out_dir = PathBuf::from("tools/locks");
    let mut soak = crate::explore::SOAK_DAYS;
    let mut now_epoch: i64 = 0;
    let mut allow_added = false;
    let mut dry_run = false;
    // --base <lock>: apply directives atop an EXISTING frozen resolution instead of upstream's
    // lock. Needed because a curated lock's history is not replayable as precise-updates (the
    // cargo-audit rand 0.9->0.10 crossing used the explorer's escalation ladder); without this,
    // incremental fixes had to be applied by hand-verified staged checkout, outside freeze's
    // soak/yank/advisory-delta ladder. The "before" posture becomes the base lock's posture.
    let mut base: Option<PathBuf> = None;
    // --patches <dir>: stage tools/patches/<tool>/*.patch onto the checkout BEFORE the lock,
    // in the producer's exact order. A curated lock built against patched manifests (cargo-vet's
    // keystone) cannot be resolved against unpatched ones; without staging, --base would
    // re-resolve the tree instead of applying directives atop it. Each patch is `git apply
    // --check`ed first: a patch that no longer applies is a hard stop, same as the producer.
    let mut patches: Option<PathBuf> = None;
    // --require-improvement: refuse unless at least one instance is FIXED. freeze alone only
    // refuses regressions (genuinely added); the autonomous "strictly better" certificate needs
    // the other half -- a change that fixes nothing is not better, however clean its delta
    // (measured: ruzstd 0.8.3 is newer than 0.8.2 and clears nothing, 0 fixed / 2 -> 2).
    let mut require_improvement = false;
    // --accept-new-package <name>: a REVIEWED exception to the lockfile shape invariant. The
    // invariant refuses any new package name because that is the shape a smuggled crate takes;
    // when a legitimate fix cannot avoid pulling one in (tokio 1.51 -> windows-link), the human
    // review the refusal asks for is recorded as a `lock-shape` statement in the tool's ack
    // lattice, and this flag names the package. Without the statement the flag does nothing:
    // the acceptance lives in a signed, committed line, not in a command-line argument.
    let mut accept_new: Vec<String> = Vec::new();
    let mut evidence_dir = PathBuf::from("supply-chain/evidence");
    // --prior-lock <lock>: the resolution we PREVIOUSLY blessed for this tool (tools/locks/<tool>.lock
    // on main). A rev bump starts from upstream's committed lock, which may be months older than
    // our curation, so without this the "delta" would be measured against a baseline we never
    // shipped: 122 packages resolved LOWER than our blessed cargo-vet lock when v0.10.3 was first
    // frozen (2026-11-12). Three effects: names already in the prior lock are not "new" to the
    // shape invariant (they were blessed, for this tool); every package resolved below its prior
    // version is a REGRESSION and refuses the write unless --allow-downgrade names it; and
    // --carry-forward adds directives that lift such packages back to the prior version first.
    let mut prior_lock: Option<PathBuf> = None;
    let mut carry_forward = false;
    let mut allow_downgrade: Vec<String> = Vec::new();
    let mut soak_overridden = false;
    let mut now_overridden = false;
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--tool" => tool = it.next().cloned().unwrap_or_default(),
            "--repo" => repo = it.next().cloned().unwrap_or_default(),
            "--rev" => rev = it.next().cloned().unwrap_or_default(),
            "--update" => {
                if let Some(v) = it.next() {
                    directives.push(v.clone());
                }
            }
            "--out-dir" => {
                if let Some(v) = it.next() {
                    out_dir = v.into();
                }
            }
            // TIME/POLICY OVERRIDES ARE RESEARCH-ONLY (see the guard below `--dry-run`):
            // they can only ever produce a report, never a written lock. Tracked so the guard
            // can tell "maintainer passed a value" from "default".
            "--soak-days" => {
                soak = it.next().and_then(|v| v.parse().ok()).unwrap_or(soak);
                soak_overridden = true;
            }
            "--now-epoch" => {
                now_epoch = it.next().and_then(|v| v.parse().ok()).unwrap_or(0);
                now_overridden = now_epoch != 0;
            }
            // Escape hatch for a deliberate, reviewed trade — never the default.
            "--allow-added-advisories" => allow_added = true,
            // Evaluate + report the full delta, write NOTHING. The safe way to try a batch:
            // see which directives are reachable and what they'd buy before committing a lock.
            "--dry-run" => dry_run = true,
            "--base" => base = it.next().map(PathBuf::from),
            "--patches" => patches = it.next().map(PathBuf::from),
            "--require-improvement" => require_improvement = true,
            "--accept-new-package" => {
                if let Some(v) = it.next() {
                    accept_new.push(v.clone());
                }
            }
            "--evidence" => {
                if let Some(v) = it.next() {
                    evidence_dir = PathBuf::from(v);
                }
            }
            "--prior-lock" => prior_lock = it.next().map(PathBuf::from),
            "--carry-forward" => carry_forward = true,
            "--allow-downgrade" => {
                if let Some(v) = it.next() {
                    allow_downgrade.push(v.clone());
                }
            }
            other => {
                eprintln!("freeze: unknown arg {other}");
                return 2;
            }
        }
    }
    // FAIL-CLOSED (#264): a soak verdict computed against overridden time or a loosened
    // threshold is a RESEARCH result, not a safety result. Such a run may print a report but
    // must never produce a lock, because a lock carries no record of the clock that judged it
    // -- downstream (gate, producer, bless) would read a forged-soak lock as indistinguishable
    // from an honest one. Refusing to WRITE is the property that makes the override safe: it
    // cannot manufacture a belief in safety that was never checked.
    if (now_overridden || soak_overridden) && !dry_run {
        eprintln!(
            "freeze: --now-epoch / --soak-days are research-only overrides and require --dry-run.
                    A lock records no evidence of the clock or threshold used, so a written lock
                    must always be judged by real time against the committed policy (#264)."
        );
        return 2;
    }
    if tool.is_empty() || repo.is_empty() || rev.is_empty() || directives.is_empty() {
        eprintln!(
            "usage: cargo xtask freeze --tool <name> --repo <owner/repo> --rev <sha> \\\n\
             \x20         --update <pkg>[@cur]=<ver> [--update ...] [--soak-days N] [--out-dir DIR] [--dry-run]"
        );
        return 2;
    }
    if now_overridden || soak_overridden {
        println!(
            "# RESEARCH RUN -- overridden instruments: now-epoch={} soak-days={}. Dry-run only;
             # no lock can be written from this run, and its soak verdicts are NOT safety claims.",
            if now_overridden {
                now_epoch.to_string()
            } else {
                "real".into()
            },
            soak
        );
    }
    if now_epoch == 0 {
        now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
    }

    // 1. Parse + SAFETY-CHECK every directive before touching a repo.
    let mut parsed = Vec::new();
    for d in &directives {
        match parse_directive(d) {
            Ok(p) => parsed.push(p),
            Err(e) => {
                eprintln!("freeze: {e}");
                return 2;
            }
        }
    }
    println!(
        "# freeze {tool} @ {} ({} directive(s))",
        &rev[..12.min(rev.len())],
        parsed.len()
    );
    for p in &parsed {
        match check_target(p, now_epoch, soak) {
            Ok(age) => println!(
                "  target OK: {} {} ({age}d old, not yanked)",
                p.package, p.version
            ),
            Err(e) => {
                eprintln!("  REFUSED: {e}");
                return 1;
            }
        }
    }

    // 2. Clone at the pinned rev.
    let work = std::env::temp_dir().join(format!("freeze-{tool}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    let url = format!("https://github.com/{repo}");
    if let Err(e) = git(&["init", "-q", work.to_str().unwrap_or_default()], None)
        .and_then(|_| git(&["remote", "add", "origin", &url], Some(&work)))
        .and_then(|_| {
            git(
                &["fetch", "-q", "--depth", "1", "origin", &rev],
                Some(&work),
            )
        })
        .and_then(|_| git(&["checkout", "-q", "FETCH_HEAD"], Some(&work)))
    {
        eprintln!("freeze: {e}");
        return 1;
    }
    let lock = work.join("Cargo.lock");
    if !lock.exists() {
        eprintln!("freeze: {repo}@{rev} has no root Cargo.lock — cannot freeze");
        let _ = std::fs::remove_dir_all(&work);
        return 1;
    }

    // 2a. --patches: stage the tool's patches onto the clean checkout first, producer order.
    // `git apply --check` before `git apply`, and a patch that fails to apply stops the run --
    // the same fail-closed supersession rule build-tools.yml enforces.
    if let Some(pdir) = &patches {
        // `git apply` runs with cwd = the staged checkout: patch paths must be absolute.
        // `absolute`, not `canonicalize` (git rejects its `\?\` form).
        let pdir = match std::path::absolute(pdir) {
            Ok(a) => a,
            Err(e) => {
                eprintln!(
                    "freeze: --patches {} cannot be absolutized: {e}",
                    pdir.display()
                );
                let _ = std::fs::remove_dir_all(&work);
                return 1;
            }
        };
        let files: Vec<PathBuf> = match patch_files(&pdir) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("freeze: --patches {} unreadable: {e}", pdir.display());
                let _ = std::fs::remove_dir_all(&work);
                return 1;
            }
        };
        for pf in &files {
            let Some(pfs) = pf.to_str() else {
                eprintln!("freeze: patch path is not UTF-8: {}", pf.display());
                let _ = std::fs::remove_dir_all(&work);
                return 1;
            };
            if git(&["apply", "--check", pfs], Some(&work)).is_err()
                || git(&["apply", pfs], Some(&work)).is_err()
            {
                eprintln!(
                    "freeze: patch {} no longer applies to {repo}@{rev} -- superseded or \
                     conflicting; refresh or drop it (fail-closed)",
                    pf.display()
                );
                let _ = std::fs::remove_dir_all(&work);
                return 1;
            }
            println!("# patch applied: {}", pf.display());
        }
    }

    // 2b. --base: the existing frozen resolution REPLACES upstream's lock as the starting
    // point, so directives apply atop the curation and "before" is the posture we actually
    // ship. Unreadable base = stop; never silently fall back to upstream's lock, which would
    // make the delta describe a tree we do not build.
    if let Some(b) = &base {
        match std::fs::read(b) {
            Ok(bytes) => {
                if let Err(e) = std::fs::write(&lock, bytes) {
                    eprintln!(
                        "freeze: cannot stage --base {} into the checkout: {e}",
                        b.display()
                    );
                    let _ = std::fs::remove_dir_all(&work);
                    return 1;
                }
                println!(
                    "# base: {} (directives apply atop this resolution)",
                    b.display()
                );
            }
            Err(e) => {
                eprintln!("freeze: --base {} unreadable: {e}", b.display());
                let _ = std::fs::remove_dir_all(&work);
                return 1;
            }
        }
    }
    // Snapshot the package NAME set before any directive runs. A drop-in may move versions
    // and may prune transitive packages, but it must never INTRODUCE a package name: a new
    // name entering through a "fix" is exactly the shape of a smuggled or squatted crate,
    // and no advisory delta would notice it. Checked after the directives, below.
    let names_before = match lock_package_names(&lock) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("freeze: cannot read package names from the starting lock: {e}");
            let _ = std::fs::remove_dir_all(&work);
            return 1;
        }
    };

    // 2c. --prior-lock: what we last blessed for this tool. Read once; used for carry-forward
    // directives here, for the shape invariant and the regression check below.
    let prior: Option<BTreeMap<String, Vec<String>>> = match &prior_lock {
        None => None,
        Some(pl) => match std::fs::read_to_string(pl) {
            Ok(t) => Some(lock_package_versions(&t)),
            Err(e) => {
                eprintln!("freeze: --prior-lock {} unreadable: {e}", pl.display());
                let _ = std::fs::remove_dir_all(&work);
                return 1;
            }
        },
    };
    if carry_forward {
        let Some(prior) = &prior else {
            eprintln!("freeze: --carry-forward needs --prior-lock");
            let _ = std::fs::remove_dir_all(&work);
            return 1;
        };
        let start = match std::fs::read_to_string(&lock) {
            Ok(t) => lock_package_versions(&t),
            Err(e) => {
                eprintln!("freeze: cannot read the starting lock: {e}");
                let _ = std::fs::remove_dir_all(&work);
                return 1;
            }
        };
        let mut carried = carry_forward_directives(&start, prior, &parsed);
        if carried.is_empty() {
            println!("# carry-forward: nothing resolved below the prior blessed lock");
        }
        for d in &carried {
            // A previously blessed version still has to be non-yanked today.
            match check_target(d, now_epoch, soak) {
                Ok(_) => println!(
                    "# carry-forward: {} {} -> {} (prior blessed version)",
                    d.package,
                    d.at.as_deref().unwrap_or("?"),
                    d.version
                ),
                Err(e) => {
                    eprintln!("  REFUSED: carry-forward {}: {e}", d.package);
                    let _ = std::fs::remove_dir_all(&work);
                    return 1;
                }
            }
        }
        // Carried moves go first: they restore the baseline the explicit directives build on.
        carried.extend(parsed);
        parsed = carried;
    }

    // 3. Advisory posture BEFORE (the starting lock), at this DB state.
    let before = match run_audit(&lock, false) {
        Ok(a) => extract_instances(&a),
        Err(e) => {
            eprintln!("freeze: baseline audit failed: {e}");
            let _ = std::fs::remove_dir_all(&work);
            return 1;
        }
    };

    // 4. Apply the directives. `cargo update --precise` moves ONLY the named packages
    //    (plus whatever their own requirements force), keeping the rest of upstream's
    //    vetted resolution intact — minimal deviation, recorded in full by the lock diff.
    // Apply EVERY directive and report EVERY refusal before failing. Stopping at the first one
    // turned a ten-directive batch into ten cycles of discovery (the same defect fixed in the
    // caps gate, #305, and the producer loop, #324). Nothing is written on any refusal: a
    // partial set is not the set that was reviewed, so no delta is computed for it either.
    let mut refused: Vec<String> = Vec::new();
    for p in &parsed {
        // An earlier directive's re-resolution may already have moved this package, so a
        // `pkg@current` spec written beforehand can match nothing. Resolve the spec against the
        // lock as it stands now: bare when one version is resident, `pkg@current` otherwise.
        let spec = match std::fs::read_to_string(&lock) {
            Ok(t) => spec_for(&lock_package_versions(&t), p),
            Err(_) => p.spec(),
        };
        let out = Command::new("cargo")
            .current_dir(&work)
            .args(["update", "-p", &spec, "--precise", &p.version])
            .env_remove("CARGO")
            .env_remove("RUSTC")
            .env_remove("RUSTUP_TOOLCHAIN")
            .output();
        match out {
            Ok(o) if o.status.success() => println!("  updated {} -> {}", p.package, p.version),
            Ok(o) => {
                // cargo's own words: the requirement that caps the move is the actionable fact.
                let err = String::from_utf8_lossy(&o.stderr);
                let why: Vec<&str> = err
                    .lines()
                    .filter(|l| !l.trim().is_empty() && !l.contains("Updating crates.io index"))
                    .take(6)
                    .collect();
                eprintln!(
                    "  REFUSED: cargo update -p {spec} --precise {} failed — unreachable from this \
                     tree's requirements:\n      {}",
                    p.version,
                    why.join("\n      ")
                );
                refused.push(format!("{}={}", p.package, p.version));
            }
            Err(e) => {
                eprintln!("  REFUSED: cannot run cargo update for {}: {e}", p.package);
                refused.push(format!("{}={}", p.package, p.version));
            }
        }
    }
    if !refused.is_empty() {
        eprintln!(
            "freeze: {} directive(s) unreachable: {refused:?} -- no lock written, no delta \
             computed (a partial set is not the reviewed set)",
            refused.len()
        );
        let _ = std::fs::remove_dir_all(&work);
        return 1;
    }

    // 5. Advisory posture AFTER — same DB state (--no-fetch), so the diff isolates the
    //    resolution change from advisory-DB drift (#241 §5).
    // LOCKFILE SHAPE INVARIANT. Precise-updates of named packages may change versions and may
    // prune transitive packages that the new versions no longer need; they may never ADD a
    // package name. `cargo update -p <name>` already refuses a name absent from the graph
    // (measured: "package ID specification `rustlss` did not match any packages"), so this is
    // the belt to that brace -- it catches a new transitive dependency riding in on a version
    // bump, which is the shape a smuggled crate would take and which no advisory delta sees.
    // Hard refusal, dry-run included: a certificate is not issued for a tree that grew.
    let names_after = match lock_package_names(&lock) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("freeze: cannot read package names from the updated lock: {e}");
            let _ = std::fs::remove_dir_all(&work);
            return 1;
        }
    };
    let mut added_names = added_package_names(&names_before, &names_after);
    if let Some(prior) = &prior {
        let (known, novel): (Vec<String>, Vec<String>) =
            added_names.into_iter().partition(|n| prior.contains_key(n));
        for n in &known {
            println!(
                "  carried name `{n}`: not in upstream's lock, but in the prior blessed lock for \
                 this tool — already in service, not a new party"
            );
        }
        added_names = novel;
    }
    if !added_names.is_empty() {
        // Each new name must be BOTH named on the command line and covered by a quality-passing
        // `lock-shape` statement for this tool. Either half alone refuses.
        let acks = crate::gate::load_acks(&evidence_dir.join(&tool).join("acks.jsonl"))
            .unwrap_or_else(|e| {
                eprintln!("  ack lattice unreadable ({e}) -- treating as NO acceptances");
                crate::gate::Acks {
                    entries: Vec::new(),
                    rejected: Vec::new(),
                }
            });
        let unaccepted: Vec<&String> = added_names
            .iter()
            .filter(|n| !(accept_new.contains(*n) && lock_shape_accepted(&acks, &tool, n)))
            .collect();
        if !unaccepted.is_empty() {
            eprintln!(
                "  REFUSED: the directives INTRODUCED package name(s) {added_names:?} -- a drop-in \
                 may move versions and prune, never add. Review the new dependency by hand before \
                 any bless (lockfile shape invariant). To accept a reviewed name: commit a \
                 `lock-shape` statement for it in supply-chain/evidence/{tool}/acks.jsonl AND pass \
                 --accept-new-package <name>:\n    {}",
                unaccepted
                    .iter()
                    .map(|n| lock_shape_template(&tool, n))
                    .collect::<Vec<_>>()
                    .join("\n    ")
            );
            let _ = std::fs::remove_dir_all(&work);
            return 1;
        }
        for n in &added_names {
            println!(
                "  ACCEPTED new package name `{n}` under a reviewed lock-shape statement in \
                 supply-chain/evidence/{tool}/acks.jsonl (shape invariant exception, recorded)"
            );
        }
    }
    let pruned: Vec<&String> = names_before.difference(&names_after).collect();
    if !pruned.is_empty() {
        println!("  pruned (no longer needed by the new versions): {pruned:?}");
    }
    // Strictly better is measured against what WE shipped, not against upstream's lock: a
    // package resolved below its previously blessed version is a regression (fixed bugs lost,
    // possibly fixed advisories lost), whatever the advisory delta says. Refused unless named.
    if let Some(prior) = &prior {
        let after_v = match std::fs::read_to_string(&lock) {
            Ok(t) => lock_package_versions(&t),
            Err(e) => {
                eprintln!("freeze: cannot read the updated lock: {e}");
                let _ = std::fs::remove_dir_all(&work);
                return 1;
            }
        };
        let regressed = downgrades(&after_v, prior);
        let dropped = dropped_lines(&after_v, prior);
        if !dropped.is_empty() {
            println!(
                "  lines we shipped that this resolution no longer contains (upstream's dependency \
                 choice, not a rollback; reviewed through caps/vuln): {}",
                dropped.join(", ")
            );
        }
        let blocking: Vec<&(String, String, String)> = regressed
            .iter()
            .filter(|(n, _, _)| !allow_downgrade.contains(n))
            .collect();
        for (n, from, to) in &regressed {
            if allow_downgrade.contains(n) {
                println!("  downgrade allowed by flag: {n} {from} -> {to}");
            }
        }
        if !blocking.is_empty() {
            eprintln!(
                "  REFUSED: {} package(s) resolve BELOW the prior blessed lock ({}): {} -- not strictly \
                 better than what we ship. Use --carry-forward to lift them to the prior versions, \
                 or --allow-downgrade <pkg> for a reviewed exception.",
                blocking.len(),
                prior_lock
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default(),
                blocking
                    .iter()
                    .map(|(n, f, t)| format!("{n} {f}->{t}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            let _ = std::fs::remove_dir_all(&work);
            return 1;
        }
    }

    let after = match run_audit(&lock, true) {
        Ok(a) => extract_instances(&a),
        Err(e) => {
            eprintln!("freeze: post-update audit failed: {e}");
            let _ = std::fs::remove_dir_all(&work);
            return 1;
        }
    };
    let removed = removed_instances(&before, &after);
    // #255 §4: refusal keys on RISK, not version movement. The same advisory carried
    // onto a bumped version ("unfixed") is reported loudly but never blocks; only a
    // genuinely new (advisory, package) — or a grown instance count — refuses.
    let (genuine, unfixed) = split_regressions(&before, &after);
    println!(
        "\n# advisory delta at one DB state: {} fixed / {} unfixed-carried / {} genuinely added \
         ({} -> {} instances)",
        removed.len() - unfixed.len(),
        unfixed.len(),
        genuine.len(),
        before.len(),
        after.len()
    );
    // "Strictly better" needs BOTH halves: no regression (genuinely added == 0, enforced
    // below) AND an actual improvement. A change that fixes nothing is not better however
    // clean its delta; under --require-improvement it is refused, and no lock is written.
    let fixed_count = removed.len() - unfixed.len();
    if require_improvement && fixed_count == 0 {
        eprintln!(
            "  REFUSED: --require-improvement set and the directives fix 0 instance(s) as measured \n             by RustSec -- newer is not better on this axis; nothing to certify, no lock written. \n             A fix outside RustSec's view (vendored C library, root store, behaviour) needs its \n             own evidence through the maintainer queue, not this flag."
        );
        let _ = std::fs::remove_dir_all(&work);
        return 1;
    }
    let unfixed_keys: BTreeSet<(String, String)> = unfixed
        .iter()
        .map(|i| (i.id.clone(), i.package.clone()))
        .collect();
    for i in &removed {
        if unfixed_keys.contains(&(i.id.clone(), i.package.clone())) {
            continue; // shown below as unfixed movement, not as a fix
        }
        println!("  - {} {} {}  (fixed)", i.id, i.package, i.version);
    }
    for i in &unfixed {
        println!(
            "  ~ {} {}: still present at {} — this bump did NOT fix it",
            i.id, i.package, i.version
        );
    }
    // #357: the instances that remain ARE the human queue; name them, do not just count them.
    for i in carried_instances(&before, &after) {
        println!(
            "  = {} {} {} ({})  (carried, unchanged)",
            i.id, i.package, i.version, i.kind
        );
    }
    for i in &genuine {
        println!(
            "  + {} {} {}  <-- GENUINELY ADDED",
            i.id, i.package, i.version
        );
    }
    if !genuine.is_empty() && !allow_added {
        eprintln!(
            "\nfreeze: REFUSED — this resolution introduces {} genuinely new advisory \
             instance(s)\n(new advisory on a package, or a second vulnerable resident \
             version). Freezing is for\nprovable non-regressions; trading one advisory for \
             another is a human decision.\nRe-run with --allow-added-advisories to record \
             that trade deliberately.",
            genuine.len()
        );
        let _ = std::fs::remove_dir_all(&work);
        return 1;
    }
    if removed.is_empty() {
        println!("  (no advisory instance removed — freeze records a resolution change only)");
    }

    if dry_run {
        println!(
            "
# DRY RUN — no lock written. Re-run without --dry-run to commit this resolution."
        );
        let _ = std::fs::remove_dir_all(&work);
        return 0;
    }

    // 6. Emit the frozen lock. From here the candidate is fully pinned: the producer builds
    //    `--locked` against THIS file, and the resulting digest is what the gate evaluates.
    if let Err(e) = std::fs::create_dir_all(&out_dir) {
        eprintln!("freeze: mkdir {}: {e}", out_dir.display());
        let _ = std::fs::remove_dir_all(&work);
        return 1;
    }
    let dest = out_dir.join(format!("{tool}.lock"));
    if let Err(e) = std::fs::copy(&lock, &dest) {
        eprintln!("freeze: write {}: {e}", dest.display());
        let _ = std::fs::remove_dir_all(&work);
        return 1;
    }
    let _ = std::fs::remove_dir_all(&work);
    println!(
        "\n# wrote {} — commit it, then run build-tools.yml (which builds --locked against it)\n\
         # and bless the produced digest through `xtask gate`. Nothing is blessed here.",
        dest.display()
    );
    0
}

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

    #[test]
    fn directive_parsing_requires_concrete_version() {
        assert_eq!(
            parse_directive("futures-util=0.3.34").unwrap(),
            Directive {
                package: "futures-util".into(),
                version: "0.3.34".into(),
                at: None
            }
        );
        assert!(parse_directive("futures-util").is_err(), "missing '='");
        assert!(parse_directive("=0.3.34").is_err(), "empty package");
        assert!(parse_directive("futures-util=").is_err(), "empty version");
        assert!(
            parse_directive("futures-util=^0.3").is_err(),
            "range, not concrete"
        );
        assert!(
            parse_directive("futures-util=v0.3.34").is_err(),
            "tag-style, not semver"
        );
        assert!(
            parse_directive("x=1.0.0-rc.1").is_err(),
            "pre-release is not promotable"
        );
    }

    #[test]
    fn directive_at_version_disambiguates_multi_version_crates() {
        // #255 §2: getrandom coexists at 0.2.x and 0.3.x; pkg@current selects one copy.
        let d = parse_directive("getrandom@0.2.7=0.2.17").unwrap();
        assert_eq!(d.package, "getrandom");
        assert_eq!(d.at.as_deref(), Some("0.2.7"));
        assert_eq!(d.version, "0.2.17");
        assert_eq!(d.spec(), "getrandom@0.2.7");
        // bare form unchanged
        let b = parse_directive("webpki=0.22.4").unwrap();
        assert_eq!(b.at, None);
        assert_eq!(b.spec(), "webpki");
        // malformed @ forms refuse
        assert!(
            parse_directive("getrandom@=0.2.17").is_err(),
            "empty current"
        );
        assert!(
            parse_directive("getrandom@^0.2=0.2.17").is_err(),
            "range current"
        );
    }

    #[test]
    fn added_and_removed_are_instance_tuple_exact() {
        let before: BTreeSet<Instance> = [inst("A", "p", "1"), inst("B", "q", "2")].into();
        let after: BTreeSet<Instance> = [inst("B", "q", "2"), inst("C", "r", "3")].into();
        assert_eq!(added_instances(&before, &after), vec![inst("C", "r", "3")]);
        assert_eq!(
            removed_instances(&before, &after),
            vec![inst("A", "p", "1")]
        );
    }

    #[test]
    fn same_advisory_new_version_counts_as_added() {
        // A second vulnerable copy is a REGRESSION a bare-ID diff would miss (#241 §6).
        let before: BTreeSet<Instance> = [inst("A", "p", "1.0")].into();
        let after: BTreeSet<Instance> = [inst("A", "p", "1.0"), inst("A", "p", "2.0")].into();
        assert_eq!(
            added_instances(&before, &after),
            vec![inst("A", "p", "2.0")]
        );
        assert!(removed_instances(&before, &after).is_empty());
    }

    #[test]
    fn pure_improvement_adds_nothing() {
        let before: BTreeSet<Instance> = [inst("A", "p", "1"), inst("B", "q", "2")].into();
        let after: BTreeSet<Instance> = [inst("B", "q", "2")].into();
        assert!(added_instances(&before, &after).is_empty());
        assert_eq!(removed_instances(&before, &after).len(), 1);
    }

    // ---- #255 §4: refusal keys on risk, not version movement ----

    #[test]
    fn same_advisory_moved_version_is_unfixed_not_genuine() {
        // The real h2 case: RUSTSEC-2026-0258 on 0.3.13 before, on 0.3.27 after.
        // Same advisory, same package, moved version: report as unfixed, do not refuse.
        let before: BTreeSet<Instance> = [inst("RUSTSEC-2026-0258", "h2", "0.3.13")].into();
        let after: BTreeSet<Instance> = [inst("RUSTSEC-2026-0258", "h2", "0.3.27")].into();
        let (genuine, unfixed) = split_regressions(&before, &after);
        assert!(genuine.is_empty(), "version movement must not refuse");
        assert_eq!(unfixed, vec![inst("RUSTSEC-2026-0258", "h2", "0.3.27")]);
    }

    #[test]
    fn new_advisory_key_is_genuine() {
        let before: BTreeSet<Instance> = [inst("A", "p", "1")].into();
        let after: BTreeSet<Instance> = [inst("A", "p", "1"), inst("B", "q", "2")].into();
        let (genuine, unfixed) = split_regressions(&before, &after);
        assert_eq!(genuine, vec![inst("B", "q", "2")]);
        assert!(unfixed.is_empty());
    }

    #[test]
    fn grown_instance_count_is_genuine() {
        // Same advisory gains a SECOND vulnerable resident version: doubled exposure,
        // the #241 §6 regression — refuse even though the (id, package) key existed.
        let before: BTreeSet<Instance> = [inst("A", "p", "1.0")].into();
        let after: BTreeSet<Instance> = [inst("A", "p", "1.0"), inst("A", "p", "2.0")].into();
        let (genuine, unfixed) = split_regressions(&before, &after);
        assert_eq!(genuine, vec![inst("A", "p", "2.0")]);
        assert!(unfixed.is_empty());
    }

    #[test]
    fn lock_shape_acceptance_needs_a_quality_statement_for_that_tool_and_name() {
        let line = |tool: &str, name: &str, notes: &str| {
            format!(
                r#"{{"schema":"hp-thermal/evidence-ack/v1","axis":"lock-shape","product":{{"name":"{tool}"}},"package":{{"name":"{name}"}},"status":"reviewed","status_notes":"{notes}","author":"a","timestamp":"2026-11-12","refs":[]}}"#
            )
        };
        let dir = std::env::temp_dir().join(format!("freeze-shape-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("acks.jsonl");
        std::fs::write(
            &p,
            format!(
                "{}\n{}\n{}\n",
                line(
                    "cargo-vet",
                    "windows-link",
                    "Microsoft windows-rs sub-crate, already in the app graph"
                ),
                line("cargo-vet", "evil", ""),
                line("cargo-deny", "windows-link", "other tool")
            ),
        )
        .unwrap();
        let acks = crate::gate::load_acks(&p).unwrap();
        assert!(lock_shape_accepted(&acks, "cargo-vet", "windows-link"));
        assert!(
            !lock_shape_accepted(&acks, "cargo-vet", "evil"),
            "placeholder notes are quality-rejected"
        );
        assert!(
            !lock_shape_accepted(&acks, "cargo-vet", "other"),
            "unnamed package"
        );
        assert!(
            !lock_shape_accepted(&acks, "cargo-audit", "windows-link"),
            "per tool"
        );
        assert!(lock_shape_template("t", "p").contains(r#""axis":"lock-shape""#));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prior_lock_helpers_measure_regressions_and_resolve_specs_against_the_live_lock() {
        let lock = |pairs: &[(&str, &str)]| -> BTreeMap<String, Vec<String>> {
            let mut m: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for (n, v) in pairs {
                m.entry(n.to_string()).or_default().push(v.to_string());
            }
            m
        };
        let prior = lock(&[
            ("flate2", "1.1.9"),
            ("miniz_oxide", "0.8.9"),
            ("adler2", "2.0.1"),
            ("only-prior", "1.0.0"),
            ("syn", "3.0.3"),
            ("toml", "0.8.23"),
            ("toml", "1.1.4+spec-1.1.0"),
        ]);
        let start = lock(&[
            ("flate2", "1.0.24"),
            ("miniz_oxide", "0.5.3"),
            ("miniz_oxide", "0.8.2"),
            ("adler", "1.0.2"),
            ("newer", "9.9.9"),
            ("syn", "2.0.111"),
            ("toml", "0.8.22"),
        ]);
        let d = downgrades(&start, &prior);
        assert_eq!(
            d,
            vec![
                (
                    "flate2".to_string(),
                    "1.1.9".to_string(),
                    "1.0.24".to_string()
                ),
                (
                    "miniz_oxide".to_string(),
                    "0.8.9".to_string(),
                    "0.8.2".to_string()
                ),
                (
                    "toml".to_string(),
                    "0.8.23".to_string(),
                    "0.8.22".to_string()
                ),
            ],
            "within-line rollbacks only: 0.5.3 is another line, syn 3->2 is a line switch, not a rollback"
        );
        assert_eq!(
            dropped_lines(&start, &prior),
            vec![
                "adler2 2.0.1".to_string(),
                "only-prior 1.0.0".to_string(),
                "syn 3.0.3".to_string(),
                "toml 1.1.4+spec-1.1.0".to_string()
            ],
            "lines we shipped that are gone (whole packages included) are reported, never carried"
        );
        let explicit = [Directive {
            package: "flate2".into(),
            version: "1.1.9".into(),
            at: None,
        }];
        let cf = carry_forward_directives(&start, &prior, &explicit);
        assert_eq!(cf.len(), 2, "explicitly named packages are not duplicated");
        assert_eq!(
            (
                cf[0].package.as_str(),
                cf[0].version.as_str(),
                cf[0].at.as_deref()
            ),
            ("miniz_oxide", "0.8.9", Some("0.8.2")),
            "at = the resident version IN THAT LINE"
        );
        assert_eq!(
            spec_for(&start, &cf[0]),
            "miniz_oxide@0.8.2",
            "two lines resident -> disambiguate"
        );
        assert_eq!(
            spec_for(&start, &explicit[0]),
            "flate2",
            "one copy resident -> bare spec"
        );
        let moved = Directive {
            package: "flate2".into(),
            version: "1.1.9".into(),
            at: Some("1.0.0".into()),
        };
        assert_eq!(
            spec_for(&start, &moved),
            "flate2",
            "stale @current is ignored when unambiguous"
        );
        let gone = Directive {
            package: "x".into(),
            version: "1".into(),
            at: Some("0".into()),
        };
        assert_eq!(
            spec_for(&start, &gone),
            "x@0",
            "unknown package falls back to the written spec"
        );
        let text = "[[package]]\nname = \"a\"\nversion = \"1.0.0\"\n\n[[package]]\nname = \"a\"\nversion = \"2.0.0\"\n\n[metadata]\nk = \"v\"\n";
        assert_eq!(lock_package_versions(text)["a"], ["1.0.0", "2.0.0"]);
    }

    #[test]
    fn version_moves_and_prunes_are_not_added_names() {
        // A drop-in: rustls bumps, ppv-lite86 is pruned. The name set may shrink or hold; the
        // invariant is about ENTRY only.
        let before = lock_package_names_from_str(
            "[[package]]\nname = \"rustls\"\nversion = \"0.23.40\"\n\n[[package]]\nname = \"ppv-lite86\"\nversion = \"0.2.21\"\n",
        );
        let after =
            lock_package_names_from_str("[[package]]\nname = \"rustls\"\nversion = \"0.23.46\"\n");
        assert!(added_package_names(&before, &after).is_empty());
    }

    #[test]
    fn a_new_package_name_is_refused_whatever_the_advisory_delta_says() {
        // The smuggle shape: the named target moves, and an unrelated crate rides in with it.
        // The advisory delta could be perfectly clean; the shape invariant still refuses.
        let before =
            lock_package_names_from_str("[[package]]\nname = \"rustls\"\nversion = \"0.23.40\"\n");
        let after = lock_package_names_from_str(
            "[[package]]\nname = \"rustls\"\nversion = \"0.23.46\"\n\n[[package]]\nname = \"rustls-helper\"\nversion = \"0.1.0\"\n",
        );
        assert_eq!(
            added_package_names(&before, &after),
            vec!["rustls-helper".to_string()]
        );
    }

    #[test]
    fn lock_name_parsing_ignores_metadata_tables() {
        // `[metadata]` and `[[patch.unused]]` tables carry `name =` lines that are not packages.
        let names = lock_package_names_from_str(
            "[[package]]\nname = \"real\"\nversion = \"1.0.0\"\n\n[[patch.unused]]\nname = \"ghost\"\nversion = \"0.0.1\"\n",
        );
        assert_eq!(names.into_iter().collect::<Vec<_>>(), vec!["real"]);
    }

    #[test]
    fn newly_yanked_package_cannot_hide_behind_existing_yanked_findings() {
        // `yanked` warnings use the kind as the id, so the key must be (id, PACKAGE):
        // a pre-existing yanked finding on one package must not launder a NEW yanked
        // package as "unfixed movement".
        let before: BTreeSet<Instance> = [inst("yanked", "futures-util", "0.3.21")].into();
        let after: BTreeSet<Instance> = [
            inst("yanked", "futures-util", "0.3.21"),
            inst("yanked", "xml-rs", "0.8.19"),
        ]
        .into();
        let (genuine, unfixed) = split_regressions(&before, &after);
        assert_eq!(genuine, vec![inst("yanked", "xml-rs", "0.8.19")]);
        assert!(unfixed.is_empty());
    }

    #[test]
    fn shrunk_count_with_moved_version_is_unfixed_only() {
        // Two vulnerable copies collapse to one still-vulnerable copy at a new version:
        // progress (one copy eliminated) plus an unfixed remainder — never a refusal.
        let before: BTreeSet<Instance> = [inst("A", "p", "1.0"), inst("A", "p", "2.0")].into();
        let after: BTreeSet<Instance> = [inst("A", "p", "3.0")].into();
        let (genuine, unfixed) = split_regressions(&before, &after);
        assert!(genuine.is_empty());
        assert_eq!(unfixed, vec![inst("A", "p", "3.0")]);
    }
    #[test]
    fn patch_files_are_absolute_sorted_and_only_patches() {
        // The staged checkout is `git apply`'s cwd, so a relative patch path would be looked
        // up under the clone. Every enumerated path must therefore be absolute.
        let dir = std::env::temp_dir().join(format!("xtask-patchfiles-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for n in ["0002-b.patch", "0001-a.patch", "README.md"] {
            std::fs::write(dir.join(n), "x").unwrap();
        }
        let rel = pathdiff_relative(&dir);
        let abs = std::path::absolute(&rel).unwrap();
        let files = patch_files(&abs).unwrap();
        let names: Vec<String> = files
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["0001-a.patch", "0002-b.patch"]);
        assert!(files.iter().all(|p| p.is_absolute()), "{files:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A relative spelling of `abs` from the cwd when one exists (same drive on Windows);
    /// otherwise `abs` itself. Enough to exercise the absolutize path in CI and locally.
    fn pathdiff_relative(abs: &std::path::Path) -> PathBuf {
        let cwd = std::env::current_dir().unwrap();
        match abs.strip_prefix(&cwd) {
            Ok(r) => r.to_path_buf(),
            Err(_) => abs.to_path_buf(),
        }
    }

    #[test]
    fn carried_instances_are_named_not_counted() {
        let before: BTreeSet<Instance> = [
            inst("A", "p", "1"),
            inst("B", "q", "2"),
            inst("C", "r", "3"),
        ]
        .into();
        let after: BTreeSet<Instance> = [
            inst("B", "q", "2"),
            inst("C", "r", "4"),
            inst("D", "s", "1"),
        ]
        .into();
        // B unchanged -> carried; C moved version -> unfixed (not carried); D -> genuine; A -> fixed
        assert_eq!(
            carried_instances(&before, &after),
            vec![inst("B", "q", "2")]
        );
    }
}
