//! `cargo xtask freeze-propose` — tier 1 (COMPUTE) of the strictly-better fix automation (#405).
//!
//! RUSTSEC-2026-0486 (rustix) showed the gap: the monitor raised it on six digests, a patched
//! version existed and was past soak, every consumer accepted it, and the fix was one
//! `xtask freeze --base … --update rustix=1.1.6 --require-improvement` per tool (#404). Nothing
//! could propose it: Dependabot cannot see `tools/locks/*.lock`, tool-updates.yml tracks release
//! lag, candidate-explore proposes candidates as data. Detection was automated; the one-line fix
//! was manual.
//!
//! WHAT THIS DOES. For every tool in TOOLS.lock: audit the lock the blessed binary is built from
//! (frozen lock or upstream's, #255 §5); for each advisory instance whose RustSec entry names a
//! `patched` range, pick the LOWEST soaked, non-yanked version newer than the resident one that
//! satisfies every patched range for that package; run the existing `xtask freeze` with those
//! directives, `--require-improvement`, atop the frozen lock and the tool's patches; then — the
//! check freeze itself does not do — soak/yank-check every TRANSITIVE package the resolver moved
//! along (seen in #404: libc, linux-raw-sys). Accepted locks land in `<out>/locks/`, with a
//! report and `proposals.json` for tier 2 (the workflow commits them via the API and opens ONE
//! PR). Refusals are reported, never papered over: a freeze refusal opens no PR.
//!
//! WHAT THIS NEVER DOES. Touch TOOLS.lock, evidence or acks; bless anything (the digest still
//! comes from a producer run and `xtask gate`); merge anything; run with an overridden clock or
//! soak (freeze refuses to write under research overrides, and this command has none).
//!
//! FAIL DIRECTIONS. Policy outcomes (nothing fixable, not yet soaked, unreachable range, freeze
//! refusal, transitive move not soaked) are REPORTED and exit 0: "no proposal" is a fine answer.
//! Infrastructure failures (TOOLS.lock unreadable, the pinned auditor broken, crates.io or the
//! freeze subprocess not runnable, output dir unwritable) exit 1 so the schedule pages: an empty
//! proposal set from a broken instrument must never read as "nothing to fix".

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

use crate::explore::{SOAK_DAYS, candidates_from_versions, fetch_versions};
use crate::freeze::{Directive, check_target};
use crate::gate::{Instance, parse_tools_lock, resolve_lock, run_audit};
use crate::toolchain::{parse_ver as parse_rust_ver, range_contains};

/// One advisory instance together with the fix RustSec names for it: `patched` is a list of
/// ALTERNATIVE version requirements (any one satisfied = patched).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fixable {
    pub inst: Instance,
    pub patched: Vec<String>,
}

fn strs(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}

fn fixable_entry(e: &Value, kind: &str) -> Option<Fixable> {
    let pkg = e.get("package")?;
    let patched = strs(e.pointer("/versions/patched"));
    if patched.is_empty() {
        return None;
    }
    Some(Fixable {
        inst: Instance {
            id: e
                .pointer("/advisory/id")
                .and_then(Value::as_str)
                .unwrap_or(kind)
                .to_string(),
            package: pkg.get("name")?.as_str()?.to_string(),
            version: pkg.get("version")?.as_str()?.to_string(),
            kind: kind.to_string(),
        },
        patched,
    })
}

/// Instances with a patched range, from `cargo audit --json`: vulnerabilities and every
/// warning kind (unsound, unmaintained-with-successor, …). An instance with no patched range
/// has no automatable fix and stays in the human queue.
pub fn fixable(audit: &Value) -> Vec<Fixable> {
    let mut out = Vec::new();
    for e in audit
        .pointer("/vulnerabilities/list")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        out.extend(fixable_entry(e, "vulnerability"));
    }
    if let Some(w) = audit.get("warnings").and_then(Value::as_object) {
        for (kind, arr) in w {
            for e in arr.as_array().into_iter().flatten() {
                out.extend(fixable_entry(e, kind));
            }
        }
    }
    out
}

/// Does `version` satisfy at least one of the alternative requirements?
fn satisfies_any(version: &str, alternatives: &[String]) -> Result<bool, String> {
    let v = parse_rust_ver(version).ok_or_else(|| format!("unparseable version {version:?}"))?;
    for r in alternatives {
        if range_contains(r, v)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The LOWEST soaked, non-yanked, non-prerelease version newer than `current` that satisfies
/// EVERY advisory's patched alternatives (`reqs`: one entry per advisory on this package).
/// Minimal movement is the least breaking move that is still a complete fix. `Ok(None)`: a
/// patched range exists but no soaked version reaches it yet. `Err`: a range this evaluator
/// cannot read — UNEVALUATED, never "no fix".
pub fn pick_target(
    current: &str,
    versions: &Value,
    reqs: &[Vec<String>],
    now_epoch: i64,
) -> Result<Option<String>, String> {
    let cands = candidates_from_versions(versions, current, now_epoch, SOAK_DAYS)?;
    for c in cands {
        if !c.soaked {
            continue;
        }
        let mut all = true;
        for alternatives in reqs {
            all &= satisfies_any(&c.version, alternatives)?;
        }
        if all {
            return Ok(Some(c.version));
        }
    }
    Ok(None)
}

/// `(name, version)` pairs of a Cargo.lock.
pub fn lock_packages(text: &str) -> BTreeSet<(String, String)> {
    let mut out = BTreeSet::new();
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
            out.insert((n.clone(), v.to_string()));
        }
    }
    out
}

/// Package versions present AFTER a freeze that were not present before, minus the directive
/// targets themselves: the moves the resolver made on its own. Each one must pass the same
/// soak/yank bar as a directive target — a transitive bump is a new build input too.
pub fn transitive_moves(
    before: &BTreeSet<(String, String)>,
    after: &BTreeSet<(String, String)>,
    directives: &[Directive],
) -> Vec<(String, String)> {
    after
        .difference(before)
        .filter(|(n, v)| {
            !directives
                .iter()
                .any(|d| d.package == *n && d.version == *v)
        })
        .cloned()
        .collect()
}

/// Resident (package, version) -> (patched alternatives per advisory, advisory ids).
type Groups = BTreeMap<(String, String), (Vec<Vec<String>>, Vec<String>)>;

#[derive(Debug, Default)]
struct Proposal {
    tool: String,
    directives: Vec<String>,
    fixes: Vec<String>,
    moved: Vec<(String, String, i64)>,
    lock: String,
    freeze_report: String,
}

#[derive(Debug)]
struct Refusal {
    tool: String,
    reason: String,
}

fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Run `xtask freeze` as a subprocess (same binary) so its output is captured for the report
/// and its exit code is the certificate. Returns (success, combined output).
fn run_freeze(args: &[String]) -> Result<(bool, String), String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let out = Command::new(&exe)
        .arg("freeze")
        .args(args)
        .output()
        .map_err(|e| format!("cannot run {}: {e}", exe.display()))?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    Ok((out.status.success(), text))
}

pub fn run(args: &[String]) -> i32 {
    let mut tools_lock = PathBuf::from("tools/TOOLS.lock");
    let mut locks_dir = PathBuf::from("tools/locks");
    let mut patches_dir = PathBuf::from("tools/patches");
    let mut out: Option<PathBuf> = None;
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--tools-lock" => tools_lock = it.next().map(PathBuf::from).unwrap_or(tools_lock),
            "--locks-dir" => locks_dir = it.next().map(PathBuf::from).unwrap_or(locks_dir),
            "--patches-dir" => patches_dir = it.next().map(PathBuf::from).unwrap_or(patches_dir),
            "--out" => out = it.next().map(PathBuf::from),
            other => {
                eprintln!("freeze-propose: unknown argument {other}");
                return 2;
            }
        }
    }
    let Some(out) = out else {
        eprintln!(
            "usage: xtask freeze-propose --out <dir> [--tools-lock P] [--locks-dir D] [--patches-dir D]"
        );
        return 2;
    };
    let text = match std::fs::read_to_string(&tools_lock) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("freeze-propose: {}: {e}", tools_lock.display());
            return 1;
        }
    };
    let pins = parse_tools_lock(&text);
    if pins.is_empty() {
        eprintln!(
            "freeze-propose: no pins parsed from {}",
            tools_lock.display()
        );
        return 1;
    }
    let locks_out = out.join("locks");
    if let Err(e) = std::fs::create_dir_all(&locks_out) {
        eprintln!("freeze-propose: mkdir {}: {e}", locks_out.display());
        return 1;
    }
    let now = now_epoch();
    let tmp = std::env::temp_dir();
    let mut first = true;
    let mut infra_failure = false;
    let mut db = String::new();
    let mut proposals: Vec<Proposal> = Vec::new();
    let mut refusals: Vec<Refusal> = Vec::new();
    let mut seen = BTreeSet::new();

    for p in &pins {
        // One lock per tool: a second target shares it.
        if !seen.insert(p.name.clone()) {
            continue;
        }
        let dest = tmp.join(format!("propose-{}.lock", p.name));
        let (lock, lock_src) = match resolve_lock(&p.name, &p.repo, &p.rev, Some(&locks_dir), &dest)
        {
            Ok(v) => v,
            Err(e) => {
                refusals.push(Refusal {
                    tool: p.name.clone(),
                    reason: format!("UNEVALUATED: {e}"),
                });
                infra_failure = true;
                continue;
            }
        };
        let audit = match run_audit(&lock, !first) {
            Ok(a) => a,
            Err(e) => {
                refusals.push(Refusal {
                    tool: p.name.clone(),
                    reason: format!("UNEVALUATED: {e}"),
                });
                infra_failure = true;
                continue;
            }
        };
        first = false;
        if db.is_empty() {
            db = audit
                .pointer("/database/last-commit")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string();
        }
        let fx = fixable(&audit);
        if fx.is_empty() {
            refusals.push(Refusal {
                tool: p.name.clone(),
                reason: format!(
                    "nothing fixable: no instance with a RustSec patched range (lock: {lock_src})"
                ),
            });
            continue;
        }
        // Group by resident (package, version): one directive per group, every advisory on it.
        let mut groups: Groups = BTreeMap::new();
        for f in &fx {
            let g = groups
                .entry((f.inst.package.clone(), f.inst.version.clone()))
                .or_default();
            g.0.push(f.patched.clone());
            g.1.push(f.inst.id.clone());
        }
        let mut directives: Vec<Directive> = Vec::new();
        let mut fixes: Vec<String> = Vec::new();
        let mut notes: Vec<String> = Vec::new();
        for ((pkg, cur), (reqs, ids)) in &groups {
            let versions = match fetch_versions(pkg) {
                Ok(v) => v,
                Err(e) => {
                    notes.push(format!("{pkg} {cur}: UNEVALUATED — {e}"));
                    infra_failure = true;
                    continue;
                }
            };
            match pick_target(cur, &versions, reqs, now) {
                Ok(Some(target)) => {
                    directives.push(Directive {
                        package: pkg.clone(),
                        version: target,
                        at: Some(cur.clone()),
                    });
                    fixes.extend(ids.iter().cloned());
                }
                Ok(None) => notes.push(format!(
                    "{pkg} {cur}: patched range {reqs:?} exists, no soaked ({SOAK_DAYS}d) non-yanked version reaches it yet"
                )),
                Err(e) => notes.push(format!("{pkg} {cur}: UNEVALUATED — {e} ({})", ids.join(", "))),
            }
        }
        if directives.is_empty() {
            refusals.push(Refusal {
                tool: p.name.clone(),
                reason: format!("no proposable directive: {}", notes.join("; ")),
            });
            continue;
        }
        // Tier-1 certificate: the existing freeze, with the strictly-better flag, atop the
        // frozen lock and the tool's patches exactly as the producer builds.
        let mut fargs: Vec<String> = vec![
            "--tool".into(),
            p.name.clone(),
            "--repo".into(),
            p.repo.clone(),
            "--rev".into(),
            p.rev.clone(),
            "--require-improvement".into(),
            "--out-dir".into(),
            locks_out.display().to_string(),
        ];
        let frozen = locks_dir.join(format!("{}.lock", p.name));
        if frozen.is_file() {
            fargs.push("--base".into());
            fargs.push(frozen.display().to_string());
            // Strictly better is measured against what we ship: the base IS the prior.
            fargs.push("--prior-lock".into());
            fargs.push(frozen.display().to_string());
        }
        let patches = patches_dir.join(&p.name);
        if patches.is_dir() {
            fargs.push("--patches".into());
            fargs.push(patches.display().to_string());
        }
        for d in &directives {
            fargs.push("--update".into());
            fargs.push(format!("{}={}", d.spec(), d.version));
        }
        let (ok, report) = match run_freeze(&fargs) {
            Ok(r) => r,
            Err(e) => {
                refusals.push(Refusal {
                    tool: p.name.clone(),
                    reason: format!("UNEVALUATED: {e}"),
                });
                infra_failure = true;
                continue;
            }
        };
        let written = locks_out.join(format!("{}.lock", p.name));
        if !ok {
            let _ = std::fs::remove_file(&written);
            let tail: Vec<&str> = report
                .lines()
                .rev()
                .take(12)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            refusals.push(Refusal {
                tool: p.name.clone(),
                reason: format!(
                    "freeze refused {}:\n{}",
                    directives
                        .iter()
                        .map(|d| format!("{}={}", d.spec(), d.version))
                        .collect::<Vec<_>>()
                        .join(" "),
                    tail.join("\n")
                ),
            });
            continue;
        }
        // The check freeze does not do (#405 tier 1): every transitive move must pass the
        // same soak/yank bar as a directive target.
        let before = std::fs::read_to_string(&lock)
            .map(|t| lock_packages(&t))
            .unwrap_or_default();
        let after = std::fs::read_to_string(&written)
            .map(|t| lock_packages(&t))
            .unwrap_or_default();
        if after.is_empty() {
            let _ = std::fs::remove_file(&written);
            refusals.push(Refusal {
                tool: p.name.clone(),
                reason: "UNEVALUATED: freeze reported success but wrote no readable lock".into(),
            });
            infra_failure = true;
            continue;
        }
        let mut moved = Vec::new();
        let mut bad = Vec::new();
        for (n, v) in transitive_moves(&before, &after, &directives) {
            match check_target(
                &Directive {
                    package: n.clone(),
                    version: v.clone(),
                    at: None,
                },
                now,
                SOAK_DAYS,
            ) {
                Ok(age) => moved.push((n, v, age)),
                Err(e) => bad.push(format!("transitive move {n} {v}: {e}")),
            }
        }
        if !bad.is_empty() {
            let _ = std::fs::remove_file(&written);
            refusals.push(Refusal {
                tool: p.name.clone(),
                reason: format!(
                    "resolver pulled along a package that fails the target bar — {}",
                    bad.join("; ")
                ),
            });
            continue;
        }
        proposals.push(Proposal {
            tool: p.name.clone(),
            directives: directives
                .iter()
                .map(|d| format!("{}={}", d.spec(), d.version))
                .collect(),
            fixes,
            moved,
            lock: format!("locks/{}.lock", p.name),
            freeze_report: report,
        });
    }

    // ---------- report + machine-readable proposals ----------
    let mut md = String::from("## freeze-propose: strictly-better lock fixes (#405)\n\n");
    let _ = writeln!(
        md,
        "*advisory DB {db}; soak {SOAK_DAYS}d; every target and every transitive move non-yanked and past soak; delta at one DB state; lock shape invariant held by `freeze`.*\n"
    );
    if proposals.is_empty() {
        md.push_str("**No proposal.** Nothing met the strictly-better bar this run.\n\n");
    }
    for p in &proposals {
        let _ = writeln!(md, "### `{}` — `{}`", p.tool, p.lock);
        let _ = writeln!(
            md,
            "- directives: {}",
            p.directives
                .iter()
                .map(|d| format!("`{d}`"))
                .collect::<Vec<_>>()
                .join(", ")
        );
        let _ = writeln!(md, "- fixes: {}", p.fixes.join(", "));
        if p.moved.is_empty() {
            md.push_str("- transitive moves: none\n");
        } else {
            let _ = writeln!(
                md,
                "- transitive moves (soaked, non-yanked): {}",
                p.moved
                    .iter()
                    .map(|(n, v, a)| format!("{n} {v} ({a}d)"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        let _ = writeln!(
            md,
            "\n<details><summary>freeze report</summary>\n\n```\n{}\n```\n</details>\n",
            p.freeze_report.trim()
        );
    }
    if !refusals.is_empty() {
        md.push_str("### Not proposed\n");
        for r in &refusals {
            let _ = writeln!(md, "- **{}**: {}", r.tool, r.reason.replace('\n', "\n  "));
        }
        md.push('\n');
    }
    md.push_str("Nothing here is blessed: a lock is a build input; the digest comes from build-tools.yml and `xtask gate` evaluates it. Merge is always a maintainer click.\n");
    print!("{md}");
    let json = serde_json::json!({
        "schema": "hp-thermal/freeze-proposals/v1",
        "advisoryDb": db,
        "soakDays": SOAK_DAYS,
        "proposals": proposals.iter().map(|p| serde_json::json!({
            "tool": p.tool, "directives": p.directives, "fixes": p.fixes,
            "moved": p.moved.iter().map(|(n, v, a)| serde_json::json!({"package": n, "version": v, "ageDays": a})).collect::<Vec<_>>(),
            "lock": p.lock,
        })).collect::<Vec<_>>(),
        "refusals": refusals.iter().map(|r| serde_json::json!({"tool": r.tool, "reason": r.reason})).collect::<Vec<_>>(),
        "infrastructureFailure": infra_failure,
    });
    for (name, content) in [("report.md", md), ("proposals.json", json.to_string())] {
        if let Err(e) = std::fs::write(out.join(name), content) {
            eprintln!("freeze-propose: write {}: {e}", out.join(name).display());
            return 1;
        }
    }
    if infra_failure {
        eprintln!(
            "freeze-propose: UNEVALUATED for at least one tool (instrument or network failure) — see report; not a clean 'nothing to fix'"
        );
        return 1;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn audit_fixture() -> Value {
        serde_json::json!({
            "database": {"last-commit": "abc"},
            "vulnerabilities": {"count": 1, "list": [
                {"advisory": {"id": "RUSTSEC-2026-0486"}, "package": {"name": "rustix", "version": "1.1.5"},
                 "versions": {"patched": [">=1.1.6"], "unaffected": []}}
            ]},
            "warnings": {
                "unmaintained": [
                    {"advisory": {"id": "RUSTSEC-2024-0001"}, "package": {"name": "basic-toml", "version": "0.1.10"},
                     "versions": {"patched": [], "unaffected": []}}
                ],
                "unsound": [
                    {"advisory": {"id": "RUSTSEC-2025-0099"}, "package": {"name": "rustix", "version": "1.1.5"},
                     "versions": {"patched": [">=1.1.6, <2.0.0", ">=2.1.0"], "unaffected": []}}
                ]
            }
        })
    }

    #[test]
    fn fixable_keeps_only_instances_with_a_patched_range_across_vulns_and_warnings() {
        let fx = fixable(&audit_fixture());
        let ids: Vec<&str> = fx.iter().map(|f| f.inst.id.as_str()).collect();
        assert_eq!(
            ids,
            ["RUSTSEC-2026-0486", "RUSTSEC-2025-0099"],
            "unmaintained without a range is left to the human queue"
        );
        assert_eq!(fx[1].patched, [">=1.1.6, <2.0.0", ">=2.1.0"]);
        assert_eq!(fx[1].inst.kind, "unsound");
    }

    fn versions(list: &[(&str, &str, bool)]) -> Value {
        serde_json::json!({"versions": list.iter().map(|(num, created, yanked)| serde_json::json!({
            "num": num, "created_at": format!("{created}T00:00:00Z"), "yanked": yanked
        })).collect::<Vec<_>>()})
    }

    #[test]
    fn pick_target_is_the_lowest_soaked_version_satisfying_every_advisory() {
        // now = 2026-11-11; soak 7d
        let now = 1_794_355_200; // 2026-11-11T00:00:00Z
        let v = versions(&[
            ("1.1.5", "2026-01-01", false),
            ("1.1.6", "2026-11-01", false), // 10d: soaked, satisfies >=1.1.6
            ("1.1.7", "2026-11-09", false), // 2d: not soaked
            ("2.0.1", "2026-10-01", false), // soaked but excluded by <2.0.0 of the second advisory
        ]);
        let reqs = vec![
            vec![">=1.1.6".to_string()],
            vec![">=1.1.6, <2.0.0".to_string(), ">=2.1.0".to_string()],
        ];
        assert_eq!(
            pick_target("1.1.5", &v, &reqs, now).unwrap(),
            Some("1.1.6".to_string())
        );
        // only the unsoaked one would do -> no proposal yet
        let v2 = versions(&[
            ("1.1.5", "2026-01-01", false),
            ("1.1.7", "2026-11-09", false),
        ]);
        assert_eq!(pick_target("1.1.5", &v2, &reqs, now).unwrap(), None);
        // a yanked fix is never a target
        let v3 = versions(&[
            ("1.1.5", "2026-01-01", false),
            ("1.1.6", "2026-10-01", true),
        ]);
        assert_eq!(pick_target("1.1.5", &v3, &reqs, now).unwrap(), None);
        // a range this evaluator cannot read is UNEVALUATED, not "no fix"
        let bad = vec![vec!["^1.1.6".to_string()]];
        assert!(pick_target("1.1.5", &v, &bad, now).is_err());
        // unparseable current version is an error too (explore's rule)
        assert!(pick_target("git-abc", &v, &reqs, now).is_err());
    }

    #[test]
    fn lock_packages_and_transitive_moves_exclude_directive_targets() {
        let before = lock_packages(
            "[[package]]\nname = \"a\"\nversion = \"1.0.0\"\n\n[[package]]\nname = \"libc\"\nversion = \"0.2.190\"\n\n[[package]]\nname = \"rustix\"\nversion = \"1.1.5\"\n\n[metadata]\nx = \"y\"\n",
        );
        let after = lock_packages(
            "[[package]]\nname = \"a\"\nversion = \"1.0.0\"\n\n[[package]]\nname = \"libc\"\nversion = \"0.2.191\"\n\n[[package]]\nname = \"rustix\"\nversion = \"1.1.6\"\n",
        );
        assert_eq!(before.len(), 3);
        let d = [Directive {
            package: "rustix".into(),
            version: "1.1.6".into(),
            at: Some("1.1.5".into()),
        }];
        assert_eq!(
            transitive_moves(&before, &after, &d),
            vec![("libc".to_string(), "0.2.191".to_string())]
        );
        assert!(transitive_moves(&before, &before, &d).is_empty());
    }
}
