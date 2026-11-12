//! `cargo xtask monitor-vuln` — the KNOWLEDGE-DELTA loop for the vuln axis (#226/#241 §5).
//!
//! Closes the gap the supply-chain monitor documented: the #241 gate fires on BUMPS, so an
//! advisory published between bumps is invisible until the next one. This asks the other
//! question — same bytes, newer knowledge: **is what we already blessed still acceptable?**
//!
//! Inputs (all read-only; this holds no credential and writes nothing):
//!   * tools/TOOLS.lock — the LIVE FRONTIER. Current pins only, never the historical evidence
//!     store: no gate consumes a finding about a binary nobody runs. O(pinned), flat.
//!   * each pinned rev's upstream Cargo.lock (fetched)
//!   * supply-chain/evidence/<tool>/<digest>/vuln.jsonl — the recorded baseline: what was
//!     true AT BLESS TIME, and (in its header) the advisory-DB commit it was scanned at.
//!   * supply-chain/evidence/<tool>/acks.jsonl — residual risk already signed off.
//!   * a FRESH advisory DB — the moving part.
//!
//! Output: a report + an exit code. Deliberately NOT an evidence write. An observation is
//! RECOMPUTABLE — the baseline records its DB commit, the advisory DB is itself a dated git
//! history, and every RUSTSEC record carries its own publication date — so storing weekly
//! snapshots would duplicate a time series upstream already maintains authoritatively. What
//! is NOT recomputable is a human DECISION, and that already lands in acks.jsonl with author
//! and timestamp. Corollary: this job never needs `contents: write`, so an unattended
//! scheduled workflow keeps zero ability to mutate the repo.
//!
//! Verdict: a NEW unacked instance FAILS (paging); an acked one warns (visible, not paging) —
//! the same notice-by-failure contract as the VT monitor. An ack written in response to a
//! finding here ALSO satisfies the #241 gate on the next bump: one lattice, two consumers.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::gate::{
    GoneMechanism, Instance, ack_covers_vuln, ack_template_vuln,
    ack_template_vuln_not_affected_observed, extract_instances, load_acks, parse_tools_lock,
    resolve_lock, run_audit,
};

/// Load the recorded baseline instance set for a blessed digest. `None` = no baseline
/// recorded (fail-secure: the caller must treat every finding as unreviewed, never as
/// "carried"). Line 1 of vuln.jsonl is the scan header (schema/scanner/db), not an instance.
pub(crate) fn load_baseline(
    evidence_dir: &Path,
    tool: &str,
    digest: &str,
) -> Option<(BTreeSet<Instance>, String)> {
    let path = evidence_dir.join(tool).join(digest).join("vuln.jsonl");
    let text = std::fs::read_to_string(path).ok()?;
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    let header: serde_json::Value = serde_json::from_str(lines.next()?).ok()?;
    let db = header
        .pointer("/scanner/db/version")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let mut set = BTreeSet::new();
    for l in lines {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(l) else {
            continue;
        };
        let (Some(id), Some(pkg), Some(ver)) = (
            v.get("id").and_then(|x| x.as_str()),
            v.get("package").and_then(|x| x.as_str()),
            v.get("version").and_then(|x| x.as_str()),
        ) else {
            continue;
        };
        set.insert(Instance {
            id: id.to_string(),
            package: pkg.to_string(),
            version: ver.to_string(),
            kind: v
                .get("kind")
                .and_then(|x| x.as_str())
                .unwrap_or("vulnerability")
                .to_string(),
        });
    }
    Some((set, db))
}

/// Classify a fresh scan against the recorded baseline. Matching is on the INSTANCE TUPLE
/// (id, package, version) — never a bare advisory id (#241 §6), so a second resident version
/// of an already-known advisory registers as NEW rather than hiding inside "carried".
/// Where cargo-audit keeps its clone of rustsec/advisory-db (its documented default).
fn advisory_db_dir() -> PathBuf {
    if let Some(h) = std::env::var_os("CARGO_HOME") {
        return PathBuf::from(h).join("advisory-db");
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .unwrap_or_default();
    PathBuf::from(home).join(".cargo").join("advisory-db")
}

/// `now` must descend from `base` in the DB clone (equal passes). Unknown commits, a missing
/// clone, or an unrelated history all fail: GONE is only meaningful against a newer DB (#251).
fn db_descends(db_dir: &Path, base: &str, now: &str) -> Result<(), String> {
    let hex = |c: &str| c.len() >= 7 && c.chars().all(|ch| ch.is_ascii_hexdigit());
    if !hex(base) {
        return Err(format!(
            "baseline records no advisory-DB commit ({base:?}); cannot order this run's DB against it"
        ));
    }
    if !hex(now) {
        return Err(format!(
            "this run's cargo-audit report carries no database.last-commit ({now:?}); cannot order it against the baseline"
        ));
    }
    let st = std::process::Command::new("git")
        .arg("-C")
        .arg(db_dir)
        .args(["merge-base", "--is-ancestor", base, now])
        .status()
        .map_err(|e| format!("cannot run git in {}: {e}", db_dir.display()))?;
    match st.code() {
        Some(0) => Ok(()),
        Some(1) => Err(format!(
            "advisory DB {} does not descend from the baseline's {} — stale or unrelated DB",
            &now[..12.min(now.len())],
            &base[..12.min(base.len())]
        )),
        c => Err(format!(
            "git merge-base in {} failed (exit {c:?}) — is this cargo-audit's DB clone?",
            db_dir.display()
        )),
    }
}

/// Exact `name`/`version` block match in a Cargo.lock. Unreadable lock -> false (caller
/// treats absence as UNEVALUATED, never as GONE).
fn lock_contains(lock: &Path, pkg: &str, ver: &str) -> bool {
    let Ok(text) = std::fs::read_to_string(lock) else {
        return false;
    };
    text.split("[[package]]").skip(1).any(|b| {
        let has = |k: &str, v: &str| b.lines().any(|l| l.trim() == format!("{k} = \"{v}\""));
        has("name", pkg) && has("version", ver)
    })
}

/// Read why the DB stopped reporting an instance from `crates/<pkg>/<ID>.md` in the clone.
/// Ok(None): a warning class with no advisory file (`yanked`) — registry state, not an advisory.
/// Err: the file is missing or unreadable — the mechanism cannot be named, so no statement.
fn gone_mechanism(db_dir: &Path, i: &Instance) -> Result<Option<GoneMechanism>, String> {
    if !i.id.starts_with("RUSTSEC-") {
        return Ok(None);
    }
    let path = db_dir
        .join("crates")
        .join(&i.package)
        .join(format!("{}.md", i.id));
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("advisory file {} unreadable ({e})", path.display()))?;
    let withdrawn = text.lines().map(str::trim).find_map(|l| {
        l.strip_prefix("withdrawn")
            .and_then(|r| r.trim_start().strip_prefix('='))
            .map(|r| r.trim().trim_matches('"').to_string())
    });
    Ok(Some(match withdrawn {
        Some(d) if !d.is_empty() => GoneMechanism::Withdrawn(d),
        _ => GoneMechanism::VersionsNarrowed,
    }))
}

/// The baseline header's `rawPayload` pointer: the cargo-audit report the recorded instance set
/// was derived from, kept in the `tools` release asset store by content-addressed name.
fn baseline_raw_payload(
    evidence_dir: &Path,
    tool: &str,
    digest: &str,
) -> Option<(String, String, String)> {
    let text =
        std::fs::read_to_string(evidence_dir.join(tool).join(digest).join("vuln.jsonl")).ok()?;
    let header: serde_json::Value =
        serde_json::from_str(text.lines().find(|l| !l.trim().is_empty())?).ok()?;
    let rp = header.get("rawPayload")?;
    Some((
        rp.get("store")?.as_str()?.to_string(),
        rp.get("asset")?.as_str()?.to_string(),
        rp.get("sha256")?.as_str()?.to_string(),
    ))
}

/// Asset digests of a release as GitHub serves them (name -> sha256 hex). One call per run; a
/// failure here makes every pin UNEVALUATED rather than silently skipping the custody check.
pub(crate) fn store_digests(
    tag: &str,
) -> Result<std::collections::BTreeMap<String, String>, String> {
    let out = std::process::Command::new("gh")
        .args(["release", "view", tag, "--json", "assets"])
        .output()
        .map_err(|e| format!("cannot run gh: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "gh release view {tag} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout)
        .map_err(|e| format!("gh release view {tag}: unparseable JSON ({e})"))?;
    let mut m = std::collections::BTreeMap::new();
    for a in v
        .get("assets")
        .and_then(|a| a.as_array())
        .into_iter()
        .flatten()
    {
        if let (Some(n), Some(d)) = (
            a.get("name").and_then(|x| x.as_str()),
            a.get("digest").and_then(|x| x.as_str()),
        ) {
            m.insert(
                n.to_string(),
                d.strip_prefix("sha256:").unwrap_or(d).to_string(),
            );
        }
    }
    Ok(m)
}

/// The backing report must exist in the store under its recorded digest. The store is an
/// UNTRUSTED byte store by design; the digest committed in-tree is the trust anchor, GitHub's
/// asset digest is what is compared here (no download). Missing or mismatched = the recorded
/// instance set has no verifiable backing.
fn raw_payload_custody(
    store: &Result<std::collections::BTreeMap<String, String>, String>,
    store_name: &str,
    asset: &str,
    sha: &str,
) -> Result<(), String> {
    if store_name != "tools release" {
        return Err(format!(
            "rawPayload store {store_name:?} is not one this check knows"
        ));
    }
    let m = store
        .as_ref()
        .map_err(|e| format!("cannot read the tools release store: {e}"))?;
    match m.get(asset) {
        None => Err(format!(
            "rawPayload asset {asset} is not in the tools release store"
        )),
        Some(d) if d != sha => Err(format!(
            "rawPayload asset {asset}: store digest {} != recorded {}",
            &d[..12.min(d.len())],
            &sha[..12.min(sha.len())]
        )),
        Some(_) => Ok(()),
    }
}

pub(crate) fn classify(
    baseline: &BTreeSet<Instance>,
    fresh: &BTreeSet<Instance>,
) -> (Vec<Instance>, Vec<Instance>, Vec<Instance>) {
    let key = |i: &Instance| (i.id.clone(), i.package.clone(), i.version.clone());
    let base_keys: BTreeSet<_> = baseline.iter().map(key).collect();
    let fresh_keys: BTreeSet<_> = fresh.iter().map(key).collect();
    let new: Vec<Instance> = fresh
        .iter()
        .filter(|i| !base_keys.contains(&key(i)))
        .cloned()
        .collect();
    let carried: Vec<Instance> = fresh
        .iter()
        .filter(|i| base_keys.contains(&key(i)))
        .cloned()
        .collect();
    // Withdrawn/superseded upstream, or fixed by a dep the lockfile no longer resolves to.
    let gone: Vec<Instance> = baseline
        .iter()
        .filter(|i| !fresh_keys.contains(&key(i)))
        .cloned()
        .collect();
    (new, carried, gone)
}

pub fn run(args: &[String]) -> i32 {
    let mut lock_path = PathBuf::from("tools/TOOLS.lock");
    let mut evidence_dir = PathBuf::from("supply-chain/evidence");
    let mut floors_path = PathBuf::from(crate::floors::DEFAULT_PATH);
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--tools-lock" => {
                if let Some(v) = it.next() {
                    lock_path = v.into();
                }
            }
            "--evidence" => {
                if let Some(v) = it.next() {
                    evidence_dir = v.into();
                }
            }
            "--floors" => {
                if let Some(v) = it.next() {
                    floors_path = v.into();
                }
            }
            other => {
                eprintln!("monitor-vuln: unknown arg {other}");
                return 2;
            }
        }
    }
    let text = match std::fs::read_to_string(&lock_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("monitor-vuln: read {}: {e}", lock_path.display());
            return 2;
        }
    };
    let pins = parse_tools_lock(&text);
    if pins.is_empty() {
        eprintln!("monitor-vuln: no pins parsed from {}", lock_path.display());
        return 2;
    }
    // Absolute floors apply to BLESSED bytes too: knowledge moves, and a floor crossed by
    // the live frontier fails the monitor whether or not the instance is acked.
    let floors = match crate::floors::load(&floors_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!(
                "monitor-vuln: UNEVALUATED — {e} (fail-secure: no floors file is not no floors)"
            );
            return 1;
        }
    };

    println!(
        "# Vuln-axis knowledge delta — live frontier ({} pins)",
        pins.len()
    );
    println!("# same bytes, newer advisory DB: is what we blessed still acceptable?\n");

    let tmp = std::env::temp_dir();
    let mut first = true;
    let mut fail = false;
    let mut unevaluated = 0;
    // Only the FETCHING run echoes database.last-commit; --no-fetch runs omit it. Every run
    // this invocation shares one DB by construction, so capture it once and reuse — reporting
    // "unknown" for the rest would misrepresent a known instrument (#241 §5).
    let mut run_db = String::new();
    let db_dir = advisory_db_dir();
    // Custody of the backing reports: one store listing for the whole run.
    let store = store_digests("tools");

    for p in &pins {
        let acks = match load_acks(&evidence_dir.join(&p.name).join("acks.jsonl")) {
            Ok(a) => a,
            Err(e) => {
                // A malformed ack file must never read as "nothing is acked".
                println!("## {}\n  UNEVALUATED: {e}", p.name);
                unevaluated += 1;
                fail = true;
                continue;
            }
        };
        let Some((baseline, base_db)) = load_baseline(&evidence_dir, &p.name, &p.sha) else {
            println!(
                "## {}\n  UNEVALUATED: no recorded baseline at supply-chain/evidence/{}/{} \
                 — cannot distinguish new from carried (fail-secure)",
                p.name, p.name, p.sha
            );
            unevaluated += 1;
            fail = true;
            continue;
        };
        // The baseline's backing report must be where the header says, under its digest.
        let custody = match baseline_raw_payload(&evidence_dir, &p.name, &p.sha) {
            None => Err("baseline header has no rawPayload pointer — the recorded instance set has no backing report".to_string()),
            Some((store_name, asset, sha)) => raw_payload_custody(&store, &store_name, &asset, &sha),
        };
        if let Err(e) = custody {
            println!("## {}\n  UNEVALUATED: {e}", p.name);
            unevaluated += 1;
            fail = true;
            continue;
        }
        // #255 §5: evaluate the lock the blessed binary was BUILT from — a committed frozen
        // lock (tools/locks/<name>.lock) overrides upstream's resolution, exactly as it does
        // in the producer. Evaluating upstream's lock for a frozen tool is stale toward old
        // versions: over-reports what we fixed and MISSES advisories on the versions we
        // froze forward to (the fail-open direction).
        let dest = tmp.join(format!("monitor-{}.lock", p.name));
        let (lock, lock_src) = match resolve_lock(
            &p.name,
            &p.repo,
            &p.rev,
            Some(Path::new("tools/locks")),
            &dest,
        ) {
            Ok(v) => v,
            Err(e) => {
                println!("## {}\n  UNEVALUATED: {e}", p.name);
                unevaluated += 1;
                fail = true;
                continue;
            }
        };
        // ONE DB state across every tool this run: the first scan fetches, the rest reuse it.
        let audit = match run_audit(&lock, !first) {
            Ok(a) => a,
            Err(e) => {
                println!("## {}\n  UNEVALUATED: {e}", p.name);
                unevaluated += 1;
                fail = true;
                continue;
            }
        };
        first = false;
        if run_db.is_empty() {
            run_db = audit
                .pointer("/database/last-commit")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
        }
        let now_db = run_db.as_str();
        // #251: against an older or unrelated DB, every advisory it lacks would read as GONE.
        // The clone cargo-audit fetched is a git repository: this run's commit must descend
        // from the baseline's (equal counts), else the pin is UNEVALUATED.
        if let Err(e) = db_descends(&db_dir, &base_db, now_db) {
            println!("## {}\n  UNEVALUATED: {e}", p.name);
            unevaluated += 1;
            fail = true;
            continue;
        }
        let fresh = extract_instances(&audit);
        let (new, carried, gone) = classify(&baseline, &fresh);
        let stops = floors.vuln_stops(&fresh, &crate::floors::extract_cvss(&audit));

        println!(
            "## {} (`{}`)  [lock: {lock_src}]",
            p.name,
            &p.sha[..12.min(p.sha.len())]
        );
        println!(
            "  blessed at db {} -> now db {}   ({} new / {} carried / {} gone)",
            &base_db[..12.min(base_db.len())],
            &now_db[..12.min(now_db.len())],
            new.len(),
            carried.len(),
            gone.len()
        );
        // #251: GONE means RustSec stopped asserting the advisory against these bytes. The
        // bytes did not change, so this is never `fixed`: read the mechanism from the advisory
        // file in the DB clone and print the grounded `not_affected` line to append. The earlier
        // statement stays — the sequence is the record. No mechanism, no template.
        for i in &gone {
            println!(
                "  - resolved: {} {} {} (no longer reported)",
                i.id, i.package, i.version
            );
            let field = |a: &serde_json::Value, k: &str| {
                a.get(k).and_then(|v| v.as_str()).unwrap_or("?").to_string()
            };
            if !lock_contains(&lock, &i.package, &i.version) {
                println!(
                    "      UNEVALUATED: {} {} is not in the lock evaluated ({lock_src}) — the lock drifted from the one the blessed bytes were built from; not GONE",
                    i.package, i.version
                );
                unevaluated += 1;
                fail = true;
                continue;
            }
            let how = match gone_mechanism(&db_dir, i) {
                Err(e) => {
                    println!(
                        "      UNEVALUATED: mechanism undetermined — {e}; no statement printed"
                    );
                    unevaluated += 1;
                    fail = true;
                    continue;
                }
                Ok(None) => {
                    println!(
                        "      `{}` is registry state, not an advisory: no VEX statement applies; the earlier statement stands",
                        i.kind
                    );
                    continue;
                }
                Ok(Some(how)) => how,
            };
            match crate::gate::last_vuln_ack(&acks, i) {
                Some(a) if crate::gate::observed_absent_at_db(a).is_some() => {
                    println!(
                        "      not_affected statement grounded in this observation already recorded"
                    );
                    continue;
                }
                Some(a) => println!(
                    "      supersedes the {} statement signed by {} on {} — record it by appending this line to supply-chain/evidence/{}/acks.jsonl (fill author / timestamp):",
                    field(a, "status"),
                    field(a, "author"),
                    field(a, "timestamp"),
                    p.name
                ),
                None => println!(
                    "      no statement on record — record the observation by appending this line to supply-chain/evidence/{}/acks.jsonl (fill author / timestamp):",
                    p.name
                ),
            }
            println!(
                "      {}",
                ack_template_vuln_not_affected_observed(&p.name, i, now_db, &how)
            );
        }
        for why in &stops {
            println!("  HARD-STOP: {why}");
            fail = true;
        }
        if new.is_empty() && stops.is_empty() {
            println!("  OK — no advisory instance has appeared since bless");
        }
        for i in &new {
            if ack_covers_vuln(&acks, i) {
                // Signed off (typically from a prior monitor run): visible, not paging.
                println!(
                    "  ACKED-NEW: {} {} {} — signed off, monitored",
                    i.id, i.package, i.version
                );
            } else {
                println!(
                    "  NEW: {} {} {} [{}] — appeared since bless, NOT signed off",
                    i.id, i.package, i.version, i.kind
                );
                println!(
                    "      accept it by committing this line to supply-chain/evidence/{}/acks.jsonl",
                    p.name
                );
                println!(
                    "      (fill status_notes / author / timestamp / refs), or bump — see the exploration report:"
                );
                println!("      {}", ack_template_vuln(&p.name, i));
                fail = true;
            }
        }
        if !acks.rejected.is_empty() {
            println!(
                "  ack-quality: {} line(s) rejected and NOT counted:\n    {}",
                acks.rejected.len(),
                acks.rejected.join("\n    ")
            );
            fail = true;
        }
    }

    println!(
        "\n# {}",
        if fail {
            if unevaluated > 0 {
                "FAIL — new unacked advisory instance(s) and/or UNEVALUATED pins (fail-secure: \
                 missing data never reads as clean)"
            } else {
                "FAIL — new advisory instance(s) need a recorded decision (ack or bump), and/or an \n                 absolute floor is crossed (HARD-STOP: not ackable — bump or remove)"
            }
        } else {
            "PASS — every pinned tool's advisory set is unchanged-or-acked since bless"
        }
    );
    i32::from(fail)
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
    fn gone_mechanism_reads_withdrawn_else_narrowed_and_skips_registry_state() {
        let dir = std::env::temp_dir().join(format!("mon-mech-{}", std::process::id()));
        let crates = dir.join("crates").join("p");
        std::fs::create_dir_all(&crates).unwrap();
        std::fs::write(
            crates.join("RUSTSEC-1.md"),
            "```toml\nid = \"RUSTSEC-1\"\npackage = \"p\"\n#withdrawn = \"never\"\nwithdrawn = \"2026-02-03\"\n```\n",
        )
        .unwrap();
        std::fs::write(
            crates.join("RUSTSEC-2.md"),
            "```toml\nid = \"RUSTSEC-2\"\n[versions]\npatched = [\">= 2\"]\n```\n",
        )
        .unwrap();
        let i = |id: &str| Instance {
            id: id.into(),
            package: "p".into(),
            version: "1".into(),
            kind: "vulnerability".into(),
        };
        assert_eq!(
            gone_mechanism(&dir, &i("RUSTSEC-1")).unwrap(),
            Some(GoneMechanism::Withdrawn("2026-02-03".into()))
        );
        assert_eq!(
            gone_mechanism(&dir, &i("RUSTSEC-2")).unwrap(),
            Some(GoneMechanism::VersionsNarrowed)
        );
        assert!(
            gone_mechanism(&dir, &i("RUSTSEC-3")).is_err(),
            "missing advisory file is not a mechanism"
        );
        assert_eq!(gone_mechanism(&dir, &i("yanked")).unwrap(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lock_contains_needs_exact_name_and_version_in_one_block() {
        let dir = std::env::temp_dir().join(format!("mon-lock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let l = dir.join("Cargo.lock");
        std::fs::write(&l, "[[package]]\nname = \"a\"\nversion = \"1.0.0\"\n\n[[package]]\nname = \"b\"\nversion = \"2.0.0\"\n").unwrap();
        assert!(lock_contains(&l, "a", "1.0.0"));
        assert!(
            !lock_contains(&l, "a", "2.0.0"),
            "version from another block must not match"
        );
        assert!(!lock_contains(&dir.join("missing.lock"), "a", "1.0.0"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn db_descends_refuses_unknown_commits_before_touching_git() {
        let nowhere = Path::new("/definitely/not/a/clone");
        assert!(db_descends(nowhere, "unknown", "0123456789abcdef").is_err());
        assert!(db_descends(nowhere, "0123456789abcdef", "unknown").is_err());
        assert!(
            db_descends(nowhere, "0123456789abcdef", "0123456789abcdef").is_err(),
            "no clone -> error, never Ok"
        );
    }

    #[test]
    fn raw_payload_custody_needs_known_store_present_asset_and_matching_digest() {
        let mut m = std::collections::BTreeMap::new();
        m.insert("audit-raw-abc.json".to_string(), "abc123".to_string());
        let store = Ok(m);
        assert!(
            raw_payload_custody(&store, "tools release", "audit-raw-abc.json", "abc123").is_ok()
        );
        assert!(raw_payload_custody(&store, "tools release", "audit-raw-abc.json", "zzz").is_err());
        assert!(
            raw_payload_custody(&store, "tools release", "audit-raw-missing.json", "abc123")
                .is_err()
        );
        assert!(raw_payload_custody(&store, "elsewhere", "audit-raw-abc.json", "abc123").is_err());
        let down: Result<std::collections::BTreeMap<String, String>, String> =
            Err("offline".into());
        assert!(
            raw_payload_custody(&down, "tools release", "audit-raw-abc.json", "abc123").is_err(),
            "store unreadable is not a pass"
        );
    }

    #[test]
    fn classify_splits_new_carried_gone() {
        let base: BTreeSet<Instance> = [inst("A", "p", "1"), inst("B", "q", "2")].into();
        let fresh: BTreeSet<Instance> = [inst("B", "q", "2"), inst("C", "r", "3")].into();
        let (new, carried, gone) = classify(&base, &fresh);
        assert_eq!(new, vec![inst("C", "r", "3")]);
        assert_eq!(carried, vec![inst("B", "q", "2")]);
        assert_eq!(gone, vec![inst("A", "p", "1")]);
    }

    #[test]
    fn same_advisory_new_resident_version_is_new_not_carried() {
        // #241 §6: identity is the instance tuple. A second vulnerable copy of an
        // already-known advisory is a REGRESSION that bare-ID matching would hide.
        let base: BTreeSet<Instance> = [inst("A", "p", "1.0")].into();
        let fresh: BTreeSet<Instance> = [inst("A", "p", "1.0"), inst("A", "p", "2.0")].into();
        let (new, carried, _) = classify(&base, &fresh);
        assert_eq!(new, vec![inst("A", "p", "2.0")]);
        assert_eq!(carried, vec![inst("A", "p", "1.0")]);
    }

    #[test]
    fn no_change_yields_no_new() {
        let base: BTreeSet<Instance> = [inst("A", "p", "1")].into();
        let (new, carried, gone) = classify(&base, &base.clone());
        assert!(new.is_empty());
        assert_eq!(carried.len(), 1);
        assert!(gone.is_empty());
    }

    #[test]
    fn baseline_loader_skips_header_and_reads_db_commit() {
        let dir = std::env::temp_dir().join(format!("monitor-test-{}", std::process::id()));
        let d = dir.join("t").join("abc");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("vuln.jsonl"),
            "{\"schema\":\"x\",\"scanner\":{\"db\":{\"version\":\"deadbeefcafe1234\"}}}\n\
             {\"id\":\"RUSTSEC-1\",\"package\":\"p\",\"version\":\"1.0\",\"kind\":\"vulnerability\"}\n",
        )
        .unwrap();
        let (set, db) = load_baseline(&dir, "t", "abc").unwrap();
        assert_eq!(db, "deadbeefcafe1234");
        assert_eq!(set.len(), 1, "header must not be counted as an instance");
        assert!(set.contains(&inst("RUSTSEC-1", "p", "1.0")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_baseline_is_none_not_empty_set() {
        // Fail-secure: absent evidence must be distinguishable from "clean baseline",
        // else every finding would silently classify as "carried".
        let dir = std::env::temp_dir().join(format!("monitor-none-{}", std::process::id()));
        assert!(load_baseline(&dir, "nope", "abc").is_none());
    }
}
