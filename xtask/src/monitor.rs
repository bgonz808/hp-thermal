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
    Instance, ack_covers_vuln, ack_template_vuln, extract_instances, load_acks, parse_tools_lock,
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
        let fresh = extract_instances(&audit);
        let (new, carried, gone) = classify(&baseline, &fresh);

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
        for i in &gone {
            println!(
                "  - resolved: {} {} {} (no longer reported)",
                i.id, i.package, i.version
            );
        }
        if new.is_empty() {
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
                "FAIL — new advisory instance(s) since bless need a recorded decision (ack or bump)"
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
