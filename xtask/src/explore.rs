//! `cargo xtask explore` — candidate ENUMERATION for the promotion pipeline (#241/#239).
//!
//! Discovery, not blessing. Given a tool's dependency findings, this enumerates every
//! viable replacement version as a CANDIDATE SET — never a single pick — because
//! parallel release lines differ INDEPENDENTLY on posture and compatibility:
//! a same-line security backport may fix only the one advisory but break nothing,
//! while the newest major may clear more advisories and break the build. Those don't
//! co-vary, so the engine presents the tradeoff and a human (or the #241 gate on the
//! frozen result) resolves it.
//!
//! Facts come from primitives we already trust — no new pinned tool is admitted (#221):
//! * crates.io API  — version list, publish date (SOAK), yank status. Version identity
//!   is the crates.io semver, NEVER a git tag string: a survey of our
//!   six upstreams found bare (`0.20.2`), `v`-prefixed, monorepo
//!   product-prefixed (`rustsec-admin/v0.8.8`, `cyclonedx-bom-0.8.1`),
//!   and one repo that SWITCHED schemes mid-history. Everyone uses
//!   semver; nobody agrees how to name it. Tags are decoration.
//! * cargo-audit --json (blessed, digest-pinned) — advisory instances + `patched`
//!   ranges, which enumerate the BACKPORT LINES upstream maintains.
//! * cargo tree -i   — which crates constrain a version (the reachability rung).
//!
//! SOAK is per-candidate, computed from that candidate's own publish date: a backport
//! to an old line can be brand new (futures-util 0.3.34 was 11 days old when this was
//! written), so "old line" never implies "well-aged".
//!
//! This module performs NO promotion and holds no credential. Output is DATA — a
//! candidate report — which is the trust boundary: an attacker who owns exploration
//! owns a proposal, never a release.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

/// Default quarantine: a candidate younger than this has not soaked (#241).
pub const SOAK_DAYS: i64 = 7;

/// Compatibility tier relative to the version in use — the BLAST RADIUS axis, which is
/// independent of the posture axis. Cargo semver: pre-1.0, the MINOR field is the
/// breaking one (0.20.x -> 0.21.0 is breaking), which this encodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// Same compatible line (0.20.6 -> 0.20.9, or 1.2.3 -> 1.9.0): drop-in.
    SameLine,
    /// Breaking under cargo semver but same major (0.20.x -> 0.21.0).
    MinorBreaking,
    /// Major bump (0.x -> 1.0, 1.x -> 2.0).
    Major,
}

impl Tier {
    pub fn label(self) -> &'static str {
        match self {
            Tier::SameLine => "same-line (drop-in)",
            Tier::MinorBreaking => "minor (breaking pre-1.0)",
            Tier::Major => "MAJOR (breaking)",
        }
    }
}

/// Parsed semver triple. Only crates.io versions are parsed here (canonical semver);
/// git tags are never parsed for identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ver(pub u64, pub u64, pub u64);

/// Parse `MAJOR.MINOR.PATCH`, ignoring any pre-release/build suffix. Returns None for
/// anything non-conforming — a pre-release candidate is not proposable.
pub fn parse_ver(s: &str) -> Option<Ver> {
    if s.contains('-') {
        return None; // pre-release: never a promotion candidate
    }
    let mut it = s.split('.');
    let a = it.next()?.trim().parse().ok()?;
    let b = it.next()?.trim().parse().ok()?;
    let c = it.next().unwrap_or("0").trim().parse().ok()?;
    if it.next().is_some() {
        return None;
    }
    Some(Ver(a, b, c))
}

/// Cargo's compatibility rule: for 0.x, MINOR is the breaking field; from 1.0, MAJOR is.
pub fn tier_of(current: Ver, cand: Ver) -> Tier {
    if current.0 == 0 && cand.0 == 0 {
        if cand.1 == current.1 {
            Tier::SameLine
        } else {
            Tier::MinorBreaking
        }
    } else if cand.0 == current.0 {
        Tier::SameLine
    } else {
        Tier::Major
    }
}

/// One enumerated candidate: a concrete version with the facts needed to judge it on
/// BOTH axes (posture + compat) plus its own soak clock.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub version: String,
    pub ver: Ver,
    pub tier: Tier,
    pub published: String,
    pub age_days: i64,
    pub soaked: bool,
}

/// Days between an RFC3339 timestamp and `now_epoch`. Pure integer date math (no chrono):
/// parse YYYY-MM-DD, convert to days-since-epoch via the civil-date algorithm.
pub fn age_days(published: &str, now_epoch: i64) -> Option<i64> {
    let d = published.get(..10)?;
    let mut p = d.split('-');
    let y: i64 = p.next()?.parse().ok()?;
    let m: i64 = p.next()?.parse().ok()?;
    let day: i64 = p.next()?.parse().ok()?;
    // days_from_civil (Howard Hinnant)
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = if y2 >= 0 { y2 } else { y2 - 399 } / 400;
    let yoe = y2 - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some((now_epoch / 86_400) - days)
}

/// Build the candidate set for one dependency: every non-yanked, non-prerelease version
/// NEWER than current, annotated with tier + soak. Deliberately returns ALL of them —
/// the caller (and the human) sees the parallel lines, including backports to older
/// lines that a "highest version wins" rule would hide.
pub fn candidates_from_versions(
    versions: &Value,
    current: &str,
    now_epoch: i64,
    soak_days: i64,
) -> Vec<Candidate> {
    let Some(cur) = parse_ver(current) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for v in versions
        .get("versions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let num = v.get("num").and_then(Value::as_str).unwrap_or("");
        let Some(ver) = parse_ver(num) else { continue };
        if ver <= cur {
            continue;
        }
        if v.get("yanked").and_then(Value::as_bool).unwrap_or(false) {
            continue; // never propose a yanked version
        }
        let published = v
            .get("created_at")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let age = age_days(&published, now_epoch).unwrap_or(-1);
        out.push(Candidate {
            version: num.to_string(),
            ver,
            tier: tier_of(cur, ver),
            published: published.chars().take(10).collect(),
            age_days: age,
            soaked: age >= soak_days,
        });
    }
    out.sort_by_key(|c| c.ver);
    out
}

/// The recommended pick WITHIN one tier: newest version that has soaked. "Recent,
/// bounded by soaked" — never the bleeding edge, never needlessly old. Superseded for
/// reporting by per-LINE representatives; retained as the tier-level query.
#[allow(dead_code)]
pub fn pick_in_tier(cands: &[Candidate], tier: Tier) -> Option<&Candidate> {
    cands
        .iter()
        .filter(|c| c.tier == tier && c.soaked)
        .max_by(|a, b| a.ver.cmp(&b.ver))
}

/// A release LINE — the unit upstream actually maintains and backports into. Cargo
/// semver: pre-1.0 each MINOR is its own line (0.20.x, 0.21.x); from 1.0 each MAJOR is
/// (1.x, 2.x).
pub fn line_of(v: Ver) -> (u64, u64) {
    if v.0 == 0 { (0, v.1) } else { (v.0, 0) }
}

/// The REPRESENTATIVE set: the newest SOAKED patch within each release line (#239's
/// bounded enumeration). Per-line, not per-tier — grouping by tier would collapse
/// parallel minors (0.21.x and 0.22.x) into one entry and hide a maintained line.
///
/// Why newest-patch-per-line: within a line, the newest patch has usually absorbed
/// every fix backported to that line, so it is generally that line's best posture at
/// the same blast radius. USUALLY, not always — which is exactly why enumeration only
/// PROPOSES and the #241 gate MEASURES each candidate's real posture before anything
/// is blessed.
pub fn representatives(cands: &[Candidate]) -> Vec<&Candidate> {
    let mut best: BTreeMap<(u64, u64), &Candidate> = BTreeMap::new();
    for c in cands.iter().filter(|c| c.soaked) {
        best.entry(line_of(c.ver))
            .and_modify(|b| {
                if c.ver > b.ver {
                    *b = c;
                }
            })
            .or_insert(c);
    }
    best.into_values().collect()
}

/// The MINIMAL-ESCALATION ladder: representatives in ascending line order, so a caller
/// wanting the smallest viable move walks them front-to-back and stops at the first that
/// satisfies. If the CURRENT line's newest patch hasn't soaked (or doesn't fix the
/// finding), the next rung is the NEXT line up — one step — never a leap to the newest
/// line. `representatives` is already line-ordered; this names the intent and is what the
/// report prints in order.
pub fn escalation_ladder(cands: &[Candidate]) -> Vec<&Candidate> {
    representatives(cands)
}

/// Fetch a crate's version list from crates.io. curl (ambient, like git/gh — std has no
/// HTTP); read-only, unauthenticated, no secret involved.
pub fn fetch_versions(crate_name: &str) -> Result<Value, String> {
    let url = format!("https://crates.io/api/v1/crates/{crate_name}/versions?per_page=100");
    let out = Command::new("curl")
        .args(["-sSfL", "-H", "User-Agent: hp-thermal-explore", &url])
        .output()
        .map_err(|e| format!("curl: {e}"))?;
    if !out.status.success() {
        return Err(format!("crates.io fetch failed for {crate_name}"));
    }
    serde_json::from_slice(&out.stdout).map_err(|e| format!("crates.io JSON for {crate_name}: {e}"))
}

/// Advisory instances from a `cargo audit --json` document, as (package, version, id).
pub fn findings(audit: &Value) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    let mut push = |e: &Value, fallback: &str| {
        if let (Some(p), Some(v)) = (
            e.pointer("/package/name").and_then(Value::as_str),
            e.pointer("/package/version").and_then(Value::as_str),
        ) {
            let id = e
                .pointer("/advisory/id")
                .and_then(Value::as_str)
                .unwrap_or(fallback);
            out.push((p.to_string(), v.to_string(), id.to_string()));
        }
    };
    for e in audit
        .pointer("/vulnerabilities/list")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        push(e, "vulnerability");
    }
    if let Some(w) = audit.get("warnings").and_then(Value::as_object) {
        for (kind, arr) in w {
            for e in arr.as_array().into_iter().flatten() {
                push(e, kind);
            }
        }
    }
    out
}

pub fn run(args: &[String]) -> i32 {
    let mut lockfile = String::from("Cargo.lock");
    let mut now_epoch: i64 = 0;
    let mut soak = SOAK_DAYS;
    // Optional triage context: with --tool + --digest we can load the recorded baseline and
    // annotate each finding NEW-since-bless vs carried(acked) — turning a flat list into a
    // priority order. Omitted (ad-hoc local use) => enumeration only, no annotation.
    let mut tool: Option<String> = None;
    let mut digest: Option<String> = None;
    let mut evidence = PathBuf::from("supply-chain/evidence");
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--lockfile" => {
                if let Some(v) = it.next() {
                    lockfile = v.clone();
                }
            }
            "--now-epoch" => {
                if let Some(v) = it.next() {
                    now_epoch = v.parse().unwrap_or(0);
                }
            }
            "--soak-days" => {
                if let Some(v) = it.next() {
                    soak = v.parse().unwrap_or(SOAK_DAYS);
                }
            }
            "--tool" => tool = it.next().cloned(),
            "--digest" => digest = it.next().cloned(),
            "--evidence" => {
                if let Some(v) = it.next() {
                    evidence = v.into();
                }
            }
            other => {
                eprintln!("explore: unknown arg {other}");
                return 2;
            }
        }
    }
    if now_epoch == 0 {
        now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
    }

    // Findings come from the blessed auditor (#221: absolute path when pinned).
    let (prog, base): (String, Vec<String>) = match std::env::var("PINNED_TOOLS_DIR") {
        Ok(d) => (
            format!("{d}/cargo-audit{}", std::env::consts::EXE_SUFFIX),
            vec!["audit".into()],
        ),
        Err(_) => ("cargo".into(), vec!["audit".into()]),
    };
    let out = match Command::new(&prog)
        .args(&base)
        .args(["--json", "--no-fetch", "--file", &lockfile])
        .env_remove("CARGO")
        .env_remove("RUSTC")
        .env_remove("RUSTUP_TOOLCHAIN")
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            eprintln!("explore: cannot run {prog}: {e}");
            return 2;
        }
    };
    let audit: Value = match serde_json::from_slice(&out.stdout) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("explore: cargo-audit JSON unparseable: {e}");
            return 2;
        }
    };

    // One entry per affected (package, version) — dedup so a crate flagged by several
    // advisories is explored once, with all its advisory ids listed.
    let mut affected: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
    for (pkg, ver, id) in findings(&audit) {
        affected.entry((pkg, ver)).or_default().push(id);
    }
    if affected.is_empty() {
        println!("explore: no findings in {lockfile} — nothing to explore");
        return 0;
    }

    // Triage context (optional): the recorded baseline says what was true AT BLESS TIME, so
    // anything absent from it APPEARED SINCE — the actionable delta. Without it every finding
    // reads with equal weight (a 2023 DoS beside a fresh memory-corruption advisory).
    // fail-secure: a requested-but-missing baseline annotates nothing and says so, rather than
    // silently labelling genuinely-new findings as "carried".
    let baseline = match (&tool, &digest) {
        (Some(t), Some(d)) => match crate::monitor::load_baseline(&evidence, t, d) {
            Some((set, db)) => Some((set, db)),
            None => {
                println!(
                    "# NOTE: no recorded baseline at {}/{t}/{d} — findings cannot be marked \
                     NEW-since-bless (showing enumeration only)",
                    evidence.display()
                );
                None
            }
        },
        _ => None,
    };
    let acks = tool
        .as_ref()
        .and_then(|t| crate::gate::load_acks(&evidence.join(t).join("acks.jsonl")).ok());

    println!("# Candidate exploration — {lockfile}");
    println!(
        "# soak >= {soak}d; candidates are crates.io versions (canonical semver), never git tags"
    );
    if let Some((_, db)) = &baseline {
        println!(
            "# findings marked vs the recorded baseline (blessed at advisory-db {})",
            &db[..12.min(db.len())]
        );
    }
    for ((pkg, ver), ids) in &affected {
        // Per-advisory triage marks: NEW (appeared since bless, needs a decision) /
        // acked (already signed off) / carried (known at bless, not separately acked).
        let marked: Vec<String> = ids
            .iter()
            .map(|id| {
                let inst = crate::gate::Instance {
                    id: id.clone(),
                    package: pkg.clone(),
                    version: ver.clone(),
                    kind: String::new(),
                };
                let is_new = baseline
                    .as_ref()
                    .map(|(set, _)| {
                        !set.iter().any(|b| {
                            b.id == inst.id
                                && b.package == inst.package
                                && b.version == inst.version
                        })
                    })
                    .unwrap_or(false);
                let is_acked = acks
                    .as_ref()
                    .map(|a| crate::gate::ack_covers_vuln(a, &inst))
                    .unwrap_or(false);
                match (baseline.is_some(), is_new, is_acked) {
                    (true, true, false) => format!("{id} **NEW**"),
                    (true, true, true) => format!("{id} NEW/acked"),
                    (true, false, true) => format!("{id} acked"),
                    (true, false, false) => format!("{id} carried"),
                    _ => id.clone(),
                }
            })
            .collect();
        println!("\n## {pkg} {ver}  [{}]", marked.join(", "));
        let versions = match fetch_versions(pkg) {
            Ok(v) => v,
            Err(e) => {
                println!("  UNEVALUATED: {e}");
                continue;
            }
        };
        let cands = candidates_from_versions(&versions, ver, now_epoch, soak);
        if cands.is_empty() {
            println!("  no newer non-yanked release exists — upstream has no fix to adopt");
            continue;
        }
        let reps = escalation_ladder(&cands);
        if reps.is_empty() {
            let newest = cands.last().unwrap();
            println!(
                "  {} newer version(s) exist but NONE has soaked (newest {} is {}d old) — hold",
                cands.len(),
                newest.version,
                newest.age_days
            );
            continue;
        }
        for c in reps {
            println!(
                "  candidate {:<10} {:<26} published {} ({}d)  -> cargo update -p {pkg} --precise {}",
                c.version,
                c.tier.label(),
                c.published,
                c.age_days,
                c.version
            );
        }
        let unsoaked: Vec<&Candidate> = cands.iter().filter(|c| !c.soaked).collect();
        if !unsoaked.is_empty() {
            println!(
                "  ({} newer version(s) withheld: not yet soaked — {})",
                unsoaked.len(),
                unsoaked
                    .iter()
                    .map(|c| format!("{} @{}d", c.version, c.age_days))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
    println!(
        "\n# Each candidate is a DISTINCT tradeoff: posture and blast-radius vary independently.\n\
         # Nothing is promoted here — freeze a candidate's resolved lock, then run `xtask gate`."
    );
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    // 2026-08-22 ~00:00 UTC, so ages are deterministic in tests.
    const NOW: i64 = 1_787_356_800;

    fn versions(list: &[(&str, &str, bool)]) -> Value {
        let arr: Vec<Value> = list
            .iter()
            .map(|(num, created, yanked)| {
                serde_json::json!({"num": num, "created_at": created, "yanked": yanked})
            })
            .collect();
        serde_json::json!({ "versions": arr })
    }

    #[test]
    fn cargo_semver_tiers_pre_and_post_1_0() {
        // pre-1.0: MINOR is the breaking field
        assert_eq!(tier_of(Ver(0, 20, 6), Ver(0, 20, 9)), Tier::SameLine);
        assert_eq!(tier_of(Ver(0, 20, 6), Ver(0, 21, 0)), Tier::MinorBreaking);
        assert_eq!(tier_of(Ver(0, 20, 6), Ver(1, 0, 0)), Tier::Major);
        // post-1.0: MAJOR is
        assert_eq!(tier_of(Ver(1, 2, 3), Ver(1, 9, 0)), Tier::SameLine);
        assert_eq!(tier_of(Ver(1, 2, 3), Ver(2, 0, 0)), Tier::Major);
    }

    #[test]
    fn prerelease_is_never_a_candidate() {
        assert!(parse_ver("1.0.0-rc.2").is_none());
        assert!(parse_ver("0.8.15-cvss-cries-wolf").is_none());
        assert_eq!(parse_ver("0.8.15"), Some(Ver(0, 8, 15)));
    }

    #[test]
    fn yanked_versions_are_never_proposed() {
        let v = versions(&[
            ("0.3.30", "2026-01-01T00:00:00Z", true),
            ("0.3.34", "2026-01-02T00:00:00Z", false),
        ]);
        let c = candidates_from_versions(&v, "0.3.21", NOW, 7);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].version, "0.3.34");
    }

    #[test]
    fn soak_is_per_candidate_not_per_line() {
        // A BACKPORT to an old line can be fresher than a newer line's release — so
        // "older line" must never imply "well soaked".
        let v = versions(&[
            ("0.20.9", "2026-08-20T00:00:00Z", false), // 2d old backport
            ("0.21.0", "2026-01-01T00:00:00Z", false), // long soaked
        ]);
        let c = candidates_from_versions(&v, "0.20.6", NOW, 7);
        let same = c.iter().find(|x| x.version == "0.20.9").unwrap();
        let minor = c.iter().find(|x| x.version == "0.21.0").unwrap();
        assert!(!same.soaked, "fresh backport must not count as soaked");
        assert!(minor.soaked);
        // the drop-in tier therefore yields NO pick; the breaking tier does
        assert!(pick_in_tier(&c, Tier::SameLine).is_none());
        assert_eq!(
            pick_in_tier(&c, Tier::MinorBreaking).unwrap().version,
            "0.21.0"
        );
    }

    #[test]
    fn representatives_expose_parallel_lines_not_just_newest() {
        // Parallel maintained lines: a same-line backport AND a newer major both exist.
        // "Highest version wins" would hide the drop-in option entirely.
        let v = versions(&[
            ("0.20.9", "2026-01-01T00:00:00Z", false),
            ("0.21.4", "2026-02-01T00:00:00Z", false),
            ("1.1.0", "2026-03-01T00:00:00Z", false),
        ]);
        let c = candidates_from_versions(&v, "0.20.6", NOW, 7);
        let reps = representatives(&c);
        assert_eq!(reps.len(), 3, "one representative per LINE");
        assert_eq!(reps[0].version, "0.20.9");
        assert_eq!(reps[0].tier, Tier::SameLine);
        assert_eq!(reps[2].tier, Tier::Major);
    }

    #[test]
    fn representative_is_newest_patch_within_each_line() {
        // Within a line the newest patch has usually absorbed that line's backports, so
        // it represents the line. Two parallel minors must BOTH appear — tier-grouping
        // would have collapsed them into one entry and hidden a maintained line.
        let v = versions(&[
            ("0.21.1", "2026-01-01T00:00:00Z", false),
            ("0.21.7", "2026-02-01T00:00:00Z", false), // newest in 0.21 line
            ("0.22.2", "2026-03-01T00:00:00Z", false),
            ("0.22.5", "2026-04-01T00:00:00Z", false), // newest in 0.22 line
        ]);
        let c = candidates_from_versions(&v, "0.21.0", NOW, 7);
        let reps = representatives(&c);
        let picked: Vec<&str> = reps.iter().map(|r| r.version.as_str()).collect();
        assert_eq!(picked, vec!["0.21.7", "0.22.5"]);
    }

    #[test]
    fn unsoaked_newest_patch_falls_back_to_older_soaked_in_same_line() {
        // A brand-new patch does not mask the line: the line is still represented by its
        // newest SOAKED patch, so the option remains available rather than disappearing.
        let v = versions(&[
            ("0.21.5", "2026-06-01T00:00:00Z", false),
            ("0.21.9", "2026-08-21T00:00:00Z", false), // 1d old — withheld
        ]);
        let c = candidates_from_versions(&v, "0.21.0", NOW, 7);
        let reps = representatives(&c);
        assert_eq!(reps.len(), 1);
        assert_eq!(reps[0].version, "0.21.5");
    }

    #[test]
    fn pick_is_newest_soaked_within_tier() {
        let v = versions(&[
            ("0.20.7", "2026-01-01T00:00:00Z", false),
            ("0.20.9", "2026-06-01T00:00:00Z", false),
            ("0.20.10", "2026-08-21T00:00:00Z", false), // too fresh
        ]);
        let c = candidates_from_versions(&v, "0.20.6", NOW, 7);
        assert_eq!(pick_in_tier(&c, Tier::SameLine).unwrap().version, "0.20.9");
    }

    #[test]
    fn minimal_escalation_steps_one_line_at_a_time() {
        // Current 0.20.x line's newest patch is too fresh to soak. The minimal move is
        // the NEXT line (0.21.x), not a leap to the newest line (0.23.x) — the ladder is
        // ascending, so walking it front-to-back yields the smallest viable step first.
        let v = versions(&[
            ("0.20.9", "2026-08-21T00:00:00Z", false), // 1d — withheld
            ("0.21.6", "2026-03-01T00:00:00Z", false), // next line up, soaked
            ("0.23.1", "2026-04-01T00:00:00Z", false), // newest line, soaked
        ]);
        let c = candidates_from_versions(&v, "0.20.6", NOW, 7);
        let ladder = escalation_ladder(&c);
        let order: Vec<&str> = ladder.iter().map(|r| r.version.as_str()).collect();
        assert_eq!(
            order,
            vec!["0.21.6", "0.23.1"],
            "ascending: minimal step first"
        );
        assert_eq!(ladder[0].tier, Tier::MinorBreaking);
    }

    #[test]
    fn age_days_math() {
        assert_eq!(age_days("2026-08-15T00:00:00Z", NOW), Some(7));
        assert_eq!(age_days("2026-08-22T00:00:00Z", NOW), Some(0));
    }

    #[test]
    fn findings_include_warnings_and_vulns() {
        let a: Value = serde_json::from_str(
            r#"{"vulnerabilities":{"list":[{"advisory":{"id":"RUSTSEC-1"},"package":{"name":"a","version":"1.0.0"}}]},
                "warnings":{"yanked":[{"package":{"name":"b","version":"0.3.21"}}]}}"#,
        )
        .unwrap();
        let f = findings(&a);
        assert_eq!(f.len(), 2);
        assert!(f.iter().any(|(p, _, id)| p == "b" && id == "yanked"));
    }
}
