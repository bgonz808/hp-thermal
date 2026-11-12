//! `xtask ci` step: cargo-vet exemptions for xtask's own dependency tree may cover only crates
//! the build never compiles, unless a recorded, dated debt entry says otherwise.
//!
//! Why this exists: cargo-vet audits the whole lockfile, conservatively. xtask's lock carries
//! crates reachable only through `cfg(any())` dependency edges (serde_core -> serde_derive,
//! serde_json -> serde), which Cargo records so versions stay paired but which no real target
//! ever compiles. Those are exempted from audit with a note saying exactly that. An exemption
//! is a statement about the build graph, and a statement nobody re-checks rots: an upstream
//! feature or manifest change could start compiling an exempted crate without a version bump,
//! and the exemption would still "cover" it. This step turns the statement into a check: for
//! every lane we build on, the resolved graph (normal + build edges) must contain no exempted
//! crate, except those listed in `supply-chain/policy/vet-debt.json` with an unexpired date.
//!
//! Fail-closed: an unparseable config, a cargo-tree failure, an expired debt entry, or an
//! exempted crate found in any lane's graph fails the step.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

const CONFIG: &str = "xtask/supply-chain/config.toml";
const DEBT: &str = "supply-chain/policy/vet-debt.json";
const MANIFEST: &str = "xtask/Cargo.toml";
/// The lanes xtask is built and run on (release.yml, build-tools.yml, supply-chain*.yml).
const LANES: &[&str] = &["x86_64-pc-windows-msvc", "x86_64-unknown-linux-gnu"];

/// `(crate, version)` pairs under `[[exemptions.<crate>]]` in a cargo-vet config. A section
/// without a `version` line is an error: the guard refuses to guess what it covers.
pub(crate) fn exemptions(config: &str) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    let mut current: Option<String> = None;
    let mut have_version = true;
    for (n, raw) in config.lines().enumerate() {
        let line = raw.trim();
        if line.starts_with("[[exemptions.") && line.ends_with("]]") {
            if !have_version {
                return Err(format!(
                    "{CONFIG}: exemption before line {} has no version",
                    n + 1
                ));
            }
            let name = line["[[exemptions.".len()..line.len() - 2]
                .trim()
                .trim_matches('"');
            current = Some(name.to_string());
            have_version = false;
        } else if line.starts_with('[') {
            if !have_version {
                return Err(format!(
                    "{CONFIG}: exemption before line {} has no version",
                    n + 1
                ));
            }
            current = None;
            have_version = true;
        } else if let (Some(name), Some(rest)) = (&current, line.strip_prefix("version")) {
            let v = rest
                .trim_start()
                .strip_prefix('=')
                .map(|s| s.trim().trim_matches('"'));
            if let Some(v) = v
                && !v.is_empty()
            {
                out.push((name.clone(), v.to_string()));
                have_version = true;
            }
        }
    }
    if !have_version {
        return Err(format!("{CONFIG}: last exemption has no version"));
    }
    Ok(out)
}

/// Dated debt: `{"xtask": [{"crate": .., "version": .., "expires": "YYYY-MM-DD", "why": ..}]}`.
/// Returns `(crate, version, expires)`; a missing file means no debt is admitted.
pub(crate) fn debt(path: &Path) -> Result<Vec<(String, String, String)>, String> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Ok(Vec::new());
    };
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut out = Vec::new();
    for e in v["xtask"]
        .as_array()
        .ok_or_else(|| format!("{}: no `xtask` array", path.display()))?
    {
        let get = |k: &str| {
            e[k].as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("{}: debt entry lacks `{k}`", path.display()))
        };
        let (c, ver, exp, why) = (get("crate")?, get("version")?, get("expires")?, get("why")?);
        if why.trim().is_empty() {
            return Err(format!("{}: {c} {ver}: empty `why`", path.display()));
        }
        if exp.len() != 10 || exp.as_bytes()[4] != b'-' || exp.as_bytes()[7] != b'-' {
            return Err(format!(
                "{}: {c} {ver}: `expires` is not YYYY-MM-DD",
                path.display()
            ));
        }
        out.push((c, ver, exp));
    }
    Ok(out)
}

/// `name vX.Y.Z` lines of `cargo tree --prefix none` into `(name, version)` pairs.
pub(crate) fn graph(tree: &str) -> BTreeSet<(String, String)> {
    tree.lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let name = it.next()?;
            let ver = it.next()?.strip_prefix('v')?;
            Some((name.to_string(), ver.to_string()))
        })
        .collect()
}

fn lane_graph(target: &str) -> Result<BTreeSet<(String, String)>, String> {
    let out = Command::new("cargo")
        .args([
            "tree",
            "--manifest-path",
            MANIFEST,
            "--locked",
            "--target",
            target,
            "-e",
            "normal,build",
            "--prefix",
            "none",
        ])
        .output()
        .map_err(|e| format!("cannot run cargo tree: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "cargo tree --target {target} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(graph(&String::from_utf8_lossy(&out.stdout)))
}

/// `(violations, expired_debt, stale_debt)` — each a list of human-readable lines.
pub(crate) type Findings = (Vec<String>, Vec<String>, Vec<String>);

/// Pure decision: exempted crates present in a lane's graph, minus unexpired debt. A debt entry
/// that matched a compiled exemption (live or expired) is "touched"; one that matched nothing
/// is stale and reported so the policy file does not accrete dead rows.
pub(crate) fn evaluate(
    exempt: &[(String, String)],
    debt: &[(String, String, String)],
    lanes: &[(String, BTreeSet<(String, String)>)],
    today: &str,
) -> Findings {
    let mut violations = Vec::new();
    let mut expired = Vec::new();
    let mut touched: BTreeSet<(String, String)> = BTreeSet::new();
    for (lane, g) in lanes {
        for (c, v) in exempt {
            if !g.contains(&(c.clone(), v.clone())) {
                continue;
            }
            match debt.iter().find(|(dc, dv, _)| dc == c && dv == v) {
                Some((_, _, exp)) => {
                    touched.insert((c.clone(), v.clone()));
                    if exp.as_str() <= today {
                        expired.push(format!("{c} {v} on {lane}: debt expired {exp}"));
                    }
                }
                None => violations.push(format!(
                    "{c} {v} is exempted from audit yet compiled on {lane} (no recorded debt)"
                )),
            }
        }
    }
    let stale: Vec<String> = debt
        .iter()
        .filter(|(c, v, _)| !touched.contains(&(c.clone(), v.clone())))
        .map(|(c, v, _)| format!("{c} {v}: debt entry not needed (not exempted or not compiled)"))
        .collect();
    (violations, expired, stale)
}

fn today_utc() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86_400);
    // civil-from-days (Howard Hinnant), proleptic Gregorian
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

/// The `xtask ci` step. Prints findings, returns pass/fail.
pub(crate) fn check() -> bool {
    println!("== vet guard: exempted xtask crates stay out of every lane's build graph");
    let run = || -> Result<(Findings, usize), String> {
        let cfg = std::fs::read_to_string(CONFIG).map_err(|e| format!("{CONFIG}: {e}"))?;
        let ex = exemptions(&cfg)?;
        let dt = debt(Path::new(DEBT))?;
        let mut lanes = Vec::new();
        for t in LANES {
            lanes.push((t.to_string(), lane_graph(t)?));
        }
        Ok((evaluate(&ex, &dt, &lanes, &today_utc()), ex.len()))
    };
    match run() {
        Ok(((violations, expired, stale), n)) => {
            for s in &stale {
                println!("  note: {s}");
            }
            for e in &expired {
                eprintln!("  FAIL: {e}");
            }
            for v in &violations {
                eprintln!("  FAIL: {v}");
            }
            if violations.is_empty() && expired.is_empty() {
                println!(
                    "  OK: {n} exemption(s) checked against {} lane(s); none compiled without live debt",
                    LANES.len()
                );
                true
            } else {
                false
            }
        }
        Err(e) => {
            eprintln!("  FAIL: {e} (the guard cannot evaluate; that is a failure, not a pass)");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CFG: &str = r#"
[cargo-vet]
version = "0.10"

[imports.mozilla]
url = "https://example/audits.toml"

[policy.xtask]
criteria = "safe-to-deploy"

[[exemptions.syn]]
version = "3.0.3"
criteria = "safe-to-deploy"
notes = "cfg(any()) only"

[[exemptions.serde_json]]
version = "1.0.154"
criteria = "safe-to-deploy"
"#;

    #[test]
    fn exemptions_are_read_with_versions_and_refuse_a_versionless_section() {
        let ex = exemptions(CFG).unwrap();
        assert_eq!(
            ex,
            vec![
                ("syn".to_string(), "3.0.3".to_string()),
                ("serde_json".to_string(), "1.0.154".to_string())
            ]
        );
        let bad = "[[exemptions.syn]]\ncriteria = \"safe-to-deploy\"\n";
        assert!(exemptions(bad).is_err(), "no version -> refuse");
        assert!(exemptions("").unwrap().is_empty());
    }

    #[test]
    fn graph_parses_prefix_none_lines() {
        let g = graph("itoa v1.0.18\nmemchr v2.8.3\nxtask v0.1.0 (C:\\x)\nserde_json v1.0.154\n\n");
        assert!(g.contains(&("itoa".to_string(), "1.0.18".to_string())));
        assert!(g.contains(&("xtask".to_string(), "0.1.0".to_string())));
        assert_eq!(g.len(), 4);
    }

    #[test]
    fn evaluate_flags_compiled_exemptions_unless_live_debt_covers_them() {
        let ex = vec![
            ("syn".to_string(), "3.0.3".to_string()),
            ("serde_json".to_string(), "1.0.154".to_string()),
            ("memchr".to_string(), "2.8.3".to_string()),
        ];
        let lane = graph("serde_json v1.0.154\nmemchr v2.8.3\nitoa v1.0.18\n");
        let lanes = vec![("win".to_string(), lane)];
        // no debt: both compiled exemptions are violations; syn (not compiled) is fine
        let (v, e, s) = evaluate(&ex, &[], &lanes, "2026-11-12");
        assert_eq!(v.len(), 2, "{v:?}");
        assert!(e.is_empty() && s.is_empty());
        // live debt for serde_json, expired for memchr
        let debt = vec![
            (
                "serde_json".to_string(),
                "1.0.154".to_string(),
                "2027-02-12".to_string(),
            ),
            (
                "memchr".to_string(),
                "2.8.3".to_string(),
                "2026-11-01".to_string(),
            ),
            (
                "syn".to_string(),
                "3.0.3".to_string(),
                "2027-01-01".to_string(),
            ),
        ];
        let (v, e, s) = evaluate(&ex, &debt, &lanes, "2026-11-12");
        assert!(v.is_empty(), "{v:?}");
        assert_eq!(e.len(), 1, "memchr debt expired: {e:?}");
        assert_eq!(s.len(), 1, "syn debt is stale (never compiled): {s:?}");
        // expiry day itself is expired (strictly greater required)
        let (_, e, _) = evaluate(
            &ex,
            &[("serde_json".into(), "1.0.154".into(), "2026-11-12".into())],
            &lanes,
            "2026-11-12",
        );
        assert_eq!(e.len(), 1);
    }

    #[test]
    fn debt_file_shape_is_enforced() {
        let dir = std::env::temp_dir().join(format!("vet-debt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("vet-debt.json");
        std::fs::write(&p, r#"{"xtask":[{"crate":"memchr","version":"2.8.3","expires":"2027-02-12","why":"no safe-to-deploy chain; OSS-Fuzz"}]}"#).unwrap();
        assert_eq!(debt(&p).unwrap().len(), 1);
        std::fs::write(
            &p,
            r#"{"xtask":[{"crate":"memchr","version":"2.8.3","expires":"soon","why":"x"}]}"#,
        )
        .unwrap();
        assert!(debt(&p).is_err(), "bad date");
        std::fs::write(
            &p,
            r#"{"xtask":[{"crate":"memchr","version":"2.8.3","expires":"2027-02-12","why":" "}]}"#,
        )
        .unwrap();
        assert!(debt(&p).is_err(), "empty why");
        assert!(
            debt(&dir.join("missing.json")).unwrap().is_empty(),
            "missing file = no debt"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn today_is_a_plausible_iso_date() {
        let t = today_utc();
        assert_eq!(t.len(), 10);
        assert!(t.starts_with("20"), "{t}");
    }
}
