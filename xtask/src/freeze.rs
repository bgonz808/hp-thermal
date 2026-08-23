//! `cargo xtask freeze` — turn an explored candidate into a REPRODUCIBLE build input (#241).
//!
//! The promotion pipeline's trust boundary. Exploration reasons about un-vetted newer
//! versions; freezing captures one specific resolution as a committed artifact, after which
//! the candidate is 100% pinned and every later build is `--locked` against THIS lock. Put
//! precisely: **non-`--locked` is a discovery property, never a build-output property.** We
//! never bless a floating build — we bless the frozen resolution that discovery proposed.
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
//!   * a freeze that would ADD an advisory instance is refused by default — freezing is for
//!     provable improvements, and trading one advisory for another is a human decision;
//!   * nothing is blessed: the digest still comes from a producer run over this lock, and the
//!     #241 gate still evaluates it. This only makes the candidate reproducible.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::explore::{age_days, parse_ver};
use crate::gate::{Instance, extract_instances, run_audit};

/// One `pkg=version` promotion directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directive {
    pub package: String,
    pub version: String,
}

/// Parse `pkg=version`. Rejects empty halves and non-semver versions — a directive must name
/// a concrete crates.io release, never a range or a tag.
pub fn parse_directive(s: &str) -> Result<Directive, String> {
    let (p, v) = s
        .split_once('=')
        .ok_or_else(|| format!("directive '{s}' must be <package>=<version>"))?;
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
    })
}

/// Verify a directive's target is safe to adopt: exists, not yanked, and past soak.
/// Returns the version's age in days.
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
            "--soak-days" => soak = it.next().and_then(|v| v.parse().ok()).unwrap_or(soak),
            "--now-epoch" => now_epoch = it.next().and_then(|v| v.parse().ok()).unwrap_or(0),
            // Escape hatch for a deliberate, reviewed trade — never the default.
            "--allow-added-advisories" => allow_added = true,
            other => {
                eprintln!("freeze: unknown arg {other}");
                return 2;
            }
        }
    }
    if tool.is_empty() || repo.is_empty() || rev.is_empty() || directives.is_empty() {
        eprintln!(
            "usage: cargo xtask freeze --tool <name> --repo <owner/repo> --rev <sha> \\\n\
             \x20         --update <pkg>=<ver> [--update ...] [--soak-days N] [--out-dir DIR]"
        );
        return 2;
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

    // 3. Advisory posture BEFORE (upstream's lock), at this DB state.
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
    for p in &parsed {
        let st = Command::new("cargo")
            .current_dir(&work)
            .args(["update", "-p", &p.package, "--precise", &p.version])
            .env_remove("CARGO")
            .env_remove("RUSTC")
            .env_remove("RUSTUP_TOOLCHAIN")
            .status();
        match st {
            Ok(s) if s.success() => println!("  updated {} -> {}", p.package, p.version),
            _ => {
                eprintln!(
                    "  REFUSED: cargo update -p {} --precise {} failed — the version is likely \
                     unreachable from this tree's requirements (see the escalation ladder in \
                     `xtask explore`)",
                    p.package, p.version
                );
                let _ = std::fs::remove_dir_all(&work);
                return 1;
            }
        }
    }

    // 5. Advisory posture AFTER — same DB state (--no-fetch), so the diff isolates the
    //    resolution change from advisory-DB drift (#241 §5).
    let after = match run_audit(&lock, true) {
        Ok(a) => extract_instances(&a),
        Err(e) => {
            eprintln!("freeze: post-update audit failed: {e}");
            let _ = std::fs::remove_dir_all(&work);
            return 1;
        }
    };
    let added = added_instances(&before, &after);
    let removed = removed_instances(&before, &after);
    println!(
        "\n# advisory delta at one DB state: {} removed / {} added ({} -> {} instances)",
        removed.len(),
        added.len(),
        before.len(),
        after.len()
    );
    for i in &removed {
        println!("  - {} {} {}", i.id, i.package, i.version);
    }
    for i in &added {
        println!("  + {} {} {}  <-- ADDED", i.id, i.package, i.version);
    }
    if !added.is_empty() && !allow_added {
        eprintln!(
            "\nfreeze: REFUSED — this resolution ADDS {} advisory instance(s). Freezing is for\n\
             provable improvements; trading one advisory for another is a human decision.\n\
             Re-run with --allow-added-advisories to record that trade deliberately.",
            added.len()
        );
        let _ = std::fs::remove_dir_all(&work);
        return 1;
    }
    if removed.is_empty() {
        println!("  (no advisory instance removed — freeze records a resolution change only)");
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
                version: "0.3.34".into()
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
}
