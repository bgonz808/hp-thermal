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
//!   * a freeze that introduces a GENUINELY NEW advisory — a new (advisory, package) key, or
//!     a second vulnerable resident version — is refused by default (#255 §4). The same
//!     advisory carried onto a bumped version is reported as UNFIXED but never blocks:
//!     refusal keys on risk, not version movement. Trading one advisory for another
//!     remains a human decision (--allow-added-advisories records it deliberately);
//!   * nothing is blessed: the digest still comes from a producer run over this lock, and the
//!     #241 gate still evaluates it. This only makes the candidate reproducible.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::explore::{age_days, parse_ver};
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
            // Evaluate + report the full delta, write NOTHING. The safe way to try a batch:
            // see which directives are reachable and what they'd buy before committing a lock.
            "--dry-run" => dry_run = true,
            other => {
                eprintln!("freeze: unknown arg {other}");
                return 2;
            }
        }
    }
    if tool.is_empty() || repo.is_empty() || rev.is_empty() || directives.is_empty() {
        eprintln!(
            "usage: cargo xtask freeze --tool <name> --repo <owner/repo> --rev <sha> \\\n\
             \x20         --update <pkg>[@cur]=<ver> [--update ...] [--soak-days N] [--out-dir DIR] [--dry-run]"
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
            .args(["update", "-p", &p.spec(), "--precise", &p.version])
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
}
