//! `cargo xtask verify-allowances` -- make every workaround assert its own precondition.
//!
//! THE PROBLEM WITH A WORKAROUND is not that it is wrong when written. It is that it stays
//! after the reason leaves. A lint allowance, a pinned-back version, a skipped test: each is
//! justified by some condition upstream, and none of them notice when that condition ends. The
//! workaround then reads as policy rather than as debt, and nothing in CI disagrees.
//!
//! This repo already answers that for one case. `tools/patches/` are applied with
//! `git apply --check`, so a patch that no longer applies is a hard error -- "superseded or
//! conflicting; refresh or drop it". Expiry by construction: the workaround is coupled to the
//! defect it works around, and dies with it.
//!
//! That mechanism cannot reach a REGISTRY dependency. It patches the tool's checked-out source
//! tree, and a crates.io dependency is not in it.
//!
//! WHY NOT PATCH THE DEPENDENCY ANYWAY. `[patch.crates-io]` would let us fix abscissa_core
//! directly, and it would inherit expiry from `git apply --check`. It would also compile bytes
//! that no longer match the sha256 in tools/locks/cargo-audit.lock. We would be shipping a
//! modified copy of a dependency we vetted by digest while the lock still named the original --
//! trading a lint suppression for a provenance gap, which is the wrong direction. The allowance
//! leaves the dependency bit-identical to what was vetted. Its only defect is that it never
//! expires, so fix THAT and leave the bytes alone.
//!
//! WHAT THIS DOES. For each allowance, read the dependency source cargo actually extracted and
//! confirm the offending shape is still present. Present: the allowance is still earning its
//! place. Gone: upstream fixed it (or a bump picked up a fixed version) and the allowance is
//! obsolete -- fail, and say so. Unreadable: fail closed, because being unable to check is not
//! permission to proceed.

use std::path::PathBuf;

/// One workaround, and the upstream condition that justifies it.
struct Allowance {
    /// The tool whose build carries the workaround.
    tool: &'static str,
    /// What is being allowed, named exactly.
    lint: &'static str,
    /// The dependency the defect actually lives in -- not necessarily the tool.
    dep: &'static str,
    /// Path within that dependency's source.
    file: &'static str,
    /// The shape that must STILL be present for the allowance to be justified.
    precondition: &'static str,
    /// How many occurrences upstream currently has. Fewer means upstream moved and the
    /// allowance needs re-justifying, not silent continuation.
    expect_at_least: usize,
    issue: &'static str,
    why: &'static str,
}

const ALLOWANCES: &[Allowance] = &[Allowance {
    tool: "cargo-audit",
    lint: "semicolon_in_expressions_from_macros",
    // The defect is NOT in cargo-audit. It re-exports abscissa_core's prelude, and `$crate`
    // in the failing macro resolves to the crate that DEFINES it.
    dep: "abscissa_core",
    file: "src/terminal/status.rs",
    // Six status_* macros, each with two arms; arm one of each ends `.unwrap();`. Those six
    // occurrences are the only `.unwrap();` in the file, so the count is a clean signal. The
    // upstream fix deletes the semicolon and keeps the call, so a fixed release reads
    // `.unwrap()` and this drops to zero.
    precondition: ".unwrap();",
    expect_at_least: 6,
    issue: "#325",
    why: "trailing semicolons in abscissa_core's status_* macro arms, called by cargo-audit in expression position",
}];

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Upstream still has the defect: the allowance is justified.
    StillNeeded(usize),
    /// Upstream fixed it. The allowance is now silently weakening a check for no reason.
    Obsolete,
    /// Fewer occurrences than recorded: upstream changed shape. Not obsolete, not justified as
    /// written -- re-read it rather than assume either.
    Moved(usize),
    /// Could not read the dependency source. Fail closed.
    Unverifiable(String),
}

/// Pure, so the polarity is testable without a cargo cache present. Getting this backwards
/// would turn an expiry check into a rubber stamp, which is the failure it exists to prevent.
pub fn classify(found: Option<usize>, expect_at_least: usize) -> Verdict {
    match found {
        None => Verdict::Unverifiable("dependency source not found".into()),
        Some(0) => Verdict::Obsolete,
        Some(n) if n >= expect_at_least => Verdict::StillNeeded(n),
        Some(n) => Verdict::Moved(n),
    }
}

fn count_occurrences(hay: &str, needle: &str) -> usize {
    if needle.is_empty() {
        return 0;
    }
    hay.match_indices(needle).count()
}

/// Cargo extracts registry sources to `$CARGO_HOME/registry/src/<registry>/<crate>-<version>/`.
/// The registry directory name is a hash that changes between cargo versions, so glob it rather
/// than hardcode it.
fn locate_dep_file(dep: &str, file: &str) -> Option<PathBuf> {
    let home = std::env::var("CARGO_HOME")
        .ok()
        .map(PathBuf::from)
        .or_else(|| std::env::var("USERPROFILE").ok().map(|h| PathBuf::from(h).join(".cargo")))
        .or_else(|| std::env::var("HOME").ok().map(|h| PathBuf::from(h).join(".cargo")))?;
    let src = home.join("registry").join("src");
    for registry in std::fs::read_dir(&src).ok()?.flatten() {
        let Ok(entries) = std::fs::read_dir(registry.path()) else {
            continue;
        };
        for e in entries.flatten() {
            let name = e.file_name();
            let name = name.to_string_lossy();
            // `abscissa_core-0.9.0` -- match the crate, not a crate that merely starts with it
            // (`abscissa_core_macros` would otherwise match a `abscissa_core` prefix test).
            if let Some(rest) = name.strip_prefix(dep) {
                if rest.starts_with('-') {
                    let candidate = e.path().join(file);
                    if candidate.is_file() {
                        return Some(candidate);
                    }
                }
            }
        }
    }
    None
}

pub fn run(_args: &[String]) -> i32 {
    println!("# every allowance must still be justified by an upstream condition (#325)");
    let mut failures = 0;
    for a in ALLOWANCES {
        let found = locate_dep_file(a.dep, a.file).and_then(|p| {
            std::fs::read_to_string(&p)
                .ok()
                .map(|t| count_occurrences(&t, a.precondition))
        });
        match classify(found, a.expect_at_least) {
            Verdict::StillNeeded(n) => println!(
                "  {}: {} still justified -- {} still has {n} x {:?} in {} ({})",
                a.tool, a.lint, a.dep, a.precondition, a.file, a.issue
            ),
            Verdict::Obsolete => {
                println!(
                    "  {}: {} is OBSOLETE -- {} no longer contains {:?} in {}. \
                     Upstream fixed {}. Remove the allowance from build-tools.yml, remove this \
                     entry, and close {}.",
                    a.tool, a.lint, a.dep, a.precondition, a.file, a.why, a.issue
                );
                failures += 1;
            }
            Verdict::Moved(n) => {
                println!(
                    "  {}: {} needs RE-READING -- expected at least {} x {:?} in {}/{}, found {n}. \
                     Upstream changed shape; decide whether the allowance is still justified.",
                    a.tool, a.lint, a.expect_at_least, a.precondition, a.dep, a.file
                );
                failures += 1;
            }
            Verdict::Unverifiable(e) => {
                println!(
                    "  {}: CANNOT VERIFY {} -- {e} ({}/{}). Being unable to check is not \
                     permission to proceed.",
                    a.tool, a.lint, a.dep, a.file
                );
                failures += 1;
            }
        }
    }
    if failures > 0 {
        eprintln!("verify-allowances: {failures} allowance(s) not justified as written");
        return 1;
    }
    println!("# every allowance is still earning its place");
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_still_broken_means_the_allowance_stands() {
        assert_eq!(classify(Some(6), 6), Verdict::StillNeeded(6));
        assert_eq!(classify(Some(7), 6), Verdict::StillNeeded(7));
    }

    #[test]
    fn upstream_fixed_means_the_allowance_must_go() {
        // The whole point: the workaround dies with the defect instead of outliving it.
        assert_eq!(classify(Some(0), 6), Verdict::Obsolete);
    }

    #[test]
    fn a_partial_change_is_not_silently_accepted() {
        // Upstream fixing SOME arms is neither "still justified" nor "obsolete". Guessing
        // either way is how a workaround quietly becomes policy.
        assert_eq!(classify(Some(3), 6), Verdict::Moved(3));
    }

    #[test]
    fn unreadable_source_fails_closed() {
        match classify(None, 6) {
            Verdict::Unverifiable(_) => {}
            other => panic!("missing source must not pass, got {other:?}"),
        }
    }

    #[test]
    fn counting_matches_the_real_upstream_shape() {
        // The six arm-one endings, as they appear in abscissa_core 0.9.0.
        let src = "
macro_rules! status_ok {
    ($msg:expr) => {
        Status::new()
            .unwrap();
    };
    ($fmt:expr, $($arg:tt)+) => {
        $crate::status_ok!(format!($fmt, $($arg)+));
    };
}
";
        assert_eq!(count_occurrences(src, ".unwrap();"), 1);
        // And the fixed shape, which is what makes the check expire.
        assert_eq!(count_occurrences(&src.replace(".unwrap();", ".unwrap()"), ".unwrap();"), 0);
    }

    #[test]
    fn every_allowance_names_an_issue_and_a_reason() {
        // An allowance with no recorded justification is indistinguishable from an accident.
        for a in ALLOWANCES {
            assert!(a.issue.starts_with('#'), "{} has no issue", a.tool);
            assert!(!a.why.is_empty(), "{} has no rationale", a.tool);
            assert!(a.expect_at_least > 0, "{} expects zero occurrences", a.tool);
        }
    }
}
