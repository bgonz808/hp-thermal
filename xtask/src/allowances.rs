//! `cargo xtask verify-allowances` -- every lint allowance must re-earn its place from the
//! diagnostics the build actually emitted.
//!
//! THE PROBLEM WITH A WORKAROUND is not that it is wrong when written. It is that it stays
//! after the reason leaves, at which point it reads as policy and nothing in CI disagrees.
//! `tools/patches/` answers that for patches (`git apply --check`: a patch that no longer
//! applies is a hard error); this answers it for lint allowances.
//!
//! FIRST DESIGN, AND WHY IT WAS WRONG. The first version grepped the DEPENDENCY SOURCE for
//! the code shape believed to trip the lint (`.unwrap();` inside abscissa_core's macros).
//! The maintainer's review named the defect: that couples the check to a PROXY. The
//! allowance exists because the COMPILER EMITS A DIAGNOSTIC; the honest precondition is the
//! diagnostic itself, observed at its emission source. Upstream could fix the lint without
//! touching that string (wrap the arms in braces), or the lint's semantics could change --
//! either way the source-grep keeps answering a question nobody asked.
//!
//! THE RATCHET. The allowance is carried as `-W <lint>` -- WARN, not ALLOW -- so the build
//! still passes while every run EMITS the evidence. The producer tees each tool's cargo
//! output to `diag-<tool>.log`, and this check reads the log the build just wrote:
//!
//!   * lint observed, from the expected macros  -> StillNeeded: the -W is earning its place
//!   * lint NOT observed                        -> Obsolete: FAIL -- shed the -W and this entry
//!   * lint observed from an UNEXPECTED macro   -> NewEmissionSource: FAIL -- the allowance
//!     is silencing something it was never reviewed for; a new decision, not a wider shield
//!   * log missing/unreadable                   -> Unverifiable: FAIL closed
//!
//! The expected-macro set comes FROM the diagnostics themselves ("this error originates in
//! the macro `$crate::status_warn`"), not from reading upstream's tree -- the emission
//! source, as reviewed, is the identity of the claim being allowed.
//!
//! Ephemeral runners make the zero-count signal sound: every producer run compiles the
//! dependency fresh, so "no diagnostic" means the lint no longer fires -- not that a warm
//! cache skipped the crate. Anyone running this locally against an incremental build would
//! get a false Obsolete, which fails loudly rather than passing, the survivable direction.

use std::collections::BTreeSet;
use std::path::Path;

/// One lint allowance, and the reviewed emission source that justifies it.
struct Allowance {
    /// The tool whose build carries `-W <lint>` (and whose diag log is read).
    tool: &'static str,
    /// The lint being downgraded, exactly as rustc names it.
    lint: &'static str,
    /// rustc's permanent pointer for the diagnostic -- for future-incompat lints, the
    /// tracking-issue reference printed on every instance ("issue #79813"). Survives both
    /// message rewording and the lint-name spelling difference.
    marker: &'static str,
    /// Macro names the reviewed diagnostics originate from. A diagnostic from any OTHER
    /// macro is a new, unreviewed emission -- refused, not absorbed.
    expected_macros: &'static [&'static str],
    issue: &'static str,
    why: &'static str,
}

const ALLOWANCES: &[Allowance] = &[Allowance {
    tool: "cargo-audit",
    lint: "semicolon_in_expressions_from_macros",
    marker: "issue #79813",
    // The defect is in abscissa_core's status_* macros (cargo-audit calls them in
    // expression position); these six names are what the reviewed diagnostics cite as the
    // origin. Names come from the diagnostics, not from grepping upstream's tree.
    expected_macros: &[
        "status_ok",
        "status_info",
        "status_warn",
        "status_err",
        "status_attr_ok",
        "status_attr_err",
    ],
    issue: "#325",
    why: "trailing semicolons in abscissa_core's status_* macro arms; fix is released upstream when the diagnostics stop -- then this -W must be shed",
}];

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The lint fired, only from reviewed macros: the -W is still earning its place.
    StillNeeded { count: usize },
    /// The lint no longer fires. The allowance is now silencing nothing -- shed it.
    Obsolete,
    /// The lint fired from a macro the review never covered. The allowance must not widen
    /// silently into a shield for it.
    NewEmissionSource(Vec<String>),
    /// The build log could not be read. Being unable to check is not permission to proceed.
    Unverifiable(String),
}

/// What one tool's build output says about one allowance. Pure, so polarity is testable
/// without a build: inverting it would turn an expiry check into a rubber stamp.
pub fn classify(diag: &str, lint: &str, marker: &str, expected_macros: &[&str]) -> Verdict {
    // rustc prints lint names HYPHENATED in diagnostics ("-W semicolon-in-expressions-
    // from-macros") while RUSTFLAGS and the lint's declared name use underscores. The
    // first live run keyed on the underscore spelling, found zero matches in 21 real
    // diagnostics, and declared the allowance Obsolete against an unfixed upstream --
    // failing closed, but wrongly. Count under both spellings, plus the diagnostic's
    // permanent marker (the tracking-issue reference rustc prints on every
    // future-incompat instance), and take the MAX: one diagnostic can carry several of
    // these, so summing would multiply-count it.
    let count = [
        diag.matches(lint).count(),
        diag.matches(&lint.replace('_', "-")).count(),
        if marker.is_empty() { 0 } else { diag.matches(marker).count() },
    ]
    .into_iter()
    .max()
    .unwrap_or(0);
    if count == 0 {
        return Verdict::Obsolete;
    }
    let origins = origin_macros(diag);
    let unexpected: Vec<String> = origins
        .iter()
        .filter(|m| !expected_macros.contains(&m.as_str()))
        .cloned()
        .collect();
    if unexpected.is_empty() {
        Verdict::StillNeeded { count }
    } else {
        Verdict::NewEmissionSource(unexpected)
    }
}

/// Macro names the diagnostics attribute themselves to. rustc phrases it as
/// "originates in the macro `$crate::status_warn`" (sometimes without the `$crate::`
/// qualifier, or naming the outer expansion: "which comes from the expansion of the macro
/// `status_warn`"); both shapes funnel through "the macro `NAME`".
pub fn origin_macros(diag: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for (idx, _) in diag.match_indices("the macro `") {
        let rest = &diag[idx + "the macro `".len()..];
        if let Some(end) = rest.find('`') {
            let name = rest[..end].trim_start_matches("$crate::");
            if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                out.insert(name.to_string());
            }
        }
    }
    out
}

pub fn run(args: &[String]) -> i32 {
    let mut diag_dir = ".".to_string();
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--diag-dir" => {
                if let Some(d) = it.next() {
                    diag_dir = d.clone();
                }
            }
            other => {
                eprintln!("verify-allowances: unknown argument {other}");
                return 2;
            }
        }
    }

    println!("# every -W allowance must be re-justified by the diagnostics this build emitted (#325)");
    let mut failures = 0;
    for a in ALLOWANCES {
        let path = Path::new(&diag_dir).join(format!("diag-{}.log", a.tool));
        let verdict = match std::fs::read_to_string(&path) {
            Ok(diag) => classify(&diag, a.lint, a.marker, a.expected_macros),
            Err(e) => Verdict::Unverifiable(format!("{}: {e}", path.display())),
        };
        match verdict {
            Verdict::StillNeeded { count } => println!(
                "  {}: {} still fires ({count} mention(s), expected macros only) -- the -W is earning its place ({})",
                a.tool, a.lint, a.issue
            ),
            Verdict::Obsolete => {
                println!(
                    "  {}: {} DID NOT FIRE. The allowance is obsolete -- {}. Remove the -W from \
                     build-tools.yml, remove this entry, and close {}.",
                    a.tool, a.lint, a.why, a.issue
                );
                failures += 1;
            }
            Verdict::NewEmissionSource(macros) => {
                println!(
                    "  {}: {} fired from UNREVIEWED macro(s) {macros:?}. The allowance covers only \
                     {:?}; widening it is a new decision, not a default.",
                    a.tool, a.lint, a.expected_macros
                );
                failures += 1;
            }
            Verdict::Unverifiable(e) => {
                println!(
                    "  {}: CANNOT VERIFY {} -- {e}. Being unable to check is not permission to proceed.",
                    a.tool, a.lint
                );
                failures += 1;
            }
        }
    }
    if failures > 0 {
        eprintln!("verify-allowances: {failures} allowance(s) not justified by this build's diagnostics");
        return 1;
    }
    println!("# every allowance is still earning its place");
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINT: &str = "semicolon_in_expressions_from_macros";
    const MARKER: &str = "issue #79813";
    const EXPECTED: &[&str] = &["status_warn", "status_err"];

    /// The diagnostic VERBATIM from producer run 33325673586 -- not an approximation.
    /// The first fixture was hand-written with the underscore lint spelling, so the tests
    /// validated the author's guess instead of the emission; the false Obsolete it hid is
    /// exactly the coupling defect this module exists to avoid. If rustc's shape changes,
    /// update this from a real log, never from memory.
    fn real_shape() -> String {
        [
            "warning: trailing semicolon in macro used in expression position",
            "   --> cargo-audit\\src\\auditor.rs:368:31",
            "    = warning: this was previously accepted by the compiler but is being phased out; it will become a hard error in a future release!",
            "    = note: for more information, see issue #79813 <https://github.com/rust-lang/rust/issues/79813>",
            "    = note: requested on the command line with `-W semicolon-in-expressions-from-macros`",
            "    = note: this warning originates in the macro `status_err` (in Nightly builds, run with -Z macro-backtrace for more info)",
        ]
        .join("\n")
    }

    #[test]
    fn the_real_hyphenated_diagnostic_keeps_the_allowance() {
        // The regression that reached CI: rustc hyphenates, the matcher expected
        // underscores, 21 live diagnostics counted as zero.
        assert_eq!(
            classify(&real_shape(), LINT, MARKER, EXPECTED),
            Verdict::StillNeeded { count: 1 }
        );
    }

    #[test]
    fn the_underscore_spelling_also_counts() {
        // Defensive in the other direction: if rustc ever prints the declared name.
        let diag = "note: `#[warn(semicolon_in_expressions_from_macros)]` on by default\n\
                    note: this warning originates in the macro `status_warn`";
        assert_eq!(
            classify(diag, LINT, "", EXPECTED),
            Verdict::StillNeeded { count: 1 }
        );
    }

    #[test]
    fn one_diagnostic_with_all_three_identifiers_counts_once() {
        // max, not sum: the same diagnostic carrying name+marker must not read as three.
        let diag = format!("{}\nsemicolon_in_expressions_from_macros", real_shape());
        assert_eq!(
            classify(&diag, LINT, MARKER, EXPECTED),
            Verdict::StillNeeded { count: 1 }
        );
    }

    #[test]
    fn lint_not_firing_means_the_allowance_must_go() {
        // The whole point: the workaround dies with the diagnostic instead of outliving it.
        assert_eq!(
            classify("   Compiling cargo-audit v0.22.2\n    Finished release\n", LINT, MARKER, EXPECTED),
            Verdict::Obsolete
        );
    }

    #[test]
    fn an_unreviewed_macro_is_refused_not_absorbed() {
        let diag = real_shape().replace("status_err", "sneaky_new_macro");
        match classify(&diag, LINT, MARKER, EXPECTED) {
            Verdict::NewEmissionSource(m) => assert_eq!(m, vec!["sneaky_new_macro".to_string()]),
            other => panic!("a new emission source must not be silently covered, got {other:?}"),
        }
    }

    #[test]
    fn origin_extraction_matches_both_of_rustcs_phrasings() {
        assert_eq!(
            origin_macros(&real_shape()).into_iter().collect::<Vec<_>>(),
            vec!["status_err"]
        );
        // The $crate-qualified double-mention form is one origin, not two.
        let q = origin_macros(
            "originates in the macro `$crate::status_err` which comes from the expansion of the macro `status_err`",
        );
        assert_eq!(q.into_iter().collect::<Vec<_>>(), vec!["status_err"]);
    }

    #[test]
    fn a_backtickless_tail_does_not_panic_or_match() {
        assert!(origin_macros("blah the macro `unterminated").is_empty());
        assert!(origin_macros("no mentions here").is_empty());
    }

    #[test]
    fn every_allowance_names_an_issue_marker_reviewed_macros_and_a_reason() {
        // An allowance with no recorded justification is indistinguishable from an accident.
        for a in ALLOWANCES {
            assert!(a.issue.starts_with('#'), "{} has no issue", a.tool);
            assert!(!a.why.is_empty(), "{} has no rationale", a.tool);
            assert!(!a.marker.is_empty(), "{} has no stable diagnostic marker", a.tool);
            assert!(!a.expected_macros.is_empty(), "{} reviews no emission source", a.tool);
        }
    }
}
