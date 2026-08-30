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
    /// Macro names the reviewed diagnostics originate from. A diagnostic from any OTHER
    /// macro is a new, unreviewed emission -- refused, not absorbed.
    expected_macros: &'static [&'static str],
    issue: &'static str,
    why: &'static str,
}

const ALLOWANCES: &[Allowance] = &[Allowance {
    tool: "cargo-audit",
    lint: "semicolon_in_expressions_from_macros",
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
pub fn classify(diag: &str, lint: &str, expected_macros: &[&str]) -> Verdict {
    let count = diag.matches(lint).count();
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
            Ok(diag) => classify(&diag, a.lint, a.expected_macros),
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
    const EXPECTED: &[&str] = &["status_warn", "status_err"];

    /// A faithful miniature of the real diagnostic shape (from producer run 33235815691).
    fn real_shape() -> String {
        "warning: trailing semicolon in macro used in expression position\n\
           --> cargo-audit\\src\\presenter.rs:267:29\n\
           = note: requested on the command line with `-W semicolon_in_expressions_from_macros`\n\
           = note: this error originates in the macro `$crate::status_warn` which comes from \
         the expansion of the macro `status_warn`\n"
            .to_string()
    }

    #[test]
    fn lint_firing_from_reviewed_macros_keeps_the_allowance() {
        assert_eq!(
            classify(&real_shape(), LINT, EXPECTED),
            Verdict::StillNeeded { count: 1 }
        );
    }

    #[test]
    fn lint_not_firing_means_the_allowance_must_go() {
        // The whole point: the workaround dies with the diagnostic instead of outliving it.
        // This is what the source-grep design could NOT promise -- upstream fixing the lint
        // without deleting the grepped string would have kept the allowance alive forever.
        assert_eq!(
            classify("   Compiling cargo-audit v0.22.2\n    Finished release\n", LINT, EXPECTED),
            Verdict::Obsolete
        );
    }

    #[test]
    fn an_unreviewed_macro_is_refused_not_absorbed() {
        let diag = real_shape().replace("status_warn", "sneaky_new_macro");
        match classify(&diag, LINT, EXPECTED) {
            Verdict::NewEmissionSource(m) => assert_eq!(m, vec!["sneaky_new_macro".to_string()]),
            other => panic!("a new emission source must not be silently covered, got {other:?}"),
        }
    }

    #[test]
    fn origin_extraction_strips_the_crate_qualifier_and_dedups() {
        let macros = origin_macros(&real_shape());
        // `$crate::status_warn` and `status_warn` are one origin, not two.
        assert_eq!(macros.into_iter().collect::<Vec<_>>(), vec!["status_warn"]);
    }

    #[test]
    fn a_backtickless_tail_does_not_panic_or_match() {
        assert!(origin_macros("blah the macro `unterminated").is_empty());
        assert!(origin_macros("no mentions here").is_empty());
    }

    #[test]
    fn every_allowance_names_an_issue_reviewed_macros_and_a_reason() {
        // An allowance with no recorded justification is indistinguishable from an accident.
        for a in ALLOWANCES {
            assert!(a.issue.starts_with('#'), "{} has no issue", a.tool);
            assert!(!a.why.is_empty(), "{} has no rationale", a.tool);
            assert!(!a.expected_macros.is_empty(), "{} reviews no emission source", a.tool);
        }
    }
}
