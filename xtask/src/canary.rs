//! `cargo xtask canary` -- negative-control canaries for the gating tools (#223).
//!
//! THE THREAT is not a checker that does something bad; it is a checker that silently
//! stops doing anything. A sabotaged transitive dependency in an auditor need not act --
//! it only has to make the tool return "clean". That failure is invisible to every other
//! control here: no egress to observe, no tampering to detect (the digest still matches
//! the bytes we blessed), the job is green, and every downstream gate is hollow.
//! Checker-integrity is a distinct threat class from ordinary dependency compromise.
//!
//! A NEGATIVE CONTROL is the standard answer, borrowed from assay design: alongside the
//! real sample, run a specimen KNOWN to be positive. If the instrument does not register
//! it, what you have learned about is the instrument, not the sample.
//!
//! POLARITY IS INVERTED from every other check in this repo: the canary PASSES when the
//! tool FAILS on the fixture. A tool that reports the fixture clean has failed its canary.
//!
//! THREE OUTCOMES, NOT TWO. Exit status alone is not evidence of detection, and this repo
//! has already been bitten by exactly that conflation: cargo-vet spent its entire
//! deployment exiting non-zero because it PANICKED before evaluating anything, while the
//! workflow attributed that exit to "unvetted dependencies" (#290). A crashed checker is
//! exactly as blind as a sabotaged one and exits the same way. So detection requires
//! POSITIVE evidence -- the expected advisory identifier in the tool's own output -- and a
//! bare non-zero exit without it is BROKEN, never a pass.
//!
//! Fixtures live in supply-chain/canaries/ and are chosen for PERMANENCE: a known-bad that
//! could later become clean would rot the canary into a silent false pass, which is the
//! precise condition it exists to detect.

use std::path::{Path, PathBuf};
use std::process::Command;

/// One negative control: a tool, a known-bad fixture, and the evidence proving the tool
/// actually saw it.
struct Canary {
    /// Binary name, resolved under `--tools-dir` (or PATH when unpinned, for local runs).
    tool: &'static str,
    /// Arguments; `{fixture}` is substituted with the fixture path.
    args: &'static [&'static str],
    fixture: &'static str,
    /// Substring that MUST appear in the output for detection to count. This is what
    /// separates "detected the planted finding" from "fell over on the way there".
    expect_marker: &'static str,
    /// Why this fixture is a DURABLE negative control.
    rationale: &'static str,
}

const CANARIES: &[Canary] = &[Canary {
    tool: "cargo-audit",
    args: &["audit", "--no-fetch", "--file", "{fixture}"],
    fixture: "supply-chain/canaries/vuln-audit.lock",
    // The advisory ID, not a phrase like "vulnerability found": wording is cosmetic and
    // changes between releases, whereas the ID is the finding's identity -- the same
    // instance-tuple discipline the gate uses (#241).
    expect_marker: "RUSTSEC-2018-0006",
    rationale: "yaml-rust 0.4.0: a real vulnerability rather than an unmaintained notice; patched in 0.4.1 so the tuple can never become clean; and no os restriction that a Windows-targeted scan could legitimately filter out",
}];

/// What a canary run tells us about the INSTRUMENT.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Failed AND produced the expected evidence: still detecting.
    Detected,
    /// Reported the known-bad fixture as clean. This is the sabotage signature.
    Blind,
    /// Failed without the expected evidence -- crash, usage error, config rot. Not
    /// detection, and deliberately not counted as one.
    Broken(String),
}

/// Classify one canary run. Pure, so the polarity is unit-testable without a tool
/// present: getting this backwards would turn the control into a rubber stamp.
pub fn classify(exit_ok: bool, output: &str, marker: &str) -> Verdict {
    if exit_ok {
        return Verdict::Blind;
    }
    if output.contains(marker) {
        Verdict::Detected
    } else {
        Verdict::Broken(format!("exited non-zero but never mentioned {marker}"))
    }
}

fn tool_path(dir: Option<&Path>, tool: &str) -> String {
    match dir {
        Some(d) => d
            .join(format!("{tool}{}", std::env::consts::EXE_SUFFIX))
            .display()
            .to_string(),
        None => tool.to_string(),
    }
}

pub fn run(args: &[String]) -> i32 {
    let mut dir: Option<PathBuf> = std::env::var("PINNED_TOOLS_DIR").ok().map(PathBuf::from);
    let mut only: Option<&str> = None;
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--tools-dir" => dir = it.next().map(PathBuf::from),
            "--tool" => only = it.next().map(String::as_str),
            other => {
                eprintln!("canary: unknown argument {other}");
                return 2;
            }
        }
    }

    let selected: Vec<&Canary> = CANARIES
        .iter()
        .filter(|c| only.is_none_or(|o| o == c.tool))
        .collect();
    if selected.is_empty() {
        // Fail-secure: a selector matching nothing must not read as "all clear".
        eprintln!(
            "canary: no canary matches --tool {}",
            only.unwrap_or("<none>")
        );
        return 2;
    }

    println!("# negative-control canaries (#223) -- a canary PASSES when the tool FAILS");
    let mut failures = 0;
    for c in selected {
        let prog = tool_path(dir.as_deref(), c.tool);
        let argv: Vec<String> = c
            .args
            .iter()
            .map(|a| a.replace("{fixture}", c.fixture))
            .collect();
        let out = match Command::new(&prog)
            .args(&argv)
            .env_remove("CARGO")
            .env_remove("RUSTC")
            .env_remove("RUSTUP_TOOLCHAIN")
            .output()
        {
            Ok(o) => o,
            Err(e) => {
                // Cannot run the checker at all: no evidence either way, so fail.
                println!("  {}: UNRUNNABLE -- {e}", c.tool);
                failures += 1;
                continue;
            }
        };
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        match classify(out.status.success(), &text, c.expect_marker) {
            Verdict::Detected => println!(
                "  {}: DETECTED {} in {} -- instrument is live",
                c.tool, c.expect_marker, c.fixture
            ),
            Verdict::Blind => {
                println!(
                    "  {}: BLIND -- reported known-bad fixture {} as CLEAN. Every verdict this tool has issued is suspect.",
                    c.tool, c.fixture
                );
                println!("      fixture rationale: {}", c.rationale);
                failures += 1;
            }
            Verdict::Broken(why) => {
                println!(
                    "  {}: BROKEN -- {why}. A crashed checker is as blind as a sabotaged one; this is NOT counted as detection.",
                    c.tool
                );
                for l in text.lines().take(6) {
                    println!("      | {l}");
                }
                failures += 1;
            }
        }
    }
    if failures > 0 {
        eprintln!("canary: {failures} canary/canaries did not demonstrate detection");
        return 1;
    }
    println!("# all canaries demonstrated detection");
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_result_on_known_bad_is_blind() {
        // The sabotage signature: the tool is content with a fixture that is not fine.
        assert_eq!(
            classify(true, "no vulnerabilities found", "RUSTSEC-2018-0006"),
            Verdict::Blind
        );
        // Even if the marker appears, a SUCCESS exit on a known-bad is blindness: the tool
        // saw it and waved it through.
        assert_eq!(
            classify(true, "RUSTSEC-2018-0006 (ignored)", "RUSTSEC-2018-0006"),
            Verdict::Blind
        );
    }

    #[test]
    fn failure_with_evidence_is_detection() {
        assert_eq!(
            classify(
                false,
                "error: 1 vulnerability found!\nID: RUSTSEC-2018-0006",
                "RUSTSEC-2018-0006"
            ),
            Verdict::Detected
        );
    }

    #[test]
    fn failure_without_evidence_is_broken_not_detection() {
        // The #290 shape: cargo-vet exited non-zero for its entire deployment because it
        // PANICKED, and that exit was read as a finding. Exit status is not evidence.
        match classify(
            false,
            "ERROR panicked: Cargo failed to set CARGO",
            "RUSTSEC-2018-0006",
        ) {
            Verdict::Broken(why) => assert!(why.contains("RUSTSEC-2018-0006")),
            other => panic!("a panic must not count as detection, got {other:?}"),
        }
    }

    #[test]
    fn every_canary_names_a_fixture_that_exists() {
        // A canary pointing at a missing fixture would fail as UNRUNNABLE forever, which
        // is loud rather than silent -- but catching it here is cheaper than in CI.
        for c in CANARIES {
            let from_workspace = std::path::Path::new("..").join(c.fixture);
            assert!(
                from_workspace.exists() || std::path::Path::new(c.fixture).exists(),
                "fixture missing for {}: {}",
                c.tool,
                c.fixture
            );
        }
    }
}
