//! `cargo xtask verify-toolchain-provenance` -- prove from the BYTES which compiler built them.
//!
//! THE DEFECT THIS ANSWERS (#321). `rustup toolchain install` installs a toolchain; it does not
//! select one. The pin was digest-verified, soak-gated, and drift-checked, and then a different
//! compiler built the tools -- silently, because every flag we passed was accepted by both. The
//! preflight assertion added in #321 closes that going forward, but a preflight is the builder
//! vouching for itself. This measures the artifact instead.
//!
//! THE FINGERPRINT. A Rust binary embeds std's source paths as `/rustc/<40-hex-commit>/library/
//! ...`, and that commit is the toolchain's own. It needs no debug info, no PDB, and no
//! cooperation from the build -- it is a property of the shipped bytes, which is the standard
//! the hardening ratchet already holds artifacts to.
//!
//! It was not a theory. Run against the published tool store, every binary reported
//! `8bab26f4f68e0e26f0bb7960be334d5b520ea452` (rustc 1.97.1 stable) where the pin is
//! `6f72b5dd5f82226a2773d40efea7bab941892a73` (nightly-2026-07-23). The check finds the real
//! defect on real artifacts, retroactively.
//!
//! WHAT IT IS NOT. This identifies the toolchain whose STD was linked. rustc and std ship
//! together, so in practice that is the compiler -- but std is what leaves the trace, and
//! saying otherwise would overstate it. Under `-Z build-std` std is recompiled from local
//! rust-src and the paths change shape entirely; that is a DISTINCT valid outcome, reported as
//! such rather than folded into a pass or a failure.

use std::collections::BTreeSet;
use std::process::Command;

/// std source paths in a normally-built binary.
const RUSTC_PREFIX: &[u8] = b"/rustc/";
/// std source paths when `-Z build-std` compiled std from the local rust-src component.
const LOCAL_STD_MARKER: &[u8] = b"rustlib/src/rust/library/";

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > hay.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Lowercase hex only: rustc emits lowercase, and accepting mixed case would let two spellings
/// of one hash compare unequal.
fn is_commit(b: &[u8]) -> bool {
    b.len() == 40 && b.iter().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
}

/// Every distinct rustc commit hash referenced by the image. Pure, so the parsing is testable
/// without producing a binary.
pub fn scan_rustc_commits(bytes: &[u8]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut i = 0usize;
    while let Some(p) = find(&bytes[i..], RUSTC_PREFIX) {
        let start = i + p + RUSTC_PREFIX.len();
        if start + 40 <= bytes.len() && is_commit(&bytes[start..start + 40]) {
            out.insert(String::from_utf8_lossy(&bytes[start..start + 40]).into_owned());
        }
        i = start;
    }
    out
}

pub fn has_local_std(bytes: &[u8]) -> bool {
    find(bytes, LOCAL_STD_MARKER).is_some()
}

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Every embedded commit is the expected one.
    Match,
    /// A commit that is not the pinned toolchain's. This is #321's signature.
    Mismatch(Vec<String>),
    /// No `/rustc/` paths, but local rust-src paths are present: `-Z build-std` rebuilt std, so
    /// the fingerprint legitimately moves. Reported, never silently passed.
    BuildStd,
    /// Neither fingerprint. Not evidence of correctness, so not a pass -- the same reasoning the
    /// canaries use for a checker that exits non-zero without naming a finding (#223).
    NoFingerprint,
}

pub fn classify(found: &BTreeSet<String>, expected: &str, local_std: bool) -> Verdict {
    if found.is_empty() {
        return if local_std {
            Verdict::BuildStd
        } else {
            Verdict::NoFingerprint
        };
    }
    let wrong: Vec<String> = found.iter().filter(|h| *h != expected).cloned().collect();
    if wrong.is_empty() {
        Verdict::Match
    } else {
        Verdict::Mismatch(wrong)
    }
}

/// The expected hash comes from the compiler that is ACTIVE, which #321's preflight has already
/// asserted is the pinned channel. Deriving it here rather than adding a fourth field to
/// TOOLCHAIN.lock keeps one declaration: a hash recorded by hand is a hash that can drift.
fn active_rustc_commit() -> Result<String, String> {
    let out = Command::new("rustc")
        .arg("-vV")
        .output()
        .map_err(|e| format!("cannot run rustc: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("commit-hash:") {
            let h = rest.trim();
            if is_commit(h.as_bytes()) {
                return Ok(h.to_string());
            }
            return Err(format!("rustc reports a non-hash commit-hash: {h:?}"));
        }
    }
    Err("rustc -vV printed no commit-hash line".into())
}

pub fn run(args: &[String]) -> i32 {
    let mut expect: Option<String> = None;
    let mut allow_build_std = false;
    let mut paths: Vec<String> = Vec::new();
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--expect-commit" => expect = it.next().cloned(),
            "--allow-build-std" => allow_build_std = true,
            other => paths.push(other.to_string()),
        }
    }
    if paths.is_empty() {
        eprintln!("verify-toolchain-provenance: no binaries given");
        return 2;
    }
    let expected = match expect {
        Some(e) if is_commit(e.as_bytes()) => e,
        Some(e) => {
            eprintln!("verify-toolchain-provenance: --expect-commit {e:?} is not a 40-hex commit");
            return 2;
        }
        None => match active_rustc_commit() {
            Ok(e) => e,
            Err(e) => {
                eprintln!("verify-toolchain-provenance: {e}");
                return 2;
            }
        },
    };

    println!("# every binary must carry the pinned toolchain's commit: {expected}");
    let mut failures = 0;
    for p in &paths {
        let bytes = match std::fs::read(p) {
            Ok(b) => b,
            Err(e) => {
                println!("  {p}: UNREADABLE -- {e}");
                failures += 1;
                continue;
            }
        };
        let found = scan_rustc_commits(&bytes);
        match classify(&found, &expected, has_local_std(&bytes)) {
            Verdict::Match => println!("  {p}: OK ({expected})"),
            Verdict::Mismatch(w) => {
                println!("  {p}: BUILT BY A DIFFERENT COMPILER -- found {w:?}, expected {expected}");
                failures += 1;
            }
            Verdict::BuildStd if allow_build_std => println!(
                "  {p}: build-std (std rebuilt from local rust-src; no /rustc/ fingerprint)"
            ),
            Verdict::BuildStd => {
                println!("  {p}: build-std fingerprint, but --allow-build-std was not passed");
                failures += 1;
            }
            Verdict::NoFingerprint => {
                println!("  {p}: NO FINGERPRINT -- cannot attribute this binary to any toolchain");
                failures += 1;
            }
        }
    }
    if failures > 0 {
        eprintln!("verify-toolchain-provenance: {failures} binar(ies) not attributable to the pin");
        return 1;
    }
    println!("# all binaries attributable to the pinned toolchain");
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(v: &[&str]) -> BTreeSet<String> {
        v.iter().map(|s| s.to_string()).collect()
    }
    const PIN: &str = "6f72b5dd5f82226a2773d40efea7bab941892a73";
    const STABLE: &str = "8bab26f4f68e0e26f0bb7960be334d5b520ea452";

    #[test]
    fn extracts_the_commit_from_an_embedded_std_path() {
        let b = format!("junk\0/rustc/{PIN}/library/std/src/rt.rs\0more");
        assert_eq!(scan_rustc_commits(b.as_bytes()), set(&[PIN]));
    }

    #[test]
    fn the_real_defect_is_a_mismatch_not_a_pass() {
        // The measured #321 signature: the published tools carried stable's hash while the repo
        // declared the nightly. If this ever returns Match, the check has stopped working.
        assert_eq!(
            classify(&set(&[STABLE]), PIN, false),
            Verdict::Mismatch(vec![STABLE.to_string()])
        );
    }

    #[test]
    fn a_binary_with_no_fingerprint_is_not_a_pass() {
        // Absence of evidence is not evidence of the pin -- the same rule the canaries apply to
        // a checker that exits non-zero without naming a finding.
        assert_eq!(classify(&set(&[]), PIN, false), Verdict::NoFingerprint);
    }

    #[test]
    fn build_std_is_its_own_verdict() {
        assert_eq!(classify(&set(&[]), PIN, true), Verdict::BuildStd);
    }

    #[test]
    fn a_mixed_binary_fails_on_the_stray_commit() {
        // Linking something built by another toolchain must not be masked by the majority.
        assert_eq!(
            classify(&set(&[PIN, STABLE]), PIN, false),
            Verdict::Mismatch(vec![STABLE.to_string()])
        );
    }

    #[test]
    fn truncated_and_malformed_hashes_are_not_accepted() {
        assert!(scan_rustc_commits(b"/rustc/abc123/library/std").is_empty());
        // Uppercase would compare unequal to rustc's own lowercase spelling of the same hash.
        let upper = format!("/rustc/{}/library", PIN.to_uppercase());
        assert!(scan_rustc_commits(upper.as_bytes()).is_empty());
    }

    #[test]
    fn a_prefix_at_end_of_file_does_not_panic() {
        assert!(scan_rustc_commits(b"padding/rustc/").is_empty());
    }

    #[test]
    fn two_binaries_worth_of_paths_yield_both_commits() {
        let b = format!("/rustc/{PIN}/library/std /rustc/{STABLE}/library/core");
        assert_eq!(scan_rustc_commits(b.as_bytes()), set(&[PIN, STABLE]));
    }
}
