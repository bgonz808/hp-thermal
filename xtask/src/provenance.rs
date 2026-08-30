//! `cargo xtask verify-toolchain-provenance` -- prove from the BYTES which compiler built them.
//!
//! THE DEFECT THIS ANSWERS (#321). `rustup toolchain install` installs a toolchain; it does not
//! select one. The pin was digest-verified, soak-gated, and drift-checked, and then a different
//! compiler built the tools -- silently, because every flag we passed was accepted by both. The
//! preflight assertion added in #320 closes that going forward, but a preflight is the builder
//! vouching for itself. This measures the artifact.
//!
//! TWO FINGERPRINTS, because a Rust binary records where std's source lived and that answer
//! depends on how std got there:
//!
//!   * NORMALLY, std is precompiled and shipped with the toolchain, and paths read
//!     `/rustc/<40-hex-commit>/library/...`. The commit identifies the toolchain exactly.
//!   * UNDER `-Z build-std`, std is COMPILED FROM SOURCE out of the rust-src component, and
//!     those paths vanish. What appears instead is the rustup layout:
//!     `...\.rustup\toolchains\nightly-2026-07-23-x86_64-pc-windows-msvc\...`, which names the
//!     CHANNEL outright -- the very string tools/TOOLCHAIN.lock declares.
//!
//! The second case was found by running the first version of this check against a real
//! build-std binary and getting NO FINGERPRINT. The guess encoded then (that std's source would
//! appear under `rustlib/src/rust/library/`) was simply wrong. Both fingerprints are now read
//! from measurement rather than from expectation, and a build-std binary is ATTRIBUTABLE rather
//! than merely excused.
//!
//! Neither needs debug info, a PDB, or cooperation from the build. They are properties of the
//! shipped bytes, which is the standard the hardening ratchet already holds artifacts to.
//!
//! WHAT IT IS NOT. This identifies the toolchain whose STD was linked. rustc and std ship
//! together, so in practice that is the compiler -- but std is what leaves the trace, and
//! saying otherwise would overstate it.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

/// std source paths in a normally-built binary.
const RUSTC_PREFIX: &[u8] = b"/rustc/";

/// rustup lays toolchains out as `<RUSTUP_HOME>/toolchains/<channel>-<target>/`. Both
/// separators, because the path is baked in as the build host wrote it.
const TOOLCHAINS_SEGMENTS: &[&[u8]] = &[b"toolchains\\", b"toolchains/"];

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

/// Every distinct rustc commit hash referenced by the image.
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

/// Toolchain directory names referenced by the image, e.g.
/// `nightly-2026-07-23-x86_64-pc-windows-msvc`. Present when std was built from source.
pub fn scan_toolchain_dirs(bytes: &[u8]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for seg in TOOLCHAINS_SEGMENTS {
        let mut i = 0usize;
        while let Some(p) = find(&bytes[i..], seg) {
            let start = i + p + seg.len();
            let mut end = start;
            while end < bytes.len() && bytes[end] != b'\\' && bytes[end] != b'/' {
                end += 1;
            }
            let name = String::from_utf8_lossy(&bytes[start..end]).into_owned();
            // A toolchain directory is `<channel>-<target-triple>`, so it always contains a
            // hyphen and starts alphanumeric. Anything else is a different `toolchains/` on
            // some unrelated path and must not be read as provenance.
            if name.len() >= 3
                && name.contains('-')
                && name.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
            {
                out.insert(name);
            }
            i = start;
        }
    }
    out
}

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Precompiled std, and every embedded commit is the expected one.
    Match,
    /// A commit that is not the pinned toolchain's. This is #321's signature.
    Mismatch(Vec<String>),
    /// std was built from source and the toolchain path names the expected channel. A pass on
    /// EVIDENCE, not an exemption.
    BuildStd(String),
    /// std was built from source, but by some other channel.
    ChannelMismatch(Vec<String>),
    /// Neither fingerprint. Not evidence of correctness, so not a pass -- the same reasoning the
    /// canaries use for a checker that exits non-zero without naming a finding (#223).
    NoFingerprint,
}

pub fn classify(
    commits: &BTreeSet<String>,
    expected_commit: &str,
    toolchains: &BTreeSet<String>,
    expected_channel: &str,
) -> Verdict {
    if !commits.is_empty() {
        let wrong: Vec<String> = commits
            .iter()
            .filter(|h| *h != expected_commit)
            .cloned()
            .collect();
        return if wrong.is_empty() {
            Verdict::Match
        } else {
            Verdict::Mismatch(wrong)
        };
    }
    if !toolchains.is_empty() {
        // `<channel>-<target>`: require the hyphen so `nightly-2026-07-2` cannot pass for
        // `nightly-2026-07-23`, which a bare prefix test would allow.
        let prefix = format!("{expected_channel}-");
        if let Some(hit) = toolchains.iter().find(|t| t.starts_with(&prefix)) {
            return Verdict::BuildStd(hit.clone());
        }
        return Verdict::ChannelMismatch(toolchains.iter().cloned().collect());
    }
    Verdict::NoFingerprint
}

/// The expected hash comes from the compiler that is ACTIVE, which #320's preflight has already
/// asserted is the pinned channel. Deriving it rather than recording it keeps one declaration:
/// a hash written down by hand is a hash that can drift.
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

/// The channel comes from TOOLCHAIN.lock, which is where it is declared. Same single-source
/// reasoning as the commit hash, from the other direction.
fn declared_channel() -> Result<String, String> {
    for p in ["tools/TOOLCHAIN.lock", "../tools/TOOLCHAIN.lock"] {
        let Ok(text) = std::fs::read_to_string(Path::new(p)) else {
            continue;
        };
        for line in text.lines() {
            let mut f = line.split_whitespace();
            if f.next() == Some("channel") {
                if let Some(c) = f.next() {
                    return Ok(c.to_string());
                }
            }
        }
        return Err(format!("{p} has no 'channel' field"));
    }
    Err("cannot read tools/TOOLCHAIN.lock".into())
}

pub fn run(args: &[String]) -> i32 {
    let mut expect_commit: Option<String> = None;
    let mut expect_channel: Option<String> = None;
    let mut paths: Vec<String> = Vec::new();
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--expect-commit" => expect_commit = it.next().cloned(),
            "--expect-channel" => expect_channel = it.next().cloned(),
            other => paths.push(other.to_string()),
        }
    }
    if paths.is_empty() {
        eprintln!("verify-toolchain-provenance: no binaries given");
        return 2;
    }
    let commit = match expect_commit {
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
    let channel = match expect_channel {
        Some(c) => c,
        None => match declared_channel() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("verify-toolchain-provenance: {e}");
                return 2;
            }
        },
    };

    println!("# expected toolchain: {channel} (commit {commit})");
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
        let commits = scan_rustc_commits(&bytes);
        let dirs = scan_toolchain_dirs(&bytes);
        match classify(&commits, &commit, &dirs, &channel) {
            Verdict::Match => println!("  {p}: OK ({commit})"),
            Verdict::BuildStd(t) => println!("  {p}: OK build-std ({t})"),
            Verdict::Mismatch(w) => {
                println!("  {p}: BUILT BY A DIFFERENT COMPILER -- found {w:?}, expected {commit}");
                failures += 1;
            }
            Verdict::ChannelMismatch(w) => {
                println!("  {p}: BUILT BY A DIFFERENT CHANNEL -- found {w:?}, expected {channel}");
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
    const CHAN: &str = "nightly-2026-07-23";
    const DIR: &str = "nightly-2026-07-23-x86_64-pc-windows-msvc";

    #[test]
    fn extracts_the_commit_from_an_embedded_std_path() {
        let b = format!("junk\0/rustc/{PIN}/library/std/src/rt.rs\0more");
        assert_eq!(scan_rustc_commits(b.as_bytes()), set(&[PIN]));
    }

    #[test]
    fn the_real_defect_is_a_mismatch_not_a_pass() {
        // The measured #321 signature: the published tools carried stable's hash while the repo
        // declared the nightly.
        assert_eq!(
            classify(&set(&[STABLE]), PIN, &set(&[]), CHAN),
            Verdict::Mismatch(vec![STABLE.to_string()])
        );
    }

    #[test]
    fn build_std_is_attributable_by_channel() {
        // Measured from the real cargo-auditable build: no /rustc/ paths, but the rustup
        // toolchain directory names the channel. The first version of this check called that
        // NO FINGERPRINT, which was wrong -- the evidence was there, under a different string.
        assert_eq!(
            classify(&set(&[]), PIN, &set(&[DIR]), CHAN),
            Verdict::BuildStd(DIR.to_string())
        );
    }

    #[test]
    fn build_std_by_the_wrong_channel_fails() {
        let other = "nightly-2026-08-25-x86_64-pc-windows-msvc";
        assert_eq!(
            classify(&set(&[]), PIN, &set(&[other]), CHAN),
            Verdict::ChannelMismatch(vec![other.to_string()])
        );
    }

    #[test]
    fn a_channel_that_merely_starts_the_same_is_not_a_match() {
        // `nightly-2026-07-2` must not satisfy `nightly-2026-07-23`; requiring the trailing
        // hyphen of `<channel>-<target>` is what prevents a bare prefix test from accepting it.
        let near = "nightly-2026-07-2-x86_64-pc-windows-msvc";
        assert_eq!(
            classify(&set(&[]), PIN, &set(&[near]), CHAN),
            Verdict::ChannelMismatch(vec![near.to_string()])
        );
    }

    #[test]
    fn a_binary_with_neither_fingerprint_is_not_a_pass() {
        assert_eq!(
            classify(&set(&[]), PIN, &set(&[]), CHAN),
            Verdict::NoFingerprint
        );
    }

    #[test]
    fn a_mixed_binary_fails_on_the_stray_commit() {
        assert_eq!(
            classify(&set(&[PIN, STABLE]), PIN, &set(&[]), CHAN),
            Verdict::Mismatch(vec![STABLE.to_string()])
        );
    }

    #[test]
    fn scans_toolchain_dirs_from_both_separators() {
        let win = format!("C:\\Users\\runneradmin\\.rustup\\toolchains\\{DIR}\\lib\\rustlib");
        assert_eq!(scan_toolchain_dirs(win.as_bytes()), set(&[DIR]));
        let nix = format!("/home/runner/.rustup/toolchains/{DIR}/lib/rustlib");
        assert_eq!(scan_toolchain_dirs(nix.as_bytes()), set(&[DIR]));
    }

    #[test]
    fn an_unrelated_toolchains_directory_is_not_read_as_provenance() {
        // A path component with no hyphen is not `<channel>-<target>`.
        assert!(scan_toolchain_dirs(b"/opt/toolchains/mine/bin").is_empty());
    }

    #[test]
    fn truncated_and_malformed_hashes_are_not_accepted() {
        assert!(scan_rustc_commits(b"/rustc/abc123/library/std").is_empty());
        let upper = format!("/rustc/{}/library", PIN.to_uppercase());
        assert!(scan_rustc_commits(upper.as_bytes()).is_empty());
    }

    #[test]
    fn a_prefix_at_end_of_file_does_not_panic() {
        assert!(scan_rustc_commits(b"padding/rustc/").is_empty());
        assert!(scan_toolchain_dirs(b"padding/toolchains/").is_empty());
    }

    #[test]
    fn commits_win_over_toolchain_dirs_when_both_are_present() {
        // A normally-built binary may reference a toolchain path incidentally. The commit is
        // the stronger signal and must decide.
        assert_eq!(classify(&set(&[PIN]), PIN, &set(&[DIR]), CHAN), Verdict::Match);
    }
}
