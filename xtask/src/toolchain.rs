//! `cargo xtask toolchain-advisories` -- the vuln axis for the TOOLCHAIN (#267).
//!
//! WHY THIS EXISTS. `cargo-audit` answers questions about a Cargo.lock, and std, rustc,
//! cargo and rustdoc appear in no lockfile. So the vuln axis has always been structurally
//! blind to the toolchain -- not clean, blind -- while toolchain vulnerabilities are real
//! and have been severe (CVE-2024-24576 "BatBadBut", CVSS 10.0 critical).
//!
//! WHY NOT THE RUSTSEC advisory-db WE ALREADY FETCH. It does ship a `rust/` tree
//! (`rust/std`, `rust/cargo`, `rust/rustdoc`), which looks like the obvious source and is
//! NOT usable as the primary one: measured 2026-08-24, its newest entry is dated
//! 2022-01-16 while the database itself was current that day, and CVE-2024-24576 is absent
//! from it entirely. A source that is stale in exactly the region we care about would
//! manufacture the most dangerous result available -- a confident "no advisories".
//!
//! SOURCE OF RECORD is therefore GitHub Security Advisories on `rust-lang/rust`, which is
//! published by the Rust Security Response WG, is machine-readable, carries per-package
//! version ranges, and does contain CVE-2024-24576 / CVE-2024-43402 / CVE-2025-11233.
//!
//! SEPARATION OF CONCERNS. The workflow performs the fetch and hands this command a file;
//! this command performs no network I/O. That keeps least privilege legible (the job needs
//! only a read-only token), keeps xtask dependency-free, and makes every decision here
//! unit-testable against fixtures rather than against a live API.
//!
//! FAIL-CLOSED THROUGHOUT. Every uncertainty resolves to "cannot say", never to "fine":
//! an unreadable or empty advisory set, an unparseable version range, or an unresolvable
//! toolchain version each fail the command. The failure mode being defended against is a
//! watcher that reports silence because it is broken, which is indistinguishable from
//! silence because there is nothing to report (#223).

use std::path::Path;
use std::process::Command;

use serde_json::Value;

/// A Rust version, with the pre-release flag kept because it changes ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RustVer {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    /// True for `-nightly` / `-beta`. A pre-release sorts BEFORE the release of the same
    /// number (1.99.0-nightly < 1.99.0), which is the conservative reading: a nightly does
    /// not yet contain a fix that shipped in its own release number.
    pub pre: bool,
}

impl RustVer {
    fn key(self) -> (u64, u64, u64, u8) {
        (self.major, self.minor, self.patch, u8::from(!self.pre))
    }
}

impl PartialOrd for RustVer {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RustVer {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.key().cmp(&other.key())
    }
}

/// Parse `1.99.0`, `1.77.2`, `1.99.0-nightly`, or a bare `1.77` (treated as `1.77.0`).
pub fn parse_ver(s: &str) -> Option<RustVer> {
    let s = s.trim();
    let (core, pre) = match s.split_once('-') {
        Some((c, _)) => (c, true),
        None => (s, false),
    };
    let mut it = core.split('.');
    let major = it.next()?.parse().ok()?;
    let minor = it.next().unwrap_or("0").parse().ok()?;
    let patch = it.next().unwrap_or("0").parse().ok()?;
    if it.next().is_some() {
        return None;
    }
    Some(RustVer {
        major,
        minor,
        patch,
        pre,
    })
}

/// Does `v` fall inside a GitHub advisory `vulnerable_version_range`?
///
/// Supported shapes are the ones GitHub actually emits for this repository, e.g.
/// `< 1.77.2`, `>= 1.0.0, < 1.58.1`, `<= 1.2.3`, `= 1.2.3`. Anything else is an ERROR
/// rather than a false: a range we cannot read is a question we cannot answer, and the
/// caller must treat it as unevaluated instead of as safe.
pub fn range_contains(range: &str, v: RustVer) -> Result<bool, String> {
    let mut all = true;
    for clause in range.split(',') {
        let clause = clause.trim();
        if clause.is_empty() {
            continue;
        }
        let (op, rest) = if let Some(r) = clause.strip_prefix(">=") {
            (">=", r)
        } else if let Some(r) = clause.strip_prefix("<=") {
            ("<=", r)
        } else if let Some(r) = clause.strip_prefix('<') {
            ("<", r)
        } else if let Some(r) = clause.strip_prefix('>') {
            (">", r)
        } else if let Some(r) = clause.strip_prefix('=') {
            ("=", r)
        } else {
            return Err(format!("unrecognised range clause {clause:?}"));
        };
        let bound =
            parse_ver(rest).ok_or_else(|| format!("unparseable version in clause {clause:?}"))?;
        let ok = match op {
            ">=" => v >= bound,
            "<=" => v <= bound,
            "<" => v < bound,
            ">" => v > bound,
            "=" => v == bound,
            _ => unreachable!(),
        };
        all &= ok;
    }
    Ok(all)
}

/// Resolve the pinned channel to a concrete version via `rustup run <channel> rustc -V`.
///
/// Deliberately the PINNED channel rather than an ambient `rustc`: the question is what
/// the build actually uses, and an ambient toolchain can differ from the committed pin.
fn resolve_version(channel: &str) -> Result<RustVer, String> {
    let out = Command::new("rustup")
        .args(["run", channel, "rustc", "--version"])
        .output()
        .map_err(|e| format!("cannot run rustup for channel {channel}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "rustup run {channel} rustc --version failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    // "rustc 1.99.0-nightly (6f72b5dd5 2026-07-22)"
    let token = text
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| format!("unexpected rustc --version output: {text:?}"))?;
    parse_ver(token).ok_or_else(|| format!("cannot parse rustc version {token:?}"))
}

fn channel_from_toolchain_file(path: &Path) -> Option<String> {
    let t = std::fs::read_to_string(path).ok()?;
    for line in t.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("channel") {
            let rest = rest.trim_start_matches([' ', '=']).trim();
            return Some(rest.trim_matches('"').to_string());
        }
    }
    None
}

pub fn run(args: &[String]) -> i32 {
    let mut advisories = String::new();
    let mut channel: Option<String> = None;
    let mut toolchain_file = String::from("app/rust-toolchain.toml");
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--advisories" => advisories = it.next().cloned().unwrap_or_default(),
            "--channel" => channel = it.next().cloned(),
            "--toolchain-file" => toolchain_file = it.next().cloned().unwrap_or(toolchain_file),
            other => {
                eprintln!("toolchain-advisories: unknown argument {other}");
                return 2;
            }
        }
    }
    if advisories.is_empty() {
        eprintln!(
            "usage: xtask toolchain-advisories --advisories <file.json> [--channel <ch>] [--toolchain-file <path>]"
        );
        return 2;
    }

    let channel = match channel.or_else(|| channel_from_toolchain_file(Path::new(&toolchain_file)))
    {
        Some(c) => c,
        None => {
            eprintln!("toolchain-advisories: no channel given and none found in {toolchain_file}");
            return 1;
        }
    };
    let ver = match resolve_version(&channel) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("toolchain-advisories: {e}");
            return 1;
        }
    };

    let text = match std::fs::read_to_string(&advisories) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("toolchain-advisories: cannot read {advisories}: {e}");
            return 1;
        }
    };
    let doc: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("toolchain-advisories: {advisories} is not valid JSON: {e}");
            return 1;
        }
    };
    let list = match doc.as_array() {
        Some(a) => a,
        None => {
            eprintln!("toolchain-advisories: expected a JSON array of advisories");
            return 1;
        }
    };
    // An EMPTY advisory set is not evidence of safety. rust-lang/rust has published
    // several advisories, so zero means the fetch failed, was rate-limited, or the API
    // shape changed -- all of which must read as "cannot say", never as "clean" (#223).
    if list.is_empty() {
        eprintln!(
            "toolchain-advisories: advisory set is EMPTY. This is treated as a FETCH FAILURE, \
             not as an all-clear: rust-lang/rust has known published advisories."
        );
        return 1;
    }

    println!(
        "# toolchain advisories (#267) -- channel {channel} resolves to {}.{}.{}{}",
        ver.major,
        ver.minor,
        ver.patch,
        if ver.pre { "-pre" } else { "" }
    );
    println!("# source: GitHub Security Advisories, rust-lang/rust ({} entries)", list.len());

    let mut affected = 0;
    let mut unevaluated = 0;
    for adv in list {
        let ghsa = adv.get("ghsa_id").and_then(Value::as_str).unwrap_or("?");
        let cve = adv.get("cve_id").and_then(Value::as_str).unwrap_or("-");
        let sev = adv.get("severity").and_then(Value::as_str).unwrap_or("?");
        let empty = Vec::new();
        let vulns = adv
            .get("vulnerabilities")
            .and_then(Value::as_array)
            .unwrap_or(&empty);
        for v in vulns {
            let pkg = v
                .get("package")
                .and_then(|p| p.get("name"))
                .and_then(Value::as_str)
                .unwrap_or("?");
            let range = v
                .get("vulnerable_version_range")
                .and_then(Value::as_str)
                .unwrap_or("");
            if range.is_empty() {
                println!("  UNEVALUATED {ghsa} ({cve}) {pkg}: advisory carries no version range");
                unevaluated += 1;
                continue;
            }
            match range_contains(range, ver) {
                Ok(true) => {
                    let patched = v
                        .get("patched_versions")
                        .and_then(Value::as_str)
                        .unwrap_or("?");
                    println!(
                        "  AFFECTED {ghsa} ({cve}) severity={sev} {pkg} range={range:?} patched={patched}"
                    );
                    affected += 1;
                }
                Ok(false) => {}
                Err(why) => {
                    println!("  UNEVALUATED {ghsa} ({cve}) {pkg}: {why}");
                    unevaluated += 1;
                }
            }
        }
    }

    if affected > 0 || unevaluated > 0 {
        eprintln!(
            "toolchain-advisories: {affected} affected, {unevaluated} unevaluated -- \
             an unevaluated advisory is NOT a pass"
        );
        return 1;
    }
    println!("# no advisory applies to this toolchain, and every advisory was evaluable");
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> RustVer {
        parse_ver(s).unwrap()
    }

    #[test]
    fn nightly_sorts_before_its_own_release() {
        // Conservative and load-bearing: a fix that shipped in 1.99.0 is NOT present in
        // 1.99.0-nightly, so a `< 1.99.0` advisory must still apply to that nightly.
        assert!(v("1.99.0-nightly") < v("1.99.0"));
        assert!(range_contains("< 1.99.0", v("1.99.0-nightly")).unwrap());
        assert!(!range_contains("< 1.99.0", v("1.99.0")).unwrap());
    }

    #[test]
    fn batbadbut_does_not_apply_to_a_modern_toolchain() {
        // CVE-2024-24576, the real shape from the API.
        assert!(!range_contains("< 1.77.2", v("1.99.0-nightly")).unwrap());
        assert!(range_contains("< 1.77.2", v("1.70.0")).unwrap());
    }

    #[test]
    fn compound_ranges_are_intersected() {
        assert!(range_contains(">= 1.0.0, < 1.58.1", v("1.50.0")).unwrap());
        assert!(!range_contains(">= 1.0.0, < 1.58.1", v("1.60.0")).unwrap());
        assert!(!range_contains(">= 1.0.0, < 1.58.1", v("0.9.0")).unwrap());
    }

    #[test]
    fn unreadable_range_is_an_error_not_a_false() {
        // The whole point: a range we cannot parse is a question we cannot answer. If this
        // returned Ok(false) the watcher would silently under-report.
        assert!(range_contains("~1.2.3", v("1.2.0")).is_err());
        assert!(range_contains("< not-a-version", v("1.2.0")).is_err());
    }

    #[test]
    fn version_parsing_handles_the_shapes_github_emits() {
        assert_eq!(v("1.77.2").patch, 2);
        assert_eq!(v("1.77").patch, 0);
        assert!(v("1.99.0-nightly").pre);
        assert!(!v("1.99.0").pre);
        assert!(parse_ver("1.2.3.4").is_none());
        assert!(parse_ver("").is_none());
    }
}
