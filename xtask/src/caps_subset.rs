//! #367: the caps axis's "strictly better" rule. A MEASURED head inventory that is a strict
//! subset of the prior blessed inventory is ALLOW without a fresh signature — but only after
//! the measurement proves it is complete. An empty or partial inventory is trivially a
//! "subset", so every condition below fails toward RAISE (today's behavior), never ALLOW.
//!
//! Conditions, all required:
//!   1. measured, not COPIED FORWARD;
//!   2. the header records `cackle exit 0` and the sha256 of the lock it ran against, and that
//!      sha256 equals the candidate's resolved lock;
//!   3. at least one `[pkg.*]` section;
//!   4. no `[pkg.*]` section vanished for a package present in BOTH locks (shrink, never
//!      disappear);
//!   5. no new `[pkg.*]` section, and for every section every key's values are a subset of
//!      the prior's (arrays) or equal (scalars) — generic over cackle's keys, so a new
//!      `allow_unsafe = true` or a widened `from.build.allow_apis` is an addition;
//!   6. the instrument (`[api.*]`, `[sandbox]`, `[common]`, everything that is not a package
//!      section) is textually identical: a subset claim under a changed instrument is not a
//!      subset claim.

use std::collections::{BTreeMap, BTreeSet};

/// `[pkg.NAME]` -> key -> values. Arrays become their quoted elements; scalars become the
/// single trimmed value. Comments and blank lines are ignored.
pub fn pkg_blocks(caps: &str) -> BTreeMap<String, BTreeMap<String, BTreeSet<String>>> {
    let mut out: BTreeMap<String, BTreeMap<String, BTreeSet<String>>> = BTreeMap::new();
    let mut pkg: Option<String> = None;
    let mut open_key: Option<String> = None;
    for raw in caps.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            open_key = None;
            pkg = line
                .strip_prefix("[pkg.")
                .and_then(|r| r.strip_suffix(']'))
                .map(|n| n.trim_matches('"').to_string());
            if let Some(p) = &pkg {
                out.entry(p.clone()).or_default();
            }
            continue;
        }
        let Some(p) = &pkg else {
            continue;
        };
        if let Some(k) = &open_key {
            let set = out
                .entry(p.clone())
                .or_default()
                .entry(k.clone())
                .or_default();
            collect_quoted(line, set);
            if line.contains(']') {
                open_key = None;
            }
            continue;
        }
        if let Some((key, rhs)) = line.split_once('=') {
            let key = key.trim().to_string();
            let rhs = rhs.trim();
            let set = out
                .entry(p.clone())
                .or_default()
                .entry(key.clone())
                .or_default();
            if rhs.starts_with('[') {
                collect_quoted(rhs, set);
                if !rhs.contains(']') {
                    open_key = Some(key);
                }
            } else {
                set.insert(rhs.trim_matches('"').to_string());
            }
        }
    }
    out
}

/// Canonicalise a cargo build-script output path so the SAME directive compares equal across
/// measurements. Everything before `/build/` is the target dir plus the PROFILE dir
/// (`.../caps-build/cackle/build/...` vs `.../cackle-release/build/...`); the package segment
/// is spelled `<pkg>-<hash>` (cargo <= 1.100) or `<pkg>/<hash>` (1.101+); the 16-hex hash
/// moves with toolchain and profile. None of that is capability. The package, the directive
/// kind and the tail under `/out` are. Measured: identical aws-lc-sys directives read as
/// additions across a profile change (run 42778958576) and a toolchain change (run
/// 42758902308) until this canonicalisation. No regex crate: a hand parser.
pub fn normalize_build_dir(v: &str) -> String {
    let Some(i) = v.find("/build/") else {
        return v.to_string();
    };
    // Keep what precedes the PATH (e.g. "cargo:rustc-link-search=native="): the path starts
    // after the last '=' before "/build/", or at the string start.
    let path_start = v[..i].rfind('=').map(|e| e + 1).unwrap_or(0);
    let prefix = &v[..path_start];
    let rest = &v[i + "/build/".len()..];
    let Some(slash) = rest.find('/') else {
        return v.to_string();
    };
    let (seg, after_seg) = (&rest[..slash], &rest[slash..]);
    let is_hash = |h: &str| h.len() == 16 && h.bytes().all(|b| b.is_ascii_hexdigit());
    let (pkg, tail) = if seg.len() > 17
        && seg.as_bytes()[seg.len() - 17] == b'-'
        && is_hash(&seg[seg.len() - 16..])
    {
        // old layout: "<pkg>-<hash>/out..."
        (&seg[..seg.len() - 17], after_seg)
    } else {
        // new layout: "<pkg>/<hash>/out..."
        let Some(stripped) = after_seg.strip_prefix('/') else {
            return v.to_string();
        };
        match stripped.find('/') {
            Some(s2) if is_hash(&stripped[..s2]) => (seg, &stripped[s2..]),
            _ => return v.to_string(),
        }
    };
    if !tail.starts_with("/out") {
        return v.to_string();
    }
    format!("{prefix}<build>/{pkg}/HASH{tail}")
}

fn collect_quoted(s: &str, into: &mut BTreeSet<String>) {
    let mut rest = s;
    while let Some(i) = rest.find('"') {
        let after = &rest[i + 1..];
        let Some(j) = after.find('"') else {
            break;
        };
        into.insert(normalize_build_dir(&after[..j]));
        rest = &after[j + 1..];
    }
}

/// Everything that is not a `[pkg.*]` section, comments and blank lines removed: the
/// instrument the inventory was measured with.
pub fn instrument_text(caps: &str) -> String {
    let mut out = Vec::new();
    let mut in_pkg = false;
    for raw in caps.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            in_pkg = line.starts_with("[pkg.");
        }
        if !in_pkg {
            out.push(line.to_string());
        }
    }
    out.join("\n")
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct MeasurementHeader {
    pub cackle_exit: Option<i64>,
    pub lock_sha256: Option<String>,
    pub copied_forward: bool,
}

/// Read the provenance header (leading `#` lines) written by caps-measure.yml.
pub fn header(caps: &str) -> MeasurementHeader {
    let mut h = MeasurementHeader::default();
    for raw in caps.lines().take_while(|l| l.trim_start().starts_with('#')) {
        let line = raw.trim_start_matches('#').trim();
        if line.contains("COPIED FORWARD") {
            h.copied_forward = true;
        }
        if let Some(i) = line.find("cackle exit ") {
            let digits: String = line[i + "cackle exit ".len()..]
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '-')
                .collect();
            h.cackle_exit = digits.parse().ok();
        }
        if let Some(i) = line.find("sha256 ") {
            let hex: String = line[i + "sha256 ".len()..]
                .chars()
                .take_while(|c| c.is_ascii_hexdigit())
                .collect();
            if hex.len() == 64 {
                h.lock_sha256 = Some(hex.to_ascii_lowercase());
            }
        }
    }
    h
}

/// `Ok(description)` when the head inventory is a complete, measured, strict subset of the
/// base inventory. `Err(reason)` otherwise — the caller falls back to RAISE, never to ALLOW.
pub fn subset_allow(
    head_caps: &str,
    base_caps: &str,
    head_lock_sha256: &str,
    head_lock_pkgs: &BTreeSet<String>,
    base_lock_pkgs: &BTreeSet<String>,
) -> Result<String, String> {
    let h = header(head_caps);
    if h.copied_forward {
        return Err("head inventory is COPIED FORWARD, not a measurement".into());
    }
    match h.cackle_exit {
        Some(0) => {}
        Some(n) => {
            return Err(format!(
                "measurement recorded cackle exit {n}: partial inventory"
            ));
        }
        None => return Err("header records no `cackle exit` code: completeness unproven".into()),
    }
    match &h.lock_sha256 {
        Some(s) if s == &head_lock_sha256.to_ascii_lowercase() => {}
        Some(s) => {
            return Err(format!(
                "header lock sha256 {}… does not match the candidate's lock {}…",
                &s[..12],
                &head_lock_sha256[..12.min(head_lock_sha256.len())]
            ));
        }
        None => {
            return Err("header records no lock sha256: measured against an unknown tree".into());
        }
    }
    let head = pkg_blocks(head_caps);
    let base = pkg_blocks(base_caps);
    if head.is_empty() {
        return Err("head inventory has no [pkg.*] sections: empty is not a subset".into());
    }
    if instrument_text(head_caps) != instrument_text(base_caps) {
        return Err(
            "instrument ([api.*]/[sandbox]/[common]) differs from the prior inventory".into(),
        );
    }
    let mut vanished = Vec::new();
    for p in base.keys() {
        if !head.contains_key(p) && head_lock_pkgs.contains(p) && base_lock_pkgs.contains(p) {
            vanished.push(p.clone());
        }
    }
    if !vanished.is_empty() {
        return Err(format!(
            "section(s) vanished for package(s) still in both locks: {}",
            vanished.join(", ")
        ));
    }
    let mut added = Vec::new();
    let mut removed = 0usize;
    for (p, keys) in &head {
        let Some(bkeys) = base.get(p) else {
            added.push(format!("{p} (new section)"));
            continue;
        };
        for (k, vals) in keys {
            match bkeys.get(k) {
                None => added.push(format!("{p}.{k}")),
                Some(bvals) => {
                    for v in vals {
                        if !bvals.contains(v) {
                            added.push(format!("{p}.{k} += {v}"));
                        }
                    }
                }
            }
        }
        for (k, bvals) in bkeys {
            match keys.get(k) {
                None => removed += bvals.len(),
                Some(vals) => removed += bvals.difference(vals).count(),
            }
        }
    }
    if !added.is_empty() {
        return Err(format!("additions present: {}", added.join(", ")));
    }
    Ok(format!(
        "measured strict subset of the prior inventory: {} section(s), {removed} grant/flag value(s) \
         removed, 0 added; instrument identical; cackle exit 0 on lock {}…",
        head.len(),
        &head_lock_sha256[..12.min(head_lock_sha256.len())]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCK: &str = "0b4722fc28204aa400d280b53842c69001ff4683b3f1380e09275a8a9456abea";
    fn hdr(exit: &str, sha: &str) -> String {
        format!(
            "# caps evidence — cackle-generated inventory\n# subject: t @ r; frozen tools/locks/t.lock sha256 {sha}\n# seed: x; cackle exit {exit}; pkg sections seed 2 -> measured 2\n"
        )
    }
    const INSTRUMENT: &str = "[common]\nversion = 2\n\n[sandbox]\nkind = \"Disabled\"\n\n[api.net]\ninclude = [\"std::net\"]\n\n";
    const BASE_PKGS: &str = "[pkg.a]\nallow_unsafe = true\nbuild.allow_apis = [\n    \"env\",\n    \"process\",\n]\n\n[pkg.b]\nallow_apis = [\"fs\"]\n";
    fn names(s: &[&str]) -> BTreeSet<String> {
        s.iter().map(|x| x.to_string()).collect()
    }
    fn base() -> String {
        format!("{}{INSTRUMENT}{BASE_PKGS}", hdr("0", LOCK))
    }

    #[test]
    fn identical_measured_inventory_is_a_subset() {
        let r = subset_allow(
            &base(),
            &base(),
            LOCK,
            &names(&["a", "b"]),
            &names(&["a", "b"]),
        );
        assert!(r.is_ok(), "{r:?}");
    }

    #[test]
    fn shrinking_a_grant_is_a_subset_and_counted() {
        let head = format!(
            "{}{INSTRUMENT}[pkg.a]\nallow_unsafe = true\n\n[pkg.b]\nallow_apis = [\"fs\"]\n",
            hdr("0", LOCK)
        );
        let r = subset_allow(
            &head,
            &base(),
            LOCK,
            &names(&["a", "b"]),
            &names(&["a", "b"]),
        )
        .unwrap();
        assert!(r.contains("2 grant/flag value(s) removed"), "{r}");
    }

    #[test]
    fn empty_partial_or_unproven_measurements_are_not_subsets() {
        let empty = format!("{}{INSTRUMENT}", hdr("0", LOCK));
        assert!(
            subset_allow(&empty, &base(), LOCK, &names(&["a"]), &names(&["a"]))
                .unwrap_err()
                .contains("empty")
        );
        let partial = format!("{}{INSTRUMENT}{BASE_PKGS}", hdr("101", LOCK));
        assert!(
            subset_allow(&partial, &base(), LOCK, &names(&["a"]), &names(&["a"]))
                .unwrap_err()
                .contains("exit 101")
        );
        let no_exit = format!(
            "# caps evidence\n# subject: t; frozen lock sha256 {LOCK}\n{INSTRUMENT}{BASE_PKGS}"
        );
        assert!(
            subset_allow(&no_exit, &base(), LOCK, &names(&["a"]), &names(&["a"]))
                .unwrap_err()
                .contains("no `cackle exit`")
        );
        let other_lock = format!("{}{INSTRUMENT}{BASE_PKGS}", hdr("0", &"ab".repeat(32)));
        assert!(
            subset_allow(&other_lock, &base(), LOCK, &names(&["a"]), &names(&["a"]))
                .unwrap_err()
                .contains("does not match")
        );
        let copied = format!(
            "# caps evidence — COPIED FORWARD from x\n{}{INSTRUMENT}{BASE_PKGS}",
            hdr("0", LOCK)
        );
        assert!(
            subset_allow(&copied, &base(), LOCK, &names(&["a"]), &names(&["a"]))
                .unwrap_err()
                .contains("COPIED FORWARD")
        );
    }

    #[test]
    fn vanished_section_is_a_gap_unless_the_package_left_the_lock() {
        let head = format!(
            "{}{INSTRUMENT}[pkg.a]\nallow_unsafe = true\n",
            hdr("0", LOCK)
        );
        // b still in both locks, its section is gone -> gap
        let r = subset_allow(
            &head,
            &base(),
            LOCK,
            &names(&["a", "b"]),
            &names(&["a", "b"]),
        );
        assert!(r.unwrap_err().contains("vanished"));
        // b left the head lock -> legitimate shrink
        let r = subset_allow(&head, &base(), LOCK, &names(&["a"]), &names(&["a", "b"]));
        assert!(r.is_ok(), "{r:?}");
    }

    #[test]
    fn any_addition_or_instrument_change_refuses() {
        let new_grant = format!(
            "{}{INSTRUMENT}{BASE_PKGS}\n[pkg.c]\nallow_apis = [\"fs\"]\n",
            hdr("0", LOCK)
        );
        assert!(
            subset_allow(
                &new_grant,
                &base(),
                LOCK,
                &names(&["a", "b", "c"]),
                &names(&["a", "b"])
            )
            .unwrap_err()
            .contains("c (new section)")
        );
        let widened = format!(
            "{}{INSTRUMENT}[pkg.a]\nallow_unsafe = true\nbuild.allow_apis = [\"env\", \"process\", \"net\"]\n\n[pkg.b]\nallow_apis = [\"fs\"]\n",
            hdr("0", LOCK)
        );
        assert!(
            subset_allow(
                &widened,
                &base(),
                LOCK,
                &names(&["a", "b"]),
                &names(&["a", "b"])
            )
            .unwrap_err()
            .contains("+= net")
        );
        let new_flag = format!(
            "{}{INSTRUMENT}[pkg.a]\nallow_unsafe = true\nallow_proc_macro = true\nbuild.allow_apis = [\"env\", \"process\"]\n\n[pkg.b]\nallow_apis = [\"fs\"]\n",
            hdr("0", LOCK)
        );
        assert!(
            subset_allow(
                &new_flag,
                &base(),
                LOCK,
                &names(&["a", "b"]),
                &names(&["a", "b"])
            )
            .unwrap_err()
            .contains("a.allow_proc_macro")
        );
        let instrument = format!(
            "{}[common]\nversion = 2\n\n[sandbox]\nkind = \"Disabled\"\n\n[api.net]\ninclude = [\"std::net\", \"mio::net\"]\n\n{BASE_PKGS}",
            hdr("0", LOCK)
        );
        assert!(
            subset_allow(
                &instrument,
                &base(),
                LOCK,
                &names(&["a", "b"]),
                &names(&["a", "b"])
            )
            .unwrap_err()
            .contains("instrument")
        );
    }

    #[test]
    fn header_parser_reads_the_caps_measure_format() {
        let h = header(&hdr("0", LOCK));
        assert_eq!(h.cackle_exit, Some(0));
        assert_eq!(h.lock_sha256.as_deref(), Some(LOCK));
        assert!(!h.copied_forward);
        assert_eq!(header("[pkg.a]\n"), MeasurementHeader::default());
    }
    #[test]
    fn build_dir_paths_compare_equal_across_layout_profile_and_hash() {
        let a =
            "cargo:rustc-link-search=native=/t/caps-build/cackle/build/ring-b94dacf97f7f4882/out";
        let b = "cargo:rustc-link-search=native=/t/caps-build/cackle-release/build/ring/0123456789abcdef/out";
        assert_eq!(normalize_build_dir(a), normalize_build_dir(b));
        assert_eq!(
            normalize_build_dir(b),
            "cargo:rustc-link-search=native=<build>/ring/HASH/out"
        );
        assert_eq!(
            normalize_build_dir("cargo:include=/t/x/build/aws-lc-sys-c48f62605a6075e3/out/include"),
            "cargo:include=<build>/aws-lc-sys/HASH/out/include"
        );
        assert_eq!(
            normalize_build_dir(
                "cargo:libcrypto_path=/t/y/build/aws-lc-sys/d604cf8917c70cbf/out/libaws_lc_0_47_0_crypto.a"
            ),
            "cargo:libcrypto_path=<build>/aws-lc-sys/HASH/out/libaws_lc_0_47_0_crypto.a"
        );
        // different packages must not collapse together
        assert_ne!(
            normalize_build_dir("cargo:root=/t/build/ring/0123456789abcdef/out"),
            normalize_build_dir("cargo:root=/t/build/zstd-sys/0123456789abcdef/out")
        );
        // not a build dir, or not a 16-hex hash: untouched
        for v in [
            "cargo:rustc-link-lib=static=zstd",
            "/t/build/ring-notahash/out",
            "/t/build/ring/notahash/out",
            "/registry/zstd-sys-2.1.2+zstd.1.5.7/zstd/lib",
        ] {
            assert_eq!(normalize_build_dir(v), v);
        }
    }

    #[test]
    fn head_with_both_layouts_is_still_a_subset_of_old_layout_base() {
        // cackle auto-accept appends the new spelling without pruning the old one.
        let base = format!(
            "{}{INSTRUMENT}[pkg.ring]
build.allow_build_instructions = [
    \"cargo:rustc-link-search=native=/t/build/ring-b94dacf97f7f4882/out\",
]
",
            hdr("0", LOCK)
        );
        let head = format!(
            "{}{INSTRUMENT}[pkg.ring]
build.allow_build_instructions = [
    \"cargo:rustc-link-search=native=/t/build/ring-b94dacf97f7f4882/out\",
    \"cargo:rustc-link-search=native=/t/build/ring/b94dacf97f7f4882/out\",
]
",
            hdr("0", LOCK)
        );
        let r = subset_allow(&head, &base, LOCK, &names(&["ring"]), &names(&["ring"]));
        assert!(r.is_ok(), "{r:?}");
    }
}
