//! `cargo xtask verify-hardening-flags` -- keep the RUSTFLAGS declaration sites from drifting.
//!
//! THE PROBLEM. Hardening flags are declared in more than one place, and cargo does not merge
//! them: the `RUSTFLAGS` environment variable REPLACES `.cargo/config.toml` rustflags outright,
//! and the tool builds run outside `app/` so they never read that file at all. A flag added to
//! one site is simply absent from the other.
//!
//! THE POLICY. `supply-chain/policy/hardening.json` is the single list: a `common` set that
//! MUST appear in every registered build path, and per-path `extra` flags that MUST appear in
//! that path (the sets legitimately differ: `+crt-static`, `-Z stack-protector` and
//! `deny-partial-mitigations` need build-std, which the app uses and the tools do not; `/STACK`
//! and `/Brepro` are app-specific). This check reads the policy and verifies presence; it
//! carries no flag list of its own, so the policy file is the only place a flag is named.
//!
//! Fail-closed: a missing or malformed policy, an unreadable build path, or an absent flag is a
//! failure. Substring matching over non-comment lines rather than a TOML/YAML parse: the
//! question is only presence, and a commented-out flag is excluded, which is the one
//! false-positive that would actually matter.

use std::path::Path;

use serde_json::Value;

pub(crate) const POLICY: &str = "supply-chain/policy/hardening.json";

/// One build path and the flags it must carry (common + its own extras).
pub(crate) struct Site {
    pub(crate) path: String,
    pub(crate) what: String,
    /// `(flag, why)`
    pub(crate) required: Vec<(String, String)>,
}

/// Parse the policy into per-path requirement lists. Refuses an empty common set, a path
/// without `path`, or a flag entry without `flag`/`why`: a policy that cannot be read whole is
/// not a policy to enforce partially.
pub(crate) fn sites(policy: &str) -> Result<Vec<Site>, String> {
    let v: Value = serde_json::from_str(policy).map_err(|e| format!("{POLICY}: {e}"))?;
    if v["schema"] != "hp-thermal/hardening-policy/v1" {
        return Err(format!("{POLICY}: unexpected schema {}", v["schema"]));
    }
    let flags = |arr: &Value, where_: &str| -> Result<Vec<(String, String)>, String> {
        let mut out = Vec::new();
        for e in arr
            .as_array()
            .ok_or_else(|| format!("{POLICY}: {where_} is not an array"))?
        {
            let (Some(f), Some(w)) = (e["flag"].as_str(), e["why"].as_str()) else {
                return Err(format!("{POLICY}: {where_}: entry lacks `flag`/`why`"));
            };
            if f.trim().is_empty() {
                return Err(format!("{POLICY}: {where_}: empty flag"));
            }
            out.push((f.to_string(), w.to_string()));
        }
        Ok(out)
    };
    let common = flags(&v["common"], "common")?;
    if common.is_empty() {
        return Err(format!(
            "{POLICY}: `common` is empty -- nothing would be enforced"
        ));
    }
    let mut out = Vec::new();
    for p in v["paths"]
        .as_array()
        .ok_or_else(|| format!("{POLICY}: `paths` is not an array"))?
    {
        let path = p["path"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| format!("{POLICY}: path entry lacks `path`"))?;
        let what = p["what"].as_str().unwrap_or(path);
        let mut required = common.clone();
        required.extend(flags(&p["extra"], &format!("paths[{path}].extra"))?);
        out.push(Site {
            path: path.to_string(),
            what: what.to_string(),
            required,
        });
    }
    if out.is_empty() {
        return Err(format!(
            "{POLICY}: `paths` is empty -- nothing would be checked"
        ));
    }
    Ok(out)
}

/// Non-comment content of a file, so a flag that is merely *mentioned* in a comment does not
/// count as declared. Handles `#` (TOML, YAML).
pub(crate) fn effective_text(raw: &str) -> String {
    raw.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Flags from `site.required` absent from `text`.
pub(crate) fn absent<'a>(site: &'a Site, text: &str) -> Vec<&'a (String, String)> {
    site.required
        .iter()
        .filter(|(f, _)| !text.contains(f.as_str()))
        .collect()
}

pub fn run(_args: &[String]) -> i32 {
    println!(
        "# hardening flags per {POLICY}: the common set in every windows build path, plus each path's extras"
    );
    let policy = match std::fs::read_to_string(POLICY) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("verify-hardening-flags: cannot read {POLICY}: {e} (no policy = fail)");
            return 1;
        }
    };
    let sites = match sites(&policy) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("verify-hardening-flags: {e}");
            return 1;
        }
    };
    let mut missing = 0;
    let mut unreadable = 0;
    for site in &sites {
        let raw = match std::fs::read_to_string(Path::new(&site.path)) {
            Ok(t) => t,
            Err(e) => {
                // Fail-closed: a source we cannot read is not a source we can call compliant.
                println!("  {}: UNREADABLE ({e})", site.path);
                unreadable += 1;
                continue;
            }
        };
        let text = effective_text(&raw);
        let gone = absent(site, &text);
        if gone.is_empty() {
            println!(
                "  {}  ({}): all {} required flags present",
                site.path,
                site.what,
                site.required.len()
            );
        } else {
            println!(
                "  {}  ({}): MISSING {:?}",
                site.path,
                site.what,
                gone.iter().map(|(f, _)| f.as_str()).collect::<Vec<_>>()
            );
            for (f, why) in &gone {
                println!("      {f} -- {why}");
            }
            missing += gone.len();
        }
    }
    if missing > 0 || unreadable > 0 {
        eprintln!(
            "verify-hardening-flags: {missing} missing, {unreadable} unreadable. RUSTFLAGS does not merge \
             with .cargo/config.toml, and the tool builds never read app/.cargo/config.toml -- a flag \
             added to one place is simply absent from the other."
        );
        return 1;
    }
    println!("# every registered build path carries its required set");
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY_OK: &str = r#"{"schema":"hp-thermal/hardening-policy/v1",
        "common":[{"flag":"link-arg=/CETCOMPAT","why":"cet"}],
        "paths":[{"path":"a.toml","what":"a","extra":[{"flag":"link-arg=/Brepro","why":"repro"}]},
                 {"path":"b.yml","what":"b","extra":[]}]}"#;

    #[test]
    fn policy_parses_into_common_plus_extras_per_path() {
        let s = sites(POLICY_OK).unwrap();
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].required.len(), 2, "common + one extra");
        assert_eq!(s[1].required.len(), 1, "common only");
    }

    #[test]
    fn policy_refuses_empty_or_malformed_shapes() {
        assert!(
            sites(
                r#"{"schema":"hp-thermal/hardening-policy/v1","common":[],"paths":[{"path":"a"}]}"#
            )
            .is_err(),
            "empty common"
        );
        assert!(sites(r#"{"schema":"hp-thermal/hardening-policy/v1","common":[{"flag":"x","why":"y"}],"paths":[]}"#).is_err(), "no paths");
        assert!(
            sites(r#"{"schema":"other","common":[{"flag":"x","why":"y"}],"paths":[{"path":"a"}]}"#)
                .is_err(),
            "schema"
        );
        assert!(sites(r#"{"schema":"hp-thermal/hardening-policy/v1","common":[{"flag":"x"}],"paths":[{"path":"a"}]}"#).is_err(), "flag without why");
        assert!(sites("not json").is_err());
    }

    #[test]
    fn a_flag_only_in_a_comment_does_not_count() {
        let raw = "# we should add -C link-arg=/CETCOMPAT one day\nrustflags = []\n";
        assert!(!effective_text(raw).contains("link-arg=/CETCOMPAT"));
        let s = sites(POLICY_OK).unwrap();
        assert_eq!(absent(&s[1], &effective_text(raw)).len(), 1);
    }

    #[test]
    fn a_declared_flag_counts_and_extras_are_per_path() {
        let s = sites(POLICY_OK).unwrap();
        let text = effective_text("rustflags = [\n  \"-C\",\n  \"link-arg=/CETCOMPAT\",\n]\n");
        assert!(
            absent(&s[1], &text).is_empty(),
            "b needs only the common flag"
        );
        assert_eq!(absent(&s[0], &text).len(), 1, "a also needs /Brepro");
    }

    #[test]
    fn the_real_policy_and_sources_satisfy_the_invariant() {
        // Runs against the actual repo files, so this test IS the regression guard: adding a flag
        // to the policy and forgetting a site fails here, not in a release.
        let root = std::path::Path::new("..");
        let Ok(policy) = std::fs::read_to_string(root.join(POLICY)) else {
            return; // tests may run from another root; the CI invocation of `run()` is authoritative
        };
        let s = sites(&policy).expect("committed policy parses");
        for site in &s {
            let Ok(raw) = std::fs::read_to_string(root.join(&site.path)) else {
                continue;
            };
            let text = effective_text(&raw);
            let gone = absent(site, &text);
            assert!(gone.is_empty(), "{} is missing {:?}", site.path, gone);
        }
    }
}
