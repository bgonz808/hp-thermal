//! `cargo xtask verify-hardening-flags` -- keep the two RUSTFLAGS sources from drifting.
//!
//! THE PROBLEM. Hardening flags are declared in TWO places, and cargo does not merge them:
//!
//!   * `app/.cargo/config.toml` -> builds `hp-thermal.exe`
//!   * the `RUSTFLAGS` env in `.github/workflows/build-tools.yml` -> builds the five PE tools
//!
//! The `RUSTFLAGS` environment variable REPLACES `.cargo/config.toml` rustflags outright, and
//! the tool builds run outside `app/` so they never read that file at all. There is no
//! inheritance to rely on: a flag added to one is simply absent from the other.
//!
//! WHY NOT ONE FILE. The two sets legitimately differ, and collapsing them would be worse
//! than the duplication:
//!
//!   * `+crt-static` is app-only ON PURPOSE. A static CRT stops inheriting Microsoft's CRT
//!     security fixes; the app accepts that for self-containment, while the tools run on
//!     ephemeral runners whose CRT is patched by the image and therefore get those fixes free.
//!   * `-Z stack-protector` and `-Z deny-partial-mitigations` require `build-std`, which the
//!     app uses and the tools do not.
//!   * `/STACK` and `/Brepro` are app-specific (stack sizing, reproducible link).
//!
//! So the invariant is not "identical" but "the COMMON set appears in both". This checks
//! exactly that, and says nothing about the deliberate differences.
//!
//! Substring matching over non-comment lines rather than a TOML/YAML parse: xtask carries one
//! dependency by design, and the question here is only presence. A commented-out flag is
//! excluded, which is the one false-positive that would actually matter.

use std::path::Path;

/// Flags that MUST be present wherever we compile a shipped Windows binary, whether that is
/// the product or a build tool. Each is either free or nearly free, and each defends
/// something both artifact classes are exposed to.
const COMMON_HARDENING: &[(&str, &str)] = &[
    (
        "control-flow-guard=checks",
        "forward-edge CFI: constrains indirect calls",
    ),
    (
        "link-arg=/DEPENDENTLOADFLAG:0x800",
        "resolve static imports from System32 only -- matters MORE for tools, which run from writable CI directories",
    ),
    (
        "link-arg=/CETCOMPAT",
        "backward-edge CFI: opts into the hardware shadow stack, the ROP defence CFG does not provide",
    ),
];

/// The two declaration sites. Adding a third build path means adding it here, which is the
/// point: the check should fail for an unregistered site rather than silently ignore it.
const SOURCES: &[(&str, &str)] = &[
    ("app/.cargo/config.toml", "hp-thermal.exe"),
    (".github/workflows/build-tools.yml", "the five PE build tools"),
];

/// Non-comment content of a file, so a flag that is merely *mentioned* in a comment does not
/// count as declared. Handles both `#` (TOML, YAML) styles.
fn effective_text(raw: &str) -> String {
    raw.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn run(_args: &[String]) -> i32 {
    println!("# common hardening flags must appear in EVERY windows build path");
    let mut missing = 0;
    let mut unreadable = 0;

    for (path, what) in SOURCES {
        let raw = match std::fs::read_to_string(Path::new(path)) {
            Ok(t) => t,
            Err(e) => {
                // Fail-closed: a source we cannot read is not a source we can call compliant.
                println!("  {path}: UNREADABLE ({e})");
                unreadable += 1;
                continue;
            }
        };
        let text = effective_text(&raw);
        let mut absent = Vec::new();
        for (flag, _why) in COMMON_HARDENING {
            if !text.contains(flag) {
                absent.push(*flag);
            }
        }
        if absent.is_empty() {
            println!("  {path}  ({what}): all {} common flags present", COMMON_HARDENING.len());
        } else {
            println!("  {path}  ({what}): MISSING {absent:?}");
            for f in &absent {
                if let Some((_, why)) = COMMON_HARDENING.iter().find(|(n, _)| n == f) {
                    println!("      {f} -- {why}");
                }
            }
            missing += absent.len();
        }
    }

    if missing > 0 || unreadable > 0 {
        eprintln!(
            "verify-hardening-flags: {missing} missing, {unreadable} unreadable. \
             RUSTFLAGS does not merge with .cargo/config.toml, and the tool builds never read \
             app/.cargo/config.toml -- a flag added to one place is simply absent from the other."
        );
        return 1;
    }
    println!("# both build paths carry the common set");
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_flag_only_in_a_comment_does_not_count() {
        // The failure this guards: someone documents a flag, believes it is applied, and the
        // check agrees with them.
        let raw = "# we should add -C link-arg=/CETCOMPAT one day\nrustflags = []\n";
        assert!(!effective_text(raw).contains("link-arg=/CETCOMPAT"));
    }

    #[test]
    fn a_declared_flag_counts() {
        let raw = "rustflags = [\n  \"-C\",\n  \"link-arg=/CETCOMPAT\",\n]\n";
        assert!(effective_text(raw).contains("link-arg=/CETCOMPAT"));
    }

    #[test]
    fn indented_comments_are_stripped_too() {
        let raw = "    # -C control-flow-guard=checks\nother = 1\n";
        assert!(!effective_text(raw).contains("control-flow-guard=checks"));
    }

    #[test]
    fn the_real_sources_satisfy_the_invariant() {
        // Runs against the actual repo files, so this test IS the regression guard: adding a
        // common flag to one site and forgetting the other fails here, not in a release.
        for (path, _) in SOURCES {
            let p = std::path::Path::new("..").join(path);
            let raw = match std::fs::read_to_string(&p) {
                Ok(t) => t,
                // Tests may run from a different root; skip rather than fail spuriously. The
                // CI invocation of `run()` is the authoritative check.
                Err(_) => continue,
            };
            let text = effective_text(&raw);
            for (flag, why) in COMMON_HARDENING {
                assert!(
                    text.contains(flag),
                    "{path} is missing the common hardening flag {flag} ({why})"
                );
            }
        }
    }
}
