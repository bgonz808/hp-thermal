//! First-run consent gate for unvalidated hardware.
//!
//! The thermal mechanism (hpqBIOS CommandType 76) is an INTERNAL HP interface
//! with no public or stable contract: HP can change it across firmware, and it
//! is not even the same mechanism on every HP platform (SmartSensing/CT76 here,
//! DPTF or PerformanceControl elsewhere — per HP's own SystemControlFeature map).
//! So we only run silently on hardware a developer has validated, or that the
//! user has explicitly accepted the risk on.
//!
//! Acceptance is keyed to `HwInfo::fingerprint()` (board + BIOS + EC), so a
//! firmware update re-triggers the prompt. It is stored unelevated in a
//! ProgramData sibling file, matching the existing `fnkey` config pattern.

use crate::app;
use crate::hwinfo::HwInfo;

/// Hardware fingerprints the developers have validated CT76/CT44 on.
/// Format matches `HwInfo::fingerprint()`: `mfg|product|family|board|bios|ec`.
/// This is the seed of the dev support table; future entries can carry the
/// SystemControlFeature backend + capability set once that abstraction exists.
const KNOWN_GOOD: &[&str] = &[
    // Dev reference: HP ENVY 16-h1xxx, board 8BE5, BIOS F.25, EC 72.35.
    "HP|HP ENVY Laptop 16-h1xxx|103C_5335M8 HP ENVY|8BE5|F.25|72.35",
];

/// Outcome of the consent check.
#[derive(Debug, PartialEq, Eq)]
pub enum Consent {
    /// Dev-validated or previously user-accepted — proceed silently.
    Trusted,
    /// Unvalidated hardware; the caller should prompt. `firmware_changed` means
    /// the user previously accepted this same board/product but the firmware has
    /// since changed (softer "re-confirm" message vs. a brand-new machine).
    NeedsPrompt { firmware_changed: bool },
}

/// Decide whether the current hardware may run silently or needs a prompt.
pub fn check(hw: &HwInfo) -> Consent {
    classify(&hw.fingerprint(), read_accepted().as_deref())
}

/// Persist the user's acceptance of the current hardware fingerprint.
/// Unelevated write to ProgramData (same pattern as `fnkey` settings).
pub fn record_acceptance(hw: &HwInfo) {
    let _ = std::fs::create_dir_all(app::data_dir());
    let _ = std::fs::write(consent_path(), hw.fingerprint().as_bytes());
}

/// Pure decision core (no I/O), so the trust logic is unit-testable.
fn classify(current: &str, accepted: Option<&str>) -> Consent {
    if KNOWN_GOOD.contains(&current) {
        return Consent::Trusted;
    }
    match accepted {
        Some(a) if a == current => Consent::Trusted,
        Some(a) => Consent::NeedsPrompt {
            firmware_changed: same_machine(a, current),
        },
        None => Consent::NeedsPrompt {
            firmware_changed: false,
        },
    }
}

/// True if two fingerprints share board + product but differ elsewhere — i.e. a
/// firmware update on a machine the user already accepted, rather than a new one.
fn same_machine(a: &str, b: &str) -> bool {
    let fa: Vec<&str> = a.split('|').collect();
    let fb: Vec<&str> = b.split('|').collect();
    // fingerprint = mfg|product|family|board|bios|ec  → index 1 = product, 3 = board
    fa.len() == 6 && fb.len() == 6 && fa[3] == fb[3] && fa[1] == fb[1]
}

fn consent_path() -> String {
    format!("{}\\consent", app::data_dir())
}

fn read_accepted() -> Option<String> {
    std::fs::read_to_string(consent_path())
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEV: &str = "HP|HP ENVY Laptop 16-h1xxx|103C_5335M8 HP ENVY|8BE5|F.25|72.35";
    const OTHER: &str = "HP|HP Pavilion 15-eh|103C_ABCD HP Pavilion|8XYZ|A.01|10.20";

    #[test]
    fn known_good_is_trusted_without_any_acceptance() {
        assert_eq!(classify(DEV, None), Consent::Trusted);
    }

    #[test]
    fn unknown_board_with_no_acceptance_prompts_as_new() {
        assert_eq!(
            classify(OTHER, None),
            Consent::NeedsPrompt {
                firmware_changed: false
            }
        );
    }

    #[test]
    fn matching_prior_acceptance_is_trusted() {
        assert_eq!(classify(OTHER, Some(OTHER)), Consent::Trusted);
    }

    #[test]
    fn firmware_update_on_accepted_machine_reprompts_softly() {
        // Same board + product, BIOS bumped A.01 -> A.02.
        let after_bios = "HP|HP Pavilion 15-eh|103C_ABCD HP Pavilion|8XYZ|A.02|10.20";
        assert_eq!(
            classify(after_bios, Some(OTHER)),
            Consent::NeedsPrompt {
                firmware_changed: true
            }
        );
    }

    #[test]
    fn a_different_machine_prompts_as_new_even_with_prior_acceptance() {
        let different = "HP|HP Omen 17|103C_ZZZZ HP OMEN|9ABC|B.05|20.30";
        assert_eq!(
            classify(different, Some(OTHER)),
            Consent::NeedsPrompt {
                firmware_changed: false
            }
        );
    }

    #[test]
    fn known_good_wins_even_over_a_stale_acceptance_file() {
        // If somehow an old acceptance is present, dev-validated HW is still trusted.
        assert_eq!(classify(DEV, Some(OTHER)), Consent::Trusted);
    }
}
