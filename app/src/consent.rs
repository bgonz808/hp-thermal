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
//! firmware update re-triggers the prompt. It is stored per-user, unelevated, in
//! `HKCU\Software\HpThermal` — the user is the authority on accepting their own
//! machine's risk, so it belongs in their own hive, not a machine-wide
//! `Users:(M)` file any local user could forge for everyone (#88).

use crate::hwinfo::HwInfo;

/// HKCU location of the accepted-hardware-fingerprint value (REG_SZ). Per-user + user-owned.
const CONSENT_SUBKEY: windows::core::PCWSTR = windows::core::w!("Software\\HpThermal");
const CONSENT_VALUE: windows::core::PCWSTR = windows::core::w!("AcceptedHwFingerprint");

/// Hardware fingerprints the developers have validated CT76/CT44 on.
/// Format matches `HwInfo::fingerprint()`: `mfg|product|family|board|bios|ec`.
/// This is the seed of the dev support table; future entries can carry the
/// SystemControlFeature backend + capability set once that abstraction exists.
const KNOWN_GOOD: &[&str] = &[
    // Dev reference: HP ENVY 16-h1xxx, board 8BE5, BIOS F.25, EC 72.35.
    "HP|HP ENVY Laptop 16-h1xxx|103C_5335M8 HP ENVY|8BE5|F.25|72.35",
    // Same board + EC (72.35 unchanged), BIOS-only bump F.25 -> F.26. Maintainer-validated
    // on real hardware; the fingerprint was confirmed byte-exact against the live registry.
    "HP|HP ENVY Laptop 16-h1xxx|103C_5335M8 HP ENVY|8BE5|F.26|72.35",
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

/// Persist the user's acceptance of the current hardware fingerprint to HKCU (per-user,
/// unelevated). Best-effort: a write failure just means the prompt reappears next launch.
pub fn record_acceptance(hw: &HwInfo) {
    use windows::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey,
        RegCreateKeyExW, RegSetValueExW,
    };
    let data: Vec<u16> = hw
        .fingerprint()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: `data` is a null-terminated UTF-16 string; reinterpreted as bytes for the REG_SZ
    // write. `key` is closed before return. HKCU write needs no elevation.
    unsafe {
        let bytes = std::slice::from_raw_parts(data.as_ptr() as *const u8, data.len() * 2);
        let mut key = HKEY::default();
        let err = RegCreateKeyExW(
            HKEY_CURRENT_USER,
            CONSENT_SUBKEY,
            None,
            windows::core::PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            None,
            &mut key,
            None,
        );
        if err.is_err() {
            return;
        }
        let _ = RegSetValueExW(key, CONSENT_VALUE, None, REG_SZ, Some(bytes));
        let _ = RegCloseKey(key);
    }
}

/// True if this fingerprint is one the maintainers have already validated (it's in `KNOWN_GOOD`),
/// so the hardware is already covered and there is nothing to contribute.
pub fn is_known_good(fingerprint: &str) -> bool {
    KNOWN_GOOD.contains(&fingerprint)
}

/// Pure decision core (no I/O), so the trust logic is unit-testable.
fn classify(current: &str, accepted: Option<&str>) -> Consent {
    if is_known_good(current) {
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

/// Read the accepted fingerprint from HKCU (`None` if absent/empty/not a string).
fn read_accepted() -> Option<String> {
    use windows::Win32::System::Registry::{HKEY_CURRENT_USER, RRF_RT_REG_SZ, RegGetValueW};
    let mut buf = [0u16; 256]; // fingerprint is short (mfg|product|family|board|bios|ec)
    let mut len = (buf.len() * 2) as u32; // byte size, in/out
    // SAFETY: RegGetValueW writes up to `len` bytes into `buf` and updates `len`; RRF_RT_REG_SZ
    // restricts to a string value.
    let rc = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            CONSENT_SUBKEY,
            CONSENT_VALUE,
            RRF_RT_REG_SZ,
            None,
            Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
            Some(&mut len),
        )
    };
    if rc.is_err() {
        return None;
    }
    // `len` counts the trailing NUL (in bytes) — drop it.
    let n = (len as usize / 2).saturating_sub(1).min(buf.len());
    let s = String::from_utf16_lossy(&buf[..n]).trim().to_string();
    (!s.is_empty()).then_some(s)
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

    #[test]
    fn f26_bios_only_bump_is_known_good() {
        // The F.25 dev reference with a BIOS-only bump to F.26 (EC 72.35 unchanged) is
        // maintainer-validated and must run silently, no acceptance needed.
        const DEV_F26: &str = "HP|HP ENVY Laptop 16-h1xxx|103C_5335M8 HP ENVY|8BE5|F.26|72.35";
        assert_eq!(classify(DEV_F26, None), Consent::Trusted);
    }
}
