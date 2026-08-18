//! Thermal-control capability ladder + per-process cache (#149).
//!
//! Two tiers of proof that the tool actually controls THIS hardware — the property
//! `KNOWN_GOOD` certifies, and the gate for contributing a fingerprint:
//!   1. READ  — a `CMD_READ_THERMAL` that returns OK. Proves the WMI/BIOS interface answers.
//!      Non-invasive.
//!   2. WRITE — read the current mode, nudge it one valid step, confirm it took, then restore
//!      the original and confirm the restore. Proves actual CONTROL, not just a live interface.
//!
//! The write probe leverages the consent the user already gave by installing + running thermal
//! control on their HP hardware (the canonical onboarding flow) — toggling a mode IS the tool's
//! function — and is minimally invasive: one step, immediately restored. Results are cached
//! write-through per process, so a proven tier never re-probes (and the fan is never re-nudged).
//! A failed WRITE is also cached, so an explicit "show" action can't re-perturb on every click.

use std::sync::atomic::{AtomicU8, Ordering};

use crate::hwinfo::HwInfo;
use crate::protocol::{CMD_READ_THERMAL, CMD_SET_THERMAL, status_ok};

const UNTESTED: u8 = 0;
const OK: u8 = 1;
const FAILED: u8 = 2;

// Process-lifetime cache. READ caches only success (re-probing a failed read is free and lets a
// late-starting service recover); WRITE caches both outcomes (a failed write must NOT re-toggle
// the fan on every attempt, and a proven write never needs repeating).
static READ: AtomicU8 = AtomicU8::new(UNTESTED);
static WRITE: AtomicU8 = AtomicU8::new(UNTESTED);

/// Valid thermal modes are 0..=3; mask so a stray high bit can't smuggle an out-of-range write.
fn mode_of(resp: [u8; 2]) -> u8 {
    resp[1] & 0x03
}

/// Tier 1: a thermal READ succeeds. Non-invasive. Caches only success.
pub fn read_ok<F: Fn(u8, u8) -> Option<[u8; 2]>>(transact: &F) -> bool {
    if READ.load(Ordering::Acquire) == OK {
        return true;
    }
    let ok = matches!(transact(CMD_READ_THERMAL, 0), Some(r) if status_ok(r[0]));
    if ok {
        READ.store(OK, Ordering::Release);
    }
    ok
}

/// Tier 2: a WRITE takes effect and restores cleanly — the `KNOWN_GOOD` gate. Runs only if the
/// read tier passed; caches both outcomes (write-through). Minimally invasive: nudges one mode
/// step and always restores the original, verifying each step.
pub fn write_ok<F: Fn(u8, u8) -> Option<[u8; 2]>>(transact: &F) -> bool {
    match WRITE.load(Ordering::Acquire) {
        OK => return true,
        FAILED => return false,
        _ => {}
    }
    let proven = read_ok(transact) && probe_write(transact);
    WRITE.store(if proven { OK } else { FAILED }, Ordering::Release);
    proven
}

/// The invasive-but-restored write probe. Assumes the read tier already passed.
fn probe_write<F: Fn(u8, u8) -> Option<[u8; 2]>>(transact: &F) -> bool {
    let Some(cur) = transact(CMD_READ_THERMAL, 0).filter(|r| status_ok(r[0])) else {
        return false;
    };
    let orig = mode_of(cur);
    let other = if orig == 0 { 1 } else { 0 }; // any different valid mode; one step

    // Nudge to a different mode and confirm it actually took.
    let set_ok = matches!(transact(CMD_SET_THERMAL, other), Some(r) if status_ok(r[0]));
    let took =
        matches!(transact(CMD_READ_THERMAL, 0), Some(r) if status_ok(r[0]) && mode_of(r) == other);

    // ALWAYS restore the original (even if the confirm above failed), then verify the restore.
    let restore_ok = matches!(transact(CMD_SET_THERMAL, orig), Some(r) if status_ok(r[0]));
    let restored =
        matches!(transact(CMD_READ_THERMAL, 0), Some(r) if status_ok(r[0]) && mode_of(r) == orig);

    set_ok && took && restore_ok && restored
}

/// Capability tier reached for the current hardware. Only [`Tier::Verified`] (write-control
/// proven) is safe to contribute to `KNOWN_GOOD`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// A write took effect and restored cleanly — proven control. Submittable.
    Verified,
    /// The interface answers a read, but write-control was not proven (failed).
    ReadOnly,
    /// No successful thermal read (service down, or unsupported hardware).
    Unverified,
}

/// Run the full ladder and report the tier reached. The single flow shared by the CLI
/// (`--hwinfo`) and the tray dialog, so both classify identically.
pub fn tier<F: Fn(u8, u8) -> Option<[u8; 2]>>(transact: &F) -> Tier {
    if write_ok(transact) {
        Tier::Verified
    } else if read_ok(transact) {
        Tier::ReadOnly
    } else {
        Tier::Unverified
    }
}

/// Human-readable hardware report shared by the CLI and the tray dialog (#149). `build` is the
/// provenance telltale that chains a submission to the exact build that proved the hardware.
pub fn report(hw: &HwInfo, tier: Tier, build: &str) -> String {
    let bin = crate::app::BIN_NAME;
    let status = match tier {
        Tier::Verified => "VERIFIED — read + write/restore OK (control proven)",
        Tier::ReadOnly => "READ-ONLY — interface answers; write-control NOT proven",
        Tier::Unverified => "UNVERIFIED — no thermal read (service down or unsupported)",
    };
    let footer = if tier == Tier::Verified {
        "To contribute: open an issue `hardware: <model>`, paste the KNOWN_GOOD line above, and\n\
         include the 'Verified by' line so it chains to this build."
    } else {
        "Not submittable: write-control could not be proven on this hardware (see status above),\n\
         so it isn't confirmed working. Please don't submit it to KNOWN_GOOD."
    };
    format!(
        "{bin} {build}\n\
         \n\
         Manufacturer:  {mfg}\n\
         Product:       {product}\n\
         Family:        {family}\n\
         Board:         {board}\n\
         BIOS:          {bios}\n\
         Board version: {bver}\n\
         \n\
         KNOWN_GOOD line:\n  {fp}\n\
         \n\
         HP hardware:      {hp}\n\
         Thermal control:  {status}\n\
         Verified by:      {bin} {build}\n\
         \n\
         {footer}\n",
        mfg = hw.manufacturer,
        product = hw.product,
        family = hw.family,
        board = hw.board,
        bios = hw.bios_version,
        bver = hw.board_version,
        fp = hw.fingerprint(),
        hp = if hw.is_hp() { "yes" } else { "no" },
    )
}

/// Machine-readable report (`--hwinfo --json`). Hand-rolled (no serde dep); fields are escaped.
pub fn report_json(hw: &HwInfo, tier: Tier, build: &str) -> String {
    let tier_str = match tier {
        Tier::Verified => "verified",
        Tier::ReadOnly => "read-only",
        Tier::Unverified => "unverified",
    };
    let e = json_escape;
    format!(
        "{{\"fingerprint\":\"{}\",\"manufacturer\":\"{}\",\"product\":\"{}\",\"family\":\"{}\",\
         \"board\":\"{}\",\"bios\":\"{}\",\"board_version\":\"{}\",\"is_hp\":{},\
         \"capability\":\"{}\",\"submittable\":{},\"verified_by\":\"{} {}\"}}\n",
        e(&hw.fingerprint()),
        e(&hw.manufacturer),
        e(&hw.product),
        e(&hw.family),
        e(&hw.board),
        e(&hw.bios_version),
        e(&hw.board_version),
        hw.is_hp(),
        tier_str,
        tier == Tier::Verified,
        e(crate::app::BIN_NAME),
        e(build),
    )
}

/// Minimal JSON string escaper (quote + backslash + control chars) — enough for SMBIOS text.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// Mock service: holds a current mode and flags for which ops succeed, so the ladder can be
    /// exercised without a running service. Reads/writes mutate `mode` like the real EC.
    struct MockEc {
        mode: Cell<u8>,
        read_ok: bool,
        write_ok: bool,
    }
    impl MockEc {
        fn transact(&self) -> impl Fn(u8, u8) -> Option<[u8; 2]> + '_ {
            move |cmd, payload| match cmd {
                CMD_READ_THERMAL if self.read_ok => Some([0, self.mode.get()]),
                CMD_SET_THERMAL if self.write_ok => {
                    self.mode.set(payload & 0x03);
                    Some([0, 0])
                }
                _ => None, // no response == failure
            }
        }
    }

    fn reset() {
        READ.store(UNTESTED, Ordering::Release);
        WRITE.store(UNTESTED, Ordering::Release);
    }

    #[test]
    fn read_only_hardware_proves_read_but_not_write() {
        reset();
        let ec = MockEc {
            mode: Cell::new(1),
            read_ok: true,
            write_ok: false,
        };
        let t = ec.transact();
        assert!(read_ok(&t), "read must pass");
        assert!(!write_ok(&t), "write must fail on read-only hardware");
        assert_eq!(ec.mode.get(), 1, "a failed write leaves the mode untouched");
    }

    #[test]
    fn full_control_proves_write_and_restores_original() {
        reset();
        let ec = MockEc {
            mode: Cell::new(2),
            read_ok: true,
            write_ok: true,
        };
        let t = ec.transact();
        assert!(write_ok(&t), "write must pass on controllable hardware");
        assert_eq!(
            ec.mode.get(),
            2,
            "the write probe must restore the original mode"
        );
    }

    #[test]
    fn no_service_fails_every_tier() {
        reset();
        let ec = MockEc {
            mode: Cell::new(0),
            read_ok: false,
            write_ok: false,
        };
        let t = ec.transact();
        assert!(!read_ok(&t));
        assert!(!write_ok(&t));
    }

    fn sample_hw() -> HwInfo {
        HwInfo {
            manufacturer: "HP".into(),
            product: "HP ENVY 16".into(),
            board: "8BE5".into(),
            family: "103C_5335KV".into(),
            bios_version: "F.26".into(),
            board_version: "72.35".into(),
        }
    }

    // #149: only the write-proven tier is submittable; the KNOWN_GOOD line + provenance appear.
    #[test]
    fn report_gates_submission_on_write_proof() {
        let hw = sample_hw();
        let fp = hw.fingerprint();

        let ok = report(&hw, Tier::Verified, "0.3.1+140.abc");
        assert!(ok.contains(&fp), "KNOWN_GOOD line present verbatim");
        assert!(ok.contains("VERIFIED"));
        assert!(ok.contains("Verified by:      hp-thermal 0.3.1+140.abc"));
        assert!(ok.contains("To contribute"));
        assert!(!ok.contains("Not submittable"));

        for tier in [Tier::ReadOnly, Tier::Unverified] {
            let s = report(&hw, tier, "0.3.1+140.abc");
            assert!(
                s.contains("Not submittable"),
                "non-verified must not be submittable"
            );
        }
    }

    #[test]
    fn report_json_escapes_and_marks_submittable() {
        let mut hw = sample_hw();
        hw.product = "HP \"Quoty\" 16".into();
        let j = report_json(&hw, Tier::Verified, "0.3.1");
        assert!(j.contains("\\\"Quoty\\\""), "quotes must be JSON-escaped");
        assert!(j.contains("\"submittable\":true"));
        assert!(report_json(&hw, Tier::ReadOnly, "0.3.1").contains("\"submittable\":false"));
    }
}
