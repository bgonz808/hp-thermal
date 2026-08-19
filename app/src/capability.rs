//! Thermal-control capability ladder + per-process cache (#149).
//!
//! Two tiers that check whether the tool can drive the HP BIOS thermal interface (over WMI) on
//! THIS hardware — the quality check `KNOWN_GOOD` uses when accepting a fingerprint:
//!   1. READ  — a `CMD_READ_THERMAL` that returns OK. The interface answers. Non-invasive.
//!   2. WRITE — read the current mode, switch to a different mode, confirm the read-back, then
//!      restore the original and confirm that too. The interface ACCEPTS a write. This is the
//!      command path working — NOT proof the fan physically actuated (that's a human/RPM effect
//!      check, deliberately out of scope so the app takes no extra capability).
//!
//! The write probe leverages the consent the user already gave by installing + running thermal
//! control on their HP hardware (the canonical onboarding flow) — toggling a mode IS the tool's
//! function — and is minimally invasive: a brief switch to another mode at similar fan noise,
//! immediately restored. Results are cached
//! write-through per process, so a proven tier never re-probes (and the fan is never re-nudged).
//! A failed WRITE is also cached, so an explicit "show" action can't re-perturb on every click.

use std::sync::atomic::{AtomicU8, Ordering};

use crate::hwinfo::HwInfo;
use crate::mode::ThermalMode;
use crate::protocol::{
    BUILD_FINGERPRINT, CMD_READ_BUILD_ID, CMD_READ_THERMAL, CMD_SET_THERMAL, status_ok,
};

const UNTESTED: u8 = 0;
const OK: u8 = 1;
const FAILED: u8 = 2;

// Process-lifetime cache. READ caches only success (re-probing a failed read is free and lets a
// late-starting service recover); WRITE caches both outcomes (a failed write must NOT re-toggle
// the fan on every attempt, and a proven write never needs repeating).
static READ: AtomicU8 = AtomicU8::new(UNTESTED);
static WRITE: AtomicU8 = AtomicU8::new(UNTESTED);

/// Verdict 1: a thermal READ succeeds. Non-invasive. Caches only success.
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

/// The service must be the SAME build before we WRITE (#183): across versions the opcode/payload
/// semantics could differ, so a write might not mean what we intend. Client-side check (co-location
/// already handles malice; this guards accidental skew). READS are safe across versions and are NOT
/// gated. Full tray/protocol skew handling is deferred to #183.
pub fn build_matches<F: Fn(u8, u8) -> Option<[u8; 2]>>(transact: &F) -> bool {
    matches!(transact(CMD_READ_BUILD_ID, 0), Some(fp) if fp == BUILD_FINGERPRINT)
}

/// Verdict 2: a WRITE is accepted (read-back matches) and restores cleanly — the `KNOWN_GOOD` gate. Runs only if the read
/// tier passed AND the service is the same build (#183) — a skew skips the write entirely. Minimally
/// invasive: nudges one mode step and always restores the original, verifying each step.
pub fn write_ok<F: Fn(u8, u8) -> Option<[u8; 2]>>(transact: &F) -> bool {
    match WRITE.load(Ordering::Acquire) {
        OK => return true,
        FAILED => return false,
        _ => {}
    }
    // No read / a build skew: skip the write WITHOUT caching, so a late service or a post-update
    // restart can recover this session (the write outcome is cached only once we actually probe).
    if !read_ok(transact) || !build_matches(transact) {
        return false;
    }
    let proven = probe_write(transact);
    WRITE.store(if proven { OK } else { FAILED }, Ordering::Release);
    proven
}

/// The invasive-but-restored write probe. Assumes the read tier already passed.
fn probe_write<F: Fn(u8, u8) -> Option<[u8; 2]>>(transact: &F) -> bool {
    let Some(cur) = transact(CMD_READ_THERMAL, 0).filter(|r| status_ok(r[0])) else {
        return false;
    };
    let orig = ThermalMode::from_u8(cur[1]);
    // A different mode at roughly the same fan noise, so the read-back proves the write WITHOUT an
    // audible fan ramp. (Crossing the loud/quiet band for an audible-confirmation probe is #188.)
    let other = orig.same_band_partner();

    // Switch to the other mode and confirm it actually took.
    let set_ok = matches!(transact(CMD_SET_THERMAL, other.as_u8()), Some(r) if status_ok(r[0]));
    let took = matches!(
        transact(CMD_READ_THERMAL, 0),
        Some(r) if status_ok(r[0]) && ThermalMode::from_u8(r[1]) == other
    );

    // ALWAYS restore the original (even if the confirm above failed), then verify the restore.
    let restore_ok = matches!(transact(CMD_SET_THERMAL, orig.as_u8()), Some(r) if status_ok(r[0]));
    let restored = matches!(
        transact(CMD_READ_THERMAL, 0),
        Some(r) if status_ok(r[0]) && ThermalMode::from_u8(r[1]) == orig
    );

    set_ok && took && restore_ok && restored
}

/// The capability verdict for the current hardware. Only [`Verdict::Verified`] (interface read +
/// write confirmed) is safe to contribute to `KNOWN_GOOD`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verdict {
    /// The interface answered a read AND accepted a write (read-back matched), then restored
    /// cleanly. Submittable.
    Verified,
    /// The interface answers a read, but the service is a DIFFERENT build, so the write test was
    /// skipped for safety (#183). Reads are fine; the write is unconfirmed.
    Skew,
    /// The interface answers a read, but the write test failed.
    ReadOnly,
    /// No successful thermal read (service down, or unsupported hardware).
    Unverified,
    /// This binary is not the installed copy, so the service pipe would reject it (co-location
    /// check, #159). The ladder is skipped entirely; run the installed copy to verify.
    NotInstalled,
}

/// Run the full ladder and report the verdict reached. The single flow shared by the CLI
/// (`--hwinfo`) and the tray dialog, so both classify identically.
pub fn verdict<F: Fn(u8, u8) -> Option<[u8; 2]>>(transact: &F) -> Verdict {
    if !read_ok(transact) {
        Verdict::Unverified
    } else if !build_matches(transact) {
        Verdict::Skew
    } else if write_ok(transact) {
        Verdict::Verified
    } else {
        Verdict::ReadOnly
    }
}

/// Human-readable hardware report shared by the CLI and the tray dialog (#149). `build` is the
/// provenance telltale that chains a submission to the exact build that produced this report.
pub fn report(hw: &HwInfo, verdict: Verdict, build: &str) -> String {
    let bin = crate::app::BIN_NAME;
    // Identity + fingerprint block, common to every verdict. ASCII only so the dialog font renders
    // it cleanly; labels are un-padded so a proportional font doesn't misalign columns.
    let head = format!(
        "{bin} {build}\n\
         \n\
         Manufacturer: {mfg}\n\
         Product: {product}\n\
         Family: {family}\n\
         Board: {board}\n\
         BIOS: {bios}\n\
         Board version: {bver}\n\
         \n\
         KNOWN_GOOD line:\n  {fp}\n\
         \n\
         HP hardware: {hp}\n",
        mfg = hw.manufacturer,
        product = hw.product,
        family = hw.family,
        board = hw.board,
        bios = hw.bios_version,
        bver = hw.board_version,
        fp = hw.fingerprint(),
        hp = if hw.is_hp() { "yes" } else { "no" },
    );

    // Not the installed copy: NOTHING was tested, so don't fake a "Thermal control:" verdict. Only
    // point at the installed copy if it actually exists on disk — otherwise the tool isn't installed.
    if verdict == Verdict::NotInstalled {
        let installed = crate::app::installed_exe();
        let tail = if std::path::Path::new(&installed).exists() {
            // Quote the path if it contains a space (it does — "Program Files"), so it pastes and
            // runs as one argument instead of the shell splitting it.
            let cmd = if installed.contains(' ') {
                format!("\"{installed}\"")
            } else {
                installed.clone()
            };
            format!(
                "This copy is not the installed binary, so thermal control was not checked.\n\
                 Run the installed copy to verify:\n  {cmd} --hwinfo"
            )
        } else {
            "This tool is not installed, so thermal control was not checked. Install it first, then \
             run it to verify."
                .to_string()
        };
        return format!("{head}\n{tail}\n");
    }

    // Name the mechanism (the HP BIOS thermal interface over WMI) so the verdict is meaningful.
    let status = match verdict {
        Verdict::Verified => {
            "VERIFIED - read + write to the HP BIOS thermal interface (WMI) confirmed"
        }
        Verdict::Skew => {
            "SKEW - service is a different build; write skipped for safety (HP BIOS read OK)"
        }
        Verdict::ReadOnly => {
            "READ-ONLY - HP BIOS thermal interface reads, but the write test failed"
        }
        Verdict::Unverified => {
            "UNVERIFIED - no read from the HP BIOS thermal interface (service down or unsupported)"
        }
        Verdict::NotInstalled => unreachable!("handled by the early return above"),
    };
    let footer = match verdict {
        Verdict::Verified => {
            "To contribute: open an issue `hardware: <model>`, paste the KNOWN_GOOD line above, and\n\
             include the 'Verified by' line so it chains to this build."
        }
        Verdict::Skew => {
            "Not submittable: this binary and the running service are different builds, so the\n\
             write-test was skipped. Reinstall/restart so both match, then re-run."
        }
        Verdict::ReadOnly | Verdict::Unverified => {
            "Not submittable: read + write to the HP BIOS thermal interface could not be confirmed\n\
             (see status above), so it isn't confirmed working. Please don't submit it to KNOWN_GOOD."
        }
        Verdict::NotInstalled => unreachable!("handled by the early return above"),
    };
    format!(
        "{head}\
         Thermal control: {status}\n\
         Verified by: {bin} {build}\n\
         \n\
         {footer}\n"
    )
}

/// Machine-readable report (`--hwinfo --json`). Hand-rolled (no serde dep); fields are escaped.
pub fn report_json(hw: &HwInfo, verdict: Verdict, build: &str) -> String {
    let verdict_str = match verdict {
        Verdict::Verified => "verified",
        Verdict::Skew => "skew",
        Verdict::ReadOnly => "read-only",
        Verdict::Unverified => "unverified",
        Verdict::NotInstalled => "not-installed",
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
        verdict_str,
        verdict == Verdict::Verified,
        e(crate::app::BIN_NAME),
        e(build),
    )
}

/// Version+build provenance string ("0.3.1+140.abc") — chains a report to the exact build.
fn build_id() -> String {
    format!("{}+{}", env!("CARGO_PKG_VERSION"), env!("BUILD_ID"))
}

/// End-to-end hardware report: read identity, run the ladder over the real service pipe, format.
/// The SINGLE entry both `--hwinfo` and the tray dialog call, so their output is identical by
/// construction — no near-duplicate read/verdict/format glue on either side (#149).
pub fn hardware_report() -> String {
    report(&HwInfo::read(), current_verdict(), &build_id())
}

/// Machine-readable variant of [`hardware_report`] (`--hwinfo --json`).
pub fn hardware_report_json() -> String {
    report_json(&HwInfo::read(), current_verdict(), &build_id())
}

/// The verdict for the real machine. Short-circuits to [`Verdict::NotInstalled`] when this binary
/// isn't the installed copy: the service pipe would reject it anyway (#159), so skip the ladder
/// and the pipe call entirely and point the user at the installed copy.
fn current_verdict() -> Verdict {
    if !crate::install::is_installed_copy() {
        return Verdict::NotInstalled;
    }
    let transact = |cmd, payload| crate::pipe::client_transact(cmd, payload);
    verdict(&transact)
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

    /// Mock service: a current mode, which ops succeed, and the build fingerprint it reports, so
    /// the ladder (incl. the #183 build-parity write gate) runs without a real service. `up=false`
    /// models a dead service (nothing responds). Reads/writes mutate `mode` like the real EC.
    struct MockEc {
        mode: Cell<u8>,
        up: bool,
        read_ok: bool,
        write_ok: bool,
        build: [u8; 2],
    }
    impl MockEc {
        fn transact(&self) -> impl Fn(u8, u8) -> Option<[u8; 2]> + '_ {
            move |cmd, payload| {
                if !self.up {
                    return None;
                }
                match cmd {
                    CMD_READ_BUILD_ID => Some(self.build),
                    CMD_READ_THERMAL if self.read_ok => Some([0, self.mode.get()]),
                    CMD_SET_THERMAL if self.write_ok => {
                        self.mode.set(payload & 0x03);
                        Some([0, 0])
                    }
                    _ => None, // no response == failure
                }
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
            up: true,
            read_ok: true,
            write_ok: false,
            build: BUILD_FINGERPRINT,
        };
        let t = ec.transact();
        assert!(read_ok(&t), "read must pass");
        assert!(!write_ok(&t), "write must fail on read-only hardware");
        assert_eq!(ec.mode.get(), 1, "a failed write leaves the mode untouched");
        assert_eq!(verdict(&t), Verdict::ReadOnly);
    }

    #[test]
    fn full_control_proves_write_and_restores_original() {
        reset();
        let ec = MockEc {
            mode: Cell::new(2),
            up: true,
            read_ok: true,
            write_ok: true,
            build: BUILD_FINGERPRINT,
        };
        let t = ec.transact();
        assert!(write_ok(&t), "write must pass on controllable hardware");
        assert_eq!(verdict(&t), Verdict::Verified);
        assert_eq!(
            ec.mode.get(),
            2,
            "the write probe must restore the original mode"
        );
    }

    // Complements the loud-band case above: a quiet-band start (PowerSaver) probes its same-band
    // partner (Balanced) and restores. Exercises the `else`/quiet branch of same_band_partner.
    #[test]
    fn full_control_quiet_band_restores_original() {
        reset();
        let ec = MockEc {
            mode: Cell::new(3), // PowerSaver (quiet); partner is Balanced, also quiet
            up: true,
            read_ok: true,
            write_ok: true,
            build: BUILD_FINGERPRINT,
        };
        let t = ec.transact();
        assert!(write_ok(&t), "write must pass on controllable hardware");
        assert_eq!(verdict(&t), Verdict::Verified);
        assert_eq!(
            ec.mode.get(),
            3,
            "the write probe must restore the original mode"
        );
    }

    #[test]
    fn no_service_fails_every_tier() {
        reset();
        let ec = MockEc {
            mode: Cell::new(0),
            up: false,
            read_ok: false,
            write_ok: false,
            build: BUILD_FINGERPRINT,
        };
        let t = ec.transact();
        assert!(!read_ok(&t));
        assert!(!write_ok(&t));
        assert_eq!(verdict(&t), Verdict::Unverified);
    }

    // #183: a different-build service → reads fine, but the write-test is SKIPPED (mode untouched).
    #[test]
    fn build_skew_reads_but_skips_write() {
        reset();
        let ec = MockEc {
            mode: Cell::new(3),
            up: true,
            read_ok: true,
            write_ok: true, // the service COULD write, but we must not ask it to on a skew
            build: [BUILD_FINGERPRINT[0] ^ 0xFF, BUILD_FINGERPRINT[1]], // different build
        };
        let t = ec.transact();
        assert!(read_ok(&t), "reads are allowed across versions");
        assert!(!write_ok(&t), "writes must be skipped on a build skew");
        assert_eq!(ec.mode.get(), 3, "no write means the mode is untouched");
        assert_eq!(verdict(&t), Verdict::Skew);
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

    // A synthetic build string (NOT a real version): report() interpolates whatever `build` it's
    // given, so this asserts the formatting, and never goes stale as the real version advances.
    const FAKE_BUILD: &str = "x.y.z+test.deadbeef";

    // #149: only the write-proven tier is submittable; the KNOWN_GOOD line + provenance appear.
    #[test]
    fn report_gates_submission_on_write_proof() {
        let hw = sample_hw();
        let fp = hw.fingerprint();

        let ok = report(&hw, Verdict::Verified, FAKE_BUILD);
        assert!(ok.contains(&fp), "KNOWN_GOOD line present verbatim");
        assert!(ok.contains("VERIFIED"));
        assert!(ok.contains(&format!("Verified by: hp-thermal {FAKE_BUILD}")));
        assert!(ok.contains("To contribute"));
        assert!(!ok.contains("Not submittable"));

        for verdict in [Verdict::Skew, Verdict::ReadOnly, Verdict::Unverified] {
            let s = report(&hw, verdict, FAKE_BUILD);
            assert!(
                s.contains("Not submittable"),
                "non-verified must not be submittable"
            );
        }
        assert!(
            report(&hw, Verdict::Skew, FAKE_BUILD).contains("SKEW"),
            "skew must be surfaced"
        );
    }

    #[test]
    fn report_json_escapes_and_marks_submittable() {
        let mut hw = sample_hw();
        hw.product = "HP \"Quoty\" 16".into();
        let j = report_json(&hw, Verdict::Verified, FAKE_BUILD);
        assert!(j.contains("\\\"Quoty\\\""), "quotes must be JSON-escaped");
        assert!(j.contains("\"submittable\":true"));
        assert!(report_json(&hw, Verdict::ReadOnly, FAKE_BUILD).contains("\"submittable\":false"));
    }

    // A non-installed copy shows the fingerprint but does NOT fake a thermal-control verdict, and
    // is never submittable. (Whether it says "run the installed copy" vs "install it first" depends
    // on the real install state, so we only assert the invariants that hold either way.)
    #[test]
    fn not_installed_does_not_fake_a_thermal_verdict() {
        let hw = sample_hw();
        let r = report(&hw, Verdict::NotInstalled, FAKE_BUILD);
        assert!(r.contains(&hw.fingerprint()), "fingerprint still shown");
        assert!(
            !r.contains("Thermal control:"),
            "must not claim a thermal verdict"
        );
        assert!(
            r.to_lowercase().contains("install"),
            "must explain the install situation"
        );
        let j = report_json(&hw, Verdict::NotInstalled, FAKE_BUILD);
        assert!(j.contains("\"capability\":\"not-installed\""));
        assert!(j.contains("\"submittable\":false"));
    }
}
