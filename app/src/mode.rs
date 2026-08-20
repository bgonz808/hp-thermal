//! The four HP thermal modes — the single source of truth for the mode set.
//!
//! Discriminant == the wire byte carried by `CMD_SET_THERMAL` / `CMD_READ_THERMAL`
//! (0..=3 over WMI and the local pipe), so `as u8` IS the wire encoding and
//! [`ThermalMode::from_u8`] parses a read-back.
//!
//! Two string forms, deliberately distinct:
//!   - [`ThermalMode::name`] is the UX label ("Power Saver", with the space).
//!   - `{:?}` (Debug) is the internal identifier ("PowerSaver"), for logs/telemetry.
//!
//! Most mode-handling still passes raw `u8` (notably the noise-adapt engine in
//! `audio.rs`, where the mode is a stored calibration field); migrating those to
//! `ThermalMode` is tracked in #187.

/// An HP thermal mode. `#[repr(u8)]` pins each discriminant to its wire value.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum ThermalMode {
    Performance = 0,
    Balanced = 1,
    Cool = 2,
    PowerSaver = 3,
}

impl ThermalMode {
    /// Parse a wire byte. Masks to the valid 0..=3 range so a stray high bit can't
    /// smuggle an out-of-range mode.
    pub fn from_u8(v: u8) -> ThermalMode {
        match v & 0x03 {
            0 => ThermalMode::Performance,
            1 => ThermalMode::Balanced,
            2 => ThermalMode::Cool,
            _ => ThermalMode::PowerSaver,
        }
    }

    /// The wire byte for this mode.
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// UX label (note the space in "Power Saver"). For the internal identifier
    /// ("PowerSaver"), use `{:?}`.
    pub fn name(self) -> &'static str {
        match self {
            ThermalMode::Performance => "Performance",
            ThermalMode::Balanced => "Balanced",
            ThermalMode::Cool => "Cool",
            ThermalMode::PowerSaver => "Power Saver",
        }
    }

    /// Fan-noise band. Performance and Cool drive the fan harder; Balanced and
    /// PowerSaver run it quieter. The reusable band primitive: `same_band_partner`
    /// keeps the write probe WITHIN a band today, and the deferred audible-
    /// confirmation probe (#188) will use this to deliberately CROSS bands.
    /// Exercised by tests now; `allow(dead_code)` until the cross-band probe lands.
    #[allow(dead_code)]
    pub fn is_loud(self) -> bool {
        matches!(self, ThermalMode::Performance | ThermalMode::Cool)
    }

    /// A different mode at roughly the same fan noise: the other member of this
    /// mode's band. The write probe (`capability.rs`) switches here so the
    /// read-back proves the write without an audible fan ramp.
    pub fn same_band_partner(self) -> ThermalMode {
        match self {
            ThermalMode::Performance => ThermalMode::Cool,
            ThermalMode::Cool => ThermalMode::Performance,
            ThermalMode::Balanced => ThermalMode::PowerSaver,
            ThermalMode::PowerSaver => ThermalMode::Balanced,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ThermalMode::*;
    use super::*;

    #[test]
    fn wire_round_trips() {
        for (v, m) in [
            (0u8, Performance),
            (1, Balanced),
            (2, Cool),
            (3, PowerSaver),
        ] {
            assert_eq!(ThermalMode::from_u8(v), m);
            assert_eq!(m.as_u8(), v);
        }
    }

    #[test]
    fn from_u8_masks_stray_high_bits() {
        // Only the low two bits select the mode.
        assert_eq!(ThermalMode::from_u8(0xFC), Performance); // ...00
        assert_eq!(ThermalMode::from_u8(0xFF), PowerSaver); // ...11
    }

    #[test]
    fn same_band_partner_stays_in_band_and_differs() {
        for m in [Performance, Balanced, Cool, PowerSaver] {
            let p = m.same_band_partner();
            assert_ne!(p, m, "partner must differ from the original mode");
            assert_eq!(
                p.is_loud(),
                m.is_loud(),
                "partner must share the fan-noise band"
            );
        }
        // Exact pairing, pinned.
        assert_eq!(Performance.same_band_partner(), Cool);
        assert_eq!(Cool.same_band_partner(), Performance);
        assert_eq!(Balanced.same_band_partner(), PowerSaver);
        assert_eq!(PowerSaver.same_band_partner(), Balanced);
    }

    #[test]
    fn ux_name_has_space_internal_debug_does_not() {
        assert_eq!(PowerSaver.name(), "Power Saver");
        assert_eq!(format!("{PowerSaver:?}"), "PowerSaver");
    }
}
