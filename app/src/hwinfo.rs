use windows::core::w;
use windows::Win32::System::Registry::*;

/// Hardware info read from SMBIOS via registry (no elevation needed).
pub struct HwInfo {
    pub manufacturer: String,
    pub product: String,
    /// BaseBoardProduct — HP's own platform key (e.g. "8BE5"); the most precise
    /// identifier of the board + EC that thermal (CT76/CT44) behavior depends on.
    pub board: String,
    pub family: String,
    /// System BIOS version, e.g. "F.25".
    pub bios_version: String,
    /// BaseBoard version — tracks EC firmware, e.g. "72.35".
    pub board_version: String,
}

impl HwInfo {
    /// Read system identity from HKLM\HARDWARE\DESCRIPTION\System\BIOS.
    pub fn read() -> Self {
        Self {
            manufacturer: read_bios_value(w!("SystemManufacturer")),
            product: read_bios_value(w!("SystemProductName")),
            board: read_bios_value(w!("BaseBoardProduct")),
            family: read_bios_value(w!("SystemFamily")),
            bios_version: read_bios_value(w!("BIOSVersion")),
            board_version: read_bios_value(w!("BaseBoardVersion")),
        }
    }

    pub fn is_hp(&self) -> bool {
        let m = self.manufacturer.to_lowercase();
        m == "hp" || m.starts_with("hewlett")
    }

    /// Stable identity fingerprint for the thermal-validation consent gate.
    ///
    /// Includes the board + BOTH firmware versions, so a BIOS or EC update on the
    /// *same* machine changes the fingerprint and re-triggers acceptance — the
    /// thermal mechanism (hpqBIOS CT76) is an internal HP interface with no
    /// stability guarantee across firmware, so prior validation can't be assumed
    /// to carry over an update. Any field change => a different fingerprint.
    pub fn fingerprint(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}",
            self.manufacturer,
            self.product,
            self.family,
            self.board,
            self.bios_version,
            self.board_version,
        )
    }
}

/// CPU model string from registry (e.g. "13th Gen Intel(R) Core(TM) i7-13700H").
pub fn cpu_name() -> String {
    // SAFETY: Registry APIs operate on stack-allocated buffers. `key` is opened
    // with KEY_READ and closed before return. `buf` is 256 wide chars (512 bytes);
    // `size` is set to the buffer capacity and updated by RegQueryValueExW.
    unsafe {
        let mut key = HKEY::default();
        let status = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            w!("HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"),
            None,
            KEY_READ,
            &mut key,
        );
        if status.is_err() {
            return String::new();
        }

        let mut buf = [0u16; 256];
        let mut size = (buf.len() * 2) as u32;
        let mut kind = REG_VALUE_TYPE::default();
        let status = RegQueryValueExW(
            key,
            w!("ProcessorNameString"),
            None,
            Some(&mut kind),
            Some(buf.as_mut_ptr() as *mut u8),
            Some(&mut size),
        );
        let _ = RegCloseKey(key);

        if status.is_err() || kind != REG_SZ {
            return String::new();
        }

        let len = (size as usize / 2).saturating_sub(1);
        String::from_utf16_lossy(&buf[..len]).trim().to_string()
    }
}

fn read_bios_value(name: windows::core::PCWSTR) -> String {
    // SAFETY: Same registry contract as cpu_name(); `name` is a compile-time
    // w!() literal with static lifetime. Key is closed before return.
    unsafe {
        let mut key = HKEY::default();
        let status = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            w!("HARDWARE\\DESCRIPTION\\System\\BIOS"),
            None,
            KEY_READ,
            &mut key,
        );
        if status.is_err() {
            return String::new();
        }

        let mut buf = [0u16; 256];
        let mut size = (buf.len() * 2) as u32;
        let mut kind = REG_VALUE_TYPE::default();
        let status = RegQueryValueExW(
            key,
            name,
            None,
            Some(&mut kind),
            Some(buf.as_mut_ptr() as *mut u8),
            Some(&mut size),
        );
        let _ = RegCloseKey(key);

        if status.is_err() || kind != REG_SZ {
            return String::new();
        }

        // size is in bytes, includes null terminator
        let len = (size as usize / 2).saturating_sub(1);
        String::from_utf16_lossy(&buf[..len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reference machine this tool's thermal RE was validated on.
    fn envy_16() -> HwInfo {
        HwInfo {
            manufacturer: "HP".into(),
            product: "HP ENVY Laptop 16-h1xxx".into(),
            board: "8BE5".into(),
            family: "103C_5335M8 HP ENVY".into(),
            bios_version: "F.25".into(),
            board_version: "72.35".into(),
        }
    }

    #[test]
    fn is_hp_matches_hp_and_hewlett() {
        let mut hw = envy_16();
        assert!(hw.is_hp());
        hw.manufacturer = "Hewlett-Packard".into();
        assert!(hw.is_hp());
        hw.manufacturer = "Dell Inc.".into();
        assert!(!hw.is_hp());
    }

    #[test]
    fn fingerprint_is_deterministic_and_covers_every_field() {
        let hw = envy_16();
        assert_eq!(hw.fingerprint(), hw.fingerprint(), "must be deterministic");
        for field in [
            "HP",
            "HP ENVY Laptop 16-h1xxx",
            "103C_5335M8 HP ENVY",
            "8BE5",
            "F.25",
            "72.35",
        ] {
            assert!(
                hw.fingerprint().contains(field),
                "fingerprint must include {field}",
            );
        }
    }

    #[test]
    fn fingerprint_changes_on_bios_or_ec_update() {
        // The core reason firmware versions are in the fingerprint: an update to
        // the same machine must re-trigger consent, because CT76 semantics are
        // not guaranteed stable across firmware.
        let base = envy_16().fingerprint();

        let mut bios_update = envy_16();
        bios_update.bios_version = "F.30".into();
        assert_ne!(
            base,
            bios_update.fingerprint(),
            "BIOS update must re-prompt"
        );

        let mut ec_update = envy_16();
        ec_update.board_version = "72.40".into();
        assert_ne!(base, ec_update.fingerprint(), "EC update must re-prompt");
    }

    #[test]
    fn fingerprint_changes_on_different_board() {
        let a = envy_16().fingerprint();
        let mut other = envy_16();
        other.board = "8XYZ".into();
        assert_ne!(a, other.fingerprint(), "a different board must re-prompt");
    }
}
