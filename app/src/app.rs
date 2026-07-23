// --- Identity ---
/// Human-readable display name (dialogs, tooltips, service display name).
pub const NAME: &str = "HP Thermal Control";
/// Binary/CLI name.
pub const BIN_NAME: &str = "hp-thermal";
pub const EXE_NAME: &str = "hp-thermal.exe";
pub const AUTHOR: &str = "bgonz808";
pub const COPYRIGHT: &str = "MIT License";
pub const REPO_URL: &str = "https://github.com/bgonz808/hp-thermal";

// --- Build identity ---

/// FNV-1a 64-bit hash of a byte slice — the one canonical implementation, used by
/// [`file_digest`] and the audio device-id hash. (The 2-byte build fingerprint in
/// `protocol` is a separate 32-bit *const* variant: it runs at compile time, so it
/// can't call this, and it needs a different width for the wire.)
pub fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

/// FNV-1a 64-bit digest of a file's contents as hex (empty on read failure). The
/// same digest the updater uses to compare on-disk binaries.
pub fn file_digest(path: &str) -> String {
    let Ok(data) = std::fs::read(path) else {
        return String::new();
    };
    format!("{:016x}", fnv1a_64(&data))
}

/// One-line build identity for startup/install logs: version, build id + date,
/// the running exe's path, and an FNV digest of that binary (so a swapped-but-
/// same-version file is still distinguishable). Lets a log reader confirm exactly
/// which build is running and from where.
pub fn build_identity() -> String {
    let exe = exe_path();
    format!(
        "{} {}+{} ({}) fnv={} path={}",
        BIN_NAME,
        env!("CARGO_PKG_VERSION"),
        env!("BUILD_ID"),
        env!("BUILD_DATE"),
        file_digest(exe),
        exe,
    )
}

// --- Service ---
pub const SERVICE_NAME: &str = "HpThermalService";
pub const SERVICE_DESC: &str = "Lightweight thermal mode control for HP laptops.\nProvides WMI access for the hp-thermal tray app.\nhttps://github.com/bgonz808/hp-thermal";
/// Service security descriptor (SDDL), composed from auditable pieces.
///
/// Each ACE: (A;; <rights> ;;; <trustee>)
///   A  = Allow
///   CC = SERVICE_QUERY_CONFIG
///   LC = SERVICE_QUERY_STATUS
///   SW = SERVICE_ENUMERATE_DEPENDENTS
///   RP = SERVICE_START              ← granted to IU
///   WP = SERVICE_STOP               ← granted to IU
///   DT = SERVICE_PAUSE_CONTINUE
///   LO = SERVICE_INTERROGATE
///   CR = SERVICE_USER_DEFINED_CONTROL
///   RC = READ_CONTROL
///   SD = WRITE_DAC
///   WD = WRITE_OWNER
///   WO = WRITE_OWNER (full)
///   GA = GENERIC_ALL
///
/// Trustees: SY=SYSTEM, BA=BUILTIN\Admins, IU=Interactive User
const ACE_SYSTEM: &str = "(A;;CCLCSWRPWPDTLOCRRC;;;SY)";
const ACE_ADMINS: &str = "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)";
/// Default IU rights + RP (start) + WP (stop) — the key addition.
const ACE_USER: &str = "(A;;CCLCSWRPWPLOCRRC;;;IU)";

// Concatenated at runtime (once, during install). Could be const with nightly, but not worth it.
pub fn service_sddl() -> String {
    format!("D:{ACE_SYSTEM}{ACE_ADMINS}{ACE_USER}")
}

// --- IPC ---
pub const PIPE_NAME: &str = r"\\.\pipe\HpThermalCtl";
pub const MUTEX_NAME: &str = "HpThermalTrayMutex";
pub const SETUP_MUTEX_NAME: &str = "HpThermalSetupMutex";
pub const WINDOW_CLASS: &str = "HpThermalTray";
pub const LOG_FILE: &str = "hp-thermal.log";
/// Named event signaled by the service when Fn+F12 (hpqBEvnt EventId=29) fires.
/// Global\ namespace = visible across sessions (service in session 0, tray in user session).
pub const FNKEY_EVENT: &str = r"Global\HpThermalFnKey";
/// Settings file for Fn+F12 behavior (single byte: bit 0 = screen toggle, bit 1 = sleep).
pub const FNKEY_CONFIG: &str = "fnkey";
/// Named event signaled by the service on startup. The tray waits on this to
/// detect version mismatches (service updated while tray is still running).
pub const SVC_START_EVENT: &str = r"Global\HpThermalSvcStart";

// --- Install paths ---
const INSTALL_DIR_NAME: &str = "HpThermal";

// --- Cached paths (computed once, reused everywhere) ---

use std::sync::OnceLock;

static EXE_PATH: OnceLock<String> = OnceLock::new();
static EXE_DIR: OnceLock<String> = OnceLock::new();
static INSTALL_DIR: OnceLock<String> = OnceLock::new();
static DATA_DIR: OnceLock<String> = OnceLock::new();

/// Full path to the running executable. Computed once via GetModuleFileNameW.
pub fn exe_path() -> &'static str {
    EXE_PATH.get_or_init(|| {
        let mut buf = [0u16; 260];
        // SAFETY: `buf` is a stack-allocated 260-char array (MAX_PATH); the API
        // writes at most buf.len() chars and returns the actual length.
        let len =
            unsafe { windows::Win32::System::LibraryLoader::GetModuleFileNameW(None, &mut buf) }
                as usize;
        String::from_utf16_lossy(&buf[..len])
    })
}

/// Directory containing the running executable. Derived from exe_path().
pub fn exe_dir() -> &'static str {
    EXE_DIR.get_or_init(|| {
        std::path::Path::new(exe_path())
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default()
    })
}

/// Canonical install directory: C:\Program Files\HpThermal
/// Uses SHGetKnownFolderPath — kernel-sourced, not environment variables.
pub fn install_dir() -> &'static str {
    INSTALL_DIR.get_or_init(|| {
        let pf = known_folder_path(&windows::Win32::UI::Shell::FOLDERID_ProgramFiles);
        format!("{pf}\\{INSTALL_DIR_NAME}")
    })
}

/// Shared data directory: C:\ProgramData\HpThermal
/// Writable by both SYSTEM (service) and Users (tray).
pub fn data_dir() -> &'static str {
    DATA_DIR.get_or_init(|| {
        let pd = known_folder_path(&windows::Win32::UI::Shell::FOLDERID_ProgramData);
        format!("{pd}\\{INSTALL_DIR_NAME}")
    })
}

/// Path to the installed exe: C:\Program Files\HpThermal\hp-thermal.exe
pub fn installed_exe() -> String {
    format!("{}\\{}", install_dir(), EXE_NAME)
}

/// Resolve a known folder via SHGetKnownFolderPath.
/// Exits the process on failure — if this API fails, the OS is broken.
fn known_folder_path(folder_id: &windows::core::GUID) -> String {
    // SAFETY: SHGetKnownFolderPath returns a CoTaskMem-allocated PWSTR.
    // We read the null-terminated string, then free it with CoTaskMemFree.
    // The GUID is a valid known-folder ID (ProgramFiles or ProgramData).
    unsafe {
        match windows::Win32::UI::Shell::SHGetKnownFolderPath(folder_id, Default::default(), None) {
            Ok(path_ptr) => {
                let len = (0..).take_while(|&i| *path_ptr.0.add(i) != 0).count();
                let result = String::from_utf16_lossy(std::slice::from_raw_parts(path_ptr.0, len));
                windows::Win32::System::Com::CoTaskMemFree(Some(
                    path_ptr.0 as *const std::ffi::c_void,
                ));
                result
            }
            Err(e) => {
                eprintln!("FATAL: SHGetKnownFolderPath failed, HRESULT={e}");
                std::process::exit(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sddl_is_a_dacl_with_three_allow_aces() {
        let sddl = service_sddl();
        assert!(sddl.starts_with("D:"), "must be a DACL: {sddl}");
        // One allow-ACE per trustee (SYSTEM, Admins, Interactive User).
        assert_eq!(
            sddl.matches("(A;;").count(),
            3,
            "expected 3 allow ACEs: {sddl}"
        );
        assert_eq!(sddl.matches(')').count(), 3, "unbalanced ACEs: {sddl}");
    }

    #[test]
    fn sddl_grants_all_three_trustees() {
        let sddl = service_sddl();
        for trustee in [";;SY)", ";;BA)", ";;IU)"] {
            assert!(
                sddl.contains(trustee),
                "missing trustee {trustee} in {sddl}"
            );
        }
    }

    #[test]
    fn interactive_user_can_start_and_stop_without_elevation() {
        // The entire reason for the custom SDDL: interactive users get
        // SERVICE_START (RP) + SERVICE_STOP (WP) so the tray can control the
        // service without UAC. Dropping either silently breaks that path.
        assert!(ACE_USER.ends_with(";;IU)"), "IU ACE malformed: {ACE_USER}");
        assert!(ACE_USER.contains("RP"), "IU must have SERVICE_START (RP)");
        assert!(ACE_USER.contains("WP"), "IU must have SERVICE_STOP (WP)");
    }

    #[test]
    fn sddl_parses_as_a_valid_security_descriptor() {
        // Prove the string we ship actually parses into a security descriptor,
        // not just that it looks well-formed. Catches a bad rights token that
        // would otherwise only surface at install time.
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::*;
        use windows::Win32::Security::Authorization::*;
        use windows::Win32::Security::*;

        let sddl_w = crate::wide::wide_null(&service_sddl());
        let mut sd = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
        // SAFETY: sddl_w is a null-terminated wide string that outlives the call.
        // On success ConvertStringSecurityDescriptor... allocates `sd` via LocalAlloc,
        // which we release with LocalFree.
        unsafe {
            let r = ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl_w.as_ptr()),
                1, // SDDL_REVISION_1
                &mut sd,
                None,
            );
            assert!(r.is_ok(), "shipped SDDL failed to parse: {r:?}");
            assert!(!sd.0.is_null(), "parse succeeded but SD is null");
            let _ = LocalFree(Some(HLOCAL(sd.0)));
        }
    }
}
