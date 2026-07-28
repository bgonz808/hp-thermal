use std::fs;
use std::os::windows::process::CommandExt;
use std::process::Command;

use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_ABANDONED, WAIT_OBJECT_0};
use windows::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
use windows::Win32::System::Services::{
    CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx,
    SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_CONTROL_STOP, SERVICE_QUERY_STATUS,
    SERVICE_RUNNING, SERVICE_START, SERVICE_STATUS, SERVICE_STATUS_PROCESS, SERVICE_STOP,
    SERVICE_STOPPED, StartServiceW,
};
use windows::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows::Win32::System::Threading::{
    CreateMutexW, GetCurrentProcess, OpenProcessToken, ReleaseMutex, WaitForSingleObject,
};
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::*;
use windows::core::{PCWSTR, w};

use crate::app;
use crate::onboarding::Choices;
use crate::wide::wide_null;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// RAII guard for the setup mutex. The lock is released (`ReleaseMutex`) and the
/// handle closed on drop, so it is held ONLY for the mutating critical section —
/// never across a modal dialog or for the whole process lifetime. This prevents a
/// stuck/leaked lock from silently bricking all future installs and updates.
pub struct SetupGuard(HANDLE);

impl Drop for SetupGuard {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a mutex handle we created and own the lock on.
        unsafe {
            let _ = ReleaseMutex(self.0);
            let _ = CloseHandle(self.0);
        }
    }
}

/// Acquire the setup mutex around a mutating install/update/start/stop.
///
/// Returns `Some(guard)` on success (hold it for the critical section, then let
/// it drop), or `None` if another setup operation is genuinely in progress. Waits
/// briefly (3 s) because an existing holder may be mid-teardown during a restart
/// handoff; recovers a mutex abandoned by a crashed holder (`WAIT_ABANDONED`), so
/// a previous crash can never permanently block setup. Callers must give the user
/// feedback on `None` (see [`warn_setup_in_progress`]) rather than exit silently.
#[must_use]
pub fn acquire_setup_lock() -> Option<SetupGuard> {
    acquire_setup_lock_timeout(3000)
}

/// Core of [`acquire_setup_lock`] with an explicit wait budget (ms). Separated so
/// tests can probe contention with a 0 ms wait instead of the production 3 s.
#[must_use]
fn acquire_setup_lock_timeout(timeout_ms: u32) -> Option<SetupGuard> {
    let name = wide_null(app::SETUP_MUTEX_NAME);
    // SAFETY: `name` is a valid null-terminated wide string that outlives the call.
    // Created unowned (bInitialOwner=false); ownership is taken via the wait below.
    unsafe {
        let h = CreateMutexW(None, false, PCWSTR(name.as_ptr())).ok()?;
        match WaitForSingleObject(h, timeout_ms) {
            // Acquired outright, or reclaimed from a crashed holder — we own it now.
            WAIT_OBJECT_0 | WAIT_ABANDONED => Some(SetupGuard(h)),
            _ => {
                let _ = CloseHandle(h);
                None
            }
        }
    }
}

/// Tell the user a concurrent setup is in progress, instead of failing silently.
pub fn warn_setup_in_progress() {
    info_box(
        "Another HP Thermal setup or update is already in progress.\n\n\
         Please wait for it to finish, then try again.",
        MB_OK | MB_ICONWARNING,
    );
}

/// Minimal message box titled with the app name.
fn info_box(text: &str, flags: MESSAGEBOX_STYLE) {
    let title = wide_null(app::NAME);
    let body = wide_null(text);
    // SAFETY: both wide strings outlive the synchronous MessageBoxW call.
    unsafe {
        MessageBoxW(None, PCWSTR(body.as_ptr()), PCWSTR(title.as_ptr()), flags);
    }
}

// ---------------------------------------------------------------------------
// Queries (no elevation needed)
// ---------------------------------------------------------------------------

/// Query the service's current state via the SCM API — no locale-dependent text
/// parsing. Returns `SERVICE_STATUS_PROCESS.dwCurrentState`, or `None` if the
/// service isn't installed or can't be opened. Works unelevated: our service SDDL
/// grants `SERVICE_QUERY_STATUS` to Users.
fn service_state() -> Option<u32> {
    // SAFETY: standard SCM open -> query sequence; both handles closed before return.
    unsafe {
        let scm = OpenSCManagerW(None, None, SC_MANAGER_CONNECT).ok()?;
        let name = wide_null(app::SERVICE_NAME);
        let svc = match OpenServiceW(scm, PCWSTR(name.as_ptr()), SERVICE_QUERY_STATUS) {
            Ok(h) => h,
            Err(_) => {
                let _ = CloseServiceHandle(scm);
                return None;
            }
        };
        let mut status = SERVICE_STATUS_PROCESS::default();
        let mut needed = 0u32;
        let buf = std::slice::from_raw_parts_mut(
            &mut status as *mut _ as *mut u8,
            std::mem::size_of::<SERVICE_STATUS_PROCESS>(),
        );
        let result = QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, Some(buf), &mut needed);
        let _ = CloseServiceHandle(svc);
        let _ = CloseServiceHandle(scm);
        result.ok()?;
        Some(status.dwCurrentState.0)
    }
}

/// Check if the service is registered (doesn't need elevation).
pub fn is_service_installed() -> bool {
    service_state().is_some()
}

/// Check if the service is running (SERVICE_RUNNING).
pub fn is_service_running() -> bool {
    service_state() == Some(SERVICE_RUNNING.0)
}

/// Check if hp-thermal.exe exists at the canonical install location.
#[allow(dead_code)]
pub fn is_installed() -> bool {
    std::path::Path::new(&app::installed_exe()).exists()
}

/// Check if the currently running exe IS the installed copy (in Program Files).
pub fn is_installed_copy() -> bool {
    let us = app::exe_path();
    let installed = app::installed_exe();
    us.eq_ignore_ascii_case(&installed)
}

/// Is the RUNNING service our exact build? No UAC needed.
///
/// Authoritative on the *running* service, NOT the on-disk file. We ask the live
/// service for its compiled-in [`BUILD_FINGERPRINT`] (baked into the running image,
/// so it reflects the code actually executing) and compare it to ours. A stale
/// service running old bytes reports the old fingerprint even after the on-disk
/// `.exe` has already been replaced — so "current" means the running code matches,
/// which is what an update must guarantee.
///
/// Not a disk-digest compare: with the disk ahead of the running process (file already
/// swapped), that reports a stale-but-running service as "current" and skips the very update
/// needed. A mismatch — or an unreachable pipe — is treated as not-current so the update
/// proceeds.
pub fn is_service_current() -> bool {
    use crate::pipe;
    use crate::protocol::*;

    // We ARE the installed copy → current by definition.
    if app::installed_exe().eq_ignore_ascii_case(app::exe_path()) {
        return true;
    }

    matches!(
        pipe::client_transact(CMD_READ_BUILD_ID, 0),
        Some(resp) if resp == BUILD_FINGERPRINT
    )
}

// ---------------------------------------------------------------------------
// Auto-start registry (elevated)
// ---------------------------------------------------------------------------

/// Register the tray in HKLM\...\Run so it auto-starts on logon for all users.
/// Must be called elevated. Silently no-ops on failure.
/// Open HKLM `...\Run` for `KEY_SET_VALUE` and pass the key to `f`, closing it
/// afterward. No-op if the key can't be opened. Shared by the run-key set/remove.
fn with_run_key(f: impl FnOnce(windows::Win32::System::Registry::HKEY)) {
    use windows::Win32::System::Registry::*;
    // SAFETY: subkey is a static wide literal; `key` is an out-param closed before return.
    unsafe {
        let mut key = HKEY::default();
        let err = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            w!("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
            None,
            KEY_SET_VALUE,
            &mut key,
        );
        if err.is_err() {
            return;
        }
        f(key);
        let _ = RegCloseKey(key);
    }
}

fn set_run_key() {
    use windows::Win32::System::Registry::*;

    let installed = app::installed_exe();
    let data: Vec<u16> = installed.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: data is a valid null-terminated UTF-16 string; we reinterpret as
    // bytes for RegSetValueExW which expects REG_SZ as raw byte data.
    let data_bytes =
        unsafe { std::slice::from_raw_parts(data.as_ptr() as *const u8, data.len() * 2) };

    with_run_key(|key| {
        // SAFETY: `key` is a valid HKEY open for KEY_SET_VALUE; `data_bytes` lives
        // for the call.
        unsafe {
            let _ = RegSetValueExW(key, w!("HpThermal"), None, REG_SZ, Some(data_bytes));
        }
    });
}

/// Remove the tray auto-start entry from HKLM\...\Run.
fn remove_run_key() {
    use windows::Win32::System::Registry::*;

    with_run_key(|key| {
        // SAFETY: `key` is a valid HKEY open for KEY_SET_VALUE.
        unsafe {
            let _ = RegDeleteValueW(key, w!("HpThermal"));
        }
    });
}

// ---------------------------------------------------------------------------
// Add/Remove Programs entry — "Installed apps" (elevated)
// ---------------------------------------------------------------------------

/// The Uninstall subkey. A STABLE name (not versioned) so install and update write the
/// same entry: a newer version updates it in place, never a duplicate, no drift.
const UNINSTALL_SUBKEY: windows::core::PCWSTR =
    w!("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\HpThermal");

/// Write (or refresh) the Windows "Installed apps" entry so the app is uninstallable from
/// Settings, not only the CLI. Idempotent; called from both install and update. Must be
/// called elevated (HKLM). No-op on failure.
fn write_uninstall_entry() {
    use windows::Win32::System::Registry::*;

    let installed = app::installed_exe();
    let uninstall_cmd = format!("\"{installed}\" uninstall");
    let est_kb = fs::metadata(&installed)
        .map(|m| (m.len() / 1024) as u32)
        .unwrap_or(0);

    // SAFETY: UNINSTALL_SUBKEY is a static wide literal; `key` is closed before return;
    // each value buffer outlives its RegSetValueExW call.
    unsafe {
        let mut key = HKEY::default();
        let err = RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            UNINSTALL_SUBKEY,
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
        reg_set_sz(key, w!("DisplayName"), app::NAME);
        reg_set_sz(key, w!("DisplayVersion"), env!("CARGO_PKG_VERSION"));
        reg_set_sz(key, w!("Publisher"), env!("CARGO_PKG_AUTHORS"));
        reg_set_sz(key, w!("InstallLocation"), app::install_dir());
        reg_set_sz(key, w!("DisplayIcon"), &installed);
        reg_set_sz(key, w!("UninstallString"), &uninstall_cmd);
        reg_set_dword(key, w!("EstimatedSize"), est_kb);
        reg_set_dword(key, w!("NoModify"), 1);
        reg_set_dword(key, w!("NoRepair"), 1);
        let _ = RegCloseKey(key);
    }
}

/// The `DisplayVersion` recorded in the "Installed apps" entry, if present — used to
/// show the version delta on an update prompt. HKLM read, no elevation needed; `None`
/// if the entry or value is missing.
pub fn installed_version() -> Option<String> {
    use windows::Win32::System::Registry::*;
    // SAFETY: UNINSTALL_SUBKEY is a static wide literal; `key` is closed before return;
    // `buf` is a stack buffer and `len` is its size in bytes for RegQueryValueExW.
    unsafe {
        let mut key = HKEY::default();
        if RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            UNINSTALL_SUBKEY,
            None,
            KEY_QUERY_VALUE,
            &mut key,
        )
        .is_err()
        {
            return None;
        }
        let mut buf = [0u16; 64];
        let mut len = (buf.len() * 2) as u32; // bytes
        let r = RegQueryValueExW(
            key,
            w!("DisplayVersion"),
            None,
            None,
            Some(buf.as_mut_ptr() as *mut u8),
            Some(&mut len),
        );
        let _ = RegCloseKey(key);
        if r.is_err() {
            return None;
        }
        let n = (len as usize / 2).min(buf.len());
        let s = String::from_utf16_lossy(&buf[..n])
            .trim_end_matches('\0')
            .trim()
            .to_string();
        (!s.is_empty()).then_some(s)
    }
}

/// Remove the "Installed apps" entry. Must be called elevated. No-op on failure.
fn remove_uninstall_entry() {
    use windows::Win32::System::Registry::*;
    // SAFETY: static wide literal subkey; the key holds only values, no child subkeys.
    unsafe {
        let _ = RegDeleteKeyW(HKEY_LOCAL_MACHINE, UNINSTALL_SUBKEY);
    }
}

/// Write a REG_SZ value into an open key.
/// # Safety
/// `key` must be a valid HKEY open for `KEY_SET_VALUE`.
unsafe fn reg_set_sz(
    key: windows::Win32::System::Registry::HKEY,
    name: windows::core::PCWSTR,
    val: &str,
) {
    use windows::Win32::System::Registry::*;
    let data: Vec<u16> = val.encode_utf16().chain(std::iter::once(0)).collect();
    let bytes = std::slice::from_raw_parts(data.as_ptr() as *const u8, data.len() * 2);
    let _ = RegSetValueExW(key, name, None, REG_SZ, Some(bytes));
}

/// Write a REG_DWORD value into an open key.
/// # Safety
/// `key` must be a valid HKEY open for `KEY_SET_VALUE`.
unsafe fn reg_set_dword(
    key: windows::Win32::System::Registry::HKEY,
    name: windows::core::PCWSTR,
    val: u32,
) {
    use windows::Win32::System::Registry::*;
    let _ = RegSetValueExW(key, name, None, REG_DWORD, Some(&val.to_le_bytes()));
}

// ---------------------------------------------------------------------------
// File operations (elevated)
// ---------------------------------------------------------------------------

/// Copy the running exe to C:\Program Files\HpThermal\.
/// Creates the directory if needed. Must be called elevated.
///
/// Uses rename-then-replace: the old binary may be locked for reading by
/// Defender/indexer even after our process exits, but Windows allows renaming
/// files opened with FILE_SHARE_DELETE. Rename old → copy new → delete old.
fn copy_exe_to_install_dir() -> Result<(), String> {
    let install_dir = app::install_dir();
    let dest = app::installed_exe();
    let old = format!("{dest}.old");
    let src = app::exe_path();

    fs::create_dir_all(install_dir).map_err(|e| format!("Failed to create {install_dir}: {e}"))?;

    // Move the old binary out of the way (works even if Defender has it open)
    if std::path::Path::new(&dest).exists() {
        let _ = fs::remove_file(&old); // clean up stale .old from prior run
        fs::rename(&dest, &old).map_err(|e| format!("Failed to rename {dest} → .old: {e}"))?;
    }

    fs::copy(src, &dest).map_err(|e| format!("Failed to copy to {dest}: {e}"))?;

    let _ = fs::remove_file(&old); // best-effort cleanup
    Ok(())
}

/// True if the running exe IS the canonical installed binary in Program Files — the only
/// admin-only-write location. The service refuses to run from anywhere else: elsewhere, the
/// assumption that a lower-privileged user cannot tamper the image no longer holds.
pub fn running_from_install_dir() -> bool {
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    let expected = std::path::PathBuf::from(app::installed_exe());
    // Canonicalize both to normalize 8.3 names, casing, and symlinks before comparing.
    match (
        std::fs::canonicalize(&exe),
        std::fs::canonicalize(&expected),
    ) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// True if the installed binary's DACL grants write/delete to ONLY SYSTEM and
/// Administrators — i.e. no lower-privileged principal can tamper the SYSTEM image. This
/// re-checks at runtime what install set at install time: an ACL loosened afterward (an
/// admin slip, or malware that briefly held admin) is caught here, and the service refuses.
/// Fail-CLOSED: any read failure, a NULL DACL (everyone-full), or a single write-granting
/// ACE to a non-privileged SID returns false.
pub fn image_write_restricted() -> bool {
    image_write_restricted_at(&app::installed_exe())
}

/// Core of [`image_write_restricted`], parameterized by path so it can be unit-tested
/// against a temp file with a controlled ACL (no service/admin required).
fn image_write_restricted_at(path: &str) -> bool {
    use std::ffi::c_void;
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows::Win32::Security::*;

    // Write/tamper-relevant rights: overwrite, append, delete, re-ACL, take ownership, or all.
    const WRITE_MASK: u32 = 0x0002      // FILE_WRITE_DATA
        | 0x0004                        // FILE_APPEND_DATA
        | 0x0001_0000                   // DELETE
        | 0x0004_0000                   // WRITE_DAC
        | 0x0008_0000                   // WRITE_OWNER
        | 0x4000_0000                   // GENERIC_WRITE
        | 0x1000_0000; // GENERIC_ALL

    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

    // SAFETY: `wide` is a valid null-terminated path. GetNamedSecurityInfoW allocates the
    // security descriptor, freed via LocalFree before every return. `dacl` points into that
    // descriptor and is only read while it is alive. ACE pointers are validated by GetAce.
    unsafe {
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        let err = GetNamedSecurityInfoW(
            windows::core::PCWSTR(wide.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut dacl),
            None,
            &mut sd,
        );
        if err.is_err() {
            return false; // can't read the ACL -> fail closed
        }
        if dacl.is_null() {
            let _ = LocalFree(Some(HLOCAL(sd.0)));
            return false; // NULL DACL = everyone full access
        }
        let mut restricted = true;
        let count = (*dacl).AceCount;
        for i in 0..count {
            let mut ace: *mut c_void = std::ptr::null_mut();
            // A successful GetAce guarantees a valid `ace`; the explicit null guard makes
            // that provable to the reader and the analyzer, and fails closed if it ever isn't.
            if GetAce(dacl, i as u32, &mut ace).is_err() || ace.is_null() {
                restricted = false;
                break;
            }
            let header = &*(ace as *const ACE_HEADER);
            // Only ALLOW ACEs grant; inherit-only ACEs don't apply to this object.
            const ACCESS_ALLOWED: u8 = 0; // ACCESS_ALLOWED_ACE_TYPE
            if header.AceType != ACCESS_ALLOWED {
                continue;
            }
            if header.AceFlags & (INHERIT_ONLY_ACE.0 as u8) != 0 {
                continue;
            }
            let allow = &*(ace as *const ACCESS_ALLOWED_ACE);
            if allow.Mask & WRITE_MASK == 0 {
                continue; // no write/tamper right granted
            }
            let sid = PSID(&allow.SidStart as *const u32 as *mut c_void);
            let privileged = IsWellKnownSid(sid, WinLocalSystemSid).as_bool()
                || IsWellKnownSid(sid, WinBuiltinAdministratorsSid).as_bool();
            if !privileged {
                restricted = false; // a lower-privileged principal can tamper the image
                break;
            }
        }
        let _ = LocalFree(Some(HLOCAL(sd.0)));
        restricted
    }
}

/// If the running exe lives inside the install dir, move it out to %TEMP% so the install
/// dir can be deleted. Windows locks a running image in place, so `remove_dir_all` would
/// otherwise leave `hp-thermal.exe` behind. NTFS allows renaming a running image within
/// the same volume (Program Files and %TEMP% are both on C:), so this is a move, not a
/// copy; the relocated copy is then scheduled for delete-on-reboot. No-op if we are not
/// running from the install dir (e.g. uninstall launched from a downloaded copy).
fn relocate_self_for_deletion() {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return,
    };
    if !exe.starts_with(app::install_dir()) {
        return;
    }
    let target = std::env::temp_dir().join(format!("hp-thermal-old-{}.exe", std::process::id()));
    if fs::rename(&exe, &target).is_ok() {
        schedule_delete_on_reboot(&target);
    }
}

/// `MoveFileExW(path, NULL, MOVEFILE_DELAY_UNTIL_REBOOT)`: register the path for deletion
/// on next boot (via HKLM PendingFileRenameOperations — needs the elevation uninstall
/// already holds).
fn schedule_delete_on_reboot(path: &std::path::Path) {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Storage::FileSystem::{MOVEFILE_DELAY_UNTIL_REBOOT, MoveFileExW};
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: `wide` is a valid null-terminated path; a null new-name = delete-on-reboot.
    unsafe {
        let _ = MoveFileExW(
            windows::core::PCWSTR(wide.as_ptr()),
            windows::core::PCWSTR::null(),
            MOVEFILE_DELAY_UNTIL_REBOOT,
        );
    }
}

/// Create C:\ProgramData\HpThermal\ and grant Users modify access.
/// Must be called elevated.
fn ensure_data_dir() -> Result<(), String> {
    let data_dir = app::data_dir();

    fs::create_dir_all(data_dir).map_err(|e| format!("Failed to create {data_dir}: {e}"))?;

    let status = Command::new(system32_exe("icacls.exe"))
        .args([data_dir, "/grant", "Users:(OI)(CI)(M)", "/T"])
        .creation_flags(CREATE_NO_WINDOW)
        .status();

    match status {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => Err(format!("icacls failed: {s}")),
        Err(e) => Err(format!("icacls exec failed: {e}")),
    }
}

// ---------------------------------------------------------------------------
// Process management
// ---------------------------------------------------------------------------

/// Post WM_CLOSE to any tray windows (message-only, class = HpThermalTray).
/// Non-blocking — returns immediately, the target processes handle it async.
fn close_tray_windows() {
    use windows::Win32::Foundation::{LPARAM, WPARAM};
    use windows::Win32::UI::WindowsAndMessaging::*;

    let our_pid = std::process::id();
    let class = crate::wide::wide_null(app::WINDOW_CLASS);
    let class_pcw = windows::core::PCWSTR(class.as_ptr());

    // SAFETY: `class` is a valid null-terminated wide string alive for the block.
    // FindWindowExW / PostMessageW are safe to call with valid HWNDs; we skip our own PID.
    unsafe {
        let Ok(mut hwnd) = FindWindowExW(Some(HWND_MESSAGE), None, class_pcw, None) else {
            return;
        };
        loop {
            let mut wnd_pid = 0u32;
            GetWindowThreadProcessId(hwnd, Some(&mut wnd_pid));
            if wnd_pid != our_pid {
                let _ = PostMessageW(Some(hwnd), WM_CLOSE, WPARAM(0), LPARAM(0));
            }
            match FindWindowExW(Some(HWND_MESSAGE), Some(hwnd), class_pcw, None) {
                Ok(next) => hwnd = next,
                Err(_) => break,
            }
        }
    }
}

/// Full image path of a process from an OPEN handle (needs
/// PROCESS_QUERY_LIMITED_INFORMATION). None if it can't be read.
unsafe fn process_image_path(h: HANDLE) -> Option<String> {
    use windows::Win32::System::Threading::{PROCESS_NAME_WIN32, QueryFullProcessImageNameW};
    let mut buf = [0u16; 260];
    let mut len = buf.len() as u32;
    QueryFullProcessImageNameW(
        h,
        PROCESS_NAME_WIN32,
        windows::core::PWSTR(buf.as_mut_ptr()),
        &mut len,
    )
    .ok()?;
    Some(String::from_utf16_lossy(&buf[..len as usize]))
}

/// Wait for our other installed instances to exit; force-kill after 3s.
/// Uses Win32 toolhelp snapshot + WaitForSingleObject (proper blocking wait).
///
/// We run ELEVATED here, so precision matters: we only terminate a process after
/// verifying its image path is our actual installed binary. The image name is a
/// cheap pre-filter only — it is spoofable and PID-reuse-racy — so a non-ours
/// process that merely happens to be named `hp-thermal.exe` is left untouched.
fn wait_or_kill_other_instances() {
    use windows::Win32::System::Diagnostics::ToolHelp::*;
    use windows::Win32::System::Threading::*;

    let our_pid = std::process::id();
    let installed = app::installed_exe();
    // SAFETY: TH32CS_SNAPPROCESS with pid=0 snapshots all processes. Always valid args.
    let Ok(snap) = (unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }) else {
        return;
    };

    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    let mut handles = Vec::new();
    // SAFETY: `snap` is a valid toolhelp snapshot handle from CreateToolhelp32Snapshot.
    // `entry.dwSize` is correctly initialized. All opened process handles are closed below.
    unsafe {
        if Process32FirstW(snap, &mut entry).is_ok() {
            loop {
                if entry.th32ProcessID != our_pid {
                    let end = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(0);
                    let name = String::from_utf16_lossy(&entry.szExeFile[..end]);
                    if name.eq_ignore_ascii_case(app::EXE_NAME) {
                        // Open with query rights and VERIFY the image path is our
                        // installed binary before adding it to the kill list.
                        // installed_exe() lives under Program Files (admin-write-only),
                        // so a path match authenticates the process as ours. Querying
                        // the path on THIS handle (not the snapshot PID) also closes a
                        // PID-reuse TOCTOU: a recycled PID whose path no longer matches
                        // is skipped. TODO(#22): also verify the Authenticode publisher
                        // once releases are signed — path is necessary, not sufficient.
                        if let Ok(h) = OpenProcess(
                            PROCESS_TERMINATE
                                | PROCESS_SYNCHRONIZE
                                | PROCESS_QUERY_LIMITED_INFORMATION,
                            false,
                            entry.th32ProcessID,
                        ) {
                            match process_image_path(h) {
                                Some(p) if p.eq_ignore_ascii_case(&installed) => handles.push(h),
                                // Name-only match or unreadable path -> not verifiably
                                // ours, so do NOT terminate it.
                                _ => {
                                    let _ = CloseHandle(h);
                                }
                            }
                        }
                    }
                }
                if Process32NextW(snap, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);

        for h in &handles {
            // Give graceful shutdown up to 3s, then force-kill
            if WaitForSingleObject(*h, 3000).0 != 0 {
                let _ = TerminateProcess(*h, 1);
                let _ = WaitForSingleObject(*h, 2000);
            }
            let _ = CloseHandle(*h);
        }
    }
}

// ---------------------------------------------------------------------------
// Polling helpers
// ---------------------------------------------------------------------------

/// Poll until the service is running (up to ~10 seconds).
pub fn wait_for_service_running() -> bool {
    for _ in 0..20 {
        if is_service_running() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    false
}

/// Poll until the service reaches STOPPED state (up to ~10 seconds).
/// Waits for "STOPPED" specifically, not just "not RUNNING" — STOP_PENDING
/// means the process may still hold file locks.
fn wait_for_service_stopped() {
    for _ in 0..40 {
        match service_state() {
            // Stopped, or gone entirely (== effectively stopped for our purposes).
            Some(s) if s == SERVICE_STOPPED.0 => return,
            None => return,
            _ => {}
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

// ---------------------------------------------------------------------------
// Install / Update / Uninstall — UAC entry points
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Start Menu shortcut — all-users, launchable/searchable from Start (elevated)
// ---------------------------------------------------------------------------

/// Path to the all-users Start Menu shortcut: `...\Programs\HP Thermal Control.lnk`.
fn start_menu_shortcut() -> Option<String> {
    use std::ffi::c_void;
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::UI::Shell::{
        FOLDERID_CommonPrograms, KF_FLAG_DEFAULT, SHGetKnownFolderPath,
    };
    // SAFETY: SHGetKnownFolderPath returns a CoTaskMem-allocated wide string we read then free.
    unsafe {
        let p = SHGetKnownFolderPath(&FOLDERID_CommonPrograms, KF_FLAG_DEFAULT, None).ok()?;
        let dir = p.to_string().ok()?;
        CoTaskMemFree(Some(p.0 as *const c_void));
        Some(format!("{dir}\\{}.lnk", app::NAME))
    }
}

/// Path to the all-users Desktop shortcut: `<Public Desktop>\HP Thermal Control.lnk`.
fn desktop_shortcut() -> Option<String> {
    use std::ffi::c_void;
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::UI::Shell::{
        FOLDERID_PublicDesktop, KF_FLAG_DEFAULT, SHGetKnownFolderPath,
    };
    // SAFETY: SHGetKnownFolderPath returns a CoTaskMem-allocated wide string we read then free.
    unsafe {
        let p = SHGetKnownFolderPath(&FOLDERID_PublicDesktop, KF_FLAG_DEFAULT, None).ok()?;
        let dir = p.to_string().ok()?;
        CoTaskMemFree(Some(p.0 as *const c_void));
        Some(format!("{dir}\\{}.lnk", app::NAME))
    }
}

/// Write (or overwrite) a `.lnk` at `lnk` pointing at the installed exe. Must be called
/// elevated (writes under all-users locations). No-op on failure. Shared by the
/// Start Menu and Desktop shortcut creators.
fn write_shortcut(lnk: &str) {
    use windows::Win32::System::Com::{
        CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
        CoUninitialize, IPersistFile,
    };
    use windows::Win32::UI::Shell::{IShellLinkW, ShellLink};
    use windows::core::Interface;

    let exe: Vec<u16> = app::installed_exe()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let lnk_w: Vec<u16> = lnk.encode_utf16().chain(std::iter::once(0)).collect();
    // Point the shortcut icon at the same System32 imageres.dll #144 the tray uses,
    // so the Start Menu/Desktop icon matches the tray (our exe embeds no icon).
    let icon = system32_exe(app::ICON_DLL);
    let icon_w: Vec<u16> = icon
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: COM create/save with valid null-terminated wide strings. We only CoUninitialize
    // when THIS call initialized COM (S_OK/S_FALSE), never on RPC_E_CHANGED_MODE.
    unsafe {
        let inited = CoInitializeEx(None, COINIT_APARTMENTTHREADED).is_ok();
        if let Ok(link) = CoCreateInstance::<_, IShellLinkW>(&ShellLink, None, CLSCTX_INPROC_SERVER)
        {
            let _ = link.SetPath(PCWSTR(exe.as_ptr()));
            let _ = link.SetIconLocation(PCWSTR(icon_w.as_ptr()), app::ICON_INDEX);
            if let Ok(file) = link.cast::<IPersistFile>() {
                let _ = file.Save(PCWSTR(lnk_w.as_ptr()), true);
            }
        }
        if inited {
            CoUninitialize();
        }
    }
}

/// Create/refresh the Start Menu shortcut pointing at the installed exe. Elevated.
fn create_start_menu_shortcut() {
    if let Some(lnk) = start_menu_shortcut() {
        write_shortcut(&lnk);
    }
}

/// Remove the Start Menu shortcut. Must be called elevated. No-op if absent.
fn remove_start_menu_shortcut() {
    if let Some(lnk) = start_menu_shortcut() {
        let _ = fs::remove_file(&lnk);
    }
}

/// Create/refresh the all-users Desktop shortcut. Elevated.
fn create_desktop_shortcut() {
    if let Some(lnk) = desktop_shortcut() {
        write_shortcut(&lnk);
    }
}

/// Remove the Desktop shortcut. Must be called elevated. No-op if absent.
fn remove_desktop_shortcut() {
    if let Some(lnk) = desktop_shortcut() {
        let _ = fs::remove_file(&lnk);
    }
}

/// Install the service with the user's onboarding choices. If not elevated,
/// re-launches with UAC via `--install-svc [--startup] [--start-menu] [--desktop]`;
/// the elevated child parses the same flags. The choice dialog already ran (in the
/// non-elevated launcher), so the privileged window stays minimal — the child only
/// does the work and exits.
pub fn install(choices: Choices) {
    let flags = choices.to_args();
    let arg = if flags.is_empty() {
        "--install-svc".to_string()
    } else {
        format!("--install-svc {flags}")
    };
    elevate_or(&arg, move || install_service(choices));
}

/// Update the service: stop → replace exe → delete → create → start.
/// If not elevated, re-launches with UAC via --update-svc.
/// Update the service binary. From a non-elevated (Medium) context — the normal case —
/// spawn the elevated `--update-svc` child for the privileged work ONLY, WAIT for it to
/// finish, then (still the logged-in user, Medium IL) wait for the service to come back up
/// and launch the tray. Launching the tray here, from Medium, is what keeps it at the
/// user's integrity level (#54) and keeps the elevated window short. If we are already
/// elevated (e.g. `install` run as admin), do the privileged work in-process; we can't
/// safely launch a Medium tray from here, so it starts at next logon via the Run key.
pub fn update() {
    if is_elevated() {
        update_service();
        return;
    }
    // Wait for the child (not just poll for "running"): during an update the OLD service
    // is briefly still RUNNING before the child stops/replaces it, so a naive poll would
    // launch the tray into the stop/replace window, where wait_or_kill_other_instances
    // would terminate it. The child's exit is the definitive "privileged work done".
    if relaunch_elevated_and_wait("--update-svc") {
        wait_for_service_running();
        ensure_tray();
    }
}

/// Uninstall the service and clean up directories. If not elevated, re-launches with UAC.
pub fn uninstall() {
    if !is_elevated() {
        relaunch_elevated("uninstall");
        return;
    }

    remove_run_key();
    remove_uninstall_entry();
    remove_start_menu_shortcut();
    remove_desktop_shortcut();
    unexclude_from_wer(); // #38: leave no WER exclusion behind

    // Close tray instances gracefully, then wait/force — native, no taskkill.
    close_tray_windows();
    wait_or_kill_other_instances();

    native_stop();
    wait_for_service_stopped();

    let _ = Command::new(system32_exe("sc.exe"))
        .args(["delete", app::SERVICE_NAME])
        .creation_flags(CREATE_NO_WINDOW)
        .status();

    // Remove install directory (C:\Program Files\HpThermal). If this process IS the
    // installed exe, move it out of the way first so the directory deletes cleanly.
    let install_dir = app::install_dir();
    if std::path::Path::new(install_dir).exists() {
        relocate_self_for_deletion();
        match fs::remove_dir_all(install_dir) {
            Ok(()) => eprintln!("Removed {install_dir}"),
            Err(e) => eprintln!("Failed to remove {install_dir}: {e}"),
        }
    }

    // Remove data directory (C:\ProgramData\HpThermal — logs, sentinel)
    let data_dir = app::data_dir();
    if std::path::Path::new(data_dir).exists() {
        match fs::remove_dir_all(data_dir) {
            Ok(()) => eprintln!("Removed {data_dir}"),
            Err(e) => eprintln!("Failed to remove {data_dir}: {e}"),
        }
    }

    eprintln!("Service removed.");
}

// ---------------------------------------------------------------------------
// Internal elevated operations (called from --install-svc / --update-svc)
// ---------------------------------------------------------------------------

/// Copy exe to Program Files, create data dir, register and start the service,
/// then apply the user's optional choices. Must be called elevated.
pub fn install_service(choices: Choices) {
    // Defense-in-depth: never create the service on non-HP hardware, even if this
    // elevated helper is somehow invoked directly (the user-facing paths already
    // gate on require_hp() and show an error before elevating).
    if !crate::hwinfo::HwInfo::read().is_hp() {
        return;
    }
    if let Err(e) = copy_exe_to_install_dir() {
        eprintln!("Install failed: {e}");
        return;
    }

    if let Err(e) = ensure_data_dir() {
        eprintln!("Data dir setup failed: {e}");
        // Non-fatal: service can still run, just can't log until fixed
    }

    let installed = app::installed_exe();
    let bin_path = format!("\"{}\" --service", installed);

    let status = Command::new(system32_exe("sc.exe"))
        .args([
            "create",
            app::SERVICE_NAME,
            &format!("binPath={}", bin_path),
            "start=auto",
            &format!("DisplayName={}", app::NAME),
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .status();
    match status {
        Ok(s) if s.success() => eprintln!("Service created."),
        Ok(s) => eprintln!("sc create failed: {}", s),
        Err(e) => eprintln!("Failed to run sc: {}", e),
    }

    let _ = Command::new(system32_exe("sc.exe"))
        .args(["description", app::SERVICE_NAME, app::SERVICE_DESC])
        .creation_flags(CREATE_NO_WINDOW)
        .status();

    let sddl = app::service_sddl();
    let _ = Command::new(system32_exe("sc.exe"))
        .args(["sdset", app::SERVICE_NAME, &sddl])
        .creation_flags(CREATE_NO_WINDOW)
        .status();

    // #39: drop the service token to least privilege before it first starts.
    set_required_privileges();
    // #4: add the per-service SID (NT SERVICE\HpThermalService) to the token for DACL scoping.
    set_service_sid_type();
    // #38: opt the installed exe out of WER — no crash dump egress (all crash paths).
    exclude_from_wer();

    start_service();
    write_uninstall_entry(); // required — the Settings > Apps entry, always written

    // Optional extras, per the onboarding choices.
    if choices.run_at_startup {
        set_run_key();
    }
    if choices.start_menu {
        create_start_menu_shortcut();
    }
    if choices.desktop {
        create_desktop_shortcut();
    }
}

/// #39: least-privilege set for the SYSTEM service token. The SCM strips every LocalSystem
/// default NOT listed here when the service starts — dropping the dangerous ones (SeDebug,
/// SeTcb, SeLoadDriver, SeAssignPrimaryToken, SeBackup/SeRestore/SeTakeOwnership, ...).
/// Effective at the next service start.
///   SeChangeNotifyPrivilege - bypass traverse checking (file/path access; near-universal)
///   SeCreateGlobalPrivilege - create Global\ named objects (svc-start / Fn-key events)
///   SeImpersonatePrivilege  - REQUIRED for the DCOM/WMI calls to the HP BIOS provider:
///     WmiPrvSE impersonates the caller to service each read/write AND the async Fn+F12
///     event sink. Dropping it did NOT break function but forced a slow COM-security path
///     (~2-5s per WMI round-trip) — a UX regression that also widened a shared-WMI-connection
///     lockup race (#65). It IS itself an LPE primitive (T1134 token theft), kept out of
///     necessity; the blast radius is contained by CIG + no-child-process (#47) +
///     ProhibitDynamicCode (#24) + win32k-off (#48). Verified on the ENVY: with it WMI is
///     instant, without it ~2-5s. LESSON: verify latency, not just function, when tightening.
/// https://learn.microsoft.com/windows/win32/services/service-security-and-access-rights
const SERVICE_REQUIRED_PRIVILEGES: &[&str] = &[
    "SeChangeNotifyPrivilege",
    "SeCreateGlobalPrivilege",
    "SeImpersonatePrivilege",
];

/// Apply the least-privilege token restriction (#39) via the native SCM API —
/// `ChangeServiceConfig2W(SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO)`, no `sc.exe` shell-out.
/// Idempotent; takes effect at the next service start, so callers invoke it before
/// start/restart. Needs SERVICE_CHANGE_CONFIG (DC), which our SDDL grants to Administrators
/// only — so this runs from the elevated install/update child.
/// https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-changeserviceconfig2w
fn set_required_privileges() {
    use windows::Win32::System::Services::{
        ChangeServiceConfig2W, SERVICE_CHANGE_CONFIG, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
        SERVICE_REQUIRED_PRIVILEGES_INFOW,
    };
    // REG_MULTI_SZ: each name NUL-terminated, the whole list terminated by a final NUL.
    let mut multi_sz: Vec<u16> = Vec::new();
    for p in SERVICE_REQUIRED_PRIVILEGES {
        multi_sz.extend(p.encode_utf16());
        multi_sz.push(0);
    }
    multi_sz.push(0);
    // SAFETY: standard SCM open -> ChangeServiceConfig2W with a valid REG_MULTI_SZ buffer
    // that outlives the call; both service handles closed before return.
    unsafe {
        let Ok(scm) = OpenSCManagerW(None, None, SC_MANAGER_CONNECT) else {
            return;
        };
        let name = wide_null(app::SERVICE_NAME);
        if let Ok(svc) = OpenServiceW(scm, PCWSTR(name.as_ptr()), SERVICE_CHANGE_CONFIG) {
            let info = SERVICE_REQUIRED_PRIVILEGES_INFOW {
                pmszRequiredPrivileges: windows::core::PWSTR(multi_sz.as_mut_ptr()),
            };
            let _ = ChangeServiceConfig2W(
                svc,
                SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
                Some(&info as *const _ as *const std::ffi::c_void),
            );
            let _ = CloseServiceHandle(svc);
        }
        let _ = CloseServiceHandle(scm);
    }
}

/// #4: give the service its own per-service SID (`NT SERVICE\HpThermalService`). Sets
/// `SERVICE_SID_TYPE_UNRESTRICTED` via `ChangeServiceConfig2W`, which adds the name-derived,
/// upgrade-stable service SID to the process token at the next start. UNRESTRICTED (not
/// RESTRICTED) so it only ADDS the SID for use in DACLs — it does NOT yet write-restrict the
/// token (that is the C5 endgame). Foundational: lets us later scope the pipe / data-dir /
/// event DACLs to *this* service rather than to any SYSTEM process. Effective at the next
/// start; needs SERVICE_CHANGE_CONFIG (elevated install/update child). Idempotent.
/// https://learn.microsoft.com/windows/win32/api/winsvc/ns-winsvc-service_sid_info
fn set_service_sid_type() {
    use windows::Win32::System::Services::{
        ChangeServiceConfig2W, SERVICE_CHANGE_CONFIG, SERVICE_CONFIG_SERVICE_SID_INFO,
        SERVICE_SID_INFO, SERVICE_SID_TYPE_UNRESTRICTED,
    };
    // SAFETY: standard SCM open -> ChangeServiceConfig2W with a stack-allocated SERVICE_SID_INFO
    // that outlives the call; both service handles are closed before return.
    unsafe {
        let Ok(scm) = OpenSCManagerW(None, None, SC_MANAGER_CONNECT) else {
            return;
        };
        let name = wide_null(app::SERVICE_NAME);
        if let Ok(svc) = OpenServiceW(scm, PCWSTR(name.as_ptr()), SERVICE_CHANGE_CONFIG) {
            let info = SERVICE_SID_INFO {
                dwServiceSidType: SERVICE_SID_TYPE_UNRESTRICTED,
            };
            let _ = ChangeServiceConfig2W(
                svc,
                SERVICE_CONFIG_SERVICE_SID_INFO,
                Some(&info as *const _ as *const std::ffi::c_void),
            );
            let _ = CloseServiceHandle(svc);
        }
        let _ = CloseServiceHandle(scm);
    }
}

/// #38 no-egress: exclude the installed exe from Windows Error Reporting entirely, so
/// WerFault.exe never collects/uploads a crash dump — covering the `__fastfail` paths
/// (stack-cookie / CFG) that the top-level exception filter cannot intercept. Writes HKLM
/// (all users), so it must run elevated. Removed by unexclude_from_wer() on uninstall.
/// Idempotent. https://learn.microsoft.com/windows/win32/api/werapi/nf-werapi-weraddexcludedapplication
fn exclude_from_wer() {
    use windows::Win32::System::ErrorReporting::WerAddExcludedApplication;
    let name = wide_null(app::EXE_NAME);
    // SAFETY: `name` is a null-terminated wide string outliving the call. `true` = all users
    // (HKLM), which needs admin — this runs only from the elevated install/update child.
    unsafe {
        let _ = WerAddExcludedApplication(PCWSTR(name.as_ptr()), true);
    }
}

/// Undo exclude_from_wer() (#38) on uninstall — leave no WER config behind.
fn unexclude_from_wer() {
    use windows::Win32::System::ErrorReporting::WerRemoveExcludedApplication;
    let name = wide_null(app::EXE_NAME);
    // SAFETY: `name` is a null-terminated wide string outliving the call; all-users (HKLM).
    unsafe {
        let _ = WerRemoveExcludedApplication(PCWSTR(name.as_ptr()), true);
    }
}

/// Stop, replace exe, delete old registration, recreate, start.
/// Must be called elevated.
pub fn update_service() {
    let log = UpdateLog::open();
    log.write("update_service started");
    log.write(&format!("installing: {}", app::build_identity()));
    log.write(&format!("target: {}", app::installed_exe()));

    // Ask tray to close gracefully (non-blocking, tray exits in background)
    close_tray_windows();
    log.write("posted WM_CLOSE to tray windows");

    native_stop();
    log.write("stop issued");

    wait_for_service_stopped();
    log.write("service stopped");

    // Block until all other instances have exited (tray should already be gone
    // from WM_CLOSE above; force-kills stragglers after 3s timeout)
    wait_or_kill_other_instances();
    log.write("all other instances exited");

    // Diagnose: who still has the PF exe open?
    let lockers = who_locks_file(&app::installed_exe());
    if lockers.is_empty() {
        log.write("file lock check: no processes holding file");
    } else {
        for l in &lockers {
            log.write(&format!("file lock: {l}"));
        }
    }

    match copy_exe_to_install_dir() {
        Ok(()) => {
            log.write("copy succeeded");
            log.write(&format!(
                "installed exe-fnv={}",
                app::file_fnv(&app::installed_exe())
            ));
        }
        Err(e) => {
            log.write(&format!("COPY FAILED: {e}"));
            return;
        }
    }

    if let Err(e) = ensure_data_dir() {
        log.write(&format!("data dir setup failed: {e}"));
    }

    write_uninstall_entry(); // refresh the "Installed apps" entry (DisplayVersion, etc.)
    // Shortcuts and the Run key are NOT touched on update: their target is a stable
    // path across versions, so there's nothing to refresh — and leaving them alone
    // preserves the user's install-time choices (e.g. a shortcut they declined).

    // #39: (re)apply least-privilege on update — covers installs created before #39 and
    // refreshes if the set ever changes. Takes effect at the restart below.
    set_required_privileges();
    // #4: (re)apply the per-service SID type — covers installs created before #4.
    set_service_sid_type();
    log.write("required privileges + service SID set");
    // #38: (re)apply the WER exclusion on update — covers installs created before #38.
    exclude_from_wer();

    // No delete+create — binPath is the same, just the file content changed.
    // Avoids ERROR_SERVICE_MARKED_FOR_DELETE (1072) race condition.
    if native_start() {
        log.write("service start requested");
    } else {
        log.write("service start FAILED");
    }

    // #54: the elevated child ENDS here — at native_start(), the last privileged op. The
    // post-start wait for RUNNING and the tray launch are deliberately NOT done in this
    // elevated child: the tray must be launched at Medium IL (an elevated tray fork-bombed
    // the #54 guard), and keeping the non-privileged tail out of the elevated child also
    // trims the elevated window (temporal least privilege). The non-elevated bootstrap
    // parent (update(), running as the logged-in user) waits for RUNNING and launches the
    // tray after this child exits.
    log.write("update_service done — privileged work complete");
}

/// Append-only log to C:\ProgramData\HpThermal\update.log for diagnosing
/// the UAC child process (which has no visible console).
struct UpdateLog {
    path: String,
}

impl UpdateLog {
    fn open() -> Self {
        let path = format!("{}\\update.log", app::data_dir());
        let _ = fs::create_dir_all(app::data_dir());
        // Truncate on each run so we only see the latest attempt
        let _ = fs::write(&path, "");
        Self { path }
    }

    fn write(&self, msg: &str) {
        use std::io::Write;
        if let Ok(mut f) = fs::OpenOptions::new().append(true).open(&self.path) {
            let _ = writeln!(f, "{msg}");
        }
    }
}

/// Use the Restart Manager API to identify which processes have a file open.
/// Returns a list of "PID: process_name" strings, or an error description.
fn who_locks_file(path: &str) -> Vec<String> {
    use windows::Win32::Foundation::WIN32_ERROR;
    use windows::Win32::System::RestartManager::*;

    let ok = WIN32_ERROR(0);
    let more_data = WIN32_ERROR(234);

    let mut session: u32 = 0;
    let mut key = [0u16; 64];

    // SAFETY: `key` is a 64-element u16 buffer (>= CCH_RM_SESSION_KEY+1). `session` is out-param.
    let err = unsafe { RmStartSession(&mut session, None, windows::core::PWSTR(key.as_mut_ptr())) };
    if err != ok {
        return vec![format!("RmStartSession failed: {:?}", err)];
    }

    let path_w: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let path_ptrs = [windows::core::PCWSTR(path_w.as_ptr())];
    // SAFETY: `session` is a valid RM session from RmStartSession. `path_ptrs` contains
    // one valid null-terminated wide string pointer that outlives the call.
    let err = unsafe { RmRegisterResources(session, Some(&path_ptrs), None, None) };
    if err != ok {
        // SAFETY: `session` is a valid RM session that must be closed on error.
        let _ = unsafe { RmEndSession(session) };
        return vec![format!("RmRegisterResources failed: {:?}", err)];
    }

    let mut needed: u32 = 0;
    let mut count: u32 = 16;
    let mut buf = vec![RM_PROCESS_INFO::default(); 16];
    let mut reason: u32 = 0;

    // SAFETY: `session` is valid. `buf` has capacity for 16 entries and `count` is set to 16,
    // so RmGetList will not write beyond the buffer.
    let err = unsafe {
        RmGetList(
            session,
            &mut needed,
            &mut count,
            Some(buf.as_mut_ptr()),
            &mut reason,
        )
    };
    if err != ok && err != more_data {
        // SAFETY: Same RmEndSession contract as above.
        let _ = unsafe { RmEndSession(session) };
        return vec![format!("RmGetList failed: {:?}", err)];
    }

    let mut result = Vec::new();
    for info in &buf[..count as usize] {
        let end = info
            .strAppName
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(info.strAppName.len());
        let name = String::from_utf16_lossy(&info.strAppName[..end]);
        result.push(format!(
            "PID {}: {} (type={})",
            info.Process.dwProcessId, name, info.ApplicationType.0,
        ));
    }

    // SAFETY: Same RmEndSession contract as above. Closes the RM session on normal exit.
    let _ = unsafe { RmEndSession(session) };
    result
}

// ---------------------------------------------------------------------------
// Tray launch / Service start-stop
// ---------------------------------------------------------------------------

/// Launch the tray from the INSTALLED location (Program Files).
/// From elevated context: uses `runas /trustlevel:0x20000` to de-elevate.
/// Ensure the installed tray is running (idempotent): spawn it only if one isn't already
/// up. MUST be called from a NON-elevated (Medium IL) context — the tray is the
/// weakly-mitigated user role and must run at the user's normal integrity level. We
/// deliberately do NOT de-elevate here: dropping High->Medium reliably needs the interactive
/// user's token (fragile — no "correct user" guarantee; see #54 and MS guidance), and the
/// prior runas /trustlevel attempt did not lower IL and fork-bombed the #54 guard. All
/// normal callers are Medium (the fresh-install parent, the post-update parent in update(),
/// the "already up to date" path). If somehow called elevated, skip — the tray comes up at
/// next logon via the Run key rather than running elevated.
pub fn ensure_tray() {
    if is_elevated() {
        return;
    }
    // Idempotent guard: if a tray already holds the singleton mutex, a second spawn would
    // run default_run then block ~3s on the singleton wait before exiting as a duplicate (a
    // busy cursor). Skip it. The run_inner singleton is still the correctness authority;
    // this is the optimization that avoids the wasteful spawn. version_mismatch_restart does
    // NOT route through here — it spawns directly and relies on that 3s handoff. #59
    if is_tray_running() {
        return;
    }
    let _ = Command::new(app::installed_exe()).spawn();
}

/// True if a tray instance already holds its singleton mutex (`app::MUTEX_NAME`). A
/// successful `OpenMutexW` proves the named object exists — i.e. a tray created it.
fn is_tray_running() -> bool {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenMutexW, SYNCHRONIZATION_ACCESS_RIGHTS};
    let name = wide_null(app::MUTEX_NAME);
    // SAFETY: `name` is a null-terminated wide string that outlives the call; the handle (if
    // opened) is closed immediately. SYNCHRONIZE (0x0010_0000) suffices to test existence.
    unsafe {
        match OpenMutexW(
            SYNCHRONIZATION_ACCESS_RIGHTS(0x0010_0000),
            false,
            windows::core::PCWSTR(name.as_ptr()),
        ) {
            Ok(h) => {
                let _ = CloseHandle(h);
                true
            }
            Err(_) => false,
        }
    }
}

/// Re-launch this exe elevated (UAC) with an internal argument string (e.g.
/// `--install-svc 5`). Fire-and-forget: the elevated child does the privileged
/// work and exits; the non-elevated parent continues (e.g. waits + launches tray).
fn relaunch_elevated(args: &str) {
    let exe_w = wide_null(app::exe_path());
    let args_w = wide_null(args);
    // SAFETY: both wide strings are null-terminated and outlive the call.
    unsafe {
        ShellExecuteW(
            None,
            w!("runas"),
            windows::core::PCWSTR(exe_w.as_ptr()),
            windows::core::PCWSTR(args_w.as_ptr()),
            None,
            SW_HIDE,
        );
    }
}

/// If not elevated, re-launch elevated with `args` (UAC) and return; otherwise run
/// `work` in-process. The relaunch-or-run preamble shared by install/update.
fn elevate_or(args: &str, work: impl FnOnce()) {
    if !is_elevated() {
        relaunch_elevated(args);
        return;
    }
    work();
}

/// Like `relaunch_elevated`, but WAITS for the elevated child to exit. Used by `update()`
/// so the non-elevated parent launches the tray only AFTER the privileged child has
/// finished stop/replace/start — otherwise the tray (the PF binary) would race the child's
/// `wait_or_kill_other_instances` and be terminated. Returns false if the user cancelled
/// UAC or the launch failed (nothing spawned). Uses `ShellExecuteExW` with
/// `SEE_MASK_NOCLOSEPROCESS` to obtain the child handle to wait on.
fn relaunch_elevated_and_wait(args: &str) -> bool {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::WaitForSingleObject;
    use windows::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};

    let exe_w = wide_null(app::exe_path());
    let verb_w = wide_null("runas");
    let args_w = wide_null(args);
    // SAFETY: the three wide strings are null-terminated and outlive the call.
    // SEE_MASK_NOCLOSEPROCESS makes ShellExecuteExW populate `hProcess`; we wait on it
    // (bounded) and close it. On UAC cancel / failure the call returns Err and we bail.
    unsafe {
        let mut info = SHELLEXECUTEINFOW {
            cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS,
            lpVerb: windows::core::PCWSTR(verb_w.as_ptr()),
            lpFile: windows::core::PCWSTR(exe_w.as_ptr()),
            lpParameters: windows::core::PCWSTR(args_w.as_ptr()),
            nShow: SW_HIDE.0,
            ..Default::default()
        };
        if ShellExecuteExW(&mut info).is_err() || info.hProcess.is_invalid() {
            return false;
        }
        // Bounded wait: the child does service stop (<=~10s) + replace + start. 120s is a
        // generous cap; on timeout we proceed and let the tray's own startup checks cope.
        let _ = WaitForSingleObject(info.hProcess, 120_000);
        let _ = CloseHandle(info.hProcess);
        true
    }
}

/// Start the service via the SCM API. True if it started or is already running;
/// false if we lack rights (caller should elevate) or it failed to start.
fn native_start() -> bool {
    if service_state() == Some(SERVICE_RUNNING.0) {
        return true;
    }
    // SAFETY: standard SCM open -> StartService; handles closed before return.
    unsafe {
        let Ok(scm) = OpenSCManagerW(None, None, SC_MANAGER_CONNECT) else {
            return false;
        };
        let name = wide_null(app::SERVICE_NAME);
        // OpenService failure (access denied / not installed) -> caller elevates.
        let ok = match OpenServiceW(scm, PCWSTR(name.as_ptr()), SERVICE_START) {
            Ok(svc) => {
                let ok = StartServiceW(svc, None).is_ok();
                let _ = CloseServiceHandle(svc);
                ok
            }
            Err(_) => false,
        };
        let _ = CloseServiceHandle(scm);
        ok
    }
}

/// Stop the service via the SCM API. True if it stopped / was already stopped or
/// is absent; false if we lack rights (caller should elevate) or control failed.
fn native_stop() -> bool {
    match service_state() {
        Some(s) if s == SERVICE_STOPPED.0 => return true,
        None => return true, // not installed == nothing to stop
        _ => {}
    }
    // SAFETY: standard SCM open -> ControlService(STOP); handles closed before return.
    unsafe {
        let Ok(scm) = OpenSCManagerW(None, None, SC_MANAGER_CONNECT) else {
            return false;
        };
        let name = wide_null(app::SERVICE_NAME);
        let ok = match OpenServiceW(scm, PCWSTR(name.as_ptr()), SERVICE_STOP) {
            Ok(svc) => {
                let mut status = SERVICE_STATUS::default();
                let ok = ControlService(svc, SERVICE_CONTROL_STOP, &mut status).is_ok();
                let _ = CloseServiceHandle(svc);
                ok
            }
            Err(_) => false,
        };
        let _ = CloseServiceHandle(scm);
        ok
    }
}

/// Stop the service. Tries directly (our SDDL grants Users SERVICE_STOP), elevates
/// as fallback.
pub fn stop() {
    if native_stop() {
        eprintln!("Service stopped.");
        return;
    }
    relaunch_elevated("--stop-svc");
}

/// Internal: stop the service (called from elevated child).
pub fn stop_service() {
    if native_stop() {
        eprintln!("Service stopped.");
    } else {
        eprintln!("Service stop failed.");
    }
}

/// Start the service. Tries directly (our SDDL grants Users SERVICE_START),
/// elevates as fallback.
pub fn start() {
    if native_start() {
        eprintln!("Service started.");
        return;
    }
    relaunch_elevated("--start-svc");
}

/// Internal: start the service (called from elevated child).
pub fn start_service() {
    if native_start() {
        eprintln!("Service started.");
    } else {
        eprintln!("Service start failed.");
    }
}

/// Absolute path to a System32 executable, e.g. `system32_exe("sc.exe")`.
///
/// Using an absolute path avoids the CreateProcess search order (application
/// directory and CWD are searched *before* System32). In the elevated child,
/// launched from wherever hp-thermal.exe lives (a user-writable Downloads folder
/// on first run), a bare name like `"sc"` could otherwise resolve to a bundled
/// malicious `sc.exe` and run as Administrator — a binary-planting LPE. An
/// absolute path is not searched, closing that class entirely.
fn system32_exe(name: &str) -> std::path::PathBuf {
    let mut buf = [0u16; 260];
    // SAFETY: GetSystemDirectoryW writes up to buf.len() wchars and returns the count.
    let len = unsafe { GetSystemDirectoryW(Some(&mut buf)) } as usize;
    if len == 0 || len >= buf.len() {
        // GetSystemDirectoryW is a core API that does not fail in practice. If it
        // ever did, DO NOT guess a path for an elevated launch. Both guesses are
        // unsafe: a hardcoded "C:\Windows\System32" is *squattable* when Windows is
        // on another drive (the C:\ root grants Users "create folders", so a
        // standard user could plant C:\Windows\System32\sc.exe), and %SystemRoot%
        // is env-spoofable in the elevated child — either would run an
        // attacker-controlled binary as Administrator, the exact class this
        // function exists to prevent. Fail closed. (Matches app::known_folder_path.)
        eprintln!("FATAL: GetSystemDirectoryW failed — refusing to resolve {name}");
        std::process::exit(1);
    }
    let dir = String::from_utf16_lossy(&buf[..len]);
    std::path::Path::new(&dir).join(name)
}

// ---------------------------------------------------------------------------
// Elevation check
// ---------------------------------------------------------------------------

/// Check elevation via token inspection — no subprocess, no console flash.
pub fn is_elevated() -> bool {
    // SAFETY: GetCurrentProcess returns a pseudo-handle (no close needed).
    // OpenProcessToken + GetTokenInformation with TOKEN_QUERY is the documented
    // pattern for checking elevation. Token handle is closed before returning.
    unsafe {
        let mut token = windows::Win32::Foundation::HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut size = 0u32;
        let result = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut TOKEN_ELEVATION as *mut std::ffi::c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        );
        let _ = CloseHandle(token);
        result.is_ok() && elevation.TokenIsElevated != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The footing check must actually DETECT a loosened image ACL, not merely pass. Point
    /// it at a temp file whose ACL we control (re-ACLing a file we own needs no admin) and
    /// toggle write for the Users group. SIDs are used verbatim so it is locale-independent.
    #[test]
    fn image_write_restricted_detects_users_write() {
        use std::process::Command;
        let path = std::env::temp_dir().join(format!("hpt-acl-{}.tmp", std::process::id()));
        std::fs::write(&path, b"x").expect("create temp file");
        let p = path.to_str().unwrap();
        let icacls = |args: &[&str]| {
            Command::new("icacls")
                .args(args)
                .output()
                .expect("run icacls");
        };

        // The OS grants the file's creator an explicit ACE that `/inheritance:r` does NOT
        // strip, so the "restricted" case would otherwise carry a non-privileged writer and
        // be environment-dependent (passed locally as a standard user; failed on the admin
        // CI runner). Capture the creator SID to remove it below.
        let user_sid = Command::new("whoami")
            .args(["/user", "/fo", "csv", "/nh"])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .and_then(|s| s.rsplit(',').next().map(str::to_string))
            .map(|s| {
                s.trim_matches(|c: char| c == '"' || c.is_whitespace())
                    .to_string()
            })
            .unwrap_or_default();

        // Lock down to SYSTEM (S-1-5-18) + Administrators (S-1-5-32-544) only.
        icacls(&[p, "/inheritance:r"]);
        icacls(&[p, "/grant:r", "*S-1-5-18:(F)", "*S-1-5-32-544:(F)"]);
        // Strip any lingering non-privileged writers: CreatorOwner, Everyone, Authenticated
        // Users, Interactive, Users, and this process's own (creator) SID.
        for g in [
            "*S-1-3-0",
            "*S-1-1-0",
            "*S-1-5-11",
            "*S-1-5-4",
            "*S-1-5-32-545",
        ] {
            icacls(&[p, "/remove:g", g]);
        }
        if !user_sid.is_empty() {
            icacls(&[p, "/remove:g", &format!("*{user_sid}")]);
        }
        assert!(
            image_write_restricted_at(p),
            "SYSTEM+Administrators-only ACL must read as restricted"
        );

        // Grant Users (S-1-5-32-545) write -> must be detected as NOT restricted.
        icacls(&[p, "/grant", "*S-1-5-32-545:(M)"]);
        assert!(
            !image_write_restricted_at(p),
            "a Users:write ACE must be detected"
        );

        icacls(&[p, "/reset"]); // re-inherit so the owner regains delete for cleanup
        let _ = std::fs::remove_file(&path);
    }

    /// The setup lock must be mutually exclusive (a held lock blocks other
    /// contenders) and must release cleanly so setup is never permanently
    /// bricked. Contention is checked from another thread because a Win32 mutex
    /// is reentrant for its owning thread. Uses a 0 ms wait so it never blocks.
    #[test]
    fn setup_lock_is_exclusive_and_releases() {
        let held = acquire_setup_lock_timeout(0).expect("first acquire should succeed");

        // A different thread must see the lock as contended (None), not acquire it.
        let contended = std::thread::spawn(|| acquire_setup_lock_timeout(0).is_none())
            .join()
            .unwrap();
        assert!(
            contended,
            "a held setup lock must be contended from another thread"
        );

        drop(held); // releases the mutex on this (owning) thread

        // After release, another thread can acquire it (and drops it there).
        let reacquired = std::thread::spawn(|| acquire_setup_lock_timeout(0).is_some())
            .join()
            .unwrap();
        assert!(
            reacquired,
            "setup lock must be acquirable again after release"
        );
    }
}
