use std::fs;
use std::os::windows::process::CommandExt;
use std::process::Command;

use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::Threading::{CreateMutexW, GetCurrentProcess, OpenProcessToken};
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::*;

use crate::app;
use crate::wide::wide_null;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Acquire the setup mutex. Returns false if another setup operation is
/// already running. The mutex handle is intentionally leaked so it stays
/// held for the lifetime of this process.
pub fn try_acquire_setup_lock() -> bool {
    let name = wide_null(app::SETUP_MUTEX_NAME);
    // SAFETY: `name` is a valid null-terminated wide string that outlives the call.
    // CreateMutexW + GetLastError is the documented pattern for detecting an existing mutex.
    unsafe {
        let _ = CreateMutexW(None, true, PCWSTR(name.as_ptr()));
        GetLastError() != ERROR_ALREADY_EXISTS
    }
}

// ---------------------------------------------------------------------------
// Queries (no elevation needed)
// ---------------------------------------------------------------------------

/// Check if the service is registered (doesn't need elevation).
pub fn is_service_installed() -> bool {
    Command::new("sc")
        .args(["query", app::SERVICE_NAME])
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Check if the service is running (STATE = 4 RUNNING).
pub fn is_service_running() -> bool {
    let output = Command::new("sc")
        .args(["query", app::SERVICE_NAME])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    let Ok(out) = output else { return false };
    let text = String::from_utf8_lossy(&out.stdout);
    text.contains("RUNNING")
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

/// Check if the installed service matches our build. No UAC needed.
///
/// 1. Quick: ask running service for BUILD_FINGERPRINT — match = current.
/// 2. Mismatch or pipe unavailable: compare installed binary on disk.
///    (Running service may be stale while the on-disk binary is already current.)
pub fn is_service_current() -> bool {
    use crate::pipe;
    use crate::protocol::*;

    let installed = app::installed_exe();
    let our_exe = app::exe_path();

    // Same path → current by definition
    if installed.eq_ignore_ascii_case(our_exe) {
        return true;
    }

    // Fast path: if running service fingerprint matches, skip disk I/O
    if let Some(resp) = pipe::client_transact(CMD_READ_BUILD_ID, 0) {
        if resp == BUILD_FINGERPRINT {
            return true;
        }
    }

    // Pipe mismatch or unavailable — compare installed binary on disk
    let Ok(our_meta) = fs::metadata(our_exe) else {
        return false;
    };
    let Ok(inst_meta) = fs::metadata(&installed) else {
        return false;
    };
    if our_meta.len() != inst_meta.len() {
        return false;
    }
    file_hash(&installed) == file_hash(our_exe)
}

/// Extract the service binary path from `sc qc` output.
#[allow(dead_code)]
fn service_exe_path() -> Option<String> {
    let output = Command::new("sc")
        .args(["qc", app::SERVICE_NAME])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("BINARY_PATH_NAME") {
            let rest = rest.trim_start_matches([' ', ':']);
            let path = rest.trim_matches('"').trim();
            return Some(path.strip_suffix(" --service").unwrap_or(path).to_string());
        }
    }
    None
}

/// FNV-1a 64-bit hash of a file's contents.
fn file_hash(path: &str) -> String {
    let Ok(data) = fs::read(path) else {
        return String::new();
    };
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in &data {
        h ^= b as u64;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{h:016x}")
}

// ---------------------------------------------------------------------------
// Auto-start registry (elevated)
// ---------------------------------------------------------------------------

/// Register the tray in HKLM\...\Run so it auto-starts on logon for all users.
/// Must be called elevated. Silently no-ops on failure.
fn set_run_key() {
    use windows::Win32::System::Registry::*;

    let installed = app::installed_exe();
    let data: Vec<u16> = installed.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: data is a valid null-terminated UTF-16 string; we reinterpret as
    // bytes for RegSetValueExW which expects REG_SZ as raw byte data.
    let data_bytes =
        unsafe { std::slice::from_raw_parts(data.as_ptr() as *const u8, data.len() * 2) };

    // SAFETY: subkey is a static wide string literal. key is an out-param from
    // RegOpenKeyExW, closed before return.
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
        let _ = RegSetValueExW(key, w!("HpThermal"), None, REG_SZ, Some(data_bytes));
        let _ = RegCloseKey(key);
    }
}

/// Remove the tray auto-start entry from HKLM\...\Run.
fn remove_run_key() {
    use windows::Win32::System::Registry::*;

    // SAFETY: subkey is a static wide string literal. key is an out-param,
    // closed before return.
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
        let _ = RegDeleteValueW(key, w!("HpThermal"));
        let _ = RegCloseKey(key);
    }
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

/// Create C:\ProgramData\HpThermal\ and grant Users modify access.
/// Must be called elevated.
fn ensure_data_dir() -> Result<(), String> {
    let data_dir = app::data_dir();

    fs::create_dir_all(data_dir).map_err(|e| format!("Failed to create {data_dir}: {e}"))?;

    let status = Command::new("icacls")
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

/// Wait for all other hp-thermal.exe processes to exit; force-kill after 3s.
/// Uses Win32 toolhelp snapshot + WaitForSingleObject (proper blocking wait).
fn wait_or_kill_other_instances() {
    use windows::Win32::System::Diagnostics::ToolHelp::*;
    use windows::Win32::System::Threading::*;

    let our_pid = std::process::id();
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
                        if let Ok(h) = OpenProcess(
                            PROCESS_TERMINATE | PROCESS_SYNCHRONIZE,
                            false,
                            entry.th32ProcessID,
                        ) {
                            handles.push(h);
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
        let output = Command::new("sc")
            .args(["query", app::SERVICE_NAME])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
        if let Ok(out) = output {
            let text = String::from_utf8_lossy(&out.stdout);
            if text.contains("STOPPED") {
                return;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

// ---------------------------------------------------------------------------
// Install / Update / Uninstall — UAC entry points
// ---------------------------------------------------------------------------

/// Install the service. If not elevated, re-launches with UAC via --install-svc.
pub fn install() {
    if !is_elevated() {
        let exe = app::exe_path();
        let exe_w = wide_null(exe);
        // SAFETY: `exe_w` is a valid null-terminated wide string alive for the call.
        // "runas" verb triggers UAC elevation. SW_HIDE is a valid nShowCmd.
        unsafe {
            ShellExecuteW(
                None,
                w!("runas"),
                windows::core::PCWSTR(exe_w.as_ptr()),
                w!("--install-svc"),
                None,
                SW_HIDE,
            );
        }
        return;
    }
    install_service();
}

/// Update the service: stop → replace exe → delete → create → start.
/// If not elevated, re-launches with UAC via --update-svc.
pub fn update() {
    if !is_elevated() {
        let exe = app::exe_path();
        let exe_w = wide_null(exe);
        // SAFETY: Same ShellExecuteW contract as install(). `exe_w` outlives the call.
        unsafe {
            ShellExecuteW(
                None,
                w!("runas"),
                windows::core::PCWSTR(exe_w.as_ptr()),
                w!("--update-svc"),
                None,
                SW_HIDE,
            );
        }
        return;
    }
    update_service();
}

/// Uninstall the service and clean up directories. If not elevated, re-launches with UAC.
pub fn uninstall() {
    if !is_elevated() {
        let exe = app::exe_path();
        let exe_w = wide_null(exe);
        // SAFETY: Same ShellExecuteW contract as install(). `exe_w` outlives the call.
        unsafe {
            ShellExecuteW(
                None,
                w!("runas"),
                windows::core::PCWSTR(exe_w.as_ptr()),
                w!("uninstall"),
                None,
                SW_HIDE,
            );
        }
        return;
    }

    remove_run_key();

    // Kill any tray instances first
    let _ = Command::new("taskkill")
        .args(["/IM", app::EXE_NAME, "/F"])
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    let _ = Command::new("sc")
        .args(["stop", app::SERVICE_NAME])
        .creation_flags(CREATE_NO_WINDOW)
        .status();

    wait_for_service_stopped();

    let _ = Command::new("sc")
        .args(["delete", app::SERVICE_NAME])
        .creation_flags(CREATE_NO_WINDOW)
        .status();

    // Remove install directory (C:\Program Files\HpThermal)
    let install_dir = app::install_dir();
    if std::path::Path::new(install_dir).exists() {
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

/// Copy exe to Program Files, create data dir, register and start the service.
/// Must be called elevated.
pub fn install_service() {
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

    let status = Command::new("sc")
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

    let _ = Command::new("sc")
        .args(["description", app::SERVICE_NAME, app::SERVICE_DESC])
        .creation_flags(CREATE_NO_WINDOW)
        .status();

    let sddl = app::service_sddl();
    let _ = Command::new("sc")
        .args(["sdset", app::SERVICE_NAME, &sddl])
        .creation_flags(CREATE_NO_WINDOW)
        .status();

    let status = Command::new("sc")
        .args(["start", app::SERVICE_NAME])
        .creation_flags(CREATE_NO_WINDOW)
        .status();
    match status {
        Ok(s) if s.success() => eprintln!("Service started."),
        Ok(s) => eprintln!("sc start failed: {}", s),
        Err(e) => eprintln!("Failed to run sc: {}", e),
    }

    set_run_key();
}

/// Stop, replace exe, delete old registration, recreate, start.
/// Must be called elevated.
pub fn update_service() {
    let log = UpdateLog::open();
    log.write("update_service started");
    log.write(&format!("our exe: {}", app::exe_path()));
    log.write(&format!("target:  {}", app::installed_exe()));

    // Ask tray to close gracefully (non-blocking, tray exits in background)
    close_tray_windows();
    log.write("posted WM_CLOSE to tray windows");

    let _ = Command::new("sc")
        .args(["stop", app::SERVICE_NAME])
        .creation_flags(CREATE_NO_WINDOW)
        .status();
    log.write("sc stop issued");

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
        Ok(()) => log.write("copy succeeded"),
        Err(e) => {
            log.write(&format!("COPY FAILED: {e}"));
            return;
        }
    }

    if let Err(e) = ensure_data_dir() {
        log.write(&format!("data dir setup failed: {e}"));
    }

    // No delete+create — binPath is the same, just the file content changed.
    // Avoids ERROR_SERVICE_MARKED_FOR_DELETE (1072) race condition.
    let status = Command::new("sc")
        .args(["start", app::SERVICE_NAME])
        .creation_flags(CREATE_NO_WINDOW)
        .status();
    match status {
        Ok(s) if s.success() => log.write("service started"),
        Ok(s) => log.write(&format!("sc start failed: {s}")),
        Err(e) => log.write(&format!("sc start exec failed: {e}")),
    }

    // Launch the tray from the updated PF binary. The bootstrap process that
    // triggered this update was killed by wait_or_kill_other_instances above,
    // so we're responsible for launching the new tray.
    launch_tray();
    log.write("tray launched — update complete");
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
/// From non-elevated context: spawns directly.
pub fn launch_tray() {
    let exe = app::installed_exe();
    if is_elevated() {
        let _ = Command::new("runas")
            .args(["/trustlevel:0x20000", &format!("\"{}\"", exe)])
            .creation_flags(CREATE_NO_WINDOW)
            .spawn();
    } else {
        let _ = Command::new(&exe).spawn();
    }
}

/// Stop the service. Tries directly (sdset grants rights), elevates as fallback.
pub fn stop() {
    if try_sc(&["stop", app::SERVICE_NAME]) {
        eprintln!("Service stopped.");
        return;
    }
    let exe = app::exe_path();
    let exe_w = wide_null(exe);
    // SAFETY: Same ShellExecuteW contract as install(). `exe_w` outlives the call.
    unsafe {
        ShellExecuteW(
            None,
            w!("runas"),
            windows::core::PCWSTR(exe_w.as_ptr()),
            w!("--stop-svc"),
            None,
            SW_HIDE,
        );
    }
}

/// Internal: stop the service (called from elevated child).
pub fn stop_service() {
    let _ = Command::new("sc")
        .args(["stop", app::SERVICE_NAME])
        .creation_flags(CREATE_NO_WINDOW)
        .status();
    eprintln!("Service stopped.");
}

/// Start the service. Tries directly (sdset grants rights), elevates as fallback.
pub fn start() {
    if try_sc(&["start", app::SERVICE_NAME]) {
        eprintln!("Service started.");
        return;
    }
    let exe = app::exe_path();
    let exe_w = wide_null(exe);
    // SAFETY: Same ShellExecuteW contract as install(). `exe_w` outlives the call.
    unsafe {
        ShellExecuteW(
            None,
            w!("runas"),
            windows::core::PCWSTR(exe_w.as_ptr()),
            w!("--start-svc"),
            None,
            SW_HIDE,
        );
    }
}

/// Internal: start the service (called from elevated child).
pub fn start_service() {
    let status = Command::new("sc")
        .args(["start", app::SERVICE_NAME])
        .creation_flags(CREATE_NO_WINDOW)
        .status();
    match status {
        Ok(s) if s.success() => eprintln!("Service started."),
        Ok(s) => eprintln!("sc start failed: {}", s),
        Err(e) => eprintln!("Failed to run sc: {}", e),
    }
}

/// Try an sc command directly (may succeed if sdset grants rights). Returns true on success.
fn try_sc(args: &[&str]) -> bool {
    Command::new("sc")
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
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
