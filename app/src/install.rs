use std::fs;
use std::os::windows::process::CommandExt;
use std::process::Command;

use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_ABANDONED, WAIT_OBJECT_0};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows::Win32::System::Threading::{
    CreateMutexW, GetCurrentProcess, OpenProcessToken, ReleaseMutex, WaitForSingleObject,
};
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::*;

use crate::app;
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

/// Check if the service is registered (doesn't need elevation).
pub fn is_service_installed() -> bool {
    try_sc(&["query", app::SERVICE_NAME])
}

/// Run `sc query <service>` and return its stdout as text (empty on failure).
fn sc_query_text() -> String {
    Command::new(system32_exe("sc.exe"))
        .args(["query", app::SERVICE_NAME])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// Check if the service is running (STATE = 4 RUNNING).
pub fn is_service_running() -> bool {
    sc_query_text().contains("RUNNING")
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
    let output = Command::new(system32_exe("sc.exe"))
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
        if sc_query_text().contains("STOPPED") {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

// ---------------------------------------------------------------------------
// Install / Update / Uninstall — UAC entry points
// ---------------------------------------------------------------------------

/// Install the service. If not elevated, re-launches with UAC via --install-svc.
pub fn install() {
    elevate_or(w!("--install-svc"), install_service);
}

/// Update the service: stop → replace exe → delete → create → start.
/// If not elevated, re-launches with UAC via --update-svc.
pub fn update() {
    elevate_or(w!("--update-svc"), update_service);
}

/// Uninstall the service and clean up directories. If not elevated, re-launches with UAC.
pub fn uninstall() {
    if !is_elevated() {
        relaunch_elevated(w!("uninstall"));
        return;
    }

    remove_run_key();

    // Kill any tray instances first
    let _ = silent_cmd("taskkill.exe")
        .args(["/IM", app::EXE_NAME, "/F"])
        .status();

    let _ = Command::new(system32_exe("sc.exe"))
        .args(["stop", app::SERVICE_NAME])
        .creation_flags(CREATE_NO_WINDOW)
        .status();

    wait_for_service_stopped();

    let _ = Command::new(system32_exe("sc.exe"))
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

    start_service();
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

    let _ = Command::new(system32_exe("sc.exe"))
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
    match sc_start_status() {
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
        let _ = Command::new(system32_exe("runas.exe"))
            .args(["/trustlevel:0x20000", &format!("\"{}\"", exe)])
            .creation_flags(CREATE_NO_WINDOW)
            .spawn();
    } else {
        let _ = Command::new(&exe).spawn();
    }
}

/// Stop the service. Tries directly (sdset grants rights), elevates as fallback.
/// Re-launch this exe elevated (UAC) with a single internal `--*-svc` argument.
/// Fire-and-forget: the elevated child does the privileged work.
fn relaunch_elevated(arg: windows::core::PCWSTR) {
    let exe_w = wide_null(app::exe_path());
    // SAFETY: `exe_w` is a null-terminated wide string that outlives the call;
    // `arg` is a static `w!()` literal.
    unsafe {
        ShellExecuteW(
            None,
            w!("runas"),
            windows::core::PCWSTR(exe_w.as_ptr()),
            arg,
            None,
            SW_HIDE,
        );
    }
}

/// If not elevated, re-launch elevated with `arg` (UAC) and return; otherwise run
/// `work` in-process. The relaunch-or-run preamble shared by install/update.
fn elevate_or(arg: windows::core::PCWSTR, work: impl FnOnce()) {
    if !is_elevated() {
        relaunch_elevated(arg);
        return;
    }
    work();
}

pub fn stop() {
    if try_sc(&["stop", app::SERVICE_NAME]) {
        eprintln!("Service stopped.");
        return;
    }
    relaunch_elevated(w!("--stop-svc"));
}

/// Internal: stop the service (called from elevated child).
pub fn stop_service() {
    let _ = Command::new(system32_exe("sc.exe"))
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
    relaunch_elevated(w!("--start-svc"));
}

/// Run `sc start <service>` and return the raw status. Shared by the CLI and
/// update paths, which report the result differently (stderr vs UpdateLog).
fn sc_start_status() -> std::io::Result<std::process::ExitStatus> {
    Command::new(system32_exe("sc.exe"))
        .args(["start", app::SERVICE_NAME])
        .creation_flags(CREATE_NO_WINDOW)
        .status()
}

/// Internal: start the service (called from elevated child).
pub fn start_service() {
    match sc_start_status() {
        Ok(s) if s.success() => eprintln!("Service started."),
        Ok(s) => eprintln!("sc start failed: {}", s),
        Err(e) => eprintln!("Failed to run sc: {}", e),
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
    let dir = if len > 0 && len < buf.len() {
        String::from_utf16_lossy(&buf[..len])
    } else {
        // Last-resort fallback; %SystemRoot% is effectively always C:\Windows.
        r"C:\Windows\System32".to_string()
    };
    std::path::Path::new(&dir).join(name)
}

/// A `Command` for a System32 tool that runs without a console window and
/// discards stdio. `program` is a bare exe name, e.g. `"sc.exe"`.
fn silent_cmd(program: &str) -> Command {
    let mut cmd = Command::new(system32_exe(program));
    cmd.creation_flags(CREATE_NO_WINDOW)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    cmd
}

/// Try an sc command directly (may succeed if sdset grants rights). Returns true on success.
fn try_sc(args: &[&str]) -> bool {
    silent_cmd("sc.exe")
        .args(args)
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

#[cfg(test)]
mod tests {
    use super::*;

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
