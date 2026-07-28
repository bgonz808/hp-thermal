//! `vsa-spike` (#61) — DEV-ONLY empirical test: can `HpThermalService` drive the HP BIOS
//! under a **virtual service account** (`NT SERVICE\HpThermalService`) instead of LocalSystem?
//!
//! It reconfigures the live service's identity, lets you exercise it, and AUTO-REVERTS. This
//! is a privileged, destructive-if-abused operation, which is why it lives only in xtask (dev
//! tooling, never in the release binary) — see #61. Safety model:
//!   - the original `ObjectName` is persisted to a snapshot file BEFORE any change, and
//!   - a typed `RevertGuard` restores it on every normal/`?`/panic exit (xtask unwinds), and
//!   - `--recover` restores from the snapshot file if a run was ever hard-killed.
//!
//! SCM is driven via advapi32 FFI (not `sc.exe`) to keep xtask's "no shell" invariant and be
//! locale-independent. Run from an ELEVATED shell (`SERVICE_CHANGE_CONFIG` needs admin).

use std::io::Write;

const SERVICE_NAME: &str = "HpThermalService";
const VIRTUAL_ACCOUNT: &str = "NT SERVICE\\HpThermalService";
const LOG_PATH: &str = r"C:\ProgramData\HpThermal\hp-thermal.log";
const SNAPSHOT_PATH: &str = r"C:\ProgramData\HpThermal\vsa-spike.snapshot";

// --- SCM constants ---
const SC_MANAGER_CONNECT: u32 = 0x0001;
const SERVICE_QUERY_CONFIG: u32 = 0x0001;
const SERVICE_CHANGE_CONFIG: u32 = 0x0002;
const SERVICE_QUERY_STATUS: u32 = 0x0004;
const SERVICE_START: u32 = 0x0010;
const SERVICE_STOP: u32 = 0x0020;
const SERVICE_NO_CHANGE: u32 = 0xFFFF_FFFF;
const SERVICE_CONTROL_STOP: u32 = 0x0000_0001;
const SERVICE_RUNNING: u32 = 0x0000_0004;
const SERVICE_STOPPED: u32 = 0x0000_0001;
const ERROR_ACCESS_DENIED: u32 = 5;

type ScHandle = isize;

#[repr(C)]
struct ServiceStatus {
    dw_service_type: u32,
    dw_current_state: u32,
    dw_controls_accepted: u32,
    dw_win32_exit_code: u32,
    dw_service_specific_exit_code: u32,
    dw_check_point: u32,
    dw_wait_hint: u32,
}

#[repr(C)]
struct QueryServiceConfigW {
    dw_service_type: u32,
    dw_start_type: u32,
    dw_error_control: u32,
    lp_binary_path_name: *const u16,
    lp_load_order_group: *const u16,
    dw_tag_id: u32,
    lp_dependencies: *const u16,
    lp_service_start_name: *const u16,
    lp_display_name: *const u16,
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenSCManagerW(machine: *const u16, database: *const u16, access: u32) -> ScHandle;
    fn OpenServiceW(scm: ScHandle, name: *const u16, access: u32) -> ScHandle;
    fn QueryServiceConfigW(svc: ScHandle, cfg: *mut u8, buf: u32, needed: *mut u32) -> i32;
    #[allow(clippy::too_many_arguments)]
    fn ChangeServiceConfigW(
        svc: ScHandle,
        service_type: u32,
        start_type: u32,
        error_control: u32,
        binary_path: *const u16,
        load_order_group: *const u16,
        tag_id: *mut u32,
        dependencies: *const u16,
        start_name: *const u16,
        password: *const u16,
        display_name: *const u16,
    ) -> i32;
    fn ControlService(svc: ScHandle, control: u32, status: *mut ServiceStatus) -> i32;
    fn StartServiceW(svc: ScHandle, argc: u32, argv: *const *const u16) -> i32;
    fn QueryServiceStatus(svc: ScHandle, status: *mut ServiceStatus) -> i32;
    fn CloseServiceHandle(handle: ScHandle) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetLastError() -> u32;
    fn Sleep(ms: u32);
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Read a null-terminated wide string from a raw pointer (or "" if null).
///
/// # Safety
/// `p` must be null or point to a valid null-terminated UTF-16 string.
unsafe fn read_wide(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    // SAFETY: caller guarantees a null-terminated string at `p`.
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `len` wchars are valid per the scan above.
    let slice = unsafe { std::slice::from_raw_parts(p, len) };
    String::from_utf16_lossy(slice)
}

/// Open the service with everything the spike needs. `None` (with a printed hint) if the SCM
/// or the service can't be opened — most often ACCESS_DENIED from a non-elevated shell.
fn open_service() -> Option<(ScHandle, ScHandle)> {
    let access = SERVICE_QUERY_CONFIG
        | SERVICE_CHANGE_CONFIG
        | SERVICE_QUERY_STATUS
        | SERVICE_START
        | SERVICE_STOP;
    // SAFETY: FFI with valid wide strings; handles are checked and closed by the caller.
    unsafe {
        let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
        if scm == 0 {
            let e = GetLastError();
            eprintln!("vsa-spike: OpenSCManager failed (err {e})");
            if e == ERROR_ACCESS_DENIED {
                eprintln!("  run this from an ELEVATED shell (SERVICE_CHANGE_CONFIG needs admin).");
            }
            return None;
        }
        let name = wide(SERVICE_NAME);
        let svc = OpenServiceW(scm, name.as_ptr(), access);
        if svc == 0 {
            let e = GetLastError();
            eprintln!("vsa-spike: OpenService({SERVICE_NAME}) failed (err {e})");
            if e == ERROR_ACCESS_DENIED {
                eprintln!("  run this from an ELEVATED shell.");
            }
            CloseServiceHandle(scm);
            return None;
        }
        Some((scm, svc))
    }
}

/// Read the service's current `ObjectName` (start account).
fn query_start_name(svc: ScHandle) -> Option<String> {
    // SAFETY: two-call size-then-fill pattern; the returned pointers point inside `buf`.
    unsafe {
        let mut needed = 0u32;
        // First call sizes the buffer (expected to "fail" with ERROR_INSUFFICIENT_BUFFER).
        QueryServiceConfigW(svc, std::ptr::null_mut(), 0, &mut needed);
        if needed == 0 {
            eprintln!(
                "vsa-spike: QueryServiceConfig sizing failed (err {})",
                GetLastError()
            );
            return None;
        }
        let mut buf = vec![0u8; needed as usize];
        if QueryServiceConfigW(svc, buf.as_mut_ptr(), needed, &mut needed) == 0 {
            eprintln!(
                "vsa-spike: QueryServiceConfig failed (err {})",
                GetLastError()
            );
            return None;
        }
        let cfg = &*(buf.as_ptr() as *const QueryServiceConfigW);
        Some(read_wide(cfg.lp_service_start_name))
    }
}

/// Set the service's `ObjectName` (start account) with a **NULL password** — everything else
/// unchanged. This spike only ever targets *passwordless* accounts (the virtual account and
/// LocalSystem), and a managed/virtual account REQUIRES a NULL password (an empty string yields
/// ERROR_INVALID_SERVICE_ACCOUNT, 1057). There is deliberately no password parameter — nothing
/// here handles a secret. MS Learn: ChangeServiceConfig.
fn set_start_name(svc: ScHandle, account: &str) -> bool {
    let acct = wide(account);
    // SAFETY: SERVICE_NO_CHANGE + null pointers leave all other config fields untouched; the
    // NULL password is required for the passwordless virtual/built-in accounts we set.
    unsafe {
        let ok = ChangeServiceConfigW(
            svc,
            SERVICE_NO_CHANGE,
            SERVICE_NO_CHANGE,
            SERVICE_NO_CHANGE,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            acct.as_ptr(),
            std::ptr::null(), // NULL password: passwordless (virtual/built-in) account
            std::ptr::null(),
        );
        if ok == 0 {
            eprintln!(
                "vsa-spike: ChangeServiceConfig(->{account}) failed (err {})",
                GetLastError()
            );
        }
        ok != 0
    }
}

fn current_state(svc: ScHandle) -> u32 {
    let mut st = zeroed_status();
    // SAFETY: `st` is a valid ServiceStatus; QueryServiceStatus only writes to it.
    unsafe {
        if QueryServiceStatus(svc, &mut st) == 0 {
            return 0;
        }
    }
    st.dw_current_state
}

fn zeroed_status() -> ServiceStatus {
    ServiceStatus {
        dw_service_type: 0,
        dw_current_state: 0,
        dw_controls_accepted: 0,
        dw_win32_exit_code: 0,
        dw_service_specific_exit_code: 0,
        dw_check_point: 0,
        dw_wait_hint: 0,
    }
}

/// Poll the service state until it reaches `target` or ~10s elapse.
fn wait_state(svc: ScHandle, target: u32) -> bool {
    for _ in 0..50 {
        if current_state(svc) == target {
            return true;
        }
        // SAFETY: Sleep has no preconditions.
        unsafe { Sleep(200) };
    }
    current_state(svc) == target
}

/// Stop (if running) then start the service; returns true if it reaches RUNNING.
fn restart(svc: ScHandle) -> bool {
    // SAFETY: FFI on a valid service handle; status structs are owned locals.
    unsafe {
        if current_state(svc) != SERVICE_STOPPED {
            let mut st = zeroed_status();
            ControlService(svc, SERVICE_CONTROL_STOP, &mut st);
            wait_state(svc, SERVICE_STOPPED);
        }
        StartServiceW(svc, 0, std::ptr::null());
    }
    wait_state(svc, SERVICE_RUNNING)
}

/// Typed auto-revert: restores the captured `ObjectName` and restarts on drop, then removes
/// the snapshot file. `disarm()` is called once the revert has been done explicitly.
struct RevertGuard {
    svc: ScHandle,
    original: String,
    armed: bool,
}

impl RevertGuard {
    fn revert(&mut self) {
        if !self.armed {
            return;
        }
        self.armed = false;
        eprintln!("\nvsa-spike: reverting ObjectName -> {}", self.original);
        set_start_name(self.svc, &self.original);
        restart(self.svc);
        let _ = std::fs::remove_file(SNAPSHOT_PATH);
        eprintln!("vsa-spike: reverted and restarted.");
    }
}

impl Drop for RevertGuard {
    fn drop(&mut self) {
        self.revert();
    }
}

fn print_log_tail(lines: usize) {
    match std::fs::read_to_string(LOG_PATH) {
        Ok(s) => {
            let all: Vec<&str> = s.lines().collect();
            let start = all.len().saturating_sub(lines);
            eprintln!("\n--- service log tail ({LOG_PATH}) ---");
            for l in &all[start..] {
                eprintln!("  {l}");
            }
            eprintln!("--- end log ---");
        }
        Err(e) => eprintln!("vsa-spike: could not read log {LOG_PATH} ({e})"),
    }
}

/// `--recover`: if a snapshot exists (a prior run was interrupted), restore it.
fn recover(svc: ScHandle) -> i32 {
    match std::fs::read_to_string(SNAPSHOT_PATH) {
        Ok(orig) => {
            let orig = orig.trim();
            eprintln!("vsa-spike: recovering ObjectName -> {orig}");
            set_start_name(svc, orig);
            restart(svc);
            let _ = std::fs::remove_file(SNAPSHOT_PATH);
            eprintln!("vsa-spike: recovered.");
            0
        }
        Err(_) => {
            eprintln!("vsa-spike: no snapshot at {SNAPSHOT_PATH} — nothing to recover.");
            0
        }
    }
}

pub fn run(args: &[String]) -> i32 {
    let Some((scm, svc)) = open_service() else {
        return 1;
    };
    // SAFETY: `scm`/`svc` are valid handles from open_service; closed on every return path
    // below. (The service handle is used by the guard's Drop, which runs before these close
    // because the guard is dropped at end of scope, before `close`.)
    let close = || unsafe {
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
    };

    if args.iter().any(|a| a == "--recover") {
        let code = recover(svc);
        close();
        return code;
    }

    let Some(original) = query_start_name(svc) else {
        close();
        return 1;
    };
    eprintln!("vsa-spike: current ObjectName = {original}");
    if original.eq_ignore_ascii_case(VIRTUAL_ACCOUNT) {
        eprintln!(
            "vsa-spike: already the virtual account — did a prior run not revert? try --recover."
        );
        close();
        return 1;
    }

    // Persist the snapshot BEFORE mutating, so an interrupted run is recoverable.
    if let Err(e) = std::fs::write(SNAPSHOT_PATH, &original) {
        eprintln!(
            "vsa-spike: cannot write snapshot {SNAPSHOT_PATH} ({e}) — aborting (unsafe without it)."
        );
        close();
        return 1;
    }

    let mut guard = RevertGuard {
        svc,
        original: original.clone(),
        armed: true,
    };

    eprintln!("vsa-spike: reconfiguring ObjectName -> {VIRTUAL_ACCOUNT}");
    if !set_start_name(svc, VIRTUAL_ACCOUNT) {
        guard.revert(); // undo (nothing took effect, but keep the invariant)
        close();
        return 1;
    }

    eprintln!("vsa-spike: restarting service as the virtual account...");
    let running = restart(svc);
    if running {
        eprintln!("vsa-spike: service reached RUNNING as {VIRTUAL_ACCOUNT}.");
    } else {
        eprintln!(
            "vsa-spike: service did NOT reach RUNNING (state={}) — VSA likely can't start it.",
            current_state(svc)
        );
    }
    print_log_tail(25);

    eprintln!(
        "\nvsa-spike: EXERCISE NOW — toggle a thermal mode (fans should change) and press Fn+F12."
    );
    eprintln!("           Watch whether the BIOS call succeeds. Then press ENTER to revert.");
    let mut _line = String::new();
    let _ = std::io::stdout().flush();
    let _ = std::io::stdin().read_line(&mut _line);

    print_log_tail(15);
    guard.revert(); // explicit; Drop would also do it
    close();
    if running { 0 } else { 2 }
}
