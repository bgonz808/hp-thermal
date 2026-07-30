use std::sync::atomic::{AtomicIsize, Ordering};
use std::time::Instant;

use windows::Win32::Foundation::*;
use windows::Win32::Security::Authorization::*;
use windows::Win32::Security::*;
use windows::Win32::System::Services::*;
use windows::Win32::System::Threading::*;
use windows::core::{PCWSTR, PWSTR, w};

use crate::app;
use crate::log;
use crate::pipe;
use crate::protocol::*;
use crate::wide::wide_null;
use crate::wmi_com::WmiConnection;

static STOP_EVENT: AtomicIsize = AtomicIsize::new(0);
static STATUS_HANDLE: AtomicIsize = AtomicIsize::new(0);

pub fn run() {
    // SAFETY: The SERVICE_TABLE_ENTRYW array is null-terminated and lives on the
    // stack for the duration of StartServiceCtrlDispatcherW. name_buf is a
    // null-terminated wide string that outlives the call.
    unsafe {
        let mut name_buf = wide_null(app::SERVICE_NAME);
        let table = [
            SERVICE_TABLE_ENTRYW {
                lpServiceName: PWSTR(name_buf.as_mut_ptr()),
                lpServiceProc: Some(service_main),
            },
            SERVICE_TABLE_ENTRYW {
                lpServiceName: PWSTR(std::ptr::null_mut()),
                lpServiceProc: None,
            },
        ];
        let _ = StartServiceCtrlDispatcherW(table.as_ptr());
    }
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut PWSTR) {
    let svc_name = wide_null(app::SERVICE_NAME);
    let Ok(handle) = RegisterServiceCtrlHandlerW(PCWSTR(svc_name.as_ptr()), Some(ctrl_handler))
    else {
        return;
    };
    STATUS_HANDLE.store(handle.0 as isize, Ordering::SeqCst);

    set_status(SERVICE_START_PENDING, 0);
    log::init("svc");
    log::install_stack_guard();
    log::etw_register("svc");
    log::write("service starting");
    log::write(&format!("build: {}", app::build_identity()));

    // Fail-closed footing check. The SYSTEM service must run from its admin-only-write
    // install directory (Program Files) AND at System/High integrity. If either is false,
    // the trust model (a lower-privileged user cannot tamper the image or stand in for the
    // service) no longer holds, so refuse to do any privileged WMI work.
    if !crate::install::running_from_install_dir() {
        log::error("REFUSING: not running from the install directory");
        set_status(SERVICE_STOPPED, 4);
        return;
    }
    if !crate::install::image_write_restricted() {
        log::error("REFUSING: install image is writable by a non-privileged principal");
        set_status(SERVICE_STOPPED, 5);
        return;
    }
    if !crate::pipe::own_process_is_privileged() {
        log::error("REFUSING: not at System/High integrity");
        set_status(SERVICE_STOPPED, 6);
        return;
    }
    log::write("footing verified: install dir + write-restricted image + privileged");

    // #2: enforce the least-privilege token at runtime — a backstop to the DECLARATIVE
    // SERVICE_REQUIRED_PRIVILEGES (#39). Remove anything beyond the intended set, then assert
    // none survive. Normal case: the SCM already applied the required-privileges set, so this
    // removes 0. A non-zero `extras` means the token could not be reduced to the intended set
    // (a broken/tampered install running over-privileged) — refuse, consistent with the
    // fail-closed footing checks above.
    {
        let keep = [
            w!("SeChangeNotifyPrivilege"),
            w!("SeCreateGlobalPrivilege"),
            w!("SeImpersonatePrivilege"),
        ];
        let (removed, extras) = crate::mitigations::strip_token_privileges_except(&keep);
        log::write(&format!(
            "token self-assert: removed {removed} extra privilege(s), {extras} beyond-set remain"
        ));
        if extras > 0 {
            log::error("REFUSING: token retains privileges beyond the least-privilege set");
            set_status(SERVICE_STOPPED, 7);
            return;
        }
    }

    let Ok(event) = CreateEventW(None, true, false, None) else {
        log::error("FAIL: CreateEventW");
        set_status(SERVICE_STOPPED, 1);
        return;
    };
    STOP_EVENT.store(event.0 as isize, Ordering::SeqCst);

    // Initialize WMI connection
    let wmi = match WmiConnection::connect() {
        Ok(w) => {
            log::write("WMI connected");
            w
        }
        Err(e) => {
            log::error(&format!("FAIL: WMI connect error=0x{e:02X}"));
            set_status(SERVICE_STOPPED, 2);
            return;
        }
    };

    // Create named pipe
    let pipe = match pipe::server_create() {
        Ok(p) => {
            log::write("pipe created");
            p
        }
        Err(e) => {
            log::error(&format!("FAIL: pipe create {e:?}"));
            set_status(SERVICE_STOPPED, 3);
            return;
        }
    };

    // Subscribe to hpqBEvnt (push-based async sink, zero idle cost). Held for
    // the service lifetime; dropped after the accept loop to cancel cleanly.
    // Non-fatal: on failure the service still runs, just without the hotkey.
    let event_sub = match create_fn_key_event() {
        Some(fn_key) => match wmi.subscribe_events(fn_key) {
            Ok(sub) => Some(sub),
            Err(_) => {
                log::warn("event listener: subscription failed (hotkey disabled)");
                // SAFETY: fn_key is a valid handle we still own on this error path.
                unsafe {
                    let _ = CloseHandle(fn_key);
                }
                None
            }
        },
        None => {
            log::warn("event listener: named event creation failed (hotkey disabled)");
            None
        }
    };

    set_status(SERVICE_RUNNING, 0);
    log::stack_sample("svc:init");

    // Signal the svc-start event so the tray can detect a version mismatch
    // (service binary updated while tray was still running in memory).
    signal_svc_start_event();

    let mut cache = CacheSet::new();

    // Accept loop
    loop {
        if !pipe::server_wait(pipe, event) {
            break; // stop event signaled
        }

        // Validate client identity
        if !pipe::server_validate_client(pipe) {
            pipe::server_disconnect(pipe);
            continue;
        }

        // Read 4-byte request (magic prefix + command + payload)
        if let Some(buf) = pipe::read_request(pipe) {
            log::trace!(log::KW_WIRE, "req: 0x{:02X} 0x{:02X}", buf[0], buf[1]);
            let response = match Request::try_from(buf) {
                Ok(req) => dispatch(&wmi, &mut cache, &req),
                Err(status) => [status, 0],
            };
            log::trace!(
                log::KW_WIRE,
                "rsp: 0x{:02X} 0x{:02X}",
                response[0],
                response[1]
            );
            pipe::write2(pipe, &response);
        }

        pipe::server_disconnect(pipe);
    }

    // Cancel the async event sink before teardown: CancelAsyncCall guarantees no
    // further callbacks, then the handle is released and "cancelled" is logged.
    drop(event_sub);

    // Dump histogram on shutdown
    log::write(&log::stack_report());
    let _ = CloseHandle(pipe);
    set_status(SERVICE_STOPPED, 0);
}

/// Per-command read cache. Returns cached value with STATUS_CACHED flag
/// when called faster than the cooldown period.
#[derive(Clone, Copy)]
struct ReadCache {
    value: [u8; 2],
    when: Instant,
}

struct CacheSet {
    thermal: Option<ReadCache>,
    coolsense: Option<ReadCache>,
    temp: Option<ReadCache>,
}

// Cooldowns in milliseconds
const COOLDOWN_THERMAL_MS: u128 = 100;
const COOLDOWN_COOLSENSE_MS: u128 = 100;
const COOLDOWN_TEMP_MS: u128 = 500;

impl CacheSet {
    fn new() -> Self {
        Self {
            thermal: None,
            coolsense: None,
            temp: None,
        }
    }

    fn cached_read(
        slot: &mut Option<ReadCache>,
        cooldown_ms: u128,
        fetch: impl FnOnce() -> [u8; 2],
    ) -> [u8; 2] {
        if let Some(c) = slot
            && c.when.elapsed().as_millis() < cooldown_ms
            && c.value[0] == STATUS_OK
        {
            return [STATUS_OK | STATUS_CACHED, c.value[1]];
        }
        let result = fetch();
        if result[0] == STATUS_OK {
            *slot = Some(ReadCache {
                value: result,
                when: Instant::now(),
            });
        }
        result
    }
}

/// The WMI/BIOS operations `dispatch` needs, abstracted behind a trait so the
/// command-routing and caching logic can be unit-tested with a mock in place of
/// live COM. `WmiConnection` is the production implementation; each method here
/// forwards to the inherent method of the same name (inherent methods take path
/// resolution priority, so there is no recursion).
trait ThermalOps {
    fn read_thermal(&self) -> Result<u8, u8>;
    fn set_thermal(&self, mode: u8) -> Result<(), u8>;
    fn read_coolsense(&self) -> Result<u8, u8>;
    fn set_coolsense(&self, on: u8) -> Result<(), u8>;
    fn read_temp(&self) -> Result<u8, u8>;
    fn read_brightness(&self) -> Result<u8, u8>;
    fn set_brightness(&self, level: u8) -> Result<(), u8>;
}

impl ThermalOps for WmiConnection {
    fn read_thermal(&self) -> Result<u8, u8> {
        WmiConnection::read_thermal(self)
    }
    fn set_thermal(&self, mode: u8) -> Result<(), u8> {
        WmiConnection::set_thermal(self, mode)
    }
    fn read_coolsense(&self) -> Result<u8, u8> {
        WmiConnection::read_coolsense(self)
    }
    fn set_coolsense(&self, on: u8) -> Result<(), u8> {
        WmiConnection::set_coolsense(self, on)
    }
    fn read_temp(&self) -> Result<u8, u8> {
        WmiConnection::read_temp(self)
    }
    fn read_brightness(&self) -> Result<u8, u8> {
        WmiConnection::read_brightness(self)
    }
    fn set_brightness(&self, level: u8) -> Result<(), u8> {
        WmiConnection::set_brightness(self, level)
    }
}

/// Map a read result to the 2-byte wire response (`[STATUS_OK, value]` / `[err, 0]`).
fn read_result(r: Result<u8, u8>) -> [u8; 2] {
    match r {
        Ok(v) => [STATUS_OK, v],
        Err(e) => [e, 0],
    }
}

/// Map a set/write result to the 2-byte wire response.
fn set_result(r: Result<(), u8>) -> [u8; 2] {
    match r {
        Ok(()) => [STATUS_OK, 0],
        Err(e) => [e, 0],
    }
}

fn dispatch<W: ThermalOps>(wmi: &W, cache: &mut CacheSet, req: &Request) -> [u8; 2] {
    let result = match req.command {
        CMD_READ_THERMAL => CacheSet::cached_read(&mut cache.thermal, COOLDOWN_THERMAL_MS, || {
            read_result(wmi.read_thermal())
        }),
        CMD_SET_THERMAL => {
            log::write(&format!("set thermal mode={}", req.payload));
            cache.thermal = None;
            set_result(wmi.set_thermal(req.payload))
        }
        CMD_READ_COOLSENSE => {
            CacheSet::cached_read(&mut cache.coolsense, COOLDOWN_COOLSENSE_MS, || {
                read_result(wmi.read_coolsense())
            })
        }
        CMD_SET_COOLSENSE => {
            log::write(&format!("set coolsense={}", req.payload));
            cache.coolsense = None;
            set_result(wmi.set_coolsense(req.payload))
        }
        CMD_READ_STATE => {
            // #69: thermal + coolsense in ONE response. Each still honors its own
            // cache/cooldown; both must succeed. The cached bit is set only when BOTH
            // reads were served from cache (informational; status_ok ignores it).
            let t = CacheSet::cached_read(&mut cache.thermal, COOLDOWN_THERMAL_MS, || {
                read_result(wmi.read_thermal())
            });
            let c = CacheSet::cached_read(&mut cache.coolsense, COOLDOWN_COOLSENSE_MS, || {
                read_result(wmi.read_coolsense())
            });
            if status_ok(t[0]) && status_ok(c[0]) {
                [
                    STATUS_OK | (t[0] & c[0] & STATUS_CACHED),
                    pack_state(t[1], c[1]),
                ]
            } else if !status_ok(t[0]) {
                [t[0], 0]
            } else {
                [c[0], 0]
            }
        }
        CMD_READ_TEMP => CacheSet::cached_read(&mut cache.temp, COOLDOWN_TEMP_MS, || {
            read_result(wmi.read_temp())
        }),
        CMD_SET_STACK_MONITOR => {
            log::set_stack_monitor(req.payload != 0);
            [STATUS_OK, 0]
        }
        CMD_READ_BUILD_ID => BUILD_FINGERPRINT,
        CMD_READ_BRIGHTNESS => read_result(wmi.read_brightness()),
        CMD_SET_BRIGHTNESS => {
            log::write(&format!("set brightness={}", req.payload));
            set_result(wmi.set_brightness(req.payload))
        }
        _ => [STATUS_INVALID_CMD, 0],
    };

    // Sample stack after WMI call (committed pages still reflect the peak depth)
    let label = match req.command {
        CMD_READ_THERMAL => "svc:read_thermal",
        CMD_SET_THERMAL => "svc:set_thermal",
        CMD_READ_COOLSENSE => "svc:read_coolsense",
        CMD_SET_COOLSENSE => "svc:set_coolsense",
        CMD_READ_STATE => "svc:read_state",
        _ => "svc:other",
    };
    log::stack_sample(label);

    result
}

unsafe extern "system" fn ctrl_handler(control: u32) {
    if control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN {
        set_status(SERVICE_STOP_PENDING, 0);
        let ev = HANDLE(STOP_EVENT.load(Ordering::SeqCst) as *mut std::ffi::c_void);
        if !ev.is_invalid() {
            let _ = SetEvent(ev);
        }
    }
}

fn set_status(state: SERVICE_STATUS_CURRENT_STATE, exit_code: u32) {
    let handle =
        SERVICE_STATUS_HANDLE(STATUS_HANDLE.load(Ordering::SeqCst) as *mut std::ffi::c_void);
    if handle.is_invalid() {
        return;
    }
    let accepts = if state == SERVICE_RUNNING {
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
    } else {
        SERVICE_ACCEPT_STOP
    };
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: accepts,
        dwWin32ExitCode: if exit_code != 0 {
            ERROR_SERVICE_SPECIFIC_ERROR.0
        } else {
            0
        },
        dwServiceSpecificExitCode: exit_code,
        dwCheckPoint: 0,
        dwWaitHint: 0,
    };
    // SAFETY: `handle` was obtained from RegisterServiceCtrlHandlerW and stored
    // atomically; the SERVICE_STATUS struct is fully initialized on the stack.
    unsafe {
        let _ = SetServiceStatus(handle, &status);
    }
}

/// Create a named auto-reset event with the shared DACL and return its handle
/// (the caller keeps or leaks it). Returns None on failure.
///
/// Explicit specific rights — generic GR/GA store the generic bit in the ACE,
/// which causes ACCESS_DENIED when the tray requests SYNCHRONIZE (a specific
/// right) via OpenEventW.
///   BU: SYNCHRONIZE|READ_CONTROL (0x00120000) — wait only, cannot signal
///   SY/BA: EVENT_ALL_ACCESS (0x001F0003) — full control
fn create_named_event(name: &str) -> Option<HANDLE> {
    // SAFETY: Stack-allocated SD freed via LocalFree; the wide event name outlives
    // the CreateEventW call.
    unsafe {
        let sddl = w!("D:(A;;0x00120000;;;BU)(A;;0x001F0003;;;SY)(A;;0x001F0003;;;BA)");
        let mut sd: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, &mut sd, None).is_err() {
            log::warn(&format!("named event {name}: SDDL parse failed"));
            return None;
        }

        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: false.into(),
        };

        // Auto-reset (bManualReset=false): resets after one waiter is released.
        let wname = wide_null(name);
        let event = CreateEventW(Some(&sa), false, false, PCWSTR(wname.as_ptr()));
        LocalFree(Some(HLOCAL(sd.0)));

        match event {
            Ok(h) => Some(h),
            Err(e) => {
                log::warn(&format!("named event {name}: CreateEventW failed: {e}"));
                None
            }
        }
    }
}

/// Create and signal the svc-start event. The tray waits on this to detect that
/// the service (re)started, then checks BUILD_FINGERPRINT via the pipe. Handle
/// is intentionally leaked — lives for the service process lifetime, and the
/// tray's OpenEventW resolves to this same kernel object.
fn signal_svc_start_event() {
    if let Some(h) = create_named_event(app::SVC_START_EVENT) {
        // SAFETY: `h` is a valid auto-reset event handle.
        unsafe {
            let _ = SetEvent(h);
        }
        log::write("svc-start event: signaled");
    }
}

/// Create the Fn+F12 named event the tray waits on.
fn create_fn_key_event() -> Option<HANDLE> {
    create_named_event(app::FNKEY_EVENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// In-memory stand-in for the WMI/BIOS layer. Records read-call counts so
    /// tests can assert the cache actually suppresses redundant WMI reads.
    #[derive(Default)]
    struct MockWmi {
        thermal: Cell<u8>,
        coolsense: Cell<u8>,
        temp: Cell<u8>,
        brightness: Cell<u8>,
        fail: Cell<bool>,
        read_thermal_calls: Cell<u32>,
        read_coolsense_calls: Cell<u32>,
        read_temp_calls: Cell<u32>,
    }

    impl ThermalOps for MockWmi {
        fn read_thermal(&self) -> Result<u8, u8> {
            self.read_thermal_calls
                .set(self.read_thermal_calls.get() + 1);
            if self.fail.get() {
                Err(STATUS_WMI_ERROR)
            } else {
                Ok(self.thermal.get())
            }
        }
        fn set_thermal(&self, mode: u8) -> Result<(), u8> {
            self.thermal.set(mode);
            Ok(())
        }
        fn read_coolsense(&self) -> Result<u8, u8> {
            self.read_coolsense_calls
                .set(self.read_coolsense_calls.get() + 1);
            Ok(self.coolsense.get())
        }
        fn set_coolsense(&self, on: u8) -> Result<(), u8> {
            self.coolsense.set(on);
            Ok(())
        }
        fn read_temp(&self) -> Result<u8, u8> {
            self.read_temp_calls.set(self.read_temp_calls.get() + 1);
            Ok(self.temp.get())
        }
        fn read_brightness(&self) -> Result<u8, u8> {
            Ok(self.brightness.get())
        }
        fn set_brightness(&self, level: u8) -> Result<(), u8> {
            self.brightness.set(level);
            Ok(())
        }
    }

    fn req(cmd: u8, payload: u8) -> Request {
        Request::try_from([cmd, payload]).expect("valid request")
    }

    #[test]
    fn read_thermal_returns_mode_then_serves_from_cache() {
        let wmi = MockWmi::default();
        wmi.thermal.set(2);
        let mut cache = CacheSet::new();

        // First read hits WMI.
        assert_eq!(
            dispatch(&wmi, &mut cache, &req(CMD_READ_THERMAL, 0)),
            [STATUS_OK, 2]
        );
        assert_eq!(wmi.read_thermal_calls.get(), 1);

        // Second read within the cooldown is served from cache (flagged), no WMI.
        let r2 = dispatch(&wmi, &mut cache, &req(CMD_READ_THERMAL, 0));
        assert_eq!(r2[0], STATUS_OK | STATUS_CACHED);
        assert_eq!(r2[1], 2);
        assert_eq!(
            wmi.read_thermal_calls.get(),
            1,
            "cache must suppress the second WMI read"
        );
    }

    #[test]
    fn read_state_batches_thermal_and_coolsense() {
        let wmi = MockWmi::default();
        wmi.thermal.set(2);
        wmi.coolsense.set(1);
        let mut cache = CacheSet::new();

        let r = dispatch(&wmi, &mut cache, &req(CMD_READ_STATE, 0));
        assert!(status_ok(r[0]), "batched read should succeed");
        assert_eq!(unpack_state(r[1]), (2, 1), "packed thermal=2, coolsense=1");
        // One WMI read of each, combined into a single response.
        assert_eq!(wmi.read_thermal_calls.get(), 1);
        assert_eq!(wmi.read_coolsense_calls.get(), 1);
    }

    #[test]
    fn read_state_propagates_wmi_error() {
        let wmi = MockWmi::default();
        wmi.fail.set(true); // read_thermal fails
        let mut cache = CacheSet::new();
        assert_eq!(
            dispatch(&wmi, &mut cache, &req(CMD_READ_STATE, 0)),
            [STATUS_WMI_ERROR, 0],
            "a failed sub-read propagates as an error, not a partial packed value",
        );
    }

    #[test]
    fn set_thermal_invalidates_the_read_cache() {
        let wmi = MockWmi::default();
        wmi.thermal.set(1);
        let mut cache = CacheSet::new();

        let _ = dispatch(&wmi, &mut cache, &req(CMD_READ_THERMAL, 0)); // populate cache
        assert_eq!(wmi.read_thermal_calls.get(), 1);

        assert_eq!(
            dispatch(&wmi, &mut cache, &req(CMD_SET_THERMAL, 3)),
            [STATUS_OK, 0]
        );
        assert_eq!(wmi.thermal.get(), 3);

        // The next read must go back to WMI and reflect the new value.
        assert_eq!(
            dispatch(&wmi, &mut cache, &req(CMD_READ_THERMAL, 0)),
            [STATUS_OK, 3]
        );
        assert_eq!(
            wmi.read_thermal_calls.get(),
            2,
            "a write must invalidate the read cache"
        );
    }

    #[test]
    fn wmi_error_is_propagated_and_not_cached() {
        let wmi = MockWmi::default();
        wmi.fail.set(true);
        let mut cache = CacheSet::new();

        assert_eq!(
            dispatch(&wmi, &mut cache, &req(CMD_READ_THERMAL, 0)),
            [STATUS_WMI_ERROR, 0]
        );
        // An error must not populate the cache — the next call retries WMI.
        let _ = dispatch(&wmi, &mut cache, &req(CMD_READ_THERMAL, 0));
        assert_eq!(wmi.read_thermal_calls.get(), 2, "errors must not be cached");
    }

    #[test]
    fn coolsense_read_set_roundtrip_with_cache_invalidation() {
        let wmi = MockWmi::default();
        wmi.coolsense.set(1);
        let mut cache = CacheSet::new();

        assert_eq!(
            dispatch(&wmi, &mut cache, &req(CMD_READ_COOLSENSE, 0)),
            [STATUS_OK, 1]
        );
        assert_eq!(
            dispatch(&wmi, &mut cache, &req(CMD_SET_COOLSENSE, 0)),
            [STATUS_OK, 0]
        );
        assert_eq!(wmi.coolsense.get(), 0);
        // Set invalidated the cache, so this reflects the new value.
        assert_eq!(
            dispatch(&wmi, &mut cache, &req(CMD_READ_COOLSENSE, 0)),
            [STATUS_OK, 0]
        );
        assert_eq!(wmi.read_coolsense_calls.get(), 2);
    }

    #[test]
    fn temp_read_is_cached() {
        let wmi = MockWmi::default();
        wmi.temp.set(60);
        let mut cache = CacheSet::new();

        assert_eq!(
            dispatch(&wmi, &mut cache, &req(CMD_READ_TEMP, 0)),
            [STATUS_OK, 60]
        );
        let r2 = dispatch(&wmi, &mut cache, &req(CMD_READ_TEMP, 0));
        assert_eq!(r2[0], STATUS_OK | STATUS_CACHED);
        assert_eq!(r2[1], 60);
        assert_eq!(wmi.read_temp_calls.get(), 1);
    }

    #[test]
    fn brightness_read_and_set_are_uncached_passthroughs() {
        let wmi = MockWmi::default();
        wmi.brightness.set(50);
        let mut cache = CacheSet::new();

        assert_eq!(
            dispatch(&wmi, &mut cache, &req(CMD_READ_BRIGHTNESS, 0)),
            [STATUS_OK, 50]
        );
        assert_eq!(
            dispatch(&wmi, &mut cache, &req(CMD_SET_BRIGHTNESS, 80)),
            [STATUS_OK, 0]
        );
        assert_eq!(wmi.brightness.get(), 80);
    }

    #[test]
    fn read_build_id_returns_fingerprint_without_touching_wmi() {
        let wmi = MockWmi::default();
        let mut cache = CacheSet::new();

        assert_eq!(
            dispatch(&wmi, &mut cache, &req(CMD_READ_BUILD_ID, 0)),
            BUILD_FINGERPRINT
        );
        assert_eq!(wmi.read_thermal_calls.get(), 0);
    }
}
