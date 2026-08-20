use windows::Win32::Foundation::*;
use windows::Win32::Graphics::Gdi::{BLACK_BRUSH, DEFAULT_GUI_FONT, GetStockObject, HBRUSH};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Power::*;
use windows::Win32::System::SystemInformation::{GetSystemDirectoryW, GetTickCount64};
use windows::Win32::System::Threading::{CreateMutexW, INFINITE, OpenEventW, WaitForSingleObject};
use windows::Win32::UI::Input::KeyboardAndMouse::{GetKeyState, SetFocus};
use windows::Win32::UI::Shell::*;
use windows::Win32::UI::WindowsAndMessaging::*;
use windows::core::{PCSTR, PCWSTR, w};

use crate::app;
use crate::pipe;
use crate::protocol::*;
use crate::wide::wide_null;

const WM_TRAYICON: u32 = WM_USER + 1;
const ID_SMART_SENSE: u32 = 100;

// NVML idle-unload sweep: armed when the GPU menu loads NVML, fires once the library has
// gone idle, then kills itself so the tray returns to zero idle cost. Period matches
// `nvml::IDLE_TIMEOUT` (10 s).
const NVML_TIMER_ID: usize = 1;
const NVML_SWEEP_MS: u32 = 10_000;
const ID_PERFORMANCE: u32 = 101;
const ID_BALANCED: u32 = 102;
const ID_COOL: u32 = 103;
const ID_POWER_SAVER: u32 = 104;
#[cfg(feature = "noise-adapt")]
const ID_NOISE_ADAPTED: u32 = 105;
#[cfg(feature = "noise-adapt")]
const ID_CALIBRATE: u32 = 106;
const ID_EXIT: u32 = 200;
#[cfg(feature = "noise-adapt")]
const WM_NOISE_ADAPT_DONE: u32 = WM_USER + 2;
#[cfg(feature = "noise-adapt")]
const WM_CALIBRATE_DONE: u32 = WM_USER + 3;
const ID_DEBUG_HEADER: u32 = 300;
const ID_RESTART_SVC: u32 = 311;
const ID_STACK_MONITOR: u32 = 312;
#[cfg(feature = "noise-adapt")]
const ID_CLEAR_CAL: u32 = 314;
#[cfg(feature = "noise-adapt")]
const ID_DEBUG_CAL: u32 = 316;
const ID_FNKEY_SCREEN: u32 = 317;
const ID_FNKEY_SLEEP: u32 = 318;
const ID_METHOD_BRIGHTNESS: u32 = 319;
const ID_METHOD_DPMS: u32 = 320;
const ID_METHOD_BLACK: u32 = 321;
const ID_SHOW_FINGERPRINT: u32 = 322;
const WM_SCREEN_ON: u32 = WM_USER + 4;

/// Window class for the read-only, selectable hardware-fingerprint dialog (#149).
const HWINFO_CLASS: PCWSTR = w!("HpThermalHwInfo");

// Notification-area (NOTIFYICON_VERSION_4) event codes, delivered in LOWORD(lParam) of the
// WM_TRAYICON callback. Not all are exported by the windows crate; the values are stable
// (shellapi.h, = WM_USER + n). We warm the cache on any hover/select signal. NIN_KEYSELECT
// shares WM_TRAYICON's numeric value (both WM_USER+1) but lives in a different parameter, so
// there is no collision. https://learn.microsoft.com/windows/win32/shell/notification-area
const NIN_SELECT: u32 = WM_USER; // 0x0400 — activate (Enter/left-click)
const NIN_KEYSELECT: u32 = WM_USER + 1; // 0x0401 — keyboard activate
const NIN_POPUPOPEN: u32 = WM_USER + 6; // 0x0406 — hover/focus (tooltip opening)

/// #64: how long a warmed thermal/coolsense cache entry stays "fresh" before a trigger
/// re-reads. Tunable. Because hover warms the cache right before the menu opens, the
/// displayed value is almost always <1s old regardless — this only gates re-reads.
const CACHE_FRESH_MS: u64 = 5_000;

const METHOD_DPMS: u8 = 0;
const METHOD_BRIGHTNESS: u8 = 1;
const METHOD_BLACK: u8 = 2;

static mut HWND_MAIN: HWND = HWND(std::ptr::null_mut());
static mut STACK_MONITOR_ON: bool = false;
#[cfg(feature = "noise-adapt")]
static mut NOISE_ADAPT_RUNNING: bool = false;
#[cfg(feature = "noise-adapt")]
static mut CALIBRATING: bool = false;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

static FNKEY_SCREEN_ON: AtomicBool = AtomicBool::new(true);
static FNKEY_SLEEP_ON: AtomicBool = AtomicBool::new(false);
/// #95: Fn+F12 idempotency. `LAST_FNKEY_MS` = `GetTickCount64` (monotonic, sleep-inclusive) at the
/// last ACTED press; a press within `FNKEY_DEBOUNCE_MS` of it is dropped, coalescing key-repeat /
/// double-taps for EVERY action (screen, sleep, any future toggle). `FNKEY_SUPPRESS_UNTIL_MS` is
/// stamped after a sleep resumes: Fn+F12 is dropped until that tick, so the wake-press latched
/// during sleep (auto-reset event consumed on resume) can't immediately re-sleep — the wake-bounce.
/// Both are checked only when an event fires — event-driven, no poll.
static LAST_FNKEY_MS: AtomicU64 = AtomicU64::new(0);
static FNKEY_SUPPRESS_UNTIL_MS: AtomicU64 = AtomicU64::new(0);
/// Coalesce presses within this window into one action (key-repeat / nervous double-tap, plus
/// physical settle time — every Fn+F12 action has non-negligible latency + after-effects). One
/// universal value for now; if actions ever diverge (e.g. a fast profile toggle vs. sleep), this
/// is the single point to split into a per-effect window.
const FNKEY_DEBOUNCE_MS: u64 = 2000;
/// After resume from an Fn+F12 sleep, ignore Fn+F12 this long so the wake can't re-sleep.
const FNKEY_RESUME_SUPPRESS_MS: u64 = 3000;
/// Tracks display state for toggling. true = screen is on.
static SCREEN_IS_ON: AtomicBool = AtomicBool::new(true);
/// Screen-off method: 0=DPMS, 1=Brightness, 2=Black Window.
static SCREEN_METHOD: AtomicU8 = AtomicU8::new(0);
/// Saved brightness level (1-100) to restore on screen-on.
static SAVED_BRIGHTNESS: AtomicU8 = AtomicU8::new(0);
/// #64 menu-state cache. Warmed OFF the UI thread (tray hover / keyboard-select / menu-open
/// backstop — all via `maybe_warm`) and read synchronously when the menu is built, so the
/// menu opens with correct checkmarks and the UI thread never blocks on the pipe. 0xFF =
/// unknown (nothing warmed yet, or the service was unreachable).
static CACHED_THERMAL: AtomicU8 = AtomicU8::new(0xFF);
/// Smart Sense / CoolSense: 0 = off, 1 = on, 0xFF = unknown.
static CACHED_COOLSENSE: AtomicU8 = AtomicU8::new(0xFF);
/// `GetTickCount64` (monotonic ms, sleep-inclusive) at the last warm attempt; 0 = never.
/// Recency = `now - stamp`. Stamped even on a failed read so a down service is throttled to
/// one attempt per `CACHE_FRESH_MS`, not hammered on every hover event.
static CACHE_STAMP: AtomicU64 = AtomicU64::new(0);
/// True while a warm worker is reading — gates duplicate reads so `maybe_warm` is idempotent.
static WARM_IN_FLIGHT: AtomicBool = AtomicBool::new(false);
/// #93: DPMS monitor-off is dispatched to an ephemeral worker so the UI thread never blocks on
/// the `SendMessage(HWND_BROADCAST, …)` broadcast — which has no timeout and permanently wedges
/// the message loop if any top-level window isn't pumping (screen-off, menu/tooltip dead until
/// the process is killed). `DIRTY` = an off-broadcast was requested; `WORKER_ACTIVE` = a worker
/// owns the broadcast. Together they coalesce a mashed Fn+F12 into at most one in-flight worker
/// without ever dropping the last request.
static MONITOR_OFF_DIRTY: AtomicBool = AtomicBool::new(false);
static MONITOR_WORKER_ACTIVE: AtomicBool = AtomicBool::new(false);
static mut BLACK_WINDOW: HWND = HWND(std::ptr::null_mut());

/// Last mic info from noise-adapt or calibration thread (stashed for UI display).
#[cfg(feature = "noise-adapt")]
static LAST_MIC_INFO: std::sync::Mutex<(String, f32)> = std::sync::Mutex::new((String::new(), 0.0));

pub fn run() {
    // #54 backstop (defense in depth): the tray must never run above Medium IL. main()
    // already refuses the elevated no-arg role (with a dialog) before any I/O, so this is
    // only reachable if a FUTURE code path reaches tray::run() elevated off that guarded
    // path — a developer-error backstop, not a user-facing path. Exit silently: no file
    // I/O at High IL (an elevated log::init would leave an admin-owned log, CWE-732), and
    // no second dialog (main() owns the user-facing message). Independent re-check, not a
    // cached value from main() — a cached bool would only be set on the guarded path.
    if crate::install::is_elevated() {
        return;
    }

    // SAFETY: run_inner() calls Win32 UI APIs (window creation, message loop,
    // tray icon) that require a single-threaded message pump. Called once from
    // main() on the main thread.
    unsafe { run_inner() }
}

unsafe fn run_inner() {
    // Singleton: if another tray instance is already running, wait briefly
    // (the previous instance may be exiting from a version-mismatch restart).
    let mutex_name = wide_null(app::MUTEX_NAME);
    let _mutex = CreateMutexW(None, true, PCWSTR(mutex_name.as_ptr()));
    if GetLastError() == ERROR_ALREADY_EXISTS {
        if let Ok(h) = _mutex {
            // SAFETY: h is a valid mutex handle from CreateMutexW.
            // 3s timeout covers the old tray's PostQuitMessage + teardown.
            let r = WaitForSingleObject(h, 3000);
            if r.0 != 0 && r.0 != 0x80 {
                // Neither WAIT_OBJECT_0 nor WAIT_ABANDONED — genuine second instance
                return;
            }
            // Acquired — handle intentionally leaked (singleton for process lifetime)
        } else {
            return;
        }
    }

    crate::log::init("tray");
    crate::log::install_stack_guard();
    crate::log::etw_register("tray");
    crate::log::write("tray starting");
    crate::log::write(&format!("build: {}", app::build_identity()));

    // Right-size the tray's own token: permanently drop every privilege it never uses. The
    // tray is the weakly-mitigated, user-facing role, and on admin accounts its Medium token
    // is one UAC away from High — so shrink what injected code could leverage. Best-effort.
    strip_unneeded_privileges();

    // No-child is deferred to HERE, not applied at dispatch by harden_for_role (Role::Tray, #157):
    // the no-arg role first acts as a bootstrap installer/launcher (default_run spawns the elevated
    // UAC child on first-run / repair / service-start), and those branches `return` before reaching
    // this point — so the lock lands only once we're committed to just running the tray. #86: from
    // here on the tray spawns nothing, so no-child costs it nothing. (CIG/win32k/ACG stay carved for
    // this role — nvml + GUI — per the profile table.)
    crate::win_harden::prohibit_child_processes();

    // Enable dark/light mode for popup menus (must be before any window creation)
    enable_system_theme_menus();

    let hinstance = GetModuleHandleW(None).unwrap();

    let class_name_buf = wide_null(app::WINDOW_CLASS);
    let class_name = PCWSTR(class_name_buf.as_ptr());
    let wc = WNDCLASSW {
        lpfnWndProc: Some(wnd_proc),
        hInstance: hinstance.into(),
        lpszClassName: class_name,
        ..Default::default()
    };
    RegisterClassW(&wc);

    // #149: class for the read-only, selectable hardware-fingerprint dialog. Registered once here
    // (COLOR_WINDOW background so the edit control blends in).
    let hwinfo_wc = WNDCLASSW {
        lpfnWndProc: Some(hwinfo_wnd_proc),
        hInstance: hinstance.into(),
        lpszClassName: HWINFO_CLASS,
        // Null background: the edit control fills the whole client area, so it's never painted.
        hbrBackground: HBRUSH::default(),
        ..Default::default()
    };
    RegisterClassW(&hwinfo_wc);

    let title = wide_null(app::NAME);
    HWND_MAIN = CreateWindowExW(
        WINDOW_EX_STYLE::default(),
        class_name,
        PCWSTR(title.as_ptr()),
        WINDOW_STYLE::default(),
        0,
        0,
        0,
        0,
        Some(HWND_MESSAGE),
        None,
        Some(hinstance.into()),
        None,
    )
    .unwrap();

    // Add tray icon
    let mut nid = new_nid(HWND_MAIN);
    // NIF_SHOWTIP: keep the standard hover tooltip. NOTIFYICON_VERSION_4 (set below) suppresses
    // it by default, expecting an app-drawn popup — we want the classic tip, so opt back in.
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP | NIF_SHOWTIP;
    nid.uCallbackMessage = WM_TRAYICON;
    nid.hIcon = load_tray_icon();
    set_tip(&mut nid, app::NAME);
    let _ = Shell_NotifyIconW(NIM_ADD, &nid);

    // Opt into NOTIFYICON_VERSION_4: richer, accessible callbacks — WM_CONTEXTMENU (fires for
    // BOTH mouse right-click and keyboard/AT invocation, e.g. Win+B -> Menu key, and carries
    // the anchor point) plus NIN_* hover/select signals. This is what makes the tray reachable
    // and correctly positioned for keyboard/screen-reader users. NOTE: v4 changes the
    // WM_TRAYICON wParam/lParam encoding (decoded in wnd_proc).
    nid.Anonymous.uVersion = NOTIFYICON_VERSION_4;
    let _ = Shell_NotifyIconW(NIM_SETVERSION, &nid);

    // Immediately read current mode and update tooltip
    update_tooltip(HWND_MAIN);

    // Warm the menu-state cache in the background so the first menu open shows correct checks
    // (idempotent + throttled; a no-op if already warm or a read is in flight).
    maybe_warm();

    // Load Fn+F12 settings
    load_fnkey_settings();

    // Open kernel events created by the service.
    // Either may fail if service isn't running — that's OK.
    let fn_key_event = open_fn_key_event();
    let svc_start_event = open_svc_start_event();
    if fn_key_event.is_some() {
        crate::log::write("tray: Fn+F12 event connected");
    }
    if svc_start_event.is_some() {
        crate::log::write("tray: svc-start event connected");
    }

    // Build wait handle array. Indices are dynamic based on which events opened.
    let mut handles: Vec<HANDLE> = Vec::with_capacity(2);
    let fn_key_idx = fn_key_event.map(|ev| {
        let i = handles.len();
        handles.push(ev);
        i
    });
    let svc_start_idx = svc_start_event.map(|ev| {
        let i = handles.len();
        handles.push(ev);
        i
    });

    // Message loop with optional event wait
    let mut msg = MSG::default();
    if !handles.is_empty() {
        loop {
            let result = MsgWaitForMultipleObjects(Some(&handles), false, INFINITE, QS_ALLINPUT);
            let signaled = result.0.wrapping_sub(WAIT_OBJECT_0.0);
            if (signaled as usize) < handles.len() {
                if fn_key_idx == Some(signaled as usize) {
                    handle_fn_key(HWND_MAIN);
                } else if svc_start_idx == Some(signaled as usize) {
                    // Service restarted — if it's a newer build, exit (no self-spawn).
                    exit_if_service_newer(HWND_MAIN);
                }
            } else if signaled == handles.len() as u32 {
                // Window messages available
                let mut quit = false;
                while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).into() {
                    if msg.message == WM_QUIT {
                        quit = true;
                        break;
                    }
                    let _ = TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
                if quit {
                    break;
                }
            } else {
                break; // WAIT_FAILED
            }
        }
        for h in &handles {
            let _ = CloseHandle(*h);
        }
    } else {
        // Fallback: standard message loop (no event support)
        while GetMessageW(&mut msg, None, 0, 0).into() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    // Cleanup
    crate::log::write(&crate::log::stack_report());
    let _ = Shell_NotifyIconW(NIM_DELETE, &nid);
}

unsafe extern "system" fn wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_TRAYICON => {
            // NOTIFYICON_VERSION_4 encoding: LOWORD(lParam) = event code, and the anchor point
            // is packed into wParam (GET_X/Y_LPARAM). WM_CONTEXTMENU covers BOTH mouse
            // right-click AND keyboard/AT invocation and carries the correct anchor, so the
            // menu is positioned by the icon for keyboard users. Hover/select events are just
            // extra places to warm the cache before the menu opens.
            let event = (lparam.0 as u32) & 0xFFFF;
            match event {
                WM_CONTEXTMENU => {
                    let x = (wparam.0 & 0xFFFF) as i16 as i32;
                    let y = ((wparam.0 >> 16) & 0xFFFF) as i16 as i32;
                    // #95: trace each right-click that actually reaches our wnd_proc. Paired with
                    // the SetForegroundWindow trace inside show_context_menu, a "menu never opens"
                    // repro is now disambiguated: WM_CONTEXTMENU logged then a stuck open menu
                    // (thread parked in a prior modal loop) vs. NO WM_CONTEXTMENU at all (the UI
                    // thread isn't pumping — wedged before the menu, a different root cause).
                    crate::log::trace!(crate::log::KW_UI, "menu: WM_CONTEXTMENU x={x} y={y}");
                    show_context_menu(hwnd, x, y);
                }
                // maybe_warm is idempotent + throttled, so listing several trigger sites is
                // free — each is just another chance to have the state ready by open time.
                WM_MOUSEMOVE | NIN_POPUPOPEN | NIN_SELECT | NIN_KEYSELECT => maybe_warm(),
                _ => {}
            }
            LRESULT(0)
        }
        WM_COMMAND => {
            let id = (wparam.0 as u32) & 0xFFFF;
            handle_menu(hwnd, id);
            LRESULT(0)
        }
        WM_TIMER => {
            // NVML idle sweep: once the dGPU library has gone idle, unload it and stop the
            // timer, so the tray drops back to zero idle cost until the menu is used again.
            if wparam.0 == NVML_TIMER_ID && crate::nvml::unload_if_idle() {
                let _ = KillTimer(Some(hwnd), NVML_TIMER_ID);
            }
            LRESULT(0)
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            LRESULT(0)
        }
        #[cfg(feature = "noise-adapt")]
        x if x == WM_NOISE_ADAPT_DONE => {
            let chosen = (wparam.0 & 0xFF) as u8;
            let fast = wparam.0 & 0x100 != 0;
            let delta_db = lparam.0 as f32 / 10.0;
            NOISE_ADAPT_RUNNING = false;

            // Dismiss any open popup menu so it doesn't show stale state
            let _ = EndMenu();

            let mode_name = if chosen == 0 {
                "Performance"
            } else {
                "Balanced"
            };
            let reason = if chosen == 0 {
                "Environment noise masks fan sound."
            } else {
                "Fans would be audible in this environment."
            };
            let method = if fast { "cached" } else { "calibrated" };
            let mic_line = if let Ok(info) = LAST_MIC_INFO.lock() {
                if !info.0.is_empty() {
                    format!("Mic: {} (gain {:.0}%)", info.0, info.1 * 100.0)
                } else {
                    String::new()
                }
            } else {
                String::new()
            };
            let body = format!(
                "Chose {mode_name} ({method})\n{reason}\n\
                 Delta: {delta_db:+.1} dB{}\n{mic_line}",
                if !fast { " (A-weighted)" } else { "" },
            );
            show_balloon(hwnd, "Noise Adapted", &body);

            update_tooltip(hwnd);
            LRESULT(0)
        }
        #[cfg(feature = "noise-adapt")]
        x if x == WM_CALIBRATE_DONE => {
            CALIBRATING = false;

            let _ = EndMenu();

            let success = wparam.0 != 0;
            if success {
                let perf = f32::from_bits(lparam.0 as u32);
                let bal = f32::from_bits((lparam.0 >> 32) as u32);
                let perf_db = if perf > 0.0 {
                    10.0 * perf.log10()
                } else {
                    -120.0
                };
                let bal_db = if bal > 0.0 {
                    10.0 * bal.log10()
                } else {
                    -120.0
                };
                let delta = perf_db - bal_db;
                let mic_line = if let Ok(info) = LAST_MIC_INFO.lock() {
                    if !info.0.is_empty() {
                        format!("\nMic: {} (gain {:.0}%)", info.0, info.1 * 100.0)
                    } else {
                        String::new()
                    }
                } else {
                    String::new()
                };
                show_balloon(
                    hwnd,
                    "Calibration Complete",
                    &format!(
                        "Fan noise measured (A-weighted).\n\
                         Performance: {perf_db:.1} dBA  Balanced: {bal_db:.1} dBA\n\
                         Delta: {delta:+.1} dB{mic_line}",
                    ),
                );
            } else {
                show_balloon(
                    hwnd,
                    "Calibration Failed",
                    "Could not measure fan noise. Check microphone.",
                );
            }
            update_tooltip(hwnd);
            LRESULT(0)
        }
        x if x == WM_SCREEN_ON => {
            // Safety escape from black window: any key/click dismisses it
            if !SCREEN_IS_ON.load(Ordering::Relaxed) {
                SCREEN_IS_ON.store(true, Ordering::Relaxed);
                crate::log::write("Fn+F12: screen on (black window dismissed)");
                screen_on();
            }
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

/// Warm the menu-state cache OFF the UI thread — idempotent + throttled (#64). Cheapest gates
/// first so the per-event cost on the UI thread is a couple of atomics: skip if a read is
/// already in flight; skip if the cache is still fresh (monotonic tick); else claim the slot
/// (CAS) and do the ONE expensive thing — the pipe/WMI read — in a short-lived worker. Safe to
/// call from any trigger (tray hover, keyboard select, menu-open backstop, startup); duplicate
/// callers are free because the gates make them no-ops.
fn maybe_warm() {
    if WARM_IN_FLIGHT.load(Ordering::Acquire) {
        return; // a read is already coming
    }
    // SAFETY: GetTickCount64 has no preconditions (reads shared user-mode data).
    let now = unsafe { GetTickCount64() };
    let stamp = CACHE_STAMP.load(Ordering::Acquire);
    if stamp != 0 && now.wrapping_sub(stamp) < CACHE_FRESH_MS {
        return; // cache still fresh
    }
    if WARM_IN_FLIGHT
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return; // another trigger won the race; let it do the read
    }
    std::thread::spawn(|| {
        // #69: one batched read (thermal + coolsense) instead of two round trips. 0xFF =
        // unknown (service down / slow / bad status).
        let (thermal, coolsense) = match pipe::client_transact(CMD_READ_STATE, 0) {
            Some(r) if status_ok(r[0]) => unpack_state(r[1]),
            _ => (0xFF, 0xFF),
        };
        CACHED_THERMAL.store(thermal, Ordering::Release);
        CACHED_COOLSENSE.store(coolsense, Ordering::Release);
        // SAFETY: GetTickCount64 has no preconditions. Stamp even on unknowns so a down
        // service is throttled, not hammered.
        CACHE_STAMP.store(unsafe { GetTickCount64() }, Ordering::Release);
        WARM_IN_FLIGHT.store(false, Ordering::Release);
    });
}

/// Optimistically update the menu-state cache after we issue a set, so the NEXT menu open
/// reflects it with no round trip (#64) — this is what "saves the round trip". Refreshes the
/// recency stamp. `None` leaves that field unchanged (a Smart Sense toggle doesn't touch the
/// thermal mode).
fn cache_store(thermal: Option<u8>, coolsense: Option<u8>) {
    if let Some(t) = thermal {
        CACHED_THERMAL.store(t, Ordering::Release);
    }
    if let Some(c) = coolsense {
        CACHED_COOLSENSE.store(c, Ordering::Release);
    }
    // SAFETY: GetTickCount64 has no preconditions.
    CACHE_STAMP.store(unsafe { GetTickCount64() }, Ordering::Release);
}

unsafe fn show_context_menu(hwnd: HWND, anchor_x: i32, anchor_y: i32) {
    let debug = (GetKeyState(0x10) as u16 & 0x8000) != 0; // VK_SHIFT = 0x10

    // #64: menu STRUCTURE (normal vs "service unavailable" + Restart) is decided by a fast
    // LOCAL service-liveness check — SCM QueryServiceStatusEx — NOT a WMI/pipe transact.
    // That distinction is the whole point: the old `connected` came from two synchronous
    // WMI reads on the UI thread (the menu lockout); this is a sub-ms local RPC that never
    // touches the HP BIOS provider, so a dead service still shows Restart without the block.
    let connected = crate::install::is_service_running();

    // Menu VALUES: the debug view reads inline (live diagnostics; each read is bounded by the
    // #64 client timeout). The normal menu reads the warm CACHE synchronously — no pipe I/O on
    // the UI thread — so it opens with correct checks; the cache is kept warm by maybe_warm on
    // hover/select and refreshed by the backstop below.
    let (thermal, coolsense) = if debug {
        let t = pipe::client_transact(CMD_READ_THERMAL, 0);
        let c = pipe::client_transact(CMD_READ_COOLSENSE, 0);
        crate::log::stack_sample("tray:menu_query");
        (t, c)
    } else {
        (None, None)
    };

    let (current_mode, cs_on): (Option<u8>, Option<bool>) = if debug {
        (
            thermal.and_then(|r| if status_ok(r[0]) { Some(r[1]) } else { None }),
            coolsense.and_then(|r| {
                if status_ok(r[0]) {
                    Some(r[1] != 0)
                } else {
                    None
                }
            }),
        )
    } else {
        let t = CACHED_THERMAL.load(Ordering::Acquire);
        let c = CACHED_COOLSENSE.load(Ordering::Acquire);
        (
            if t <= 3 { Some(t) } else { None }, // 0xFF unknown -> no check
            match c {
                0 => Some(false),
                1 => Some(true),
                _ => None,
            },
        )
    };

    let hmenu = CreatePopupMenu().unwrap();

    // Smart Sense item
    if connected {
        append_item(hmenu, ID_SMART_SENSE, "Smart Sense", cs_on == Some(true));
    } else {
        append_item_disabled(hmenu, ID_SMART_SENSE, "Smart Sense");
    }
    let _ = AppendMenuW(hmenu, MF_SEPARATOR, 0, None);

    // Noise Adapted + calibration: mic-based environment detection (opt-in feature)
    #[cfg(feature = "noise-adapt")]
    {
        // Noise Adapted: one-shot mic-based environment detection
        if connected {
            if NOISE_ADAPT_RUNNING {
                append_item_disabled(hmenu, ID_NOISE_ADAPTED, "Noise Adapted (measuring...)");
            } else if CALIBRATING {
                append_item_disabled(hmenu, ID_NOISE_ADAPTED, "Noise Adapted");
            } else {
                append_item(hmenu, ID_NOISE_ADAPTED, "Noise Adapted", false);
            }
        } else {
            append_item_disabled(hmenu, ID_NOISE_ADAPTED, "Noise Adapted");
        }

        // Run calibration: stress test for fan noise measurement
        if connected {
            if CALIBRATING {
                append_item_disabled(hmenu, ID_CALIBRATE, "Calibrating...");
            } else if NOISE_ADAPT_RUNNING {
                append_item_disabled(hmenu, ID_CALIBRATE, "Run calibration...");
            } else {
                append_item(hmenu, ID_CALIBRATE, "Run calibration...", false);
            }
        } else {
            append_item_disabled(hmenu, ID_CALIBRATE, "Run calibration...");
        }
        let _ = AppendMenuW(hmenu, MF_SEPARATOR, 0, None);
    }

    // Thermal mode items. When connected, rows are enabled and the selected one is checked
    // async (normal path) or now (debug path); Smart Sense ON suppresses the mode check.
    let modes = [
        (ID_PERFORMANCE, "Performance", 0u8),
        (ID_BALANCED, "Balanced", 1),
        (ID_COOL, "Cool", 2),
        (ID_POWER_SAVER, "Power Saver", 3),
    ];
    for (id, label, mode) in &modes {
        if connected {
            let checked = current_mode == Some(*mode) && cs_on != Some(true);
            append_item(hmenu, *id, label, checked);
        } else {
            append_item_disabled(hmenu, *id, label);
        }
    }

    // Service down: restore the dead-service affordance (#64) — disabled rows above, plus
    // an explicit unavailable marker and a Restart action (needs no UAC; see handle_menu).
    if !connected {
        let _ = AppendMenuW(hmenu, MF_SEPARATOR, 0, None);
        append_item_disabled(hmenu, ID_DEBUG_HEADER + 9, "Service unavailable");
        append_item(hmenu, ID_RESTART_SVC, "Restart Service...", false);
    }

    let _ = AppendMenuW(hmenu, MF_SEPARATOR, 0, None);
    append_item(hmenu, ID_EXIT, "Exit", false);

    // Shift+right-click: append debug info
    if debug {
        let mut id = ID_DEBUG_HEADER;

        // --- Build + hardware ---
        let _ = AppendMenuW(hmenu, MF_SEPARATOR, 0, None);
        let bd = env!("BUILD_DATE");
        let date_fmt = if bd.len() >= 13 {
            format!(
                "{}-{}-{} {}:{}",
                &bd[0..4],
                &bd[4..6],
                &bd[6..8],
                &bd[9..11],
                &bd[11..13],
            )
        } else {
            bd.to_string()
        };
        append_item_disabled(
            hmenu,
            id,
            &format!("Build: {} ({})", env!("BUILD_ID"), date_fmt),
        );
        id += 1;
        let cpu = crate::hwinfo::cpu_name();
        let temp_str = match pipe::client_transact(CMD_READ_TEMP, 0) {
            Some([s, t]) if status_ok(s) => format!(" {t}C"),
            _ => String::new(),
        };
        if cpu.is_empty() {
            append_item_disabled(hmenu, id, &format!("CPU:{temp_str} unknown"));
        } else {
            append_item_disabled(hmenu, id, &format!("CPU:{temp_str} {cpu}"));
        }
        id += 1;

        // --- dGPU ---
        match crate::nvml::gpu_info() {
            Some(info) => {
                let pstate = if info.pstate <= 15 {
                    format!("P{}", info.pstate)
                } else {
                    "P?".into()
                };
                append_item_disabled(
                    hmenu,
                    id,
                    &format!(
                        "dGPU: {} {pstate} {}C {:.1}W",
                        info.name,
                        info.temp_c,
                        info.power_mw as f32 / 1000.0,
                    ),
                );
            }
            None => {
                append_item_disabled(hmenu, id, "dGPU: not available");
            }
        }
        id += 1;

        // --- Service ---
        let _ = AppendMenuW(hmenu, MF_SEPARATOR, 0, None);
        let pipe_str = match pipe::client_connect() {
            Some(h) => {
                let _ = windows::Win32::Foundation::CloseHandle(h);
                "pipe: connected".into()
            }
            None => "pipe: FAIL".to_string(),
        };
        let thermal_str = match thermal {
            Some([s, r]) => format!("thermal: 0x{s:02X} 0x{r:02X}"),
            None => "thermal: no response".into(),
        };
        let cs_str = match coolsense {
            Some([s, r]) => format!("coolsense: 0x{s:02X} 0x{r:02X}"),
            None => "coolsense: no response".into(),
        };
        let stack_str = format!(
            "stack: depth={} KB committed={} KB (peak: {}/{})",
            crate::log::stack_depth() / 1024,
            crate::log::stack_committed() / 1024,
            crate::log::stack_depth_peak_kb(),
            crate::log::stack_peak_kb(),
        );
        append_item_disabled(hmenu, id, &pipe_str);
        id += 1;
        append_item_disabled(hmenu, id, &thermal_str);
        id += 1;
        append_item_disabled(hmenu, id, &cs_str);
        id += 1;
        append_item_disabled(hmenu, id, &stack_str);

        // --- Contribute hardware (#149) ---
        // Enabled once a live thermal read confirms the interface answers; clicking runs the full
        // read→write/restore ladder and shows the SAME report as `--hwinfo` in a selectable dialog.
        // Greyed when there's no service to read. Fixed command id — doesn't disturb the running `id`.
        let _ = AppendMenuW(hmenu, MF_SEPARATOR, 0, None);
        if matches!(thermal, Some([s, _]) if status_ok(s)) {
            append_item(
                hmenu,
                ID_SHOW_FINGERPRINT,
                "Show hardware fingerprint...",
                false,
            );
        } else {
            append_item_disabled(
                hmenu,
                ID_SHOW_FINGERPRINT,
                "Hardware fingerprint (no service)",
            );
        }

        // --- Noise calibration (opt-in feature) ---
        #[cfg(feature = "noise-adapt")]
        {
            let mut id = id + 1;
            let _ = AppendMenuW(hmenu, MF_SEPARATOR, 0, None);
            if let Some(ndi) = crate::audio::debug_info() {
                append_item_disabled(
                    hmenu,
                    id,
                    &format!(
                        "Fan: perf={:.1e} bal={:.1e}",
                        ndi.fan_perf_power, ndi.fan_bal_power,
                    ),
                );
                id += 1;
                let cross_str = match ndi.crossover_dbfs {
                    Some(c) => format!("{c:.0}"),
                    None => "-".into(),
                };
                append_item_disabled(
                    hmenu,
                    id,
                    &format!(
                        "Points: {}/8, crossover ~{} dBFS",
                        ndi.num_points, cross_str,
                    ),
                );
                id += 1;
                let age_str = if ndi.cal_age_secs == 0 || ndi.fan_perf_power == 0.0 {
                    "never".into()
                } else {
                    let days = ndi.cal_age_secs / 86400;
                    let hours = (ndi.cal_age_secs % 86400) / 3600;
                    if days > 0 {
                        format!("{days}d ago")
                    } else {
                        format!("{hours}h ago")
                    }
                };
                append_item_disabled(hmenu, id, &format!("Last cal: {age_str}"));
            } else {
                append_item_disabled(hmenu, id, "Noise cal: none");
            }
            append_item(hmenu, ID_CLEAR_CAL, "Clear calibration", false);
            if NOISE_ADAPT_RUNNING || CALIBRATING {
                append_item_disabled(hmenu, ID_DEBUG_CAL, "Debug Calibration (WAV)...");
            } else {
                append_item(hmenu, ID_DEBUG_CAL, "Debug Calibration (WAV)...", false);
            }
        }

        // --- Fn+F12 hotkey ---
        let _ = AppendMenuW(hmenu, MF_SEPARATOR, 0, None);
        append_item(
            hmenu,
            ID_FNKEY_SCREEN,
            "Fn+F12: Screen On/Off",
            FNKEY_SCREEN_ON.load(Ordering::Relaxed),
        );
        append_item(
            hmenu,
            ID_FNKEY_SLEEP,
            "Fn+F12: Sleep",
            FNKEY_SLEEP_ON.load(Ordering::Relaxed),
        );

        // --- Monitor Off Method ---
        let _ = AppendMenuW(hmenu, MF_SEPARATOR, 0, None);
        let method = SCREEN_METHOD.load(Ordering::Relaxed);
        append_item(
            hmenu,
            ID_METHOD_DPMS,
            "Screen Off: DPMS",
            method == METHOD_DPMS,
        );
        append_item(
            hmenu,
            ID_METHOD_BRIGHTNESS,
            "Screen Off: Brightness (WMI)",
            method == METHOD_BRIGHTNESS,
        );
        append_item(
            hmenu,
            ID_METHOD_BLACK,
            "Screen Off: Black Window",
            method == METHOD_BLACK,
        );

        // --- Tools ---
        let _ = AppendMenuW(hmenu, MF_SEPARATOR, 0, None);
        append_item(hmenu, ID_STACK_MONITOR, "Stack Monitor", STACK_MONITOR_ON);
    }

    // Backstop warm (#64): refresh the cache for the NEXT open. Idempotent + throttled, so a
    // no-op if a hover already warmed it or a read is in flight. This covers the cold path — a
    // keyboard-invoked menu with no prior hover: this open shows honest "unknown", the next is
    // correct. Skip when the service is down (SCM says nothing to read).
    if connected {
        maybe_warm();
    }

    // Position at the anchor the shell gave us in WM_CONTEXTMENU — correct for BOTH mouse and
    // keyboard/AT invocation. Fall back to the cursor only if the anchor is unset. KB Q135788:
    // SetForegroundWindow before TrackPopupMenu so the menu dismisses on click-away.
    let (x, y) = if anchor_x == 0 && anchor_y == 0 {
        let mut pt = POINT::default();
        let _ = GetCursorPos(&mut pt);
        (pt.x, pt.y)
    } else {
        (anchor_x, anchor_y)
    };
    // #95/#6: SetForegroundWindow is gated by the foreground lock (aggravated after resume). On
    // failure, TrackPopupMenu can show a menu that won't dismiss on click-away and parks the UI
    // thread in its modal loop — the observed "tooltip alive, menu dead" wedge. Instrument the
    // result so a repro is diagnostic: verbose ETW always, a durable Event Log warn on the anomaly.
    let fg = SetForegroundWindow(hwnd).as_bool();
    crate::log::trace!(crate::log::KW_UI, "menu: SetForegroundWindow={fg}");
    if !fg {
        crate::log::warn(
            "menu: SetForegroundWindow failed (foreground lock?) — menu may not dismiss",
        );
    }
    let _ = TrackPopupMenu(
        hmenu,
        TPM_LEFTALIGN | TPM_RIGHTBUTTON,
        x,
        y,
        Some(0),
        hwnd,
        None,
    );
    let _ = PostMessageW(Some(hwnd), WM_NULL, WPARAM(0), LPARAM(0));

    let _ = DestroyMenu(hmenu);

    // If building the menu loaded NVML (a dGPU is present), (re)arm the idle sweep. Each
    // menu use resets the period; when it finally lapses the sweep unloads NVML and stops.
    if crate::nvml::is_loaded() {
        let _ = SetTimer(Some(hwnd), NVML_TIMER_ID, NVML_SWEEP_MS, None);
    }
}

unsafe fn handle_menu(hwnd: HWND, id: u32) {
    match id {
        ID_SMART_SENSE => {
            // Toggle CoolSense
            let current = pipe::client_transact(CMD_READ_COOLSENSE, 0);
            let new_val = match current {
                Some([s, state]) if status_ok(s) && state != 0 => 0,
                _ => 1,
            };
            pipe::client_transact(CMD_SET_COOLSENSE, new_val);
            cache_store(None, Some(new_val)); // optimistic: next open reflects the toggle
        }
        ID_SHOW_FINGERPRINT => {
            // #149: the SAME unified path as `--hwinfo` — capability::hardware_report runs the
            // read→write/restore ladder (cached) over the pipe; we just show it in a selectable
            // dialog instead of printing. No app-side clipboard/shell ops.
            show_text_dialog(&crate::capability::hardware_report());
        }
        #[cfg(feature = "noise-adapt")]
        ID_NOISE_ADAPTED => {
            if NOISE_ADAPT_RUNNING || CALIBRATING {
                return;
            }
            NOISE_ADAPT_RUNNING = true;
            run_smart_measure_thread(hwnd, false, "noise-adapt");
            set_tooltip_text(
                hwnd,
                &format!("{}: Noise Adapted (measuring...)", app::NAME),
            );
            return;
        }
        #[cfg(feature = "noise-adapt")]
        ID_CALIBRATE => {
            if CALIBRATING || NOISE_ADAPT_RUNNING {
                return;
            }
            CALIBRATING = true;

            show_balloon(
                hwnd,
                "Calibrating Fan Noise",
                "CPU will be stressed for ~2 minutes\nto measure steady-state fan noise in each thermal mode.",
            );

            let hwnd_raw = hwnd.0 as usize;
            std::thread::spawn(move || {
                let result = crate::audio::stress_calibrate(|mode| {
                    pipe::client_transact(CMD_SET_THERMAL, mode);
                });

                let (wparam_val, lparam_val) = match result {
                    Ok(cal) => {
                        if let Ok(mut info) = LAST_MIC_INFO.lock() {
                            *info = (cal.mic_name, cal.mic_gain);
                        }
                        // Pack two f32 into LPARAM (64-bit):
                        // low 32 = perf bits, high 32 = bal bits
                        let lo = cal.fan_perf_power.to_bits() as u64;
                        let hi = (cal.fan_bal_power.to_bits() as u64) << 32;
                        (1usize, (lo | hi) as isize)
                    }
                    Err(e) => {
                        crate::log::warn(&format!("stress-cal: error: {e}"));
                        (0usize, 0isize)
                    }
                };

                // SAFETY: Same PostMessageW cross-thread contract as noise-adapt above.
                unsafe {
                    let _ = PostMessageW(
                        Some(HWND(hwnd_raw as *mut _)),
                        WM_CALIBRATE_DONE,
                        WPARAM(wparam_val),
                        LPARAM(lparam_val),
                    );
                }
            });

            set_tooltip_text(hwnd, &format!("{}: Calibrating...", app::NAME));
            return;
        }
        ID_PERFORMANCE | ID_BALANCED | ID_COOL | ID_POWER_SAVER => {
            let mode = match id {
                ID_PERFORMANCE => 0,
                ID_BALANCED => 1,
                ID_COOL => 2,
                _ => 3,
            };
            // Selecting a specific mode implicitly disables Smart Sense (CoolSense)
            pipe::client_transact(CMD_SET_COOLSENSE, 0);
            pipe::client_transact(CMD_SET_THERMAL, mode);
            cache_store(Some(mode), Some(0)); // optimistic: mode on, Smart Sense off
        }
        ID_RESTART_SVC => {
            // Start via the SCM start-right (sdset grants interactive users SERVICE_START) — no
            // child process, so it works under the tray's prohibit_child_processes (#86). No
            // elevated fallback here: the start right is always granted, and the tray can't
            // spawn anyway. A failure is logged, not escalated.
            if crate::install::native_start() {
                if crate::install::wait_for_service_running() {
                    update_tooltip(hwnd);
                }
            } else {
                crate::log::warn("tray: service start failed (SCM SERVICE_START denied?)");
            }
            return;
        }
        ID_STACK_MONITOR => {
            STACK_MONITOR_ON = !STACK_MONITOR_ON;
            crate::log::set_stack_monitor(STACK_MONITOR_ON);
            pipe::client_transact(CMD_SET_STACK_MONITOR, if STACK_MONITOR_ON { 1 } else { 0 });
            return;
        }
        ID_FNKEY_SCREEN => {
            let prev = FNKEY_SCREEN_ON.load(Ordering::Relaxed);
            FNKEY_SCREEN_ON.store(!prev, Ordering::Relaxed);
            save_fnkey_settings();
            return;
        }
        ID_FNKEY_SLEEP => {
            let prev = FNKEY_SLEEP_ON.load(Ordering::Relaxed);
            FNKEY_SLEEP_ON.store(!prev, Ordering::Relaxed);
            save_fnkey_settings();
            return;
        }
        ID_METHOD_BRIGHTNESS | ID_METHOD_DPMS | ID_METHOD_BLACK => {
            let method = match id {
                ID_METHOD_BRIGHTNESS => METHOD_BRIGHTNESS,
                ID_METHOD_DPMS => METHOD_DPMS,
                _ => METHOD_BLACK,
            };
            SCREEN_METHOD.store(method, Ordering::Relaxed);
            save_fnkey_settings();
            return;
        }
        #[cfg(feature = "noise-adapt")]
        ID_CLEAR_CAL => {
            crate::audio::clear_cal();
            show_balloon(
                hwnd,
                "Calibration Cleared",
                "Noise calibration data deleted.",
            );
            return;
        }
        #[cfg(feature = "noise-adapt")]
        ID_DEBUG_CAL => {
            if NOISE_ADAPT_RUNNING || CALIBRATING {
                return;
            }
            NOISE_ADAPT_RUNNING = true;
            show_balloon(
                hwnd,
                "Debug Calibration",
                "A/B test with WAV recording. Results path is in the Event Log.",
            );
            run_smart_measure_thread(hwnd, true, "debug-cal");
            set_tooltip_text(hwnd, &format!("{}: Debug Calibration...", app::NAME));
            return;
        }
        ID_EXIT => {
            let nid = new_nid(hwnd);
            let _ = Shell_NotifyIconW(NIM_DELETE, &nid);
            PostQuitMessage(0);
            return;
        }
        _ => return,
    }
    update_tooltip(hwnd);
}

unsafe fn update_tooltip(hwnd: HWND) {
    // #69: one batched read (thermal + coolsense) instead of two round trips.
    let mode = match pipe::client_transact(CMD_READ_STATE, 0) {
        Some([s, r]) if status_ok(s) => {
            let (t, c) = unpack_state(r);
            if c == 1 {
                "Smart Sense"
            } else {
                crate::mode::ThermalMode::from_u8(t).name() // UX label ("Power Saver" has the space)
            }
        }
        _ => "(unavailable)",
    };
    let label = format!("{}: {mode}", app::NAME);

    let mut nid = new_nid(hwnd);
    nid.uFlags = NIF_TIP | NIF_SHOWTIP; // NIF_SHOWTIP: keep the standard tip under v4
    set_tip(&mut nid, &label);
    let _ = Shell_NotifyIconW(NIM_MODIFY, &nid);
}

/// Run a background smart-measure (noise-adapt or debug-cal) and post the result
/// to the UI thread via `WM_NOISE_ADAPT_DONE`. `debug` selects WAV-recording A/B
/// mode; `label` tags any error log line. Shared body of the two menu handlers.
#[cfg(feature = "noise-adapt")]
fn run_smart_measure_thread(hwnd: HWND, debug: bool, label: &'static str) {
    // Disable CoolSense (a manual selection overrides auto), then capture the
    // current mode as the measurement baseline.
    pipe::client_transact(CMD_SET_COOLSENSE, 0);
    let current = pipe::client_transact(CMD_READ_THERMAL, 0)
        .map(|r| r[1])
        .unwrap_or(1);
    let hwnd_raw = hwnd.0 as usize;
    std::thread::spawn(move || {
        let result = crate::audio::smart_measure(
            current,
            |mode| {
                pipe::client_transact(CMD_SET_THERMAL, mode);
            },
            debug,
        );

        let (wparam_val, lparam_val) = match result {
            Ok(r) => {
                if let Ok(mut info) = LAST_MIC_INFO.lock() {
                    *info = (r.mic_name, r.mic_gain);
                }
                let w = r.chosen_mode as usize | if r.fast_path { 0x100 } else { 0 };
                let l = (r.delta_db * 10.0) as i32;
                (w, l)
            }
            Err(e) => {
                crate::log::warn(&format!("{label}: error: {e}"));
                (current as usize, 0i32)
            }
        };

        // SAFETY: PostMessageW is thread-safe. hwnd_raw was captured from a valid
        // HWND on the UI thread; the window outlives this worker thread.
        unsafe {
            let _ = PostMessageW(
                Some(HWND(hwnd_raw as *mut _)),
                WM_NOISE_ADAPT_DONE,
                WPARAM(wparam_val),
                LPARAM(lparam_val as isize),
            );
        }
    });
}

#[cfg(feature = "noise-adapt")]
unsafe fn set_tooltip_text(hwnd: HWND, text: &str) {
    let mut nid = new_nid(hwnd);
    nid.uFlags = NIF_TIP | NIF_SHOWTIP; // NIF_SHOWTIP: keep the standard tip under v4
    set_tip(&mut nid, text);
    let _ = Shell_NotifyIconW(NIM_MODIFY, &nid);
}

/// Show a silent balloon (toast) notification from the tray icon.
#[cfg(feature = "noise-adapt")]
unsafe fn show_balloon(hwnd: HWND, title: &str, body: &str) {
    let mut nid = new_nid(hwnd);
    nid.uFlags = NIF_INFO;
    nid.dwInfoFlags = NIIF_INFO | NIIF_NOSOUND;

    // szInfoTitle: max 63 chars
    let title_w: Vec<u16> = title.encode_utf16().collect();
    let tlen = title_w.len().min(63);
    nid.szInfoTitle[..tlen].copy_from_slice(&title_w[..tlen]);
    nid.szInfoTitle[tlen] = 0;

    // szInfo: max 255 chars
    let body_w: Vec<u16> = body.encode_utf16().collect();
    let blen = body_w.len().min(255);
    nid.szInfo[..blen].copy_from_slice(&body_w[..blen]);
    nid.szInfo[blen] = 0;

    let _ = Shell_NotifyIconW(NIM_MODIFY, &nid);
}

unsafe fn append_item(hmenu: HMENU, id: u32, text: &str, checked: bool) {
    let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    let flags = MF_STRING | if checked { MF_CHECKED } else { MF_UNCHECKED };
    let _ = AppendMenuW(hmenu, flags, id as usize, PCWSTR(wide.as_ptr()));
}

/// Window proc for the #149 fingerprint dialog. MODELESS (it lives on the tray's own message
/// loop), so WM_DESTROY must NOT PostQuitMessage — that would tear down the whole tray. WM_SIZE
/// keeps the single edit child filling the client area; the close button / Esc destroy it.
unsafe extern "system" fn hwinfo_wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_SIZE => {
            if let Ok(edit) = GetDlgItem(Some(hwnd), 1) {
                let mut rc = RECT::default();
                let _ = GetClientRect(hwnd, &mut rc);
                let _ = MoveWindow(edit, 0, 0, rc.right, rc.bottom, true);
            }
            LRESULT(0)
        }
        WM_CLOSE => {
            let _ = DestroyWindow(hwnd);
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

/// Show `text` in a read-only, SELECTABLE modeless dialog (#149). The user selects + Ctrl+C the
/// exact string — the app performs no clipboard or shell ops (consent: the copy is the user's own
/// action). Reuses only user32/gdi the tray already links; adds no imports / no capabilities.
unsafe fn show_text_dialog(text: &str) {
    let hinstance = GetModuleHandleW(None).unwrap();
    let title = wide_null("Hardware fingerprint");
    let Ok(dlg) = CreateWindowExW(
        WINDOW_EX_STYLE::default(),
        HWINFO_CLASS,
        PCWSTR(title.as_ptr()),
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        600,
        400,
        None,
        None,
        Some(hinstance.into()),
        None,
    ) else {
        return;
    };

    let mut rc = RECT::default();
    let _ = GetClientRect(dlg, &mut rc);
    // Multiline EDIT controls need CRLF, not bare LF, or every line collapses into one paragraph.
    let body = wide_null(&text.replace('\n', "\r\n"));
    if let Ok(edit) = CreateWindowExW(
        WINDOW_EX_STYLE::default(),
        w!("EDIT"),
        PCWSTR(body.as_ptr()),
        WS_CHILD
            | WS_VISIBLE
            | WS_VSCROLL
            | WINDOW_STYLE((ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL) as u32),
        0,
        0,
        rc.right,
        rc.bottom,
        Some(dlg),
        Some(HMENU(std::ptr::without_provenance_mut(1))), // control id 1 — the WM_SIZE lookup key
        Some(hinstance.into()),
        None,
    ) {
        // Native system GUI font (stock object — no cleanup) instead of the ancient default EDIT
        // font. WM_SETFONT = 0x0030, redraw = true.
        let font = GetStockObject(DEFAULT_GUI_FONT);
        SendMessageW(edit, 0x0030, Some(WPARAM(font.0 as usize)), Some(LPARAM(1)));
        // Select-all + focus so Ctrl+C copies the exact string immediately. EM_SETSEL = 0x00B1.
        SendMessageW(edit, 0x00B1, Some(WPARAM(0)), Some(LPARAM(-1)));
        let _ = SetFocus(Some(edit));
    }
}

unsafe fn append_item_disabled(hmenu: HMENU, id: u32, text: &str) {
    let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    let _ = AppendMenuW(
        hmenu,
        MF_STRING | MF_GRAYED,
        id as usize,
        PCWSTR(wide.as_ptr()),
    );
}

/// Load the tray icon by REFERENCE from a Windows system DLL — `app::ICON_DLL` #`ICON_INDEX`
/// (shared with the shortcuts), so no icon bytes are embedded and no Microsoft asset is
/// redistributed. `ExtractIconExW` returns a DPI-correct small icon. On any failure — DLL
/// missing, index shifted on a future Windows, extraction error — it falls back to the
/// generic application icon; it NEVER panics and NEVER returns a null icon.
fn load_tray_icon() -> HICON {
    // SAFETY: GetSystemDirectoryW/ExtractIconExW/LoadIconW operate on stack and
    // owned buffers with checked results; `path` is null-terminated. No caller
    // preconditions — always returns a valid, non-null HICON.
    unsafe {
        // Build "<system32>\imageres.dll" so extraction doesn't depend on the
        // current directory or DLL search path, and works on any Windows drive.
        let mut buf = [0u16; 260];
        let len = GetSystemDirectoryW(Some(&mut buf)) as usize;
        if len > 0 && len < buf.len() {
            let mut path: Vec<u16> = buf[..len].to_vec();
            path.push(b'\\' as u16);
            path.extend(app::ICON_DLL.encode_utf16());
            path.push(0);
            let mut icon = HICON::default();
            let n = ExtractIconExW(
                PCWSTR(path.as_ptr()),
                app::ICON_INDEX,
                None,
                Some(&mut icon),
                1,
            );
            if n > 0 && !icon.is_invalid() {
                return icon;
            }
        }

        // Safe fallback: the predefined, always-available application icon.
        // unwrap_or_default keeps this panic-free even in the impossible failure case.
        LoadIconW(None, IDI_APPLICATION).unwrap_or_default()
    }
}

fn new_nid(hwnd: HWND) -> NOTIFYICONDATAW {
    NOTIFYICONDATAW {
        cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: hwnd,
        uID: 1,
        ..Default::default()
    }
}

fn set_tip(nid: &mut NOTIFYICONDATAW, tip: &str) {
    let wide: Vec<u16> = tip.encode_utf16().collect();
    let len = wide.len().min(127);
    nid.szTip[..len].copy_from_slice(&wide[..len]);
    nid.szTip[len] = 0;
}

/// Enable system-aware theming for popup menus (dark/light mode).
/// Uses undocumented uxtheme.dll ordinals used by Explorer, PowerToys, Qt, SDL3, etc.
/// On Windows 10 1809+: menus follow system dark/light mode.
/// On Windows 11: also gets native rounded corners and Mica shadow.
/// On older Windows: silently no-ops, menus stay classic. Zero risk.
unsafe fn enable_system_theme_menus() {
    let uxtheme = crate::win_harden::dll::load_system32(w!("uxtheme.dll"));
    let Ok(uxtheme) = uxtheme else {
        crate::log::trace!(
            crate::log::KW_UI,
            "dark mode: uxtheme.dll not found, using classic menus"
        );
        return;
    };

    // Ordinal 135: SetPreferredAppMode(mode: u32) -> u32
    // mode 1 = AllowDark (follow system setting)
    // PCSTR with value < 0x10000 is interpreted as MAKEINTRESOURCEA(ordinal)
    let ord_135 = PCSTR(135usize as *const u8);
    let Some(proc) = GetProcAddress(uxtheme, ord_135) else {
        crate::log::trace!(
            crate::log::KW_UI,
            "dark mode: ordinal 135 not found (pre-1809?), using classic menus"
        );
        return;
    };
    let set_preferred_app_mode: unsafe extern "system" fn(u32) -> u32 = std::mem::transmute(proc);
    set_preferred_app_mode(1);

    // Ordinal 136: FlushMenuThemes() -> void
    // Forces cached menu theme to refresh. Harmless no-op on Win11 22H2+,
    // needed for some Win10 builds.
    let ord_136 = PCSTR(136usize as *const u8);
    if let Some(proc) = GetProcAddress(uxtheme, ord_136) {
        let flush_menu_themes: unsafe extern "system" fn() = std::mem::transmute(proc);
        flush_menu_themes();
    }

    crate::log::trace!(
        crate::log::KW_UI,
        "dark mode: enabled (SetPreferredAppMode=AllowDark)"
    );
}

// ---------------------------------------------------------------------------
// Fn+F12 hotkey: event handling, display control, settings persistence
// ---------------------------------------------------------------------------

const SC_MONITORPOWER: usize = 0xF170;

/// Open a named event created by the service, for SYNCHRONIZE (wait) access.
/// `None` if it doesn't exist yet (service not running); `what` labels log errors.
fn open_named_event(name: &str, what: &str) -> Option<HANDLE> {
    use windows::Win32::System::Threading::SYNCHRONIZATION_ACCESS_RIGHTS;
    let wname = wide_null(name);
    // SAFETY: `wname` is a null-terminated wide string that outlives the OpenEventW
    // call. Returns a valid handle or fails (service not running).
    let result = unsafe {
        OpenEventW(
            SYNCHRONIZATION_ACCESS_RIGHTS(0x0010_0000), // SYNCHRONIZE
            false,
            PCWSTR(wname.as_ptr()),
        )
    };
    match result {
        Ok(h) => Some(h),
        Err(e) => {
            crate::log::warn(&format!("tray: {what} event open failed: {e}"));
            None
        }
    }
}

/// Open the named event created by the service for Fn+F12 notifications.
fn open_fn_key_event() -> Option<HANDLE> {
    open_named_event(app::FNKEY_EVENT, "Fn+F12")
}

/// Open the named event signaled by the service on startup.
/// Used for version-mismatch detection (tray restarts if stale).
fn open_svc_start_event() -> Option<HANDLE> {
    open_named_event(app::SVC_START_EVENT, "svc-start")
}

/// Called when the service signals that Fn+F12 was pressed.
/// Screen toggle takes priority when both features are enabled.
/// Ctrl modifier detection was removed: the ~2s WMI poll delay means
/// Ctrl is always released by the time we check GetKeyState.
unsafe fn handle_fn_key(_hwnd: HWND) {
    // #95: idempotency guards, both from GetTickCount64 (checked only when an event fires — no poll).
    let now = GetTickCount64();
    // Post-resume suppression: drop a press latched during sleep so the wake can't re-sleep.
    if now < FNKEY_SUPPRESS_UNTIL_MS.load(Ordering::Relaxed) {
        crate::log::trace!(
            crate::log::KW_UI,
            "fn+f12: dropped (post-resume suppression)"
        );
        return;
    }
    // Debounce: coalesce key-repeat / double-taps into ONE action — for any Fn+F12 behavior.
    let last = LAST_FNKEY_MS.load(Ordering::Relaxed);
    if last != 0 && now.saturating_sub(last) < FNKEY_DEBOUNCE_MS {
        crate::log::trace!(crate::log::KW_UI, "fn+f12: dropped (debounce)");
        return;
    }
    LAST_FNKEY_MS.store(now, Ordering::Relaxed);

    if FNKEY_SCREEN_ON.load(Ordering::Relaxed) {
        let was_on = SCREEN_IS_ON.load(Ordering::Relaxed);
        SCREEN_IS_ON.store(!was_on, Ordering::Relaxed);
        let now_on = !was_on;
        crate::log::write(&format!(
            "Fn+F12: screen {}",
            if now_on { "on" } else { "off" }
        ));
        if now_on {
            screen_on();
        } else {
            screen_off();
        }
    } else if FNKEY_SLEEP_ON.load(Ordering::Relaxed) {
        crate::log::write("Fn+F12: entering sleep");
        enable_shutdown_privilege();
        let ok = SetSuspendState(false, false, false);
        if !ok {
            crate::log::warn("Fn+F12: SetSuspendState failed");
        }
        // Resumed — SetSuspendState blocks until wake. Suppress Fn+F12 briefly so the wake-press
        // (or one latched during sleep) is dropped instead of re-sleeping. Re-stamp LAST too.
        let resumed = GetTickCount64();
        FNKEY_SUPPRESS_UNTIL_MS.store(resumed + FNKEY_RESUME_SUPPRESS_MS, Ordering::Relaxed);
        LAST_FNKEY_MS.store(resumed, Ordering::Relaxed);
        crate::log::write("Fn+F12: resumed from sleep");
    }
}

/// Turn the screen off using the currently selected method.
unsafe fn screen_off() {
    let method = SCREEN_METHOD.load(Ordering::Relaxed);
    match method {
        METHOD_BRIGHTNESS => {
            // Save current brightness, then set to 0 via WMI (no power state change).
            // Also overlay a black window -- brightness=0 kills the backlight PWM,
            // black window kills LCD pixel leakage. Together = darkest without DPMS.
            if let Some([s, level]) = pipe::client_transact(CMD_READ_BRIGHTNESS, 0)
                && status_ok(s)
                && level > 0
            {
                SAVED_BRIGHTNESS.store(level, Ordering::Relaxed);
            }
            pipe::client_transact(CMD_SET_BRIGHTNESS, 0);
            if BLACK_WINDOW.0.is_null() {
                BLACK_WINDOW = create_black_window();
            }
        }
        METHOD_DPMS => {
            // Keep the system awake (don't auto-sleep) while the screen is manually off. This is
            // a PERSISTENT, per-thread request, so it stays on the long-lived UI thread — on the
            // ephemeral broadcast worker it would evaporate the instant that worker exits.
            SetThreadExecutionState(ES_SYSTEM_REQUIRED | ES_CONTINUOUS);
            // #93: the SC_MONITORPOWER broadcast is offloaded — it must NEVER run on the UI
            // thread (raw SendMessage to HWND_BROADCAST has no timeout and can wedge it forever).
            request_monitor_off();
        }
        METHOD_BLACK
            // Fullscreen topmost black window. Useful for OLED (true black).
            if BLACK_WINDOW.0.is_null() => {
                BLACK_WINDOW = create_black_window();
            }
        _ => {}
    }
}

/// Restore the screen. Cleans up ALL methods in case the user switched
/// method while the screen was off.
unsafe fn screen_on() {
    // Restore brightness if we saved it
    let saved = SAVED_BRIGHTNESS.swap(0, Ordering::Relaxed);
    if saved > 0 {
        pipe::client_transact(CMD_SET_BRIGHTNESS, saved);
    }

    // Destroy black window if present
    if !BLACK_WINDOW.0.is_null() {
        let _ = DestroyWindow(BLACK_WINDOW);
        BLACK_WINDOW = HWND(std::ptr::null_mut());
    }

    // Clear DPMS flags and force display on
    SetThreadExecutionState(ES_CONTINUOUS);
    SetThreadExecutionState(ES_DISPLAY_REQUIRED);
}

/// #93: request a DPMS monitor-off broadcast, executed OFF the UI thread. Raw
/// `SendMessageW(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, …)` has no timeout and blocks
/// until every top-level window in the system acks — so a single non-pumping window wedges the
/// caller forever. On the UI thread that permanently freezes the tray (menu/tooltip dead until
/// the process is killed). We move it to an ephemeral worker (see `monitor_off_broadcast`). A
/// dirty flag + single-worker guard coalesce mashed toggles into one worker without dropping the
/// last request; the worker exits when there's no pending request, so there's zero idle thread.
fn request_monitor_off() {
    MONITOR_OFF_DIRTY.store(true, Ordering::SeqCst);
    // Claim ownership iff no worker is active — only the claiming caller spawns. An already
    // running worker will observe DIRTY and re-broadcast, so a concurrent request is not lost.
    if MONITOR_WORKER_ACTIVE.swap(true, Ordering::SeqCst) {
        return;
    }
    std::thread::spawn(|| {
        loop {
            // Drain: broadcast once per pending request (coalesced — the target is idempotent).
            while MONITOR_OFF_DIRTY.swap(false, Ordering::SeqCst) {
                monitor_off_broadcast();
            }
            MONITOR_WORKER_ACTIVE.store(false, Ordering::SeqCst);
            // Close the race where a request set DIRTY after our last drain but before we
            // released ownership: reclaim if we can, else another caller already owns it.
            if MONITOR_OFF_DIRTY.load(Ordering::SeqCst)
                && !MONITOR_WORKER_ACTIVE.swap(true, Ordering::SeqCst)
            {
                continue;
            }
            break;
        }
    });
}

/// Bounded monitor-off broadcast — worker-thread only. `SMTO_ABORTIFHUNG` returns immediately
/// for any window already flagged not-responding; the 1000 ms per-window cap bounds a merely
/// busy (not hung) window. Unlike raw `SendMessage`, this can never wait indefinitely.
fn monitor_off_broadcast() {
    // SAFETY: a standard WM_SYSCOMMAND/SC_MONITORPOWER broadcast; no pointers are retained and
    // the timeout guarantees return even if a peer window is hung. `lpdwresult` is unused.
    unsafe {
        let _ = SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SYSCOMMAND,
            WPARAM(SC_MONITORPOWER),
            LPARAM(2), // 2 = power off
            SMTO_ABORTIFHUNG,
            1000,
            None,
        );
    }
}

/// Create a fullscreen topmost black window covering all monitors.
/// The window responds to any key/click by posting WM_SCREEN_ON to the
/// main window (safety escape if Fn+F12 event path isn't working).
unsafe fn create_black_window() -> HWND {
    let hinstance = windows::Win32::System::LibraryLoader::GetModuleHandleW(None).unwrap();
    let class_name = wide_null("HpThermalBlack");

    let wc = WNDCLASSW {
        lpfnWndProc: Some(black_wnd_proc),
        hInstance: hinstance.into(),
        lpszClassName: PCWSTR(class_name.as_ptr()),
        hbrBackground: HBRUSH(GetStockObject(BLACK_BRUSH).0),
        ..Default::default()
    };
    RegisterClassW(&wc); // idempotent (ERROR_CLASS_ALREADY_EXISTS is fine)

    // Virtual screen bounds: covers all monitors
    let x = GetSystemMetrics(SM_XVIRTUALSCREEN);
    let y = GetSystemMetrics(SM_YVIRTUALSCREEN);
    let cx = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    let cy = GetSystemMetrics(SM_CYVIRTUALSCREEN);

    let hwnd = CreateWindowExW(
        WS_EX_TOPMOST,
        PCWSTR(class_name.as_ptr()),
        None,
        WS_POPUP | WS_VISIBLE,
        x,
        y,
        cx,
        cy,
        None,
        None,
        Some(hinstance.into()),
        None,
    )
    .unwrap();

    let _ = SetForegroundWindow(hwnd);
    hwnd
}

/// Window proc for the fullscreen black window.
/// Any key/click posts WM_SCREEN_ON to the main window as a safety escape.
unsafe extern "system" fn black_wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_KEYDOWN | WM_LBUTTONDOWN | WM_MBUTTONDOWN | WM_RBUTTONDOWN => {
            let _ = PostMessageW(Some(HWND_MAIN), WM_SCREEN_ON, WPARAM(0), LPARAM(0));
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

/// Right-size the tray's own token: permanently drop every privilege the tray never uses,
/// keeping only SeChangeNotify (path traversal / file access) and SeShutdown (Fn+F12 sleep,
/// enabled on demand by `enable_shutdown_privilege`). Delegates to the shared, SSoT enforcement
/// in `win_harden` — the same helper the service uses (#2).
fn strip_unneeded_privileges() {
    let (removed, _extras) =
        crate::win_harden::strip_token_privileges_except(crate::win_harden::TRAY_KEEP_PRIVILEGES);
    crate::log::write(&format!(
        "tray: token right-sized ({removed} unused privilege(s) removed)"
    ));
}

/// Enable SE_SHUTDOWN_NAME privilege (required by SetSuspendState).
/// Harmless no-op if already enabled (the default for interactive users).
unsafe fn enable_shutdown_privilege() {
    use windows::Win32::Security::*;
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = windows::Win32::Foundation::HANDLE::default();
    if OpenProcessToken(
        GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &mut token,
    )
    .is_err()
    {
        return;
    }

    let mut luid = windows::Win32::Foundation::LUID::default();
    if LookupPrivilegeValueW(None, w!("SeShutdownPrivilege"), &mut luid).is_err() {
        let _ = CloseHandle(token);
        return;
    }

    let tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    let _ = AdjustTokenPrivileges(token, false, Some(&tp as *const _), 0, None, None);
    let _ = CloseHandle(token);
}

/// Settings file path: C:\ProgramData\HpThermal\fnkey
fn fnkey_config_path() -> String {
    format!("{}\\{}", app::data_dir(), app::FNKEY_CONFIG)
}

/// Load Fn+F12 settings from disk.
/// Format: [flags, method] -- 2 bytes. Old 1-byte files are handled (method defaults to 0).
fn load_fnkey_settings() {
    if let Ok(data) = std::fs::read(fnkey_config_path()) {
        if let Some(&byte) = data.first() {
            FNKEY_SCREEN_ON.store(byte & 0x01 != 0, Ordering::Relaxed);
            FNKEY_SLEEP_ON.store(byte & 0x02 != 0, Ordering::Relaxed);
        }
        if let Some(&method) = data.get(1)
            && method <= METHOD_BLACK
        {
            SCREEN_METHOD.store(method, Ordering::Relaxed);
        }
        crate::log::write(&format!(
            "fnkey: loaded screen={} sleep={} method={}",
            FNKEY_SCREEN_ON.load(Ordering::Relaxed),
            FNKEY_SLEEP_ON.load(Ordering::Relaxed),
            SCREEN_METHOD.load(Ordering::Relaxed),
        ));
    }
    // If file doesn't exist, defaults apply (screen=true, sleep=false, method=brightness)
}

/// Save Fn+F12 settings to disk.
fn save_fnkey_settings() {
    let screen = FNKEY_SCREEN_ON.load(Ordering::Relaxed) as u8;
    let sleep = FNKEY_SLEEP_ON.load(Ordering::Relaxed) as u8;
    let flags = screen | (sleep << 1);
    let method = SCREEN_METHOD.load(Ordering::Relaxed);
    let _ = std::fs::create_dir_all(app::data_dir());
    let _ = std::fs::write(fnkey_config_path(), [flags, method]);
}

/// Check if the running service has a different BUILD_FINGERPRINT than
/// this in-memory tray binary. If so, spawn the updated on-disk binary
/// directly (no shell) and exit. The new instance retries the singleton
/// mutex for up to 3s while we wind down.
/// The service (re)started as a build different from this tray's. We do NOT hot-swap
/// ourselves: the tray prohibits child processes (#86), and a stale tray must not keep running
/// against a newer service — so log it and exit cleanly. The normal update path already
/// relaunches via `install::ensure_tray`; an out-of-band service update (an admin manually
/// swapping the binary + restarting the service) recovers via the Run key at next logon or by
/// the admin relaunching. (Was a self-spawn; removing that spawn is what lets the tray adopt
/// prohibit_child_processes — a service-triggered relaunch task is the deferred follow-up.)
unsafe fn exit_if_service_newer(hwnd: HWND) {
    use crate::protocol::{BUILD_FINGERPRINT, CMD_READ_BUILD_ID};

    let Some(resp) = pipe::client_transact(CMD_READ_BUILD_ID, 0) else {
        return; // Service not reachable
    };
    if resp == BUILD_FINGERPRINT {
        return; // Same build
    }

    crate::log::write(&format!(
        "tray: service is a newer build (tray={:02X}{:02X} svc={:02X}{:02X}), exiting for relaunch",
        BUILD_FINGERPRINT[0], BUILD_FINGERPRINT[1], resp[0], resp[1],
    ));

    // Remove the tray icon before exiting (avoids a ghost icon).
    let nid = new_nid(hwnd);
    let _ = Shell_NotifyIconW(NIM_DELETE, &nid);

    // No self-spawn — exit and let ensure_tray / the Run key bring up the new build.
    PostQuitMessage(0);
}
