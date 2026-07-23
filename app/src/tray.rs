use windows::core::{w, PCSTR, PCWSTR};
use windows::Win32::Foundation::*;
use windows::Win32::Graphics::Gdi::{GetStockObject, BLACK_BRUSH, HBRUSH};
use windows::Win32::System::LibraryLoader::{
    GetModuleHandleW, GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use windows::Win32::System::Power::*;
use windows::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows::Win32::System::Threading::{CreateMutexW, OpenEventW, WaitForSingleObject, INFINITE};
use windows::Win32::UI::Input::KeyboardAndMouse::GetKeyState;
use windows::Win32::UI::Shell::*;
use windows::Win32::UI::WindowsAndMessaging::*;

use crate::app;
use crate::pipe;
use crate::protocol::*;
use crate::wide::wide_null;

const WM_TRAYICON: u32 = WM_USER + 1;
const ID_SMART_SENSE: u32 = 100;
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
const ID_VERBOSE_LOG: u32 = 309;
const ID_OPEN_LOG: u32 = 310;
const ID_RESTART_SVC: u32 = 311;
const ID_STACK_MONITOR: u32 = 312;
const ID_CLEAR_LOG: u32 = 313;
#[cfg(feature = "noise-adapt")]
const ID_CLEAR_CAL: u32 = 314;
#[cfg(feature = "noise-adapt")]
const ID_OPEN_TSV: u32 = 315;
#[cfg(feature = "noise-adapt")]
const ID_DEBUG_CAL: u32 = 316;
const ID_FNKEY_SCREEN: u32 = 317;
const ID_FNKEY_SLEEP: u32 = 318;
const ID_METHOD_BRIGHTNESS: u32 = 319;
const ID_METHOD_DPMS: u32 = 320;
const ID_METHOD_BLACK: u32 = 321;
const WM_SCREEN_ON: u32 = WM_USER + 4;

const METHOD_DPMS: u8 = 0;
const METHOD_BRIGHTNESS: u8 = 1;
const METHOD_BLACK: u8 = 2;

static mut HWND_MAIN: HWND = HWND(std::ptr::null_mut());
static mut VERBOSE_ON: bool = false;
static mut STACK_MONITOR_ON: bool = false;
#[cfg(feature = "noise-adapt")]
static mut NOISE_ADAPT_RUNNING: bool = false;
#[cfg(feature = "noise-adapt")]
static mut CALIBRATING: bool = false;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

static FNKEY_SCREEN_ON: AtomicBool = AtomicBool::new(true);
static FNKEY_SLEEP_ON: AtomicBool = AtomicBool::new(false);
/// Tracks display state for toggling. true = screen is on.
static SCREEN_IS_ON: AtomicBool = AtomicBool::new(true);
/// Screen-off method: 0=DPMS, 1=Brightness, 2=Black Window.
static SCREEN_METHOD: AtomicU8 = AtomicU8::new(0);
/// Saved brightness level (1-100) to restore on screen-on.
static SAVED_BRIGHTNESS: AtomicU8 = AtomicU8::new(0);
static mut BLACK_WINDOW: HWND = HWND(std::ptr::null_mut());

/// Last mic info from noise-adapt or calibration thread (stashed for UI display).
#[cfg(feature = "noise-adapt")]
static LAST_MIC_INFO: std::sync::Mutex<(String, f32)> = std::sync::Mutex::new((String::new(), 0.0));

pub fn run() {
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
    crate::log::write("tray starting");

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
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_TRAYICON;
    nid.hIcon = load_tray_icon();
    set_tip(&mut nid, app::NAME);
    let _ = Shell_NotifyIconW(NIM_ADD, &nid);

    // Immediately read current mode and update tooltip
    update_tooltip(HWND_MAIN);

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
                    // Service restarted — check if we're stale
                    version_mismatch_restart(HWND_MAIN);
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
            let event = (lparam.0 as u32) & 0xFFFF;
            if event == WM_RBUTTONUP {
                show_context_menu(hwnd);
            }
            LRESULT(0)
        }
        WM_COMMAND => {
            let id = (wparam.0 as u32) & 0xFFFF;
            handle_menu(hwnd, id);
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

unsafe fn show_context_menu(hwnd: HWND) {
    let debug = (GetKeyState(0x10) as u16 & 0x8000) != 0; // VK_SHIFT = 0x10

    // Read current state from the service
    let thermal = pipe::client_transact(CMD_READ_THERMAL, 0);
    let coolsense = pipe::client_transact(CMD_READ_COOLSENSE, 0);
    crate::log::stack_sample("tray:menu_query");

    let current_mode: Option<u8> =
        thermal.and_then(|r| if status_ok(r[0]) { Some(r[1]) } else { None });
    let cs_on: Option<bool> = coolsense.and_then(|r| {
        if status_ok(r[0]) {
            Some(r[1] != 0)
        } else {
            None
        }
    });

    let hmenu = CreatePopupMenu().unwrap();
    let connected = thermal.is_some() || coolsense.is_some();

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

    // Thermal mode items
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
            append_item(hmenu, ID_OPEN_TSV, "Open capture TSV", false);
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
        append_item(hmenu, ID_VERBOSE_LOG, "Verbose Logging", VERBOSE_ON);
        append_item(hmenu, ID_STACK_MONITOR, "Stack Monitor", STACK_MONITOR_ON);
        append_item(hmenu, ID_OPEN_LOG, "Open Log", false);
        append_item(hmenu, ID_CLEAR_LOG, "Clear Log", false);
    }

    // KB Q135788: SetForegroundWindow before TrackPopupMenu
    let mut pt = POINT::default();
    let _ = GetCursorPos(&mut pt);
    let _ = SetForegroundWindow(hwnd);
    let _ = TrackPopupMenu(
        hmenu,
        TPM_LEFTALIGN | TPM_RIGHTBUTTON,
        pt.x,
        pt.y,
        Some(0),
        hwnd,
        None,
    );
    let _ = PostMessageW(Some(hwnd), WM_NULL, WPARAM(0), LPARAM(0));

    let _ = DestroyMenu(hmenu);
}

unsafe fn handle_menu(hwnd: HWND, id: u32) {
    match id {
        ID_SMART_SENSE => {
            // Toggle CoolSense
            let current = pipe::client_transact(CMD_READ_COOLSENSE, 0);
            let new_val = match current {
                Some([s, state]) if status_ok(s) => {
                    if state != 0 {
                        0
                    } else {
                        1
                    }
                }
                _ => 1,
            };
            pipe::client_transact(CMD_SET_COOLSENSE, new_val);
        }
        #[cfg(feature = "noise-adapt")]
        ID_NOISE_ADAPTED => {
            if NOISE_ADAPT_RUNNING || CALIBRATING {
                return;
            }
            NOISE_ADAPT_RUNNING = true;

            // Disable CoolSense (manual selection overrides auto)
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
                    false,
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
                        crate::log::write(&format!("noise-adapt: error: {e}"));
                        (current as usize, 0i32)
                    }
                };

                // SAFETY: PostMessageW is thread-safe. hwnd_raw was captured from a
                // valid HWND on the UI thread; the window outlives this worker thread.
                unsafe {
                    let _ = PostMessageW(
                        Some(HWND(hwnd_raw as *mut _)),
                        WM_NOISE_ADAPT_DONE,
                        WPARAM(wparam_val),
                        LPARAM(lparam_val as isize),
                    );
                }
            });

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
                        crate::log::write(&format!("stress-cal: error: {e}"));
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
        }
        ID_RESTART_SVC => {
            // sdset grants interactive users start rights — no UAC needed
            crate::install::start();
            if crate::install::wait_for_service_running() {
                update_tooltip(hwnd);
            }
            return;
        }
        ID_VERBOSE_LOG => {
            VERBOSE_ON = !VERBOSE_ON;
            crate::log::set_verbose(VERBOSE_ON);
            pipe::client_transact(CMD_SET_LOGGING, if VERBOSE_ON { 1 } else { 0 });
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
        ID_OPEN_LOG => {
            let path = crate::log::log_path();
            let path_w = crate::wide::wide_null(&path);
            // SAFETY: path_w is a null-terminated wide string on the stack;
            // ShellExecuteW reads it synchronously before returning.
            unsafe {
                ShellExecuteW(
                    None,
                    w!("open"),
                    PCWSTR(path_w.as_ptr()),
                    None,
                    None,
                    SW_SHOW,
                );
            }
            return;
        }
        ID_CLEAR_LOG => {
            crate::log::clear();
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
        ID_OPEN_TSV => {
            let path = format!("{}\\noise-capture.tsv", app::data_dir());
            let path_w = crate::wide::wide_null(&path);
            // SAFETY: Same ShellExecuteW contract as ID_OPEN_LOG above.
            unsafe {
                ShellExecuteW(
                    None,
                    w!("open"),
                    PCWSTR(path_w.as_ptr()),
                    None,
                    None,
                    SW_SHOW,
                );
            }
            return;
        }
        #[cfg(feature = "noise-adapt")]
        ID_DEBUG_CAL => {
            if NOISE_ADAPT_RUNNING || CALIBRATING {
                return;
            }
            NOISE_ADAPT_RUNNING = true;

            pipe::client_transact(CMD_SET_COOLSENSE, 0);

            let current = pipe::client_transact(CMD_READ_THERMAL, 0)
                .map(|r| r[1])
                .unwrap_or(1);

            show_balloon(
                hwnd,
                "Debug Calibration",
                "A/B test with WAV recording.\nWill open results folder when done.",
            );

            let hwnd_raw = hwnd.0 as usize;
            std::thread::spawn(move || {
                let result = crate::audio::smart_measure(
                    current,
                    |mode| {
                        pipe::client_transact(CMD_SET_THERMAL, mode);
                    },
                    true,
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
                        crate::log::write(&format!("debug-cal: error: {e}"));
                        (current as usize, 0i32)
                    }
                };

                // SAFETY: Same PostMessageW cross-thread contract as noise-adapt above.
                unsafe {
                    let _ = PostMessageW(
                        Some(HWND(hwnd_raw as *mut _)),
                        WM_NOISE_ADAPT_DONE,
                        WPARAM(wparam_val),
                        LPARAM(lparam_val as isize),
                    );
                }
            });

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
    let thermal = pipe::client_transact(CMD_READ_THERMAL, 0);
    let cs = pipe::client_transact(CMD_READ_COOLSENSE, 0);

    let mode = match (cs, thermal) {
        (Some([s, 1]), _) if status_ok(s) => "Smart Sense",
        (_, Some([s, 0])) if status_ok(s) => "Performance",
        (_, Some([s, 1])) if status_ok(s) => "Balanced",
        (_, Some([s, 2])) if status_ok(s) => "Cool",
        (_, Some([s, 3])) if status_ok(s) => "Power Saver",
        _ => "(unavailable)",
    };
    let label = format!("{}: {mode}", app::NAME);

    let mut nid = new_nid(hwnd);
    nid.uFlags = NIF_TIP;
    set_tip(&mut nid, &label);
    let _ = Shell_NotifyIconW(NIM_MODIFY, &nid);
}

#[cfg(feature = "noise-adapt")]
unsafe fn set_tooltip_text(hwnd: HWND, text: &str) {
    let mut nid = new_nid(hwnd);
    nid.uFlags = NIF_TIP;
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

unsafe fn append_item_disabled(hmenu: HMENU, id: u32, text: &str) {
    let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    let _ = AppendMenuW(
        hmenu,
        MF_STRING | MF_GRAYED,
        id as usize,
        PCWSTR(wide.as_ptr()),
    );
}

/// Load the tray icon by REFERENCE from a Windows system DLL — no icon bytes are
/// embedded in our binary, and no Microsoft asset is redistributed. Uses
/// `imageres.dll` #144 (the green activity/performance graph) at the DPI-correct
/// small-icon size (`ExtractIconExW` returns `SM_CXSMICON`-sized icons). If
/// anything fails — DLL missing, index shifted on a future Windows, extraction
/// error — it falls back to the generic application icon. It NEVER panics and
/// NEVER returns a null icon (a null `hIcon` would show a blank/broken tray entry).
unsafe fn load_tray_icon() -> HICON {
    // imageres.dll #144 = green activity/performance graph. Index can shift across
    // major Windows releases, so this is best-effort with a guaranteed fallback.
    const IMAGERES_PERF_GRAPH: i32 = 144;

    // Build "<system32>\imageres.dll" so extraction doesn't depend on the current
    // directory or DLL search path, and works regardless of the Windows drive.
    let mut buf = [0u16; 260];
    let len = GetSystemDirectoryW(Some(&mut buf)) as usize;
    if len > 0 && len < buf.len() {
        let mut path: Vec<u16> = buf[..len].to_vec();
        path.extend(r"\imageres.dll".encode_utf16());
        path.push(0);
        let mut icon = HICON::default();
        let n = ExtractIconExW(
            PCWSTR(path.as_ptr()),
            IMAGERES_PERF_GRAPH,
            None,
            Some(&mut icon),
            1,
        );
        if n > 0 && !icon.is_invalid() {
            return icon;
        }
    }

    // Safe fallback: the predefined, always-available application icon. Using
    // unwrap_or_default keeps this panic-free even in the impossible failure case.
    LoadIconW(None, IDI_APPLICATION).unwrap_or_default()
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
    let uxtheme = LoadLibraryExW(w!("uxtheme.dll"), None, LOAD_LIBRARY_SEARCH_SYSTEM32);
    let Ok(uxtheme) = uxtheme else {
        if crate::log::is_verbose() {
            crate::log::write("dark mode: uxtheme.dll not found, using classic menus");
        }
        return;
    };

    // Ordinal 135: SetPreferredAppMode(mode: u32) -> u32
    // mode 1 = AllowDark (follow system setting)
    // PCSTR with value < 0x10000 is interpreted as MAKEINTRESOURCEA(ordinal)
    let ord_135 = PCSTR(135usize as *const u8);
    let Some(proc) = GetProcAddress(uxtheme, ord_135) else {
        if crate::log::is_verbose() {
            crate::log::write("dark mode: ordinal 135 not found (pre-1809?), using classic menus");
        }
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

    if crate::log::is_verbose() {
        crate::log::write("dark mode: enabled (SetPreferredAppMode=AllowDark)");
    }
}

// ---------------------------------------------------------------------------
// Fn+F12 hotkey: event handling, display control, settings persistence
// ---------------------------------------------------------------------------

const SC_MONITORPOWER: usize = 0xF170;

/// Open the named event created by the service for Fn+F12 notifications.
fn open_fn_key_event() -> Option<HANDLE> {
    use windows::Win32::System::Threading::SYNCHRONIZATION_ACCESS_RIGHTS;
    let name = wide_null(app::FNKEY_EVENT);
    // SAFETY: name is a null-terminated wide string on the stack that outlives
    // the OpenEventW call. Returns a valid handle or fails (service not running).
    let result = unsafe {
        OpenEventW(
            SYNCHRONIZATION_ACCESS_RIGHTS(0x0010_0000), // SYNCHRONIZE
            false,
            PCWSTR(name.as_ptr()),
        )
    };
    match result {
        Ok(h) => Some(h),
        Err(e) => {
            crate::log::write(&format!("tray: Fn+F12 event open failed: {e}"));
            None
        }
    }
}

/// Open the named event signaled by the service on startup.
/// Used for version-mismatch detection (tray restarts if stale).
fn open_svc_start_event() -> Option<HANDLE> {
    use windows::Win32::System::Threading::SYNCHRONIZATION_ACCESS_RIGHTS;
    let name = wide_null(app::SVC_START_EVENT);
    // SAFETY: Same contract as open_fn_key_event above.
    let result = unsafe {
        OpenEventW(
            SYNCHRONIZATION_ACCESS_RIGHTS(0x0010_0000), // SYNCHRONIZE
            false,
            PCWSTR(name.as_ptr()),
        )
    };
    match result {
        Ok(h) => Some(h),
        Err(e) => {
            crate::log::write(&format!("tray: svc-start event open failed: {e}"));
            None
        }
    }
}

/// Called when the service signals that Fn+F12 was pressed.
/// Screen toggle takes priority when both features are enabled.
/// Ctrl modifier detection was removed: the ~2s WMI poll delay means
/// Ctrl is always released by the time we check GetKeyState.
unsafe fn handle_fn_key(_hwnd: HWND) {
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
            crate::log::write("Fn+F12: SetSuspendState failed");
        }
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
            if let Some([s, level]) = pipe::client_transact(CMD_READ_BRIGHTNESS, 0) {
                if status_ok(s) && level > 0 {
                    SAVED_BRIGHTNESS.store(level, Ordering::Relaxed);
                }
            }
            pipe::client_transact(CMD_SET_BRIGHTNESS, 0);
            if BLACK_WINDOW.0.is_null() {
                BLACK_WINDOW = create_black_window();
            }
        }
        METHOD_DPMS => {
            // DPMS off via SC_MONITORPOWER. Warning: triggers Modern Standby on
            // some systems, which can freeze this process for 16-22 seconds.
            SetThreadExecutionState(ES_SYSTEM_REQUIRED | ES_CONTINUOUS);
            SendMessageW(
                HWND(0xFFFF as *mut _),
                WM_SYSCOMMAND,
                Some(WPARAM(SC_MONITORPOWER)),
                Some(LPARAM(2)),
            );
        }
        METHOD_BLACK => {
            // Fullscreen topmost black window. Useful for OLED (true black).
            if BLACK_WINDOW.0.is_null() {
                BLACK_WINDOW = create_black_window();
            }
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
        if let Some(&method) = data.get(1) {
            if method <= METHOD_BLACK {
                SCREEN_METHOD.store(method, Ordering::Relaxed);
            }
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
unsafe fn version_mismatch_restart(hwnd: HWND) {
    use crate::protocol::{BUILD_FINGERPRINT, CMD_READ_BUILD_ID};

    let Some(resp) = pipe::client_transact(CMD_READ_BUILD_ID, 0) else {
        return; // Service not reachable
    };
    if resp == BUILD_FINGERPRINT {
        return; // Same build
    }

    crate::log::write(&format!(
        "tray: version mismatch (tray={:02X}{:02X} svc={:02X}{:02X}), restarting",
        BUILD_FINGERPRINT[0], BUILD_FINGERPRINT[1], resp[0], resp[1],
    ));

    // Remove tray icon before exiting (avoids ghost icon in the tray)
    let nid = new_nid(hwnd);
    let _ = Shell_NotifyIconW(NIM_DELETE, &nid);

    // Spawn the updated binary directly — no shell, no cmd.exe.
    // Path is the canonical install location (C:\Program Files\HpThermal\).
    let installed = app::installed_exe();
    let _ = std::process::Command::new(&installed).spawn();

    PostQuitMessage(0);
}
