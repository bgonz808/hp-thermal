#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![deny(clippy::undocumented_unsafe_blocks)]
// `unsafe_op_in_unsafe_fn` is allowed: this FFI-dense crate documents SAFETY at the fn
// boundary rather than per-op. The `deny` above still forces SAFETY on every standalone
// unsafe block. Per-op SAFETY blocks are tracked as future work — see #25.
#![allow(unsafe_op_in_unsafe_fn)]

#[allow(dead_code)]
mod app;
#[cfg(feature = "noise-adapt")]
mod audio;
mod consent;
mod hwinfo;
mod install;
mod log;
mod mitigations;
mod nvml;
mod onboarding;
mod pipe;
mod protocol;
mod service;
mod tray;
mod wide;
mod wmi_com;

use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::UI::Controls::*;
use windows::Win32::UI::WindowsAndMessaging::*;
use windows::core::{HRESULT, PCWSTR};

use crate::wide::wide_null;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const BUILD_ID: &str = env!("BUILD_ID");
const BUILD_DATE: &str = env!("BUILD_DATE");

const BTN_ACTION: i32 = 100;
const BTN_CANCEL: i32 = 2; // IDCANCEL

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // #54: the no-arg role is the tray and its bootstrap installer/launcher — the
    // weakly-mitigated, user-facing role (loads nvml, runs a win32k GUI, is a common
    // injection target, and as the installer is a long-lived dialog from an unvetted
    // download folder). It must NEVER run above Medium IL. We do NOT try to de-elevate:
    // dropping High->Medium from an elevated process reliably needs the interactive
    // user's token (fragile — no "correct user" guarantee; MS guidance is to run the
    // launcher unelevated instead), and the prior runas /trustlevel attempt neither
    // lowered IL nor stopped fork-bombing this guard. So refuse — with NO file I/O: an
    // elevated log::init would leave an admin-owned log in the user data dir (CWE-732),
    // the very thing this guard exists to prevent. This fires before mitigations, the
    // hardware probe, consent, or the log. Normal launches (logon Run key, bootstrap, the
    // post-update Medium parent) are already Medium, so this is a backstop against
    // Run-as-administrator, not a happy path. Only --service (SCM/SYSTEM) and the UAC
    // install children (install/*-svc) run elevated by design.
    if args.get(1).is_none() && install::is_elevated() {
        // Exit immediately and SILENTLY. A modal MessageBox here would run its own message
        // loop inside THIS elevated process until dismissed — prolonging the High-IL
        // lifetime and being the exact long-lived elevated message pump we avoid. A
        // non-blocking popup can't be hosted by an elevated process either, so there is no
        // cheap "warn and exit" (see the refuse-vs-de-elevate note where this is called).
        // No file I/O (an elevated log::init would leave an admin-owned log, CWE-732).
        // Normal launches are Medium; this only fires on Run-as-administrator misuse.
        return;
    }

    // Harden every role (tray, service, installer helpers) as early as possible.
    mitigations::apply();

    match args.get(1).map(|s| s.as_str()) {
        Some("--service") => {
            // Crown-jewel hardening: the SYSTEM service loads only MS-signed
            // WMI/COM DLLs, so lock it to Microsoft-signed images only (blocks all
            // non-MS injection/planting). Not applied to the tray (nvml + GUI
            // third-party injection). Set before WMI/COM pulls in its DLLs.
            mitigations::enforce_ms_signed_only();
            // The service spawns no child processes; forbid it at the OS level so even
            // injected code cannot shell out (LOLBin/proxy exfil). Service-only (#47).
            mitigations::prohibit_child_processes();
            // Headless service has no GUI — cut off the win32k syscall surface (a major
            // kernel LPE target). Service-only; live-validated. (#48)
            mitigations::disallow_win32k_syscalls();
            // Strongest anti-shellcode mitigation: forbid dynamic/executable-memory codegen
            // (ProhibitDynamicCode). Validated audit-first (a clean live run) then enforced.
            // Service-only; live-validated. (#24)
            mitigations::prohibit_dynamic_code();
            service::run();
        }
        Some("install" | "--install") => {
            // HP gate first (never elevate on non-HP). Then split update vs fresh
            // install. The onboarding dialog (fresh install only) runs HERE, in the
            // non-elevated launcher, BEFORE the setup lock and BEFORE UAC — so cancel
            // means no lock, no prompt, nothing.
            if require_hp().is_none() {
                return;
            }
            if install::is_service_installed() {
                // Update: no dialog; existing choices are preserved.
                let Some(_lock) = install::acquire_setup_lock() else {
                    install::warn_setup_in_progress();
                    return;
                };
                install::update();
            } else if let Some(choices) = onboarding::prompt() {
                let Some(_lock) = install::acquire_setup_lock() else {
                    install::warn_setup_in_progress();
                    return;
                };
                install::install(choices);
                // Launch the tray once the service is up: immediately if we were
                // already elevated (no child to wait on), else after the child starts it.
                if install::is_elevated() || install::wait_for_service_running() {
                    install::ensure_tray();
                }
            }
        }
        // Internal: UAC children — do sc commands only, parent handles tray.
        // `--install-svc [--startup] [--start-menu] [--desktop]` carries the onboarding
        // choices as readable flags. from_args presence-scans the WHOLE argv (the exe
        // path and `--install-svc` can't match a flag), so there's no positional index
        // to drift; unknown/extra args are ignored.
        //
        // CIG here too: the elevated install/update child may run from a user-writable
        // dir (e.g. Downloads) on first install, so lock it to Microsoft-signed images
        // to block DLL planting/injection into the admin process. Safe because it loads
        // only MS-signed system DLLs — nvml (NVIDIA, non-MS) is tray-only, never loaded
        // on this path. Set before install_service pulls in shell/COM for shortcuts.
        Some("--install-svc") => {
            mitigations::enforce_ms_signed_only();
            install::install_service(onboarding::Choices::from_args(&args));
        }
        Some("--update-svc") => {
            mitigations::enforce_ms_signed_only();
            install::update_service();
        }
        Some("--stop-svc") => install::stop_service(),
        Some("--start-svc") => install::start_service(),
        Some("stop" | "--stop") => guarded_setup(install::stop),
        Some("start" | "--start") => guarded_setup(install::start),
        Some("uninstall" | "--uninstall") => guarded_setup(install::uninstall),
        // Dev preview: pop the fresh-install onboarding dialog and report the
        // choices. Pure UI — no hardware check, no elevation, no system change.
        Some("--preview-onboarding") => report_choices(onboarding::prompt()),
        Some("--help" | "-h" | "help") => print_help(),
        Some("--version" | "-v" | "-V") => {
            println!("{} {VERSION}+{BUILD_ID} ({BUILD_DATE})", app::BIN_NAME);
        }
        None => default_run(),
        Some(unknown) => {
            eprintln!("Unknown argument: {unknown}");
            print_help();
        }
    }
}

/// Hard manufacturer gate. Reads SMBIOS (unelevated) and rejects non-HP hardware
/// with an error dialog BEFORE anything can elevate (UAC) or modify system state.
/// Every command that installs, elevates, or changes the service must call this
/// FIRST — fail early, on unsupported hardware, before any permission or change.
/// Run a privileged setup operation behind the two mandatory gates, in order:
/// (1) the HP-hardware check — never elevate or touch a non-HP box; (2) the
/// setup lock — fail closed, with user feedback on contention. The lock is held
/// for the whole operation and released when it returns. Every install/update/
/// start/stop/uninstall entry point must go through here so the ordering is
/// enforced in exactly one place.
fn guarded_setup(op: impl FnOnce()) {
    if require_hp().is_none() {
        return;
    }
    let Some(_lock) = install::acquire_setup_lock() else {
        install::warn_setup_in_progress();
        return;
    };
    op();
}

fn require_hp() -> Option<hwinfo::HwInfo> {
    let hw = hwinfo::HwInfo::read();
    if !hw.is_hp() {
        let msg = format!(
            "This app requires an HP laptop.\n\n\
             Detected hardware:\n  \
             Manufacturer: {}\n  \
             Model: {}\n\n\
             Your hardware is not supported.",
            hw.manufacturer, hw.product
        );
        msgbox(&msg, MB_OK | MB_ICONERROR);
        return None;
    }
    Some(hw)
}

fn default_run() {
    let Some(hw) = require_hp() else {
        return;
    };

    // Consent gate: run silently only on dev-validated or user-accepted hardware.
    // Firing here (before both the bootstrap and installed-copy branches) means the
    // bootstrap copy prompts once and records acceptance, so the installed copy it
    // launches sees a matching fingerprint and does not prompt again.
    if let consent::Consent::NeedsPrompt { firmware_changed } = consent::check(&hw) {
        let content = if firmware_changed {
            format!(
                "The system firmware has changed since you enabled {} on this machine \
                 (board {}, BIOS {}).\n\n\
                 Thermal control uses an undocumented HP interface that firmware updates \
                 can change without notice. Re-confirm that you want to keep it enabled?",
                app::NAME,
                hw.board,
                hw.bios_version,
            )
        } else {
            format!(
                "{} was validated by its developers only on the HP ENVY 16 (board 8BE5).\n\n\
                 Your hardware (board {}, BIOS {}) is community-untested. Thermal control uses \
                 an undocumented HP interface and may not work, or may behave differently, on \
                 your model.\n\n\
                 Enable thermal control on this machine anyway?",
                app::NAME,
                hw.board,
                hw.bios_version,
            )
        };
        if !task_dialog("Enable", &content, TD_WARNING_ICON, false) {
            return;
        }
        consent::record_acceptance(&hw);
    }

    // If we're NOT the installed copy, act as a bootstrap installer/launcher.
    if !install::is_installed_copy() {
        bootstrap_run();
        return;
    }

    // --- We ARE the installed copy (running from Program Files) ---

    if !install::is_service_installed() {
        // Installed copy, but the service is missing (repair). Onboarding is the
        // confirmation + options, shown pre-lock / pre-UAC. Cancel = nothing.
        let Some(choices) = onboarding::prompt() else {
            return;
        };
        let Some(_lock) = install::acquire_setup_lock() else {
            install::warn_setup_in_progress();
            return;
        };
        install::install(choices);
        if !install::wait_for_service_running() {
            msgbox("Service failed to start.", MB_OK | MB_ICONERROR);
            return;
        }
    } else if !install::is_service_running() {
        let content = format!("The {} service is installed but not running.", app::NAME);
        if !task_dialog("Start Service", &content, TD_WARNING_ICON, false) {
            return;
        }
        let Some(_lock) = install::acquire_setup_lock() else {
            install::warn_setup_in_progress();
            return;
        };
        install::start();
        if !install::wait_for_service_running() {
            msgbox("Service failed to start.", MB_OK | MB_ICONERROR);
            return;
        }
    }

    tray::run();
}

/// Called when running from a non-installed location (Desktop, Downloads, etc.).
/// Handles fresh install, update, or redirect to the existing installed copy.
/// The bootstrap copy NEVER calls tray::run() — it always launches the PF copy and exits.
fn bootstrap_run() {
    // Read-only decisions and user consent come FIRST — no lock. The setup lock
    // is acquired only immediately before the mutating install/update, held for
    // that critical section, and never across a dialog. This is what keeps a
    // stuck/leaked lock from silently swallowing every future launch.
    if !install::is_service_installed() {
        // Fresh install: the onboarding dialog is the confirmation + options, shown
        // here in the non-elevated launcher BEFORE the lock or UAC. Cancel = nothing.
        let Some(choices) = onboarding::prompt() else {
            return;
        };
        let Some(_lock) = install::acquire_setup_lock() else {
            install::warn_setup_in_progress();
            return;
        };
        install::install(choices);
        if !install::wait_for_service_running() {
            msgbox(
                "Service failed to start. Try running install from an admin prompt.",
                MB_OK | MB_ICONERROR,
            );
            return;
        }
        install::ensure_tray();
        return;
    }

    if !install::is_service_current() {
        // Update: this copy differs from the installed one. Show the version delta
        // (if we can read the installed version) and reassure that choices are kept.
        let new = env!("CARGO_PKG_VERSION");
        let head = match install::installed_version() {
            Some(old) if old != new => format!("Update from v{old} to v{new}?"),
            _ => format!("Reinstall {} v{new}?", app::NAME),
        };
        let content = format!(
            "{head}\n\n\
             This replaces the background service.\n\
             Your settings and shortcuts are kept."
        );
        if !task_dialog("Update", &content, TD_WARNING_ICON, true) {
            // User declined the update. Just exit: cancelling a setup dialog must neither
            // launch anything nor depend on any extant tray/service. (Previously this
            // spawned a redundant tray that blocked ~3s on the singleton wait. #59)
            return;
        }
        let Some(_lock) = install::acquire_setup_lock() else {
            install::warn_setup_in_progress();
            return;
        };
        // #54: the elevated UAC child (--update-svc) does the privileged work ONLY
        // (stop / replace binary / start) and exits. install() runs here in the
        // logged-in-user (Medium IL) process: it waits for that child to finish, then
        // launches the tray at Medium IL — the tray must never be launched elevated.
        install::update();
        return;
    }

    // Installed and current — this is a deliberately-run copy, so give feedback
    // (rather than silently vanishing) before handing off to the installed tray.
    msgbox(
        &format!("{} is already installed and up to date.", app::NAME),
        MB_OK | MB_ICONINFORMATION,
    );
    install::ensure_tray();
}

/// Show a TaskDialog with a custom action button + Cancel. When `shield` is set, the
/// action button wears the UAC shield (it elevates on click).
/// Returns true if the user clicked the action button, false for Cancel/X.
fn task_dialog(action_label: &str, content: &str, icon: PCWSTR, shield: bool) -> bool {
    let title = wide_null(app::NAME);
    let content_w = wide_null(content);
    let action_w = wide_null(action_label);

    let buttons = [
        TASKDIALOG_BUTTON {
            nButtonID: BTN_ACTION,
            pszButtonText: PCWSTR(action_w.as_ptr()),
        },
        TASKDIALOG_BUTTON {
            nButtonID: BTN_CANCEL,
            pszButtonText: windows::core::w!("Cancel"),
        },
    ];

    let config = TASKDIALOGCONFIG {
        cbSize: std::mem::size_of::<TASKDIALOGCONFIG>() as u32,
        dwFlags: TDF_ALLOW_DIALOG_CANCELLATION,
        pszWindowTitle: PCWSTR(title.as_ptr()),
        Anonymous1: TASKDIALOGCONFIG_0 { pszMainIcon: icon },
        pszContent: PCWSTR(content_w.as_ptr()),
        cButtons: buttons.len() as u32,
        pButtons: buttons.as_ptr(),
        nDefaultButton: BTN_ACTION,
        pfCallback: if shield { Some(td_shield_cb) } else { None },
        ..Default::default()
    };

    let mut pressed = 0i32;
    // SAFETY: `config` is fully initialized on the stack with valid PCWSTR pointers
    // to local wide strings that outlive the call. `buttons` array is stack-allocated.
    let ok = unsafe { TaskDialogIndirect(&config, Some(&mut pressed), None, None) };
    ok.is_ok() && pressed == BTN_ACTION
}

/// TaskDialog callback: once the dialog is created, stamp the UAC shield on the
/// action button (it triggers elevation on click).
unsafe extern "system" fn td_shield_cb(
    hwnd: HWND,
    msg: TASKDIALOG_NOTIFICATIONS,
    _wparam: WPARAM,
    _lparam: LPARAM,
    _ref_data: isize,
) -> HRESULT {
    if msg == TDN_CREATED {
        SendMessageW(
            hwnd,
            TDM_SET_BUTTON_ELEVATION_REQUIRED_STATE.0 as u32,
            Some(WPARAM(BTN_ACTION as usize)),
            Some(LPARAM(1)),
        );
    }
    HRESULT(0) // S_OK
}

fn msgbox(text: &str, flags: MESSAGEBOX_STYLE) -> MESSAGEBOX_RESULT {
    let title = wide_null(app::NAME);
    let body = wide_null(text);
    // SAFETY: `title` and `body` are null-terminated wide strings on the stack
    // that outlive the synchronous MessageBoxW call.
    unsafe { MessageBoxW(None, PCWSTR(body.as_ptr()), PCWSTR(title.as_ptr()), flags) }
}

/// Report the choices returned by an onboarding dialog (dev preview).
/// Cancel/close is silent — it just exits, as the real install will.
fn report_choices(choices: Option<onboarding::Choices>) {
    if let Some(c) = choices {
        msgbox(
            &format!(
                "Install clicked.\n\n\
                 Run at startup: {}\n\
                 Start Menu shortcut: {}\n\
                 Desktop shortcut: {}",
                c.run_at_startup, c.start_menu, c.desktop
            ),
            MB_OK | MB_ICONINFORMATION,
        );
    }
}

fn print_help() {
    let bin = app::BIN_NAME;
    println!("{bin} {VERSION}+{BUILD_ID} ({BUILD_DATE})");
    println!("HP laptop thermal mode control — without the bloat.\n");
    println!("USAGE:");
    println!("  {bin}              Launch tray app (installs service if needed)");
    println!("  {bin} install      Install and start the background service");
    println!("  {bin} uninstall    Stop and remove the background service");
    println!("  {bin} start        Start the service");
    println!("  {bin} stop         Stop the service");
    println!("  {bin} --help       Show this help");
    println!("  {bin} --version    Show version");
}
