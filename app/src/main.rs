#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![deny(clippy::undocumented_unsafe_blocks)]
// Edition 2024's unsafe_op_in_unsafe_fn would require wrapping every FFI `unsafe fn`
// body in an explicit `unsafe {}`. For this FFI-dense crate the whole function IS the
// unsafe boundary (documented at the fn + call sites), so we keep the fn-level scope
// rather than adding ~40 boilerplate SAFETY blocks. Per-op SAFETY docs are a possible
// future hardening; the deny above still forces SAFETY on every standalone unsafe block.
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
mod pipe;
mod protocol;
mod service;
mod tray;
mod wide;
mod wmi_com;

use windows::Win32::UI::Controls::*;
use windows::Win32::UI::WindowsAndMessaging::*;
use windows::core::PCWSTR;

use crate::wide::wide_null;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const BUILD_ID: &str = env!("BUILD_ID");
const BUILD_DATE: &str = env!("BUILD_DATE");

const BTN_ACTION: i32 = 100;
const BTN_CANCEL: i32 = 2; // IDCANCEL

fn main() {
    // Harden every role (tray, service, installer helpers) as early as possible.
    mitigations::apply();

    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("--service") => {
            // Crown-jewel hardening: the SYSTEM service loads only MS-signed
            // WMI/COM DLLs, so lock it to Microsoft-signed images only (blocks all
            // non-MS injection/planting). Not applied to the tray (nvml + GUI
            // third-party injection). Set before WMI/COM pulls in its DLLs.
            mitigations::enforce_ms_signed_only();
            service::run();
        }
        Some("install" | "--install") => guarded_setup(|| {
            // Already installed → this is an update, not a fresh install. Route to
            // update() so the RUNNING service+tray are replaced (stop, swap exe,
            // restart, relaunch tray) rather than only overwriting the on-disk file
            // and leaving the old code executing. update_service launches the tray.
            if install::is_service_installed() {
                install::update();
                return;
            }
            install::install();
            // Launch the tray once we know the service is up: immediately when we
            // were already elevated (no child to wait on), otherwise after the
            // elevated child has started it. `||` short-circuits the wait if elevated.
            if install::is_elevated() || install::wait_for_service_running() {
                install::launch_tray();
            }
        }),
        // Internal: UAC children — do sc commands only, parent handles tray.
        Some("--install-svc") => install::install_service(),
        Some("--update-svc") => install::update_service(),
        Some("--stop-svc") => install::stop_service(),
        Some("--start-svc") => install::start_service(),
        Some("stop" | "--stop") => guarded_setup(install::stop),
        Some("start" | "--start") => guarded_setup(install::start),
        Some("uninstall" | "--uninstall") => guarded_setup(install::uninstall),
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
        if !task_dialog("Enable", &content, TD_WARNING_ICON) {
            return;
        }
        consent::record_acceptance(&hw);
    }

    // If we're NOT the installed copy, act as a bootstrap installer/launcher.
    if !install::is_installed_copy() {
        bootstrap_run(&hw);
        return;
    }

    // --- We ARE the installed copy (running from Program Files) ---

    if !install::is_service_installed() {
        let content = format!("{} service is not registered. Re-install?", app::NAME);
        if !task_dialog("Install", &content, TD_INFORMATION_ICON) {
            return;
        }
        let Some(_lock) = install::acquire_setup_lock() else {
            install::warn_setup_in_progress();
            return;
        };
        install::install();
        if !install::wait_for_service_running() {
            msgbox("Service failed to start.", MB_OK | MB_ICONERROR);
            return;
        }
    } else if !install::is_service_running() {
        let content = format!("The {} service is installed but not running.", app::NAME);
        if !task_dialog("Start Service", &content, TD_WARNING_ICON) {
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
fn bootstrap_run(hw: &hwinfo::HwInfo) {
    // Read-only decisions and user consent come FIRST — no lock. The setup lock
    // is acquired only immediately before the mutating install/update, held for
    // that critical section, and never across a dialog. This is what keeps a
    // stuck/leaked lock from silently swallowing every future launch.
    if !install::is_service_installed() {
        // Fresh install
        let content = format!(
            "Detected hardware:\n  \
             Manufacturer: {}\n  \
             Model: {}\n  \
             Board: {}\n\n\
             {} needs to install a background service \
             to manage thermal modes.\n\n\
             This requires one-time administrator access.",
            hw.manufacturer,
            hw.product,
            hw.board,
            app::NAME
        );
        if !task_dialog("Install", &content, TD_INFORMATION_ICON) {
            return;
        }
        let Some(_lock) = install::acquire_setup_lock() else {
            install::warn_setup_in_progress();
            return;
        };
        install::install();
        if !install::wait_for_service_running() {
            msgbox(
                "Service failed to start. Try running install from an admin prompt.",
                MB_OK | MB_ICONERROR,
            );
            return;
        }
        install::launch_tray();
        return;
    }

    if !install::is_service_current() {
        // Update: this copy differs from the installed one
        let content = format!(
            "A newer version of {} is available.\n\n\
             Update the service?",
            app::NAME
        );
        if !task_dialog("Update", &content, TD_WARNING_ICON) {
            // User declined — launch existing installed copy anyway
            install::launch_tray();
            return;
        }
        let Some(_lock) = install::acquire_setup_lock() else {
            install::warn_setup_in_progress();
            return;
        };
        // The UAC child (--update-svc) stops the service, replaces the
        // binary, restarts the service, AND launches the tray. We must
        // NOT race it by polling or launching tray ourselves — the child
        // will kill us via wait_or_kill_other_instances anyway.
        install::update();
        return;
    }

    // Installed and current — this is a deliberately-run copy, so give feedback
    // (rather than silently vanishing) before handing off to the installed tray.
    msgbox(
        &format!("{} is already installed and up to date.", app::NAME),
        MB_OK | MB_ICONINFORMATION,
    );
    install::launch_tray();
}

/// Show a TaskDialog with a custom action button + Cancel.
/// Returns true if the user clicked the action button, false for Cancel/X.
fn task_dialog(action_label: &str, content: &str, icon: PCWSTR) -> bool {
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
        ..Default::default()
    };

    let mut pressed = 0i32;
    // SAFETY: `config` is fully initialized on the stack with valid PCWSTR pointers
    // to local wide strings that outlive the call. `buttons` array is stack-allocated.
    let ok = unsafe { TaskDialogIndirect(&config, Some(&mut pressed), None, None) };
    ok.is_ok() && pressed == BTN_ACTION
}

fn msgbox(text: &str, flags: MESSAGEBOX_STYLE) -> MESSAGEBOX_RESULT {
    let title = wide_null(app::NAME);
    let body = wide_null(text);
    // SAFETY: `title` and `body` are null-terminated wide strings on the stack
    // that outlive the synchronous MessageBoxW call.
    unsafe { MessageBoxW(None, PCWSTR(body.as_ptr()), PCWSTR(title.as_ptr()), flags) }
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
