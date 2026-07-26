//! Fresh-install onboarding dialog.
//!
//! Shown ONCE, in the non-elevated launcher, BEFORE any UAC prompt: it discloses
//! the mandatory install actions (the Required rows, locked on) and offers the
//! three optional extras. The chosen options are returned to the caller, which
//! hands them to the elevated child — so the privileged process only does the
//! work and never renders UI. Upgrades skip this and preserve existing state.
//!
//! Implemented as a DIALOGEX resource (laid out in dialog units — see build.rs).
//! `DialogBoxParamW` runs the dialog manager, which does font/DPI scaling,
//! Tab/Esc/Enter + default button, centering, and the modal loop natively — so
//! there is no manual layout, measuring, or message pump here. The dialog proc
//! supplies only the runtime bits a static template can't: the default check
//! states, the dynamic build id, the UAC shield, and the white background.

use std::ffi::c_void;

use windows::Win32::Foundation::*;
use windows::Win32::Graphics::Gdi::*;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Controls::BCM_SETSHIELD;
use windows::Win32::UI::WindowsAndMessaging::*;
use windows::core::PCWSTR;

use crate::app;
use crate::wide::wide_null;

/// The user's optional choices. The mandatory actions (service, Program Files
/// copy, uninstall entry) are the locked Required rows — not represented here,
/// since they always happen; only genuine choices are toggles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Choices {
    pub run_at_startup: bool,
    pub start_menu: bool,
    pub desktop: bool,
}

impl Choices {
    /// Serialize as space-joined flags for the elevated child's command line —
    /// presence = on, absence = off. Fully explicit: the child does exactly what's
    /// flagged and assumes NO defaults of its own (the default-on state lives in the
    /// dialog's initial check state, not here). An all-off result is the empty string.
    /// Readable in Process Explorer, which is the point — no opaque codes.
    pub fn to_args(self) -> String {
        let mut parts: Vec<&str> = Vec::new();
        if self.run_at_startup {
            parts.push("--startup");
        }
        if self.start_menu {
            parts.push("--start-menu");
        }
        if self.desktop {
            parts.push("--desktop");
        }
        parts.join(" ")
    }

    /// Decode from the elevated child's argv tail. Unknown flags are ignored, so a
    /// malformed argument can never do more than the three booleans allow.
    pub fn from_args(args: &[String]) -> Self {
        let has = |f: &str| args.iter().any(|a| a == f);
        Self {
            run_at_startup: has("--startup"),
            start_menu: has("--start-menu"),
            desktop: has("--desktop"),
        }
    }
}

// Must match the DIALOGEX resource in build.rs's generated .rc.
const IDD: u16 = 100;
const IDOK: i32 = 1;
const IDCANCEL: i32 = 2;
const IDC_STARTUP: i32 = 1001;
const IDC_PROGRAMS: i32 = 1002;
const IDC_DESKTOP: i32 = 1003;
const IDC_R1: i32 = 1011;
const IDC_R2: i32 = 1012;
const IDC_R3: i32 = 1013;
const IDC_VERSION: i32 = 1020;
const BST_CHECKED: usize = 1;

/// Reached from the dialog proc via GWLP_USERDATA; lives on `prompt`'s stack for
/// the duration of the modal call.
struct DlgState {
    result: Option<Choices>,
    version_ctrl: HWND,
}

/// Show the onboarding dialog modally and return the chosen options, or `None`
/// if the user cancelled / closed the window (nothing should be installed).
pub fn prompt() -> Option<Choices> {
    // SAFETY: DialogBoxParamW runs a modal dialog on the calling thread and only
    // returns after EndDialog. `state` outlives the call; its pointer is handed to
    // the dialog proc as the init param and stored in GWLP_USERDATA.
    unsafe {
        let hinst: HINSTANCE = GetModuleHandleW(None).unwrap().into();
        let mut state = DlgState {
            result: None,
            version_ctrl: HWND(std::ptr::null_mut()),
        };
        let ret = DialogBoxParamW(
            Some(hinst),
            PCWSTR(IDD as usize as *const u16), // MAKEINTRESOURCE
            None,
            Some(dlg_proc),
            LPARAM(&mut state as *mut DlgState as isize),
        );
        if ret == 1 { state.result } else { None }
    }
}

unsafe extern "system" fn dlg_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> isize {
    match msg {
        WM_INITDIALOG => {
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, lparam.0);
            let st = lparam.0 as *mut DlgState;

            // Defaults: required rows locked-on; startup + Start Menu on, Desktop off.
            for id in [IDC_R1, IDC_R2, IDC_R3, IDC_STARTUP, IDC_PROGRAMS] {
                if let Ok(c) = GetDlgItem(Some(hwnd), id) {
                    SendMessageW(c, BM_SETCHECK, Some(WPARAM(BST_CHECKED)), None);
                }
            }

            // Dynamic build-id text (a static template can't carry it).
            if let Ok(vc) = GetDlgItem(Some(hwnd), IDC_VERSION) {
                (*st).version_ctrl = vc;
            }
            let ver = wide_null(&format!(
                "{} v{}+{}",
                app::BIN_NAME,
                env!("CARGO_PKG_VERSION"),
                env!("BUILD_ID")
            ));
            let _ = SetDlgItemTextW(hwnd, IDC_VERSION, PCWSTR(ver.as_ptr()));

            // UAC shield on the elevating button.
            if let Ok(ok) = GetDlgItem(Some(hwnd), IDOK) {
                SendMessageW(ok, BCM_SETSHIELD, Some(WPARAM(0)), Some(LPARAM(1)));
            }
            1 // TRUE — let the manager set default focus
        }
        WM_CTLCOLORDLG => GetStockObject(WHITE_BRUSH).0 as isize,
        WM_CTLCOLORSTATIC => {
            let hdc = HDC(wparam.0 as *mut c_void);
            SetBkMode(hdc, TRANSPARENT);
            let st = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *const DlgState;
            if !st.is_null() && lparam.0 == (*st).version_ctrl.0 as isize {
                SetTextColor(hdc, COLORREF(0x0080_8080)); // dim the build id
            }
            GetStockObject(WHITE_BRUSH).0 as isize
        }
        WM_COMMAND => {
            match (wparam.0 & 0xFFFF) as i32 {
                IDOK => {
                    let st = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut DlgState;
                    if !st.is_null() {
                        (*st).result = Some(Choices {
                            run_at_startup: is_checked(hwnd, IDC_STARTUP),
                            start_menu: is_checked(hwnd, IDC_PROGRAMS),
                            desktop: is_checked(hwnd, IDC_DESKTOP),
                        });
                    }
                    let _ = EndDialog(hwnd, 1);
                }
                IDCANCEL => {
                    let _ = EndDialog(hwnd, 0);
                }
                _ => {}
            }
            1
        }
        _ => 0,
    }
}

unsafe fn is_checked(hwnd: HWND, id: i32) -> bool {
    match GetDlgItem(Some(hwnd), id) {
        Ok(c) => SendMessageW(c, BM_GETCHECK, None, None).0 as usize == BST_CHECKED,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn choices(run_at_startup: bool, start_menu: bool, desktop: bool) -> Choices {
        Choices {
            run_at_startup,
            start_menu,
            desktop,
        }
    }

    #[test]
    fn args_roundtrip_every_combination() {
        for run_at_startup in [false, true] {
            for start_menu in [false, true] {
                for desktop in [false, true] {
                    let c = choices(run_at_startup, start_menu, desktop);
                    let argv: Vec<String> =
                        c.to_args().split_whitespace().map(String::from).collect();
                    assert_eq!(Choices::from_args(&argv), c);
                }
            }
        }
    }

    #[test]
    fn flag_names_are_stable() {
        // The elevated child parses these exact strings — don't let them drift.
        assert_eq!(choices(true, false, false).to_args(), "--startup");
        assert_eq!(choices(false, true, false).to_args(), "--start-menu");
        assert_eq!(choices(false, false, true).to_args(), "--desktop");
        assert_eq!(choices(false, false, false).to_args(), "");
    }

    #[test]
    fn from_args_ignores_unknown_flags() {
        // A malformed/unexpected flag must decode to just the known booleans.
        let argv = vec![
            "--startup".to_string(),
            "--bogus".to_string(),
            "--desktop".to_string(),
        ];
        assert_eq!(Choices::from_args(&argv), choices(true, false, true));
    }
}
