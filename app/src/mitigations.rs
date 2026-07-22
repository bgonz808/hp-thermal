//! Process mitigation policies applied at startup to both roles (tray + service).
//!
//! These raise the bar against the one attack the pipe design can't fully prevent
//! by construction — same-user in-memory tampering (injection/hollowing). They are
//! hardening, not a security boundary: the real boundary is the OS (user +
//! integrity level + Program Files ACL), and the pipe's bounded command set caps
//! the impact regardless. See SECURITY.md.

use windows::Win32::System::SystemServices::PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY;
use windows::Win32::System::Threading::{
    ProcessExtensionPointDisablePolicy, SetProcessMitigationPolicy,
};

/// Apply process mitigation policies. Best-effort: failures are non-fatal (older
/// Windows may not support a given policy), so a failure just means that one
/// layer is absent — the OS-level boundaries still hold.
pub fn apply() {
    disable_extension_points();
    // NOTE: ProcessDynamicCodePolicy (ProhibitDynamicCode) is the strongest
    // anti-shellcode mitigation, but it can break in-process components that
    // generate code — and this process hosts COM/WMI (service) and WASAPI/COM
    // (tray). Enabling it is deferred until validated end-to-end that WMI still
    // connects and the tray still functions with it on. Documented in SECURITY.md.
}

/// Block legacy injection vectors: AppInit_DLLs, global SetWindowsHookEx hooks,
/// and legacy IMEs. Low compatibility risk, meaningful against injection.
fn disable_extension_points() {
    // SAFETY: `policy` is a fully-initialized, zeroed struct; we set the
    // DisableExtensionPoints flag (bit 0) via the Flags union member and pass the
    // struct with its exact size. A failing call is ignored (non-fatal hardening).
    unsafe {
        let mut policy = PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY::default();
        policy.Anonymous.Flags = 1; // DisableExtensionPoints
        let _ = SetProcessMitigationPolicy(
            ProcessExtensionPointDisablePolicy,
            std::ptr::addr_of!(policy) as *const std::ffi::c_void,
            std::mem::size_of::<PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY>(),
        );
    }
}
