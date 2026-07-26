//! Process mitigation policies applied at startup to both roles (tray + service).
//!
//! These raise the bar against the one attack the pipe design can't fully prevent
//! by construction — same-user in-memory tampering (injection/hollowing). They are
//! hardening, not a security boundary: the real boundary is the OS (user +
//! integrity level + Program Files ACL), and the pipe's bounded command set caps
//! the impact regardless. See SECURITY.md.

use windows::Win32::System::LibraryLoader::{
    LOAD_LIBRARY_SEARCH_SYSTEM32, SetDefaultDllDirectories,
};
use windows::Win32::System::SystemServices::{
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY, PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY,
    PROCESS_MITIGATION_IMAGE_LOAD_POLICY,
};
use windows::Win32::System::Threading::{
    ProcessExtensionPointDisablePolicy, ProcessImageLoadPolicy, ProcessSignaturePolicy,
    SetProcessMitigationPolicy,
};

// Policy `Flags` bit masks. The `windows` crate exposes these bitfields only as a
// raw `Flags: u32`, so we set the documented winnt.h bits directly. Bit positions
// are a frozen Windows ABI contract (reordering would break binary compatibility).
//
// PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY: MicrosoftSignedOnly = bit 0.
const MICROSOFT_SIGNED_ONLY: u32 = 0x1;
// PROCESS_MITIGATION_IMAGE_LOAD_POLICY:
//   NoRemoteImages(0) | NoLowMandatoryLabelImages(1) | PreferSystem32Images(2).
const IMAGE_LOAD_HARDENING: u32 = 0b111;

/// Apply process mitigation policies. Best-effort: failures are non-fatal (older
/// Windows may not support a given policy), so a failure just means that one
/// layer is absent — the OS-level boundaries still hold.
pub fn apply() {
    restrict_dll_search();
    restrict_image_loads();
    disable_extension_points();
    // ProcessDynamicCodePolicy (ProhibitDynamicCode) — the strongest anti-shellcode
    // mitigation — is deferred: it can break in-process code generators, and this
    // process hosts COM/WMI (service) and WASAPI/COM (tray). See #24.
}

/// Restrict runtime `LoadLibrary` (calls without their own search flags) to
/// System32, dropping the app dir and CWD — runtime companion to the PE
/// `/DEPENDENTLOADFLAG` that covers static imports. We ship no sidecar DLLs.
/// https://learn.microsoft.com/windows/win32/api/libloaderapi/nf-libloaderapi-setdefaultdlldirectories
fn restrict_dll_search() {
    // SAFETY: flags-only call, no pointers; non-fatal hardening (ignored on failure).
    unsafe {
        let _ = SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);
    }
}

/// Image-load policy: prefer System32, block DLLs loaded from remote (UNC) paths,
/// and refuse DLLs carrying a LOW integrity label (written by a low-IL process such
/// as a sandboxed browser or AppContainer) — an anti-planting layer on top of the
/// search-path restriction. All our real dependencies are System32/driver-store.
/// https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-process_mitigation_image_load_policy
fn restrict_image_loads() {
    // SAFETY: `policy` is a zeroed struct; we set NoRemoteImages(bit0) |
    // NoLowMandatoryLabelImages(bit1) | PreferSystem32Images(bit2) = 0b111 via the
    // Flags union member and pass its exact size. Non-fatal (ignored on failure).
    unsafe {
        let mut policy = PROCESS_MITIGATION_IMAGE_LOAD_POLICY::default();
        policy.Anonymous.Flags = IMAGE_LOAD_HARDENING;
        let _ = SetProcessMitigationPolicy(
            ProcessImageLoadPolicy,
            std::ptr::addr_of!(policy) as *const std::ffi::c_void,
            std::mem::size_of::<PROCESS_MITIGATION_IMAGE_LOAD_POLICY>(),
        );
    }
}

/// Enforce Code Integrity Guard (only Microsoft-signed DLLs may load; a one-way
/// ratchet that cannot be disabled once set).
///
/// Applied to the `--service` role AND the elevated install/update child: both load
/// only MS-signed system DLLs (WMI/COM for the service — the HP WMI provider runs
/// out-of-process in WmiPrvSE; shell/COM for the installer), so there is no functional
/// cost while every non-MS DLL injection or plant is blocked.
///
/// NOT applied to the tray: it deliberately loads `nvml.dll` (NVIDIA, non-MS-signed)
/// for the GPU readout, which CIG would block. (As a GUI process the tray is also a
/// common injection *target* for third-party software — AV/EDR, input hooks — that
/// CIG would fight; but nvml is the concrete blocker.) The tray stays at the search +
/// image-load tier. Best-effort: ignored on older Windows.
/// https://learn.microsoft.com/windows/win32/secbp/mitigation-guard
pub fn enforce_ms_signed_only() {
    // SAFETY: `policy` is a zeroed struct; we set MicrosoftSignedOnly (bit 0) via
    // the Flags union member and pass its exact size. Ignored on failure.
    unsafe {
        let mut policy = PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY::default();
        policy.Anonymous.Flags = MICROSOFT_SIGNED_ONLY;
        let _ = SetProcessMitigationPolicy(
            ProcessSignaturePolicy,
            std::ptr::addr_of!(policy) as *const std::ffi::c_void,
            std::mem::size_of::<PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY>(),
        );
    }
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
