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
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY, PROCESS_MITIGATION_CHILD_PROCESS_POLICY,
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY, PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY,
    PROCESS_MITIGATION_IMAGE_LOAD_POLICY, PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY,
};
use windows::Win32::System::Threading::{
    ProcessChildProcessPolicy, ProcessDynamicCodePolicy, ProcessExtensionPointDisablePolicy,
    ProcessImageLoadPolicy, ProcessSignaturePolicy, ProcessSystemCallDisablePolicy,
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
// PROCESS_MITIGATION_CHILD_PROCESS_POLICY: NoChildProcessCreation = bit 0.
const NO_CHILD_PROCESS: u32 = 0x1;
// PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY: DisallowWin32kSystemCalls = bit 0.
const DISALLOW_WIN32K: u32 = 0x1;
// PROCESS_MITIGATION_DYNAMIC_CODE_POLICY: ProhibitDynamicCode = bit 0 (enforce),
// AuditProhibitDynamicCode = bit 3 (log to Microsoft-Windows-Security-Mitigations, no kill).
const AUDIT_PROHIBIT_DYNAMIC_CODE: u32 = 0x8;

/// Apply process mitigation policies. Best-effort: failures are non-fatal (older
/// Windows may not support a given policy), so a failure just means that one
/// layer is absent — the OS-level boundaries still hold.
pub fn apply() {
    restrict_dll_search();
    restrict_image_loads();
    disable_extension_points();
    // ProcessDynamicCodePolicy is NOT applied globally: it can break in-process code
    // generators, and this process hosts COM/WMI (service) and WASAPI/COM (tray). It is
    // applied to the `--service` role in AUDIT mode (audit_dynamic_code, #24); enforcement
    // (ProhibitDynamicCode) follows once a live audit run is confirmed clean.
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

/// Prohibit child-process creation. Applied to the `--service` role ONLY: the SYSTEM
/// service spawns nothing (verified — every CreateProcess/ShellExecute/spawn lives in
/// the installer or tray, never in service.rs; its WMI/COM run in-proc or out-of-process
/// in WmiPrvSE, launched by the SCM, not by us). This removes the LOLBin/proxy exfil path
/// (curl/powershell/certutil/...) even from injected code — one fewer rung to the network.
/// NOT applied to the installer/tray, which legitimately spawn (elevation, launch_tray,
/// opening links). Integrity-conditional until signing (#21) makes it tamper-rejected;
/// best-effort (ignored on older Windows).
/// https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-process_mitigation_child_process_policy
pub fn prohibit_child_processes() {
    // SAFETY: `policy` is a zeroed struct; we set NoChildProcessCreation (bit 0) via the
    // Flags union member and pass its exact size. Ignored on failure.
    unsafe {
        let mut policy = PROCESS_MITIGATION_CHILD_PROCESS_POLICY::default();
        policy.Anonymous.Flags = NO_CHILD_PROCESS;
        let _ = SetProcessMitigationPolicy(
            ProcessChildProcessPolicy,
            std::ptr::addr_of!(policy) as *const std::ffi::c_void,
            std::mem::size_of::<PROCESS_MITIGATION_CHILD_PROCESS_POLICY>(),
        );
    }
}

/// Disable win32k system calls. Applied to the `--service` role ONLY: the headless SYSTEM
/// service has no GUI and never enters win32k (MTA COM/WMI + named-pipe I/O — no window, no
/// message pump), so cutting off the win32k syscall surface removes one of the largest kernel
/// LPE attack surfaces from the crown-jewel process. NOT applied to the tray, which IS a GUI
/// (win32k) process. Once set it is permanent and any win32k call terminates the process, so
/// it is validated by a live service run (WMI read/write + event sink + pipe) before shipping.
/// Best-effort (ignored on older Windows). runtime-mitigation (#48).
/// https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-process_mitigation_system_call_disable_policy
pub fn disallow_win32k_syscalls() {
    // SAFETY: `policy` is a zeroed struct; we set DisallowWin32kSystemCalls (bit 0) via the
    // Flags union member and pass its exact size. Ignored on failure.
    unsafe {
        let mut policy = PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY::default();
        policy.Anonymous.Flags = DISALLOW_WIN32K;
        let _ = SetProcessMitigationPolicy(
            ProcessSystemCallDisablePolicy,
            std::ptr::addr_of!(policy) as *const std::ffi::c_void,
            std::mem::size_of::<PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY>(),
        );
    }
}

/// AUDIT (do NOT yet enforce) ProcessDynamicCodePolicy on the `--service` role. Setting
/// AuditProhibitDynamicCode logs — to the Microsoft-Windows-Security-Mitigations channel —
/// every operation ProhibitDynamicCode WOULD block (allocating/modifying executable memory,
/// mapping an image writable+executable) WITHOUT terminating the process. ProhibitDynamicCode
/// is the strongest anti-shellcode mitigation (CWE-94: blocks JIT-style code injection), but
/// it can break in-process code generators and the service hosts COM/WMI, so audit-first lets
/// us confirm a clean run (WMI read/write + event sink + pipe) before flipping bit 0 to
/// enforce. Applied to the service ONLY (the tray hosts WASAPI/COM). Best-effort — ignored on
/// older Windows. #24.
/// https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-process_mitigation_dynamic_code_policy
pub fn audit_dynamic_code() {
    // SAFETY: `policy` is a zeroed struct; we set AuditProhibitDynamicCode (bit 3) via the
    // Flags union member and pass its exact size. Ignored on failure.
    unsafe {
        let mut policy = PROCESS_MITIGATION_DYNAMIC_CODE_POLICY::default();
        policy.Anonymous.Flags = AUDIT_PROHIBIT_DYNAMIC_CODE;
        let _ = SetProcessMitigationPolicy(
            ProcessDynamicCodePolicy,
            std::ptr::addr_of!(policy) as *const std::ffi::c_void,
            std::mem::size_of::<PROCESS_MITIGATION_DYNAMIC_CODE_POLICY>(),
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
