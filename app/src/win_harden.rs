//! `win_harden` — reusable Windows process/DLL hardening for a single-binary MSVC app.
//!
//! Consolidates the runtime hardening surface into one module (#114): process
//! mitigation policies (here) + System32-confined DLL loading ([`dll`]). The link-time
//! half — `/DEPENDENTLOADFLAG` (static imports), `/DELAYLOAD` + `delayimp.lib` (deferred
//! deps), CFG / stack canaries — lives in `build.rs` and `.cargo/config.toml`; a shared
//! build-side emitter is tracked in #120, and a pre-`main`-airtight child launch
//! (`spawn_hardened`) in #119.
//!
//! These raise the bar against the one attack the pipe design can't fully prevent
//! by construction — same-user in-memory tampering (injection/hollowing). They are
//! hardening, not a security boundary: the real boundary is the OS (user +
//! integrity level + Program Files ACL), and the pipe's bounded command set caps
//! the impact regardless. See SECURITY.md.

pub mod dll;

use windows::Win32::Foundation::{CloseHandle, HANDLE, LUID};
use windows::Win32::Security::{
    AdjustTokenPrivileges, GetTokenInformation, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW,
    SE_PRIVILEGE_REMOVED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY, TokenPrivileges,
};
use windows::Win32::System::Diagnostics::Debug::{EXCEPTION_POINTERS, SetUnhandledExceptionFilter};
use windows::Win32::System::LibraryLoader::{
    LOAD_LIBRARY_SEARCH_SYSTEM32, SetDefaultDllDirectories,
};
use windows::Win32::System::SystemServices::{
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY, PROCESS_MITIGATION_CHILD_PROCESS_POLICY,
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY, PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY,
    PROCESS_MITIGATION_IMAGE_LOAD_POLICY, PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcessToken, ProcessChildProcessPolicy, ProcessDynamicCodePolicy,
    ProcessExtensionPointDisablePolicy, ProcessImageLoadPolicy, ProcessSignaturePolicy,
    ProcessSystemCallDisablePolicy, SetProcessMitigationPolicy, TerminateProcess,
};
use windows::core::PCWSTR;

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
// AuditProhibitDynamicCode = bit 3 (log only). We enforce (bit 0) after a clean audit run.
const PROHIBIT_DYNAMIC_CODE: u32 = 0x1;

/// Apply process mitigation policies. Best-effort: failures are non-fatal (older
/// Windows may not support a given policy), so a failure just means that one
/// layer is absent — the OS-level boundaries still hold.
pub fn apply() {
    suppress_wer();
    restrict_dll_search();
    restrict_image_loads();
    disable_extension_points();
    // ProcessDynamicCodePolicy is NOT applied globally: it can break in-process code
    // generators, and this process hosts COM/WMI (service) and WASAPI/COM (tray). It is
    // enforced on the `--service` role only (prohibit_dynamic_code, #24), validated
    // audit-first against a clean live run.
}

/// #38 top-level exception filter: on any crash that reaches it, terminate immediately so
/// WerFault.exe never collects/uploads a dump of our process memory.
///
/// SAFETY: matches the LPTOP_LEVEL_EXCEPTION_FILTER ABI. `GetCurrentProcess` is a pseudo-
/// handle (no close); `TerminateProcess` ends this process deterministically without
/// chaining to the default handler (which is what invokes WER). We do not touch `_info`.
unsafe extern "system" fn terminate_no_wer(_info: *const EXCEPTION_POINTERS) -> i32 {
    let _ = TerminateProcess(GetCurrentProcess(), 1);
    1 // EXCEPTION_EXECUTE_HANDLER — "handled, do not run WER" (fallback if the above returns)
}

/// Suppress Windows Error Reporting for THIS process (#38, all roles). Registers a
/// top-level exception filter that terminates without chaining to WER — so a crash dump
/// never egresses to Microsoft even though WerFault.exe runs *out-of-process* (our
/// in-binary no-network posture cannot stop it). Covers the SEH crash paths: Rust panics
/// (panic=immediate-abort -> ud2) and access violations. The `__fastfail` paths
/// (stack-cookie / CFG) bypass this filter and are covered on the INSTALLED exe by
/// WerAddExcludedApplication (install.rs). Best-effort.
/// https://learn.microsoft.com/windows/win32/api/errhandlingapi/nf-errhandlingapi-setunhandledexceptionfilter
pub fn suppress_wer() {
    // SAFETY: registers a 'static filter fn pointer; returns (and we drop) the previous one.
    unsafe {
        SetUnhandledExceptionFilter(Some(terminate_no_wer));
    }
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
/// NOT applied to the installer/tray, which legitimately spawn (elevation, ensure_tray,
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

/// Enforce ProcessDynamicCodePolicy (ProhibitDynamicCode) on the `--service` role: the
/// process can no longer allocate/modify executable memory or map an image writable+
/// executable, and any such attempt TERMINATES it. This is the strongest anti-shellcode
/// mitigation (CWE-94: blocks JIT-style code injection / dynamically-generated shellcode).
/// It can break in-process code generators, so it was validated audit-first
/// (AuditProhibitDynamicCode, bit 3) against a live run — WMI read/write + event sink +
/// pipe produced ZERO dynamic-code events — before enforcing here. Once set it is a
/// permanent one-way ratchet, so it is validated by a live service run before shipping.
/// Applied to the service ONLY: the tray loads third-party code (nvml) and hosts WASAPI/COM,
/// which are not audited for dynamic-code use. Best-effort — ignored on older Windows. #24.
/// https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-process_mitigation_dynamic_code_policy
pub fn prohibit_dynamic_code() {
    // SAFETY: `policy` is a zeroed struct; we set ProhibitDynamicCode (bit 0) via the
    // Flags union member and pass its exact size. Ignored on failure.
    unsafe {
        let mut policy = PROCESS_MITIGATION_DYNAMIC_CODE_POLICY::default();
        policy.Anonymous.Flags = PROHIBIT_DYNAMIC_CODE;
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

/// Read the LUIDs of every privilege currently in `token`. Empty on any failure.
///
/// # Safety
/// `token` must be a valid access-token handle opened with `TOKEN_QUERY`.
unsafe fn token_privilege_luids(token: HANDLE) -> Vec<LUID> {
    // Two-call size-then-fill of the variable-length TOKEN_PRIVILEGES.
    let mut len = 0u32;
    // SAFETY: sizing call — a null buffer is expected to "fail" while setting `len`.
    let _ = unsafe { GetTokenInformation(token, TokenPrivileges, None, 0, &mut len) };
    if len == 0 {
        return Vec::new();
    }
    let mut buf = vec![0u8; len as usize];
    // SAFETY: `buf` is `len` bytes; on success it holds a TOKEN_PRIVILEGES header + array.
    if unsafe {
        GetTokenInformation(
            token,
            TokenPrivileges,
            Some(buf.as_mut_ptr() as *mut _),
            len,
            &mut len,
        )
    }
    .is_err()
    {
        return Vec::new();
    }
    // SAFETY: the buffer starts with a TOKEN_PRIVILEGES whose `PrivilegeCount` bounds the
    // trailing LUID_AND_ATTRIBUTES array (typed `[_; 1]` by the crate) within `buf`.
    unsafe {
        let header = &*(buf.as_ptr() as *const TOKEN_PRIVILEGES);
        let count = header.PrivilegeCount as usize;
        std::slice::from_raw_parts(header.Privileges.as_ptr(), count)
            .iter()
            .map(|p| p.Luid)
            .collect()
    }
}

/// Permanently REMOVE (`SE_PRIVILEGE_REMOVED`) every privilege in THIS process's token whose
/// name is not in `keep`. Returns `(removed, extras_remaining)` — `extras_remaining` counts
/// non-kept privileges still present afterward (should be 0; a non-zero value is an anomaly a
/// caller may fail-closed on). This is the runtime, in-code counterpart to the service's
/// declarative `SERVICE_REQUIRED_PRIVILEGES` (#39) — and the same enforcement for the tray —
/// so a token is right-sized to exactly what its role needs regardless of install config.
/// Best-effort: it resolves/removes each privilege independently and never panics.
pub fn strip_token_privileges_except(keep: &[PCWSTR]) -> (u32, u32) {
    // SAFETY: standard OpenProcessToken -> enumerate -> AdjustTokenPrivileges on our own token;
    // the handle is closed before every return and each FFI arg is an owned local / checked ptr.
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
            &mut token,
        )
        .is_err()
        {
            return (0, 0);
        }

        // Resolve the LUIDs we KEEP.
        let mut keep_luids: Vec<LUID> = Vec::with_capacity(keep.len());
        for name in keep {
            let mut luid = LUID::default();
            if LookupPrivilegeValueW(None, *name, &mut luid).is_ok() {
                keep_luids.push(luid);
            }
        }
        let is_kept = |l: &LUID| {
            keep_luids
                .iter()
                .any(|k| k.LowPart == l.LowPart && k.HighPart == l.HighPart)
        };

        let mut removed = 0u32;
        for luid in token_privilege_luids(token) {
            if is_kept(&luid) {
                continue;
            }
            let adj = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_REMOVED,
                }],
            };
            if AdjustTokenPrivileges(token, false, Some(&adj as *const _), 0, None, None).is_ok() {
                removed += 1;
            }
        }

        // Authoritative recount: how many non-kept privileges survived the strip.
        let extras = token_privilege_luids(token)
            .iter()
            .filter(|l| !is_kept(l))
            .count() as u32;
        let _ = CloseHandle(token);
        (removed, extras)
    }
}

/// Launch `exe` with a CREATION-TIME image-load mitigation baked into the child's
/// process-creation policy — the only pre-`main`-airtight form of the hardening that
/// [`apply`]'s `restrict_image_loads` / `restrict_dll_search` apply at runtime. Those
/// runtime calls only take effect once the child's own `main` runs; a DLL planted next to
/// the exe could already win during the child's *startup* import resolution, before then.
/// The creation-time `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` closes that window for the
/// launches we own (parent → tray, via `install::ensure_tray`).
///
/// Policy = PreferSystem32 | NoRemoteImages | NoLowMandatoryLabelImages — the same bits
/// `restrict_image_loads` sets, but enforced from image #0. NOT CIG/no-child/win32k: the
/// tray is a Medium-IL GUI that loads nvml and must keep spawning nothing-special behavior.
///
/// The child inherits our token, so its integrity level is unchanged — call only from a
/// Medium parent (`ensure_tray` guarantees this). Returns false on any failure; callers
/// treat the launch as best-effort (the logon Run key is the backstop).
pub fn spawn_hardened(exe: &str) -> bool {
    use std::ffi::c_void;
    use windows::Win32::System::Threading::{
        CreateProcessW, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
        InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
        STARTUPINFOEXW, UpdateProcThreadAttribute,
    };
    use windows::core::PCWSTR;

    // PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY = ProcThreadAttributeValue(7, FALSE, TRUE, FALSE)
    // = 7 | PROC_THREAD_ATTRIBUTE_INPUT(0x0002_0000). The `windows` crate doesn't export the
    // assembled constant, so we spell the frozen winbase.h value directly.
    const PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY: usize = 0x0002_0007;
    // PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_* (winbase.h) — DWORD64 bit positions:
    //   NO_REMOTE_ALWAYS_ON (1<<52) | NO_LOW_LABEL_ALWAYS_ON (1<<56) | PREFER_SYSTEM32_ALWAYS_ON (1<<60).
    const IMAGE_LOAD_POLICY: u64 = (1u64 << 52) | (1u64 << 56) | (1u64 << 60);

    let exe_w = crate::wide::wide_null(exe);

    // SAFETY: textbook attribute-list dance — size (null-list call sets `size`) -> allocate ->
    // init -> UpdateProcThreadAttribute with a `u64` policy that outlives the CreateProcessW
    // call -> CreateProcessW with EXTENDED_STARTUPINFO_PRESENT. The attribute list is always
    // deleted and both returned handles closed before any success return.
    unsafe {
        let mut size = 0usize;
        // Sizing call: expected to "fail" (null list) while writing the required `size`.
        let _ = InitializeProcThreadAttributeList(None, 1, None, &mut size);
        if size == 0 {
            return false;
        }
        let mut buf = vec![0u8; size];
        let attr = LPPROC_THREAD_ATTRIBUTE_LIST(buf.as_mut_ptr() as *mut c_void);
        if InitializeProcThreadAttributeList(Some(attr), 1, None, &mut size).is_err() {
            return false;
        }

        let policy: u64 = IMAGE_LOAD_POLICY;
        let updated = UpdateProcThreadAttribute(
            attr,
            0,
            PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
            Some(std::ptr::addr_of!(policy) as *const c_void),
            std::mem::size_of::<u64>(),
            None,
            None,
        )
        .is_ok();
        if !updated {
            DeleteProcThreadAttributeList(attr);
            return false;
        }

        let mut si = STARTUPINFOEXW::default();
        si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        si.lpAttributeList = attr;
        let mut pi = PROCESS_INFORMATION::default();

        // lpApplicationName = the absolute installed exe path (no CreateProcess search order);
        // lpCommandLine null -> argv[0] is the app path, matching the prior Command::spawn.
        let created = CreateProcessW(
            PCWSTR(exe_w.as_ptr()),
            None,
            None,
            None,
            false,
            EXTENDED_STARTUPINFO_PRESENT,
            None,
            PCWSTR::null(),
            std::ptr::addr_of!(si.StartupInfo),
            &mut pi,
        )
        .is_ok();

        DeleteProcThreadAttributeList(attr);
        if created {
            let _ = CloseHandle(pi.hProcess);
            let _ = CloseHandle(pi.hThread);
        }
        created
    }
}
