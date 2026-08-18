//! `win_harden` — reusable Windows process/DLL hardening for a single-binary MSVC app.
//!
//! Consolidates the runtime hardening surface into one module (#114): process
//! mitigation policies (here) + System32-confined DLL loading ([`dll`]). The link-time
//! half — `/DEPENDENTLOADFLAG` (static imports), `/DELAYLOAD` + `delayimp.lib` (deferred
//! deps), CFG / stack canaries — stays in `build.rs` / `.cargo/config.toml` by design
//! (`build.rs` can't import `src/`, and the three link-arg lines don't warrant shared
//! plumbing).
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
    // enforced per role by `harden_for_role` (prohibit_dynamic_code, #24), validated
    // audit-first against a clean live run.
}

/// The distinct execution roles of this single binary, resolved from argv (#157).
/// [`harden_for_role`] maps each to an explicit [`Profile`]; that mapping — not scattered
/// per-call-site decisions — is the single source of truth for what a role locks down.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    /// `--service`: headless SYSTEM service (the crown jewel). Non-interactive; takes every lock.
    Service,
    /// default (no argv): interactive Medium-IL tray. nvml + GUI force relaxations.
    Tray,
    /// `--install-svc` / `--update-svc`: elevated UAC child that (de)registers the service,
    /// often first-run from a user-writable dir (Downloads) — CIG defeats DLL planting there.
    ElevatedSetup,
    /// Medium-IL launchers that ShellExecute the elevated helper and/or show setup dialogs:
    /// `install`, `stop`/`start`/`uninstall`, `--stop-svc`/`--start-svc`, `--preview-onboarding`.
    Launcher,
    /// `--help` / `--version` / unrecognized argv: text-only, spawns nothing, shows no window.
    TextOnly,
}

/// Which process-mitigation locks a role engages. Every lock is ON in [`Profile::MAX`]; a
/// role earns a relaxation ONLY by proving it can't function under the lock, and every
/// carve-out in [`profile_for`] names its reason (#157). The safe default is `MAX`: a role
/// that forgets to relax fails LOUDLY (a blocked child/dialog/DLL), never runs silently
/// under-hardened.
#[derive(Clone, Copy)]
struct Profile {
    /// CIG (MicrosoftSignedOnly): load only Microsoft-signed images.
    ms_signed_only: bool,
    /// NoChildProcessCreation: the process can spawn nothing.
    no_child: bool,
    /// DisallowWin32kSystemCalls: no GUI syscalls — headless / no-window roles only.
    no_win32k: bool,
    /// ProhibitDynamicCode (ACG): no dynamically-generated / executable memory.
    no_dynamic_code: bool,
}

impl Profile {
    /// Maximum hardening — every lock engaged. The floor every role starts from.
    const MAX: Profile = Profile {
        ms_signed_only: true,
        no_child: true,
        no_win32k: true,
        no_dynamic_code: true,
    };

    // Carve-outs from MAX. Each takes the REASON as a string so a relaxation reads as its own
    // rationale at the `profile_for` call site; the string is compile-time-only documentation.
    const fn allow_unsigned_dlls(mut self, _why: &'static str) -> Self {
        self.ms_signed_only = false;
        self
    }
    const fn allow_child_processes(mut self, _why: &'static str) -> Self {
        self.no_child = false;
        self
    }
    const fn allow_win32k(mut self, _why: &'static str) -> Self {
        self.no_win32k = false;
        self
    }
    const fn allow_dynamic_code(mut self, _why: &'static str) -> Self {
        self.no_dynamic_code = false;
        self
    }
}

/// The role→profile table — the exhaustive SSoT (#157). Adding a [`Role`] variant without a
/// profile here is a COMPILE ERROR (no wildcard arm), so no role can be silently forgotten;
/// relaxations from [`Profile::MAX`] are the earned exception, each annotated with its cause.
///
/// STAGED (held back, default-conservative until validated — #180): CIG on the interactive
/// roles (Tray/TextOnly) and ACG on the Tray. CIG on an interactive process also blocks legit
/// non-MS injectors (IME, accessibility, EDR) and needs a soak; Tray ACG needs on-hardware
/// validation. Flipping either on is a one-line carve-out removal once proven.
const fn profile_for(role: Role) -> Profile {
    match role {
        // Non-interactive crown jewel: every lock. Live-validated (#24, #48).
        Role::Service => Profile::MAX,
        // Interactive GUI + on-demand nvml (NVIDIA-signed, loaded from System32) + a broad
        // third-party injection surface. Keeps no-child, but that lock is applied late in
        // `tray::run` (not at dispatch) because the no-arg role bootstraps/spawns first — see
        // `harden_for_role`.
        Role::Tray => Profile::MAX
            .allow_unsigned_dlls("nvml is NVIDIA-signed; IME/a11y/EDR inject into GUI procs")
            .allow_win32k("interactive GUI needs win32k")
            .allow_dynamic_code("nvml + GUI components may generate code"),
        // Elevated, often first-run from a user-writable dir → CIG defeats DLL planting. Still
        // runs sc / builds shortcuts, so the remaining locks are carved pending validation.
        Role::ElevatedSetup => Profile::MAX
            .allow_child_processes("runs sc / service-control helpers")
            .allow_win32k("COM/shell shortcut creation touches win32k")
            .allow_dynamic_code("elevated setup path not yet ACG-validated"),
        // Medium-IL: its job is to ShellExecute the elevated child and/or show setup dialogs.
        Role::Launcher => Profile::MAX
            .allow_unsigned_dlls("ShellExecute may load non-MS shell extensions")
            .allow_child_processes("spawns the elevated UAC helper")
            .allow_win32k("shows onboarding / error dialogs")
            .allow_dynamic_code("shell/COM path not yet ACG-validated"),
        // Text-only leaf: no window, no spawn, no JIT. win32k is safe here — the service runs
        // the SAME CRT headless under this exact lock. CIG held back (interactive soak, #180).
        Role::TextOnly => {
            Profile::MAX.allow_unsigned_dlls("interactive EDR/IME injection compat — soak (#180)")
        }
    }
}

/// Apply the baseline hardening ([`apply`]) plus the role's earned strong-tier locks (#157).
/// Call ONCE, as early as possible, before the role does any work. The token-strip is applied
/// separately at each role's own timing-sensitive call site (service.rs / tray.rs).
pub fn harden_for_role(role: Role) {
    apply();
    let p = profile_for(role);
    if p.ms_signed_only {
        enforce_ms_signed_only();
    }
    // no-child is applied here for every role that takes it EXCEPT the Tray: the no-arg role
    // first acts as a bootstrap installer/launcher (default_run spawns the elevated UAC child
    // on first-run / repair / service-start) before it becomes the tray, so its no-child lock
    // is deferred to `tray::run`, past those spawn-capable branches. Its profile still declares
    // no_child (intent/SSoT); tray.rs is just its timing-correct application site.
    if p.no_child && role != Role::Tray {
        prohibit_child_processes();
    }
    if p.no_win32k {
        disallow_win32k_syscalls();
    }
    if p.no_dynamic_code {
        prohibit_dynamic_code();
    }
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

/// Enforce Code Integrity Guard (only Microsoft-signed DLLs may load) — blocks every non-MS
/// DLL injection or plant. A one-way ratchet that cannot be disabled once set. Which roles
/// engage it, and why the Tray can't (nvml is NVIDIA-signed), is declared in [`profile_for`]
/// (#157). Best-effort: ignored on older Windows.
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

/// Prohibit child-process creation — removes the LOLBin/proxy exfil path (curl/powershell/
/// certutil/...) even from injected code, one fewer rung to the network. Role assignment (and
/// why the launchers, which must spawn the UAC child, can't take it) is declared in
/// [`profile_for`] (#47, #157). Best-effort (ignored on older Windows).
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

/// Disable win32k system calls — cuts off one of the largest kernel-LPE surfaces. PERMANENT
/// once set: any win32k call then terminates the process, so it is validated by a live run of
/// the engaging role before shipping, and only no-window roles can take it (the tray is a GUI).
/// Role assignment is declared in [`profile_for`] (#48, #157). Best-effort (ignored on older Windows).
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

/// Enforce ProcessDynamicCodePolicy (ACG): the process can no longer allocate/modify
/// executable memory, and any attempt TERMINATES it — the strongest anti-shellcode mitigation
/// (CWE-94: blocks JIT-style code injection / dynamically-generated shellcode). A permanent
/// one-way ratchet that can break in-process codegen, so it was validated audit-first
/// (AuditProhibitDynamicCode) against a clean live run before enforcing, and is re-validated by
/// a live run of the engaging role before shipping. Role assignment (and why the Tray, which
/// hosts nvml + WASAPI/COM, can't take it) is declared in [`profile_for`] (#24, #157).
/// Best-effort — ignored on older Windows.
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

/// Privileges each ROLE's token is right-sized to KEEP — the single source of truth consumed by
/// [`strip_token_privileges_except`] at the service (`service.rs`) and tray (`tray.rs`) call sites.
/// Everything NOT listed is permanently removed at runtime. These sets are load-bearing
/// least-privilege policy (#35); a regression that WIDENS either (e.g. re-adding
/// `SeDebugPrivilege`) or renames an entry is caught by `keep_set_tests` below — making the
/// by-convention invariant durable in CI (#158/#28).
///
/// Service keeps: SeChangeNotify (path/file traversal), plus SeCreateGlobal + SeImpersonate — the
/// DCOM/WMI path to the HP BIOS provider needs them; SeImpersonate is a deliberate residual kept
/// for latency (see `install.rs` SERVICE_REQUIRED_PRIVILEGES / #66).
pub const SERVICE_KEEP_PRIVILEGES: &[PCWSTR] = &[
    windows::core::w!("SeChangeNotifyPrivilege"),
    windows::core::w!("SeCreateGlobalPrivilege"),
    windows::core::w!("SeImpersonatePrivilege"),
];

/// Tray keeps: SeChangeNotify + SeShutdown (Fn+F12 sleep, enabled on demand by
/// `enable_shutdown_privilege`).
pub const TRAY_KEEP_PRIVILEGES: &[PCWSTR] = &[
    windows::core::w!("SeChangeNotifyPrivilege"),
    windows::core::w!("SeShutdownPrivilege"),
];

#[cfg(test)]
mod keep_set_tests {
    use super::{SERVICE_KEEP_PRIVILEGES, TRAY_KEEP_PRIVILEGES};
    use windows::core::PCWSTR;

    fn names(set: &[PCWSTR]) -> Vec<String> {
        // SAFETY: every entry is a `w!()` NUL-terminated UTF-16 string literal with 'static storage.
        set.iter()
            .map(|p| unsafe { p.to_string() }.expect("keep-set entry is valid UTF-16"))
            .collect()
    }

    // Least-privilege is load-bearing: these keep-sets must NOT silently widen. Adding a privilege
    // (e.g. SeDebugPrivilege) or renaming an entry fails here before it can ship (#158/#28).
    #[test]
    fn service_keep_set_is_exactly_minimal() {
        assert_eq!(
            names(SERVICE_KEEP_PRIVILEGES),
            [
                "SeChangeNotifyPrivilege",
                "SeCreateGlobalPrivilege",
                "SeImpersonatePrivilege",
            ]
        );
    }

    #[test]
    fn tray_keep_set_is_exactly_change_notify_and_shutdown() {
        assert_eq!(
            names(TRAY_KEEP_PRIVILEGES),
            ["SeChangeNotifyPrivilege", "SeShutdownPrivilege"]
        );
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
