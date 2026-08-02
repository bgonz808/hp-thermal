//! DLL loading confined to System32 — the runtime companion to the link-time
//! `/DEPENDENTLOADFLAG:0x800` (static imports) and the process-wide
//! `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` pin in the parent module.
//!
//! [`load_system32`] is the single audited chokepoint for the *genuine* on-demand
//! loads we cannot avoid (nvml, uxtheme): it passes `LOAD_LIBRARY_SEARCH_SYSTEM32`
//! explicitly, so the DLL resolves ONLY from `%SystemRoot%\System32` — never the app
//! dir, CWD, or PATH — independent of the process-wide default (which a caller may run
//! before, or an old OS may lack). One call site, one SAFETY contract.
//!
//! Prefer `/DELAYLOAD` (see `build.rs`) over this for deferring a *linked* import: a
//! delay import stays a DECLARED entry in the delay-import directory, visible to static
//! analysis, whereas a manual `LoadLibrary`+`GetProcAddress` reads as
//! [T1027.007](https://attack.mitre.org/techniques/T1027/007/) dynamic-API-resolution.
//! Use this helper only for DLLs we never link — optional, third-party, or ordinal-only.

use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::LibraryLoader::{LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW};
use windows::core::PCWSTR;

/// Load `name` from System32 only — never the app dir, CWD, or PATH. `name` is
/// typically a `w!("foo.dll")` literal. Returns the module handle (caller owns its
/// lifetime: `FreeLibrary` when done, or leave resident intentionally).
///
/// # Safety
/// Loading a DLL runs its `DllMain`, so the caller must trust `name`. Confining the
/// search to System32 is precisely what makes that trust sound: an attacker-planted
/// `name` in a writable run dir cannot win the search, so a fixed OS/driver DLL name
/// resolves to the genuine System32 image.
pub unsafe fn load_system32(name: PCWSTR) -> windows::core::Result<HMODULE> {
    // SAFETY: flags-scoped load with the search set pinned to System32; the caller
    // owns `name` and its trust per the contract above.
    unsafe { LoadLibraryExW(name, None, LOAD_LIBRARY_SEARCH_SYSTEM32) }
}
