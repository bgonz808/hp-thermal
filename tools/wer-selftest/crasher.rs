//! Throwaway crash target for the WER opt-out self-test (see wer-abtest.ps1).
//!
//! Built to the image name `hpthermal-wertest.exe` so Windows Error Reporting matches
//! it against the *throwaway* `ExcludedApplications` entry the harness adds/removes — the
//! real `hp-thermal.exe` exclusion is never touched.
//!
//!   arg "av"       -> null write -> 0xC0000005 access violation
//!   arg "fastfail" -> abort()    -> __fastfail on MSVC -> 0xC0000409 (stack-buffer-overrun
//!                                   family; the path our stack-cookie / CFG failures take)
fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("fastfail") => std::process::abort(),
        _ => unsafe {
            std::ptr::null_mut::<u32>().write_volatile(0xDEAD);
        },
    }
}
