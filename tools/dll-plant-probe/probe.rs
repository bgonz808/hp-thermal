//! DLL-plant load probe (#106 dynamic tier). Built as a cdylib and planted — renamed to a target
//! dependency's filename (e.g. `ncrypt.dll`) — next to a throwaway copy of the target exe. All of
//! the real DLL's exports are forwarded (via a generated `.def`) to a renamed copy of the genuine
//! System32 DLL, so if THIS copy is loaded the target keeps running normally instead of failing
//! its import bind. A `.CRT$XCU` initializer (runs on DLL attach, reliably, for the MSVC CRT that
//! Rust cdylibs link) writes a marker file at `HP_PLANT_MARKER`. Marker present == the run-dir
//! copy won the search order == plantable. Dev tool, never shipped, never in CI's product build.
#![crate_type = "cdylib"]

use std::ffi::c_void;

fn write_marker() {
    if let Ok(path) = std::env::var("HP_PLANT_MARKER") {
        let _ = std::fs::write(path, b"planted-dll-loaded");
    }
}

// CRT static initializer: the MSVC `_DllMainCRTStartup` runs `.CRT$XC*` entries on
// DLL_PROCESS_ATTACH, before the loader hands control anywhere else. More reliable than a bare
// Rust `DllMain` across toolchain versions.
#[used]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XCU")]
static CTOR: extern "C" fn() = {
    extern "C" fn init() {
        write_marker();
    }
    init
};

// Redundant belt-and-suspenders: some setups invoke a user DllMain directly.
#[no_mangle]
pub extern "system" fn DllMain(_hinst: *mut c_void, reason: u32, _reserved: *mut c_void) -> i32 {
    const DLL_PROCESS_ATTACH: u32 = 1;
    if reason == DLL_PROCESS_ATTACH {
        write_marker();
    }
    1 // TRUE
}
