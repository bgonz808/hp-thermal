//! DLL-plant load probe (#106 dynamic tier). Built as a cdylib and planted — renamed to a target
//! dependency's filename (e.g. `ncrypt.dll`) — next to a throwaway copy of the target exe. All of
//! the real DLL's exports are forwarded (via a generated `.def`) to a renamed copy of the genuine
//! System32 DLL, so if THIS copy is loaded the target keeps running normally instead of failing
//! its import bind. On DLL attach, a `.CRT$XCU` initializer runs and:
//!   1. captures the load call stack (RtlCaptureStackBackTrace) and resolves each frame to its
//!      owning module — this names WHICH dependency dynamically loaded us (the discovery tier), and
//!   2. writes it, plus a `planted-dll-loaded` header, to the file at `HP_PLANT_MARKER`.
//! Marker present == the run-dir copy won the search order == plantable. The chain identifies the
//! loader so we can pin/defer it. Dev tool, never shipped, never in CI's product build.
#![crate_type = "cdylib"]

use std::ffi::c_void;

// Raw FFI so this stays a single-file cdylib (no windows-crate / Cargo project needed).
#[link(name = "ntdll")]
extern "system" {
    fn RtlCaptureStackBackTrace(
        frames_to_skip: u32,
        frames_to_capture: u32,
        back_trace: *mut *mut c_void,
        back_trace_hash: *mut u32,
    ) -> u16;
}
#[link(name = "kernel32")]
extern "system" {
    fn GetModuleHandleExW(flags: u32, module_name: *const u16, module: *mut *mut c_void) -> i32;
    fn GetModuleFileNameW(module: *mut c_void, filename: *mut u16, size: u32) -> u32;
}

const GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS: u32 = 0x0000_0004;
const GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT: u32 = 0x0000_0002; // safe under loader lock

/// Basename of the module owning `addr`, or None if it can't be resolved.
fn module_at(addr: *mut c_void) -> Option<String> {
    let mut hmod: *mut c_void = std::ptr::null_mut();
    // SAFETY: FROM_ADDRESS reinterprets the name pointer as an address; UNCHANGED_REFCOUNT avoids
    // touching the refcount (no LdrUnloadDll risk) while we're inside loader lock.
    let ok = unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            addr as *const u16,
            &mut hmod,
        )
    };
    if ok == 0 {
        return None;
    }
    let mut buf = [0u16; 260];
    // SAFETY: `hmod` is a valid module handle; buf is 260 wide chars.
    let len = unsafe { GetModuleFileNameW(hmod, buf.as_mut_ptr(), buf.len() as u32) } as usize;
    if len == 0 {
        return None;
    }
    let full = String::from_utf16_lossy(&buf[..len.min(buf.len())]);
    Some(
        full.rsplit(['\\', '/'])
            .next()
            .unwrap_or(&full)
            .to_ascii_lowercase(),
    )
}

fn write_marker() {
    let mut out = String::from("planted-dll-loaded\n");

    // Capture the load call stack and resolve the module chain (dedup consecutive dupes).
    let mut frames = [std::ptr::null_mut::<c_void>(); 48];
    // SAFETY: `frames` is a valid 48-slot buffer; no hash requested.
    let n = unsafe {
        RtlCaptureStackBackTrace(0, frames.len() as u32, frames.as_mut_ptr(), std::ptr::null_mut())
    } as usize;
    let mut last = String::new();
    for &addr in frames.iter().take(n) {
        if let Some(m) = module_at(addr) {
            if m != last {
                out.push_str(&m);
                out.push('\n');
                last = m;
            }
        }
    }

    if let Ok(path) = std::env::var("HP_PLANT_MARKER") {
        let _ = std::fs::write(path, out);
    }
}

// CRT static initializer: the MSVC `_DllMainCRTStartup` runs `.CRT$XC*` entries on
// DLL_PROCESS_ATTACH, inside the loader stack that pulled us — so the captured backtrace names the
// loader. More reliable than a bare Rust `DllMain` across toolchain versions.
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
