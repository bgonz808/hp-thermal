use std::sync::Mutex;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{FreeLibrary, HMODULE};
use windows::Win32::System::LibraryLoader::GetProcAddress;
use windows::core::{PCSTR, w};

/// How long NVML may sit unused before the idle sweep unloads it. NVIDIA keeps nvml.dll's
/// image resident system-wide, so a reload just re-maps warm pages; only `nvmlInit` recurs.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(10);

struct NvmlState {
    lib: isize,    // HMODULE, kept as isize so NvmlState is Send (it lives in a static Mutex)
    device: usize, // nvmlDevice_t
    shutdown: unsafe extern "C" fn() -> u32,
    get_temp: unsafe extern "C" fn(usize, u32, *mut u32) -> u32,
    get_power: unsafe extern "C" fn(usize, *mut u32) -> u32,
    get_name: unsafe extern "C" fn(usize, *mut u8, u32) -> u32,
    get_pstate: unsafe extern "C" fn(usize, *mut u32) -> u32,
    last_use: Instant,
}

pub struct GpuInfo {
    pub name: String,
    pub temp_c: u32,
    pub power_mw: u32,
    pub pstate: u32, // 0=P0, 1=P1, ... 15=P15, 32=unknown
}

// Resettable (unlike OnceLock) so the idle sweep can unload NVML and a later query reloads.
static NVML: Mutex<Option<NvmlState>> = Mutex::new(None);

/// Load nvml.dll, init NVML, resolve the exports. Frees the library on ANY post-load
/// failure so a non-NVIDIA machine (or a failed init) never leaks the ~28 MB mapping.
fn init() -> Option<NvmlState> {
    // SAFETY: load_system32 loads nvml.dll from System32 only; on success we hand the
    // handle to build_state, otherwise there is nothing to free.
    unsafe {
        let lib = crate::win_harden::dll::load_system32(w!("nvml.dll")).ok()?;
        match build_state(lib) {
            Some(state) => Some(state),
            None => {
                // SAFETY: `lib` is the handle we just loaded and no longer use.
                let _ = FreeLibrary(lib);
                None
            }
        }
    }
}

/// # Safety
/// `lib` must be a valid, loaded module handle for nvml.dll.
unsafe fn build_state(lib: HMODULE) -> Option<NvmlState> {
    let init_fn: unsafe extern "C" fn() -> u32 = std::mem::transmute(GetProcAddress(
        lib,
        PCSTR(c"nvmlInit_v2".as_ptr().cast::<u8>()),
    )?);
    if init_fn() != 0 {
        return None;
    }
    let get_handle: unsafe extern "C" fn(u32, *mut usize) -> u32 =
        std::mem::transmute(GetProcAddress(
            lib,
            PCSTR(c"nvmlDeviceGetHandleByIndex".as_ptr().cast::<u8>()),
        )?);
    let mut device: usize = 0;
    if get_handle(0, &mut device) != 0 {
        return None;
    }

    // Resolve an NVML export and transmute it to a typed fn pointer; `?` bails out (and
    // init() then frees the library) if a symbol is missing.
    macro_rules! load_fn {
        ($sym:literal, $ty:ty) => {
            std::mem::transmute::<unsafe extern "system" fn() -> isize, $ty>(GetProcAddress(
                lib,
                PCSTR($sym.as_ptr().cast::<u8>()),
            )?)
        };
    }

    Some(NvmlState {
        lib: lib.0 as isize,
        device,
        shutdown: load_fn!(c"nvmlShutdown", unsafe extern "C" fn() -> u32),
        get_temp: load_fn!(
            c"nvmlDeviceGetTemperature",
            unsafe extern "C" fn(usize, u32, *mut u32) -> u32
        ),
        get_power: load_fn!(
            c"nvmlDeviceGetPowerUsage",
            unsafe extern "C" fn(usize, *mut u32) -> u32
        ),
        get_name: load_fn!(
            c"nvmlDeviceGetName",
            unsafe extern "C" fn(usize, *mut u8, u32) -> u32
        ),
        get_pstate: load_fn!(
            c"nvmlDeviceGetPerformanceState",
            unsafe extern "C" fn(usize, *mut u32) -> u32
        ),
        last_use: Instant::now(),
    })
}

/// Query the dGPU, loading NVML on demand and stamping last-use so the idle sweep can
/// later unload it. Returns None if there is no NVIDIA dGPU or a query fails.
pub fn gpu_info() -> Option<GpuInfo> {
    let mut guard = NVML.lock().ok()?;
    if guard.is_none() {
        *guard = init();
    }
    let state = guard.as_mut()?;
    state.last_use = Instant::now();
    // SAFETY: `device` and the fn pointers came from a successful build_state(); output
    // pointers are stack buffers sized per the NVML ABI (name_buf is 96 bytes).
    unsafe {
        let mut temp: u32 = 0;
        let mut power: u32 = 0;
        let mut name_buf = [0u8; 96];

        if (state.get_temp)(state.device, 0, &mut temp) != 0 {
            return None;
        }
        if (state.get_power)(state.device, &mut power) != 0 {
            return None;
        }
        let mut pstate: u32 = 32; // NVML_PSTATE_UNKNOWN
        let _ = (state.get_pstate)(state.device, &mut pstate);
        let _ = (state.get_name)(state.device, name_buf.as_mut_ptr(), 96);

        let len = name_buf
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(name_buf.len());
        Some(GpuInfo {
            name: String::from_utf8_lossy(&name_buf[..len]).into_owned(),
            temp_c: temp,
            power_mw: power,
            pstate,
        })
    }
}

/// True if NVML is currently loaded, so the tray only starts the idle sweep when there is
/// something to sweep.
pub fn is_loaded() -> bool {
    NVML.lock().map(|g| g.is_some()).unwrap_or(false)
}

/// Unload NVML if it has been idle at least [`IDLE_TIMEOUT`]. Returns true when NVML is no
/// longer loaded (unloaded now, or already gone) so the caller can stop the sweep timer.
/// Safe: the lock excludes any in-flight `gpu_info`, so no live handle is freed underneath.
pub fn unload_if_idle() -> bool {
    let Ok(mut guard) = NVML.lock() else {
        return false;
    };
    let idle = matches!(guard.as_ref(), Some(s) if s.last_use.elapsed() >= IDLE_TIMEOUT);
    if idle && let Some(state) = guard.take() {
        // SAFETY: nvmlShutdown releases NVML's internal state; FreeLibrary then unmaps the
        // DLL. No fn pointer in `state` is used after this — it is dropped.
        unsafe {
            let _ = (state.shutdown)();
            let _ = FreeLibrary(HMODULE(state.lib as *mut _));
        }
    }
    guard.is_none()
}
