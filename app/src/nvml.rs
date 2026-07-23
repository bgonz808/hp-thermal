use std::sync::OnceLock;
use windows::core::{w, PCSTR};
use windows::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
};

struct NvmlState {
    device: usize, // nvmlDevice_t
    get_temp: unsafe extern "C" fn(usize, u32, *mut u32) -> u32,
    get_power: unsafe extern "C" fn(usize, *mut u32) -> u32,
    get_name: unsafe extern "C" fn(usize, *mut u8, u32) -> u32,
    get_pstate: unsafe extern "C" fn(usize, *mut u32) -> u32,
}

pub struct GpuInfo {
    pub name: String,
    pub temp_c: u32,
    pub power_mw: u32,
    pub pstate: u32, // 0=P0, 1=P1, ... 15=P15, 32=unknown
}

static NVML: OnceLock<Option<NvmlState>> = OnceLock::new();

fn init() -> Option<NvmlState> {
    // SAFETY: LoadLibraryExW loads nvml.dll from System32 only. GetProcAddress
    // returns valid fn pointers for the NVML C ABI. Each transmute matches the
    // documented NVML function signature. nvmlInit_v2 and nvmlDeviceGetHandleByIndex
    // are called with valid stack pointers; failure returns None (no state leak).
    unsafe {
        let lib = LoadLibraryExW(w!("nvml.dll"), None, LOAD_LIBRARY_SEARCH_SYSTEM32).ok()?;

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

        // Resolve an NVML export and transmute it to a typed fn pointer; `?` bails
        // out of the enclosing fn if the symbol is missing.
        macro_rules! load_fn {
            ($lib:expr, $sym:literal, $ty:ty) => {
                std::mem::transmute::<unsafe extern "system" fn() -> isize, $ty>(GetProcAddress(
                    $lib,
                    PCSTR($sym.as_ptr().cast::<u8>()),
                )?)
            };
        }

        Some(NvmlState {
            device,
            get_temp: load_fn!(
                lib,
                c"nvmlDeviceGetTemperature",
                unsafe extern "C" fn(usize, u32, *mut u32) -> u32
            ),
            get_power: load_fn!(
                lib,
                c"nvmlDeviceGetPowerUsage",
                unsafe extern "C" fn(usize, *mut u32) -> u32
            ),
            get_name: load_fn!(
                lib,
                c"nvmlDeviceGetName",
                unsafe extern "C" fn(usize, *mut u8, u32) -> u32
            ),
            get_pstate: load_fn!(
                lib,
                c"nvmlDeviceGetPerformanceState",
                unsafe extern "C" fn(usize, *mut u32) -> u32
            ),
        })
    }
}

pub fn gpu_info() -> Option<GpuInfo> {
    let state = NVML.get_or_init(init).as_ref()?;
    // SAFETY: `state.device` is a valid nvmlDevice_t from init(). All fn pointers
    // were resolved from nvml.dll and match the C ABI. Output pointers are
    // stack-allocated with sufficient size (name_buf is 96 bytes as NVML requires).
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
        let name = String::from_utf8_lossy(&name_buf[..len]).into_owned();

        Some(GpuInfo {
            name,
            temp_c: temp,
            power_mw: power,
            pstate,
        })
    }
}
