use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU32, AtomicUsize, Ordering};
use std::sync::Mutex;

use windows::core::PCWSTR;
use windows::Win32::Foundation::HANDLE;

static LOG: Mutex<Option<std::fs::File>> = Mutex::new(None);
static VERBOSE: AtomicBool = AtomicBool::new(false);
static STACK_MONITOR: AtomicBool = AtomicBool::new(false);

/// Process label: "svc" or "tray". Set once at init.
static LABEL: Mutex<&str> = Mutex::new("???");

/// Initialize logging to a shared file next to the executable.
/// `label` identifies the process ("svc" or "tray") in each line.
/// Also restores verbose state from sentinel file (persistent across restarts).
pub fn init(label: &'static str) {
    if let Ok(mut guard) = LABEL.lock() {
        *guard = label;
    }
    // Ensure data directory exists (no-op if already present)
    let _ = std::fs::create_dir_all(crate::app::data_dir());
    let path = log_path();
    if let Some(f) = open_log_file(&path) {
        if let Ok(mut guard) = LOG.lock() {
            *guard = Some(f);
        }
    }
    // Restore verbose state from sentinel file
    if std::path::Path::new(&verbose_sentinel_path()).exists() {
        VERBOSE.store(true, Ordering::Relaxed);
    }
}

/// Write a timestamped, labeled line to the log.
/// Formats the entire line first, then writes in a single `write_all` call
/// so that concurrent appends from service + tray don't interleave.
pub fn write(msg: &str) {
    if let Ok(mut guard) = LOG.lock() {
        if let Some(f) = guard.as_mut() {
            use std::io::Write;
            let ts = timestamp();
            let label = LABEL.lock().map(|g| *g).unwrap_or("???");
            let line = format!("[{ts}] [{label}] {msg}\n");
            let _ = f.write_all(line.as_bytes());
            let _ = f.flush();
        }
    }
}

/// Local time as "YYYY-MM-DD HH:MM:SS.mmm" using Win32 GetLocalTime.
fn timestamp() -> String {
    // SAFETY: GetLocalTime writes to a stack-allocated SYSTEMTIME; no preconditions.
    let st = unsafe { windows::Win32::System::SystemInformation::GetLocalTime() };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds
    )
}

/// Open the log file in create + append mode (`None` on failure).
fn open_log_file(path: &str) -> Option<std::fs::File> {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .ok()
}

/// Truncate the log file and reopen in append mode.
/// `set_len(0)` doesn't work here because append mode opens with
/// FILE_APPEND_DATA (no FILE_WRITE_DATA), so we close → truncate → reopen.
pub fn clear() {
    let path = log_path();
    if let Ok(mut guard) = LOG.lock() {
        *guard = None; // close old handle
        let _ = std::fs::File::create(&path); // truncate to 0
        if let Some(f) = open_log_file(&path) {
            *guard = Some(f);
        }
    }
    write("log cleared");
}

pub fn set_verbose(on: bool) {
    VERBOSE.store(on, Ordering::Relaxed);
    // Persist via sentinel file: create to enable, delete to disable.
    // Both service and tray check this at startup.
    let sentinel = verbose_sentinel_path();
    if on {
        let _ = std::fs::File::create(&sentinel);
    } else {
        let _ = std::fs::remove_file(&sentinel);
    }
    write(&format!(
        "verbose logging {}",
        if on { "ON" } else { "OFF" }
    ));
}

pub fn is_verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

pub fn set_stack_monitor(on: bool) {
    STACK_MONITOR.store(on, Ordering::Relaxed);
    write(&format!("stack monitor {}", if on { "ON" } else { "OFF" }));
}

#[allow(dead_code)]
pub fn is_stack_monitor() -> bool {
    STACK_MONITOR.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Stack overflow guard (VEH)
// ---------------------------------------------------------------------------

/// Raw log file handle for the VEH handler. Separate from the Mutex-guarded
/// File so the crash handler can write with zero allocations.
static GUARD_LOG_HANDLE: AtomicIsize = AtomicIsize::new(0);

/// Pre-formatted crash message, written once at init. The VEH handler reads
/// this with zero allocations — no format!(), no Mutex, no heap.
static mut GUARD_MSG: [u8; 80] = [0; 80];
static GUARD_MSG_LEN: AtomicUsize = AtomicUsize::new(0);

/// Install a vectored exception handler that catches STATUS_STACK_OVERFLOW.
/// Writes a fixed message to the log file using a pre-opened raw handle,
/// then lets the OS terminate the process. Call once after `init()`.
pub fn install_stack_guard() {
    // SAFETY: GUARD_MSG is written once here before the VEH can fire (single-
    // threaded init). The raw file handle outlives the process. The VEH handler
    // only reads the static and does a single WriteFile with zero allocations.
    unsafe {
        use windows::Win32::Storage::FileSystem::*;

        // Pre-format the crash message while we still have stack
        let label = LABEL.lock().map(|g| *g).unwrap_or("???");
        let msg = format!("[FATAL] [{label}] STATUS_STACK_OVERFLOW\n");
        let bytes = msg.as_bytes();
        let len = bytes.len().min(80);
        let dst = std::ptr::addr_of_mut!(GUARD_MSG) as *mut u8;
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, len);
        GUARD_MSG_LEN.store(len, Ordering::Relaxed);

        // Open a raw append handle (separate from the Mutex<File>)
        let path_w = crate::wide::wide_null(&log_path());
        if let Ok(h) = CreateFileW(
            PCWSTR(path_w.as_ptr()),
            FILE_APPEND_DATA.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            None,
        ) {
            GUARD_LOG_HANDLE.store(h.0 as isize, Ordering::Relaxed);
        }

        windows::Win32::System::Diagnostics::Debug::AddVectoredExceptionHandler(
            1,
            Some(stack_overflow_handler),
        );
    }
}

/// VEH handler: fires on STATUS_STACK_OVERFLOW (0xC00000FD).
/// Uses only pre-allocated statics and a raw WriteFile — safe with ~4 KB of
/// remaining stack.  Returns EXCEPTION_CONTINUE_SEARCH so the OS terminates.
unsafe extern "system" fn stack_overflow_handler(
    info: *mut windows::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS,
) -> i32 {
    if !info.is_null() && !(*info).ExceptionRecord.is_null() {
        let code = (*(*info).ExceptionRecord).ExceptionCode.0 as u32;
        if code == 0xC000_00FD {
            let h = GUARD_LOG_HANDLE.load(Ordering::Relaxed);
            if h != 0 {
                let len = GUARD_MSG_LEN.load(Ordering::Relaxed);
                let src = std::ptr::addr_of!(GUARD_MSG) as *const u8;
                let msg = std::slice::from_raw_parts(src, len);
                let mut written = 0u32;
                let _ = windows::Win32::Storage::FileSystem::WriteFile(
                    HANDLE(h as *mut std::ffi::c_void),
                    Some(msg),
                    Some(&mut written),
                    None,
                );
            }
        }
    }
    0 // EXCEPTION_CONTINUE_SEARCH
}

// ---------------------------------------------------------------------------
// Stack monitoring
// ---------------------------------------------------------------------------

/// Log2 histogram bins for stack depth. 8 bins from 4 KB up to the stack
/// reserve, plus an overflow bin for anything beyond.
///   bin 0: <4 KB (baseline/idle)
///   bin 1: 4-8 KB       bin 2: 8-16 KB      bin 3: 16-32 KB
///   bin 4: 32-64 KB     bin 5: 64-128 KB    bin 6: 128-256 KB
///   bin 7: 256 KB+  (overflow -- approaching stack reserve!)
const STACK_NUM_BINS: usize = 8;
static STACK_BINS: [AtomicU32; STACK_NUM_BINS] = [const { AtomicU32::new(0) }; STACK_NUM_BINS];
static STACK_PEAK: AtomicUsize = AtomicUsize::new(0);
/// Peak instantaneous depth (RSP-based). Unlike committed peak, this only
/// captures depths at our sample points — can miss peaks between samples.
static STACK_DEPTH_PEAK: AtomicUsize = AtomicUsize::new(0);
static STACK_SAMPLES: AtomicU32 = AtomicU32::new(0);
/// Count of samples that hit the overflow bin (approaching stack limit).
static STACK_OVERFLOW_WARN: AtomicU32 = AtomicU32::new(0);

const BIN_LABELS: [&str; STACK_NUM_BINS] = [
    "<4K", "4-8K", "8-16K", "16-32K", "32-64K", "64-128K", "128-256K", "256K+!",
];

/// Current stack depth in bytes from the stack base.
/// Unlike `stack_committed()`, this fluctuates -- it goes UP during deep calls
/// and back DOWN when they return. Use for per-operation attribution.
pub fn stack_depth() -> usize {
    // SAFETY: The anchor variable's address approximates the current RSP.
    unsafe {
        let (_, high) = stack_limits();
        let anchor: u8 = 0;
        let rsp = &anchor as *const u8 as usize;
        high.saturating_sub(rsp)
    }
}

/// Current thread's stack (low, high) address bounds.
unsafe fn stack_limits() -> (usize, usize) {
    // SAFETY: GetCurrentThreadStackLimits writes to stack-allocated usizes.
    let mut low: usize = 0;
    let mut high: usize = 0;
    windows::Win32::System::Threading::GetCurrentThreadStackLimits(&mut low, &mut high);
    (low, high)
}

/// Committed stack pages (bytes). Monotonic -- reflects the all-time peak
/// because Windows never decommits stack pages. Captures COM/WMI internal
/// frames that have already returned (their pages stay committed).
pub fn stack_committed() -> usize {
    use windows::Win32::System::Memory::*;
    // SAFETY: GetCurrentThreadStackLimits provides valid low/high bounds.
    // VirtualQuery is called within those bounds; MBI is stack-allocated.
    unsafe {
        let (low, high) = stack_limits();

        let mut committed = 0usize;
        let mut addr = low;
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        while addr < high {
            let size = VirtualQuery(
                Some(addr as *const std::ffi::c_void),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );
            if size == 0 {
                break;
            }
            if mbi.State == MEM_COMMIT {
                committed += mbi.RegionSize;
            }
            addr += mbi.RegionSize;
        }
        committed
    }
}

/// Record a stack sample: update histogram, track peak, optionally log with label.
/// No-op unless stack monitoring is enabled via debug menu toggle.
pub fn stack_sample(label: &str) {
    if !STACK_MONITOR.load(Ordering::Relaxed) {
        return;
    }
    let committed = stack_committed();

    // Update peak (committed = true ceiling including returned COM frames)
    let mut peak = STACK_PEAK.load(Ordering::Relaxed);
    while committed > peak {
        match STACK_PEAK.compare_exchange_weak(
            peak,
            committed,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(p) => peak = p,
        }
    }

    // Histogram bin based on committed size (the true peak including COM internals)
    let kb = committed / 1024;
    let bin = if kb < 4 {
        0
    } else {
        let log2 = usize::BITS - 1 - kb.leading_zeros() as u32;
        (log2 as usize).saturating_sub(1).min(STACK_NUM_BINS - 1)
    };
    STACK_BINS[bin].fetch_add(1, Ordering::Relaxed);
    STACK_SAMPLES.fetch_add(1, Ordering::Relaxed);

    // Track overflow (bin 7 = approaching stack reserve limit)
    if bin == STACK_NUM_BINS - 1 {
        let prev = STACK_OVERFLOW_WARN.fetch_add(1, Ordering::Relaxed);
        if prev == 0 {
            // First overflow: always log regardless of verbose
            write(&format!(
                "WARNING: stack [{label}] hit overflow bin! committed={kb} KB"
            ));
        }
    }

    // Track peak depth (cheap: just RSP subtraction, no VirtualQuery)
    let depth = stack_depth();
    let mut depth_peak = STACK_DEPTH_PEAK.load(Ordering::Relaxed);
    while depth > depth_peak {
        match STACK_DEPTH_PEAK.compare_exchange_weak(
            depth_peak,
            depth,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(p) => depth_peak = p,
        }
    }

    if is_verbose() {
        write(&format!(
            "stack [{label}] depth={} KB committed={kb} KB peak_depth={} KB peak_committed={} KB",
            depth / 1024,
            STACK_DEPTH_PEAK.load(Ordering::Relaxed) / 1024,
            STACK_PEAK.load(Ordering::Relaxed) / 1024,
        ));
    }
}

/// Format the histogram as a single log line.
pub fn stack_report() -> String {
    let peak_committed = STACK_PEAK.load(Ordering::Relaxed);
    let peak_depth = STACK_DEPTH_PEAK.load(Ordering::Relaxed);
    let total = STACK_SAMPLES.load(Ordering::Relaxed);
    let overflows = STACK_OVERFLOW_WARN.load(Ordering::Relaxed);
    let mut s = format!(
        "stack report: peak_depth={} KB peak_committed={} KB samples={}",
        peak_depth / 1024,
        peak_committed / 1024,
        total,
    );
    if overflows > 0 {
        s.push_str(&format!(" OVERFLOW={overflows}"));
    }
    s.push_str(" |");
    for (i, label) in BIN_LABELS.iter().enumerate() {
        let count = STACK_BINS[i].load(Ordering::Relaxed);
        if count > 0 {
            s.push_str(&format!(" {label}:{count}"));
        }
    }
    s
}

/// Return peak committed stack in KB (for tray debug menu display).
pub fn stack_peak_kb() -> usize {
    STACK_PEAK.load(Ordering::Relaxed) / 1024
}

/// Return peak instantaneous depth in KB (for tray debug menu display).
pub fn stack_depth_peak_kb() -> usize {
    STACK_DEPTH_PEAK.load(Ordering::Relaxed) / 1024
}

/// Get the log file path (in ProgramData).
pub fn log_path() -> String {
    format!("{}\\{}", crate::app::data_dir(), crate::app::LOG_FILE)
}

/// Sentinel file path for persistent verbose state (in ProgramData).
fn verbose_sentinel_path() -> String {
    format!("{}\\hp-thermal.verbose", crate::app::data_dir())
}
