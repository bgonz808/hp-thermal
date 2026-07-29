use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU32, AtomicUsize, Ordering};

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::EventLog::{
    EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE, EVENTLOG_WARNING_TYPE, REPORT_EVENT_TYPE,
    RegisterEventSourceW, ReportEventW,
};
use windows::core::PCWSTR;

/// Handle from `RegisterEventSourceW`, kept for the process lifetime. 0 = not initialized
/// (writes become no-ops). Stored as isize so the crash-handler can read it lock-free.
static EVENT_SOURCE: AtomicIsize = AtomicIsize::new(0);
static VERBOSE: AtomicBool = AtomicBool::new(false);
static STACK_MONITOR: AtomicBool = AtomicBool::new(false);

/// Single event ID for our free-text diagnostic lines. With no message resource
/// registered, Event Viewer prefixes a generic wrapper — harmless, and `Get-WinEvent`
/// returns the bare string regardless. Non-zero so it's never the "success" sentinel.
const EVENT_ID_LINE: u32 = 1000;

/// Register this process's Event Log source. `label` ("svc"/"tray") selects the per-role
/// source name (`HpThermal-Service` / `HpThermal-Tray`), both derived from one brand stem.
/// If the source isn't registry-registered (portable run), the EventLog service routes to
/// the Application log by name — logging still works, just less isolated.
pub fn init(label: &'static str) {
    let source = source_name(label);
    let wide = crate::wide::wide_null(&source);
    // SAFETY: `wide` is a null-terminated wide string alive for the call. The returned
    // handle is a process-lifetime EventLog handle we never explicitly deregister (the
    // OS reclaims it at exit) — matching how the service/tray run until process death.
    unsafe {
        if let Ok(h) = RegisterEventSourceW(PCWSTR::null(), PCWSTR(wide.as_ptr())) {
            EVENT_SOURCE.store(h.0 as isize, Ordering::SeqCst);
        }
    }
}

/// Map the process label to its per-role Event Log source name.
fn source_name(label: &str) -> String {
    match label {
        "svc" => crate::app::event_source_service(),
        _ => crate::app::event_source_tray(),
    }
}

/// Write one diagnostic line as an Information event. The EventLog service stamps time,
/// source, and level — so no timestamp/label prefix here (the source encodes svc vs tray).
pub fn write(msg: &str) {
    report(EVENTLOG_INFORMATION_TYPE, msg);
}

/// Warning event: a degraded state, a non-fatal failure, or a fallback taken (an optional
/// feature disabled itself, a hardening step didn't apply). Surfaces under `Level -le 3`.
pub fn warn(msg: &str) {
    report(EVENTLOG_WARNING_TYPE, msg);
}

/// Error event: a fail-closed refusal, or a core operation that failed (WMI connect, a
/// thermal command that didn't apply). Surfaces under `Level -le 2`.
pub fn error(msg: &str) {
    report(EVENTLOG_ERROR_TYPE, msg);
}

/// Emit a single-string event of the given type. No-op until `init()` has run.
fn report(kind: REPORT_EVENT_TYPE, msg: &str) {
    let h = EVENT_SOURCE.load(Ordering::Relaxed);
    if h == 0 {
        return;
    }
    let wide = crate::wide::wide_null(msg);
    let strings = [PCWSTR(wide.as_ptr())];
    // SAFETY: `h` is our registered source handle; `strings` points at a live wide string
    // that outlives the call; no user SID / raw data.
    unsafe {
        let _ = ReportEventW(
            HANDLE(h as *mut std::ffi::c_void),
            kind,
            0,
            EVENT_ID_LINE,
            None,
            0,
            Some(&strings),
            None,
        );
    }
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

/// Pre-built, null-terminated wide crash message. Written once at init so the VEH
/// handler allocates nothing — it only reads this static and the source handle.
static mut GUARD_MSG_W: [u16; 32] = [0; 32];

/// Install a vectored exception handler that catches STATUS_STACK_OVERFLOW and emits a
/// best-effort Error event before the OS terminates the process. Best-effort because
/// `ReportEventW` makes an RPC to the EventLog service, which may not fit in the ~4 KB of
/// stack left at overflow — if it faults, we lose only the breadcrumb (the process was
/// dying anyway) and gain no file. WER is excluded for this exe (#38), so this is the only
/// crash trace; the earlier "approaching overflow" warning (stack monitor) is the primary
/// precursor signal. Call once after `init()`.
pub fn install_stack_guard() {
    // SAFETY: GUARD_MSG_W is written once here before the VEH can fire (single-threaded
    // init). The handler only reads it and the source handle, both process-lifetime.
    unsafe {
        let msg: Vec<u16> = "STATUS_STACK_OVERFLOW".encode_utf16().collect();
        let len = msg.len().min(31); // leave room for the NUL terminator
        let dst = std::ptr::addr_of_mut!(GUARD_MSG_W) as *mut u16;
        std::ptr::copy_nonoverlapping(msg.as_ptr(), dst, len);
        *dst.add(len) = 0;

        windows::Win32::System::Diagnostics::Debug::AddVectoredExceptionHandler(
            1,
            Some(stack_overflow_handler),
        );
    }
}

/// VEH handler: fires on STATUS_STACK_OVERFLOW (0xC00000FD). Best-effort `ReportEventW`
/// using only pre-built statics, then EXCEPTION_CONTINUE_SEARCH so the OS terminates.
unsafe extern "system" fn stack_overflow_handler(
    info: *mut windows::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS,
) -> i32 {
    if !info.is_null() && !(*info).ExceptionRecord.is_null() {
        let code = (*(*info).ExceptionRecord).ExceptionCode.0 as u32;
        if code == 0xC000_00FD {
            let h = EVENT_SOURCE.load(Ordering::Relaxed);
            if h != 0 {
                let src = std::ptr::addr_of!(GUARD_MSG_W) as *const u16;
                let strings = [PCWSTR(src)];
                let _ = ReportEventW(
                    HANDLE(h as *mut std::ffi::c_void),
                    EVENTLOG_ERROR_TYPE,
                    0,
                    EVENT_ID_LINE,
                    None,
                    0,
                    Some(&strings),
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
    // The anchor variable's address approximates the current RSP. Taking a
    // reference's address and integer subtraction are safe.
    let (_, high) = stack_limits();
    let anchor: u8 = 0;
    let rsp = &anchor as *const u8 as usize;
    high.saturating_sub(rsp)
}

/// Current thread's stack (low, high) address bounds. Safe: no preconditions and
/// the OS writes both out-params before return.
fn stack_limits() -> (usize, usize) {
    let mut low: usize = 0;
    let mut high: usize = 0;
    // SAFETY: GetCurrentThreadStackLimits writes to two stack-allocated usizes.
    unsafe {
        windows::Win32::System::Threading::GetCurrentThreadStackLimits(&mut low, &mut high);
    }
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
        let log2 = usize::BITS - 1 - kb.leading_zeros();
        (log2 as usize).saturating_sub(1).min(STACK_NUM_BINS - 1)
    };
    STACK_BINS[bin].fetch_add(1, Ordering::Relaxed);
    STACK_SAMPLES.fetch_add(1, Ordering::Relaxed);

    // Track overflow (bin 7 = approaching stack reserve limit)
    if bin == STACK_NUM_BINS - 1 {
        let prev = STACK_OVERFLOW_WARN.fetch_add(1, Ordering::Relaxed);
        if prev == 0 {
            // First overflow: always log regardless of verbose. Warning level — the
            // "WARNING:" text prefix is gone, the event level now carries it.
            warn(&format!(
                "stack [{label}] hit overflow bin! committed={kb} KB"
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
