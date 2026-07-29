use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Etw::{
    ENABLECALLBACK_ENABLED_STATE, EVENT_FILTER_DESCRIPTOR, EventRegister, EventWriteString,
    REGHANDLE,
};
use windows::Win32::System::EventLog::{
    EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE, EVENTLOG_WARNING_TYPE, REPORT_EVENT_TYPE,
    RegisterEventSourceW, ReportEventW,
};
use windows::core::{GUID, PCWSTR};

/// Handle from `RegisterEventSourceW`, kept for the process lifetime. 0 = not initialized
/// (writes become no-ops). Stored as isize so the crash-handler can read it lock-free.
static EVENT_SOURCE: AtomicIsize = AtomicIsize::new(0);
static STACK_MONITOR: AtomicBool = AtomicBool::new(false);

// --- Verbose/trace tier (ETW, on-demand) --------------------------------------------------
/// ETW registration handle (REGHANDLE). 0 = unregistered.
static ETW_HANDLE: AtomicU64 = AtomicU64::new(0);
/// True while a trace session has our provider enabled (set by the enable callback). The
/// `trace!` macro reads this BEFORE formatting, so at rest a trace line is one atomic load.
static ETW_ENABLED: AtomicBool = AtomicBool::new(false);
/// Stable ETW provider GUID for HpThermal verbose/trace. Consumers subscribe by this GUID
/// (wpr / logman / PerfView). Fixed — reproducible builds + version stability.
const ETW_PROVIDER_GUID: GUID = GUID::from_u128(0x7b2a1c4e_9d3f_4a8b_b1e6_2c5d8f0a3e71);
/// TRACE_LEVEL_VERBOSE — a session enabling at >= this level receives our trace lines.
const ETW_LEVEL_VERBOSE: u8 = 5;

/// Single event ID for our free-text diagnostic lines. With no message resource
/// registered, Event Viewer prefixes a generic wrapper — harmless, and `Get-WinEvent`
/// returns the bare string regardless. Non-zero so it's never the "success" sentinel.
const EVENT_ID_LINE: u32 = 1000;

/// Register this process's Event Log source. `label` ("svc"/"tray"/"setup") selects the
/// per-role source name, but the resident `-Service`/`-Tray` identities are asserted ONLY
/// from the canonical install dir (see `source_name`). If the source isn't registry-
/// registered (portable run), the EventLog service routes to the Application log by name —
/// logging still works, just less isolated.
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

/// Map the process label to its Event Log source, steered by provenance:
/// - `"setup"` (the install/update helper) → always `HpThermal-Setup`, whatever the location
///   (bootstrap legitimately runs from the download dir).
/// - `"svc"` / `"tray"` → `HpThermal-Service` / `HpThermal-Tray` ONLY from the canonical,
///   admin-write-only install dir. From anywhere else the resident image is unverified, so
///   they route to `HpThermal-Untrusted` — a distinct, forensically loud bucket (NOT Setup:
///   this is an anomaly, not a benign bootstrap). A copied/misplaced binary thus can't
///   masquerade as the resident service/tray, and a service started non-canonically files
///   its "REFUSING: not from install dir" refusal under Untrusted (init precedes the check).
fn source_name(label: &str) -> String {
    if label == "setup" {
        return crate::app::event_source_setup();
    }
    if !crate::install::running_from_install_dir() {
        return crate::app::event_source_untrusted();
    }
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

/// Register the verbose/trace ETW provider. Call once per process, after `init()`. Near-zero
/// cost at rest — events are dropped unless a trace session subscribes. Not explicitly
/// unregistered (process-lifetime; the OS reclaims at exit), matching the Event Log source.
pub fn etw_register() {
    let mut handle = REGHANDLE(0);
    // SAFETY: standard EventRegister with our static provider GUID + enable callback; the
    // out-param `handle` is a stack REGHANDLE written before return.
    unsafe {
        if EventRegister(
            &ETW_PROVIDER_GUID,
            Some(etw_enable_callback),
            None,
            &mut handle,
        ) == 0
        {
            ETW_HANDLE.store(handle.0 as u64, Ordering::SeqCst);
        }
    }
}

/// ETW enable callback: a trace session enabling/disabling our provider flips `ETW_ENABLED`.
/// State 1 = enable, 0 = disable; 2 = capture-state (rundown), which is not an enable-state
/// change, so it's ignored.
unsafe extern "system" fn etw_enable_callback(
    _source: *const GUID,
    is_enabled: ENABLECALLBACK_ENABLED_STATE,
    _level: u8,
    _match_any: u64,
    _match_all: u64,
    _filter: *const EVENT_FILTER_DESCRIPTOR,
    _ctx: *mut core::ffi::c_void,
) {
    match is_enabled.0 {
        0 => ETW_ENABLED.store(false, Ordering::Relaxed),
        1 => ETW_ENABLED.store(true, Ordering::Relaxed),
        _ => {}
    }
}

/// Whether a trace session is currently listening. The `trace!` macro gates on this before
/// formatting, so at rest a `trace!(...)` is a single atomic load.
#[inline]
pub fn trace_enabled() -> bool {
    ETW_ENABLED.load(Ordering::Relaxed)
}

/// The fat side of `trace!`: format the args and emit one Verbose ETW string. Only reached
/// when `trace_enabled()` — so the `format!` cost is paid only while a session is capturing.
pub fn trace_line(args: std::fmt::Arguments) {
    let h = ETW_HANDLE.load(Ordering::Relaxed);
    if h == 0 {
        return;
    }
    let s = std::fmt::format(args);
    let wide = crate::wide::wide_null(&s);
    // SAFETY: `h` is our registration handle; `wide` is a live null-terminated wide string.
    unsafe {
        let _ = EventWriteString(
            REGHANDLE(h as i64),
            ETW_LEVEL_VERBOSE,
            0,
            PCWSTR(wide.as_ptr()),
        );
    }
}

/// Verbose/trace line → ETW (Verbose level), NOT the always-on Event Log. Gated on an active
/// trace session BEFORE `format_args!`, so at rest it is one atomic load and nothing else.
/// Collected on-demand via wpr / logman / PerfView / `Get-WinEvent -Path *.etl`, and
/// correlated with the durable Event Log by timestamp. The heavy path lives once in
/// `trace_line` (thin-macro / fat-fn — negligible per-call-site code).
macro_rules! trace {
    ($($arg:tt)*) => {
        if $crate::log::trace_enabled() {
            $crate::log::trace_line(format_args!($($arg)*));
        }
    };
}
pub(crate) use trace;

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

    if trace_enabled() {
        trace_line(format_args!(
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
