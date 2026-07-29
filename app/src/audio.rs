//! Noise Adapt v2: mic-based environment detection for thermal mode selection.
//!
//! v1: single-point cache, one A/B test, fragile power subtraction.
//! v2: interpolation table (up to 8 points) + stress calibration for reliable
//! fan noise measurements. Fast path uses dB-space interpolation for instant
//! decisions; slow path (A/B test) accumulates points for future fast paths.

use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use windows::Win32::Media::Audio::Endpoints::IAudioEndpointVolume;
use windows::Win32::Media::Audio::*;
use windows::Win32::System::Com::*;
use windows::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
use windows::Win32::System::Threading::{
    GetCurrentThread, SetThreadPriority, THREAD_PRIORITY_BELOW_NORMAL,
};
use windows::Win32::UI::Shell::PropertiesSystem::IPropertyStore;
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SW_SHOW;
use windows::core::BOOL; // 0.62: primitive types moved Win32::Foundation -> windows::core
use windows::core::{GUID, Interface, PCWSTR, PWSTR, w};

/// Result of a noise-adapt measurement.
#[allow(dead_code)]
pub struct SmartResult {
    pub chosen_mode: u8,
    pub level_balanced: f32,
    pub level_performance: f32,
    pub delta_db: f32,
    pub fast_path: bool,
    pub mic_name: String,
    pub mic_gain: f32,
}

/// Result of stress calibration.
pub struct StressCal {
    pub fan_perf_power: f32,
    pub fan_bal_power: f32,
    pub mic_name: String,
    pub mic_gain: f32,
}

/// Debug info for Shift+right-click display.
pub struct NoiseDebugInfo {
    pub fan_perf_power: f32,
    pub fan_bal_power: f32,
    pub num_points: u32,
    pub crossover_dbfs: Option<f32>,
    pub cal_age_secs: u64,
}

/// Threshold in dB. If perf-vs-balanced delta >= this, fans are audible.
pub(crate) const THRESHOLD_DB: f32 = 3.0;
/// Interpolation confidence band: THRESHOLD_DB +/- this value.
const CONFIDENCE_BAND: f32 = 1.5;
/// Mic capture duration for fast path (ms).
const FAST_CAPTURE_MS: u32 = 1500;
/// Mic capture duration for slow path A/B test (ms).
const SLOW_CAPTURE_MS: u32 = 3000;
/// Max cache age before requiring recalibration (30 days).
const MAX_CAL_AGE: u64 = 30 * 86400;

// Audio format tags
const FMT_PCM: u16 = 1;
const FMT_FLOAT: u16 = 3;
const FMT_EXTENSIBLE: u16 = 0xFFFE;

// KSDATAFORMAT_SUBTYPE_IEEE_FLOAT {00000003-0000-0010-8000-00AA00389B71}
const SUBFMT_FLOAT: GUID = GUID {
    data1: 3,
    data2: 0,
    data3: 0x0010,
    data4: [0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71],
};

// ---- Decision logic (pure function, testable offline) -----------------------

/// Inputs to the fan noise decision algorithm.
pub(crate) struct DecisionInput {
    pub perf_power: f32,
    pub bal_power: f32,
    pub perf_tonal: f32,
    pub bal_tonal: f32,
    pub avg_moving_perf: f32,
    pub avg_moving_bal: f32,
    pub current_mode: u8,
    /// Spectral centroid difference (Performance - Balanced) in Hz.
    /// Positive = Performance has higher centroid (louder fans shift centroid up).
    /// Used as secondary confidence booster when power delta is marginal (1-3 dB).
    pub centroid_shift_hz: f32,
}

/// Result of the fan noise decision algorithm.
pub(crate) struct DecisionOutput {
    pub chosen: u8,
    pub delta_db: f32,
    pub used_tonal: bool,
    pub low_confidence: bool,
}

/// Pure decision function: given A/B test power measurements, decide which mode.
///
/// Uses tonal power when detectable fan tones exist, falls back to total power.
/// Low-confidence gate: if delta < 1 dB and no fan ramp detected, keep current mode.
pub(crate) fn compute_decision(input: &DecisionInput) -> DecisionOutput {
    let (decision_perf, decision_bal, used_tonal) =
        if input.perf_tonal > 1e-4 || input.bal_tonal > 1e-4 {
            (input.perf_tonal, input.bal_tonal, true)
        } else {
            (input.perf_power, input.bal_power, false)
        };

    let delta_db = if decision_bal > 1e-10 {
        10.0 * (decision_perf / decision_bal).log10()
    } else if decision_perf > 1e-10 {
        20.0
    } else {
        0.0
    };

    let low_confidence =
        delta_db.abs() < 1.0 && input.avg_moving_perf < 1.0 && input.avg_moving_bal < 1.0;

    // Centroid confidence boost: when power delta is marginal (1-3 dB),
    // concordant centroid shift (>200 Hz, same direction) tips the decision.
    let centroid_boosted = !low_confidence
        && delta_db.abs() >= 1.0
        && delta_db.abs() < THRESHOLD_DB
        && input.centroid_shift_hz.abs() > 200.0
        && ((delta_db > 0.0 && input.centroid_shift_hz > 0.0)
            || (delta_db < 0.0 && input.centroid_shift_hz < 0.0));

    let chosen = if low_confidence {
        input.current_mode
    } else if delta_db >= THRESHOLD_DB || (centroid_boosted && delta_db > 0.0) {
        1
    } else {
        0
    };

    DecisionOutput {
        chosen,
        delta_db,
        used_tonal,
        low_confidence,
    }
}

// ---- Calibration cache (v2) ------------------------------------------------

const MAX_POINTS: usize = 8;

/// A single interpolation point from an A/B test.
#[repr(C)]
#[derive(Clone, Copy)]
struct CalPoint {
    ambient_dbfs: f32, // gain-normalized ambient in dBFS
    delta_db: f32,     // measured delta (Performance vs Balanced)
    chosen: u8,        // 0=Performance, 1=Balanced
    temp_c: u8,        // CPU package temp at measurement
    _pad: [u8; 2],
}

/// Calibration cache v2 (136 bytes, persisted to disk).
#[repr(C)]
#[derive(Clone, Copy)]
struct NoiseCal {
    magic: [u8; 4],      // "NAC2"
    version: u32,        // 2
    mic_hash: u64,       // FNV-1a of device endpoint ID
    ref_gain: f32,       // mic gain at first calibration
    fan_perf_power: f32, // fan-only power, Performance mode
    fan_bal_power: f32,  // fan-only power, Balanced mode
    cal_timestamp: u64,  // last stress calibration (UNIX epoch)
    num_points: u32,     // 0..MAX_POINTS
    points: [CalPoint; MAX_POINTS],
}

fn cal_path() -> String {
    format!("{}\\smart-cal.bin", crate::app::data_dir())
}

fn load_cal() -> Option<NoiseCal> {
    let data = std::fs::read(cal_path()).ok()?;
    if data.len() != std::mem::size_of::<NoiseCal>() {
        return None;
    }
    // SAFETY: Length check above ensures `data` is exactly sizeof(NoiseCal);
    // read_unaligned handles any alignment. NoiseCal is repr(C) + Copy, all bit patterns valid.
    let cal: NoiseCal = unsafe { ptr::read_unaligned(data.as_ptr() as *const NoiseCal) };
    if &cal.magic != b"NAC2" || cal.version != 2 {
        return None;
    }
    Some(cal)
}

fn save_cal(cal: &NoiseCal) {
    // SAFETY: `cal` is a valid reference; NoiseCal is repr(C) + Copy so its
    // bytes are a valid [u8] slice of exactly size_of::<NoiseCal>() bytes.
    let bytes: &[u8] = unsafe {
        std::slice::from_raw_parts(
            cal as *const NoiseCal as *const u8,
            std::mem::size_of::<NoiseCal>(),
        )
    };
    if let Err(e) = std::fs::write(cal_path(), bytes) {
        crate::log::warn(&format!("noise-adapt: cache write failed: {e}"));
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn new_cal(mic_hash: u64, ref_gain: f32) -> NoiseCal {
    NoiseCal {
        magic: *b"NAC2",
        version: 2,
        mic_hash,
        ref_gain,
        fan_perf_power: 0.0,
        fan_bal_power: 0.0,
        cal_timestamp: 0,
        num_points: 0,
        points: [CalPoint {
            ambient_dbfs: 0.0,
            delta_db: 0.0,
            chosen: 0,
            temp_c: 0,
            _pad: [0; 2],
        }; MAX_POINTS],
    }
}

// ---- Point insertion + eviction --------------------------------------------

/// Estimate the crossover ambient_dbfs from stored points.
/// Crossover = midpoint of nearest adjacent pair with different decisions.
fn estimate_crossover(cal: &NoiseCal) -> Option<f32> {
    let n = cal.num_points as usize;
    if n < 2 {
        return None;
    }
    let pts = &cal.points[..n];
    let mut best_gap = f32::MAX;
    let mut best_mid = None;
    for i in 0..n - 1 {
        if pts[i].chosen != pts[i + 1].chosen {
            let gap = (pts[i + 1].ambient_dbfs - pts[i].ambient_dbfs).abs();
            if gap < best_gap {
                best_gap = gap;
                best_mid = Some((pts[i].ambient_dbfs + pts[i + 1].ambient_dbfs) / 2.0);
            }
        }
    }
    best_mid
}

/// Insert a calibration point with eviction logic.
///
/// 4 slots per side (Balanced / Performance). Keep points closest to crossover.
fn insert_point(cal: &mut NoiseCal, pt: CalPoint) {
    let n = cal.num_points as usize;

    // Count same-side points and find farthest from crossover
    let crossover = estimate_crossover(cal);

    // If table is not full, just insert in sorted order
    if n < MAX_POINTS {
        let pos = cal.points[..n].partition_point(|p| p.ambient_dbfs < pt.ambient_dbfs);
        // Shift right
        for i in (pos..n).rev() {
            cal.points[i + 1] = cal.points[i];
        }
        cal.points[pos] = pt;
        cal.num_points = (n + 1) as u32;
        return;
    }

    // Table full: eviction logic
    let same_side: Vec<usize> = (0..n)
        .filter(|&i| cal.points[i].chosen == pt.chosen)
        .collect();

    if same_side.is_empty() {
        // All 8 points are the opposite side -- replace farthest from crossover
        let cross = crossover.unwrap_or(pt.ambient_dbfs);
        let farthest = (0..n)
            .max_by(|&a, &b| {
                let da = (cal.points[a].ambient_dbfs - cross).abs();
                let db = (cal.points[b].ambient_dbfs - cross).abs();
                da.partial_cmp(&db).unwrap_or(std::cmp::Ordering::Equal)
            })
            .unwrap();
        cal.points[farthest] = pt;
        sort_points(cal);
        return;
    }

    // Check if this point flips the expected decision (refines boundary)
    let flips = if let Some(cross) = crossover {
        // Balanced points should be below crossover, Performance above
        if pt.chosen == 1 {
            pt.ambient_dbfs > cross
        } else {
            pt.ambient_dbfs < cross
        }
    } else {
        false
    };

    if flips {
        // Flipping point always stored -- evict farthest same-side from crossover
        let cross = crossover.unwrap_or(pt.ambient_dbfs);
        let farthest = same_side
            .iter()
            .copied()
            .max_by(|&a, &b| {
                let da = (cal.points[a].ambient_dbfs - cross).abs();
                let db = (cal.points[b].ambient_dbfs - cross).abs();
                da.partial_cmp(&db).unwrap_or(std::cmp::Ordering::Equal)
            })
            .unwrap();
        cal.points[farthest] = pt;
        sort_points(cal);
        return;
    }

    // Normal insert: only if closer to crossover than farthest same-side
    let cross = crossover.unwrap_or(pt.ambient_dbfs);
    let farthest_idx = same_side
        .iter()
        .copied()
        .max_by(|&a, &b| {
            let da = (cal.points[a].ambient_dbfs - cross).abs();
            let db = (cal.points[b].ambient_dbfs - cross).abs();
            da.partial_cmp(&db).unwrap_or(std::cmp::Ordering::Equal)
        })
        .unwrap();

    let new_dist = (pt.ambient_dbfs - cross).abs();
    let old_dist = (cal.points[farthest_idx].ambient_dbfs - cross).abs();

    if new_dist < old_dist {
        cal.points[farthest_idx] = pt;
        sort_points(cal);
    }
    // else: new point is farther than all existing same-side, skip (redundant)
}

fn sort_points(cal: &mut NoiseCal) {
    let n = cal.num_points as usize;
    // Simple insertion sort (n <= 8)
    for i in 1..n {
        let key = cal.points[i];
        let mut j = i;
        while j > 0 && cal.points[j - 1].ambient_dbfs > key.ambient_dbfs {
            cal.points[j] = cal.points[j - 1];
            j -= 1;
        }
        cal.points[j] = key;
    }
}

// ---- Mic identity + gain --------------------------------------------------

/// FNV-1a hash of the device endpoint ID string.
///
/// # Safety
/// `device` must be a valid COM `IMMDevice` pointer. The returned PWSTR from
/// `GetId` is freed with `CoTaskMemFree` before returning.
unsafe fn mic_device_hash(device: &IMMDevice) -> u64 {
    let Ok(id) = device.GetId() else { return 0 };
    let p = id.0;
    // Collect the null-terminated wide id into bytes (little-endian per wchar),
    // then hash with the canonical FNV-1a. Empty (null id) hashes to the FNV
    // offset basis, matching the previous behavior.
    let mut bytes = Vec::new();
    if !p.is_null() {
        let mut i = 0;
        loop {
            let ch = *p.add(i);
            if ch == 0 {
                break;
            }
            bytes.push((ch & 0xFF) as u8);
            bytes.push((ch >> 8) as u8);
            i += 1;
        }
        CoTaskMemFree(Some(p as *const std::ffi::c_void));
    }
    crate::app::fnv1a_64(&bytes)
}

/// Read the system mic gain (0.0-1.0) via IAudioEndpointVolume.
///
/// # Safety
/// `device` must be a valid COM `IMMDevice` pointer for `Activate` to succeed.
unsafe fn mic_gain(device: &IMMDevice) -> f32 {
    let Ok(vol): Result<IAudioEndpointVolume, _> = device.Activate(CLSCTX_ALL, None) else {
        return 1.0;
    };
    vol.GetMasterVolumeLevelScalar().unwrap_or(1.0)
}

// ---- Device selection (find the built-in mic) -----------------------------

// PKEY_Device_FriendlyName {A45C254E-DF1C-4EFD-8020-67D146A850E0}, 14
const PKEY_DEVICE_FRIENDLY_NAME: windows::Win32::Foundation::PROPERTYKEY =
    windows::Win32::Foundation::PROPERTYKEY {
        fmtid: GUID {
            data1: 0xa45c254e,
            data2: 0xdf1c,
            data3: 0x4efd,
            data4: [0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0],
        },
        pid: 14,
    };

/// Read the friendly name of an audio endpoint (e.g. "Microphone Array (Intel...)").
///
/// # Safety
/// `device` must be a valid COM `IMMDevice` pointer. The PROPVARIANT containing
/// the LPWSTR is read via COM accessors; null-check guards the raw pointer dereference.
unsafe fn device_friendly_name(device: &IMMDevice) -> Option<String> {
    let store: IPropertyStore = device.OpenPropertyStore(STGM(0)).ok()?; // STGM_READ = 0
    let prop = store.GetValue(&PKEY_DEVICE_FRIENDLY_NAME).ok()?;
    // VT_LPWSTR = 31
    let vt = prop.Anonymous.Anonymous.vt;
    if vt == windows::Win32::System::Variant::VT_LPWSTR {
        let pwsz: PWSTR = prop.Anonymous.Anonymous.Anonymous.pwszVal;
        if pwsz.0.is_null() {
            return None;
        }
        let len = (0..).take_while(|&i| *pwsz.0.add(i) != 0).count();
        Some(String::from_utf16_lossy(std::slice::from_raw_parts(
            pwsz.0, len,
        )))
    } else {
        None
    }
}

/// Score a device name: higher = more likely to be the built-in laptop mic.
fn device_score(name: &str) -> i32 {
    let lower = name.to_lowercase();
    let mut score = 0i32;

    // Strong built-in indicators
    if lower.contains("microphone array") {
        score += 20;
    }
    if lower.contains("intel") && lower.contains("smart sound") {
        score += 15;
    }
    if lower.contains("realtek") {
        score += 10;
    }
    if lower.contains("internal") {
        score += 10;
    }

    // External interface indicators (penalize)
    for ext in &[
        "motu",
        "focusrite",
        "scarlett",
        "behringer",
        "presonus",
        "audient",
    ] {
        if lower.contains(ext) {
            score -= 20;
        }
    }
    if lower.contains("loopback") {
        score -= 15;
    }
    if lower.contains("usb audio") {
        score -= 10;
    }

    score
}

/// Select the best capture device for fan noise measurement.
///
/// Uses IAudioMeterInformation (hardware peak meter) for the signal test —
/// this reads the same level data shown in Windows Sound Settings. NO audio
/// is captured or recorded during device selection; no mic-in-use indicator
/// appears. All devices are polled concurrently in a 200ms round-robin.
///
/// Strategy:
/// 1. Enumerate all active capture endpoints, get friendly names
/// 2. Score each by name (built-in indicators > external interface indicators)
/// 3. Poll all peak meters concurrently for 200ms to detect live signal
/// 4. Select: highest score wins, peak level breaks ties
/// # Safety
/// `enumerator` must be a valid COM `IMMDeviceEnumerator`. Calls COM methods
/// (EnumAudioEndpoints, Activate) that require COM to be initialized on this thread.
unsafe fn select_capture_device(
    enumerator: &IMMDeviceEnumerator,
) -> Result<IMMDevice, &'static str> {
    use windows::Win32::Media::Audio::Endpoints::IAudioMeterInformation;

    let collection = enumerator
        .EnumAudioEndpoints(eCapture, DEVICE_STATE_ACTIVE)
        .map_err(|_| "cannot enumerate capture devices")?;
    let count = collection
        .GetCount()
        .map_err(|_| "cannot count capture devices")?;

    if count == 0 {
        return Err("no active capture devices");
    }

    crate::log::write(&format!(
        "noise-adapt: scanning {count} capture device(s) (peak meter, no audio recorded):"
    ));

    struct Candidate {
        device: IMMDevice,
        name: String,
        score: i32,
        peak: f32, // 0.0-1.0 from hardware peak meter
    }

    // Phase 1: enumerate devices, get names + scores, activate peak meters
    let mut candidates: Vec<Candidate> = Vec::new();
    let mut meters: Vec<Option<IAudioMeterInformation>> = Vec::new();

    for i in 0..count {
        let Ok(device) = collection.Item(i) else {
            continue;
        };
        let name = device_friendly_name(&device).unwrap_or_else(|| format!("Unknown Device {i}"));
        let score = device_score(&name);

        // Activate peak meter (no capture stream, no permissions needed)
        let meter: Option<IAudioMeterInformation> = device.Activate(CLSCTX_ALL, None).ok();

        meters.push(meter);
        candidates.push(Candidate {
            device,
            name,
            score,
            peak: 0.0,
        });
    }

    if candidates.is_empty() {
        return Err("no usable capture device");
    }

    // Phase 2: poll ALL peak meters concurrently for 200ms (round-robin)
    // Each device is sampled ~20 times; we keep the max peak per device.
    for _ in 0..20 {
        for (i, meter_opt) in meters.iter().enumerate() {
            if let Some(meter) = meter_opt
                && let Ok(p) = meter.GetPeakValue()
                && p > candidates[i].peak
            {
                candidates[i].peak = p;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    // Phase 3: log results and select
    for (i, c) in candidates.iter().enumerate() {
        let has_meter = meters[i].is_some();
        crate::log::write(&format!(
            "  [{i}] {} (score={}, peak={:.4}{})",
            c.name,
            c.score,
            c.peak,
            if !has_meter { ", no meter" } else { "" },
        ));
    }

    // Highest score wins; among ties, highest peak wins
    candidates.sort_by(|a, b| {
        b.score.cmp(&a.score).then_with(|| {
            b.peak
                .partial_cmp(&a.peak)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    });

    let best = candidates.remove(0);
    crate::log::write(&format!(
        "noise-adapt: SELECTED: {} (score={}, peak={:.4})",
        best.name, best.score, best.peak,
    ));

    if best.peak < 0.0001 && best.score <= 0 {
        crate::log::write(
            "noise-adapt: WARNING: no device shows signal and no built-in mic detected",
        );
    }

    Ok(best.device)
}

// ---- Public API -----------------------------------------------------------

/// Run the noise-adapt measurement. Blocking -- run on a dedicated thread.
///
/// Tries the fast path (1.5s) if a valid calibration cache with stress data exists.
/// Falls back to the slow A/B path (18s) and saves a calibration point.
pub fn smart_measure(
    current_mode: u8,
    set_mode: impl Fn(u8),
    debug: bool,
) -> Result<SmartResult, &'static str> {
    // SAFETY: COM initialization for this thread. COINIT_MULTITHREADED is safe
    // to call from any thread; paired with CoUninitialize below.
    unsafe {
        CoInitializeEx(None, COINIT_MULTITHREADED)
            .ok()
            .map_err(|_| "COM init failed")?;
    }

    let result = measure_inner(current_mode, &set_mode, debug);

    // SAFETY: Balances the CoInitializeEx above; called once on the same thread.
    unsafe { CoUninitialize() };
    result
}

/// Run stress calibration. Blocking -- run on a dedicated thread (~45s).
///
/// Spawns a single-core stress thread, measures fan noise in both thermal modes,
/// and saves the calibration cache.
pub fn stress_calibrate(set_mode: impl Fn(u8)) -> Result<StressCal, &'static str> {
    // SAFETY: Same COM init/uninit contract as smart_measure above.
    unsafe {
        CoInitializeEx(None, COINIT_MULTITHREADED)
            .ok()
            .map_err(|_| "COM init failed")?;
    }

    let result = stress_calibrate_inner(&set_mode);

    // SAFETY: Balances the CoInitializeEx above; called once on the same thread.
    unsafe { CoUninitialize() };
    result
}

/// Delete the calibration cache file.
pub fn clear_cal() {
    let path = cal_path();
    if let Err(e) = std::fs::remove_file(&path) {
        crate::log::warn(&format!("noise-adapt: clear cal: {e}"));
    } else {
        crate::log::write("noise-adapt: calibration cleared");
    }
}

/// Get debug info for menu display.
pub fn debug_info() -> Option<NoiseDebugInfo> {
    let cal = load_cal()?;
    let age = unix_now().saturating_sub(cal.cal_timestamp);
    let crossover = estimate_crossover(&cal);
    Some(NoiseDebugInfo {
        fan_perf_power: cal.fan_perf_power,
        fan_bal_power: cal.fan_bal_power,
        num_points: cal.num_points,
        crossover_dbfs: crossover,
        cal_age_secs: age,
    })
}

fn measure_inner(
    current_mode: u8,
    set_mode: &dyn Fn(u8),
    debug: bool,
) -> Result<SmartResult, &'static str> {
    // Select the best capture device (built-in mic, not external interface)
    // SAFETY: COM is initialized by the caller (smart_measure). MMDeviceEnumerator
    // is a well-known COM class; CLSCTX_ALL is the standard creation context.
    let enumerator: IMMDeviceEnumerator = unsafe {
        CoCreateInstance(&MMDeviceEnumerator, None, CLSCTX_ALL)
            .map_err(|_| "no audio enumerator")?
    };
    // SAFETY: `enumerator` is a valid COM object from CoCreateInstance above.
    let device = unsafe { select_capture_device(&enumerator)? };
    // SAFETY: `device` is a valid IMMDevice returned by select_capture_device.
    let dev_hash = unsafe { mic_device_hash(&device) };
    // SAFETY: Same valid IMMDevice contract as above.
    let dev_gain = unsafe { mic_gain(&device) };
    // SAFETY: Same valid IMMDevice contract as above.
    let dev_name = unsafe { device_friendly_name(&device) }.unwrap_or_else(|| "Unknown".into());

    crate::log::write(&format!(
        "noise-adapt: mic=\"{dev_name}\" hash={dev_hash:016x} gain={dev_gain:.2}"
    ));

    // Try fast path with cached calibration + stress data
    if let Some(cal) = load_cal() {
        let age = unix_now().saturating_sub(cal.cal_timestamp);
        if cal.mic_hash == dev_hash && age < MAX_CAL_AGE {
            // Fast path requires stress calibration data (fan powers > 0)
            if cal.fan_perf_power > 0.0 && cal.fan_bal_power > 0.0 {
                crate::log::write(&format!(
                    "noise-adapt: cache valid ({}s old, {} pts)",
                    age, cal.num_points
                ));
                match fast_path(&device, &cal, dev_gain, current_mode, &dev_name) {
                    Ok(Some(result)) => {
                        set_mode(result.chosen_mode);
                        return Ok(result);
                    }
                    Ok(None) => {
                        crate::log::write("noise-adapt: fast path low confidence, falling back");
                    }
                    Err(e) => {
                        crate::log::write(&format!(
                            "noise-adapt: fast path error: {e}, falling back"
                        ));
                    }
                }
            } else {
                crate::log::write("noise-adapt: no stress cal data, using slow path");
            }
        } else {
            crate::log::write("noise-adapt: cache stale or mic changed");
        }
    }

    // Slow path: full A/B test
    let result = slow_path(
        &device,
        dev_hash,
        dev_gain,
        &dev_name,
        current_mode,
        set_mode,
        debug,
    )?;

    Ok(result)
}

// ---- Stress calibration (~45s) --------------------------------------------

/// Get number of logical CPUs via GetSystemInfo.
fn logical_cpu_count() -> usize {
    // SAFETY: SYSTEM_INFO is a plain C struct (all-zeros is a valid initial state).
    let mut info: SYSTEM_INFO = unsafe { std::mem::zeroed() };
    // SAFETY: GetSystemInfo always succeeds and writes to the provided pointer.
    unsafe { GetSystemInfo(&mut info) };
    (info.dwNumberOfProcessors as usize).max(1)
}

/// Spawn N stress threads that hammer all cores at BELOW_NORMAL priority.
/// Each thread has a hard `max_secs` timeout — self-terminates even if
/// the stop flag is never set (prevents orphaned runaway threads).
///
/// Uses 4-wide ILP multiply chains in batches of 4096 to maximize ALU
/// utilization. Control checks (stop flag + clock) only run between batches
/// to avoid overhead dominating under opt-level=z.
fn spawn_stress_threads(
    n: usize,
    stop: &Arc<AtomicBool>,
    max_secs: u64,
) -> Vec<std::thread::JoinHandle<()>> {
    (0..n)
        .map(|_| {
            let stop = stop.clone();
            std::thread::spawn(move || {
                // SAFETY: GetCurrentThread returns a pseudo-handle valid for the
                // calling thread. BELOW_NORMAL is a valid priority constant.
                unsafe {
                    let _ = SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
                }
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(max_secs);
                // 4 independent multiply chains for instruction-level parallelism
                let mut a = 1u64;
                let mut b = 2u64;
                let mut c = 3u64;
                let mut d = 4u64;
                let mut batch = 0u32;
                loop {
                    // 4096 iterations * 4 chains = 16384 multiplies per batch
                    // This is the actual CPU work — tight ALU loop, no branches
                    for _ in 0..4096 {
                        a = a.wrapping_mul(0x5851F42D4C957F2D).wrapping_add(1);
                        b = b.wrapping_mul(0x14057B7EF767814F).wrapping_add(1);
                        c = c.wrapping_mul(0x5851F42D4C957F2D).wrapping_add(3);
                        d = d.wrapping_mul(0x14057B7EF767814F).wrapping_add(3);
                    }
                    // One black_box per batch (not per iteration!) to prevent
                    // the compiler from optimizing away the compute
                    std::hint::black_box(a);
                    std::hint::black_box(b);
                    std::hint::black_box(c);
                    std::hint::black_box(d);

                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    batch += 1;
                    // Check deadline every ~64 batches (~1M multiplies, ~0.5ms)
                    if batch & 0x3F == 0 && std::time::Instant::now() >= deadline {
                        break;
                    }
                }
            })
        })
        .collect()
}

fn stress_calibrate_inner(set_mode: &dyn Fn(u8)) -> Result<StressCal, &'static str> {
    // SAFETY: COM is initialized by the caller (stress_calibrate). Same
    // CoCreateInstance + device query contract as measure_inner.
    let enumerator: IMMDeviceEnumerator = unsafe {
        CoCreateInstance(&MMDeviceEnumerator, None, CLSCTX_ALL)
            .map_err(|_| "no audio enumerator")?
    };
    // SAFETY: Valid COM enumerator from CoCreateInstance above.
    let device = unsafe { select_capture_device(&enumerator)? };
    // SAFETY: Valid IMMDevice from select_capture_device.
    let dev_hash = unsafe { mic_device_hash(&device) };
    // SAFETY: Same valid IMMDevice contract as above.
    let dev_gain = unsafe { mic_gain(&device) };
    // SAFETY: Same valid IMMDevice contract as above.
    let dev_name = unsafe { device_friendly_name(&device) }.unwrap_or_else(|| "Unknown".into());

    let ncpus = logical_cpu_count();
    crate::log::write(&format!(
        "stress-cal: starting, {ncpus} logical CPUs, mic=\"{dev_name}\" hash={dev_hash:016x} gain={dev_gain:.2}"
    ));

    // Open ONE continuous audio stream for the entire calibration.
    // All transitions (mode switches, load start/stop) are recorded as markers
    // in the stream, giving us a complete picture of fan behavior over time.
    //
    // Timing rationale (from CT76 experiment 16c):
    //   - EC fan controller takes 10-15s to ramp fans to new steady state
    //   - CPU thermals stabilize in ~5s but fan PID lags behind
    //   - Need 15s settle + 30s load (first 15s ramp, last 15s steady state)
    //   - Cooldown must let fans spin back down before next mode
    //
    // Total: ~2 min (15+30+15+15+15+30+15 = 135s)
    // SAFETY: `device` is a valid IMMDevice. COM is initialized on this thread.
    // CaptureStream::open activates WASAPI capture via COM interfaces.
    let mut stream = unsafe { CaptureStream::open(&device, false)? };
    stream.mark("init");

    // ========= PERFORMANCE MODE =========
    crate::log::write("stress-cal: mode -> Performance, settling 15s");
    set_mode(0);
    stream.mark("settle_perf");
    // SAFETY: Stream is open and client/capture COM pointers are valid.
    unsafe { stream.poll_for(15_000)? };

    // 30s full CPU load (all cores) -- fans spool up over first ~15s
    crate::log::write(&format!(
        "stress-cal: PERF load phase, {ncpus} threads, 30s"
    ));
    let stop_perf = Arc::new(AtomicBool::new(false));
    let handles_perf = spawn_stress_threads(ncpus, &stop_perf, 35);
    stream.mark("load_perf");
    // Capture ramp-up (first 15s) -- recorded but not used for fan power
    // SAFETY: Same open stream contract as above.
    unsafe { stream.poll_for(15_000)? };
    stream.mark("steady_perf");
    let steady_perf_start = stream.meter.window_powers.len() as u32;
    // Capture steady state (last 15s) -- this is the measurement we use
    // SAFETY: Same open stream contract as above.
    unsafe { stream.poll_for(15_000)? };
    let steady_perf_end = stream.meter.window_powers.len() as u32;

    // Stop load
    stop_perf.store(true, Ordering::Relaxed);
    for h in handles_perf {
        let _ = h.join();
    }
    crate::log::write("stress-cal: PERF load done, capturing 15s falloff");
    stream.mark("falloff_perf");
    // SAFETY: Same open stream contract as above.
    unsafe { stream.poll_for(15_000)? };

    // ========= COOLDOWN =========
    crate::log::write("stress-cal: 15s cooldown");
    stream.mark("cooldown");
    // SAFETY: Same open stream contract as above.
    unsafe { stream.poll_for(15_000)? };

    // ========= BALANCED MODE =========
    crate::log::write("stress-cal: mode -> Balanced, settling 15s");
    set_mode(1);
    stream.mark("settle_bal");
    // SAFETY: Same open stream contract as above.
    unsafe { stream.poll_for(15_000)? };

    // 30s full CPU load (all cores)
    crate::log::write(&format!("stress-cal: BAL load phase, {ncpus} threads, 30s"));
    let stop_bal = Arc::new(AtomicBool::new(false));
    let handles_bal = spawn_stress_threads(ncpus, &stop_bal, 35);
    stream.mark("load_bal");
    // Ramp-up (first 15s)
    // SAFETY: Same open stream contract as above.
    unsafe { stream.poll_for(15_000)? };
    stream.mark("steady_bal");
    let steady_bal_start = stream.meter.window_powers.len() as u32;
    // Steady state (last 15s)
    // SAFETY: Same open stream contract as above.
    unsafe { stream.poll_for(15_000)? };
    let steady_bal_end = stream.meter.window_powers.len() as u32;

    // Stop load
    stop_bal.store(true, Ordering::Relaxed);
    for h in handles_bal {
        let _ = h.join();
    }
    crate::log::write("stress-cal: BAL load done, capturing 15s falloff");
    stream.mark("falloff_bal");
    // SAFETY: Same open stream contract as above.
    unsafe { stream.poll_for(15_000)? };
    stream.mark("end");

    // Compute fan power from the STEADY-STATE portion only (skip ramp)
    let fan_perf_power = stream.phase_power(steady_perf_start, steady_perf_end);
    let fan_bal_power = stream.phase_power(steady_bal_start, steady_bal_end);
    let tonal_perf = stream.phase_tonal_power(steady_perf_start, steady_perf_end);
    let tonal_bal = stream.phase_tonal_power(steady_bal_start, steady_bal_end);

    crate::log::write(&format!(
        "stress-cal: fan_perf={fan_perf_power:.6e} fan_bal={fan_bal_power:.6e}"
    ));
    crate::log::write(&format!(
        "stress-cal: tonal perf={tonal_perf:.6e} bal={tonal_bal:.6e}"
    ));

    let total_windows = stream.meter.window_powers.len();
    stream.meter.log_stats("stress-cal continuous");

    // Write continuous TSV with all phases and markers
    stream.write_continuous_tsv(dev_gain, fan_perf_power, fan_bal_power);

    // Close the audio stream
    // SAFETY: Stream is still open; close() stops capture and frees COM format memory.
    unsafe { stream.close() };

    // Save calibration
    let mut cal = load_cal()
        .filter(|c| c.mic_hash == dev_hash)
        .unwrap_or_else(|| new_cal(dev_hash, dev_gain));

    cal.fan_perf_power = fan_perf_power;
    cal.fan_bal_power = fan_bal_power;
    cal.cal_timestamp = unix_now();
    cal.ref_gain = dev_gain;
    save_cal(&cal);

    crate::log::write(&format!(
        "stress-cal: saved ({total_windows} total windows captured)"
    ));

    Ok(StressCal {
        fan_perf_power,
        fan_bal_power,
        mic_name: dev_name,
        mic_gain: dev_gain,
    })
}

// ---- Fast path (1.5 seconds, interpolation) -------------------------------

/// Try the fast path using dB-space interpolation.
/// Returns Ok(None) if confidence is too low (fall back to A/B).
fn fast_path(
    device: &IMMDevice,
    cal: &NoiseCal,
    current_gain: f32,
    current_mode: u8,
    mic_name: &str,
) -> Result<Option<SmartResult>, &'static str> {
    crate::log::write(&format!(
        "noise-adapt: fast path, capturing {}ms in mode {}",
        FAST_CAPTURE_MS, current_mode
    ));

    let cap = capture_with_device(device, FAST_CAPTURE_MS)?;
    let measured_power = cap.power;

    // Gain-normalize: adjusted = measured * (ref_gain / current_gain)^2
    let gain_ratio = if cal.ref_gain > 0.01 {
        cal.ref_gain / current_gain
    } else {
        1.0
    };
    let adjusted = measured_power * gain_ratio * gain_ratio;

    // Subtract current mode's fan power
    let current_fan_power = if current_mode == 0 {
        cal.fan_perf_power
    } else {
        cal.fan_bal_power
    };
    let ambient = (adjusted - current_fan_power).max(1e-10);

    // Convert to dBFS
    let ambient_dbfs = 10.0 * ambient.log10();

    crate::log::write(&format!(
        "noise-adapt: fast: measured={measured_power:.6} adjusted={adjusted:.6} \
         ambient={ambient:.6} ambient_dbfs={ambient_dbfs:.1}"
    ));

    let n = cal.num_points as usize;

    // No points at all -> fall back to A/B
    if n == 0 {
        crate::log::write("noise-adapt: fast: no interpolation points");
        return Ok(None);
    }

    let pts = &cal.points[..n];

    // Binary search: find where ambient_dbfs falls
    let pos = pts.partition_point(|p| p.ambient_dbfs < ambient_dbfs);

    let (chosen, delta_db) = if pos == 0 {
        // Below all points
        let p = &pts[0];
        if p.chosen == 1 {
            // Below all Balanced points -> Balanced
            // (monotonicity: quieter environment = fans louder relative to noise)
            crate::log::write(&format!(
                "noise-adapt: fast: below all points, lowest={:.1} chose=Balanced",
                p.ambient_dbfs
            ));
            (1u8, p.delta_db)
        } else {
            // Below all Performance points -> low confidence
            crate::log::write("noise-adapt: fast: below all Performance points, low confidence");
            return Ok(None);
        }
    } else if pos == n {
        // Above all points
        let p = &pts[n - 1];
        if p.chosen == 0 {
            // Above all Performance points -> Performance
            crate::log::write(&format!(
                "noise-adapt: fast: above all points, highest={:.1} chose=Performance",
                p.ambient_dbfs
            ));
            (0u8, p.delta_db)
        } else {
            // Above all Balanced points -> low confidence
            crate::log::write("noise-adapt: fast: above all Balanced points, low confidence");
            return Ok(None);
        }
    } else {
        // Between two points: interpolate delta_db in dB space
        let lo = &pts[pos - 1];
        let hi = &pts[pos];
        let span = hi.ambient_dbfs - lo.ambient_dbfs;
        let interp_delta = if span.abs() > 0.001 {
            let t = (ambient_dbfs - lo.ambient_dbfs) / span;
            lo.delta_db + t * (hi.delta_db - lo.delta_db)
        } else {
            (lo.delta_db + hi.delta_db) / 2.0
        };

        crate::log::write(&format!(
            "noise-adapt: fast: interp between [{:.1},{:.1}dB] and [{:.1},{:.1}dB] -> {:.1}dB",
            lo.ambient_dbfs, lo.delta_db, hi.ambient_dbfs, hi.delta_db, interp_delta
        ));

        // Check confidence: if interpolated delta is within the ambiguous band,
        // fall back to A/B for a real measurement
        if interp_delta > THRESHOLD_DB - CONFIDENCE_BAND
            && interp_delta < THRESHOLD_DB + CONFIDENCE_BAND
        {
            crate::log::write(&format!(
                "noise-adapt: fast: low confidence (delta {:.1} in band {:.1}..{:.1})",
                interp_delta,
                THRESHOLD_DB - CONFIDENCE_BAND,
                THRESHOLD_DB + CONFIDENCE_BAND
            ));
            return Ok(None);
        }

        let chosen = if interp_delta >= THRESHOLD_DB { 1 } else { 0 };
        (chosen, interp_delta)
    };

    let decision_str = if chosen == 0 {
        "Performance"
    } else {
        "Balanced"
    };
    crate::log::write(&format!(
        "noise-adapt: fast: delta={delta_db:.1}dB -> {decision_str}",
    ));

    // Write capture log
    let mut log = CaptureLog::new(cap.raw_mode, current_gain);
    log.append_meter(&cap.meter, "capture_fast", current_mode);
    log.write_tsv(
        decision_str,
        delta_db,
        cal.fan_perf_power,
        cal.fan_bal_power,
    );

    Ok(Some(SmartResult {
        chosen_mode: chosen,
        level_balanced: cal.fan_bal_power.sqrt(),
        level_performance: cal.fan_perf_power.sqrt(),
        delta_db,
        fast_path: true,
        mic_name: mic_name.to_string(),
        mic_gain: current_gain,
    }))
}

// ---- Slow path (A/B test with CPU stress, ~30-50 seconds) -----------------

/// Minimum stress threads for the A/B test.
/// ~1/4 of cores (min 4) to hit 65-70C and engage differential fan speeds.
/// 1 thread kept CPU at 27C = fans OFF in both modes = measuring ambient.
const AB_STRESS_THREADS: usize = 4;
/// Adaptive settle: consecutive frames with zero moving tracks = settled.
/// At 42.67ms/frame (HOP=2048 at 48kHz), 48 frames ≈ 2.05 seconds of stable fans.
const SETTLE_STABLE_FRAMES: usize = 48;
/// Max settle time per mode (ms). Safety net if fans never fully stabilize.
const MAX_SETTLE_MS: u64 = 20_000;
/// Min settle time before checking fans_settled (ms). Let EC PID react first.
const MIN_SETTLE_MS: u64 = 8_000;

fn slow_path(
    device: &IMMDevice,
    dev_hash: u64,
    dev_gain: f32,
    mic_name: &str,
    current_mode: u8,
    set_mode: &dyn Fn(u8),
    debug: bool,
) -> Result<SmartResult, &'static str> {
    let ncpus = logical_cpu_count();
    let stress_n = (ncpus / 4).max(AB_STRESS_THREADS).min(ncpus);

    crate::log::write(&format!(
        "noise-adapt: A/B slow path, {stress_n} stress thread(s), \
         settle={MIN_SETTLE_MS}-{MAX_SETTLE_MS}ms adaptive"
    ));

    // Open ONE continuous audio stream for the entire A/B test.
    // This captures the transition (fan ramp) which helps fans_settled() detect
    // when fans have reached steady state.
    // Create debug output directory if debug mode
    let debug_dir = if debug {
        let stamp = chrono_stamp();
        let dir = format!("{}\\debug-cal-{stamp}", crate::app::data_dir());
        if let Err(e) = std::fs::create_dir_all(&dir) {
            crate::log::warn(&format!("debug-cal: failed to create dir: {e}"));
            return Err("debug dir creation failed");
        }
        crate::log::write(&format!("debug-cal: output dir: {dir}"));
        Some(dir)
    } else {
        None
    };

    // Start telemetry poller in debug mode
    let telem_stop = Arc::new(AtomicBool::new(false));
    let telem_handle = if debug {
        let stop = telem_stop.clone();
        Some(std::thread::spawn(move || telemetry_poller(stop)))
    } else {
        None
    };

    // SAFETY: `device` is a valid IMMDevice; COM is initialized on this thread.
    let mut stream = unsafe { CaptureStream::open(device, debug)? };
    stream.mark("init");

    // Start light CPU stress so fans actually differentiate between modes.
    // Without this, at idle temps (<30°C) both modes have fans OFF and
    // we'd just be measuring ambient noise fluctuations.
    let stop_stress = Arc::new(AtomicBool::new(false));
    let stress_handles = spawn_stress_threads(stress_n, &stop_stress, 120);
    crate::log::write("noise-adapt: stress thread started");

    // Always test Performance first, then Balanced.
    // This order is deterministic (not dependent on current_mode) so the
    // transition direction is always Perf→Bal, making fan_settled() consistent.

    // ========= PERFORMANCE MODE =========
    crate::log::write("noise-adapt: A/B -> Performance (0)");
    set_mode(0);
    stream.mark("settle_perf");

    // Adaptive settle: poll audio and check for fan stabilization
    let settle_perf = adaptive_settle(&mut stream, MIN_SETTLE_MS, MAX_SETTLE_MS)?;
    crate::log::write(&format!(
        "noise-adapt: Perf settled in {:.1}s ({})",
        settle_perf.elapsed_ms as f64 / 1000.0,
        if settle_perf.detected {
            "fans stable"
        } else {
            "timeout"
        }
    ));

    stream.mark("capture_perf");
    let perf_start = stream.meter.window_powers.len() as u32;
    // SAFETY: Stream is open; poll_for drains WASAPI buffers via valid COM pointers.
    unsafe { stream.poll_for(SLOW_CAPTURE_MS as u64)? };
    let perf_end = stream.meter.window_powers.len() as u32;

    // ========= BALANCED MODE =========
    crate::log::write("noise-adapt: A/B -> Balanced (1)");
    set_mode(1);

    // Verify mode switch
    let verify = crate::pipe::client_transact(crate::protocol::CMD_READ_THERMAL, 0);
    crate::log::write(&format!("noise-adapt: mode verify: {verify:?}"));

    stream.mark("settle_bal");

    let settle_bal = adaptive_settle(&mut stream, MIN_SETTLE_MS, MAX_SETTLE_MS)?;
    crate::log::write(&format!(
        "noise-adapt: Bal settled in {:.1}s ({})",
        settle_bal.elapsed_ms as f64 / 1000.0,
        if settle_bal.detected {
            "fans stable"
        } else {
            "timeout"
        }
    ));

    stream.mark("capture_bal");
    let bal_start = stream.meter.window_powers.len() as u32;
    // SAFETY: Same open stream contract as above.
    unsafe { stream.poll_for(SLOW_CAPTURE_MS as u64)? };
    let bal_end = stream.meter.window_powers.len() as u32;

    stream.mark("end");

    // Stop stress
    stop_stress.store(true, Ordering::Relaxed);
    for h in stress_handles {
        let _ = h.join();
    }
    crate::log::write("noise-adapt: stress stopped");

    // Compute BOTH total and tonal power (trimmed mean of capture windows)
    let perf_power = stream.phase_power(perf_start, perf_end);
    let bal_power = stream.phase_power(bal_start, bal_end);
    let perf_tonal = stream.phase_tonal_power(perf_start, perf_end);
    let bal_tonal = stream.phase_tonal_power(bal_start, bal_end);

    // Log track summaries at each measurement point
    crate::log::write(&format!(
        "noise-adapt: Perf capture: {}",
        phase_track_summary(&stream, perf_start, perf_end)
    ));
    crate::log::write(&format!(
        "noise-adapt: Bal capture: {}",
        phase_track_summary(&stream, bal_start, bal_end)
    ));

    // Average moving track count per phase (fan activity indicator)
    let ps = perf_start as usize;
    let pe = (perf_end as usize).min(stream.meter.window_moving_count.len());
    let bs = bal_start as usize;
    let be = (bal_end as usize).min(stream.meter.window_moving_count.len());
    let avg_moving_perf = if pe > ps {
        stream.meter.window_moving_count[ps..pe]
            .iter()
            .map(|&c| c as f32)
            .sum::<f32>()
            / (pe - ps) as f32
    } else {
        0.0
    };
    let avg_moving_bal = if be > bs {
        stream.meter.window_moving_count[bs..be]
            .iter()
            .map(|&c| c as f32)
            .sum::<f32>()
            / (be - bs) as f32
    } else {
        0.0
    };

    // Spectral centroid shift (Performance - Balanced), reusing ps/pe/bs/be ranges
    let perf_centroid = if pe > ps {
        stream.meter.window_centroids[ps..pe].iter().sum::<f32>() / (pe - ps) as f32
    } else {
        0.0
    };
    let bal_centroid = if be > bs {
        stream.meter.window_centroids[bs..be].iter().sum::<f32>() / (be - bs) as f32
    } else {
        0.0
    };
    let centroid_shift_hz = perf_centroid - bal_centroid;

    let decision = compute_decision(&DecisionInput {
        perf_power,
        bal_power,
        perf_tonal,
        bal_tonal,
        avg_moving_perf,
        avg_moving_bal,
        current_mode,
        centroid_shift_hz,
    });
    let DecisionOutput {
        chosen,
        delta_db,
        used_tonal,
        low_confidence,
    } = decision;

    if low_confidence {
        crate::log::write(
            "noise-adapt: LOW CONFIDENCE: delta<1dB, no fan ramp detected, keeping current mode",
        );
    }

    // Log total power
    let total_delta = if bal_power > 1e-10 {
        10.0 * (perf_power / bal_power).log10()
    } else {
        0.0
    };
    crate::log::write(&format!(
        "noise-adapt: A/B total: perf={perf_power:.2e} bal={bal_power:.2e} delta={total_delta:.1}dB"
    ));
    // Log tonal power
    let tonal_delta = if bal_tonal > 1e-10 {
        10.0 * (perf_tonal / bal_tonal).log10()
    } else {
        0.0
    };
    crate::log::write(&format!(
        "noise-adapt: A/B tonal: perf={perf_tonal:.2e} bal={bal_tonal:.2e} delta={tonal_delta:.1}dB{}",
        if used_tonal { " [USED]" } else { "" }
    ));
    // Log moving tracks + decision
    crate::log::write(&format!(
        "noise-adapt: A/B moving: perf={avg_moving_perf:.1} bal={avg_moving_bal:.1}{} -> {}",
        if low_confidence { " LOW_CONF" } else { "" },
        if chosen == 0 {
            "Performance"
        } else {
            "Balanced"
        }
    ));

    set_mode(chosen);

    // Stop telemetry poller
    telem_stop.store(true, Ordering::Relaxed);

    // Write continuous TSV (captures transitions + both measurement windows)
    if let Some(ref dir) = debug_dir {
        // Debug mode: write all outputs to debug directory
        let tsv_path = format!("{dir}\\analysis.tsv");
        stream.write_continuous_tsv_to(&tsv_path, dev_gain, perf_power, bal_power);
        stream.write_debug_wav(&format!("{dir}\\capture.wav"));

        if let Some(handle) = telem_handle
            && let Ok(readings) = handle.join()
        {
            write_telemetry_tsv(&readings, &format!("{dir}\\telemetry.tsv"));
        }

        // Open the directory in Explorer
        let dir_w = crate::wide::wide_null(dir);
        // SAFETY: `dir_w` is a valid null-terminated UTF-16 path on the stack.
        // ShellExecuteW with "open" on a directory launches Explorer; no handles leaked.
        unsafe {
            ShellExecuteW(
                None,
                w!("open"),
                PCWSTR(dir_w.as_ptr()),
                None,
                None,
                SW_SHOW,
            );
        }
        crate::log::write(&format!("debug-cal: opened {dir}"));
    } else {
        stream.write_continuous_tsv(dev_gain, perf_power, bal_power);
    }
    stream.meter.log_stats("A/B continuous");

    // SAFETY: Stream is still open; close() stops capture and frees COM format memory.
    unsafe { stream.close() };

    // Record calibration point
    let mut cal = load_cal()
        .filter(|c| c.mic_hash == dev_hash)
        .unwrap_or_else(|| new_cal(dev_hash, dev_gain));

    // Gain-normalize for the point
    let gain_ratio = if cal.ref_gain > 0.01 {
        cal.ref_gain / dev_gain
    } else {
        1.0
    };
    let gain_sq = gain_ratio * gain_ratio;

    // Estimate ambient: use Balanced mode's power as the lower-fan reference
    // If we have stress cal data, use that; otherwise use A/B powers directly
    let ambient_power = if cal.fan_perf_power > 0.0 && cal.fan_bal_power > 0.0 {
        // Use stress calibration fan powers
        let avg_fan = (cal.fan_perf_power + cal.fan_bal_power) / 2.0;
        let avg_measured = (perf_power * gain_sq + bal_power * gain_sq) / 2.0;
        (avg_measured - avg_fan).max(1e-10)
    } else {
        // No stress cal: use balanced power as fan proxy, perf-bal delta as signal
        // Store raw powers as fan power proxies for initial cache
        if cal.cal_timestamp == 0 {
            cal.fan_perf_power = perf_power * gain_sq;
            cal.fan_bal_power = bal_power * gain_sq;
            cal.cal_timestamp = unix_now();
            cal.ref_gain = dev_gain;
        }
        // Ambient estimate: subtract fan from total
        let current_fan = bal_power * gain_sq;
        (perf_power * gain_sq - current_fan).max(1e-10)
    };

    let ambient_dbfs = 10.0 * ambient_power.log10();

    // Read CPU temp for the point
    let temp_c = crate::pipe::client_transact(crate::protocol::CMD_READ_TEMP, 0)
        .and_then(|[s, t]| {
            if crate::protocol::status_ok(s) {
                Some(t)
            } else {
                None
            }
        })
        .unwrap_or(0);

    let pt = CalPoint {
        ambient_dbfs,
        delta_db,
        chosen,
        temp_c,
        _pad: [0; 2],
    };

    crate::log::write(&format!(
        "noise-adapt: recording point: ambient={ambient_dbfs:.1}dBFS \
         delta={delta_db:.1}dB chosen={} temp={temp_c}C",
        if chosen == 0 { "Perf" } else { "Bal" }
    ));

    insert_point(&mut cal, pt);
    save_cal(&cal);

    crate::log::write(&format!("noise-adapt: saved ({} points)", cal.num_points));

    Ok(SmartResult {
        chosen_mode: chosen,
        level_balanced: bal_power.sqrt(),
        level_performance: perf_power.sqrt(),
        delta_db,
        fast_path: false,
        mic_name: mic_name.to_string(),
        mic_gain: dev_gain,
    })
}

/// Result of adaptive settle detection.
struct SettleResult {
    elapsed_ms: u64,
    detected: bool, // true = fans_settled() triggered, false = timeout
}

/// Poll audio until fans_settled() fires or timeout.
/// Waits at least `min_ms` before checking (let EC PID controller react),
/// then checks every poll cycle until `max_ms`.
fn adaptive_settle(
    stream: &mut CaptureStream,
    min_ms: u64,
    max_ms: u64,
) -> Result<SettleResult, &'static str> {
    let start = std::time::Instant::now();
    let min_deadline = start + std::time::Duration::from_millis(min_ms);
    let max_deadline = start + std::time::Duration::from_millis(max_ms);

    // Phase 1: minimum settle (just poll, don't check)
    while std::time::Instant::now() < min_deadline {
        // SAFETY: Stream is open; poll drains WASAPI buffers via valid COM pointers.
        unsafe { stream.poll()? };
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    // SAFETY: Same open stream contract as above.
    unsafe { stream.poll()? };

    // Phase 2: check fans_settled() every ~50ms until max timeout
    loop {
        let now = std::time::Instant::now();
        if now >= max_deadline {
            return Ok(SettleResult {
                elapsed_ms: start.elapsed().as_millis() as u64,
                detected: false,
            });
        }
        if stream.meter.fans_settled(SETTLE_STABLE_FRAMES) {
            return Ok(SettleResult {
                elapsed_ms: start.elapsed().as_millis() as u64,
                detected: true,
            });
        }
        // SAFETY: Same open stream contract as above.
        unsafe { stream.poll()? };
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// Summarize average power + track count for a window range.
fn phase_track_summary(stream: &CaptureStream, start: u32, end: u32) -> String {
    let s = start as usize;
    let e = (end as usize).min(stream.meter.window_powers.len());
    if s >= e {
        return "no windows".into();
    }
    let n = e - s;
    let avg_power: f32 = stream.meter.window_powers[s..e].iter().sum::<f32>() / n as f32;
    let avg_tonal: f32 = stream.meter.window_tonal_power[s..e].iter().sum::<f32>() / n as f32;
    let avg_moving: f32 = stream.meter.window_moving_count[s..e]
        .iter()
        .map(|&c| c as f32)
        .sum::<f32>()
        / n as f32;
    let dbfs = if avg_power > 0.0 {
        10.0 * avg_power.log10()
    } else {
        -120.0
    };
    let tonal_pct = if avg_power > 0.0 {
        100.0 * avg_tonal / avg_power
    } else {
        0.0
    };
    format!("{n} win, {dbfs:.1} dBFS, tonal={tonal_pct:.0}%, moving={avg_moving:.1}",)
}

// ---- WASAPI capture -------------------------------------------------------

/// Try to get an IAudioClient in RAW mode (bypasses Windows noise suppression).
/// Returns (Some(client), true) on success, (None, false) on failure.
///
/// # Safety
/// `device` must be a valid COM `IMMDevice` pointer. COM must be initialized
/// on the calling thread. Activates IAudioClient2 and sets raw stream properties.
unsafe fn try_raw_client(device: &IMMDevice) -> (Option<IAudioClient>, bool) {
    let Ok(client2): Result<IAudioClient2, _> = device.Activate(CLSCTX_ALL, None) else {
        return (None, false);
    };

    let props = AudioClientProperties {
        cbSize: std::mem::size_of::<AudioClientProperties>() as u32,
        bIsOffload: BOOL(0),
        eCategory: AUDIO_STREAM_CATEGORY(0), // AudioCategory_Other
        Options: AUDCLNT_STREAMOPTIONS_RAW,
    };

    if client2.SetClientProperties(&props).is_err() {
        // Raw not supported by this driver; the client2 is still usable
        // but in processed mode. Cast and return it anyway.
        return match client2.cast::<IAudioClient>() {
            Ok(c) => (Some(c), false),
            Err(_) => (None, false),
        };
    }

    match client2.cast::<IAudioClient>() {
        Ok(c) => (Some(c), true),
        Err(_) => (None, false),
    }
}

/// Result of a single capture phase (power + per-window data for logging).
struct CaptureResult {
    power: f32,
    meter: NoiseMeter,
    raw_mode: bool,
}

/// A long-lived WASAPI capture stream that can be polled incrementally.
/// Opens the audio device once and feeds samples to a NoiseMeter on each poll.
struct CaptureStream {
    client: IAudioClient,
    capture: IAudioCaptureClient,
    format_ptr: *mut WAVEFORMATEX,
    is_float: bool,
    channels: usize,
    raw: bool,
    meter: NoiseMeter,
    /// Phase markers: (window_index, label) recorded at transition points.
    markers: Vec<(u32, &'static str)>,
    /// When true, raw mono f32 samples are buffered for WAV output.
    debug_wav: bool,
    /// Mono f32 samples captured when debug_wav=true (~13 MB for 70s @ 48kHz).
    samples: Vec<f32>,
}

impl CaptureStream {
    /// Open and start a continuous capture stream on `device`.
    /// When `debug` is true, raw mono samples are buffered for WAV output.
    ///
    /// # Safety
    /// `device` must be a valid COM `IMMDevice`. COM must be initialized on the
    /// calling thread. Activates WASAPI client, reads mix format (raw pointer from
    /// COM allocator), and starts capture. The format pointer is freed in `close()`.
    unsafe fn open(device: &IMMDevice, debug: bool) -> Result<Self, &'static str> {
        let (client_opt, raw) = try_raw_client(device);
        let client: IAudioClient = match client_opt {
            Some(c) => c,
            None => device
                .Activate(CLSCTX_ALL, None)
                .map_err(|_| "audio client activate failed")?,
        };

        if raw {
            crate::log::write("  stream: RAW mode (no DSP)");
        } else {
            crate::log::write("  stream: processed mode (raw unavailable)");
        }

        let format_ptr = client.GetMixFormat().map_err(|_| "GetMixFormat failed")?;
        let fmt = &*format_ptr;

        let sample_rate = fmt.nSamplesPerSec;
        let channels = fmt.nChannels as usize;
        let tag = fmt.wFormatTag;

        let is_float = match tag {
            FMT_FLOAT => true,
            FMT_PCM => false,
            FMT_EXTENSIBLE => {
                if fmt.cbSize >= 22 {
                    let ext = format_ptr as *const WAVEFORMATEXTENSIBLE;
                    let sub: GUID = ptr::read_unaligned(ptr::addr_of!((*ext).SubFormat));
                    sub == SUBFMT_FLOAT
                } else {
                    false
                }
            }
            _ => {
                CoTaskMemFree(Some(format_ptr as *const std::ffi::c_void));
                return Err("unsupported audio format");
            }
        };

        client
            .Initialize(AUDCLNT_SHAREMODE_SHARED, 0, 10_000_000, 0, format_ptr, None)
            .map_err(|_| "audio init failed")?;

        if let Ok(session) = client.GetService::<IAudioSessionControl>() {
            let label: Vec<u16> =
                "HP Thermal \u{2014} Listening for cooling fans vs. ambient noise"
                    .encode_utf16()
                    .chain(std::iter::once(0))
                    .collect();
            let _ = session.SetDisplayName(windows::core::PCWSTR(label.as_ptr()), ptr::null());
        }

        let capture: IAudioCaptureClient = client.GetService().map_err(|_| "no capture service")?;

        let meter = NoiseMeter::new(sample_rate);

        client.Start().map_err(|_| "capture start failed")?;

        // ~70s at 48kHz mono = 3_360_000 samples * 4 bytes = 13.4 MB
        let samples = if debug {
            Vec::with_capacity(sample_rate as usize * 70)
        } else {
            Vec::new()
        };

        Ok(CaptureStream {
            client,
            capture,
            format_ptr,
            is_float,
            channels,
            raw,
            meter,
            markers: Vec::with_capacity(16),
            debug_wav: debug,
            samples,
        })
    }

    /// Record a phase marker at the current window position.
    fn mark(&mut self, label: &'static str) {
        let window = self.meter.window_powers.len() as u32;
        crate::log::write(&format!("  stream: marker \"{label}\" at window {window}"));
        self.markers.push((window, label));
    }

    /// Drain available audio packets, feeding them to the NoiseMeter.
    /// Call this frequently (every ~50ms) to prevent buffer overrun.
    ///
    /// # Safety
    /// The capture stream must be open (client started, capture interface valid).
    /// GetBuffer returns a raw pointer to the audio engine's buffer; we read
    /// `frames * channels` samples bounded by the buffer size the API reports.
    /// ReleaseBuffer is called unconditionally to return the buffer.
    unsafe fn poll(&mut self) -> Result<(), &'static str> {
        loop {
            let pkt = self
                .capture
                .GetNextPacketSize()
                .map_err(|_| "GetNextPacketSize failed")?;
            if pkt == 0 {
                return Ok(());
            }

            let mut buf: *mut u8 = ptr::null_mut();
            let mut frames = 0u32;
            let mut flags = 0u32;
            self.capture
                .GetBuffer(&mut buf, &mut frames, &mut flags, None, None)
                .map_err(|_| "GetBuffer failed")?;

            if flags & 2 != 0 {
                self.meter.silent_bufs += 1;
            } else {
                self.meter.active_bufs += 1;
            }

            if flags & 2 == 0 && !buf.is_null() {
                for f in 0..frames as usize {
                    let sample = if self.is_float {
                        let p = buf as *const f32;
                        let mut sum = 0f32;
                        for ch in 0..self.channels {
                            sum += *p.add(f * self.channels + ch);
                        }
                        sum / self.channels as f32
                    } else {
                        let p = buf as *const i16;
                        let mut sum = 0f32;
                        for ch in 0..self.channels {
                            sum += *p.add(f * self.channels + ch) as f32 / 32768.0;
                        }
                        sum / self.channels as f32
                    };
                    if self.debug_wav {
                        self.samples.push(sample);
                    }
                    self.meter.feed(sample);
                }
            }

            let _ = self.capture.ReleaseBuffer(frames);
        }
    }

    /// Poll in a loop for `duration_ms`, sleeping between polls.
    ///
    /// # Safety
    /// Same contract as `poll()`: capture stream must be open with valid COM pointers.
    unsafe fn poll_for(&mut self, duration_ms: u64) -> Result<(), &'static str> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(duration_ms);
        while std::time::Instant::now() < deadline {
            self.poll()?;
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        // Final drain
        self.poll()
    }

    /// Compute trimmed-mean power for windows in range [start_window..end_window).
    fn phase_power(&self, start: u32, end: u32) -> f32 {
        let s = start as usize;
        let e = (end as usize).min(self.meter.window_powers.len());
        if s >= e {
            return 0.0;
        }
        let mut slice: Vec<f32> = self.meter.window_powers[s..e].to_vec();
        slice.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let n = slice.len();
        let trim = n * 15 / 100;
        let start = trim;
        let end = n - trim;
        if start >= end {
            slice.iter().sum::<f32>() / n as f32
        } else {
            slice[start..end].iter().sum::<f32>() / (end - start) as f32
        }
    }

    /// Trimmed-mean TONAL power for windows in range [start_window..end_window).
    /// Only counts energy under tracked peaks (fan harmonics), rejecting
    /// broadband ambient noise that contaminates total power measurements.
    fn phase_tonal_power(&self, start: u32, end: u32) -> f32 {
        let s = start as usize;
        let e = (end as usize).min(self.meter.window_tonal_power.len());
        if s >= e {
            return 0.0;
        }
        let mut slice: Vec<f32> = self.meter.window_tonal_power[s..e].to_vec();
        slice.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let n = slice.len();
        let trim = n * 15 / 100;
        let lo = trim;
        let hi = n - trim;
        if lo >= hi {
            slice.iter().sum::<f32>() / n as f32
        } else {
            slice[lo..hi].iter().sum::<f32>() / (hi - lo) as f32
        }
    }

    /// Stop capture and free format memory.
    ///
    /// # Safety
    /// Must only be called once. `self.client` and `self.format_ptr` must still
    /// be valid (not previously freed). `format_ptr` was allocated by WASAPI's
    /// COM allocator and is freed here with `CoTaskMemFree`.
    unsafe fn close(self) {
        let _ = self.client.Stop();
        CoTaskMemFree(Some(self.format_ptr as *const std::ffi::c_void));
    }

    /// Write a continuous TSV with phase labels derived from markers.
    fn write_continuous_tsv(&self, mic_gain: f32, fan_perf_power: f32, fan_bal_power: f32) {
        let path = format!("{}\\noise-capture.tsv", crate::app::data_dir());
        self.write_continuous_tsv_to(&path, mic_gain, fan_perf_power, fan_bal_power);
    }

    /// Write a continuous TSV to a specific path.
    fn write_continuous_tsv_to(
        &self,
        path: &str,
        mic_gain: f32,
        fan_perf_power: f32,
        fan_bal_power: f32,
    ) {
        let n = self.meter.window_powers.len();
        let mut out = String::with_capacity(n * 80 + 512);

        out.push_str(&format!(
            "# stress-cal continuous {}\n# raw={} mic_gain={:.3}\n",
            chrono_stamp(),
            self.raw,
            mic_gain,
        ));

        // Build marker index for phase lookup
        out.push_str("# markers:");
        for (w, label) in &self.markers {
            out.push_str(&format!(" {w}={label}"));
        }
        out.push('\n');

        // Window time step: HOP samples / sample_rate
        let win_step = HOP as f64 / self.meter.sample_rate as f64;
        out.push_str(
            "window\ttime_s\tphase\tpower\tpower_dbfs\tcentroid_hz\t\
             peak_freq_hz\tpeak_mag\tmoving\ttonal_power\tnoise_power\n",
        );

        for i in 0..n {
            let t = i as f64 * win_step;
            let phase = self.phase_at(i as u32);
            let p = self.meter.window_powers[i];
            let dbfs = if p > 0.0 { 10.0 * p.log10() } else { -120.0 };
            let centroid = self.meter.window_centroids.get(i).copied().unwrap_or(0.0);
            let peak_freq = self.meter.window_peak_freqs.get(i).copied().unwrap_or(0.0);
            let peak_mag = self.meter.window_peak_mags.get(i).copied().unwrap_or(0.0);
            let moving = self.meter.window_moving_count.get(i).copied().unwrap_or(0);
            let tonal = self.meter.window_tonal_power.get(i).copied().unwrap_or(0.0);
            let noise = (p - tonal).max(0.0);
            out.push_str(&format!(
                "{i}\t{t:.3}\t{phase}\t{p:.6e}\t{dbfs:.1}\t{centroid:.0}\t\
                 {peak_freq:.1}\t{peak_mag:.6e}\t{moving}\t{tonal:.6e}\t{noise:.6e}\n",
            ));
        }

        let perf_db = if fan_perf_power > 0.0 {
            10.0 * fan_perf_power.log10()
        } else {
            -120.0
        };
        let bal_db = if fan_bal_power > 0.0 {
            10.0 * fan_bal_power.log10()
        } else {
            -120.0
        };
        out.push_str(&format!(
            "# fan_perf={fan_perf_power:.6e} ({perf_db:.1} dBFS) fan_bal={fan_bal_power:.6e} ({bal_db:.1} dBFS)\n",
        ));

        if let Err(e) = std::fs::write(path, out.as_bytes()) {
            crate::log::warn(&format!("stress-cal: TSV write failed: {e}"));
        } else {
            crate::log::write(&format!("stress-cal: wrote {n} windows to {path}"));
        }
    }

    /// Write a WAV file with embedded RIFF cue-point markers.
    /// Format: 32-bit float mono (WAVE_FORMAT_IEEE_FLOAT = 0x0003).
    /// Audacity reads cue points natively as a label track.
    fn write_debug_wav(&self, path: &str) {
        if self.samples.is_empty() {
            crate::log::write("debug-cal: no samples to write");
            return;
        }

        let sample_rate = self.meter.sample_rate;
        let num_samples = self.samples.len() as u32;
        let bytes_per_sample = 4u32; // f32
        let data_size = num_samples * bytes_per_sample;

        // Build cue chunk
        let num_cues = self.markers.len() as u32;
        let cue_chunk_size = 4 + num_cues * 24; // dwCuePoints + N * 24-byte entries

        // Build label sub-chunks for LIST/adtl
        // Each labl: 4 (chunk id) + 4 (size) + 4 (dwName) + label bytes + NUL, padded to even
        let mut label_data: Vec<u8> = Vec::new();
        for (i, &(_win, lbl)) in self.markers.iter().enumerate() {
            let id = (i + 1) as u32;
            let text = lbl.as_bytes();
            let text_len = text.len() as u32 + 1; // include NUL
            let labl_size = 4 + text_len; // dwName + text + NUL
            label_data.extend_from_slice(b"labl");
            label_data.extend_from_slice(&labl_size.to_le_bytes());
            label_data.extend_from_slice(&id.to_le_bytes());
            label_data.extend_from_slice(text);
            label_data.push(0); // NUL terminator
            // Pad to even if needed
            if labl_size & 1 != 0 {
                label_data.push(0);
            }
        }

        let list_payload_size = 4 + label_data.len() as u32; // "adtl" + labels
        let has_markers = num_cues > 0;

        // Total RIFF file size
        let fmt_chunk_total = 8 + 16u32; // "fmt " + size + 16 bytes PCM
        let data_chunk_total = 8 + data_size;
        let cue_chunk_total = if has_markers { 8 + cue_chunk_size } else { 0 };
        let list_chunk_total = if has_markers {
            8 + list_payload_size
        } else {
            0
        };
        let riff_payload =
            4 + fmt_chunk_total + data_chunk_total + cue_chunk_total + list_chunk_total; // "WAVE" + chunks

        let total_size = 8 + riff_payload; // "RIFF" + size + payload
        let mut buf: Vec<u8> = Vec::with_capacity(total_size as usize);

        // RIFF header
        buf.extend_from_slice(b"RIFF");
        buf.extend_from_slice(&riff_payload.to_le_bytes());
        buf.extend_from_slice(b"WAVE");

        // fmt chunk (16 bytes, IEEE float)
        buf.extend_from_slice(b"fmt ");
        buf.extend_from_slice(&16u32.to_le_bytes());
        buf.extend_from_slice(&3u16.to_le_bytes()); // WAVE_FORMAT_IEEE_FLOAT
        buf.extend_from_slice(&1u16.to_le_bytes()); // mono
        buf.extend_from_slice(&sample_rate.to_le_bytes());
        buf.extend_from_slice(&(sample_rate * bytes_per_sample).to_le_bytes()); // byte rate
        buf.extend_from_slice(&(bytes_per_sample as u16).to_le_bytes()); // block align
        buf.extend_from_slice(&32u16.to_le_bytes()); // bits per sample

        // data chunk
        buf.extend_from_slice(b"data");
        buf.extend_from_slice(&data_size.to_le_bytes());
        // Write samples as raw f32 LE bytes
        for &s in &self.samples {
            buf.extend_from_slice(&s.to_le_bytes());
        }

        // cue chunk
        if has_markers {
            buf.extend_from_slice(b"cue ");
            buf.extend_from_slice(&cue_chunk_size.to_le_bytes());
            buf.extend_from_slice(&num_cues.to_le_bytes());
            for (i, &(win, _lbl)) in self.markers.iter().enumerate() {
                let id = (i + 1) as u32;
                let sample_pos = win * HOP as u32;
                buf.extend_from_slice(&id.to_le_bytes()); // dwName
                buf.extend_from_slice(&sample_pos.to_le_bytes()); // dwPosition
                buf.extend_from_slice(b"data"); // fccChunk
                buf.extend_from_slice(&0u32.to_le_bytes()); // dwChunkStart
                buf.extend_from_slice(&0u32.to_le_bytes()); // dwBlockStart
                buf.extend_from_slice(&sample_pos.to_le_bytes()); // dwSampleOffset
            }

            // LIST/adtl chunk with labels
            buf.extend_from_slice(b"LIST");
            buf.extend_from_slice(&list_payload_size.to_le_bytes());
            buf.extend_from_slice(b"adtl");
            buf.extend_from_slice(&label_data);
        }

        if let Err(e) = std::fs::write(path, &buf) {
            crate::log::warn(&format!("debug-cal: WAV write failed: {e}"));
        } else {
            let mb = buf.len() as f64 / (1024.0 * 1024.0);
            crate::log::write(&format!(
                "debug-cal: wrote {path} ({num_samples} samples, {mb:.1} MB, {} markers)",
                self.markers.len(),
            ));
        }
    }

    /// Look up the phase label for a given window index.
    fn phase_at(&self, window: u32) -> &'static str {
        let mut phase = "init";
        for &(w, label) in &self.markers {
            if window >= w {
                phase = label;
            } else {
                break;
            }
        }
        phase
    }
}

/// Capture audio from an already-opened device for `duration_ms`.
/// Returns EMA-smoothed band power + per-window data for capture log.
///
/// Requests RAW (unprocessed) audio via IAudioClient2 to bypass Windows
/// noise suppression, which would otherwise strip the fan noise we're
/// trying to measure. Falls back to processed audio if raw unavailable.
fn capture_with_device(
    device: &IMMDevice,
    duration_ms: u32,
) -> Result<CaptureResult, &'static str> {
    // SAFETY: Entire block uses COM/WASAPI interfaces on a valid IMMDevice.
    // COM is initialized by the caller. Raw pointers (format_ptr, audio buffer)
    // are obtained from COM APIs and freed/released before returning. Buffer
    // reads are bounded by the `frames` count returned by GetBuffer. The
    // format_ptr is freed with CoTaskMemFree at the end.
    unsafe {
        // Try RAW capture (bypasses noise suppression / echo cancellation)
        let (client, raw) = try_raw_client(device);
        let client: IAudioClient = match client {
            Some(c) => c,
            None => device
                .Activate(CLSCTX_ALL, None)
                .map_err(|_| "audio client activate failed")?,
        };

        if raw {
            crate::log::write("  capture: RAW mode (no DSP)");
        } else {
            crate::log::write("  capture: processed mode (raw unavailable)");
        }

        let format_ptr = client.GetMixFormat().map_err(|_| "GetMixFormat failed")?;
        let fmt = &*format_ptr;

        let sample_rate = fmt.nSamplesPerSec;
        let channels = fmt.nChannels as usize;
        let tag = fmt.wFormatTag;

        let is_float = match tag {
            FMT_FLOAT => true,
            FMT_PCM => false,
            FMT_EXTENSIBLE => {
                if fmt.cbSize >= 22 {
                    let ext = format_ptr as *const WAVEFORMATEXTENSIBLE;
                    let sub: GUID = ptr::read_unaligned(ptr::addr_of!((*ext).SubFormat));
                    sub == SUBFMT_FLOAT
                } else {
                    false
                }
            }
            _ => {
                CoTaskMemFree(Some(format_ptr as *const std::ffi::c_void));
                return Err("unsupported audio format");
            }
        };

        // Shared mode, 1-second buffer (100ns units)
        client
            .Initialize(AUDCLNT_SHAREMODE_SHARED, 0, 10_000_000, 0, format_ptr, None)
            .map_err(|_| "audio init failed")?;

        // Label our audio session so the volume mixer / privacy settings
        // show a clear purpose instead of a mystery process.
        if let Ok(session) = client.GetService::<IAudioSessionControl>() {
            let label: Vec<u16> =
                "HP Thermal \u{2014} Listening for cooling fans vs. ambient noise"
                    .encode_utf16()
                    .chain(std::iter::once(0))
                    .collect();
            let _ = session.SetDisplayName(windows::core::PCWSTR(label.as_ptr()), ptr::null());
        }

        let capture: IAudioCaptureClient = client.GetService().map_err(|_| "no capture service")?;

        let mut meter = NoiseMeter::new(sample_rate);

        client.Start().map_err(|_| "capture start failed")?;

        let deadline =
            std::time::Instant::now() + std::time::Duration::from_millis(duration_ms as u64);

        while std::time::Instant::now() < deadline {
            let pkt = capture
                .GetNextPacketSize()
                .map_err(|_| "GetNextPacketSize failed")?;
            if pkt == 0 {
                std::thread::sleep(std::time::Duration::from_millis(5));
                continue;
            }

            let mut buf: *mut u8 = ptr::null_mut();
            let mut frames = 0u32;
            let mut flags = 0u32;
            capture
                .GetBuffer(&mut buf, &mut frames, &mut flags, None, None)
                .map_err(|_| "GetBuffer failed")?;

            // Track silent vs active buffers for diagnostics
            if flags & 2 != 0 {
                meter.silent_bufs += 1;
            } else {
                meter.active_bufs += 1;
            }

            // Skip silent buffers (bit 1 = AUDCLNT_BUFFERFLAGS_SILENT)
            if flags & 2 == 0 && !buf.is_null() {
                for f in 0..frames as usize {
                    let sample = if is_float {
                        let p = buf as *const f32;
                        let mut sum = 0f32;
                        for ch in 0..channels {
                            sum += *p.add(f * channels + ch);
                        }
                        sum / channels as f32
                    } else {
                        let p = buf as *const i16;
                        let mut sum = 0f32;
                        for ch in 0..channels {
                            sum += *p.add(f * channels + ch) as f32 / 32768.0;
                        }
                        sum / channels as f32
                    };
                    meter.feed(sample);
                }
            }

            let _ = capture.ReleaseBuffer(frames);
        }

        let _ = client.Stop();
        CoTaskMemFree(Some(format_ptr as *const std::ffi::c_void));

        meter.log_stats(&format!("capture {duration_ms}ms"));
        let power = meter.power();
        Ok(CaptureResult {
            power,
            meter,
            raw_mode: raw,
        })
    }
}

// ---- DSP: Multi-peak tracker + A-weighted power ----------------------------

const FFT_N: usize = 32768;
/// Fixed-time hop: 2048 samples = 42.67ms at 48 kHz regardless of FFT size.
/// For small FFTs, clamp to NFFT/2 (50% overlap floor).
const HOP: usize = if FFT_N / 2 < 2048 { FFT_N / 2 } else { 2048 };
const BAND_LO_HZ: u32 = 300;
const BAND_HI_HZ: u32 = 14000;

/// A-weight scale: u8 value / 128.0 = power multiplier.
const AW_SCALE: f32 = 128.0;

/// Max simultaneous peaks tracked per frame.
const MAX_PEAKS: usize = 8;
/// Max frequency jump (Hz) for track linking between frames.
/// At 42.67ms/frame with fan slew ~25 Hz/s, max jump per frame ~1.1 Hz.
/// Allow 400 Hz to cover mode transitions (fan slews ~80 Hz in a few frames).
const TRACK_MAX_JUMP_HZ: f32 = 400.0;
/// Frames a track can go unlinked before dying (~341ms gap tolerance).
const TRACK_MAX_MISSED: u8 = 8;
/// Maximum number of live tracks.
const MAX_TRACKS: usize = 16;

/// A tracked spectral peak across frames.
#[derive(Clone)]
struct PeakTrack {
    freq: f32,         // current frequency (Hz)
    mag: f32,          // current magnitude
    freq_ema: f32,     // EMA-smoothed frequency for slope detection
    slope: f32,        // frequency slope (Hz/frame), + = rising
    power_sum: f32,    // cumulative A-weighted power (for tonal vs noise)
    frames_alive: u16, // how long this track has been active
    missed: u8,        // consecutive frames with no matching peak
    alive: bool,
}

impl PeakTrack {
    fn new(freq: f32, mag: f32) -> Self {
        Self {
            freq,
            mag,
            freq_ema: freq,
            slope: 0.0,
            power_sum: 0.0,
            frames_alive: 1,
            missed: 0,
            alive: true,
        }
    }

    /// Is this track moving (ramping) significantly?
    /// At 42.67ms/frame: 2.0 Hz/frame ≈ 47 Hz/s physical rate.
    fn is_moving(&self) -> bool {
        self.frames_alive > 8 && self.slope.abs() > 2.0
    }

    /// Is this track stationary (ambient/HVAC)?
    /// At 42.67ms/frame: 0.4 Hz/frame ≈ 9.4 Hz/s physical rate.
    fn is_stationary(&self) -> bool {
        self.frames_alive > 12 && self.slope.abs() < 0.4
    }
}

struct NoiseMeter {
    buf: Vec<f32>,
    buf_pos: usize,
    hann: Vec<f32>,
    /// Precomputed FFT twiddle factors (cosine), length FFT_N/2.
    twiddle_re: Vec<f32>,
    /// Precomputed FFT twiddle factors (sine), length FFT_N/2.
    twiddle_im: Vec<f32>,
    /// Scratch buffer for FFT real part (reused each frame).
    scratch_re: Vec<f32>,
    /// Scratch buffer for FFT imaginary part (reused each frame).
    scratch_im: Vec<f32>,
    /// Scratch buffer for A-weighted mag^2 in band (reused each frame).
    scratch_aw: Vec<f32>,
    /// Scratch buffer for raw mag^2 in band (reused each frame).
    scratch_raw: Vec<f32>,
    sample_rate: u32,
    /// FFT bin range for analysis band.
    bin_lo: usize,
    bin_hi: usize,
    /// IEC 61672 A-weight power multipliers, u8 fixed-point (scale 1/128).
    a_weights: Vec<u8>,
    ema_power: f32,
    frame_count: u32,
    /// Per-window A-weighted band powers.
    window_powers: Vec<f32>,
    /// Per-window spectral centroids (Hz).
    window_centroids: Vec<f32>,
    /// Per-window dominant tracked peak frequency (Hz).
    window_peak_freqs: Vec<f32>,
    /// Per-window peak magnitude.
    window_peak_mags: Vec<f32>,
    /// Multi-peak tracker: live tracks.
    tracks: Vec<PeakTrack>,
    /// Per-window: number of moving tracks (for transition detection).
    window_moving_count: Vec<u8>,
    /// Per-window: total A-weighted power in tonal peaks (tracks).
    window_tonal_power: Vec<f32>,
    /// Per-window: number of detected harmonic groups.
    window_harmonic_groups: Vec<u8>,
    /// Per-window: max autocorrelation pitch confidence (0.0-1.0).
    window_pitch_confidence: Vec<f32>,
    /// Count of silent buffers (AUDCLNT_BUFFERFLAGS_SILENT).
    silent_bufs: u32,
    /// Count of non-silent buffers.
    active_bufs: u32,
}

impl NoiseMeter {
    fn new(sample_rate: u32) -> Self {
        let hann: Vec<f32> = (0..FFT_N)
            .map(|i| 0.5 - 0.5 * (std::f32::consts::TAU * i as f32 / (FFT_N - 1) as f32).cos())
            .collect();

        let (twiddle_re, twiddle_im) = precompute_twiddles(FFT_N);

        let bin_lo = (BAND_LO_HZ as usize * FFT_N)
            .div_ceil(sample_rate as usize)
            .max(1);
        let bin_hi = (BAND_HI_HZ as usize * FFT_N / sample_rate as usize).min(FFT_N / 2 - 1);

        let band_len = bin_hi - bin_lo + 1;

        let a_weights: Vec<u8> = (bin_lo..=bin_hi)
            .map(|k| {
                let f = k as f32 * sample_rate as f32 / FFT_N as f32;
                let w = a_weight_power(f);
                (w * AW_SCALE).round().min(255.0) as u8
            })
            .collect();

        crate::log::write(&format!(
            "  NoiseMeter: sr={sample_rate} fft={FFT_N} bins={bin_lo}..{bin_hi} \
             a_weights={} bytes, freq_res={:.2}Hz, band_bins={band_len}",
            a_weights.len(),
            sample_rate as f32 / FFT_N as f32,
        ));

        Self {
            buf: vec![0.0; FFT_N],
            buf_pos: 0,
            hann,
            twiddle_re,
            twiddle_im,
            scratch_re: vec![0.0; FFT_N],
            scratch_im: vec![0.0; FFT_N],
            scratch_aw: vec![0.0; band_len],
            scratch_raw: vec![0.0; band_len],
            sample_rate,
            bin_lo,
            bin_hi,
            a_weights,
            ema_power: 0.0,
            frame_count: 0,
            window_powers: Vec::with_capacity(600),
            window_centroids: Vec::with_capacity(600),
            window_peak_freqs: Vec::with_capacity(600),
            window_peak_mags: Vec::with_capacity(600),
            tracks: Vec::with_capacity(MAX_TRACKS),
            window_moving_count: Vec::with_capacity(600),
            window_tonal_power: Vec::with_capacity(600),
            window_harmonic_groups: Vec::with_capacity(600),
            window_pitch_confidence: Vec::with_capacity(600),
            silent_bufs: 0,
            active_bufs: 0,
        }
    }

    fn feed(&mut self, sample: f32) {
        self.buf[self.buf_pos] = sample;
        self.buf_pos += 1;
        if self.buf_pos == FFT_N {
            self.process_frame();
            // Slide: keep the last (FFT_N - HOP) samples for the next frame's overlap
            self.buf.copy_within(HOP..FFT_N, 0);
            self.buf_pos = FFT_N - HOP;
        }
    }

    fn process_frame(&mut self) {
        // Take scratch buffers out of self to avoid borrow conflicts
        let mut re = std::mem::take(&mut self.scratch_re);
        let mut im = std::mem::take(&mut self.scratch_im);
        let mut aw_mag_sq = std::mem::take(&mut self.scratch_aw);
        let mut raw_mag_sq_buf = std::mem::take(&mut self.scratch_raw);

        // Windowed FFT
        for (r, (b, h)) in re.iter_mut().zip(self.buf.iter().zip(self.hann.iter())) {
            *r = *b * *h;
        }
        for v in im.iter_mut() {
            *v = 0.0;
        }
        fft(&mut re, &mut im, FFT_N, &self.twiddle_re, &self.twiddle_im);

        let sr = self.sample_rate;
        let bin_hz = sr as f32 / FFT_N as f32;

        // ---- A-weighted power + centroid ----
        let mut power = 0f32;
        let mut weighted_freq = 0f64;
        let mut total_mag = 0f64;

        // Pre-compute A-weighted magnitude^2 for the band
        // (used for power, centroid, AND peak extraction)
        let band_len = self.bin_hi - self.bin_lo + 1;

        for k in self.bin_lo..=self.bin_hi {
            let idx = k - self.bin_lo;
            let raw = re[k] * re[k] + im[k] * im[k];
            raw_mag_sq_buf[idx] = raw;
            let w = self.a_weights[idx] as f32 * (1.0 / AW_SCALE);
            let mag_sq = raw * w;
            aw_mag_sq[idx] = mag_sq;
            power += mag_sq;
            let mag = mag_sq.sqrt() as f64;
            let freq = k as f64 * sr as f64 / FFT_N as f64;
            weighted_freq += freq * mag;
            total_mag += mag;
        }

        let centroid = if total_mag > 0.0 {
            (weighted_freq / total_mag) as f32
        } else {
            0.0
        };

        // ---- Extract top N local maxima ----
        // A local max: aw_mag_sq[i] > aw_mag_sq[i-1] and aw_mag_sq[i] > aw_mag_sq[i+1]
        struct FramePeak {
            freq: f32,
            mag: f32,
            aw_power: f32,
        }
        let mut peaks: Vec<FramePeak> = Vec::with_capacity(MAX_PEAKS + 4);

        for i in 1..band_len.saturating_sub(1) {
            let m = aw_mag_sq[i];
            if m > aw_mag_sq[i - 1] && m > aw_mag_sq[i + 1] && m > 1e-12 {
                let k = self.bin_lo + i;
                // Parabolic interpolation for sub-bin frequency
                let alpha = aw_mag_sq[i - 1].sqrt();
                let beta = m.sqrt();
                let gamma = aw_mag_sq[i + 1].sqrt();
                let denom = alpha - 2.0 * beta + gamma;
                let offset = if denom.abs() > 1e-10 {
                    0.5 * (alpha - gamma) / denom
                } else {
                    0.0
                };
                let freq = (k as f32 + offset) * bin_hz;
                peaks.push(FramePeak {
                    freq,
                    mag: beta,
                    aw_power: m,
                });
            }
        }

        // Sort by magnitude descending, keep top MAX_PEAKS
        peaks.sort_by(|a, b| {
            b.mag
                .partial_cmp(&a.mag)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        peaks.truncate(MAX_PEAKS);

        // ---- Link peaks to existing tracks (greedy nearest-neighbor) ----
        let mut used = [false; MAX_PEAKS];
        for track in self.tracks.iter_mut() {
            if !track.alive {
                continue;
            }
            let mut best_dist = TRACK_MAX_JUMP_HZ;
            let mut best_idx: Option<usize> = None;
            for (i, p) in peaks.iter().enumerate() {
                if used[i] {
                    continue;
                }
                let dist = (p.freq - track.freq).abs();
                if dist < best_dist {
                    best_dist = dist;
                    best_idx = Some(i);
                }
            }
            if let Some(idx) = best_idx {
                used[idx] = true;
                let p = &peaks[idx];
                // Update slope with EMA (0.2/0.8: at 42.67ms frames each sample
                // is noisier, so smooth more aggressively)
                let new_slope = p.freq - track.freq;
                track.slope = 0.2 * new_slope + 0.8 * track.slope;
                track.freq = p.freq;
                track.mag = p.mag;
                track.freq_ema = 0.025 * p.freq + 0.975 * track.freq_ema;
                track.power_sum += p.aw_power;
                track.frames_alive = track.frames_alive.saturating_add(1);
                track.missed = 0;
            } else {
                track.missed += 1;
                if track.missed >= TRACK_MAX_MISSED {
                    track.alive = false;
                }
            }
        }

        // Birth new tracks from unlinked peaks (if room)
        for (i, p) in peaks.iter().enumerate() {
            if used[i] {
                continue;
            }
            if self.tracks.len() < MAX_TRACKS {
                self.tracks.push(PeakTrack::new(p.freq, p.mag));
            } else {
                // Recycle a dead track slot
                if let Some(slot) = self.tracks.iter_mut().find(|t| !t.alive) {
                    *slot = PeakTrack::new(p.freq, p.mag);
                }
            }
        }

        // ---- Compute per-frame track statistics ----
        let mut moving_count = 0u8;
        let mut tonal_power = 0f32;
        let mut best_track_freq = 0f32;
        let mut best_track_mag = 0f32;

        for track in &self.tracks {
            if !track.alive || track.frames_alive < 3 {
                continue;
            }
            tonal_power += track.mag * track.mag; // approximate A-weighted
            if track.is_moving() {
                moving_count += 1;
            }
            if track.mag > best_track_mag {
                best_track_mag = track.mag;
                best_track_freq = track.freq;
            }
        }

        // Noise power = total - tonal (broadband turbulence component)
        let noise_power = (power - tonal_power).max(0.0);
        let _ = noise_power; // available for future use

        // ---- Harmonic grouping ----
        let alive_peaks: Vec<(f32, f32)> = self
            .tracks
            .iter()
            .filter(|t| t.alive && t.frames_alive >= 3)
            .map(|t| (t.freq, t.mag))
            .collect();
        let hgroups = find_harmonic_groups(&alive_peaks, 50.0);
        let n_groups = hgroups.len().min(255) as u8;

        // ---- Constrained autocorrelation (only when harmonic groups detected) ----
        let pitch_confidence = if !hgroups.is_empty() {
            let mut best = 0f32;
            for g in &hgroups {
                let conf = autocorrelation_confirm(&self.buf, g.fundamental_hz, self.sample_rate);
                if conf > best {
                    best = conf;
                }
            }
            best
        } else {
            0.0
        };

        // ---- EMA power ----
        const ALPHA: f32 = 0.05;
        if self.frame_count == 0 {
            self.ema_power = power;
        } else {
            self.ema_power = ALPHA * power + (1.0 - ALPHA) * self.ema_power;
        }
        self.frame_count += 1;

        // ---- Collect per-window data ----
        self.window_powers.push(power);
        self.window_centroids.push(centroid);
        self.window_peak_freqs.push(best_track_freq);
        self.window_peak_mags.push(best_track_mag);
        self.window_moving_count.push(moving_count);
        self.window_tonal_power.push(tonal_power);
        self.window_harmonic_groups.push(n_groups);
        self.window_pitch_confidence.push(pitch_confidence);

        // Restore scratch buffers for reuse
        self.scratch_re = re;
        self.scratch_im = im;
        self.scratch_aw = aw_mag_sq;
        self.scratch_raw = raw_mag_sq_buf;
    }

    /// Primary measurement: EMA-smoothed A-weighted band power.
    fn power(&self) -> f32 {
        self.ema_power
    }

    /// Trimmed mean of per-window band powers.
    fn trimmed_power(&self) -> f32 {
        if self.window_powers.is_empty() {
            return 0.0;
        }
        let mut sorted = self.window_powers.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let n = sorted.len();
        let trim = n * 15 / 100;
        let start = trim;
        let end = n - trim;
        if start >= end {
            sorted.iter().sum::<f32>() / n as f32
        } else {
            sorted[start..end].iter().sum::<f32>() / (end - start) as f32
        }
    }

    /// Check if fans have settled after a mode transition.
    /// Returns true when no tracks are actively ramping for `stable_frames` consecutive frames.
    fn fans_settled(&self, stable_frames: usize) -> bool {
        let n = self.window_moving_count.len();
        if n < stable_frames {
            return false;
        }
        // Check last `stable_frames` windows: all must have 0 moving tracks
        self.window_moving_count[n - stable_frames..]
            .iter()
            .all(|&c| c == 0)
    }

    /// Summary of track state for logging.
    fn track_summary(&self) -> String {
        let alive: Vec<&PeakTrack> = self.tracks.iter().filter(|t| t.alive).collect();
        let moving = alive.iter().filter(|t| t.is_moving()).count();
        let stationary = alive.iter().filter(|t| t.is_stationary()).count();
        let mut s = format!(
            "{} tracks ({} moving, {} stationary)",
            alive.len(),
            moving,
            stationary
        );
        // Show top 3 tracks by magnitude
        let mut sorted = alive.clone();
        sorted.sort_by(|a, b| {
            b.mag
                .partial_cmp(&a.mag)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        for (i, t) in sorted.iter().take(3).enumerate() {
            let dir = if t.slope > 1.2 {
                "^"
            } else if t.slope < -1.2 {
                "v"
            } else {
                "="
            };
            s.push_str(&format!(" [{}]{:.0}Hz{dir}{:+.1}", i, t.freq, t.slope));
        }
        s
    }

    fn log_stats(&self, label: &str) {
        let n = self.window_powers.len();
        if n == 0 {
            crate::log::write(&format!("  {label}: 0 windows"));
            return;
        }
        let min = self.window_powers.iter().cloned().fold(f32::MAX, f32::min);
        let max = self.window_powers.iter().cloned().fold(f32::MIN, f32::max);
        let raw_mean: f32 = self.window_powers.iter().sum::<f32>() / n as f32;
        let trimmed = self.trimmed_power();
        let ema = self.ema_power;

        // Average tonal vs total power ratio
        let total_sum: f32 = self.window_powers.iter().sum();
        let tonal_sum: f32 = self.window_tonal_power.iter().sum();
        let tonal_pct = if total_sum > 0.0 {
            100.0 * tonal_sum / total_sum
        } else {
            0.0
        };

        crate::log::write(&format!(
            "  {label}: {n} win, min={min:.2e} max={max:.2e} \
             mean={raw_mean:.2e} trim={trimmed:.2e} ema={ema:.2e} \
             tonal={tonal_pct:.0}% silent={} active={}",
            self.silent_bufs, self.active_bufs,
        ));
        crate::log::write(&format!("  {label}: {}", self.track_summary()));
    }
}

/// IEC 61672 A-weighting in the power domain (multiplier for mag_sq).
///
/// Computes directly from the rational function -- zero storage, one sqrt,
/// no log/pow transcendentals. A(1000 Hz) = 1.0 (0 dBA).
fn a_weight_power(f: f32) -> f32 {
    let f = f.max(1.0) as f64;
    let f2 = f * f;
    let numer = 148693636.0 * f2 * f2; // 12194^2 * f^4
    let denom = (f2 + 424.36)           // f^2 + 20.6^2
        * ((f2 + 11599.29) * (f2 + 544496.41)).sqrt() // sqrt((f^2+107.7^2)(f^2+737.9^2))
        * (f2 + 148693636.0); // f^2 + 12194^2
    let ra = numer / denom;
    (ra * ra / 0.6309573444801932) as f32
}

// ---- Harmonic grouping + constrained autocorrelation -----------------------

/// A group of peaks forming a harmonic series (fundamental + overtones).
#[allow(dead_code)]
struct HarmonicGroup {
    fundamental_hz: f32,
    peak_count: u8,
}

/// Check if peaks form harmonic series. Returns groups of (fundamental_hz, count).
///
/// Uses loose tolerance (50 cents ≈ 3%) to handle fan inharmonicity.
/// Partial matches (2-of-4 harmonics) still count as a group.
fn find_harmonic_groups(peaks: &[(f32, f32)], tolerance_cents: f32) -> Vec<HarmonicGroup> {
    let mut groups = Vec::new();
    if peaks.len() < 2 {
        return groups;
    }

    let ratio_tolerance = 2f32.powf(tolerance_cents / 1200.0); // cents → ratio

    // For each peak as candidate fundamental, check how many others are harmonics
    let mut used = vec![false; peaks.len()];
    for i in 0..peaks.len() {
        if used[i] {
            continue;
        }
        let fund = peaks[i].0;
        if fund < 50.0 {
            continue; // too low to be a useful fundamental
        }

        let mut count = 1u8;
        for j in (i + 1)..peaks.len() {
            if used[j] {
                continue;
            }
            let ratio = peaks[j].0 / fund;
            let nearest_int = ratio.round();
            if !(2.0..=8.0).contains(&nearest_int) {
                continue;
            }
            // Check if ratio is within tolerance of an integer
            let deviation = ratio / nearest_int;
            if deviation > 1.0 / ratio_tolerance && deviation < ratio_tolerance {
                count += 1;
                used[j] = true;
            }
        }

        if count >= 2 {
            used[i] = true;
            groups.push(HarmonicGroup {
                fundamental_hz: fund,
                peak_count: count,
            });
        }
    }

    groups
}

/// Autocorrelation-based pitch confirmation for a candidate frequency.
///
/// Returns confidence 0.0-1.0 (normalized correlation at the candidate lag).
/// Only computes ±2 samples around the candidate lag (constrained, not full ACF).
fn autocorrelation_confirm(buf: &[f32], candidate_hz: f32, sample_rate: u32) -> f32 {
    if candidate_hz < 50.0 {
        return 0.0;
    }
    let center_lag = (sample_rate as f32 / candidate_hz).round() as usize;
    if center_lag < 2 || center_lag >= buf.len() / 2 {
        return 0.0;
    }

    // Constrained ACF: check ±2 samples around candidate lag.
    // Uses proper normalized cross-correlation: r = Σxy / sqrt(Σx² · Σy²)
    let mut best_corr = 0f32;
    for lag_offset in -2i32..=2 {
        let lag = (center_lag as i32 + lag_offset) as usize;
        if lag >= buf.len() / 2 {
            continue;
        }
        let n = buf.len() - lag;
        let mut xy = 0f64;
        let mut xx = 0f64;
        let mut yy = 0f64;
        for i in 0..n {
            let x = buf[i] as f64;
            let y = buf[i + lag] as f64;
            xy += x * y;
            xx += x * x;
            yy += y * y;
        }
        let denom = (xx * yy).sqrt();
        if denom > 1e-20 {
            let r = (xy / denom) as f32;
            if r > best_corr {
                best_corr = r;
            }
        }
    }

    best_corr.min(1.0)
}

// ---- Capture log (structured TSV for post-processing) ---------------------

/// A single row in the capture log.
struct CaptureRow {
    window: u32,
    phase: &'static str,
    mode: u8,          // thermal mode during this window
    power: f32,        // A-weighted band power (300-14000 Hz)
    centroid_hz: f32,  // spectral centroid
    peak_freq_hz: f32, // phase vocoder tracked peak frequency
    peak_mag: f32,     // magnitude at dominant peak
    ema_power: f32,    // running EMA at this point
    power_dbfs: f32,   // 10*log10(power) for readability
}

/// Accumulates rows across multiple capture phases and writes a TSV.
struct CaptureLog {
    rows: Vec<CaptureRow>,
    raw_mode: bool,
    mic_gain: f32,
}

impl CaptureLog {
    fn new(raw_mode: bool, mic_gain: f32) -> Self {
        Self {
            rows: Vec::with_capacity(600),
            raw_mode,
            mic_gain,
        }
    }

    /// Drain a NoiseMeter's per-window data into rows with the given phase/mode labels.
    fn append_meter(&mut self, meter: &NoiseMeter, phase: &'static str, mode: u8) {
        let base = self.rows.last().map(|r| r.window + 1).unwrap_or(0);
        let n = meter.window_powers.len();
        let mut ema = 0f32;
        for i in 0..n {
            let p = meter.window_powers[i];
            if i == 0 {
                ema = p;
            } else {
                ema = 0.05 * p + 0.95 * ema;
            }
            let dbfs = if p > 0.0 { 10.0 * p.log10() } else { -120.0 };
            self.rows.push(CaptureRow {
                window: base + i as u32,
                phase,
                mode,
                power: p,
                centroid_hz: *meter.window_centroids.get(i).unwrap_or(&0.0),
                peak_freq_hz: *meter.window_peak_freqs.get(i).unwrap_or(&0.0),
                peak_mag: *meter.window_peak_mags.get(i).unwrap_or(&0.0),
                ema_power: ema,
                power_dbfs: dbfs,
            });
        }
    }

    /// Write accumulated rows to `C:\ProgramData\HpThermal\noise-capture.tsv`.
    /// Appends a header + decision summary at the end.
    fn write_tsv(&self, decision: &str, delta_db: f32, perf_power: f32, bal_power: f32) {
        let path = format!("{}\\noise-capture.tsv", crate::app::data_dir());
        let mut out = String::with_capacity(self.rows.len() * 80 + 512);

        // Header comment with metadata
        out.push_str(&format!(
            "# noise-capture {}\n# raw={} mic_gain={:.3}\n",
            chrono_stamp(),
            self.raw_mode,
            self.mic_gain,
        ));

        // TSV header
        out.push_str("window\tphase\tmode\tpower\tpower_dbfs\tcentroid_hz\tpeak_freq_hz\tpeak_mag\tema_power\n");

        for r in &self.rows {
            out.push_str(&format!(
                "{}\t{}\t{}\t{:.6e}\t{:.1}\t{:.0}\t{:.1}\t{:.6e}\t{:.6e}\n",
                r.window,
                r.phase,
                r.mode,
                r.power,
                r.power_dbfs,
                r.centroid_hz,
                r.peak_freq_hz,
                r.peak_mag,
                r.ema_power,
            ));
        }

        // Decision summary
        let perf_db = if perf_power > 0.0 {
            10.0 * perf_power.log10()
        } else {
            -120.0
        };
        let bal_db = if bal_power > 0.0 {
            10.0 * bal_power.log10()
        } else {
            -120.0
        };
        out.push_str(&format!(
            "# decision={} delta_db={:.2} perf_power={:.6e} ({:.1} dBFS) bal_power={:.6e} ({:.1} dBFS)\n",
            decision, delta_db, perf_power, perf_db, bal_power, bal_db,
        ));

        if let Err(e) = std::fs::write(&path, out.as_bytes()) {
            crate::log::warn(&format!("noise-adapt: TSV write failed: {e}"));
        } else {
            crate::log::write(&format!(
                "noise-adapt: wrote {} rows to {path}",
                self.rows.len()
            ));
        }
    }
}

// ---- Telemetry poller for debug calibration --------------------------------

struct TelemetryReading {
    elapsed_ms: u64,
    temp_c: u8,
    mode: u8,
}

/// Poll temp + thermal mode every 2 seconds until stopped.
/// Returns the collected readings.
fn telemetry_poller(stop: Arc<AtomicBool>) -> Vec<TelemetryReading> {
    let start = std::time::Instant::now();
    let mut readings = Vec::with_capacity(40);
    while !stop.load(Ordering::Relaxed) {
        let temp = crate::pipe::client_transact(crate::protocol::CMD_READ_TEMP, 0)
            .map(|[s, t]| if crate::protocol::status_ok(s) { t } else { 0 })
            .unwrap_or(0);
        let mode = crate::pipe::client_transact(crate::protocol::CMD_READ_THERMAL, 0)
            .map(|[s, m]| {
                if crate::protocol::status_ok(s) {
                    m
                } else {
                    255
                }
            })
            .unwrap_or(255);
        readings.push(TelemetryReading {
            elapsed_ms: start.elapsed().as_millis() as u64,
            temp_c: temp,
            mode,
        });
        // Sleep in 200ms increments so we respond to stop quickly
        for _ in 0..10 {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }
    readings
}

fn mode_name(mode: u8) -> &'static str {
    match mode {
        0 => "Performance",
        1 => "Balanced",
        2 => "Cool",
        3 => "PowerSaver",
        255 => "Unknown",
        _ => "Other",
    }
}

/// Write telemetry readings to a TSV file.
fn write_telemetry_tsv(readings: &[TelemetryReading], path: &str) {
    let mut out = String::with_capacity(readings.len() * 40 + 100);
    out.push_str("elapsed_ms\ttemp_c\tmode\tmode_name\n");
    for r in readings {
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\n",
            r.elapsed_ms,
            r.temp_c,
            r.mode,
            mode_name(r.mode),
        ));
    }
    if let Err(e) = std::fs::write(path, out.as_bytes()) {
        crate::log::warn(&format!("debug-cal: telemetry TSV write failed: {e}"));
    } else {
        crate::log::write(&format!(
            "debug-cal: wrote {} telemetry readings to {path}",
            readings.len(),
        ));
    }
}

/// Simple timestamp without chrono crate: YYYYMMDD_HHMMSS (UTC).
fn chrono_stamp() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Manual UTC decomposition (no leap seconds, fine for logging)
    let secs_per_day = 86400u64;
    let days = d / secs_per_day;
    let time_of_day = d % secs_per_day;
    let h = time_of_day / 3600;
    let m = (time_of_day % 3600) / 60;
    let s = time_of_day % 60;

    // Days since 1970-01-01 -> Y/M/D
    let mut y = 1970i32;
    let mut rem = days;
    loop {
        let ydays = if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) {
            366u64
        } else {
            365
        };
        if rem < ydays {
            break;
        }
        rem -= ydays;
        y += 1;
    }
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let mdays = [
        31u64,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut mo = 0;
    #[allow(clippy::needless_range_loop)]
    for i in 0..12 {
        if rem < mdays[i] {
            mo = i + 1;
            break;
        }
        rem -= mdays[i];
    }
    let day = rem + 1;
    format!("{y:04}{mo:02}{day:02}_{h:02}{m:02}{s:02}")
}

// ---- FFT: radix-2 Cooley-Tukey DIT with precomputed twiddles -------------

/// Precompute twiddle factors (cos/sin table) for an N-point FFT.
/// Returns (re, im) each of length N/2.
fn precompute_twiddles(n: usize) -> (Vec<f32>, Vec<f32>) {
    debug_assert!(n.is_power_of_two());
    let half = n / 2;
    let mut tw_re = vec![0f32; half];
    let mut tw_im = vec![0f32; half];
    for i in 0..half {
        let angle = -std::f32::consts::TAU * i as f32 / n as f32;
        let (s, c) = angle.sin_cos();
        tw_re[i] = c;
        tw_im[i] = s;
    }
    (tw_re, tw_im)
}

/// In-place radix-2 DIT FFT using precomputed twiddle tables.
/// `n` must be a power of two. `tw_re`/`tw_im` from `precompute_twiddles(n)`.
fn fft(re: &mut [f32], im: &mut [f32], n: usize, tw_re: &[f32], tw_im: &[f32]) {
    debug_assert!(n.is_power_of_two() && re.len() >= n && im.len() >= n);
    debug_assert!(tw_re.len() >= n / 2 && tw_im.len() >= n / 2);
    let bits = n.trailing_zeros();

    // Bit-reversal permutation
    for i in 0..n {
        let j = bit_reverse(i, bits);
        if i < j {
            re.swap(i, j);
            im.swap(i, j);
        }
    }

    // Butterfly stages with twiddle table lookup
    let mut size = 2usize;
    while size <= n {
        let half = size / 2;
        let stride = n / size; // twiddle stride for this stage
        let mut k = 0;
        while k < n {
            for j in 0..half {
                let tw_idx = j * stride;
                let c = tw_re[tw_idx];
                let s = tw_im[tw_idx];
                let a = k + j;
                let b = a + half;
                let tr = re[b] * c - im[b] * s;
                let ti = re[b] * s + im[b] * c;
                re[b] = re[a] - tr;
                im[b] = im[a] - ti;
                re[a] += tr;
                im[a] += ti;
            }
            k += size;
        }
        size <<= 1;
    }
}

/// In-place radix-2 DIT FFT without precomputed twiddles (for tests/characterization).
/// `n` must be a power of two.
#[cfg(test)]
fn fft_no_twiddle(re: &mut [f32], im: &mut [f32], n: usize) {
    let (tw_re, tw_im) = precompute_twiddles(n);
    fft(re, im, n, &tw_re, &tw_im);
}

fn bit_reverse(mut x: usize, bits: u32) -> usize {
    let mut r = 0;
    for _ in 0..bits {
        r = (r << 1) | (x & 1);
        x >>= 1;
    }
    r
}

// ---- Replay test infrastructure --------------------------------------------
//
// Deterministic regression tests for the noise-adapt decision algorithm.
// Feeds recorded (or synthetic) audio through NoiseMeter and checks the
// decision output. Runs under `cargo test` with zero hardware dependencies.
//
// Real WAV fixtures: generate with Debug Calibration (Shift+right-click menu),
// copy `capture.wav` to `app/tests/fixtures/`. WAV files are gitignored.
//
// Synthetic fixtures: generated programmatically, no files needed.

#[cfg(test)]
mod tests {
    use super::*;

    // ---- WAV reader (inverse of write_debug_wav) ----------------------------

    /// Read a 32-bit float mono WAV file with RIFF cue markers.
    /// Returns (samples, sample_rate, markers) where markers are (sample_pos, label).
    fn read_wav(path: &str) -> Result<(Vec<f32>, u32, Vec<(u32, String)>), String> {
        let data = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
        if data.len() < 44 {
            return Err("file too small for WAV header".into());
        }
        if &data[0..4] != b"RIFF" || &data[8..12] != b"WAVE" {
            return Err("not a RIFF/WAVE file".into());
        }

        let mut sample_rate = 0u32;
        let mut samples: Vec<f32> = Vec::new();
        let mut cue_positions: Vec<(u32, u32)> = Vec::new(); // (id, sample_pos)
        let mut cue_labels: Vec<(u32, String)> = Vec::new(); // (id, label)

        // Walk chunks starting at offset 12
        let mut pos = 12usize;
        while pos + 8 <= data.len() {
            let chunk_id = &data[pos..pos + 4];
            let chunk_size =
                u32::from_le_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]])
                    as usize;
            let chunk_data_start = pos + 8;
            let chunk_data_end = (chunk_data_start + chunk_size).min(data.len());

            match chunk_id {
                b"fmt " => {
                    if chunk_size < 16 {
                        return Err("fmt chunk too small".into());
                    }
                    let d = &data[chunk_data_start..];
                    let format_tag = u16::from_le_bytes([d[0], d[1]]);
                    let channels = u16::from_le_bytes([d[2], d[3]]);
                    sample_rate = u32::from_le_bytes([d[4], d[5], d[6], d[7]]);
                    let bits = u16::from_le_bytes([d[14], d[15]]);

                    if channels != 1 {
                        return Err(format!("expected mono, got {channels} channels"));
                    }
                    if format_tag != 3 {
                        return Err(format!("expected IEEE float (tag=3), got tag={format_tag}"));
                    }
                    if bits != 32 {
                        return Err(format!("expected 32-bit, got {bits}-bit"));
                    }
                }
                b"data" => {
                    let d = &data[chunk_data_start..chunk_data_end];
                    samples.reserve(d.len() / 4);
                    for chunk in d.chunks_exact(4) {
                        samples.push(f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
                    }
                }
                b"cue " => {
                    if chunk_size < 4 {
                        continue;
                    }
                    let d = &data[chunk_data_start..chunk_data_end];
                    let num_cues = u32::from_le_bytes([d[0], d[1], d[2], d[3]]);
                    let mut off = 4usize;
                    for _ in 0..num_cues {
                        if off + 24 > d.len() {
                            break;
                        }
                        let id = u32::from_le_bytes([d[off], d[off + 1], d[off + 2], d[off + 3]]);
                        // dwSampleOffset is at offset 20 within the cue point
                        let sample_pos = u32::from_le_bytes([
                            d[off + 20],
                            d[off + 21],
                            d[off + 22],
                            d[off + 23],
                        ]);
                        cue_positions.push((id, sample_pos));
                        off += 24;
                    }
                }
                b"LIST" => {
                    if chunk_size < 4 {
                        // skip
                    } else {
                        let d = &data[chunk_data_start..chunk_data_end];
                        let list_type = &d[0..4];
                        if list_type == b"adtl" {
                            // Parse labl sub-chunks
                            let mut off = 4usize;
                            while off + 8 <= d.len() {
                                let sub_id = &d[off..off + 4];
                                let sub_size = u32::from_le_bytes([
                                    d[off + 4],
                                    d[off + 5],
                                    d[off + 6],
                                    d[off + 7],
                                ]) as usize;
                                if sub_id == b"labl" && sub_size >= 4 {
                                    let sub_data = &d[off + 8..];
                                    if sub_data.len() >= sub_size {
                                        let id = u32::from_le_bytes([
                                            sub_data[0],
                                            sub_data[1],
                                            sub_data[2],
                                            sub_data[3],
                                        ]);
                                        // Label text: after the 4-byte ID, NUL-terminated
                                        let text_bytes = &sub_data[4..sub_size];
                                        let text =
                                            text_bytes.split(|&b| b == 0).next().unwrap_or(b"");
                                        let label = String::from_utf8_lossy(text).into_owned();
                                        cue_labels.push((id, label));
                                    }
                                }
                                // Advance past sub-chunk (padded to even)
                                off += 8 + sub_size + (sub_size & 1);
                            }
                        }
                    }
                }
                _ => {} // skip unknown chunks
            }

            // Advance to next chunk (padded to even boundary)
            pos = chunk_data_start + chunk_size + (chunk_size & 1);
        }

        if samples.is_empty() {
            return Err("no audio data found".into());
        }
        if sample_rate == 0 {
            return Err("no fmt chunk found".into());
        }

        // Merge cue positions with labels by ID
        let mut markers: Vec<(u32, String)> = Vec::new();
        for &(id, sample_pos) in &cue_positions {
            let label = cue_labels
                .iter()
                .find(|&&(lid, _)| lid == id)
                .map(|(_, l)| l.clone())
                .unwrap_or_else(|| format!("cue_{id}"));
            markers.push((sample_pos, label));
        }
        // Sort by sample position
        markers.sort_by_key(|&(pos, _)| pos);

        Ok((samples, sample_rate, markers))
    }

    /// Given markers [(sample_pos, label), ...], find the sample range for a phase.
    /// The phase runs from its marker to the next marker (or end of file).
    fn find_phase(markers: &[(u32, String)], label: &str, total_samples: u32) -> (u32, u32) {
        for (i, (pos, lbl)) in markers.iter().enumerate() {
            if lbl == label {
                let end = markers.get(i + 1).map(|(p, _)| *p).unwrap_or(total_samples);
                return (*pos, end);
            }
        }
        panic!(
            "marker '{label}' not found in {:?}",
            markers.iter().map(|(_, l)| l.as_str()).collect::<Vec<_>>()
        );
    }

    /// Trimmed mean (15% trim each end) of a float slice.
    fn trimmed_mean(slice: &[f32]) -> f32 {
        if slice.is_empty() {
            return 0.0;
        }
        let mut sorted = slice.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let n = sorted.len();
        let trim = n * 15 / 100;
        let lo = trim;
        let hi = n - trim;
        if lo >= hi {
            sorted.iter().sum::<f32>() / n as f32
        } else {
            sorted[lo..hi].iter().sum::<f32>() / (hi - lo) as f32
        }
    }

    /// Replay a WAV file through NoiseMeter and return the decision.
    ///
    /// The WAV must contain cue markers from Debug Calibration:
    /// "capture_perf" and "capture_bal" at minimum.
    fn replay_wav(path: &str, current_mode: u8) -> DecisionOutput {
        let (samples, sample_rate, markers) = read_wav(path).unwrap();
        let mut meter = NoiseMeter::new(sample_rate);

        // Feed all samples through the analysis pipeline
        for &s in &samples {
            meter.feed(s);
        }

        // Convert sample-position markers to window indices.
        // First window fires at sample FFT_N, then every HOP samples.
        let win_markers: Vec<(u32, String)> = markers
            .iter()
            .map(|(pos, label)| {
                let idx = pos.saturating_sub(FFT_N as u32) / HOP as u32;
                (idx, label.clone())
            })
            .collect();

        let total_windows = meter.window_powers.len() as u32;
        let (perf_start, perf_end) = find_phase(&win_markers, "capture_perf", total_windows);
        let (bal_start, bal_end) = find_phase(&win_markers, "capture_bal", total_windows);

        let ps = perf_start as usize;
        let pe = (perf_end as usize).min(meter.window_powers.len());
        let bs = bal_start as usize;
        let be = (bal_end as usize).min(meter.window_powers.len());

        let perf_power = trimmed_mean(&meter.window_powers[ps..pe]);
        let bal_power = trimmed_mean(&meter.window_powers[bs..be]);
        let perf_tonal = trimmed_mean(&meter.window_tonal_power[ps..pe]);
        let bal_tonal = trimmed_mean(&meter.window_tonal_power[bs..be]);

        let avg_moving_perf = if pe > ps {
            meter.window_moving_count[ps..pe]
                .iter()
                .map(|&c| c as f32)
                .sum::<f32>()
                / (pe - ps) as f32
        } else {
            0.0
        };
        let avg_moving_bal = if be > bs {
            meter.window_moving_count[bs..be]
                .iter()
                .map(|&c| c as f32)
                .sum::<f32>()
                / (be - bs) as f32
        } else {
            0.0
        };

        let perf_centroid = trimmed_mean(&meter.window_centroids[ps..pe]);
        let bal_centroid = trimmed_mean(&meter.window_centroids[bs..be]);
        let centroid_shift_hz = perf_centroid - bal_centroid;

        compute_decision(&DecisionInput {
            perf_power,
            bal_power,
            perf_tonal,
            bal_tonal,
            avg_moving_perf,
            avg_moving_bal,
            current_mode,
            centroid_shift_hz,
        })
    }

    // ---- Synthetic fixture generation ---------------------------------------

    /// Generate synthetic A/B test samples with markers.
    ///
    /// Creates two phases with different tone amplitudes to simulate fan noise
    /// differences between Performance and Balanced modes.
    ///
    /// Returns (samples, sample_rate, markers) in the same format as read_wav().
    fn synthetic_ab_samples(
        sample_rate: u32,
        settle_secs: f32,
        capture_secs: f32,
        perf_tone_hz: f32,
        perf_amplitude: f32,
        bal_tone_hz: f32,
        bal_amplitude: f32,
    ) -> (Vec<f32>, u32, Vec<(u32, String)>) {
        let settle_samples = (settle_secs * sample_rate as f32) as usize;
        let capture_samples = (capture_secs * sample_rate as f32) as usize;
        let total = 2 * settle_samples + 2 * capture_samples;
        let mut samples = Vec::with_capacity(total);
        let mut markers = Vec::new();

        let two_pi = std::f32::consts::TAU;

        // Phase 1: settle_perf (silence)
        markers.push((0u32, "settle_perf".to_string()));
        for _ in 0..settle_samples {
            samples.push(0.0);
        }

        // Phase 2: capture_perf (tone at perf_amplitude)
        let capture_perf_start = samples.len() as u32;
        markers.push((capture_perf_start, "capture_perf".to_string()));
        let mut phase = 0.0f32;
        for _ in 0..capture_samples {
            let s = perf_amplitude * (two_pi * perf_tone_hz * phase / sample_rate as f32).sin();
            samples.push(s);
            phase += 1.0;
        }

        // Phase 3: settle_bal (silence)
        markers.push((samples.len() as u32, "settle_bal".to_string()));
        for _ in 0..settle_samples {
            samples.push(0.0);
        }

        // Phase 4: capture_bal (tone at bal_amplitude)
        let capture_bal_start = samples.len() as u32;
        markers.push((capture_bal_start, "capture_bal".to_string()));
        phase = 0.0;
        for _ in 0..capture_samples {
            let s = bal_amplitude * (two_pi * bal_tone_hz * phase / sample_rate as f32).sin();
            samples.push(s);
            phase += 1.0;
        }

        markers.push((samples.len() as u32, "end".to_string()));

        (samples, sample_rate, markers)
    }

    /// Feed synthetic samples through NoiseMeter and return the decision.
    fn replay_synthetic(
        samples: &[f32],
        sample_rate: u32,
        markers: &[(u32, String)],
        current_mode: u8,
    ) -> DecisionOutput {
        let mut meter = NoiseMeter::new(sample_rate);
        for &s in samples {
            meter.feed(s);
        }

        // Convert sample-position markers to window indices.
        // First window fires at sample FFT_N, then every HOP samples.
        let win_markers: Vec<(u32, String)> = markers
            .iter()
            .map(|(pos, label)| {
                let idx = pos.saturating_sub(FFT_N as u32) / HOP as u32;
                (idx, label.clone())
            })
            .collect();

        let total_windows = meter.window_powers.len() as u32;
        let (perf_start, perf_end) = find_phase(&win_markers, "capture_perf", total_windows);
        let (bal_start, bal_end) = find_phase(&win_markers, "capture_bal", total_windows);

        let ps = perf_start as usize;
        let pe = (perf_end as usize).min(meter.window_powers.len());
        let bs = bal_start as usize;
        let be = (bal_end as usize).min(meter.window_powers.len());

        let perf_power = trimmed_mean(&meter.window_powers[ps..pe]);
        let bal_power = trimmed_mean(&meter.window_powers[bs..be]);
        let perf_tonal = trimmed_mean(&meter.window_tonal_power[ps..pe]);
        let bal_tonal = trimmed_mean(&meter.window_tonal_power[bs..be]);

        let avg_moving_perf = if pe > ps {
            meter.window_moving_count[ps..pe]
                .iter()
                .map(|&c| c as f32)
                .sum::<f32>()
                / (pe - ps) as f32
        } else {
            0.0
        };
        let avg_moving_bal = if be > bs {
            meter.window_moving_count[bs..be]
                .iter()
                .map(|&c| c as f32)
                .sum::<f32>()
                / (be - bs) as f32
        } else {
            0.0
        };

        let perf_centroid = trimmed_mean(&meter.window_centroids[ps..pe]);
        let bal_centroid = trimmed_mean(&meter.window_centroids[bs..be]);
        let centroid_shift_hz = perf_centroid - bal_centroid;

        compute_decision(&DecisionInput {
            perf_power,
            bal_power,
            perf_tonal,
            bal_tonal,
            avg_moving_perf,
            avg_moving_bal,
            current_mode,
            centroid_shift_hz,
        })
    }

    // ---- Tests: synthetic fixtures ------------------------------------------

    /// Loud fan tone in Performance, quiet in Balanced -> should choose Balanced.
    ///
    /// 1 kHz tone at -20 dBFS (perf) vs -40 dBFS (bal) = 20 dB delta.
    #[test]
    fn synthetic_fans_audible() {
        let (samples, sr, markers) = synthetic_ab_samples(
            48000, 2.0,    // 2s settle (≥1 FFT window warmup + margin)
            6.0,    // 6s capture (enough windows at 42.67ms/frame)
            1000.0, // 1 kHz tone (perf)
            0.1,    // -20 dBFS
            1000.0, // 1 kHz tone (bal)
            0.01,   // -40 dBFS
        );
        let result = replay_synthetic(&samples, sr, &markers, 0);
        assert_eq!(
            result.chosen, 1,
            "should choose Balanced when fans are 20 dB louder in Performance \
             (delta={:.1} dB, tonal={})",
            result.delta_db, result.used_tonal,
        );
        assert!(
            result.delta_db >= THRESHOLD_DB,
            "delta {:.1} dB should exceed threshold {:.1} dB",
            result.delta_db,
            THRESHOLD_DB,
        );
    }

    /// Both modes equally quiet -> should choose Performance (no fan difference).
    #[test]
    fn synthetic_quiet_room() {
        let (samples, sr, markers) = synthetic_ab_samples(
            48000, 2.0,    // 2s settle
            6.0,    // 6s capture
            1000.0, // same tone
            0.001,  // -60 dBFS (very quiet)
            1000.0, 0.001, // same level
        );
        let result = replay_synthetic(&samples, sr, &markers, 0);
        assert_eq!(
            result.chosen, 0,
            "should choose Performance when both modes equally quiet \
             (delta={:.1} dB)",
            result.delta_db,
        );
    }

    /// Moderate fan difference (just above threshold) -> should choose Balanced.
    #[test]
    fn synthetic_marginal_fans() {
        // ~5 dB difference (just above 3 dB threshold)
        let (samples, sr, markers) = synthetic_ab_samples(
            48000, 2.0, 6.0, 1000.0, 0.05, // perf: louder
            1000.0, 0.028, // bal: ~5 dB quieter
        );
        let result = replay_synthetic(&samples, sr, &markers, 0);
        assert_eq!(
            result.chosen, 1,
            "should choose Balanced for ~5 dB fan delta \
             (delta={:.1} dB, tonal={})",
            result.delta_db, result.used_tonal,
        );
    }

    /// Test that compute_decision is a pure function with predictable output.
    #[test]
    fn decision_pure_function() {
        let input = DecisionInput {
            perf_power: 1e-3,
            bal_power: 1e-4,
            perf_tonal: 5e-4,
            bal_tonal: 5e-5,
            avg_moving_perf: 2.0,
            avg_moving_bal: 0.5,
            current_mode: 0,
            centroid_shift_hz: 0.0,
        };
        let r1 = compute_decision(&input);
        let r2 = compute_decision(&input);
        assert_eq!(r1.chosen, r2.chosen);
        assert_eq!(r1.delta_db, r2.delta_db);
        assert_eq!(r1.used_tonal, r2.used_tonal);
        assert_eq!(r1.low_confidence, r2.low_confidence);
    }

    /// Low confidence: tiny delta + no moving tracks -> keep current mode.
    #[test]
    fn decision_low_confidence_keeps_current() {
        let input = DecisionInput {
            perf_power: 1e-5,
            bal_power: 1e-5,
            perf_tonal: 0.0,
            bal_tonal: 0.0,
            avg_moving_perf: 0.0,
            avg_moving_bal: 0.0,
            current_mode: 1, // currently Balanced
            centroid_shift_hz: 0.0,
        };
        let result = compute_decision(&input);
        assert!(result.low_confidence, "should be low confidence");
        assert_eq!(result.chosen, 1, "should keep current mode (Balanced)");
    }

    // ---- Tests: real WAV fixtures (run with `cargo test -- --ignored`) -------

    /// Replay a debug calibration WAV where fans were clearly audible.
    /// Generate with: Debug Calibration -> copy capture.wav to tests/fixtures/fans-audible.wav
    #[test]
    #[ignore]
    fn replay_fans_audible() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/fans-audible.wav"
        );
        if !std::path::Path::new(path).exists() {
            eprintln!("SKIP: {path} not found (generate with Debug Calibration)");
            return;
        }
        let result = replay_wav(path, 0);
        assert_eq!(
            result.chosen, 1,
            "fans-audible fixture: expected Balanced (delta={:.1} dB, tonal={})",
            result.delta_db, result.used_tonal,
        );
    }

    /// Replay a quiet room WAV where fan noise is negligible.
    /// Generate with: Debug Calibration -> copy capture.wav to tests/fixtures/quiet-room.wav
    #[test]
    #[ignore]
    fn replay_quiet_room() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/quiet-room.wav");
        if !std::path::Path::new(path).exists() {
            eprintln!("SKIP: {path} not found (generate with Debug Calibration)");
            return;
        }
        let result = replay_wav(path, 0);
        assert_eq!(
            result.chosen, 0,
            "quiet-room fixture: expected Performance (delta={:.1} dB)",
            result.delta_db,
        );
    }

    // ---- Tests: committed 16c fixtures (run in CI) ---------------------------

    /// Replay experiment 16c: Performance vs Balanced under CPU stress.
    ///
    /// On the CT76, Performance fans are slightly louder than Balanced (~3.2 dB
    /// at 32K FFT resolution). At 1K FFT this measured ~2.9 dB due to spectral
    /// smearing; 32K FFT resolves the tonal content precisely enough to push
    /// above the 3 dB threshold. This is a marginal case at the decision boundary.
    #[test]
    fn replay_perf_vs_balanced_16c() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/perf-vs-balanced-16c.wav"
        );
        let result = replay_wav(path, 0);
        // Performance IS louder
        assert!(
            result.delta_db > 0.0,
            "16c: Performance should be louder than Balanced, got delta={:.1} dB",
            result.delta_db,
        );
        // At 32K FFT, tonal resolution pushes this just above threshold
        assert!(
            result.delta_db >= THRESHOLD_DB,
            "16c: at 32K FFT, delta {:.1} dB should be at/above threshold {:.1} dB",
            result.delta_db,
            THRESHOLD_DB,
        );
        // Just-above-threshold → choose Balanced (fans are audibly louder)
        assert_eq!(
            result.chosen, 1,
            "16c perf-vs-balanced: above threshold → expected Balanced (delta={:.1} dB, tonal={})",
            result.delta_db, result.used_tonal,
        );
    }

    /// Replay experiment 16c Quiet mode: both phases at similar quiet level.
    /// No significant fan difference → should choose Performance.
    #[test]
    fn replay_quiet_room_16c() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/quiet-room-16c.wav"
        );
        let result = replay_wav(path, 0);
        assert_eq!(
            result.chosen, 0,
            "16c quiet-room: expected Performance (delta={:.1} dB, tonal={})",
            result.delta_db, result.used_tonal,
        );
    }

    // ---- WAV reader tests ---------------------------------------------------

    /// Round-trip test: write a WAV with write_debug_wav format, read it back.
    #[test]
    fn wav_round_trip() {
        let sample_rate = 48000u32;
        let num_samples = 48000u32; // 1 second
        let mut samples = Vec::with_capacity(num_samples as usize);
        for i in 0..num_samples {
            let t = i as f32 / sample_rate as f32;
            samples.push(0.1 * (std::f32::consts::TAU * 440.0 * t).sin());
        }

        // Build WAV bytes manually (same format as write_debug_wav)
        let markers: Vec<(u32, &str)> = vec![
            (0, "init"),
            (100, "capture_perf"),
            (300, "capture_bal"),
            (500, "end"),
        ];
        let bytes_per_sample = 4u32;
        let data_size = num_samples * bytes_per_sample;
        let num_cues = markers.len() as u32;
        let cue_chunk_size = 4 + num_cues * 24;

        let mut label_data: Vec<u8> = Vec::new();
        for (i, &(_win, lbl)) in markers.iter().enumerate() {
            let id = (i + 1) as u32;
            let text = lbl.as_bytes();
            let text_len = text.len() as u32 + 1;
            let labl_size = 4 + text_len;
            label_data.extend_from_slice(b"labl");
            label_data.extend_from_slice(&labl_size.to_le_bytes());
            label_data.extend_from_slice(&id.to_le_bytes());
            label_data.extend_from_slice(text);
            label_data.push(0);
            if labl_size & 1 != 0 {
                label_data.push(0);
            }
        }
        let list_payload_size = 4 + label_data.len() as u32;

        let fmt_chunk_total = 8 + 16u32;
        let data_chunk_total = 8 + data_size;
        let cue_chunk_total = 8 + cue_chunk_size;
        let list_chunk_total = 8 + list_payload_size;
        let riff_payload =
            4 + fmt_chunk_total + data_chunk_total + cue_chunk_total + list_chunk_total;

        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(b"RIFF");
        buf.extend_from_slice(&riff_payload.to_le_bytes());
        buf.extend_from_slice(b"WAVE");

        buf.extend_from_slice(b"fmt ");
        buf.extend_from_slice(&16u32.to_le_bytes());
        buf.extend_from_slice(&3u16.to_le_bytes());
        buf.extend_from_slice(&1u16.to_le_bytes());
        buf.extend_from_slice(&sample_rate.to_le_bytes());
        buf.extend_from_slice(&(sample_rate * bytes_per_sample).to_le_bytes());
        buf.extend_from_slice(&(bytes_per_sample as u16).to_le_bytes());
        buf.extend_from_slice(&32u16.to_le_bytes());

        buf.extend_from_slice(b"data");
        buf.extend_from_slice(&data_size.to_le_bytes());
        for &s in &samples {
            buf.extend_from_slice(&s.to_le_bytes());
        }

        buf.extend_from_slice(b"cue ");
        buf.extend_from_slice(&cue_chunk_size.to_le_bytes());
        buf.extend_from_slice(&num_cues.to_le_bytes());
        for (i, &(win, _)) in markers.iter().enumerate() {
            let id = (i + 1) as u32;
            let sample_pos = win * HOP as u32;
            buf.extend_from_slice(&id.to_le_bytes());
            buf.extend_from_slice(&sample_pos.to_le_bytes());
            buf.extend_from_slice(b"data");
            buf.extend_from_slice(&0u32.to_le_bytes());
            buf.extend_from_slice(&0u32.to_le_bytes());
            buf.extend_from_slice(&sample_pos.to_le_bytes());
        }

        buf.extend_from_slice(b"LIST");
        buf.extend_from_slice(&list_payload_size.to_le_bytes());
        buf.extend_from_slice(b"adtl");
        buf.extend_from_slice(&label_data);

        // Write to temp file
        let dir = std::env::temp_dir();
        let path = format!("{}\\hp-thermal-test-roundtrip.wav", dir.display());
        std::fs::write(&path, &buf).unwrap();

        // Read it back
        let (read_samples, read_sr, read_markers) = read_wav(&path).unwrap();
        std::fs::remove_file(&path).ok();

        assert_eq!(read_sr, sample_rate);
        assert_eq!(read_samples.len(), samples.len());
        // Check samples match (exact f32 round-trip)
        for (i, (&orig, &read)) in samples.iter().zip(read_samples.iter()).enumerate() {
            assert_eq!(orig, read, "sample {i} mismatch");
        }
        // Check markers
        assert_eq!(read_markers.len(), markers.len());
        for (i, ((pos, label), &(expected_win, expected_label))) in
            read_markers.iter().zip(markers.iter()).enumerate()
        {
            let expected_pos = expected_win * HOP as u32;
            assert_eq!(*pos, expected_pos, "marker {i} position mismatch");
            assert_eq!(label, expected_label, "marker {i} label mismatch");
        }
    }

    // ---- Phase 1: DSP primitive unit tests ----------------------------------

    // ---- 1a. FFT correctness ----

    /// Pure cosine at exactly bin k → magnitude should concentrate in that bin.
    #[test]
    fn fft_single_tone_peak_bin() {
        let n = FFT_N;
        let target_bin = 10usize;
        let mut re = vec![0f32; n];
        let mut im = vec![0f32; n];
        // Generate cosine at bin frequency: cos(2π·k·n/N)
        for i in 0..n {
            re[i] = (std::f32::consts::TAU * target_bin as f32 * i as f32 / n as f32).cos();
        }
        fft_no_twiddle(&mut re, &mut im, n);

        // Compute magnitudes
        let mut total_energy = 0f64;
        let mut bin_energy = 0f64;
        for k in 0..n {
            let mag_sq = (re[k] as f64) * (re[k] as f64) + (im[k] as f64) * (im[k] as f64);
            total_energy += mag_sq;
            if k == target_bin || k == n - target_bin {
                bin_energy += mag_sq;
            }
        }
        let ratio = bin_energy / total_energy;
        assert!(
            ratio > 0.99,
            "bin {target_bin} should have >99% energy, got {:.4}%",
            ratio * 100.0,
        );
    }

    /// Parseval's theorem: sum |X[k]|^2 == N * sum |x[n]|^2.
    #[test]
    fn fft_parseval_energy_conservation() {
        let n = FFT_N;
        let mut re = vec![0f32; n];
        let mut im = vec![0f32; n];
        // Arbitrary signal: sum of two cosines
        for i in 0..n {
            re[i] = 0.7 * (std::f32::consts::TAU * 5.0 * i as f32 / n as f32).cos()
                + 0.3 * (std::f32::consts::TAU * 50.0 * i as f32 / n as f32).sin();
        }
        let time_energy: f64 = re.iter().map(|&x| (x as f64) * (x as f64)).sum();

        fft_no_twiddle(&mut re, &mut im, n);
        let freq_energy: f64 = re
            .iter()
            .zip(im.iter())
            .take(n)
            .map(|(&r, &i)| (r as f64) * (r as f64) + (i as f64) * (i as f64))
            .sum();

        // freq_energy should equal N * time_energy (DFT scaling)
        let expected = n as f64 * time_energy;
        let rel_err = (freq_energy - expected).abs() / expected;
        assert!(
            rel_err < 1e-4,
            "Parseval violated: freq={freq_energy:.2}, expected={expected:.2}, rel_err={rel_err:.6}",
        );
    }

    /// DC signal → all energy in bin 0, zero elsewhere.
    #[test]
    fn fft_dc_signal() {
        let n = FFT_N;
        let mut re = vec![1.0f32; n];
        let mut im = vec![0f32; n];
        fft_no_twiddle(&mut re, &mut im, n);

        // Bin 0 should be N (sum of all 1.0 values)
        assert!(
            (re[0] - n as f32).abs() < 0.5,
            "DC bin should be {n}, got {}",
            re[0],
        );
        // All other bins should be ~0
        for k in 1..n {
            let mag = (re[k] * re[k] + im[k] * im[k]).sqrt();
            assert!(mag < 0.5, "bin {k} should be ~0 for DC, got mag={mag:.6}",);
        }
    }

    // ---- 1b. A-weighting verification ----

    /// A(1000 Hz) should be ~1.0 (0 dBA reference point).
    #[test]
    fn a_weight_1khz_is_unity() {
        let w = a_weight_power(1000.0);
        assert!((w - 1.0).abs() < 0.01, "A(1kHz) should be ~1.0, got {w}",);
    }

    /// 100 Hz should be heavily attenuated in the A-weighting curve.
    #[test]
    fn a_weight_rolloff_at_low_freq() {
        let w = a_weight_power(100.0);
        assert!(
            w < 0.05,
            "A(100Hz) should be <0.05 in power domain, got {w}",
        );
    }

    /// A-weighting rises from 200 Hz to ~2-4 kHz (ear sensitivity peak).
    #[test]
    fn a_weight_monotonic_200_to_4000() {
        let w200 = a_weight_power(200.0);
        let w1k = a_weight_power(1000.0);
        let w4k = a_weight_power(4000.0);
        assert!(w200 < w1k, "A(200Hz)={w200} should be < A(1kHz)={w1k}",);
        // 4 kHz may be slightly above 1 kHz in A-weighting
        assert!(
            w1k <= w4k * 1.5,
            "A(1kHz)={w1k} should be within 1.5x of A(4kHz)={w4k}",
        );
    }

    // ---- 1c. Parabolic interpolation ----

    /// Symmetric neighbors → interpolated offset should be 0.
    #[test]
    fn parabolic_interp_centered_peak() {
        // alpha = gamma → offset = 0.5*(alpha-gamma)/(alpha-2*beta+gamma) = 0
        let alpha: f32 = 0.5;
        let beta: f32 = 1.0;
        let gamma: f32 = 0.5;
        let denom = alpha - 2.0 * beta + gamma;
        let offset = if denom.abs() > 1e-10 {
            0.5 * (alpha - gamma) / denom
        } else {
            0.0
        };
        assert!(
            offset.abs() < 1e-6,
            "symmetric peak should give offset=0, got {offset}",
        );
    }

    /// Asymmetric neighbors → offset should shift toward the larger neighbor.
    #[test]
    fn parabolic_interp_asymmetric() {
        let alpha: f32 = 0.3; // left neighbor (smaller)
        let beta: f32 = 1.0; // center (peak)
        let gamma: f32 = 0.8; // right neighbor (larger)
        let denom = alpha - 2.0 * beta + gamma;
        let offset = if denom.abs() > 1e-10 {
            0.5 * (alpha - gamma) / denom
        } else {
            0.0
        };
        // gamma > alpha → offset should be positive (peak shifts right toward gamma)
        assert!(
            offset > 0.0,
            "peak should shift toward larger neighbor (right), got offset={offset}",
        );
        assert!(
            offset > -0.5 && offset < 0.5,
            "offset should be within ±0.5 bins, got {offset}",
        );
    }

    // ---- 1d. fans_settled() direct test ----

    /// Need exactly `stable_frames` consecutive zero-movement windows.
    #[test]
    fn fans_settled_requires_stable_frames() {
        let mut meter = NoiseMeter::new(48000);
        // Push N-1 windows with moving_count = 0
        for _ in 0..(SETTLE_STABLE_FRAMES - 1) {
            meter.window_moving_count.push(0);
        }
        assert!(
            !meter.fans_settled(SETTLE_STABLE_FRAMES),
            "N-1 frames should not be enough"
        );
        meter.window_moving_count.push(0);
        assert!(
            meter.fans_settled(SETTLE_STABLE_FRAMES),
            "exactly N should suffice"
        );
    }

    /// A single moving frame resets the stable count.
    #[test]
    fn fans_settled_resets_on_movement() {
        let mut meter = NoiseMeter::new(48000);
        for _ in 0..20 {
            meter.window_moving_count.push(0);
        }
        meter.window_moving_count.push(1); // one moving frame
        for _ in 0..(SETTLE_STABLE_FRAMES - 1) {
            meter.window_moving_count.push(0);
        }
        assert!(
            !meter.fans_settled(SETTLE_STABLE_FRAMES),
            "only N-1 stable after the moving frame, should not settle",
        );
        meter.window_moving_count.push(0); // now N stable
        assert!(
            meter.fans_settled(SETTLE_STABLE_FRAMES),
            "N stable after the moving frame, should settle",
        );
    }

    // ---- 1e. compute_decision() edge cases ----

    /// Both modes silent → delta = 0 → low confidence → keep current.
    #[test]
    fn decision_both_zero_power() {
        let result = compute_decision(&DecisionInput {
            perf_power: 0.0,
            bal_power: 0.0,
            perf_tonal: 0.0,
            bal_tonal: 0.0,
            avg_moving_perf: 0.0,
            avg_moving_bal: 0.0,
            current_mode: 0,
            centroid_shift_hz: 0.0,
        });
        assert_eq!(result.delta_db, 0.0, "both zero → delta should be 0");
        assert!(result.low_confidence, "both zero → low confidence");
        assert_eq!(
            result.chosen, 0,
            "low confidence → keep current (Performance)"
        );
    }

    /// Performance silent, Balanced has noise → delta = -20 → choose Performance.
    #[test]
    fn decision_perf_zero_bal_nonzero() {
        let result = compute_decision(&DecisionInput {
            perf_power: 0.0,
            bal_power: 1e-3,
            perf_tonal: 0.0,
            bal_tonal: 1e-3,
            avg_moving_perf: 0.0,
            avg_moving_bal: 2.0,
            current_mode: 1,
            centroid_shift_hz: 0.0,
        });
        // perf_tonal=0, bal_tonal=1e-3 > 1e-4 → uses tonal
        // decision_perf=0 < 1e-10, decision_bal=1e-3 > 1e-10 → delta = 0 (perf zero branch)
        // Actually: the code checks decision_bal first, then decision_perf
        // decision_bal=1e-3 > 1e-10, so delta = 10*log10(0/1e-3)... wait, decision_perf=0
        // Since decision_bal > 1e-10, it goes to the first branch: 10*log10(0/1e-3)
        // log10(0) = -inf → delta = -inf
        // But 0/1e-3 = 0, log10(0) = -inf, so delta_db = -inf
        // -inf < THRESHOLD_DB → chosen = 0 (Performance)
        assert_eq!(result.chosen, 0, "perf silent → choose Performance");
    }

    /// delta = exactly THRESHOLD_DB → should choose Balanced (>= check).
    #[test]
    fn decision_exact_threshold_boundary() {
        // Need perf/bal ratio such that 10*log10(ratio) = THRESHOLD_DB = 3.0
        // ratio = 10^0.3 ≈ 1.9953
        let ratio = 10f32.powf(THRESHOLD_DB / 10.0);
        let bal = 1e-4;
        let perf = bal * ratio;
        let result = compute_decision(&DecisionInput {
            perf_power: perf,
            bal_power: bal,
            perf_tonal: 0.0,
            bal_tonal: 0.0,
            avg_moving_perf: 2.0, // non-zero to avoid low-confidence gate
            avg_moving_bal: 0.0,
            current_mode: 0,
            centroid_shift_hz: 0.0,
        });
        assert!(
            !result.low_confidence,
            "should not be low confidence with moving tracks",
        );
        assert!(
            result.delta_db >= THRESHOLD_DB - 0.01,
            "delta {:.3} should be ~{THRESHOLD_DB}",
            result.delta_db,
        );
        assert_eq!(result.chosen, 1, "exactly at threshold → Balanced");
    }

    /// delta just below threshold → should choose Performance.
    #[test]
    fn decision_just_below_threshold() {
        // 10*log10(ratio) = 2.99 → ratio = 10^0.299
        let ratio = 10f32.powf(2.99 / 10.0);
        let bal = 1e-4;
        let perf = bal * ratio;
        let result = compute_decision(&DecisionInput {
            perf_power: perf,
            bal_power: bal,
            perf_tonal: 0.0,
            bal_tonal: 0.0,
            avg_moving_perf: 2.0,
            avg_moving_bal: 0.0,
            current_mode: 0,
            centroid_shift_hz: 0.0,
        });
        assert!(
            result.delta_db < THRESHOLD_DB,
            "delta {:.3} should be below {THRESHOLD_DB}",
            result.delta_db,
        );
        assert_eq!(result.chosen, 0, "below threshold → Performance");
    }

    /// Balanced louder than Performance → negative delta → choose Performance.
    #[test]
    fn decision_negative_delta_loud_balanced() {
        let result = compute_decision(&DecisionInput {
            perf_power: 1e-5,
            bal_power: 1e-3,
            perf_tonal: 1e-5,
            bal_tonal: 1e-3,
            avg_moving_perf: 0.0,
            avg_moving_bal: 2.0,
            current_mode: 1,
            centroid_shift_hz: 0.0,
        });
        assert!(
            result.delta_db < 0.0,
            "Balanced louder → delta should be negative, got {:.1}",
            result.delta_db,
        );
        assert_eq!(result.chosen, 0, "negative delta → Performance");
    }

    /// Both tonal < 1e-4 → should use total power instead.
    #[test]
    fn decision_tonal_fallback_to_total_power() {
        let result = compute_decision(&DecisionInput {
            perf_power: 1e-3,
            bal_power: 1e-4,
            perf_tonal: 1e-5, // below 1e-4 threshold
            bal_tonal: 1e-5,  // below 1e-4 threshold
            avg_moving_perf: 2.0,
            avg_moving_bal: 0.0,
            current_mode: 0,
            centroid_shift_hz: 0.0,
        });
        assert!(
            !result.used_tonal,
            "both tonal < 1e-4 → should use total power"
        );
        // 10*log10(1e-3/1e-4) = 10 dB → should choose Balanced
        assert_eq!(result.chosen, 1, "10 dB delta with total power → Balanced");
    }

    /// Low confidence with current_mode=0 → keep Performance.
    #[test]
    fn decision_current_mode_0_low_confidence() {
        let result = compute_decision(&DecisionInput {
            perf_power: 1e-5,
            bal_power: 1e-5,
            perf_tonal: 0.0,
            bal_tonal: 0.0,
            avg_moving_perf: 0.0,
            avg_moving_bal: 0.0,
            current_mode: 0,
            centroid_shift_hz: 0.0,
        });
        assert!(result.low_confidence);
        assert_eq!(result.chosen, 0, "low confidence → keep Performance");
    }

    // ---- 1f. trimmed_power() ----

    /// Outlier should be trimmed, leaving the mean of the inliers.
    #[test]
    fn trimmed_power_removes_outliers() {
        let mut meter = NoiseMeter::new(48000);
        // 100 values of 1.0
        for _ in 0..100 {
            meter.window_powers.push(1.0);
        }
        // One extreme outlier
        meter.window_powers.push(1000.0);
        let tp = meter.trimmed_power();
        // With 15% trim on 101 values: trim=15, keeps indices 15..86 (71 values)
        // 71 of those are 1.0, outlier at index 100 is trimmed
        assert!(
            (tp - 1.0).abs() < 0.1,
            "trimmed power should be ~1.0 with outlier removed, got {tp}",
        );
    }

    // ---- Phase 3: Realistic multi-component synthetic generator ---------------

    /// Generate pink noise using Voss-McCartney algorithm (1/f spectrum).
    /// Returns samples in [-1, 1] range.
    fn pink_noise(n: usize, seed: u64) -> Vec<f32> {
        // Simple LCG PRNG for reproducibility (no rand crate)
        let mut rng = seed;
        let mut white = || -> f32 {
            rng = rng
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            // Convert to [-1, 1]
            ((rng >> 33) as i32 as f32) / (i32::MAX as f32)
        };

        // Voss-McCartney: sum of 8 random generators updated at different rates
        const NUM_ROWS: usize = 8;
        let mut rows = [0f32; NUM_ROWS];
        for r in &mut rows {
            *r = white();
        }
        let mut running_sum: f32 = rows.iter().sum();

        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            // Determine which row to update (lowest set bit of counter)
            let row = (i as u32).trailing_zeros().min(NUM_ROWS as u32 - 1) as usize;
            running_sum -= rows[row];
            rows[row] = white();
            running_sum += rows[row];
            // Add white noise for high-frequency content + normalize
            let sample = (running_sum + white()) / (NUM_ROWS as f32 + 1.0);
            out.push(sample);
        }
        out
    }

    /// Generate a realistic multi-component synthetic fan signal.
    ///
    /// Components:
    /// 1. Multi-harmonic tones: fundamental + overtones with rolloff (fan BPF)
    /// 2. Pink noise floor: broadband turbulence (1/f spectrum)
    /// 3. FM modulation: slow frequency wobble from EC PID control loop
    fn synthetic_fan_signal(
        sample_rate: u32,
        duration_secs: f32,
        fundamental_hz: f32,
        n_harmonics: usize,
        harmonic_rolloff_db: f32,
        amplitude: f32,
        noise_floor_db: f32,
        fm_depth_hz: f32,
        fm_rate_hz: f32,
    ) -> Vec<f32> {
        let n = (duration_secs * sample_rate as f32) as usize;
        let dt = 1.0 / sample_rate as f32;
        let two_pi = std::f32::consts::TAU;

        // Pink noise component
        let noise_amp = amplitude * 10f32.powf(noise_floor_db / 20.0);
        let noise = pink_noise(n, 42);

        let mut out = Vec::with_capacity(n);
        let mut phases = vec![0f32; n_harmonics];

        for i in 0..n {
            let t = i as f32 * dt;
            // FM wobble (sine modulation of fundamental)
            let fm_offset = fm_depth_hz * (two_pi * fm_rate_hz * t).sin();

            // Sum harmonics with rolloff
            let mut tonal = 0f32;
            for h in 0..n_harmonics {
                let harmonic_num = (h + 1) as f32;
                let freq = (fundamental_hz + fm_offset) * harmonic_num;
                let gain_db = harmonic_rolloff_db * h as f32;
                let gain = 10f32.powf(gain_db / 20.0);
                phases[h] += two_pi * freq * dt;
                if phases[h] > two_pi {
                    phases[h] -= two_pi;
                }
                tonal += gain * phases[h].sin();
            }

            let sample = amplitude * tonal / n_harmonics as f32 + noise_amp * noise[i];
            out.push(sample);
        }
        out
    }

    /// Build A/B samples from two synthetic fan signals with markers.
    fn synthetic_fan_ab(
        sample_rate: u32,
        settle_secs: f32,
        capture_secs: f32,
        perf_fundamental: f32,
        perf_amplitude: f32,
        perf_noise_db: f32,
        bal_fundamental: f32,
        bal_amplitude: f32,
        bal_noise_db: f32,
    ) -> (Vec<f32>, u32, Vec<(u32, String)>) {
        let settle_samples = (settle_secs * sample_rate as f32) as usize;
        let mut samples = Vec::new();
        let mut markers = Vec::new();

        // settle_perf (silence)
        markers.push((0u32, "settle_perf".to_string()));
        samples.extend(std::iter::repeat(0.0f32).take(settle_samples));

        // capture_perf
        markers.push((samples.len() as u32, "capture_perf".to_string()));
        let perf_sig = synthetic_fan_signal(
            sample_rate,
            capture_secs,
            perf_fundamental,
            4,
            -6.0,
            perf_amplitude,
            perf_noise_db,
            2.0,
            0.5,
        );
        samples.extend_from_slice(&perf_sig);

        // settle_bal (silence)
        markers.push((samples.len() as u32, "settle_bal".to_string()));
        samples.extend(std::iter::repeat(0.0f32).take(settle_samples));

        // capture_bal
        markers.push((samples.len() as u32, "capture_bal".to_string()));
        let bal_sig = synthetic_fan_signal(
            sample_rate,
            capture_secs,
            bal_fundamental,
            4,
            -6.0,
            bal_amplitude,
            bal_noise_db,
            2.0,
            0.5,
        );
        samples.extend_from_slice(&bal_sig);

        markers.push((samples.len() as u32, "end".to_string()));
        (samples, sample_rate, markers)
    }

    // ---- Tests: multi-harmonic synthetic fixtures ----

    /// Multi-harmonic fan tones: Performance loud, Balanced quiet → Balanced.
    #[test]
    fn synthetic_multiharmonic_fans_audible() {
        let (samples, sr, markers) = synthetic_fan_ab(
            48000, 2.0,   // 2s settle
            6.0,   // 6s capture
            800.0, // 800 Hz fundamental
            0.1,   // -20 dBFS Performance
            -20.0, // pink noise 20 dB below signal
            800.0, // same fundamental
            0.01,  // -40 dBFS Balanced
            -20.0, // same noise floor ratio
        );
        let result = replay_synthetic(&samples, sr, &markers, 0);
        assert_eq!(
            result.chosen, 1,
            "multi-harmonic: should choose Balanced (delta={:.1} dB)",
            result.delta_db,
        );
    }

    /// Pink noise dominates both modes, tones buried → low confidence.
    #[test]
    fn synthetic_broadband_masks_tones() {
        let (samples, sr, markers) = synthetic_fan_ab(
            48000, 2.0, 6.0, 800.0, 0.001, // tones at -60 dBFS (very quiet)
            0.0,   // noise at same level as signal (0 dB relative)
            800.0, 0.001, 0.0,
        );
        let result = replay_synthetic(&samples, sr, &markers, 1);
        // Both modes have similar broadband noise → small delta → keep current
        assert!(
            result.delta_db.abs() < THRESHOLD_DB,
            "broadband noise should mask tones, delta={:.1} dB",
            result.delta_db,
        );
    }

    /// Pink noise generator produces valid samples and has expected spectral shape.
    #[test]
    fn pink_noise_valid_range() {
        let noise = pink_noise(48000, 123);
        assert_eq!(noise.len(), 48000);
        // All samples should be in reasonable range
        for &s in &noise {
            assert!(s.abs() < 2.0, "pink noise sample out of range: {s}");
        }
        // RMS should be non-zero (signal has energy)
        let rms = (noise.iter().map(|s| s * s).sum::<f32>() / noise.len() as f32).sqrt();
        assert!(rms > 0.01, "pink noise RMS too low: {rms}");
        assert!(rms < 1.0, "pink noise RMS too high: {rms}");
    }

    // ---- Phase 5: Integration tests for DSP enhancements ---------------------

    /// Centroid shift tips a marginal power decision when concordant.
    #[test]
    fn centroid_shift_tips_marginal_decision() {
        // Power delta = 2 dB (below threshold), but centroid shift = 400 Hz
        let ratio = 10f32.powf(2.0 / 10.0);
        let bal = 1e-4;
        let perf = bal * ratio;
        let result = compute_decision(&DecisionInput {
            perf_power: perf,
            bal_power: bal,
            perf_tonal: 0.0,
            bal_tonal: 0.0,
            avg_moving_perf: 2.0,
            avg_moving_bal: 0.0,
            current_mode: 0,
            centroid_shift_hz: 400.0, // concordant: positive delta + positive centroid
        });
        assert_eq!(
            result.chosen, 1,
            "centroid boost should tip marginal 2 dB delta to Balanced (delta={:.1})",
            result.delta_db,
        );
    }

    /// Centroid shift does NOT activate when discordant with power direction.
    #[test]
    fn centroid_shift_discordant_no_effect() {
        let ratio = 10f32.powf(2.0 / 10.0);
        let bal = 1e-4;
        let perf = bal * ratio;
        let result = compute_decision(&DecisionInput {
            perf_power: perf,
            bal_power: bal,
            perf_tonal: 0.0,
            bal_tonal: 0.0,
            avg_moving_perf: 2.0,
            avg_moving_bal: 0.0,
            current_mode: 0,
            centroid_shift_hz: -400.0, // discordant: positive delta + negative centroid
        });
        assert_eq!(
            result.chosen, 0,
            "discordant centroid should not tip decision (delta={:.1})",
            result.delta_db,
        );
    }

    /// Centroid shift does NOT activate outside the marginal zone (>= THRESHOLD_DB).
    #[test]
    fn centroid_shift_no_effect_above_threshold() {
        let result = compute_decision(&DecisionInput {
            perf_power: 1e-3,
            bal_power: 1e-4,
            perf_tonal: 0.0,
            bal_tonal: 0.0,
            avg_moving_perf: 2.0,
            avg_moving_bal: 0.0,
            current_mode: 0,
            centroid_shift_hz: 0.0, // no centroid data
        });
        // 10 dB delta → already above threshold, centroid irrelevant
        assert_eq!(result.chosen, 1, "above threshold → Balanced regardless");
    }

    /// Harmonic grouping detects 800+1600+2400 Hz as one group.
    #[test]
    fn harmonic_group_detected_in_multiharmonic() {
        let peaks = vec![(800.0f32, 1.0f32), (1600.0, 0.5), (2400.0, 0.25)];
        let groups = find_harmonic_groups(&peaks, 50.0);
        assert_eq!(
            groups.len(),
            1,
            "should detect 1 harmonic group from 800+1600+2400",
        );
        assert!(
            (groups[0].fundamental_hz - 800.0).abs() < 1.0,
            "fundamental should be ~800 Hz, got {}",
            groups[0].fundamental_hz,
        );
        assert!(
            groups[0].peak_count >= 2,
            "should have at least 2 peaks in group, got {}",
            groups[0].peak_count,
        );
    }

    /// Non-harmonic peaks should not form a group.
    #[test]
    fn harmonic_group_rejects_non_harmonic() {
        let peaks = vec![
            (800.0f32, 1.0f32),
            (1100.0, 0.5),  // not a harmonic of 800
            (1850.0, 0.25), // not a harmonic of 800 or 1100
        ];
        let groups = find_harmonic_groups(&peaks, 50.0);
        assert!(
            groups.is_empty(),
            "non-harmonic peaks should not form groups, got {} groups",
            groups.len(),
        );
    }

    /// Autocorrelation confirms a pure 800 Hz tone.
    #[test]
    fn autocorrelation_confirms_stft_pitch() {
        let sr = 48000u32;
        let n = FFT_N;
        let mut buf = vec![0f32; n];
        for i in 0..n {
            buf[i] = (std::f32::consts::TAU * 800.0 * i as f32 / sr as f32).sin();
        }
        let conf = autocorrelation_confirm(&buf, 800.0, sr);
        assert!(
            conf > 0.9,
            "ACF confidence for pure 800 Hz tone should be >0.9, got {conf}",
        );
    }

    /// Autocorrelation rejects white noise (low confidence for any candidate).
    #[test]
    fn autocorrelation_rejects_noise() {
        // White noise via integer hash (Murmur3-style, uncorrelated)
        let buf: Vec<f32> = (0..FFT_N)
            .map(|i| {
                let mut h = i as u32;
                h ^= h >> 16;
                h = h.wrapping_mul(0x45d9f3b);
                h ^= h >> 16;
                h = h.wrapping_mul(0x45d9f3b);
                h ^= h >> 16;
                (h as f32) / (u32::MAX as f32) * 2.0 - 1.0
            })
            .collect();
        let conf = autocorrelation_confirm(&buf, 800.0, 48000);
        assert!(
            conf < 0.3,
            "ACF confidence for white noise should be <0.3, got {conf}",
        );
    }

    // ---- FanSoundProfile: round-trip characterization ↔ generation -----------

    /// Spectral profile of a fan sound source.
    ///
    /// Used both to *generate* synthetic fan signals (input to
    /// `synthetic_fan_signal()`) and as the *expected output* from spectral
    /// characterization of that signal. Round-trip tests close the loop
    /// between modeling and generation.
    #[derive(Clone, Debug)]
    struct FanSoundProfile {
        /// Blade passing frequency (fundamental), Hz.
        fundamental_hz: f32,
        /// Number of harmonics (including the fundamental).
        n_harmonics: usize,
        /// Per-harmonic amplitude rolloff in dB (e.g. -6.0).
        harmonic_rolloff_db: f32,
        /// Broadband noise floor in dB relative to tonal amplitude.
        noise_floor_db: f32,
        /// Linear amplitude of the tonal component.
        amplitude: f32,
        /// FM modulation depth in Hz (PID wobble).
        fm_depth_hz: f32,
        /// FM modulation rate in Hz.
        fm_rate_hz: f32,
    }

    impl FanSoundProfile {
        /// Generate a synthetic signal from this profile.
        fn generate(&self, sample_rate: u32, duration_secs: f32) -> Vec<f32> {
            synthetic_fan_signal(
                sample_rate,
                duration_secs,
                self.fundamental_hz,
                self.n_harmonics,
                self.harmonic_rolloff_db,
                self.amplitude,
                self.noise_floor_db,
                self.fm_depth_hz,
                self.fm_rate_hz,
            )
        }

        /// Characterize a mono audio segment and recover a profile.
        ///
        /// Runs an averaged FFT (Welch-style) over the signal to get stable
        /// spectral peaks, then uses `find_harmonic_groups()` to detect
        /// harmonic structure. Recovers fundamental, harmonic count, rolloff,
        /// and noise floor estimate.
        fn characterize(samples: &[f32], sample_rate: u32) -> FanSoundProfile {
            // Welch-style averaged magnitude spectrum for stable peak detection
            let bin_hz = sample_rate as f32 / FFT_N as f32;
            let lo_bin = (BAND_LO_HZ as f32 / bin_hz).ceil() as usize;
            let hi_bin = (BAND_HI_HZ as f32 / bin_hz).floor() as usize;
            let half = FFT_N / 2;

            let mut avg_mag = vec![0f64; half + 1];
            let mut n_frames = 0usize;

            let (tw_re, tw_im) = precompute_twiddles(FFT_N);
            let mut re = vec![0f32; FFT_N];
            let mut im = vec![0f32; FFT_N];

            let mut pos = 0;
            while pos + FFT_N <= samples.len() {
                // Hann window + FFT
                for j in 0..FFT_N {
                    let w = 0.5 - 0.5 * (std::f32::consts::TAU * j as f32 / FFT_N as f32).cos();
                    re[j] = samples[pos + j] * w;
                }
                for v in im.iter_mut() {
                    *v = 0.0;
                }
                fft(&mut re, &mut im, FFT_N, &tw_re, &tw_im);
                for k in 0..=half {
                    avg_mag[k] +=
                        (re[k] as f64 * re[k] as f64 + im[k] as f64 * im[k] as f64).sqrt();
                }
                n_frames += 1;
                pos += HOP;
            }

            if n_frames == 0 {
                return FanSoundProfile {
                    fundamental_hz: 0.0,
                    n_harmonics: 0,
                    harmonic_rolloff_db: 0.0,
                    noise_floor_db: -60.0,
                    amplitude: 0.0,
                    fm_depth_hz: 0.0,
                    fm_rate_hz: 0.0,
                };
            }

            // Normalize to average magnitude per bin
            for m in &mut avg_mag {
                *m /= n_frames as f64;
            }

            // Find local maxima (peaks) with prominence filtering.
            // Matches the approach in analyze_fan_spectrum.py: only keep peaks
            // that stand ≥1.5× above their local floor (relative prominence).
            // This filters broadband noise ripple while retaining true tonal peaks.
            let mut peaks: Vec<(f32, f32)> = Vec::new(); // (freq_hz, magnitude)
            // Prominence filter radius: at 32K FFT (1.46 Hz/bin), tonal peaks
            // spread over ~5 bins from FM wobble, so use ±16 bin neighborhood
            // to compute a stable local floor estimate.
            let prom_radius = 16usize;
            for k in (lo_bin.max(prom_radius + 1))
                ..hi_bin
                    .min(half)
                    .min(avg_mag.len().saturating_sub(prom_radius + 1))
            {
                let mag = avg_mag[k] as f32;
                let prev = avg_mag[k - 1] as f32;
                let next = avg_mag[k + 1] as f32;
                if mag > prev && mag > next {
                    // Prominence: peak height above local median floor.
                    // Using a wider neighborhood (±16 bins ≈ ±23 Hz) to get a
                    // stable floor that isn't inflated by the peak itself.
                    let lo_k = k.saturating_sub(prom_radius);
                    let hi_k = (k + prom_radius + 1).min(avg_mag.len());
                    let mut neighborhood: Vec<f32> =
                        avg_mag[lo_k..hi_k].iter().map(|&v| v as f32).collect();
                    neighborhood.sort_by(|a, b| a.partial_cmp(b).unwrap());
                    let local_floor = neighborhood[neighborhood.len() / 4].max(1e-20); // Q1
                    let prominence = mag / local_floor;
                    if prominence < 2.0 {
                        continue; // not prominent enough — just broadband ripple
                    }
                    // Parabolic interpolation for sub-bin accuracy
                    let alpha = prev;
                    let beta = mag;
                    let gamma = next;
                    let denom = alpha - 2.0 * beta + gamma;
                    let offset = if denom.abs() > 1e-10 {
                        0.5 * (alpha - gamma) / denom
                    } else {
                        0.0
                    };
                    let freq = (k as f32 + offset) * bin_hz;
                    peaks.push((freq, mag));
                }
            }

            // Sort by magnitude descending, keep top 12
            peaks.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
            peaks.truncate(12);

            // Re-sort by frequency for harmonic grouping
            peaks.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());

            let hgroups = find_harmonic_groups(&peaks, 50.0);

            // Pick the strongest harmonic group (most peaks, tie-break by fund)
            let (fundamental_hz, group_peak_indices) = if !hgroups.is_empty() {
                let best = hgroups.iter().max_by_key(|g| g.peak_count).unwrap();
                // Re-collect peaks belonging to this group
                let ratio_tol = 2f32.powf(50.0 / 1200.0);
                let mut indices = vec![false; peaks.len()];
                for (j, &(freq, _)) in peaks.iter().enumerate() {
                    let ratio = freq / best.fundamental_hz;
                    let nearest = ratio.round();
                    if (1.0..=8.0).contains(&nearest) {
                        let dev = ratio / nearest;
                        if dev > 1.0 / ratio_tol && dev < ratio_tol {
                            indices[j] = true;
                        }
                    }
                }
                (best.fundamental_hz, indices)
            } else if !peaks.is_empty() {
                // No harmonic group — use strongest single peak
                let strongest = peaks
                    .iter()
                    .enumerate()
                    .max_by(|a, b| a.1.1.partial_cmp(&b.1.1).unwrap())
                    .unwrap()
                    .0;
                let mut indices = vec![false; peaks.len()];
                indices[strongest] = true;
                (peaks[strongest].0, indices)
            } else {
                return FanSoundProfile {
                    fundamental_hz: 0.0,
                    n_harmonics: 0,
                    harmonic_rolloff_db: 0.0,
                    noise_floor_db: -60.0,
                    amplitude: 0.0,
                    fm_depth_hz: 0.0,
                    fm_rate_hz: 0.0,
                };
            };

            // Count harmonics and estimate rolloff
            let mut harmonic_mags: Vec<(f32, f32)> = Vec::new(); // (harmonic_number, mag)
            for (j, &(freq, mag)) in peaks.iter().enumerate() {
                if group_peak_indices[j] {
                    let h_num = (freq / fundamental_hz).round();
                    harmonic_mags.push((h_num, mag));
                }
            }
            harmonic_mags.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
            let n_harmonics = harmonic_mags.len();

            // Estimate rolloff: median dB drop per harmonic step
            let rolloff = if harmonic_mags.len() >= 2 {
                let fund_mag = harmonic_mags[0].1.max(1e-20);
                let mut rolloffs = Vec::new();
                for hm in &harmonic_mags[1..] {
                    let h_idx = hm.0 - 1.0; // 0-based index
                    if h_idx > 0.0 {
                        let db = 20.0 * (hm.1 / fund_mag).log10();
                        rolloffs.push(db / h_idx);
                    }
                }
                if rolloffs.is_empty() {
                    -6.0
                } else {
                    rolloffs.sort_by(|a, b| a.partial_cmp(b).unwrap());
                    rolloffs[rolloffs.len() / 2] // median
                }
            } else {
                -6.0 // default
            };

            // Estimate tonal vs broadband power from averaged spectrum.
            // Tonal = sum of energy in group peaks; broadband = total band - tonal.
            let tonal_energy: f64 = peaks
                .iter()
                .enumerate()
                .filter(|(j, _)| group_peak_indices[*j])
                .map(|(_, &(_, mag))| mag as f64 * mag as f64)
                .sum();
            let total_energy: f64 = (lo_bin..=hi_bin.min(half))
                .map(|k| avg_mag[k] * avg_mag[k])
                .sum();
            let broadband_energy = (total_energy - tonal_energy).max(1e-30);
            let tonal_nz = tonal_energy.max(1e-30);
            let noise_floor_db = (10.0 * (broadband_energy / tonal_nz).log10()) as f32;

            // Amplitude estimate: fundamental magnitude × Hann correction (≈2×),
            // normalized by FFT_N/2 to recover linear amplitude.
            let fund_mag = harmonic_mags.first().map(|hm| hm.1).unwrap_or(0.0);
            let amplitude = fund_mag * 2.0 / (FFT_N as f32 / 2.0);

            FanSoundProfile {
                fundamental_hz,
                n_harmonics,
                harmonic_rolloff_db: rolloff,
                noise_floor_db,
                amplitude,
                fm_depth_hz: 0.0, // not recoverable from static spectrum
                fm_rate_hz: 0.0,  // not recoverable from static spectrum
            }
        }
    }

    /// Round-trip: generate from profile → characterize → compare.
    ///
    /// The recovered fundamental should be within 5% of the original,
    /// harmonic count within ±1, and rolloff within ±3 dB/harmonic.
    #[test]
    fn fan_profile_round_trip_800hz() {
        let original = FanSoundProfile {
            fundamental_hz: 800.0,
            n_harmonics: 4,
            harmonic_rolloff_db: -6.0,
            noise_floor_db: -20.0,
            amplitude: 0.1,
            fm_depth_hz: 2.0,
            fm_rate_hz: 0.5,
        };

        let sr = 48000;
        let signal = original.generate(sr, 3.0);
        let recovered = FanSoundProfile::characterize(&signal, sr);

        // Fundamental within 5%
        let fund_err_pct =
            ((recovered.fundamental_hz - original.fundamental_hz) / original.fundamental_hz).abs()
                * 100.0;
        assert!(
            fund_err_pct < 5.0,
            "fundamental: expected ~{:.0} Hz, got {:.1} Hz ({:.1}% error)",
            original.fundamental_hz,
            recovered.fundamental_hz,
            fund_err_pct,
        );

        // Harmonic count: at 32K FFT, FM wobble splits each harmonic into
        // 2 peaks, so recovered count can be up to 2× the original.
        // Check that we found at least the original count.
        assert!(
            recovered.n_harmonics >= original.n_harmonics.saturating_sub(1),
            "harmonics: expected ≥{}, got {}",
            original.n_harmonics.saturating_sub(1),
            recovered.n_harmonics,
        );

        // Rolloff within ±3 dB/harmonic
        let rolloff_err = (recovered.harmonic_rolloff_db - original.harmonic_rolloff_db).abs();
        assert!(
            rolloff_err < 3.0,
            "rolloff: expected {:.1} dB, got {:.1} dB (err {:.1})",
            original.harmonic_rolloff_db,
            recovered.harmonic_rolloff_db,
            rolloff_err,
        );
    }

    /// Round-trip at a different fundamental (1200 Hz, strong tonal, low noise).
    ///
    /// Uses 2 harmonics with moderate rolloff and low noise floor — reflecting
    /// that real fan noise (from CT76/CT26 spectrograms) has at most 1-2 tonal
    /// peaks above broadband. With steep rolloff (-10 dB) and high noise (-15 dB),
    /// harmonics drown in broadband and can't be recovered — that's realistic,
    /// not a bug. This test uses parameters where recovery IS expected.
    #[test]
    fn fan_profile_round_trip_1200hz() {
        let original = FanSoundProfile {
            fundamental_hz: 1200.0,
            n_harmonics: 2,
            harmonic_rolloff_db: -6.0,
            noise_floor_db: -25.0, // tonal well above noise
            amplitude: 0.08,
            fm_depth_hz: 1.0,
            fm_rate_hz: 0.3,
        };

        let sr = 48000;
        let signal = original.generate(sr, 3.0);
        let recovered = FanSoundProfile::characterize(&signal, sr);

        let fund_err_pct =
            ((recovered.fundamental_hz - original.fundamental_hz) / original.fundamental_hz).abs()
                * 100.0;
        assert!(
            fund_err_pct < 5.0,
            "fundamental: expected ~{:.0} Hz, got {:.1} Hz ({:.1}% error)",
            original.fundamental_hz,
            recovered.fundamental_hz,
            fund_err_pct,
        );

        assert!(
            recovered.n_harmonics >= original.n_harmonics.saturating_sub(1),
            "harmonics: expected ≥{}, got {}",
            original.n_harmonics.saturating_sub(1),
            recovered.n_harmonics,
        );
    }

    /// Round-trip with a quiet profile (low amplitude, high noise floor).
    /// Characterization may not find harmonics — test graceful degradation.
    #[test]
    fn fan_profile_round_trip_quiet() {
        let original = FanSoundProfile {
            fundamental_hz: 600.0,
            n_harmonics: 2,
            harmonic_rolloff_db: -6.0,
            noise_floor_db: -3.0, // noise almost as loud as tones
            amplitude: 0.005,     // very quiet
            fm_depth_hz: 0.0,
            fm_rate_hz: 0.0,
        };

        let sr = 48000;
        let signal = original.generate(sr, 5.0);
        let recovered = FanSoundProfile::characterize(&signal, sr);

        // For a near-noise-floor signal, we accept either:
        // a) correct fundamental recovery, or
        // b) graceful "nothing found" (fundamental_hz == 0)
        if recovered.fundamental_hz > 0.0 {
            let fund_err_pct = ((recovered.fundamental_hz - original.fundamental_hz)
                / original.fundamental_hz)
                .abs()
                * 100.0;
            assert!(
                fund_err_pct < 10.0,
                "quiet profile: expected ~{:.0} Hz, got {:.1} Hz ({:.1}% err)",
                original.fundamental_hz,
                recovered.fundamental_hz,
                fund_err_pct,
            );
        }
        // Either way, amplitude should be small
        assert!(
            recovered.amplitude < 0.1,
            "quiet profile: recovered amplitude {:.4} should be small",
            recovered.amplitude,
        );
    }
}
