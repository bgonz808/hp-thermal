//! Capture test: validates device selection + audio pipeline.
//!
//! Enumerates all capture devices, shows their names and peak levels,
//! then does a 1-second real capture on the best device and reports
//! FFT power + spectral centroid + peak frequency.
//!
//! Usage:
//!   cargo run --example capture_test --release
//!   cargo run --example capture_test --release -- 2   # force device index 2

use std::ptr;
use std::time::Instant;
use windows::Win32::Foundation::{BOOL, PROPERTYKEY};
use windows::Win32::Media::Audio::Endpoints::{IAudioEndpointVolume, IAudioMeterInformation};
use windows::Win32::Media::Audio::*;
use windows::Win32::System::Com::*;
use windows::Win32::System::Variant::VT_LPWSTR;
use windows::Win32::UI::Shell::PropertiesSystem::IPropertyStore;
use windows::core::{GUID, Interface, PWSTR};

const PKEY_DEVICE_FRIENDLY_NAME: PROPERTYKEY = PROPERTYKEY {
    fmtid: GUID {
        data1: 0xa45c254e,
        data2: 0xdf1c,
        data3: 0x4efd,
        data4: [0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0],
    },
    pid: 14,
};

// KSDATAFORMAT_SUBTYPE_IEEE_FLOAT
const SUBFMT_FLOAT: GUID = GUID {
    data1: 3,
    data2: 0,
    data3: 0x0010,
    data4: [0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71],
};

unsafe fn device_name(device: &IMMDevice) -> String {
    unsafe {
        let Ok(store): Result<IPropertyStore, _> = device.OpenPropertyStore(STGM(0)) else {
            return "??".into();
        };
        let Ok(prop) = store.GetValue(&PKEY_DEVICE_FRIENDLY_NAME) else {
            return "??".into();
        };
        if prop.Anonymous.Anonymous.vt == VT_LPWSTR {
            let pwsz: PWSTR = prop.Anonymous.Anonymous.Anonymous.pwszVal;
            if !pwsz.0.is_null() {
                let len = (0..).take_while(|&i| *pwsz.0.add(i) != 0).count();
                return String::from_utf16_lossy(std::slice::from_raw_parts(pwsz.0, len));
            }
        }
        "??".into()
    }
}

/// Minimal 512-point FFT (same as main app).
fn fft_512(re: &mut [f32; 512], im: &mut [f32; 512]) {
    for i in 0..512usize {
        let j = bit_reverse_9(i);
        if i < j {
            re.swap(i, j);
            im.swap(i, j);
        }
    }
    let mut size = 2usize;
    while size <= 512 {
        let half = size / 2;
        let angle_step = -std::f32::consts::TAU / size as f32;
        let mut k = 0;
        while k < 512 {
            for j in 0..half {
                let angle = angle_step * j as f32;
                let (s, c) = angle.sin_cos();
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

fn bit_reverse_9(mut x: usize) -> usize {
    let mut r = 0;
    for _ in 0..9 {
        r = (r << 1) | (x & 1);
        x >>= 1;
    }
    r
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let force_device: Option<u32> = args.get(1).and_then(|s| s.parse().ok());

    unsafe {
        CoInitializeEx(None, COINIT_MULTITHREADED)
            .ok()
            .expect("COM init failed");

        let enumerator: IMMDeviceEnumerator =
            CoCreateInstance(&MMDeviceEnumerator, None, CLSCTX_ALL).expect("no audio enumerator");

        let collection = enumerator
            .EnumAudioEndpoints(eCapture, DEVICE_STATE_ACTIVE)
            .expect("no capture devices");
        let count = collection.GetCount().expect("count failed");

        println!("=== Capture devices ({count}) ===\n");

        let mut best_idx = 0u32;
        let mut best_score = i32::MIN;

        for i in 0..count {
            let Ok(device) = collection.Item(i) else {
                continue;
            };
            let name = device_name(&device);

            let gain = device
                .Activate::<IAudioEndpointVolume>(CLSCTX_ALL, None)
                .ok()
                .and_then(|v| v.GetMasterVolumeLevelScalar().ok())
                .unwrap_or(-1.0);

            let peak = device
                .Activate::<IAudioMeterInformation>(CLSCTX_ALL, None)
                .ok()
                .and_then(|m| {
                    // Quick 100ms poll
                    let mut p = 0.0f32;
                    for _ in 0..10 {
                        if let Ok(v) = m.GetPeakValue() {
                            p = p.max(v);
                        }
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Some(p)
                })
                .unwrap_or(0.0);

            let score = device_score(&name);
            let marker = if let Some(f) = force_device {
                if f == i { " <-- FORCED" } else { "" }
            } else if score > best_score {
                best_score = score;
                best_idx = i;
                ""
            } else {
                ""
            };

            println!(
                "  [{i}] {name}\n      gain={gain:.2}  peak={peak:.4}  score={score}{marker}\n"
            );
        }

        let target_idx = force_device.unwrap_or(best_idx);
        let device = collection.Item(target_idx).expect("device not found");
        let name = device_name(&device);
        println!("=== Capturing 1s from [{target_idx}] {name} ===\n");

        // Try RAW mode
        let (client, raw) = {
            let Ok(client2): Result<IAudioClient2, _> = device.Activate(CLSCTX_ALL, None) else {
                panic!("cannot activate audio client");
            };
            let props = AudioClientProperties {
                cbSize: std::mem::size_of::<AudioClientProperties>() as u32,
                bIsOffload: BOOL(0),
                eCategory: AUDIO_STREAM_CATEGORY(0),
                Options: AUDCLNT_STREAMOPTIONS_RAW,
            };
            let raw = client2.SetClientProperties(&props).is_ok();
            let client: IAudioClient = client2.cast().expect("cast failed");
            (client, raw)
        };
        println!(
            "  Audio mode: {}",
            if raw { "RAW (no DSP)" } else { "processed" }
        );

        let format_ptr = client.GetMixFormat().expect("GetMixFormat failed");
        let fmt = &*format_ptr;
        let sample_rate = fmt.nSamplesPerSec;
        let channels = fmt.nChannels as usize;
        let tag = fmt.wFormatTag;
        let is_float = match tag {
            1 => false,
            3 => true,
            0xFFFE => {
                if fmt.cbSize >= 22 {
                    let ext = format_ptr as *const WAVEFORMATEXTENSIBLE;
                    let sub: GUID = ptr::read_unaligned(ptr::addr_of!((*ext).SubFormat));
                    sub == SUBFMT_FLOAT
                } else {
                    false
                }
            }
            _ => panic!("unsupported format tag {tag}"),
        };
        println!(
            "  Format: {}Hz, {}ch, {}",
            sample_rate,
            channels,
            if is_float { "float32" } else { "int16" }
        );

        client
            .Initialize(AUDCLNT_SHAREMODE_SHARED, 0, 10_000_000, 0, format_ptr, None)
            .expect("audio init failed");

        let capture: IAudioCaptureClient = client.GetService().expect("no capture service");

        // Build Hann window
        let mut hann = [0f32; 512];
        for i in 0..512 {
            hann[i] = 0.5 - 0.5 * (std::f32::consts::TAU * i as f32 / 511.0).cos();
        }

        let mut buf_ring = [0f32; 512];
        let mut buf_pos = 0usize;
        let mut window_count = 0u32;
        let mut total_power = 0f64;
        let mut total_centroid = 0f64;
        let mut silent_bufs = 0u32;
        let mut active_bufs = 0u32;
        let mut min_sample = f32::MAX;
        let mut max_sample = f32::MIN;
        let mut sample_count = 0u64;

        client.Start().expect("capture start failed");
        let start = Instant::now();
        let deadline = start + std::time::Duration::from_secs(1);

        while Instant::now() < deadline {
            let pkt = capture.GetNextPacketSize().expect("packet size failed");
            if pkt == 0 {
                std::thread::sleep(std::time::Duration::from_millis(2));
                continue;
            }

            let mut pbuf: *mut u8 = ptr::null_mut();
            let mut frames = 0u32;
            let mut flags = 0u32;
            capture
                .GetBuffer(&mut pbuf, &mut frames, &mut flags, None, None)
                .expect("GetBuffer failed");

            if flags & 2 != 0 {
                silent_bufs += 1;
            } else {
                active_bufs += 1;
            }

            if flags & 2 == 0 && !pbuf.is_null() {
                for f in 0..frames as usize {
                    let sample = if is_float {
                        let p = pbuf as *const f32;
                        let mut sum = 0f32;
                        for ch in 0..channels {
                            sum += *p.add(f * channels + ch);
                        }
                        sum / channels as f32
                    } else {
                        let p = pbuf as *const i16;
                        let mut sum = 0f32;
                        for ch in 0..channels {
                            sum += *p.add(f * channels + ch) as f32 / 32768.0;
                        }
                        sum / channels as f32
                    };

                    if sample < min_sample {
                        min_sample = sample;
                    }
                    if sample > max_sample {
                        max_sample = sample;
                    }
                    sample_count += 1;

                    buf_ring[buf_pos] = sample;
                    buf_pos += 1;
                    if buf_pos == 512 {
                        // FFT this window
                        let mut re = [0f32; 512];
                        for i in 0..512 {
                            re[i] = buf_ring[i] * hann[i];
                        }
                        let mut im = [0f32; 512];
                        fft_512(&mut re, &mut im);

                        let bin_lo = ((300u32 * 512 + sample_rate - 1) / sample_rate) as usize;
                        let bin_hi = ((3000u32 * 512) / sample_rate).min(255) as usize;

                        let mut power = 0f32;
                        let mut wf = 0f64;
                        let mut tm = 0f64;
                        for k in bin_lo..=bin_hi {
                            let mag_sq = re[k] * re[k] + im[k] * im[k];
                            power += mag_sq;
                            let mag = mag_sq.sqrt() as f64;
                            wf += (k as f64) * (sample_rate as f64) / 512.0 * mag;
                            tm += mag;
                        }
                        total_power += power as f64;
                        if tm > 0.0 {
                            total_centroid += wf / tm;
                        }
                        window_count += 1;

                        // 50% overlap
                        buf_ring.copy_within(256..512, 0);
                        buf_pos = 256;
                    }
                }
            }

            let _ = capture.ReleaseBuffer(frames);
        }

        let _ = client.Stop();
        CoTaskMemFree(Some(format_ptr as *const std::ffi::c_void));

        let avg_power = if window_count > 0 {
            total_power / window_count as f64
        } else {
            0.0
        };
        let avg_centroid = if window_count > 0 {
            total_centroid / window_count as f64
        } else {
            0.0
        };
        let db = if avg_power > 0.0 {
            10.0 * avg_power.log10()
        } else {
            -120.0
        };

        println!("\n=== Results ===\n");
        println!("  Samples:    {sample_count}");
        println!("  Min/Max:    {min_sample:.6} / {max_sample:.6}");
        println!("  Silent bufs: {silent_bufs}");
        println!("  Active bufs: {active_bufs}");
        println!("  FFT windows: {window_count}");
        println!("  Avg power:   {avg_power:.6e} ({db:.1} dBFS)");
        println!("  Avg centroid: {avg_centroid:.0} Hz");
        println!();

        if avg_power < 1e-8 {
            println!("  *** NOISE FLOOR: this device may not be receiving input ***");
        } else if avg_power < 1e-5 {
            println!("  Quiet environment (low signal)");
        } else {
            println!("  Good signal level");
        }

        CoUninitialize();
    }
}

fn device_score(name: &str) -> i32 {
    let lower = name.to_lowercase();
    let mut score = 0i32;
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
