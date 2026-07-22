//! Rapid-fire peak meter polling experiment.
//!
//! Polls IAudioMeterInformation on ALL capture devices at max rate for
//! a configurable duration, outputs TSV to stdout for plotting.
//!
//! Usage:
//!   cargo run --example peak_poll --release          # 5 seconds, all devices
//!   cargo run --example peak_poll --release -- 10    # 10 seconds
//!   cargo run --example peak_poll --release -- 5 2   # 5 seconds, device index 2 only
//!
//! Output (TSV to stdout):
//!   time_us  device  peak  delta_us
//!
//! Pipe to file:
//!   cargo run --example peak_poll --release -- 10 > peak_data.tsv

use std::time::Instant;
use windows::core::{Interface, GUID, PWSTR};
use windows::Win32::Foundation::PROPERTYKEY;
use windows::Win32::Media::Audio::Endpoints::{IAudioEndpointVolume, IAudioMeterInformation};
use windows::Win32::Media::Audio::*;
use windows::Win32::System::Com::*;
use windows::Win32::System::Variant::VT_LPWSTR;
use windows::Win32::UI::Shell::PropertiesSystem::IPropertyStore;

const PKEY_DEVICE_FRIENDLY_NAME: PROPERTYKEY = PROPERTYKEY {
    fmtid: GUID {
        data1: 0xa45c254e,
        data2: 0xdf1c,
        data3: 0x4efd,
        data4: [0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0],
    },
    pid: 14,
};

unsafe fn device_name(device: &IMMDevice) -> String {
    let Ok(store): Result<IPropertyStore, _> = device.OpenPropertyStore(STGM(0)) else {
        return "??".into();
    };
    let Ok(prop) = store.GetValue(&PKEY_DEVICE_FRIENDLY_NAME) else {
        return "??".into();
    };
    let vt = prop.Anonymous.Anonymous.vt;
    if vt == VT_LPWSTR {
        let pwsz: PWSTR = prop.Anonymous.Anonymous.Anonymous.pwszVal;
        if !pwsz.0.is_null() {
            let len = (0..).take_while(|&i| *pwsz.0.add(i) != 0).count();
            return String::from_utf16_lossy(std::slice::from_raw_parts(pwsz.0, len));
        }
    }
    "??".into()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let duration_secs: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(5);
    let device_filter: Option<u32> = args.get(2).and_then(|s| s.parse().ok());

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

        // Enumerate and print device info to stderr
        struct Dev {
            name: String,
            meter: IAudioMeterInformation,
            gain: f32,
        }
        let mut devices: Vec<(u32, Dev)> = Vec::new();

        for i in 0..count {
            if let Some(filter) = device_filter {
                if i != filter {
                    continue;
                }
            }
            let Ok(device) = collection.Item(i) else {
                continue;
            };
            let name = device_name(&device);
            let Ok(meter): Result<IAudioMeterInformation, _> = device.Activate(CLSCTX_ALL, None)
            else {
                eprintln!("[{i}] {name}: no peak meter, skipping");
                continue;
            };
            let gain = device
                .Activate::<IAudioEndpointVolume>(CLSCTX_ALL, None)
                .ok()
                .and_then(|v| v.GetMasterVolumeLevelScalar().ok())
                .unwrap_or(-1.0);

            eprintln!("[{i}] {name} (gain={gain:.2})");
            devices.push((i, Dev { name, meter, gain }));
        }

        if devices.is_empty() {
            eprintln!("No devices to poll!");
            return;
        }

        eprintln!(
            "Polling {} device(s) for {}s at max rate...",
            devices.len(),
            duration_secs
        );

        // TSV header
        println!("time_us\tdevice\tdevice_name\tpeak\tdelta_us");

        let start = Instant::now();
        let deadline = start + std::time::Duration::from_secs(duration_secs);
        let mut samples = 0u64;
        let mut prev_time = start;

        while Instant::now() < deadline {
            let now = Instant::now();
            let time_us = now.duration_since(start).as_micros();
            let delta_us = now.duration_since(prev_time).as_micros();
            prev_time = now;

            for (idx, dev) in &devices {
                if let Ok(peak) = dev.meter.GetPeakValue() {
                    println!(
                        "{}\t{}\t{}\t{:.6}\t{}",
                        time_us, idx, dev.name, peak, delta_us
                    );
                }
            }
            samples += 1;

            // No sleep — poll as fast as the OS will let us
            // (yields to other threads via the syscall overhead of GetPeakValue)
        }

        let elapsed = start.elapsed().as_secs_f64();
        let rate = samples as f64 / elapsed;
        eprintln!(
            "Done: {} samples in {:.2}s = {:.0} Hz effective poll rate",
            samples, elapsed, rate
        );

        CoUninitialize();
    }
}
