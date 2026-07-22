//! Stress test: validates CPU load generation.
//!
//! Spawns stress threads on all logical cores at BELOW_NORMAL priority,
//! runs for a configurable duration, and reports CPU temps via the service
//! pipe. Watch HWiNFO/Task Manager to verify sustained 100% utilization.
//!
//! Usage:
//!   cargo run --example stress_test --release          # 15 seconds
//!   cargo run --example stress_test --release -- 30    # 30 seconds
//!   cargo run --example stress_test --release -- 60 4  # 60 seconds, 4 threads only

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use windows::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
use windows::Win32::System::Threading::{
    GetCurrentThread, SetThreadPriority, THREAD_PRIORITY_BELOW_NORMAL,
};

fn logical_cpu_count() -> usize {
    let mut info: SYSTEM_INFO = unsafe { std::mem::zeroed() };
    unsafe { GetSystemInfo(&mut info) };
    info.dwNumberOfProcessors as usize
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let duration_secs: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(15);
    let ncpus = logical_cpu_count();
    let thread_count: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(ncpus);

    eprintln!("=== Stress Test ===");
    eprintln!("  Logical CPUs: {ncpus}");
    eprintln!("  Threads:      {thread_count}");
    eprintln!("  Duration:     {duration_secs}s");
    eprintln!("  Priority:     BELOW_NORMAL");
    eprintln!();
    eprintln!("Watch Task Manager or HWiNFO for CPU utilization + temps.");
    eprintln!("Press Ctrl+C to abort early.");
    eprintln!();

    let stop = Arc::new(AtomicBool::new(false));

    // Spawn stress threads
    let handles: Vec<_> = (0..thread_count)
        .map(|id| {
            let stop = stop.clone();
            std::thread::spawn(move || {
                unsafe {
                    let _ = SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
                }
                let mut a = (id as u64).wrapping_add(1);
                let mut b = (id as u64).wrapping_add(2);
                let mut c = (id as u64).wrapping_add(3);
                let mut d = (id as u64).wrapping_add(4);
                let mut batches = 0u64;

                while !stop.load(Ordering::Relaxed) {
                    for _ in 0..4096 {
                        a = a.wrapping_mul(0x5851F42D4C957F2D).wrapping_add(1);
                        b = b.wrapping_mul(0x14057B7EF767814F).wrapping_add(1);
                        c = c.wrapping_mul(0x5851F42D4C957F2D).wrapping_add(3);
                        d = d.wrapping_mul(0x14057B7EF767814F).wrapping_add(3);
                    }
                    std::hint::black_box(a);
                    std::hint::black_box(b);
                    std::hint::black_box(c);
                    std::hint::black_box(d);
                    batches += 1;
                }

                batches
            })
        })
        .collect();

    eprintln!("  [{:.1}s] All {thread_count} threads running", 0.0);

    let start = Instant::now();
    let deadline = start + Duration::from_secs(duration_secs);

    // Report progress every second
    let mut tick = 1u64;
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_secs(1));
        let elapsed = start.elapsed().as_secs_f64();
        eprintln!("  [{elapsed:.1}s] running... ({tick}/{duration_secs})");
        tick += 1;
    }

    // Stop all threads
    stop.store(true, Ordering::Relaxed);
    let mut total_batches = 0u64;
    for h in handles {
        if let Ok(b) = h.join() {
            total_batches += b;
        }
    }

    let elapsed = start.elapsed().as_secs_f64();
    let total_muls = total_batches * 4096 * 4; // 4 chains * 4096 per batch
    let muls_per_sec = total_muls as f64 / elapsed;

    eprintln!();
    eprintln!("=== Done ===");
    eprintln!("  Elapsed:    {elapsed:.1}s");
    eprintln!("  Batches:    {total_batches}");
    eprintln!(
        "  Throughput: {:.1}B muls/s ({:.1} Gmul/s)",
        muls_per_sec / 1e9,
        muls_per_sec / 1e9
    );
    eprintln!();
    eprintln!("If CPU utilization was NOT ~100% in Task Manager,");
    eprintln!("the stress loop may be getting optimized away.");
}
