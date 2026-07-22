//! Cross-platform dev tooling for hp-thermal. Pure std, no shell/PowerShell.
//!
//! `xtask` itself runs on any OS. The checks it invokes that *compile the app*
//! need Windows (the app is Windows-only); the artifact checks (deny/audit) and
//! `verify-hardening` (byte-level PE parsing) run anywhere.

use std::process::{exit, Command};

/// The app crate lives in a sibling directory; xtask shells into it so app's
/// build-std/nightly config applies (it's scoped to app/.cargo/config.toml).
const APP_DIR: &str = "app";
const RELEASE_EXE: &str = "app/target/x86_64-pc-windows-msvc/release/hp-thermal.exe";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("ci") => cmd_ci(args.iter().any(|a| a == "--fast")),
        Some("verify-hardening") => cmd_verify_hardening(args.get(1).map(String::as_str)),
        _ => {
            eprintln!("usage: cargo xtask <command>");
            eprintln!("  ci [--fast]              run checks (fast = fmt + clippy + test)");
            eprintln!("  verify-hardening [EXE]   check PE exploit-mitigation flags");
            2
        }
    };
    exit(code);
}

/// Run a step, streaming its output. Returns true on success.
fn step(desc: &str, dir: &str, program: &str, args: &[&str]) -> bool {
    eprintln!("\n=== {desc} ===");
    match Command::new(program).current_dir(dir).env_remove("RUSTUP_TOOLCHAIN").args(args).status() {
        Ok(s) if s.success() => true,
        Ok(s) => {
            eprintln!("FAIL: {desc} (exit {:?})", s.code());
            false
        }
        Err(e) => {
            eprintln!("FAIL: {desc} — cannot run `{program}` ({e})");
            false
        }
    }
}

fn cmd_ci(fast: bool) -> i32 {
    let mut ok = true;

    // Fast tier: format, lint, test — both feature configs.
    ok &= step("fmt", APP_DIR, "cargo", &["fmt", "--check"]);
    ok &= step("clippy (default)", APP_DIR, "cargo", &["clippy", "--", "-D", "warnings"]);
    ok &= step(
        "clippy (noise-adapt)",
        APP_DIR,
        "cargo",
        &["clippy", "--features", "noise-adapt", "--", "-D", "warnings"],
    );
    ok &= step("test (default)", APP_DIR, "cargo", &["test"]);
    ok &= step(
        "test (noise-adapt)",
        APP_DIR,
        "cargo",
        &["test", "--features", "noise-adapt"],
    );

    if fast {
        return finish(ok);
    }

    // Full tier: supply-chain policy + artifact attestation. Run in release.yml (which
    // installs cargo-deny + cargo-auditable + cargo-audit by git-rev). osv-scanner is
    // intentionally NOT invoked here — RustSec exports to OSV in real time, so cargo-deny/
    // cargo-audit already cover it; continuous scanning is Dependabot's job off-workflow.
    // Run `osv-scanner --lockfile=app/Cargo.lock` locally if you want the extra cross-check.
    ok &= step("cargo-deny", APP_DIR, "cargo", &["deny", "check"]);
    ok &= step(
        "auditable release build",
        APP_DIR,
        "cargo",
        &["auditable", "build", "--release"],
    );
    ok &= step("audit shipped binary", ".", "cargo", &["audit", "bin", RELEASE_EXE]);
    ok &= cmd_verify_hardening(Some(RELEASE_EXE)) == 0;

    finish(ok)
}

fn finish(ok: bool) -> i32 {
    eprintln!("\n{}", if ok { "all checks passed" } else { "CHECKS FAILED" });
    i32::from(!ok)
}

/// Read the PE `DllCharacteristics` field and report the exploit-mitigation flags.
/// Pure byte parsing — works on any OS.
fn cmd_verify_hardening(exe: Option<&str>) -> i32 {
    let path = exe.unwrap_or(RELEASE_EXE);
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("verify-hardening: cannot read {path} ({e})");
            return 1;
        }
    };
    let Some(dllc) = pe_dll_characteristics(&bytes) else {
        eprintln!("verify-hardening: {path} is not a valid PE image");
        return 1;
    };

    println!("PE DllCharacteristics: 0x{dllc:04X}  ({path})");
    let mut ok = true;
    for (name, bit) in [
        ("ASLR / DYNAMICBASE", 0x0040u16),
        ("High-entropy ASLR", 0x0020),
        ("DEP / NX", 0x0100),
        ("Control Flow Guard", 0x4000),
    ] {
        let set = dllc & bit != 0;
        println!("  [{}] {name}", if set { "x" } else { " " });
        ok &= set;
    }
    // Stack canaries (-Z stack-protector) are inline code, not a PE header bit.
    println!("  (-) stack canaries: not PE-header-visible; enforced via build config");
    if ok {
        0
    } else {
        eprintln!("verify-hardening: a mitigation flag is MISSING");
        1
    }
}

/// `DllCharacteristics` sits at optional-header offset 0x46 (70) for both PE32
/// and PE32+, so we don't need to branch on the magic beyond validating it.
fn pe_dll_characteristics(b: &[u8]) -> Option<u16> {
    let pe = u32::from_le_bytes(b.get(0x3C..0x40)?.try_into().ok()?) as usize;
    if b.get(pe..pe + 4)? != b"PE\0\0" {
        return None;
    }
    let opt = pe + 24; // 4-byte signature + 20-byte COFF header
    let magic = u16::from_le_bytes(b.get(opt..opt + 2)?.try_into().ok()?);
    if magic != 0x10B && magic != 0x20B {
        return None; // not PE32 / PE32+
    }
    let off = opt + 70;
    Some(u16::from_le_bytes(b.get(off..off + 2)?.try_into().ok()?))
}
