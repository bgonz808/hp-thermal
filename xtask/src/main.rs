//! Cross-platform dev tooling for hp-thermal. Pure std, no shell/PowerShell.
//!
//! `xtask` itself runs on any OS. The checks it invokes that *compile the app*
//! need Windows (the app is Windows-only); the artifact checks (deny/audit) and
//! `verify-hardening` (byte-level PE parsing) run anywhere.

use std::process::{Command, exit};

/// The app crate lives in a sibling directory; xtask shells into it so app's
/// build-std/nightly config applies (it's scoped to app/.cargo/config.toml).
const APP_DIR: &str = "app";
const RELEASE_EXE: &str = "app/target/x86_64-pc-windows-msvc/release/hp-thermal.exe";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("ci") => cmd_ci(args.iter().any(|a| a == "--fast")),
        Some("verify-hardening") => cmd_verify_hardening(args.get(1).map(String::as_str)),
        Some("capabilities") => cmd_capabilities(args.get(1).map(String::as_str)),
        _ => {
            eprintln!("usage: cargo xtask <command>");
            eprintln!("  ci [--fast]              run checks (fast = fmt + clippy + test)");
            eprintln!("  verify-hardening [EXE]   check PE exploit-mitigation flags");
            eprintln!("  capabilities [EXE]       list imported DLLs; fail on network APIs");
            2
        }
    };
    exit(code);
}

/// Run a step, streaming its output. Returns true on success.
fn step(desc: &str, dir: &str, program: &str, args: &[&str]) -> bool {
    eprintln!("\n=== {desc} ===");
    match Command::new(program)
        .current_dir(dir)
        .env_remove("RUSTUP_TOOLCHAIN")
        .args(args)
        .status()
    {
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
    ok &= step(
        "clippy (default)",
        APP_DIR,
        "cargo",
        &["clippy", "--", "-D", "warnings"],
    );
    ok &= step(
        "clippy (noise-adapt)",
        APP_DIR,
        "cargo",
        &[
            "clippy",
            "--features",
            "noise-adapt",
            "--",
            "-D",
            "warnings",
        ],
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
    ok &= step(
        "audit shipped binary",
        ".",
        "cargo",
        &["audit", "bin", RELEASE_EXE],
    );
    ok &= cmd_verify_hardening(Some(RELEASE_EXE)) == 0;
    ok &= cmd_capabilities(Some(RELEASE_EXE)) == 0;

    finish(ok)
}

fn finish(ok: bool) -> i32 {
    eprintln!(
        "\n{}",
        if ok {
            "all checks passed"
        } else {
            "CHECKS FAILED"
        }
    );
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

/// Capability baseline via the PE import table. hp-thermal is a LOCAL thermal tool,
/// so it must not link networking APIs. Prints the imported DLLs (a capability
/// manifest) and FAILS if any network-capable DLL is present — catching a
/// supply-chain compromise that adds telemetry/exfil, which a valid signature and an
/// up-to-date SBOM would pass (the injected code is signed and in the dep tree, but
/// it changed what the binary can *do*).
fn cmd_capabilities(exe: Option<&str>) -> i32 {
    let path = exe.unwrap_or(RELEASE_EXE);
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("capabilities: cannot read {path} ({e})");
            return 1;
        }
    };
    let Some(mut dlls) = pe_imported_dlls(&bytes) else {
        eprintln!("capabilities: {path} is not a walkable PE image");
        return 1;
    };
    dlls.sort();
    dlls.dedup();
    println!("Imported DLLs ({}) ({path}):", dlls.len());
    for d in &dlls {
        println!("  {d}");
    }
    // Network-capable DLLs a purely-local tool must never import. rpcrt4/ole32/combase
    // are deliberately NOT here — COM/WMI use them locally.
    const NET_DLLS: &[&str] = &[
        "ws2_32.dll",
        "wsock32.dll",
        "mswsock.dll",
        "winhttp.dll",
        "wininet.dll",
        "urlmon.dll",
        "dnsapi.dll",
    ];
    let hits: Vec<&str> = dlls
        .iter()
        .map(String::as_str)
        .filter(|d| NET_DLLS.contains(d))
        .collect();
    if hits.is_empty() {
        println!("capabilities: OK — no network-capable imports");
        0
    } else {
        eprintln!("capabilities: FAIL — unexpected network import(s): {hits:?}");
        eprintln!("  a local thermal tool must not link networking APIs (possible injection)");
        1
    }
}

/// Parse the PE import directory and return the imported DLL names (lowercased).
/// Pure byte parsing; `None` if the image can't be walked.
fn pe_imported_dlls(b: &[u8]) -> Option<Vec<String>> {
    let pe = u32::from_le_bytes(b.get(0x3C..0x40)?.try_into().ok()?) as usize;
    if b.get(pe..pe + 4)? != b"PE\0\0" {
        return None;
    }
    let num_sections = u16::from_le_bytes(b.get(pe + 6..pe + 8)?.try_into().ok()?) as usize;
    let opt_size = u16::from_le_bytes(b.get(pe + 20..pe + 22)?.try_into().ok()?) as usize;
    let opt = pe + 24;
    let magic = u16::from_le_bytes(b.get(opt..opt + 2)?.try_into().ok()?);
    // Data directories start at opt+96 (PE32) or opt+112 (PE32+); import = entry #1.
    let datadir = opt + if magic == 0x20B { 112 } else { 96 };
    let import_rva =
        u32::from_le_bytes(b.get(datadir + 8..datadir + 12)?.try_into().ok()?) as usize;
    if import_rva == 0 {
        return Some(Vec::new());
    }
    // Map an RVA to a file offset via the section table (follows the optional header).
    let sections = opt + opt_size;
    let rva_to_off = |rva: usize| -> Option<usize> {
        for i in 0..num_sections {
            let sh = sections + i * 40;
            let vsz = u32::from_le_bytes(b.get(sh + 8..sh + 12)?.try_into().ok()?) as usize;
            let va = u32::from_le_bytes(b.get(sh + 12..sh + 16)?.try_into().ok()?) as usize;
            let raw = u32::from_le_bytes(b.get(sh + 16..sh + 20)?.try_into().ok()?) as usize;
            let ptr = u32::from_le_bytes(b.get(sh + 20..sh + 24)?.try_into().ok()?) as usize;
            if rva >= va && rva < va + vsz.max(raw) {
                return Some(ptr + (rva - va));
            }
        }
        None
    };
    // Walk the IMAGE_IMPORT_DESCRIPTOR array (20 bytes each; Name RVA at +12).
    let mut off = rva_to_off(import_rva)?;
    let mut dlls = Vec::new();
    for _ in 0..4096 {
        let first_thunk = u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?);
        let name_rva = u32::from_le_bytes(b.get(off + 12..off + 16)?.try_into().ok()?) as usize;
        if first_thunk == 0 && name_rva == 0 {
            break; // null terminator
        }
        if let Some(no) = rva_to_off(name_rva) {
            let rest = b.get(no..)?;
            let len = rest.iter().position(|&c| c == 0).unwrap_or(rest.len());
            if let Ok(s) = std::str::from_utf8(&rest[..len]) {
                dlls.push(s.to_ascii_lowercase());
            }
        }
        off += 20;
    }
    Some(dlls)
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
