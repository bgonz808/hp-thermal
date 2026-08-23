//! Cross-platform dev tooling for hp-thermal. Pure std, no shell/PowerShell.
//!
//! `xtask` itself runs on any OS. The checks it invokes that *compile the app*
//! need Windows (the app is Windows-only); the artifact checks (deny/audit) and
//! `verify-hardening` (byte-level PE parsing) run anywhere.

use std::process::{Command, exit};

// DEV-ONLY (#61): reconfigures the live service to a virtual account, tests, auto-reverts.
// Lives only in xtask (never in the release binary). Windows-only (SCM FFI), gated so xtask
// stays cross-platform. See vsa.rs.
#[cfg(windows)]
mod vsa;

// #241: the 3-axis candidate-evaluation gate (TOOLS.lock bumps vs the per-digest
// evidence store). Policy-as-code: the verdict algebra lives here, unit-tested,
// not in workflow bash. See gate.rs.
mod gate;

// #245: per-binary capability-manifest gate (binary vantage of the #241 caps axis).
// Measures a binary's import surface against a committed manifest, fails closed on
// divergence. One engine for every binary we produce (tools + releases). See caps.rs.
mod caps;

// #241/#239: candidate ENUMERATION (discovery) for the promotion pipeline. Proposes
// per-line representatives with soak + tier facts; promotes nothing. See explore.rs.
mod explore;

// #226/#241: knowledge-delta loop for the vuln axis — same bytes, newer advisory DB.
// Read-only, writes nothing (observations are recomputable; decisions live in acks).
mod monitor;

// #241: turn an explored candidate into a REPRODUCIBLE build input (frozen resolved
// lock). The promotion pipeline's trust boundary — discovery may float, builds never do.
mod freeze;

/// The app crate lives in a sibling directory; xtask shells into it so app's
/// build-std/nightly config applies (it's scoped to app/.cargo/config.toml).
const APP_DIR: &str = "app";
const RELEASE_EXE: &str = "app/target/x86_64-pc-windows-msvc/release/hp-thermal.exe";
/// build.rs names the pdb hp-thermal.pdb AT THE SOURCE (/PDB + /PDBALTPATH from CARGO_PKG_NAME,
/// #168), matching the exe basename — no rename anywhere. This is the build-output name.
const RELEASE_PDB: &str = "app/target/x86_64-pc-windows-msvc/release/hp-thermal.pdb";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("ci") => cmd_ci(args.iter().any(|a| a == "--fast")),
        Some("release-attest") => cmd_release_attest(),
        Some("verify-hardening") => cmd_verify_hardening(args.get(1).map(String::as_str)),
        Some("capabilities") => cmd_capabilities(args.get(1).map(String::as_str)),
        Some("verify-artifact") => cmd_verify_artifact(
            args.get(1).map(String::as_str),
            args.get(2).map(String::as_str),
        ),
        Some("stamp-time") => cmd_stamp_time(
            args.get(1).map(String::as_str),
            args.get(2).map(String::as_str),
        ),
        Some("verify-timestamp") => cmd_verify_timestamp(
            args.get(1).map(String::as_str),
            args.get(2).map(String::as_str),
        ),
        Some("audit-dll-closure") => cmd_audit_dll_closure(args.get(1).map(String::as_str)),
        Some("audit-dll-planting") => cmd_audit_dll_planting(
            args.get(1).map(String::as_str),
            args.get(2).map(String::as_str),
        ),
        Some("gate") => gate::run(&args),
        Some("explore") => explore::run(&args),
        Some("monitor-vuln") => monitor::run(&args),
        Some("freeze") => freeze::run(&args),
        Some("verify-caps") => caps::run(args.get(1).map(String::as_str), {
            // optional --manifest <path>
            let mut mpath = None;
            let mut it = args.iter();
            while let Some(a) = it.next() {
                if a == "--manifest" {
                    mpath = it.next().map(String::as_str);
                }
            }
            mpath
        }),
        #[cfg(windows)]
        Some("vsa-spike") => vsa::run(&args[1..]),
        _ => {
            eprintln!("usage: cargo xtask <command>");
            eprintln!("  ci [--fast]              run checks (fast = fmt + clippy + test)");
            eprintln!(
                "  release-attest           production-artifact checks only (deny, auditable build, audit bin, verify-artifact)"
            );
            eprintln!("  verify-hardening [EXE]   check PE exploit-mitigation flags");
            eprintln!(
                "  capabilities [EXE]       list imports (+ delay-load); fail off the golden allowlist"
            );
            eprintln!(
                "  verify-artifact [EXE] [PDB]  hardening + capabilities + exe<->pdb GUID bind"
            );
            eprintln!(
                "  stamp-time [EXE] [EPOCH]  reconcile ALL PE timestamps to EPOCH (else SOURCE_DATE_EPOCH)"
            );
            eprintln!(
                "  verify-timestamp [EXE] [CEIL]  fail if PE timestamps are implausible/inconsistent"
            );
            eprintln!(
                "  audit-dll-closure [EXE]  flag non-KnownDLL transitive imports (DLL-plant surface, #106)"
            );
            eprintln!(
                "  audit-dll-planting [EXE] [DLL]  DEV: plant a forwarding proxy, test run-dir load (#106)"
            );
            eprintln!(
                "  gate --base <TOOLS.lock>  3-axis candidate gate vs supply-chain/evidence (#241)"
            );
            eprintln!("  verify-caps <EXE> [--manifest <p>]  per-binary caps manifest gate (#245)");
            eprintln!(
                "  vsa-spike [--recover]    DEV #61: test the service under a virtual account (elevated)"
            );
            2
        }
    };
    exit(code);
}

/// IMAGE_DEBUG_TYPE_REPRO — the `/Brepro` marker that declares the COFF TimeDateStamp a
/// build-id hash rather than a time. We neutralize it (see cmd_stamp_time).
const IMAGE_DEBUG_TYPE_REPRO: u32 = 0x10;

/// File offsets of every timestamp-bearing field in the PE, discovered by parsing (offsets
/// shift every build, so nothing is hardcoded). Shared by stamp-time (writer) and
/// verify-timestamp (reader) so they agree on exactly which fields exist.
struct PeTsFields {
    coff_ts: usize,            // COFF FileHeader.TimeDateStamp (PE+8)
    debug_entries: Vec<usize>, // file offset of each IMAGE_DEBUG_DIRECTORY entry (ts at +4, type at +12)
    rsrc_ts: Option<usize>,    // IMAGE_RESOURCE_DIRECTORY.TimeDateStamp, if a resource dir exists
}

fn pe_timestamp_fields(b: &[u8]) -> Option<PeTsFields> {
    let pe = u32::from_le_bytes(b.get(0x3C..0x40)?.try_into().ok()?) as usize;
    if b.get(pe..pe + 4)? != b"PE\0\0" {
        return None;
    }
    let opt = pe + 24;
    let magic = u16::from_le_bytes(b.get(opt..opt + 2)?.try_into().ok()?);
    let datadir = opt + if magic == 0x20B { 112 } else { 96 }; // PE32+ vs PE32
    // Debug directory = data dir #6; walk its 28-byte entries.
    let dbg = datadir + 6 * 8;
    let dbg_rva = u32::from_le_bytes(b.get(dbg..dbg + 4)?.try_into().ok()?) as usize;
    let dbg_size = u32::from_le_bytes(b.get(dbg + 4..dbg + 8)?.try_into().ok()?) as usize;
    let mut debug_entries = Vec::new();
    // pe_rva_to_off returns None for rva 0, so no separate zero-guard is needed.
    if let Some(dbg_off) = pe_rva_to_off(b, dbg_rva) {
        for i in 0..(dbg_size / 28) {
            let e = dbg_off + i * 28;
            if b.get(e..e + 28).is_some() {
                debug_entries.push(e);
            }
        }
    }
    // Resource directory = data dir #2; IMAGE_RESOURCE_DIRECTORY.TimeDateStamp is at +4.
    let rsrc = datadir + 2 * 8;
    let rsrc_rva = u32::from_le_bytes(b.get(rsrc..rsrc + 4)?.try_into().ok()?) as usize;
    let rsrc_ts = if rsrc_rva != 0 {
        pe_rva_to_off(b, rsrc_rva).map(|o| o + 4)
    } else {
        None
    };
    Some(PeTsFields {
        coff_ts: pe + 8,
        debug_entries,
        rsrc_ts,
    })
}

/// Parse an epoch from the arg, else SOURCE_DATE_EPOCH. `None` if neither is a valid u32-range epoch.
fn epoch_arg_or_env(epoch: Option<&str>) -> Option<u32> {
    epoch
        .and_then(|s| s.trim().parse::<u64>().ok())
        .or_else(|| {
            std::env::var("SOURCE_DATE_EPOCH")
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
        })
        .filter(|&e| e <= u32::MAX as u64)
        .map(|e| e as u32)
}

/// #104/#109: reconcile EVERY PE timestamp field to a deterministic, plausible epoch (the commit
/// date), replacing the `/Brepro` content-hash that link.exe writes (link.exe has no `/TIMESTAMP`,
/// so this is post-link). Patches the COFF `TimeDateStamp` AND each debug-directory entry's
/// timestamp, and ZEROES the `IMAGE_DEBUG_TYPE_REPRO` entry so nothing still declares the field a
/// build-id hash (leaving it would ship a now-stale self-hash and a COFF-vs-debug-dir mismatch —
/// the exact timestomp tell). Result mimics a normal deterministic-timestamp build. MUST run
/// BEFORE any hash/sign/attest step. Reproducible: same commit -> same epoch -> same bytes.
fn cmd_stamp_time(exe: Option<&str>, epoch: Option<&str>) -> i32 {
    let path = exe.unwrap_or(RELEASE_EXE);
    let Some(epoch) = epoch_arg_or_env(epoch) else {
        eprintln!(
            "stamp-time: no valid epoch (pass EPOCH arg or set SOURCE_DATE_EPOCH; must fit 32 bits)"
        );
        return 1;
    };
    let mut data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("stamp-time: read {path}: {e}");
            return 1;
        }
    };
    let Some(f) = pe_timestamp_fields(&data) else {
        eprintln!("stamp-time: {path} is not a parseable PE");
        return 1;
    };
    let le = epoch.to_le_bytes();
    let old = u32::from_le_bytes(data[f.coff_ts..f.coff_ts + 4].try_into().unwrap());

    // Snapshot for the bounded-transform proof, then collect the byte ranges we intend to touch.
    let pre = data.clone();
    let mut allowed: Vec<std::ops::Range<usize>> = Vec::new();
    allowed.push(f.coff_ts..f.coff_ts + 4);
    data[f.coff_ts..f.coff_ts + 4].copy_from_slice(&le);

    let (mut restamped, mut zeroed) = (0usize, 0usize);
    for &e in &f.debug_entries {
        let ty = u32::from_le_bytes(data[e + 12..e + 16].try_into().unwrap());
        match ty {
            IMAGE_DEBUG_TYPE_REPRO => {
                data[e..e + 28].fill(0); // neutralize: null entry, tools skip type-0
                allowed.push(e..e + 28);
                zeroed += 1;
            }
            0 => {} // already-null entry (idempotent re-run) — leave it
            _ => {
                data[e + 4..e + 8].copy_from_slice(&le);
                allowed.push(e + 4..e + 8);
                restamped += 1;
            }
        }
    }

    // Bounded-transform proof: REFUSE to write if any changed byte falls outside the fields we
    // meant to touch. Makes "only the timestamp fields moved" a fail-closed, logged invariant
    // (idempotent: a re-run changes zero bytes and passes).
    let stray: Vec<usize> = (0..data.len())
        .filter(|&i| data[i] != pre[i] && !allowed.iter().any(|r| r.contains(&i)))
        .collect();
    if !stray.is_empty() {
        eprintln!(
            "stamp-time: REFUSING to write — {} byte(s) changed OUTSIDE the timestamp fields: {stray:?}",
            stray.len()
        );
        return 1;
    }
    if let Err(e) = std::fs::write(path, &data) {
        eprintln!("stamp-time: write {path}: {e}");
        return 1;
    }
    let (y, mo, d) = civil_date(epoch);
    eprintln!(
        "stamp-time: {path}  COFF 0x{old:08X} -> 0x{epoch:08X} ({y:04}-{mo:02}-{d:02}); \
         restamped {restamped} debug entr(ies), zeroed {zeroed} repro marker(s)"
    );
    0
}

/// #109 consumer gate: fail-closed on an implausible OR inconsistent PE timestamp on the SHIPPED
/// bytes. Plausibility: COFF TimeDateStamp must be non-zero and inside [project floor, now+skew]
/// (catches a zeroed field, an unstamped `/Brepro` hash — random/pre-project year — or a
/// future date). Consistency: every non-null debug-dir entry must equal the COFF stamp, no
/// `IMAGE_DEBUG_TYPE_REPRO` marker may survive, and the resource-dir stamp must be 0 or match.
/// Together they prove stamp-time actually reconciled every field. Runs ONLY on the post-stamp
/// artifact (dist/), never in the pre-stamp `ci` pass. Ceiling overridable via arg / SOURCE_DATE_EPOCH.
fn cmd_verify_timestamp(exe: Option<&str>, ceiling: Option<&str>) -> i32 {
    // hp-thermal's root commit (2026-07-22). No legitimate build predates the source; a rebased
    // root would trip this loudly (bump the constant), never pass silently.
    const FIRST_COMMIT_EPOCH: u32 = 1_784_744_572;
    const SKEW: u32 = 172_800; // 2 days: build->verify gap + clock skew

    let path = exe.unwrap_or(RELEASE_EXE);
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("verify-timestamp: read {path}: {e}");
            return 1;
        }
    };
    let Some(f) = pe_timestamp_fields(&data) else {
        eprintln!("verify-timestamp: {path} is not a parseable PE");
        return 1;
    };
    let coff = u32::from_le_bytes(data[f.coff_ts..f.coff_ts + 4].try_into().unwrap());
    let ceiling = epoch_arg_or_env(ceiling)
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs().min(u32::MAX as u64) as u32)
                .unwrap_or(u32::MAX)
        })
        .saturating_add(SKEW);

    let mut ok = true;
    let (y, mo, d) = civil_date(coff);
    // --- Plausibility (COFF header) ---
    if coff == 0 {
        eprintln!("verify-timestamp: FAIL — COFF TimeDateStamp is 0 (zeroed / not stamped)");
        ok = false;
    } else if coff < FIRST_COMMIT_EPOCH {
        eprintln!(
            "verify-timestamp: FAIL — COFF 0x{coff:08X} = {y:04}-{mo:02}-{d:02} predates the \
             project (floor 0x{FIRST_COMMIT_EPOCH:08X}); likely an unstamped /Brepro hash"
        );
        ok = false;
    } else if coff > ceiling {
        eprintln!(
            "verify-timestamp: FAIL — COFF 0x{coff:08X} = {y:04}-{mo:02}-{d:02} is future-dated \
             (ceiling 0x{ceiling:08X})"
        );
        ok = false;
    }
    // --- Consistency (debug dir + resource dir vs COFF) ---
    for (i, &e) in f.debug_entries.iter().enumerate() {
        let ty = u32::from_le_bytes(data[e + 12..e + 16].try_into().unwrap());
        let ts = u32::from_le_bytes(data[e + 4..e + 8].try_into().unwrap());
        if ty == IMAGE_DEBUG_TYPE_REPRO {
            eprintln!(
                "verify-timestamp: FAIL — debug entry #{i} is a surviving REPRO marker (0x10)"
            );
            ok = false;
        } else if ty != 0 && ts != coff {
            eprintln!(
                "verify-timestamp: FAIL — debug entry #{i} (type {ty}) ts 0x{ts:08X} != COFF 0x{coff:08X}"
            );
            ok = false;
        }
    }
    if let Some(r) = f.rsrc_ts {
        let rts = u32::from_le_bytes(data[r..r + 4].try_into().unwrap());
        if rts != 0 && rts != coff {
            eprintln!(
                "verify-timestamp: FAIL — resource-dir ts 0x{rts:08X} is neither 0 nor COFF 0x{coff:08X}"
            );
            ok = false;
        }
    }
    if ok {
        println!(
            "verify-timestamp: OK — COFF + {} debug entr(ies) all = 0x{coff:08X} ({y:04}-{mo:02}-{d:02}), \
             plausible, no REPRO marker",
            f.debug_entries.len()
        );
        0
    } else {
        1
    }
}

/// UTC (year, month, day) from a Unix timestamp — compact civil-calendar decode (Hinnant's
/// algorithm), for legible check messages. No chrono dependency. Valid across the u32 PE range.
fn civil_date(epoch: u32) -> (i64, u32, u32) {
    let z = (epoch / 86400) as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Run a step, streaming its output. Returns true on success.
fn step(desc: &str, dir: &str, program: &str, args: &[&str]) -> bool {
    eprintln!("\n=== {desc} ===");
    // Toolchain-env scrub: when xtask itself runs under `cargo xtask`, the parent shim exports
    // CARGO/RUSTC pointing at the REAL binaries of whatever toolchain resolved at the parent's
    // cwd (repo root -> the default, often stable — rust-toolchain.toml lives in app/ only).
    // A child invoked as `cargo` re-resolves via the rustup shim per-cwd and is immune, but a
    // directly-invoked tool (#221 pinned binaries) honors the inherited CARGO env and silently
    // uses the WRONG toolchain (observed: stable cargo failing on panic-immediate-abort).
    // Scrubbing forces every child to resolve cargo/rustc via the shim at ITS cwd — the
    // committed rust-toolchain.toml decides, never ambient env.
    match Command::new(program)
        .current_dir(dir)
        .env_remove("RUSTUP_TOOLCHAIN")
        .env_remove("CARGO")
        .env_remove("RUSTC")
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

// #192: two semantically distinct tiers. `ci` proves SOURCE quality (what PR CI and the
// pre-commit hook need); `release-attest` proves PRODUCTION ARTIFACT quality (what the
// release pipeline needs). `ci` without --fast still runs both, so its behavior is
// unchanged; release.yml switching to `release-attest` alone is #196 (gated on the #191
// provenance-verified source gate).
fn cmd_ci(fast: bool) -> i32 {
    let mut ok = ci_source_checks();
    if fast {
        return finish(ok);
    }
    ok &= release_attest_checks();
    finish(ok)
}

fn cmd_release_attest() -> i32 {
    finish(release_attest_checks())
}

/// Source-quality tier: format, lint, test — both feature configs.
fn ci_source_checks() -> bool {
    let mut ok = true;
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
    ok
}

/// #221: run a `cargo-<sub>` tool with zero ambient authority. With PINNED_TOOLS_DIR set
/// (CI: the digest-verified prebuilt dir from .github/actions/fetch-tools), the tool binary
/// is invoked by ABSOLUTE PATH — no PATH lookup, nothing shadowable. The argv is identical
/// either way: cargo itself executes `cargo-<sub>` with the subcommand name as argv[1], so
/// the same args slice works for both (verified against the pinned exes for deny/auditable/
/// audit). Unset (local dev): fall back to `cargo <sub>` resolution.
fn cargo_tool_step(desc: &str, cwd: &str, args: &[&str]) -> bool {
    match std::env::var("PINNED_TOOLS_DIR") {
        Ok(dir) => {
            let exe = format!("{dir}/cargo-{}{}", args[0], std::env::consts::EXE_SUFFIX);
            step(desc, cwd, &exe, args)
        }
        Err(_) => step(desc, cwd, "cargo", args),
    }
}

/// Production-artifact tier: supply-chain policy + artifact attestation. Run in release.yml
/// (which fetches the digest-pinned prebuilt tools, #138/#221). osv-scanner is
/// intentionally NOT invoked here — RustSec exports to OSV in real time, so cargo-deny/
/// cargo-audit already cover it; continuous scanning is Dependabot's job off-workflow.
/// Run `osv-scanner --lockfile=app/Cargo.lock` locally if you want the extra cross-check.
fn release_attest_checks() -> bool {
    let mut ok = true;
    ok &= cargo_tool_step("cargo-deny", APP_DIR, &["deny", "check"]);
    // xtask grew a real dependency tree (serde_json, for the #241 gate), so it gets
    // the SAME policy + advisory checks as the app tree — under app's deny config
    // (one shared policy, no drift) and the same pinned auditor. The toolchain that
    // attests the release must itself be clean.
    ok &= cargo_tool_step(
        "cargo-deny (xtask tree, shared policy)",
        ".",
        &[
            "deny",
            "--manifest-path",
            "xtask/Cargo.toml",
            "--config",
            "app/deny.toml",
            "check",
        ],
    );
    ok &= cargo_tool_step(
        "audit xtask lockfile",
        ".",
        &["audit", "--file", "xtask/Cargo.lock"],
    );
    ok &= cargo_tool_step(
        "auditable release build",
        APP_DIR,
        &["auditable", "build", "--release"],
    );
    ok &= cargo_tool_step("audit shipped binary", ".", &["audit", "bin", RELEASE_EXE]);
    ok &= cmd_verify_artifact(Some(RELEASE_EXE), Some(RELEASE_PDB)) == 0;
    ok
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

/// Capability baseline via the PE import table (static + delay-load). hp-thermal is a
/// LOCAL thermal tool, so it must import ONLY a vetted set of OS DLLs. Prints the imports
/// (a capability manifest) and FAILS on anything off the golden allowlist — catching a
/// supply-chain compromise that adds telemetry/exfil (e.g. winhttp), which a valid
/// signature and an up-to-date SBOM would pass: the injected code is signed and in the
/// dep tree, but it changed what the binary can *do*.
///
/// The allowlist is a function of CRT linkage + feature set, NOT opt-level/LTO (those only
/// drop imports, never add): a dynamic/hybrid CRT (#32) reintroduces ucrtbase/vcruntime/
/// api-ms-win-crt-* and MUST update ALLOWED; `--features noise-adapt` adds audio DLLs.
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
    dlls.extend(pe_delay_imported_dlls(&bytes).unwrap_or_default());
    dlls.sort();
    dlls.dedup();
    println!("Imported DLLs ({}) ({path}):", dlls.len());
    for d in &dlls {
        println!("  {d}");
    }
    // Golden allowlist: the shipped static-CRT, default-features build imports ONLY these
    // concrete OS DLLs. MS OS API-sets (api-ms-win-* / ext-ms-win-*) are allowed by prefix
    // because their version suffix shifts across toolchain bumps but they are OS-provided.
    const ALLOWED: &[&str] = &[
        "advapi32.dll",
        "combase.dll",
        "comctl32.dll",
        "gdi32.dll",
        "kernel32.dll",
        "ntdll.dll",
        "ole32.dll",
        "oleaut32.dll",
        "powrprof.dll",
        "rstrtmgr.dll",
        "shell32.dll",
        "user32.dll",
    ];
    let allowed = |d: &str| {
        ALLOWED.contains(&d) || d.starts_with("api-ms-win-") || d.starts_with("ext-ms-win-")
    };
    // EXACT-MATCH ratchet: the concrete-DLL surface must equal ALLOWED, not merely be a subset.
    //   * off_list — imported but NOT allowed  => capability GREW (supply-chain / feature creep).
    //   * stale    — allowed but NOT imported  => surface SHRANK; ALLOWED must be tightened to lock
    //                the smaller surface in, else the upper-bound over-permits a silent regression.
    let imported: std::collections::HashSet<&str> = dlls.iter().map(String::as_str).collect();
    let off_list: Vec<&str> = dlls
        .iter()
        .map(String::as_str)
        .filter(|d| !allowed(d))
        .collect();
    let stale: Vec<&str> = ALLOWED
        .iter()
        .copied()
        .filter(|a| !imported.contains(a))
        .collect();
    if off_list.is_empty() && stale.is_empty() {
        println!(
            "capabilities: OK — imports EXACTLY match the golden allowlist (no network/unknown DLLs)"
        );
        0
    } else {
        if !off_list.is_empty() {
            eprintln!("capabilities: FAIL — off-allowlist import(s): {off_list:?}");
            eprintln!("  a shipped build must import only the vetted OS set; a new entry is a");
            eprintln!(
                "  capability change — update ALLOWED only for a deliberate CRT/feature change."
            );
        }
        if !stale.is_empty() {
            eprintln!("capabilities: FAIL — allowlist entr(ies) no longer imported: {stale:?}");
            eprintln!("  the surface shrank — REMOVE these from ALLOWED to ratchet the posture");
            eprintln!(
                "  (an upper-bound allowlist that over-permits lets the capability regress)."
            );
        }
        1
    }
}

/// Parse a PE import-style directory and return the referenced DLL names (lowercased).
/// `dir_index` selects the data directory (1 = imports, 13 = delay-load); descriptors are
/// `desc_size` bytes each with the DLL-name RVA at `name_off`. An all-zero descriptor
/// terminates the array. Pure byte parsing; `None` if the image can't be walked.
fn pe_import_dir_dlls(
    b: &[u8],
    dir_index: usize,
    desc_size: usize,
    name_off: usize,
) -> Option<Vec<String>> {
    let pe = u32::from_le_bytes(b.get(0x3C..0x40)?.try_into().ok()?) as usize;
    if b.get(pe..pe + 4)? != b"PE\0\0" {
        return None;
    }
    let num_sections = u16::from_le_bytes(b.get(pe + 6..pe + 8)?.try_into().ok()?) as usize;
    let opt_size = u16::from_le_bytes(b.get(pe + 20..pe + 22)?.try_into().ok()?) as usize;
    let opt = pe + 24;
    let magic = u16::from_le_bytes(b.get(opt..opt + 2)?.try_into().ok()?);
    // Data directories start at opt+96 (PE32) or opt+112 (PE32+); each entry is 8 bytes
    // (RVA, size). Entry #1 = imports, #13 = delay-load.
    let datadir = opt + if magic == 0x20B { 112 } else { 96 };
    let entry = datadir + dir_index * 8;
    let dir_rva = u32::from_le_bytes(b.get(entry..entry + 4)?.try_into().ok()?) as usize;
    if dir_rva == 0 {
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
    let mut off = rva_to_off(dir_rva)?;
    let mut dlls = Vec::new();
    for _ in 0..4096 {
        let desc = b.get(off..off + desc_size)?;
        if desc.iter().all(|&x| x == 0) {
            break; // null-terminator descriptor
        }
        // Terminator already handled above; a real descriptor has a non-zero name RVA
        // (and rva_to_off(0) would return None regardless, so no guard is needed).
        let name_rva =
            u32::from_le_bytes(b.get(off + name_off..off + name_off + 4)?.try_into().ok()?)
                as usize;
        if let Some(no) = rva_to_off(name_rva) {
            let rest = b.get(no..)?;
            let len = rest.iter().position(|&c| c == 0).unwrap_or(rest.len());
            if let Ok(s) = std::str::from_utf8(&rest[..len]) {
                dlls.push(s.to_ascii_lowercase());
            }
        }
        off += desc_size;
    }
    Some(dlls)
}

/// Statically-imported DLLs (import directory #1; 20-byte descriptors, name RVA at +12).
pub(crate) fn pe_imported_dlls(b: &[u8]) -> Option<Vec<String>> {
    pe_import_dir_dlls(b, 1, 20, 12)
}

/// Delay-loaded DLLs (delay-import directory #13; 32-byte descriptors, name RVA at +4).
pub(crate) fn pe_delay_imported_dlls(b: &[u8]) -> Option<Vec<String>> {
    pe_import_dir_dlls(b, 13, 32, 4)
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

/// Consolidated artifact gate: exploit-mitigation flags + capability allowlist + the
/// exe<->pdb CodeView GUID/age bind. The pipeline-gate half of the assurance case — it
/// proves properties of the SHIPPED bytes (what the toolchain produced), complementing the
/// source-side checks. Run in `ci` and by the release verify job.
/// Assert the SHIPPED PE embeds the ComCtl32 v6 application manifest. TaskDialogIndirect lives
/// only in comctl32 v6, which the loader provides ONLY if the manifest declares
/// `Microsoft.Windows.Common-Controls` version 6.0.0.0. A silent resource-embed failure (e.g.
/// the Server-2025 runner dropping the whole resource) ships a binary that binds comctl32 v5
/// and crashes on launch ("entry point TaskDialogIndirect not found"). This checks the property
/// on the actual bytes -- mechanism-independent, so no build-tool failure can slip a
/// manifest-less binary through. Would have caught rc.2.
fn cmd_verify_manifest(exe_path: &str) -> i32 {
    let bytes = match std::fs::read(exe_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("verify-manifest: cannot read {exe_path} ({e})");
            return 1;
        }
    };
    // The manifest is embedded as UTF-8 XML in the RT_MANIFEST resource.
    let has = |needle: &str| bytes.windows(needle.len()).any(|w| w == needle.as_bytes());
    let name = has("Microsoft.Windows.Common-Controls");
    let ver = has("6.0.0.0");
    if name && ver {
        println!(
            "verify-manifest: OK -- ComCtl32 v6 dependency present (TaskDialogIndirect resolvable)"
        );
        0
    } else {
        eprintln!(
            "verify-manifest: FAIL -- embedded manifest missing the ComCtl32 v6 dependency \
             (name={name}, version-6.0.0.0={ver}). Binary would crash on launch \
             (TaskDialogIndirect not found) -- a resource-embed step was silently dropped."
        );
        1
    }
}

fn cmd_verify_artifact(exe: Option<&str>, pdb: Option<&str>) -> i32 {
    let exe_path = exe.unwrap_or(RELEASE_EXE);
    let pdb_path = pdb.unwrap_or(RELEASE_PDB);
    let mut ok = true;
    ok &= cmd_verify_hardening(Some(exe_path)) == 0;
    ok &= cmd_capabilities(Some(exe_path)) == 0;
    ok &= cmd_imports_scan(exe_path) == 0;
    // #245: manifest-driven caps gate on the SHIPPED bytes — the binary vantage that
    // applies the same engine to hp-thermal.exe as to every prebuilt tool. Runs
    // alongside cmd_capabilities during transition (the hp-thermal manifest is
    // byte-identical to that hardcoded allowlist, so they agree); once proven in CI,
    // cmd_capabilities + the imports-scan denylist retire into the manifest.
    ok &= caps::run(Some(exe_path), None) == 0;
    ok &= cmd_pdb_link(exe_path, pdb_path) == 0;
    ok &= cmd_verify_manifest(exe_path) == 0;
    if ok { 0 } else { 1 }
}

/// Assert the exe and its PDB belong together: the exe's CodeView debug-directory
/// {GUID, age} must equal the PDB info-stream {GUID, age}. Turns the debugger ecosystem's
/// best-effort match into an enforced check. Consistency, NOT authenticity — authenticity
/// is SHA256SUMS + the SLSA attestation.
fn cmd_pdb_link(exe_path: &str, pdb_path: &str) -> i32 {
    let exe = match std::fs::read(exe_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("pdb-link: cannot read {exe_path} ({e})");
            return 1;
        }
    };
    let pdb = match std::fs::read(pdb_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("pdb-link: cannot read {pdb_path} ({e})");
            return 1;
        }
    };
    let Some((ge, ae, name)) = pe_codeview(&exe) else {
        eprintln!("pdb-link: {exe_path} has no CodeView debug directory (was a PDB built?)");
        return 1;
    };
    let Some((gp, ap)) = pdb_guid_age(&pdb) else {
        eprintln!("pdb-link: {pdb_path} is not a parseable PDB (MSF 7.0)");
        return 1;
    };
    if ge == gp && ae == ap {
        println!(
            "pdb-link: OK — exe references {name}; GUID/age match ({}, age {ae})",
            guid_str(&ge)
        );
        0
    } else {
        eprintln!(
            "pdb-link: FAIL — exe {}/age {ae} != pdb {}/age {ap}",
            guid_str(&ge),
            guid_str(&gp)
        );
        1
    }
}

/// Function-level import scan. FAILS on high-risk injection/exfil primitives the tool
/// never uses (a compromised build adding them is caught even though the DLL — kernel32/
/// ntdll — is already allowlisted). REPORTS dynamic-resolution APIs (LoadLibrary/
/// GetProcAddress): those are legitimate here (the tray loads nvml.dll on demand), so they
/// are informational, not a gate. The source denylist (B4) vets *what* gets loaded; this
/// only surfaces that dynamic resolution happens.
fn cmd_imports_scan(exe_path: &str) -> i32 {
    let bytes = match std::fs::read(exe_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("imports-scan: cannot read {exe_path} ({e})");
            return 1;
        }
    };
    let Some(funcs) = pe_imported_functions(&bytes) else {
        eprintln!("imports-scan: {exe_path} import names not walkable");
        return 1;
    };
    let lower: Vec<String> = funcs.iter().map(|f| f.to_ascii_lowercase()).collect();
    let has = |n: &str| lower.iter().any(|f| f == n);

    // Injection/exfil primitives this tool never legitimately imports. (OpenProcess/
    // OpenProcessToken are NOT here — the pipe integrity check uses them benignly.)
    const HIGH_RISK: &[&str] = &[
        "createremotethread",
        "createremotethreadex",
        "writeprocessmemory",
        "virtualallocex",
        "virtualprotectex",
        "queueuserapc",
        "ntqueueapcthread",
        "setthreadcontext",
        "setwindowshookexw",
        "setwindowshookexa",
        "ntmapviewofsection",
        "rtlcreateuserthread",
        "winexec",
    ];
    let hits: Vec<&str> = HIGH_RISK.iter().copied().filter(|n| has(n)).collect();

    const DYN: &[&str] = &[
        "loadlibraryw",
        "loadlibrarya",
        "loadlibraryexw",
        "loadlibraryexa",
        "getprocaddress",
        "ldrloaddll",
        "ldrgetprocedureaddress",
    ];
    let dyn_hits: Vec<&str> = DYN.iter().copied().filter(|n| has(n)).collect();
    println!("imports-scan: dynamic-resolution present: {dyn_hits:?} (expected: nvml on-demand)");

    if hits.is_empty() {
        println!("imports-scan: OK — no high-risk injection/exfil imports");
        0
    } else {
        eprintln!("imports-scan: FAIL — high-risk import(s): {hits:?}");
        eprintln!("  injection/exfil primitives the tool never uses (possible tamper)");
        1
    }
}

/// #106: static gate for the T1574.001/.002 pre-main transitive-load class. Walks the exe's
/// static-import closure and flags any DLL that (a) is reached *transitively* — i.e. is NOT one
/// of our own direct imports, which `/DEPENDENTLOADFLAG:0x800` already pins to System32 — and
/// (b) is not a KnownDLL / api-set / loader-core DLL. Such a DLL resolves via the search path,
/// so a copy planted in a writable run dir can win over System32 before our runtime mitigations
/// execute. Regression-gates: fails on any flagged dep NOT in the accepted allowlist.
/// PRE-MAIN transitive deps we've reviewed and accepted (the plant surface — loaded before our
/// runtime pins). EMPTY: #106 deferred `rstrtmgr` to a lazy System32 load, removing `ncrypt` (its
/// former pre-main dep) from the static closure — so the gate now asserts ZERO pre-main plant
/// surface, and any new one fails CI. `umpdc`/`wmiclnt` (via `powrprof`) are DELAY imports →
/// runtime-pinned by SetDefaultDllDirectories, so not gated here.
const DLL_CLOSURE_ACCEPTED: &[&str] = &[];

fn cmd_audit_dll_closure(exe: Option<&str>) -> i32 {
    use std::collections::{HashSet, VecDeque};
    let path = exe.unwrap_or(RELEASE_EXE);
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("audit-dll-closure: read {path}: {e}");
            return 1;
        }
    };
    let Some(direct_raw) = pe_imported_dlls(&bytes) else {
        eprintln!("audit-dll-closure: {path} import table not walkable");
        return 1;
    };
    let known = load_known_dlls();
    // Exempt = cannot be planted from the app dir: api-sets are loader-resolved from the
    // schema; ntdll/kernelbase are mapped by the kernel before any search; KnownDLLs (and
    // their static closure) are forced from System32 by the loader.
    let exempt = |n: &str| {
        n.starts_with("api-ms-")
            || n.starts_with("ext-ms-")
            || n == "ntdll.dll"
            || n == "kernelbase.dll"
            || known.contains(n)
    };
    let direct: HashSet<String> = direct_raw.iter().map(|d| d.to_ascii_lowercase()).collect();
    // Our OWN delay imports (e.g. rstrtmgr/powrprof via build.rs /DELAYLOAD): declared but loaded
    // at first use — after our SetDefaultDllDirectories pin — so they seed the walk as pre_main=false.
    let delayed: HashSet<String> = pe_delay_imported_dlls(&bytes)
        .unwrap_or_default()
        .iter()
        .map(|d| d.to_ascii_lowercase())
        .collect();
    // Our own imports (regular + delay) are pinned/deferred by us — not transitive plant surface.
    let own: HashSet<String> = direct.union(&delayed).cloned().collect();

    // BFS the closure from our imports, tracking a `pre_main` flag: true means every edge from the
    // exe to this DLL is a REGULAR static import, so it resolves during process init (before main,
    // before our runtime pins). A DELAY edge anywhere (our own /DELAYLOAD, or a dependency's delay
    // import) defers the whole subtree to first-use — by then SetDefaultDllDirectories(SYSTEM32) is
    // live, so the plant window is closed. That split is the real severity: pre-main = plantable;
    // delay/runtime = pinned.
    let mut visited: HashSet<String> = HashSet::new();
    let mut flagged: Vec<(String, String, bool)> = Vec::new(); // (dll, via, pre_main)
    let mut q: VecDeque<(String, String, bool)> = direct
        .iter()
        .map(|d| (d.clone(), "<exe>".to_string(), true))
        .chain(
            delayed
                .iter()
                .map(|d| (d.clone(), "<exe> [delay]".to_string(), false)),
        )
        .collect();
    while let Some((dll, via, pre_main)) = q.pop_front() {
        if !visited.insert(dll.clone()) {
            continue;
        }
        if exempt(&dll) {
            continue; // protected closure — stop, don't recurse
        }
        // Non-exempt = search-path-resolvable. Flag it UNLESS it's one of OUR OWN imports (regular
        // ones are pinned by /DEPENDENTLOADFLAG; delay ones load post-pin from System32).
        if !own.contains(&dll) {
            flagged.push((dll.clone(), via.clone(), pre_main));
        }
        // Recurse: regular imports inherit pre_main; delay imports force the subtree to runtime.
        if let Ok(b) = std::fs::read(format!("C:\\Windows\\System32\\{dll}")) {
            for d in pe_imported_dlls(&b).unwrap_or_default() {
                q.push_back((d.to_ascii_lowercase(), dll.clone(), pre_main));
            }
            for d in pe_delay_imported_dlls(&b).unwrap_or_default() {
                q.push_back((d.to_ascii_lowercase(), dll.clone(), false));
            }
        }
    }

    flagged.sort();
    flagged.dedup();
    println!(
        "audit-dll-closure: {path}  ({} direct imports)",
        direct.len()
    );
    if flagged.is_empty() {
        println!("  closure clean — no transitive search-path deps");
        return 0;
    }
    // Only PRE-MAIN transitive deps are the plant surface (loaded before our runtime pins);
    // gate those against the allowlist. delay/rt deps load post-mitigation — reported for
    // completeness (the full runtime surface), not gated.
    let mut new_premain = 0;
    for (dll, via, pre_main) in &flagged {
        if *pre_main {
            let accepted = DLL_CLOSURE_ACCEPTED.contains(&dll.as_str());
            if !accepted {
                new_premain += 1;
            }
            println!(
                "  PRE-MAIN  {dll:<16} via {via:<14} [{}]",
                if accepted {
                    "accepted"
                } else {
                    "*** NEW — plantable ***"
                }
            );
        } else {
            println!("  delay/rt  {dll:<16} via {via:<14} (runtime-pinned)");
        }
    }
    if new_premain > 0 {
        eprintln!(
            "audit-dll-closure: FAIL — {new_premain} NEW pre-main transitive dep(s): plantable \
             before runtime mitigations. Defer the parent import or add to DLL_CLOSURE_ACCEPTED."
        );
        1
    } else {
        println!(
            "audit-dll-closure: OK — pre-main plant surface allow-listed; delay/rt deps pinned \
             by SetDefaultDllDirectories. (#106)"
        );
        0
    }
}

/// KnownDLLs from `HKLM\...\Session Manager\KnownDLLs` (lowercased, `.dll` suffix). The loader
/// forces these — and their static closure — from System32, so they cannot be planted. Uses
/// reg.exe to avoid a registry-crate dependency; empty set on failure (fails safe: more flags).
fn load_known_dlls() -> std::collections::HashSet<String> {
    let mut set = std::collections::HashSet::new();
    let out = std::process::Command::new("reg")
        .args([
            "query",
            r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs",
        ])
        .output();
    if let Ok(o) = out {
        for line in String::from_utf8_lossy(&o.stdout).lines() {
            // "  <name>    REG_SZ    <value>"; keep bare *.dll values, skip DllDirectory paths.
            if let Some(v) = line.split("REG_SZ").nth(1) {
                let v = v.trim().to_ascii_lowercase();
                if v.ends_with(".dll") && !v.contains('\\') {
                    set.insert(v);
                }
            }
        }
    }
    set
}

#[cfg(windows)]
unsafe extern "system" {
    fn SetErrorMode(mode: u32) -> u32;
}

/// #106 dynamic tier (DEV). Plant a BARE proxy DLL under a dependency's filename next to a
/// THROWAWAY copy of the exe and see whether the loader picks it up from the run dir. For a
/// DYNAMIC load (a dependency's runtime LoadLibrary), the loader runs the proxy's `.CRT$XCU` init
/// on load — writing a marker + the resolved loader stack — BEFORE any GetProcAddress, so no
/// export forwarding is needed (the target's later crypto call fails, but the load is already
/// recorded; we kill the process shortly after). The complementary STATIC gate (audit-dll-closure)
/// covers static-import re-introduction, so this tier need not forward. Deterministic, user-mode,
/// no admin/driver.
///
/// Exit codes are DISJOINT — a harness failure must never masquerade as a verdict:
///   1 = PLANTABLE (marker present), 0 = not plantable, 2 = INCONCLUSIVE (build/copy/spawn error).
fn cmd_audit_dll_planting(exe: Option<&str>, candidate: Option<&str>) -> i32 {
    const ERR: i32 = 2; // inconclusive — distinct from the 0/1 verdict codes
    let exe = exe.unwrap_or(RELEASE_EXE);
    let cand = candidate.unwrap_or("ncrypt.dll").to_ascii_lowercase();
    let probe_src = "tools/dll-plant-probe/probe.rs";
    if !std::path::Path::new(probe_src).exists() {
        eprintln!("audit-dll-planting: {probe_src} not found (run from repo root)");
        return ERR;
    }
    let base = cand.trim_end_matches(".dll");
    let dir = std::env::temp_dir().join(format!("hp-plant-{}-{base}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);

    // Build the BARE proxy cdylib named exactly <cand>. No `/DEF`: rustc's cdylib already emits its
    // own export .def, and passing a second one is what caused the earlier `link.exe` 1120 failure.
    // Forwarding is unnecessary for a dynamic load — the marker fires on attach, before any bind.
    let proxy = dir.join(&cand);
    let build = Command::new("rustc")
        .args([
            "--crate-type",
            "cdylib",
            "-O",
            "--target",
            "x86_64-pc-windows-msvc",
            "--edition",
            "2021",
        ])
        .arg(probe_src)
        .arg("-o")
        .arg(&proxy)
        .status();
    match build {
        Ok(s) if s.success() => {}
        other => {
            eprintln!("audit-dll-planting: proxy build failed ({other:?})");
            let _ = std::fs::remove_dir_all(&dir);
            return ERR;
        }
    }

    // Assemble the plant dir: throwaway exe copy + the proxy under the dependency's name.
    let target = dir.join("hp-thermal.exe");
    if let Err(e) = std::fs::copy(exe, &target) {
        eprintln!(
            "audit-dll-planting: copy exe -> temp failed ({e}). If os error 225, Defender \
             quarantined the copy — run on CI / an isolated VM (do not weaken Defender here)."
        );
        let _ = std::fs::remove_dir_all(&dir);
        return ERR;
    }

    let marker = dir.join("loaded.marker");
    let _ = std::fs::remove_file(&marker);

    // Suppress the hard-error dialog so a static-import bind failure (export-less proxy winning the
    // search) exits with its NTSTATUS instead of blocking on a modal box.
    #[cfg(windows)]
    // SAFETY: SetErrorMode only sets this process's (inherited) error-mode flags.
    unsafe {
        SetErrorMode(0x0001 | 0x0002 | 0x8000); // FAILCRITICALERRORS | NOGPFAULTERRORBOX | NOOPENFILEERRORBOX
    }

    // Run the throwaway copy; poll for an EARLY exit (static bind failure) up to the timeout, else
    // kill it (it ran normally).
    let spawned = Command::new(&target)
        .current_dir(&dir)
        .env("HP_PLANT_MARKER", &marker)
        .spawn();
    let mut child = match spawned {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "audit-dll-planting: spawn failed ({e}) — likely Defender (os 225). Run on CI."
            );
            let _ = std::fs::remove_dir_all(&dir);
            return ERR;
        }
    };
    let mut early: Option<i32> = None;
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(3000);
    loop {
        match child.try_wait() {
            Ok(Some(st)) => {
                early = st.code();
                break;
            }
            Ok(None) if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break;
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(100)),
            Err(_) => break,
        }
    }

    let loaded = marker.exists();
    // Read the probe's resolved module chain (loader stack) BEFORE cleanup wipes it.
    let chain = std::fs::read_to_string(&marker).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);

    // Two independent plantable signals:
    //   * marker present         -> a DYNAMIC LoadLibrary picked up our proxy (its init ran).
    //   * early exit w/ a loader  -> a STATIC-import bind failed because our export-less proxy won
    //     NTSTATUS (0xC00001xx)      the search (real ncrypt would have bound cleanly and run on).
    let static_hijack = early
        .map(|c| c as u32)
        .is_some_and(|c| matches!(c, 0xC0000135 | 0xC0000139 | 0xC000007B));
    if loaded || static_hijack {
        let how = if loaded {
            "dynamic load — marker fired"
        } else {
            "static bind failure — export-less proxy won the search"
        };
        println!("audit-dll-planting: {cand} *** LOADED from run dir *** — PLANTABLE ({how})");
        // Discovery tier (dynamic case only): the module chain names WHO pulled the planted DLL.
        let chain: Vec<&str> = chain.lines().skip(1).collect();
        if !chain.is_empty() {
            println!("  load chain (nearest caller first) — who pulled {cand}:");
            for m in &chain {
                println!("    {m}");
            }
        }
        1
    } else {
        println!("audit-dll-planting: {cand} not loaded from run dir — not plantable on this path");
        0
    }
}

/// Format a raw 16-byte CodeView/PDB GUID in the usual mixed-endian display form.
fn guid_str(g: &[u8; 16]) -> String {
    format!(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        u32::from_le_bytes([g[0], g[1], g[2], g[3]]),
        u16::from_le_bytes([g[4], g[5]]),
        u16::from_le_bytes([g[6], g[7]]),
        g[8],
        g[9],
        g[10],
        g[11],
        g[12],
        g[13],
        g[14],
        g[15]
    )
}

/// Map a PE RVA to a file offset via the section table. Self-contained (re-parses the
/// header) so debug/import walkers can share it. `None` if the RVA is 0 or unmapped.
fn pe_rva_to_off(b: &[u8], rva: usize) -> Option<usize> {
    if rva == 0 {
        return None;
    }
    let pe = u32::from_le_bytes(b.get(0x3C..0x40)?.try_into().ok()?) as usize;
    if b.get(pe..pe + 4)? != b"PE\0\0" {
        return None;
    }
    let num_sections = u16::from_le_bytes(b.get(pe + 6..pe + 8)?.try_into().ok()?) as usize;
    let opt_size = u16::from_le_bytes(b.get(pe + 20..pe + 22)?.try_into().ok()?) as usize;
    let opt = pe + 24;
    let sections = opt + opt_size;
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
}

/// Extract the CodeView RSDS record from the exe's debug directory (data dir #6):
/// (GUID bytes, age, pdb name). `None` if there is no CodeView entry.
fn pe_codeview(b: &[u8]) -> Option<([u8; 16], u32, String)> {
    let pe = u32::from_le_bytes(b.get(0x3C..0x40)?.try_into().ok()?) as usize;
    if b.get(pe..pe + 4)? != b"PE\0\0" {
        return None;
    }
    let opt = pe + 24;
    let magic = u16::from_le_bytes(b.get(opt..opt + 2)?.try_into().ok()?);
    let datadir = opt + if magic == 0x20B { 112 } else { 96 };
    let dbg = datadir + 6 * 8; // debug directory = data dir entry #6
    let dbg_rva = u32::from_le_bytes(b.get(dbg..dbg + 4)?.try_into().ok()?) as usize;
    let dbg_size = u32::from_le_bytes(b.get(dbg + 4..dbg + 8)?.try_into().ok()?) as usize;
    let dbg_off = pe_rva_to_off(b, dbg_rva)?;
    // Walk IMAGE_DEBUG_DIRECTORY entries (28 bytes); find Type==2 (CODEVIEW).
    for i in 0..(dbg_size / 28) {
        let e = dbg_off + i * 28;
        if u32::from_le_bytes(b.get(e + 12..e + 16)?.try_into().ok()?) != 2 {
            continue;
        }
        let size = u32::from_le_bytes(b.get(e + 16..e + 20)?.try_into().ok()?) as usize;
        let ptr = u32::from_le_bytes(b.get(e + 24..e + 28)?.try_into().ok()?) as usize;
        let cv = b.get(ptr..ptr + size)?;
        if cv.get(0..4)? != b"RSDS" {
            continue;
        }
        let mut guid = [0u8; 16];
        guid.copy_from_slice(cv.get(4..20)?);
        let age = u32::from_le_bytes(cv.get(20..24)?.try_into().ok()?);
        let name = cv.get(24..)?;
        let len = name.iter().position(|&c| c == 0).unwrap_or(name.len());
        return Some((
            guid,
            age,
            String::from_utf8_lossy(&name[..len]).into_owned(),
        ));
    }
    None
}

/// Extract {GUID, age} from a PDB (MSF 7.0) info stream (stream #1). Pure byte parsing.
fn pdb_guid_age(b: &[u8]) -> Option<([u8; 16], u32)> {
    const MAGIC: &[u8] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0";
    if b.get(0..MAGIC.len())? != MAGIC {
        return None;
    }
    let at = |o: usize| -> Option<usize> {
        Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?) as usize)
    };
    let block_size = at(32)?;
    let num_dir_bytes = at(44)?;
    let block_map = at(52)?;
    if block_size == 0 {
        return None;
    }
    let block =
        |idx: usize| -> Option<&[u8]> { b.get(idx * block_size..idx * block_size + block_size) };
    // Directory block indices live at the block-map block.
    let num_dir_blocks = num_dir_bytes.div_ceil(block_size);
    let map = block(block_map)?;
    let mut dir = Vec::new();
    for i in 0..num_dir_blocks {
        let idx = u32::from_le_bytes(map.get(i * 4..i * 4 + 4)?.try_into().ok()?) as usize;
        dir.extend_from_slice(block(idx)?);
    }
    dir.truncate(num_dir_bytes);
    // Stream directory: NumStreams, sizes[NumStreams], then per-stream block lists.
    let d = |o: usize| -> Option<usize> {
        Some(u32::from_le_bytes(dir.get(o..o + 4)?.try_into().ok()?) as usize)
    };
    let num_streams = d(0)?;
    let mut pos = 4;
    let mut sizes = Vec::with_capacity(num_streams);
    for _ in 0..num_streams {
        sizes.push(d(pos)?);
        pos += 4;
    }
    let mut s1_blocks = Vec::new();
    for (s, &size) in sizes.iter().enumerate() {
        let nblocks = if size == u32::MAX as usize {
            0
        } else {
            size.div_ceil(block_size)
        };
        if s == 1 {
            for i in 0..nblocks {
                s1_blocks.push(d(pos + i * 4)?);
            }
        }
        pos += nblocks * 4;
    }
    let s1_size = *sizes.get(1)?;
    let mut s1 = Vec::new();
    for &idx in &s1_blocks {
        s1.extend_from_slice(block(idx)?);
    }
    s1.truncate(s1_size);
    // PDB info stream: Version(u32), Signature(u32), Age(u32 @8), GUID(16 @12).
    let age = u32::from_le_bytes(s1.get(8..12)?.try_into().ok()?);
    let mut guid = [0u8; 16];
    guid.copy_from_slice(s1.get(12..28)?);
    Some((guid, age))
}

/// Imported FUNCTION names across the whole import directory. Ordinal-only imports (no
/// name) are skipped. Pure byte parsing; walks each descriptor's import-name-table thunks.
pub(crate) fn pe_imported_functions(b: &[u8]) -> Option<Vec<String>> {
    let pe = u32::from_le_bytes(b.get(0x3C..0x40)?.try_into().ok()?) as usize;
    if b.get(pe..pe + 4)? != b"PE\0\0" {
        return None;
    }
    let opt = pe + 24;
    let magic = u16::from_le_bytes(b.get(opt..opt + 2)?.try_into().ok()?);
    let pe32plus = magic == 0x20B;
    let datadir = opt + if pe32plus { 112 } else { 96 };
    let import_rva =
        u32::from_le_bytes(b.get(datadir + 8..datadir + 12)?.try_into().ok()?) as usize;
    if import_rva == 0 {
        return Some(Vec::new());
    }
    let thunk_size = if pe32plus { 8 } else { 4 };
    let ord_bit: u64 = if pe32plus { 1 << 63 } else { 1 << 31 };
    let mut off = pe_rva_to_off(b, import_rva)?;
    let mut funcs = Vec::new();
    for _ in 0..4096 {
        let desc = b.get(off..off + 20)?;
        if desc.iter().all(|&x| x == 0) {
            break;
        }
        let orig = u32::from_le_bytes(desc[0..4].try_into().ok()?) as usize;
        let first = u32::from_le_bytes(desc[16..20].try_into().ok()?) as usize;
        let ilt_rva = if orig != 0 { orig } else { first };
        if let Some(mut t) = pe_rva_to_off(b, ilt_rva) {
            for _ in 0..16384 {
                let val = if pe32plus {
                    u64::from_le_bytes(b.get(t..t + 8)?.try_into().ok()?)
                } else {
                    u32::from_le_bytes(b.get(t..t + 4)?.try_into().ok()?) as u64
                };
                if val == 0 {
                    break;
                }
                // Named import (ordinal-bit clear): low 31 bits = RVA to IMAGE_IMPORT_BY_NAME
                // (a u16 hint followed by the null-terminated name).
                if val & ord_bit == 0 {
                    let name_rva = (val & 0x7FFF_FFFF) as usize;
                    if let Some(no) = pe_rva_to_off(b, name_rva) {
                        let rest = b.get(no + 2..)?;
                        let len = rest.iter().position(|&c| c == 0).unwrap_or(rest.len());
                        if let Ok(s) = std::str::from_utf8(&rest[..len]) {
                            funcs.push(s.to_string());
                        }
                    }
                }
                t += thunk_size;
            }
        }
        off += 20;
    }
    Some(funcs)
}

#[cfg(test)]
mod tests {
    use super::civil_date;

    /// Independent, obviously-correct reference: walk forward from 1970-01-01 one day at a
    /// time, subtracting whole years then whole months. Structurally unlike `civil_date`
    /// (Hinnant's closed form), so a shared bug is implausible — agreement across every day
    /// in the range is the proof.
    fn ref_civil(epoch: u32) -> (i64, u32, u32) {
        let leap = |y: i64| (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        let mut days = (epoch / 86400) as i64;
        let mut y = 1970i64;
        loop {
            let yd = if leap(y) { 366 } else { 365 };
            if days < yd {
                break;
            }
            days -= yd;
            y += 1;
        }
        let md = [
            31,
            if leap(y) { 29 } else { 28 },
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
        let mut m = 0usize;
        while days >= md[m] as i64 {
            days -= md[m] as i64;
            m += 1;
        }
        (y, (m + 1) as u32, (days + 1) as u32)
    }

    /// Anchors hard-coded from an independent authority (`date -u -d @<epoch>`), including the
    /// leap-year edge cases: 2000 IS leap (÷400), 2100 is NOT (÷100 not ÷400), and the u32 ceiling.
    #[test]
    fn anchors_match_os_ground_truth() {
        assert_eq!(civil_date(0), (1970, 1, 1));
        assert_eq!(civil_date(1_784_744_572), (2026, 7, 22)); // repo's first commit
        assert_eq!(civil_date(1_785_526_818), (2026, 7, 31)); // HEAD stamp
        assert_eq!(civil_date(951_782_400), (2000, 2, 29)); // 2000 leap day
        assert_eq!(civil_date(4_107_456_000), (2100, 2, 28)); // 2100 not leap...
        assert_eq!(civil_date(4_107_542_400), (2100, 3, 1)); // ...so no 2100-02-29
        assert_eq!(civil_date(4_294_967_295), (2106, 2, 7)); // u32::MAX
    }

    /// Every day from 1970 to the u32 ceiling (~49710 days, year 2106) must match the
    /// independent reference. Exhaustive over the entire domain `civil_date` can be called with.
    #[test]
    fn matches_reference_every_day_in_u32_range() {
        let max_day = u32::MAX / 86400;
        for day in 0..=max_day {
            let e = day * 86400;
            assert_eq!(civil_date(e), ref_civil(e), "day {day}, epoch {e}");
        }
    }

    /// Any second within a day maps to the same date (we key on epoch/86400).
    #[test]
    fn intra_day_is_constant() {
        let base = 1_785_526_818 - (1_785_526_818 % 86400);
        for s in [0u32, 1, 3600, 43_200, 86_399] {
            assert_eq!(civil_date(base + s), (2026, 7, 31));
        }
    }
}
