//! `cargo xtask verify-caps` — per-binary capability-manifest gate (#245).
//!
//! The BINARY vantage of the #241 caps axis: measure a shipped binary's IMPORT SURFACE
//! against a committed manifest of what it's *allowed* to import, and fail closed on any
//! divergence.
//!
//! WHAT THIS DOES AND DOES NOT PROVE (read before quoting a caps result as assurance):
//! the import table is a LOWER BOUND on capability, never an exhaustive account of what
//! the binary can do. Three ways code acts outside it:
//!   * direct syscalls — a stub that issues a syscall by number imports nothing, so the
//!     table shows no trace of it (a standard malware technique, not an exotic one);
//!   * dynamic resolution — GetProcAddress/LoadLibrary reach code the table never names.
//!     DYN_APIS + expected_dynamic bound *that dynamic resolution happens at all*, which
//!     is weaker than bounding what it reaches;
//!   * imported != called, so the surface also overstates in the other direction.
//! So the honest claim is CHANGE DETECTION, not containment: an exact-match ratchet over
//! a statically visible surface means a delta is always real and always reviewed. It does
//! not mean the binary is limited to what the manifest lists. Real containment is an OS
//! enforcing the policy at runtime (the pledge/seccomp/AppContainer shape below); we
//! measure and gate, we do not confine. Complements cackle's SOURCE vantage (#50): a
//! build-time injection invisible in source (malicious build.rs, linked C) surfaces
//! here as an undeclared import. The universal shape — declared manifest + enforcer
//! that fails closed on the undeclared — is pledge/unveil, seccomp, AppContainer, WASI.
//!
//! One engine, every binary we produce: the producer gates each tool before upload,
//! release-attest gates hp-thermal.exe. Manifests live in supply-chain/policy/caps/
//! (policy, separate from measured evidence). NO MANIFEST = FAIL (fail-secure, #241 §3):
//! absence is never a skip. Authoring is ergonomic despite standalone manifests — a
//! missing manifest prints a PROPOSED one (the measured surface) to review + commit,
//! same "commit the printed thing = sign-off" UX as the gate's ack lines.
//!
//! Manifests are JSON (parsed by serde_json, xtask's one dep — no second parser, and
//! the propose-flow means humans review machine-authored manifests rather than hand-
//! writing TOML). Two-sided policy: an allowlist with an EXACT-MATCH ratchet (off-list
//! import fails AND a stale allow entry fails, so the surface can only shrink
//! deliberately) plus a denylist of injection/exfil primitives that must be absent.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::{pe_delay_imported_dlls, pe_imported_dlls, pe_imported_functions};

/// Injection/exfil primitives a normal local tool never imports. A compromised build
/// adding one is caught even though the host DLL (kernel32/ntdll) is already allowed —
/// the DLL is allowlisted, but the *function* changes what the binary can do. Seeds a
/// proposed manifest's deny_functions; a manifest may extend it, never shrink below it.
const BASELINE_DENY: &[&str] = &[
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

/// Dynamic-resolution APIs. Legitimate here (the tray loads nvml on demand), so they are
/// declared in `expected_dynamic` and any UNEXPECTED one fails — the source denylist (B4)
/// vets *what* gets loaded; this bounds *that* dynamic resolution happens at all.
const DYN_APIS: &[&str] = &[
    "loadlibraryw",
    "loadlibrarya",
    "loadlibraryexw",
    "loadlibraryexa",
    "getprocaddress",
    "ldrloaddll",
    "ldrgetprocedureaddress",
];

struct Measured {
    dlls: BTreeSet<String>,
    functions: BTreeSet<String>,
}

/// Walk a PE's full import surface (static DLLs + delay-load DLLs + named functions),
/// lowercased. `None` if the bytes are not a walkable PE.
fn measure_pe(bytes: &[u8]) -> Option<Measured> {
    let mut dlls: BTreeSet<String> = pe_imported_dlls(bytes)?.into_iter().collect();
    dlls.extend(pe_delay_imported_dlls(bytes).unwrap_or_default());
    let functions: BTreeSet<String> = pe_imported_functions(bytes)
        .unwrap_or_default()
        .into_iter()
        .map(|f| f.to_ascii_lowercase())
        .collect();
    Some(Measured { dlls, functions })
}

// ---- manifest (JSON, navigated as Value; serde derive stays off) ----

fn arr(v: &Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Emit a proposed manifest from the measured surface, for review + commit. Concrete
/// DLLs go to allow_imports; MS OS API-sets (version suffix shifts across toolchains) go
/// to allow_import_prefixes; observed dynamic APIs to expected_dynamic; deny starts at the
/// baseline. The human tightens, never has to author from scratch.
fn propose(binary: &str, m: &Measured) -> String {
    let (mut allow, mut prefixes) = (Vec::new(), BTreeSet::new());
    for d in &m.dlls {
        if d.starts_with("api-ms-win-") {
            prefixes.insert("api-ms-win-");
        } else if d.starts_with("ext-ms-win-") {
            prefixes.insert("ext-ms-win-");
        } else {
            allow.push(d.clone());
        }
    }
    let expected_dynamic: Vec<&str> = DYN_APIS
        .iter()
        .copied()
        .filter(|f| m.functions.contains(*f))
        .collect();
    serde_json::to_string_pretty(&serde_json::json!({
        "schema": "hp-thermal/caps-manifest/v1",
        "binary": binary,
        "format": "pe",
        "allow_imports": allow,
        "allow_import_prefixes": prefixes.into_iter().collect::<Vec<_>>(),
        "deny_functions": BASELINE_DENY,
        "expected_dynamic": expected_dynamic,
    }))
    .unwrap_or_default()
}

struct Violations(Vec<String>);

/// Check the measured surface against the manifest. Fail-closed on ALL of:
/// off-allowlist import; STALE allow entry (imported-nothing → ratchet, surface shrinks
/// only); denied function present; unexpected dynamic-resolution API. Deny is enforced as
/// a superset of BASELINE_DENY regardless of what the manifest lists (can't weaken below
/// baseline).
fn check(m: &Measured, manifest: &Value) -> Violations {
    let allow: BTreeSet<String> = arr(manifest, "allow_imports").into_iter().collect();
    let prefixes = arr(manifest, "allow_import_prefixes");
    let mut deny: BTreeSet<String> = arr(manifest, "deny_functions").into_iter().collect();
    deny.extend(BASELINE_DENY.iter().map(|s| s.to_string()));
    let expected_dyn: BTreeSet<String> = arr(manifest, "expected_dynamic").into_iter().collect();

    let allowed = |d: &str| allow.contains(d) || prefixes.iter().any(|p| d.starts_with(p));
    let mut v = Vec::new();

    // off-allowlist imports (capability GREW)
    for d in &m.dlls {
        if !allowed(d) {
            v.push(format!("off-allowlist import: {d}"));
        }
    }
    // stale allow entries (surface SHRANK — ratchet must be tightened; else the upper
    // bound over-permits a silent future regression). Prefixes are exempt (they float).
    for a in &allow {
        if !m.dlls.contains(a) {
            v.push(format!(
                "stale allow_imports entry (no longer imported): {a}"
            ));
        }
    }
    // denied functions present (injection/exfil primitive — possible tamper)
    for f in &m.functions {
        if deny.contains(f) {
            v.push(format!("denied function imported: {f}"));
        }
    }
    // unexpected dynamic resolution
    for f in &m.functions {
        if DYN_APIS.contains(&f.as_str()) && !expected_dyn.contains(f) {
            v.push(format!("undeclared dynamic-resolution API: {f}"));
        }
    }
    Violations(v)
}

/// Default manifest path for a binary name, under the policy tree.
fn manifest_path(binary: &str) -> PathBuf {
    PathBuf::from("supply-chain/policy/caps").join(format!("{binary}.json"))
}

/// Derive a binary's manifest name from its path stem (hp-thermal.exe -> hp-thermal).
fn binary_name(path: &Path) -> String {
    path.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string()
}

pub fn run(binary: Option<&str>, manifest: Option<&str>) -> i32 {
    let Some(binary) = binary else {
        eprintln!("usage: cargo xtask verify-caps <binary> [--manifest <path>]");
        return 2;
    };
    let bin_path = Path::new(binary);
    let name = binary_name(bin_path);
    let bytes = match std::fs::read(bin_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("verify-caps: cannot read {binary}: {e}");
            return 1;
        }
    };
    // Fail-closed: unparseable binary is never "clean".
    let Some(m) = measure_pe(&bytes) else {
        eprintln!("verify-caps: {binary} is not a walkable PE (fail-closed)");
        return 1;
    };

    let mpath = manifest
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest_path(&name));
    let manifest_val: Value = match std::fs::read_to_string(&mpath) {
        Ok(t) => match serde_json::from_str(&t) {
            Ok(v) => v,
            Err(e) => {
                eprintln!(
                    "verify-caps: {} is not valid JSON: {e} (fail-closed)",
                    mpath.display()
                );
                return 1;
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // NO MANIFEST = FAIL, but print a proposal so authoring is one reviewed commit.
            eprintln!(
                "verify-caps: FAIL — no manifest at {} (fail-secure: absence is never a skip).\n\
                 Review the proposed manifest below and, if correct, commit it there:\n",
                mpath.display()
            );
            println!("{}", propose(&name, &m));
            return 1;
        }
        Err(e) => {
            eprintln!("verify-caps: read {}: {e}", mpath.display());
            return 1;
        }
    };

    let Violations(v) = check(&m, &manifest_val);
    if v.is_empty() {
        println!(
            "verify-caps: OK — {} import(s) within manifest {} (allowlist exact-match, no denied \
             functions, dynamic resolution declared)",
            m.dlls.len(),
            mpath.display()
        );
        0
    } else {
        eprintln!(
            "verify-caps: FAIL — {} manifest violation(s) for {name}:",
            v.len()
        );
        for line in &v {
            eprintln!("  - {line}");
        }
        eprintln!(
            "  a shipped binary must match its committed capability manifest exactly; update \
             {} only for a deliberate, reviewed capability change.",
            mpath.display()
        );
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(dlls: &[&str], funcs: &[&str]) -> Measured {
        Measured {
            dlls: dlls.iter().map(|s| s.to_string()).collect(),
            functions: funcs.iter().map(|s| s.to_string()).collect(),
        }
    }
    fn manifest(json: &str) -> Value {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn clean_binary_passes() {
        let meas = m(
            &["kernel32.dll", "api-ms-win-crt-runtime-l1-1-0.dll"],
            &["getprocaddress"],
        );
        let man = manifest(
            r#"{"allow_imports":["kernel32.dll"],"allow_import_prefixes":["api-ms-win-"],
                "expected_dynamic":["getprocaddress"]}"#,
        );
        assert!(check(&meas, &man).0.is_empty());
    }

    #[test]
    fn off_allowlist_import_fails() {
        let meas = m(&["kernel32.dll", "winhttp.dll"], &[]);
        let man = manifest(r#"{"allow_imports":["kernel32.dll"]}"#);
        let v = check(&meas, &man).0;
        assert!(
            v.iter()
                .any(|x| x.contains("off-allowlist import: winhttp.dll"))
        );
    }

    #[test]
    fn stale_allow_entry_fails_ratchet() {
        // allowlist permits a DLL the binary no longer imports -> surface shrank, ratchet.
        let meas = m(&["kernel32.dll"], &[]);
        let man = manifest(r#"{"allow_imports":["kernel32.dll","ole32.dll"]}"#);
        let v = check(&meas, &man).0;
        assert!(
            v.iter()
                .any(|x| x.contains("stale allow_imports entry") && x.contains("ole32.dll"))
        );
    }

    #[test]
    fn denied_function_fails_even_on_allowed_dll() {
        // kernel32 is allowlisted, but importing a denied primitive from it is caught.
        let meas = m(&["kernel32.dll"], &["writeprocessmemory"]);
        let man = manifest(r#"{"allow_imports":["kernel32.dll"]}"#);
        let v = check(&meas, &man).0;
        assert!(
            v.iter()
                .any(|x| x.contains("denied function imported: writeprocessmemory"))
        );
    }

    #[test]
    fn deny_cannot_be_weakened_below_baseline() {
        // manifest omits the denylist entirely — BASELINE_DENY still enforced.
        let meas = m(&["kernel32.dll"], &["createremotethread"]);
        let man = manifest(r#"{"allow_imports":["kernel32.dll"],"deny_functions":[]}"#);
        let v = check(&meas, &man).0;
        assert!(v.iter().any(|x| x.contains("createremotethread")));
    }

    #[test]
    fn undeclared_dynamic_resolution_fails() {
        let meas = m(&["kernel32.dll"], &["loadlibraryw"]);
        let man = manifest(r#"{"allow_imports":["kernel32.dll"],"expected_dynamic":[]}"#);
        let v = check(&meas, &man).0;
        assert!(
            v.iter()
                .any(|x| x.contains("undeclared dynamic-resolution API: loadlibraryw"))
        );
    }

    #[test]
    fn proposal_splits_apisets_into_prefixes() {
        let meas = m(
            &["kernel32.dll", "api-ms-win-crt-heap-l1-1-0.dll"],
            &["getprocaddress"],
        );
        let p = propose("t", &meas);
        let v: Value = serde_json::from_str(&p).unwrap();
        let allow: Vec<String> = super::arr(&v, "allow_imports");
        let pre: Vec<String> = super::arr(&v, "allow_import_prefixes");
        assert_eq!(allow, vec!["kernel32.dll"]);
        assert!(pre.contains(&"api-ms-win-".to_string()));
        // baseline deny present; observed dynamic API captured
        assert!(super::arr(&v, "deny_functions").contains(&"createremotethread".to_string()));
        assert!(super::arr(&v, "expected_dynamic").contains(&"getprocaddress".to_string()));
    }
}
