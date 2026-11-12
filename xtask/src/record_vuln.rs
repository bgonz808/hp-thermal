//! `cargo xtask record-vuln` — the in-repo writer of `supply-chain/evidence/<tool>/<digest>/vuln.jsonl`.
//!
//! Until now the vuln baseline was written by a scratch script that took the scanner's digest as a
//! FLAG, so the header could name an instrument other than the one that ran (it did, once, on
//! 2026-11-12; caught by a digest check before anything was gated). Code can make that mistake
//! impossible: this command hashes the auditor binary it is about to execute, refuses unless that
//! digest is the `cargo-audit` entry blessed in TOOLS.lock, runs it, and writes the header from
//! what it measured. Nothing about the instrument is typed by a human.
//!
//! Output: the baseline (header + one row per advisory instance, same row shape the gate's
//! `extract_instances` reads) and the raw payload file named by its own sha256, ready for the
//! content-addressed `tools` release store (the monitor's rawPayload custody check reads it).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

use crate::gate::parse_tools_lock;

fn today_utc() -> String {
    crate::eox::fmt_days(crate::eox::today_days())
}

/// `cargo-audit X.Y.Z` -> `X.Y.Z`; anything else is refused (the version is part of the record).
fn auditor_version(exe: &Path) -> Result<String, String> {
    let out = Command::new(exe)
        .arg("--version")
        .output()
        .map_err(|e| format!("cannot run {}: {e}", exe.display()))?;
    let text = String::from_utf8_lossy(&out.stdout);
    let v = text
        .split_whitespace()
        .nth(1)
        .unwrap_or("")
        .trim()
        .to_string();
    if !v.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        return Err(format!(
            "{}: unexpected --version output {text:?}",
            exe.display()
        ));
    }
    Ok(v)
}

/// The rows the gate reads, in a stable order.
pub fn instance_rows(audit: &Value) -> Vec<Value> {
    let mut rows = Vec::new();
    let mut push = |e: &Value, kind: &str| {
        let adv = e.get("advisory");
        let id = adv
            .and_then(|a| a.get("id"))
            .and_then(Value::as_str)
            .unwrap_or(kind);
        let aliases = adv
            .and_then(|a| a.get("aliases"))
            .cloned()
            .unwrap_or_else(|| Value::Array(vec![]));
        if let (Some(p), Some(v)) = (
            e.pointer("/package/name").and_then(Value::as_str),
            e.pointer("/package/version").and_then(Value::as_str),
        ) {
            rows.push(serde_json::json!({"id": id, "aliases": aliases, "package": p, "version": v, "kind": kind}));
        }
    };
    for e in audit
        .pointer("/vulnerabilities/list")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        push(e, "vulnerability");
    }
    if let Some(w) = audit.get("warnings").and_then(Value::as_object) {
        for (kind, arr) in w {
            for e in arr.as_array().into_iter().flatten() {
                push(e, kind);
            }
        }
    }
    rows.sort_by_key(|r| {
        (
            r["id"].as_str().unwrap_or("").to_string(),
            r["package"].as_str().unwrap_or("").to_string(),
            r["version"].as_str().unwrap_or("").to_string(),
        )
    });
    rows
}

/// Build the header from MEASURED facts only.
/// Everything the header states about the instrument and the input, all measured by this command.
pub struct Measured<'a> {
    pub tool: &'a str,
    pub digest: &'a str,
    pub scanner_version: &'a str,
    pub scanner_digest: &'a str,
    pub lock_sha256: &'a str,
    pub lock_provenance: &'a str,
    pub raw_sha256: &'a str,
}

pub fn header(m: &Measured<'_>, audit: &Value) -> Result<Value, String> {
    let Measured {
        tool,
        digest,
        scanner_version,
        scanner_digest,
        lock_sha256,
        lock_provenance,
        raw_sha256,
    } = *m;
    let db_commit = audit
        .pointer("/database/last-commit")
        .and_then(Value::as_str);
    let db_updated = audit
        .pointer("/database/last-updated")
        .and_then(Value::as_str);
    let (Some(db_commit), Some(db_updated)) = (db_commit, db_updated) else {
        return Err("audit report carries no database commit/timestamp (a --no-fetch report?) — the baseline must name its DB state".into());
    };
    Ok(serde_json::json!({
        "schema": "hp-thermal/evidence-vuln/v1",
        "subject": {"name": tool, "sha256": digest},
        "scanner": {
            "uri": "github.com/rustsec/rustsec#cargo-audit",
            "version": scanner_version,
            "digest": scanner_digest,
            "db": {"uri": "github.com/rustsec/advisory-db", "version": db_commit, "lastUpdate": db_updated},
        },
        "scanFinishedOn": today_utc(),
        "lockProvenance": format!("{lock_provenance} (lock sha256 {lock_sha256})"),
        "rawPayload": {"sha256": raw_sha256, "store": "tools release", "asset": format!("audit-raw-{}.json", &raw_sha256[..12])},
    }))
}

pub fn run(args: &[String]) -> i32 {
    let mut tool = String::new();
    let mut digest = String::new();
    let mut auditor: Option<PathBuf> = None;
    let mut lock: Option<PathBuf> = None;
    let mut tools_lock = PathBuf::from("tools/TOOLS.lock");
    let mut evidence = PathBuf::from("supply-chain/evidence");
    let mut provenance = String::new();
    let mut out_raw: Option<PathBuf> = None;
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--tool" => tool = it.next().cloned().unwrap_or_default(),
            "--digest" => digest = it.next().cloned().unwrap_or_default(),
            "--auditor" => auditor = it.next().map(PathBuf::from),
            "--lock" => lock = it.next().map(PathBuf::from),
            "--tools-lock" => tools_lock = it.next().map(PathBuf::from).unwrap_or(tools_lock),
            "--evidence" => evidence = it.next().map(PathBuf::from).unwrap_or(evidence),
            "--lock-provenance" => provenance = it.next().cloned().unwrap_or_default(),
            "--out-raw" => out_raw = it.next().map(PathBuf::from),
            other => {
                eprintln!("record-vuln: unknown argument {other}");
                return 2;
            }
        }
    }
    let (Some(auditor), Some(lock), Some(out_raw)) = (auditor, lock, out_raw) else {
        eprintln!(
            "usage: xtask record-vuln --tool <name> --digest <sha256> --auditor <cargo-audit exe> --lock <Cargo.lock> --out-raw <dir> [--lock-provenance TEXT] [--tools-lock P] [--evidence D]"
        );
        return 2;
    };
    if tool.is_empty() || digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        eprintln!("record-vuln: --tool and a full 64-hex --digest are required");
        return 2;
    }

    // 1. The instrument's identity is MEASURED and must be the blessed frontier auditor.
    let bytes = match std::fs::read(&auditor) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("record-vuln: {}: {e}", auditor.display());
            return 1;
        }
    };
    let scanner_digest = crate::sha256::sha256_hex(&bytes);
    let pins = match std::fs::read_to_string(&tools_lock) {
        Ok(t) => parse_tools_lock(&t),
        Err(e) => {
            eprintln!("record-vuln: {}: {e}", tools_lock.display());
            return 1;
        }
    };
    let blessed: Vec<&str> = pins
        .iter()
        .filter(|p| p.name == "cargo-audit")
        .map(|p| p.sha.as_str())
        .collect();
    if !blessed.contains(&scanner_digest.as_str()) {
        eprintln!(
            "record-vuln: REFUSED — {} has sha256 {scanner_digest}, which is not the blessed cargo-audit in {} ({}). Fetch the frontier auditor from the tools store; a baseline must name the instrument that actually ran.",
            auditor.display(),
            tools_lock.display(),
            if blessed.is_empty() {
                "no entry".to_string()
            } else {
                blessed.join(", ")
            }
        );
        return 1;
    }
    let scanner_version = match auditor_version(&auditor) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("record-vuln: {e}");
            return 1;
        }
    };

    // 2. Scan (fetching the DB: the baseline must name a DB commit).
    let lock_bytes = match std::fs::read(&lock) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("record-vuln: {}: {e}", lock.display());
            return 1;
        }
    };
    let lock_sha = crate::sha256::sha256_hex(&lock_bytes);
    let out = match Command::new(&auditor)
        .args(["audit", "--json", "--file"])
        .arg(&lock)
        .env_remove("RUSTUP_TOOLCHAIN")
        .env_remove("CARGO")
        .env_remove("RUSTC")
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            eprintln!("record-vuln: cannot run {}: {e}", auditor.display());
            return 1;
        }
    };
    // cargo-audit exits non-zero when it has findings; parse failure is the error signal.
    let raw = out.stdout;
    let audit: Value = match serde_json::from_slice(&raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "record-vuln: auditor output is not JSON ({e}); stderr: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            return 1;
        }
    };
    let raw_sha = crate::sha256::sha256_hex(&raw);
    let measured = Measured {
        tool: &tool,
        digest: &digest,
        scanner_version: &scanner_version,
        scanner_digest: &scanner_digest,
        lock_sha256: &lock_sha,
        lock_provenance: &provenance,
        raw_sha256: &raw_sha,
    };
    let hdr = match header(&measured, &audit) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("record-vuln: {e}");
            return 1;
        }
    };
    let rows = instance_rows(&audit);

    // 3. Write the baseline and the raw payload (content-addressed name).
    let dir = evidence.join(&tool).join(&digest);
    if let Err(e) = std::fs::create_dir_all(&dir).and_then(|_| std::fs::create_dir_all(&out_raw)) {
        eprintln!("record-vuln: mkdir: {e}");
        return 1;
    }
    let mut text = String::new();
    text.push_str(&hdr.to_string());
    text.push('\n');
    for r in &rows {
        text.push_str(&r.to_string());
        text.push('\n');
    }
    let asset = out_raw.join(
        hdr["rawPayload"]["asset"]
            .as_str()
            .unwrap_or("audit-raw.json"),
    );
    if let Err(e) =
        std::fs::write(dir.join("vuln.jsonl"), text).and_then(|_| std::fs::write(&asset, &raw))
    {
        eprintln!("record-vuln: write: {e}");
        return 1;
    }
    let by_kind: BTreeMap<&str, usize> = rows.iter().fold(BTreeMap::new(), |mut m, r| {
        *m.entry(r["kind"].as_str().unwrap_or("?")).or_default() += 1;
        m
    });
    println!(
        "record-vuln: {tool} {}: scanner cargo-audit {scanner_version} {} (measured, blessed); db {}; {} instance(s) {:?}; wrote {} and {}",
        &digest[..12],
        &scanner_digest[..12],
        &hdr["scanner"]["db"]["version"].as_str().unwrap_or("?")[..12],
        rows.len(),
        by_kind,
        dir.join("vuln.jsonl").display(),
        asset.display()
    );
    println!(
        "upload: gh release upload tools {} --clobber",
        asset.display()
    );
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_is_built_from_measured_facts_and_refuses_a_db_less_report() {
        let audit = serde_json::json!({"database": {"last-commit": "abcdef1234567890", "last-updated": "2026-11-12T00:00:00Z"},
            "vulnerabilities": {"count": 0, "list": []}, "warnings": {}});
        let (a, b, c, d) = (
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
            "d".repeat(64),
        );
        let m = Measured {
            tool: "t",
            digest: &a,
            scanner_version: "0.22.2",
            scanner_digest: &b,
            lock_sha256: &c,
            lock_provenance: "frozen lock",
            raw_sha256: &d,
        };
        let h = header(&m, &audit).unwrap();
        assert_eq!(h["scanner"]["digest"], "b".repeat(64));
        assert_eq!(h["scanner"]["version"], "0.22.2");
        assert_eq!(h["rawPayload"]["asset"], "audit-raw-dddddddddddd.json");
        assert!(
            h["lockProvenance"]
                .as_str()
                .unwrap()
                .contains(&"c".repeat(64))
        );
        let no_db =
            serde_json::json!({"database": null, "vulnerabilities": {"count": 0, "list": []}});
        assert!(header(&m, &no_db).is_err());
    }

    #[test]
    fn rows_cover_vulns_and_every_warning_kind_in_a_stable_order() {
        let audit = serde_json::json!({
            "vulnerabilities": {"list": [{"advisory": {"id": "RUSTSEC-2026-0002", "aliases": ["CVE-1"]}, "package": {"name": "b", "version": "1"}}]},
            "warnings": {"unmaintained": [{"advisory": {"id": "RUSTSEC-2024-0001"}, "package": {"name": "a", "version": "2"}}],
                         "yanked": [{"package": {"name": "c", "version": "3"}}]}
        });
        let rows = instance_rows(&audit);
        let ids: Vec<&str> = rows.iter().map(|r| r["id"].as_str().unwrap()).collect();
        assert_eq!(ids, ["RUSTSEC-2024-0001", "RUSTSEC-2026-0002", "yanked"]);
        assert_eq!(rows[1]["aliases"], serde_json::json!(["CVE-1"]));
        assert_eq!(rows[2]["kind"], "yanked");
    }
}
