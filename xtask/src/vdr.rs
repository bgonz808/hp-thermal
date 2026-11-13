//! `cargo xtask vdr emit|check --product <name> --digest <sha256> [--sbom <path>]` — the
//! CycloneDX 1.6 Vulnerability Disclosure Report (VDR) for one measured product (#396).
//!
//! Ruling (2026-11-11, #396): CycloneDX 1.6 VDR over SPDX for measurement records; every field
//! below is a CycloneDX field or a standard it points at. Research-first rule (2026-11-12): no
//! custom property namespace; where the standard has no carrier, the fact is left out and said
//! so here.
//!
//! Inputs, all already in the evidence store or derivable from it:
//!   * `supply-chain/evidence/<product>/<digest>/vuln.jsonl` — the measured header (scanner,
//!     advisory-DB commit, raw payload custody) written by `record-vuln`;
//!   * the raw cargo-audit payload the header names, fetched from the `tools` release and
//!     verified against the header's sha256 before anything is read from it;
//!   * components: a tool's frozen `tools/locks/<tool>.lock`, or for the app the release SBOM
//!     (`--sbom`), whose components already carry `scope` and `bom-ref`s;
//!   * `supply-chain/evidence/<product>/acks.jsonl` — maintainer rulings. An ack supplies
//!     `analysis` ONLY when it carries a native CycloneDX ruling (`cyclonedx.state`, optionally
//!     `cyclonedx.justification` / `cyclonedx.response`), chosen by the maintainer; the OpenVEX
//!     fields are never mapped (the two vocabularies are not a bijection). Legacy acks without
//!     one leave `analysis` absent and are listed as burn-down.
//!
//! Vantage: `metadata.lifecycles = [pre-build]` — the lockfile view. The post-build view (the
//! binary's embedded dependency list) is a follow-up; xtask cannot inflate `.dep-v0` yet.
//!
//! Determinism: `metadata.timestamp` is the scan date from the header, not wall-clock, and the
//! serial number is derived from the subject digest, so `check` can regenerate and diff.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};

use crate::advance::{gh, read_jsonl, s};

const SPEC: &str = "1.6";

fn evidence_dir(product: &str, digest: &str) -> PathBuf {
    PathBuf::from("supply-chain/evidence")
        .join(product)
        .join(digest)
}

/// Components from a frozen Cargo.lock: name, version, checksum (crates.io registry entries).
pub(crate) fn components_from_lock(lock: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let mut cur: Map<String, Value> = Map::new();
    let flush = |cur: &mut Map<String, Value>, out: &mut Vec<Value>| {
        if let (Some(Value::String(n)), Some(Value::String(v))) =
            (cur.get("name"), cur.get("version"))
        {
            let purl = format!("pkg:cargo/{n}@{v}");
            let mut c =
                json!({"type": "library", "bom-ref": purl, "name": n, "version": v, "purl": purl});
            if let Some(Value::String(h)) = cur.get("checksum") {
                c["hashes"] = json!([{"alg": "SHA-256", "content": h}]);
            }
            out.push(c);
        }
        cur.clear();
    };
    for line in lock.lines() {
        let l = line.trim();
        if l == "[[package]]" {
            flush(&mut cur, &mut out);
            continue;
        }
        if l.starts_with('[') {
            flush(&mut cur, &mut out);
            continue;
        }
        if let Some((k, v)) = l.split_once(" = ")
            && matches!(k, "name" | "version" | "checksum")
        {
            cur.insert(
                k.to_string(),
                Value::String(v.trim_matches('"').to_string()),
            );
        }
    }
    flush(&mut cur, &mut out);
    out
}

/// bom-ref of the component matching (name, version), whichever shape the components came in.
pub(crate) fn bom_ref_for(components: &[Value], name: &str, version: &str) -> Option<String> {
    components
        .iter()
        .find(|c| s(c, &["name"]) == name && s(c, &["version"]) == version)
        .map(|c| s(c, &["bom-ref"]))
        .filter(|r| !r.is_empty())
}

/// RustSec aliases to CycloneDX `references`, source named by the identifier scheme.
pub(crate) fn references(aliases: &[Value]) -> Vec<Value> {
    aliases
        .iter()
        .filter_map(Value::as_str)
        .map(|a| {
            let (name, url) = if a.starts_with("CVE-") {
                ("NVD", format!("https://nvd.nist.gov/vuln/detail/{a}"))
            } else if a.starts_with("GHSA-") {
                (
                    "GitHub Advisory Database",
                    format!("https://github.com/advisories/{a}"),
                )
            } else {
                ("other", String::new())
            };
            let mut src = json!({"name": name});
            if !url.is_empty() {
                src["url"] = Value::String(url);
            }
            json!({"id": a, "source": src})
        })
        .collect()
}

/// Ratings: a CVSS vector becomes a rating with the matching method; a RustSec informational
/// class (unmaintained, unsound, yanked, notice) becomes a `severity: info` rating under
/// `method: other` with the class in `justification` — the standard's own carrier for
/// "not a vulnerability score".
pub(crate) fn ratings(cvss: Option<&str>, informational: Option<&str>) -> Vec<Value> {
    let mut out = Vec::new();
    if let Some(v) = cvss.filter(|v| !v.is_empty()) {
        let method = if v.starts_with("CVSS:3.1") {
            "CVSSv31"
        } else if v.starts_with("CVSS:3.0") {
            "CVSSv3"
        } else if v.starts_with("CVSS:4.0") {
            "CVSSv4"
        } else {
            "other"
        };
        out.push(json!({"source": {"name": "RustSec"}, "method": method, "vector": v}));
    }
    if let Some(kind) = informational.filter(|k| !k.is_empty()) {
        out.push(json!({
            "source": {"name": "RustSec"},
            "severity": "info",
            "method": "other",
            "justification": format!("RustSec informational advisory class: {kind}")
        }));
    }
    out
}

/// The maintainer's native CycloneDX ruling, if the matching ack carries one. The last ack for
/// the (advisory, package, version) instance wins, as in the gate.
pub(crate) fn analysis_from_acks(
    acks: &[Value],
    id: &str,
    package: &str,
    version: &str,
) -> Option<Value> {
    let matching: Vec<&Value> = acks
        .iter()
        .filter(|a| {
            s(a, &["axis"]) == "vuln"
                && s(a, &["vulnerability", "name"]) == id
                && s(a, &["product", "package"]) == package
                && s(a, &["product", "version"]) == version
        })
        .collect();
    let ack = *matching.last()?;
    let cdx = &ack["cyclonedx"];
    let state = cdx["state"].as_str()?;
    // The native ruling's own `detail` when it has one; the OpenVEX notes otherwise.
    let detail = cdx["detail"]
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| s(ack, &["status_notes"]));
    // firstIssued / lastUpdated are date-times in the schema; acks record dates.
    let first = matching
        .iter()
        .map(|a| s(a, &["timestamp"]))
        .min()
        .unwrap_or_default();
    let last = matching
        .iter()
        .map(|a| s(a, &["timestamp"]))
        .max()
        .unwrap_or_default();
    let mut an =
        json!({"state": state, "firstIssued": date_time(&first), "lastUpdated": date_time(&last)});
    if !detail.is_empty() {
        an["detail"] = Value::String(detail);
    }
    if let Some(j) = cdx["justification"].as_str() {
        an["justification"] = Value::String(j.to_string());
    }
    if let Some(r) = cdx["response"].as_array() {
        an["response"] = Value::Array(r.clone());
    }
    Some(an)
}

/// All findings of a cargo-audit report as (kind, entry); the entry carries `advisory`,
/// `package`, `versions` (patched / unaffected requirements) and `affected` (arch / os / functions).
fn findings(raw: &Value) -> Vec<(String, Value)> {
    let mut out = Vec::new();
    for v in raw["vulnerabilities"]["list"]
        .as_array()
        .into_iter()
        .flatten()
    {
        out.push(("vulnerability".to_string(), v.clone()));
    }
    if let Some(w) = raw["warnings"].as_object() {
        for (kind, list) in w {
            for e in list.as_array().into_iter().flatten() {
                out.push((kind.clone(), e.clone()));
            }
        }
    }
    out
}

/// `2026-11-13` -> `2026-11-13T00:00:00Z`; a value that already carries a time is kept.
fn date_time(d: &str) -> String {
    if d.len() == 10 && d.as_bytes()[4] == b'-' && d.as_bytes()[7] == b'-' {
        format!("{d}T00:00:00Z")
    } else {
        d.to_string()
    }
}

/// A RustSec/semver requirement (`>=0.3.0, <0.10.1`) as a Package URL `vers` range
/// (`vers:cargo/>=0.3.0|<0.10.1`). Only plain comparators over release versions map exactly;
/// anything else (caret, tilde, wildcard, pre-release) returns None and is left to the advisory.
pub(crate) fn req_to_vers(req: &str) -> Option<String> {
    let mut parts: Vec<(Vec<u64>, String)> = Vec::new();
    for c in req.split(',').map(str::trim).filter(|c| !c.is_empty()) {
        let (op, ver) = ["<=", ">=", "<", ">", "="]
            .iter()
            .find_map(|op| c.strip_prefix(op).map(|v| (*op, v.trim())))?;
        let nums: Vec<u64> = ver
            .split('.')
            .map(|n| n.parse().ok())
            .collect::<Option<_>>()?;
        if nums.is_empty() || nums.len() > 3 {
            return None;
        }
        parts.push((nums, format!("{op}{ver}")));
    }
    if parts.is_empty() {
        return None;
    }
    parts.sort_by(|a, b| a.0.cmp(&b.0));
    Some(format!(
        "vers:cargo/{}",
        parts.into_iter().map(|p| p.1).collect::<Vec<_>>().join("|")
    ))
}

/// `affects[].versions`: the measured version as affected, and every patched / unaffected
/// requirement from the advisory as an unaffected `vers` range.
fn affected_versions(pver: &str, versions: &Value) -> Vec<Value> {
    let mut out = vec![json!({"version": pver, "status": "affected"})];
    for key in ["patched", "unaffected"] {
        for r in versions[key].as_array().into_iter().flatten() {
            if let Some(v) = r.as_str().and_then(req_to_vers) {
                out.push(json!({"range": v, "status": "unaffected"}));
            }
        }
    }
    out
}

fn serial_number(digest: &str) -> String {
    // Deterministic per subject: the first 16 bytes of sha256("vdr:" + digest) laid out as a UUID.
    let h = crate::sha256::sha256(format!("vdr:{digest}").as_bytes());
    format!(
        "urn:uuid:{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-4{:01x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        h[0],
        h[1],
        h[2],
        h[3],
        h[4],
        h[5],
        h[6] & 0x0f,
        h[7],
        (h[8] & 0x3f) | 0x80,
        h[9],
        h[10],
        h[11],
        h[12],
        h[13],
        h[14],
        h[15]
    )
}

/// Build the VDR document. Pure: every input is passed in.
pub(crate) fn build(
    product: &str,
    digest: &str,
    header: &Value,
    raw: &Value,
    components: Vec<Value>,
    subject: Option<Value>,
    acks: &[Value],
) -> Result<(Value, Vec<String>), String> {
    let mut burn_down = Vec::new();
    let mut vulns = Vec::new();
    for (kind, entry) in findings(raw) {
        let (adv, pkg) = (entry["advisory"].clone(), entry["package"].clone());
        let id = s(&adv, &["id"]);
        let (pname, pver) = (s(&pkg, &["name"]), s(&pkg, &["version"]));
        let bom_ref = bom_ref_for(&components, &pname, &pver).ok_or_else(|| {
            format!("{id}: affected {pname} {pver} is not among the components — the components source does not match the measured lock")
        })?;
        let informational = if kind == "vulnerability" {
            None
        } else {
            Some(kind.as_str())
        };
        let url = adv["url"]
            .as_str()
            .filter(|u| !u.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| format!("https://rustsec.org/advisories/{id}.html"));
        let mut v = json!({
            "bom-ref": format!("vuln:{id}@{pname}@{pver}"),
            "id": id,
            "source": {"name": "RustSec", "url": url},
            "references": references(adv["aliases"].as_array().map(Vec::as_slice).unwrap_or(&[])),
            "ratings": ratings(adv["cvss"].as_str(), informational),
            "description": s(&adv, &["title"]),
            "detail": s(&adv, &["description"]),
            "advisories": [{"title": s(&adv, &["title"]), "url": url}],
            "affects": [{"ref": bom_ref, "versions": affected_versions(&pver, &entry["versions"])}],
        });
        if let Some(d) = adv["date"].as_str() {
            v["published"] = Value::String(format!("{d}T00:00:00Z"));
        }
        match analysis_from_acks(acks, &id, &pname, &pver) {
            Some(an) => v["analysis"] = an,
            None => burn_down.push(format!("{id} {pname} {pver}")),
        }
        vulns.push(v);
    }
    let scan_date = s(header, &["scanFinishedOn"]);
    let tools = json!({"components": [
        {"type": "application", "name": "cargo-audit", "version": s(header, &["scanner", "version"]),
         "hashes": [{"alg": "SHA-256", "content": s(header, &["scanner", "digest"])}],
         "externalReferences": [{"type": "vcs", "url": format!("https://{}", s(header, &["scanner", "uri"]).replace('#', "/tree/main/"))}]},
        {"type": "data", "name": "rustsec/advisory-db", "version": s(header, &["scanner", "db", "version"]),
         "externalReferences": [{"type": "vcs", "url": format!("https://{}", s(header, &["scanner", "db", "uri"]))}]},
        {"type": "application", "name": "xtask", "version": env!("CARGO_PKG_VERSION"),
         "externalReferences": [{"type": "vcs", "url": "https://github.com/bgonz808/hp-thermal"}]}
    ]});
    let mut subject = subject.unwrap_or_else(|| json!({"type": "application", "name": product}));
    subject["hashes"] = json!([{"alg": "SHA-256", "content": digest}]);
    let doc = json!({
        "bomFormat": "CycloneDX",
        "specVersion": SPEC,
        "serialNumber": serial_number(digest),
        "version": 1,
        "metadata": {
            "timestamp": format!("{scan_date}T00:00:00Z"),
            "lifecycles": [{"phase": "pre-build"}],
            "tools": tools,
            "component": subject,
        },
        "components": components,
        "vulnerabilities": vulns,
    });
    Ok((doc, burn_down))
}

/// `(name, version)` of every package recorded in a cargo-auditable `.dep-v0` section (zlib-
/// compressed JSON). Runtime and build kinds are both recorded by cargo-auditable; the root is too.
pub(crate) fn packages_from_dep_v0(section: &[u8]) -> Result<BTreeSet<(String, String)>, String> {
    let bytes = miniz_oxide::inflate::decompress_to_vec_zlib(section)
        .map_err(|e| format!(".dep-v0: zlib inflate failed: {e:?}"))?;
    let v: Value = serde_json::from_slice(&bytes).map_err(|e| format!(".dep-v0: {e}"))?;
    let pk = v["packages"]
        .as_array()
        .ok_or(".dep-v0: no packages array")?;
    let mut out = BTreeSet::new();
    for p in pk {
        match (p["name"].as_str(), p["version"].as_str()) {
            (Some(n), Some(ver)) => {
                out.insert((n.to_string(), ver.to_string()));
            }
            _ => return Err(".dep-v0: package without name/version".into()),
        }
    }
    if out.is_empty() {
        return Err(".dep-v0: empty package list".into());
    }
    Ok(out)
}

/// The compiled dependency graph recorded in a `.dep-v0` section: each package with the
/// packages it depends on (runtime and build edges, as cargo-auditable records them).
pub(crate) type DepGraph = Vec<((String, String), Vec<(String, String)>)>;

pub(crate) fn graph_from_dep_v0(section: &[u8]) -> Result<DepGraph, String> {
    let bytes = miniz_oxide::inflate::decompress_to_vec_zlib(section)
        .map_err(|e| format!(".dep-v0: zlib inflate failed: {e:?}"))?;
    let v: Value = serde_json::from_slice(&bytes).map_err(|e| format!(".dep-v0: {e}"))?;
    let pk = v["packages"]
        .as_array()
        .ok_or(".dep-v0: no packages array")?;
    let key = |p: &Value| -> Option<(String, String)> {
        Some((
            p["name"].as_str()?.to_string(),
            p["version"].as_str()?.to_string(),
        ))
    };
    let mut out = Vec::new();
    for p in pk {
        let k = key(p).ok_or(".dep-v0: package without name/version")?;
        let mut deps = Vec::new();
        for i in p["dependencies"].as_array().into_iter().flatten() {
            let idx = i.as_u64().ok_or(".dep-v0: non-integer dependency index")? as usize;
            let d = pk
                .get(idx)
                .and_then(key)
                .ok_or(".dep-v0: dependency index out of range")?;
            deps.push(d);
        }
        deps.sort();
        deps.dedup();
        out.push((k, deps));
    }
    Ok(out)
}

/// CycloneDX `dependencies[]` for the compiled graph, keyed by the components' bom-refs. A
/// package in the binary that the frozen lock does not list is an error, never skipped: the
/// binary would then contain code the measured lock does not account for.
pub(crate) fn dependencies_from_graph(
    components: &[Value],
    graph: &DepGraph,
) -> Result<Vec<Value>, String> {
    let r = |(n, v): &(String, String)| {
        bom_ref_for(components, n, v)
            .ok_or_else(|| format!("binary contains {n} {v}, which the frozen lock does not list"))
    };
    let mut out = Vec::new();
    for (pkg, deps) in graph {
        let mut on: Vec<String> = deps.iter().map(r).collect::<Result<_, _>>()?;
        on.sort();
        on.dedup();
        out.push(json!({"ref": r(pkg)?, "dependsOn": on}));
    }
    out.sort_by(|a, b| a["ref"].as_str().cmp(&b["ref"].as_str()));
    Ok(out)
}

/// The version a freshly built report takes, given the committed one: the same content under
/// the same serial keeps the committed version; anything else is the next version. A committed
/// report for a different serial (another subject) is not this report's history.
pub(crate) fn settle_version(mut doc: Value, existing: Option<&Value>) -> Value {
    let Some(ex) = existing.filter(|e| e["serialNumber"] == doc["serialNumber"]) else {
        doc["version"] = json!(1);
        return doc;
    };
    let v = ex["version"].as_u64().filter(|v| *v >= 1).unwrap_or(1);
    doc["version"] = json!(v);
    if &doc != ex {
        doc["version"] = json!(v + 1);
    }
    doc
}

/// BOM-Link to another CycloneDX document: `urn:cdx:<serial uuid>/<version>`.
pub(crate) fn bom_link(serial: &str, version: u64) -> Option<String> {
    let uuid = serial.strip_prefix("urn:uuid:")?;
    (uuid.len() == 36 && version >= 1).then(|| format!("urn:cdx:{uuid}/{version}"))
}

/// The packages compiled into a binary, read from its own `.dep-v0` section (PE or ELF).
pub(crate) fn auditable_packages(bin: &[u8]) -> Result<BTreeSet<(String, String)>, String> {
    packages_from_dep_v0(crate::auditable::dep_v0_section(bin)?)
}

/// CycloneDX `scope` per component from the binary's package set: `required` when the lock
/// package is in the binary, `excluded` when the lock carries it but the binary does not (an
/// optional, feature-gated, dev or proc-macro-only entry). Each component also states how its
/// identity was established (`evidence.identity`): the frozen lock always, the binary when present.
pub(crate) fn apply_scope(
    components: &mut [Value],
    present: &BTreeSet<(String, String)>,
    binary_desc: &str,
) {
    for c in components.iter_mut() {
        let key = (
            c["name"].as_str().unwrap_or_default().to_string(),
            c["version"].as_str().unwrap_or_default().to_string(),
        );
        let in_binary = present.contains(&key);
        c["scope"] = json!(if in_binary { "required" } else { "excluded" });
        let mut methods = vec![json!({
            "technique": "manifest-analysis",
            "confidence": 1.0,
            "value": "frozen Cargo.lock (tools/locks)"
        })];
        if in_binary {
            methods.push(json!({
                "technique": "binary-analysis",
                "confidence": 1.0,
                "value": binary_desc
            }));
        }
        c["evidence"] =
            json!({"identity": [{"field": "purl", "confidence": 1.0, "methods": methods}]});
    }
}

/// Content-addressed asset name in the `tools` release for a TOOLS.lock row.
pub(crate) fn tool_asset_name(name: &str, target: &str, digest: &str) -> String {
    let short = &digest[..12];
    if target == "windows-x86_64" {
        format!("{name}-{short}.exe")
    } else {
        format!("{name}-{short}-{target}")
    }
}

/// The TOOLS.lock target whose row carries this digest.
pub(crate) fn tools_lock_target(lock: &str, name: &str, digest: &str) -> Option<String> {
    lock.lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
        .find_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() >= 5 && f[0] == name && f[4] == digest).then(|| f[3].to_string())
        })
}

/// Download the pinned tool binary from the `tools` release and verify it IS the digest.
fn fetch_tool_binary(product: &str, digest: &str) -> Result<(String, Vec<u8>), String> {
    let lock = std::fs::read_to_string("tools/TOOLS.lock")
        .map_err(|e| format!("tools/TOOLS.lock: {e}"))?;
    let target = tools_lock_target(&lock, product, digest).ok_or_else(|| {
        format!(
            "tools/TOOLS.lock has no {product} row with digest {digest}: VDRs are emitted for pinned digests"
        )
    })?;
    let asset = tool_asset_name(product, &target, digest);
    let tmp = std::env::temp_dir().join(format!("vdr-bin-{asset}"));
    let _ = std::fs::remove_file(&tmp);
    gh(&[
        "release",
        "download",
        "tools",
        "--pattern",
        &asset,
        "-O",
        &tmp.to_string_lossy(),
        "--clobber",
    ])?;
    let bytes = std::fs::read(&tmp).map_err(|e| e.to_string())?;
    let got = crate::sha256::sha256_hex(&bytes);
    if got != digest {
        return Err(format!(
            "{asset}: sha256 {got} != pinned {digest} (custody failure)"
        ));
    }
    Ok((asset, bytes))
}

fn fetch_raw(header: &Value) -> Result<Value, String> {
    let asset = s(header, &["rawPayload", "asset"]);
    let want = s(header, &["rawPayload", "sha256"]);
    if s(header, &["rawPayload", "store"]) != "tools release" || asset.is_empty() {
        return Err("vuln.jsonl header names no raw payload in the tools release".into());
    }
    let tmp = std::env::temp_dir().join(format!("vdr-{asset}"));
    let _ = std::fs::remove_file(&tmp);
    gh(&[
        "release",
        "download",
        "tools",
        "--pattern",
        &asset,
        "-O",
        &tmp.to_string_lossy(),
        "--clobber",
    ])?;
    let bytes = std::fs::read(&tmp).map_err(|e| e.to_string())?;
    let got = crate::sha256::sha256_hex(&bytes);
    if got != want {
        return Err(format!(
            "raw payload {asset}: sha256 {got} != header {want} (custody failure)"
        ));
    }
    serde_json::from_slice(&bytes).map_err(|e| format!("{asset}: {e}"))
}

pub fn run(args: &[String]) -> i32 {
    let usage = "usage: cargo xtask vdr <emit|check> --product <name> --digest <sha256> [--sbom <release cdx.json>] [--out <path>]";
    let Some(cmd) = args.get(1).map(String::as_str) else {
        eprintln!("{usage}");
        return 2;
    };
    let (mut product, mut digest, mut sbom, mut out) = (
        String::new(),
        String::new(),
        None::<PathBuf>,
        None::<PathBuf>,
    );
    let mut it = args.iter().skip(2);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--product" => product = it.next().cloned().unwrap_or_default(),
            "--digest" => digest = it.next().cloned().unwrap_or_default(),
            "--sbom" => sbom = it.next().map(PathBuf::from),
            "--out" => out = it.next().map(PathBuf::from),
            other => {
                eprintln!("vdr: unknown argument {other}\n{usage}");
                return 2;
            }
        }
    }
    if product.is_empty() || digest.len() != 64 {
        eprintln!("vdr: --product and a 64-hex --digest are required\n{usage}");
        return 2;
    }
    let dir = evidence_dir(&product, &digest);
    let out = out.unwrap_or_else(|| dir.join("vdr.cdx.json"));
    let res = (|| -> Result<(Value, Vec<String>), String> {
        let mut graph: Option<DepGraph> = None;
        let mut sbom_link: Option<String> = None;
        let rows = read_jsonl(&dir.join("vuln.jsonl"));
        let header = rows
            .first()
            .cloned()
            .ok_or_else(|| format!("{}: no vuln.jsonl header", dir.display()))?;
        let raw = fetch_raw(&header)?;
        let (components, subject) = match &sbom {
            Some(p) => {
                let b: Value = serde_json::from_str(
                    &std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?,
                )
                .map_err(|e| format!("{}: {e}", p.display()))?;
                let comps = b["components"]
                    .as_array()
                    .cloned()
                    .ok_or("SBOM has no components")?;
                sbom_link = Some(
                    bom_link(
                        b["serialNumber"].as_str().unwrap_or_default(),
                        b["version"].as_u64().unwrap_or(0),
                    )
                    .ok_or("SBOM has no CycloneDX serialNumber/version to link to")?,
                );
                let mut subj = b["metadata"]["component"].clone();
                if subj.is_null() {
                    subj = json!({"type": "application", "name": product});
                }
                (comps, Some(subj))
            }
            None => {
                let lock = std::fs::read_to_string(format!("tools/locks/{product}.lock")).map_err(
                    |e| format!("tools/locks/{product}.lock: {e} (pass --sbom for the app)"),
                )?;
                let mut comps = components_from_lock(&lock);
                // Scope from the artifact, not the manifest: the pinned binary's cargo-auditable
                // list says which lock packages were compiled into it (runtime and build kinds).
                let (asset, bin) = fetch_tool_binary(&product, &digest)?;
                let present = auditable_packages(&bin).map_err(|e| format!("{asset}: {e}"))?;
                graph = Some(
                    graph_from_dep_v0(
                        crate::auditable::dep_v0_section(&bin)
                            .map_err(|e| format!("{asset}: {e}"))?,
                    )
                    .map_err(|e| format!("{asset}: {e}"))?,
                );
                apply_scope(
                    &mut comps,
                    &present,
                    &format!("cargo-auditable .dep-v0 section of {asset} (sha256 {digest})"),
                );
                (comps, None)
            }
        };
        let acks = read_jsonl(
            Path::new("supply-chain/evidence")
                .join(&product)
                .join("acks.jsonl")
                .as_path(),
        );
        let deps = match &graph {
            Some(g) => Some(dependencies_from_graph(&components, g)?),
            None => None,
        };
        let (mut doc, burn) = build(&product, &digest, &header, &raw, components, subject, &acks)?;
        if let Some(d) = deps {
            // The scope and the edges were measured from the built binary: post-build too.
            doc["dependencies"] = Value::Array(d);
            doc["metadata"]["lifecycles"] =
                json!([{"phase": "pre-build"}, {"phase": "post-build"}]);
        }
        if let Some(l) = sbom_link {
            doc["externalReferences"] = json!([{"type": "bom", "url": l}]);
        }
        Ok((doc, burn))
    })();
    let (doc, burn_down) = match res {
        Ok(x) => x,
        Err(e) => {
            eprintln!("vdr: {e}");
            return 1;
        }
    };
    // CycloneDX versioning: one serialNumber per subject, and `version` names the revision. The
    // committed report is the ledger: identical content keeps its version, changed content takes
    // the next one, so a version once published (attested on a release) never changes meaning.
    let existing: Option<Value> = std::fs::read_to_string(&out)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok());
    let doc = settle_version(doc, existing.as_ref());
    let text = serde_json::to_string_pretty(&doc).unwrap() + "\n";
    for b in &burn_down {
        eprintln!("vdr: no native CycloneDX ruling in acks for {b} — analysis omitted (burn-down)");
    }
    match cmd {
        "emit" => {
            if let Err(e) = std::fs::write(&out, &text) {
                eprintln!("vdr: {}: {e}", out.display());
                return 1;
            }
            println!(
                "vdr: wrote {} — {} component(s), {} vulnerabilit(ies), {} without analysis",
                out.display(),
                doc["components"].as_array().map_or(0, Vec::len),
                doc["vulnerabilities"].as_array().map_or(0, Vec::len),
                burn_down.len()
            );
            0
        }
        "check" => match std::fs::read_to_string(&out) {
            Ok(have) if have == text => {
                println!("vdr: {} is up to date with the evidence", out.display());
                0
            }
            Ok(_) => {
                eprintln!(
                    "vdr: {} differs from what the evidence regenerates — re-run `vdr emit` (it becomes version {})",
                    out.display(),
                    doc["version"]
                );
                1
            }
            Err(e) => {
                eprintln!("vdr: {}: {e} — not emitted yet", out.display());
                1
            }
        },
        other => {
            eprintln!("vdr: unknown command `{other}`\n{usage}");
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCK: &str = "[[package]]\nname = \"a\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"ab\"\n\n[[package]]\nname = \"b\"\nversion = \"2.0.0\"\n\n[metadata]\nk = \"v\"\n";

    #[test]
    fn scope_and_identity_evidence_follow_the_binary_package_set() {
        let mut comps = components_from_lock(LOCK);
        let mut present = BTreeSet::new();
        present.insert(("a".to_string(), "1.0.0".to_string()));
        apply_scope(&mut comps, &present, "x.exe (sha256 d)");
        assert_eq!(comps[0]["scope"], "required");
        assert_eq!(
            comps[0]["evidence"]["identity"][0]["methods"][1]["technique"],
            "binary-analysis"
        );
        assert_eq!(comps[1]["scope"], "excluded");
        assert_eq!(
            comps[1]["evidence"]["identity"][0]["methods"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn dep_v0_packages_inflate_and_refuse_malformed() {
        let doc = br#"{"packages":[{"name":"a","version":"1.0.0","root":true},{"name":"b","version":"2.0.0","kind":"build"}]}"#;
        let z = miniz_oxide::deflate::compress_to_vec_zlib(doc, 6);
        let set = packages_from_dep_v0(&z).unwrap();
        assert!(set.contains(&("b".to_string(), "2.0.0".to_string())));
        assert_eq!(set.len(), 2);
        assert!(packages_from_dep_v0(b"not zlib").is_err());
        let empty = miniz_oxide::deflate::compress_to_vec_zlib(br#"{"packages":[]}"#, 6);
        assert!(packages_from_dep_v0(&empty).unwrap_err().contains("empty"));
    }

    #[test]
    fn tool_asset_names_and_lock_target_lookup() {
        assert_eq!(
            tool_asset_name("cargo-audit", "windows-x86_64", "b16c10e3c7d43570ab"),
            "cargo-audit-b16c10e3c7d4.exe"
        );
        assert_eq!(
            tool_asset_name("cargo-acl", "linux-x86_64", "87c159d397e93e88ff"),
            "cargo-acl-87c159d397e9-linux-x86_64"
        );
        let lock = "# name repo rev target sha\ncargo-acl o/r deadbeef linux-x86_64 87c1 # note\ncargo-acl o/r deadbeef windows-x86_64 ffff\n";
        assert_eq!(
            tools_lock_target(lock, "cargo-acl", "87c1").unwrap(),
            "linux-x86_64"
        );
        assert!(tools_lock_target(lock, "cargo-acl", "0000").is_none());
    }

    #[test]
    fn vers_ranges_map_plain_comparators_and_refuse_the_rest() {
        assert_eq!(req_to_vers(">=0.10.1").unwrap(), "vers:cargo/>=0.10.1");
        assert_eq!(
            req_to_vers("<0.6.0, >= 0.5.16").unwrap(),
            "vers:cargo/>=0.5.16|<0.6.0"
        );
        assert!(req_to_vers("^1.2").is_none());
        assert!(req_to_vers(">=1.0.0-rc.1").is_none());
        assert!(req_to_vers("").is_none());
        let v = affected_versions(
            "0.10.0",
            &json!({"patched": [">=0.10.1"], "unaffected": ["<0.3.0"]}),
        );
        assert_eq!(v.len(), 3);
        assert_eq!(v[1]["range"], "vers:cargo/>=0.10.1");
        assert_eq!(v[2]["status"], "unaffected");
    }

    #[test]
    fn dep_v0_graph_becomes_dependencies_and_refuses_unlisted_packages() {
        let doc = br#"{"packages":[{"name":"a","version":"1.0.0","root":true,"dependencies":[1]},{"name":"b","version":"2.0.0","kind":"build"}]}"#;
        let z = miniz_oxide::deflate::compress_to_vec_zlib(doc, 6);
        let g = graph_from_dep_v0(&z).unwrap();
        let comps = components_from_lock(LOCK);
        let d = dependencies_from_graph(&comps, &g).unwrap();
        assert_eq!(d[0]["ref"], "pkg:cargo/a@1.0.0");
        assert_eq!(d[0]["dependsOn"][0], "pkg:cargo/b@2.0.0");
        let stray = br#"{"packages":[{"name":"z","version":"9.9.9","dependencies":[]}]}"#;
        let g2 = graph_from_dep_v0(&miniz_oxide::deflate::compress_to_vec_zlib(stray, 6)).unwrap();
        assert!(
            dependencies_from_graph(&comps, &g2)
                .unwrap_err()
                .contains("does not list")
        );
        let bad = br#"{"packages":[{"name":"a","version":"1.0.0","dependencies":[7]}]}"#;
        assert!(graph_from_dep_v0(&miniz_oxide::deflate::compress_to_vec_zlib(bad, 6)).is_err());
    }

    #[test]
    fn versions_advance_only_when_content_changes() {
        let a = json!({"serialNumber": "urn:uuid:x", "version": 1, "k": 1});
        assert_eq!(settle_version(a.clone(), None)["version"], 1);
        assert_eq!(settle_version(a.clone(), Some(&a))["version"], 1);
        let changed = json!({"serialNumber": "urn:uuid:x", "version": 1, "k": 2});
        assert_eq!(settle_version(changed.clone(), Some(&a))["version"], 2);
        let v2 = settle_version(changed.clone(), Some(&a));
        assert_eq!(settle_version(changed.clone(), Some(&v2))["version"], 2);
        let other = json!({"serialNumber": "urn:uuid:y", "version": 7, "k": 2});
        assert_eq!(settle_version(changed, Some(&other))["version"], 1);
    }

    #[test]
    fn bom_link_and_date_time_shapes() {
        assert_eq!(
            bom_link("urn:uuid:2a67a31e-7e1b-4744-862b-917e05dbc6a0", 1).unwrap(),
            "urn:cdx:2a67a31e-7e1b-4744-862b-917e05dbc6a0/1"
        );
        assert!(bom_link("2a67a31e", 1).is_none());
        assert!(bom_link("urn:uuid:2a67a31e-7e1b-4744-862b-917e05dbc6a0", 0).is_none());
        assert_eq!(date_time("2026-11-13"), "2026-11-13T00:00:00Z");
        assert_eq!(date_time("2026-11-13T05:00:00Z"), "2026-11-13T05:00:00Z");
    }

    #[test]
    fn components_from_lock_carry_purl_and_hash() {
        let c = components_from_lock(LOCK);
        assert_eq!(c.len(), 2);
        assert_eq!(c[0]["purl"], "pkg:cargo/a@1.0.0");
        assert_eq!(c[0]["hashes"][0]["content"], "ab");
        assert!(c[1].get("hashes").is_none());
        assert_eq!(bom_ref_for(&c, "b", "2.0.0").unwrap(), "pkg:cargo/b@2.0.0");
        assert!(bom_ref_for(&c, "b", "2.0.1").is_none());
    }

    #[test]
    fn references_and_ratings_map_to_standard_fields() {
        let r = references(&[
            json!("CVE-2024-0001"),
            json!("GHSA-xxxx-yyyy-zzzz"),
            json!("OSV-1"),
        ]);
        assert_eq!(r[0]["source"]["name"], "NVD");
        assert_eq!(r[1]["source"]["name"], "GitHub Advisory Database");
        assert_eq!(r[2]["source"]["name"], "other");
        let rt = ratings(Some("CVSS:3.1/AV:N/AC:L"), None);
        assert_eq!(rt[0]["method"], "CVSSv31");
        let inf = ratings(None, Some("unmaintained"));
        assert_eq!(inf[0]["severity"], "info");
        assert_eq!(inf[0]["method"], "other");
        assert!(ratings(None, None).is_empty());
    }

    #[test]
    fn analysis_comes_only_from_native_cyclonedx_rulings() {
        let legacy = json!({"axis":"vuln","vulnerability":{"name":"RUSTSEC-1"},"product":{"package":"a","version":"1.0.0"},"status":"not_affected","justification":"component_not_present","timestamp":"2026-11-12","status_notes":"dev-only"});
        assert!(
            analysis_from_acks(std::slice::from_ref(&legacy), "RUSTSEC-1", "a", "1.0.0").is_none(),
            "OpenVEX-only ack is never mapped"
        );
        let mut native = legacy.clone();
        native["cyclonedx"] = json!({"state":"not_affected","justification":"code_not_present","response":["will_not_fix"]});
        let an = analysis_from_acks(&[legacy, native], "RUSTSEC-1", "a", "1.0.0").unwrap();
        assert_eq!(an["state"], "not_affected");
        assert_eq!(an["justification"], "code_not_present");
        assert_eq!(an["response"][0], "will_not_fix");
        assert_eq!(an["firstIssued"], "2026-11-12T00:00:00Z");
        assert_eq!(an["lastUpdated"], "2026-11-12T00:00:00Z");
        // A later ack moves lastUpdated; the earliest one keeps firstIssued.
        let mut later = an_source_with_time("2026-11-20");
        later["cyclonedx"] = json!({"state":"not_affected","justification":"code_not_present"});
        let first = json!({"axis":"vuln","vulnerability":{"name":"RUSTSEC-1"},"product":{"package":"a","version":"1.0.0"},"timestamp":"2026-11-01"});
        let an2 = analysis_from_acks(&[first, later], "RUSTSEC-1", "a", "1.0.0").unwrap();
        assert_eq!(an2["firstIssued"], "2026-11-01T00:00:00Z");
        assert_eq!(an2["lastUpdated"], "2026-11-20T00:00:00Z");
        assert!(
            an2.get("detail").is_none(),
            "no detail when neither the ruling nor notes carry one"
        );
    }

    fn an_source_with_time(t: &str) -> Value {
        json!({"axis":"vuln","vulnerability":{"name":"RUSTSEC-1"},"product":{"package":"a","version":"1.0.0"},"timestamp":t})
    }

    #[test]
    fn build_is_deterministic_and_fails_closed_on_unknown_components() {
        let header = json!({"scanFinishedOn":"2026-11-12","scanner":{"uri":"github.com/rustsec/rustsec#cargo-audit","version":"0.22.2","digest":"b1","db":{"uri":"github.com/rustsec/advisory-db","version":"af7b"}}});
        let raw = json!({"vulnerabilities":{"list":[]},"warnings":{"unmaintained":[{"advisory":{"id":"RUSTSEC-2024-0320","title":"yaml-rust is unmaintained","description":"d","date":"2024-03-20","aliases":[],"url":null,"cvss":null},"package":{"name":"yaml-rust","version":"0.4.5"}}]}});
        let comps =
            components_from_lock("[[package]]\nname = \"yaml-rust\"\nversion = \"0.4.5\"\n");
        let (doc, burn) = build(
            "t",
            &"d".repeat(64),
            &header,
            &raw,
            comps.clone(),
            None,
            &[],
        )
        .unwrap();
        assert_eq!(doc["specVersion"], "1.6");
        assert_eq!(doc["metadata"]["lifecycles"][0]["phase"], "pre-build");
        assert_eq!(
            doc["vulnerabilities"][0]["affects"][0]["ref"],
            "pkg:cargo/yaml-rust@0.4.5"
        );
        assert_eq!(doc["vulnerabilities"][0]["ratings"][0]["severity"], "info");
        assert_eq!(
            doc["vulnerabilities"][0]["source"]["url"],
            "https://rustsec.org/advisories/RUSTSEC-2024-0320.html"
        );
        assert_eq!(burn, vec!["RUSTSEC-2024-0320 yaml-rust 0.4.5".to_string()]);
        let (doc2, _) = build("t", &"d".repeat(64), &header, &raw, comps, None, &[]).unwrap();
        assert_eq!(doc, doc2, "same inputs, same document");
        let other = components_from_lock("[[package]]\nname = \"other\"\nversion = \"1.0.0\"\n");
        assert!(
            build("t", &"d".repeat(64), &header, &raw, other, None, &[]).is_err(),
            "affected package missing from components"
        );
    }
}
