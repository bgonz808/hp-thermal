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
    let ack = acks.iter().rev().find(|a| {
        s(a, &["axis"]) == "vuln"
            && s(a, &["vulnerability", "name"]) == id
            && s(a, &["product", "package"]) == package
            && s(a, &["product", "version"]) == version
    })?;
    let cdx = &ack["cyclonedx"];
    let state = cdx["state"].as_str()?;
    let mut an = json!({"state": state, "firstIssued": s(ack, &["timestamp"]), "detail": s(ack, &["status_notes"])});
    if let Some(j) = cdx["justification"].as_str() {
        an["justification"] = Value::String(j.to_string());
    }
    if let Some(r) = cdx["response"].as_array() {
        an["response"] = Value::Array(r.clone());
    }
    Some(an)
}

/// All findings of a cargo-audit report as (kind, advisory, package) triples.
fn findings(raw: &Value) -> Vec<(String, Value, Value)> {
    let mut out = Vec::new();
    for v in raw["vulnerabilities"]["list"]
        .as_array()
        .into_iter()
        .flatten()
    {
        out.push((
            "vulnerability".to_string(),
            v["advisory"].clone(),
            v["package"].clone(),
        ));
    }
    if let Some(w) = raw["warnings"].as_object() {
        for (kind, list) in w {
            for e in list.as_array().into_iter().flatten() {
                out.push((kind.clone(), e["advisory"].clone(), e["package"].clone()));
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
    for (kind, adv, pkg) in findings(raw) {
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
            "affects": [{"ref": bom_ref, "versions": [{"version": pver, "status": "affected"}]}],
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
                (components_from_lock(&lock), None)
            }
        };
        let acks = read_jsonl(
            Path::new("supply-chain/evidence")
                .join(&product)
                .join("acks.jsonl")
                .as_path(),
        );
        build(&product, &digest, &header, &raw, components, subject, &acks)
    })();
    let (doc, burn_down) = match res {
        Ok(x) => x,
        Err(e) => {
            eprintln!("vdr: {e}");
            return 1;
        }
    };
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
                    "vdr: {} differs from what the evidence regenerates — re-run `vdr emit`",
                    out.display()
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
        assert_eq!(an["firstIssued"], "2026-11-12");
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
