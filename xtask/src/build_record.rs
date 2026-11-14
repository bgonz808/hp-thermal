//! `cargo xtask build-record` -- cargo's own record of a build: every unit it compiled and every
//! directive a build script gave rustc.
//!
//! The producer builds with `--message-format=json-render-diagnostics`. Cargo writes its
//! documented JSON messages (The Cargo Book, "External tools" > "JSON messages") to stdout and
//! still renders rustc's diagnostics as text on stderr, so `verify-allowances` reads the same log.
//! stdout is the record. It is a subject of the same provenance statement as the binary and is
//! stored in the content-addressed `tools` release as
//! `<binary asset without .exe>.build-<record sha256:0:12>.jsonl`.
//!
//! Evidence (`build.jsonl` beside the digest's other records) is a header that anchors the raw
//! record by sha256, then the kept messages, sorted, in cargo's own shape minus runner paths.
//!
//! It measures two things nothing else here does:
//!   * the compiled set. `.dep-v0` is the resolved graph, a superset of what was compiled (#476);
//!     `compiler-artifact` is one message per unit cargo built.
//!   * `rustc-cfg`. cackle permits it without recording it (floors.json `build_instructions`);
//!     `build-script-executed.cfgs` lists each one, as emitted for the binary's own target.

use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::advance::{gh, gh_json, is_hex64, log_message};

pub(crate) const SCHEMA: &str = "hp-thermal/evidence-build/v1";
pub(crate) const FORMAT: &str = "cargo --message-format=json-render-diagnostics";
pub(crate) const FILE: &str = "build.jsonl";
const STORE_TAG: &str = "tools";
const PRODUCER: &str = ".github/workflows/build-tools-pipeline.yml";

/// Target kinds whose code links into the produced binary. A `proc-macro` runs inside rustc and
/// a `custom-build` script runs before it; neither ships.
const LINKED_KINDS: &[&str] = &["lib", "rlib", "dylib", "cdylib", "staticlib", "bin"];

/// `(name, version)` from a cargo package ID spec: `registry+URL#name@1.2.3`, or
/// `path+file:///.../name#1.2.3`, where the name is the URL's last path segment.
pub(crate) fn package_of(id: &str) -> Result<(String, String), String> {
    let bad = || format!("`{id}` is not a cargo package ID spec");
    let (url, frag) = id.rsplit_once('#').ok_or_else(bad)?;
    let (name, version) = match frag.split_once('@') {
        Some((n, v)) => (n.to_string(), v.to_string()),
        None => {
            let path = url.split('?').next().unwrap_or(url).trim_end_matches('/');
            (
                path.rsplit('/').next().unwrap_or("").to_string(),
                frag.to_string(),
            )
        }
    };
    if name.is_empty() || !version.starts_with(|c: char| c.is_ascii_digit()) {
        return Err(bad());
    }
    Ok((name, version))
}

fn str_array(v: &Value, what: &str) -> Result<Value, String> {
    match v.as_array() {
        Some(a) if a.iter().all(Value::is_string) => Ok(v.clone()),
        _ => Err(format!("`{what}` is not an array of strings")),
    }
}

/// Kept fields of a `compiler-artifact`: package, target kind and name, profile, features.
/// Paths (manifest, sources, outputs), `executable` and `fresh` describe the runner, not the build.
fn artifact(v: &Value) -> Result<Value, String> {
    let id = v["package_id"]
        .as_str()
        .ok_or("compiler-artifact without `package_id`")?;
    package_of(id)?;
    let t = &v["target"];
    let name = t["name"]
        .as_str()
        .ok_or("compiler-artifact without `target.name`")?;
    if !v["profile"].is_object() {
        return Err("compiler-artifact without `profile`".into());
    }
    Ok(json!({
        "reason": "compiler-artifact",
        "package_id": id,
        "target": {
            "kind": str_array(&t["kind"], "target.kind")?,
            "crate_types": str_array(&t["crate_types"], "target.crate_types")?,
            "name": name,
        },
        "profile": v["profile"].clone(),
        "features": str_array(&v["features"], "features")?,
    }))
}

/// Kept fields of a `build-script-executed`: everything the script told rustc. `out_dir` is a
/// runner path.
fn script(v: &Value) -> Result<Value, String> {
    let id = v["package_id"]
        .as_str()
        .ok_or("build-script-executed without `package_id`")?;
    package_of(id)?;
    let pairs = v["env"].as_array().is_some_and(|a| {
        a.iter().all(|p| {
            p.as_array()
                .is_some_and(|kv| kv.len() == 2 && kv.iter().all(Value::is_string))
        })
    });
    if !pairs {
        return Err("`env` is not an array of [name, value] pairs".into());
    }
    Ok(json!({
        "reason": "build-script-executed",
        "package_id": id,
        "cfgs": str_array(&v["cfgs"], "cfgs")?,
        "env": v["env"].clone(),
        "linked_libs": str_array(&v["linked_libs"], "linked_libs")?,
        "linked_paths": str_array(&v["linked_paths"], "linked_paths")?,
    }))
}

/// Parse cargo's stdout. Every line must be a JSON message with a `reason`; the record must end
/// with a successful `build-finished`. Other reasons are skipped: cargo documents that new ones
/// may appear. Returns the kept messages, sorted.
pub(crate) fn parse(raw: &str) -> Result<Vec<Value>, String> {
    let mut kept = Vec::new();
    let mut finished: Option<bool> = None;
    for (i, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let at = |e: String| format!("line {}: {e}", i + 1);
        if finished.is_some() {
            return Err(at("message after build-finished".into()));
        }
        let v: Value =
            serde_json::from_str(line).map_err(|e| at(format!("not a JSON message ({e})")))?;
        match v["reason"].as_str() {
            Some("compiler-artifact") => kept.push(artifact(&v).map_err(at)?),
            Some("build-script-executed") => kept.push(script(&v).map_err(at)?),
            Some("build-finished") => finished = Some(v["success"].as_bool() == Some(true)),
            Some(_) => {}
            None => return Err(at("no `reason`".into())),
        }
    }
    match finished {
        Some(true) => {}
        Some(false) => return Err("build-finished reports failure".into()),
        None => return Err("no build-finished message: the record is incomplete".into()),
    }
    let mut keyed: Vec<(String, Value)> = kept.into_iter().map(|v| (v.to_string(), v)).collect();
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(keyed.into_iter().map(|(_, v)| v).collect())
}

/// Where the raw record came from and which binary it describes.
pub(crate) struct Anchor<'a> {
    pub tool: &'a str,
    pub digest: &'a str,
    pub run_url: &'a str,
    pub raw_sha256: &'a str,
    pub asset: &'a str,
}

/// `build.jsonl`: the anchoring header, then one kept message per line.
pub(crate) fn evidence(a: &Anchor, messages: &[Value]) -> String {
    let header = json!({
        "schema": SCHEMA,
        "subject": {"name": a.tool, "sha256": a.digest},
        "format": FORMAT,
        "producerRun": a.run_url,
        "rawRecord": {"sha256": a.raw_sha256, "store": "tools release", "asset": a.asset},
    });
    let mut out = header.to_string();
    out.push('\n');
    for m in messages {
        out.push_str(&m.to_string());
        out.push('\n');
    }
    out
}

/// Read `build.jsonl` back: the header must carry this schema, and every message line must be
/// exactly what `parse` keeps, so a hand-added field or reason is refused.
pub(crate) fn read_evidence(text: &str) -> Result<(Value, Vec<Value>), String> {
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    let header: Value = serde_json::from_str(lines.next().ok_or("empty build record")?)
        .map_err(|e| format!("header: {e}"))?;
    if header["schema"] != SCHEMA {
        return Err(format!("header schema is not {SCHEMA}"));
    }
    if !header["subject"]["sha256"].as_str().is_some_and(is_hex64) {
        return Err("header has no subject sha256".into());
    }
    let mut msgs = Vec::new();
    for (i, l) in lines.enumerate() {
        let at = |e: String| format!("line {}: {e}", i + 2);
        let v: Value = serde_json::from_str(l).map_err(|e| at(e.to_string()))?;
        let kept = match v["reason"].as_str() {
            Some("compiler-artifact") => artifact(&v).map_err(at)?,
            Some("build-script-executed") => script(&v).map_err(at)?,
            _ => return Err(at("not a kept message".into())),
        };
        if kept != v {
            return Err(at("fields outside the kept subset".into()));
        }
        msgs.push(v);
    }
    Ok((header, msgs))
}

fn kinds(m: &Value) -> impl Iterator<Item = &str> {
    m["target"]["kind"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
}

/// Packages with a compiled unit whose code links into a binary.
pub(crate) fn linked(messages: &[Value]) -> BTreeSet<(String, String)> {
    messages
        .iter()
        .filter(|m| m["reason"] == "compiler-artifact")
        .filter(|m| kinds(m).any(|k| LINKED_KINDS.contains(&k)))
        .filter_map(|m| package_of(m["package_id"].as_str()?).ok())
        .collect()
}

/// Packages compiled as dependencies of the standard library (`-Z build-std`): cargo builds
/// them with the `rustc-dep-of-std` feature, and they link into the binary through std.
pub(crate) fn std_deps(messages: &[Value]) -> BTreeSet<(String, String)> {
    messages
        .iter()
        .filter(|m| m["reason"] == "compiler-artifact")
        .filter(|m| kinds(m).any(|k| LINKED_KINDS.contains(&k)))
        .filter(|m| {
            m["features"]
                .as_array()
                .is_some_and(|f| f.iter().any(|x| x == "rustc-dep-of-std"))
        })
        .filter_map(|m| package_of(m["package_id"].as_str()?).ok())
        .collect()
}

/// Packages cargo compiled any unit of: linked code, a proc-macro, or a build script.
pub(crate) fn compiled(messages: &[Value]) -> BTreeSet<(String, String)> {
    messages
        .iter()
        .filter(|m| m["reason"] == "compiler-artifact")
        .filter_map(|m| package_of(m["package_id"].as_str()?).ok())
        .collect()
}

/// The semver-compatible series of a version, as cargo groups them: `1.2.3` -> `1`,
/// `0.52.0` -> `0.52`, `0.0.7` -> `0.0.7`.
fn series(version: &str) -> String {
    let core = version.split(['-', '+']).next().unwrap_or(version);
    let p: Vec<&str> = core.split('.').collect();
    match p.as_slice() {
        [maj, ..] if *maj != "0" => (*maj).to_string(),
        ["0", min, ..] if *min != "0" => format!("0.{min}"),
        _ => core.to_string(),
    }
}

/// Per package series (`name@series`, so windows-sys 0.52 and 0.61 stay apart while a patch bump
/// keeps its key), the `rustc-cfg` and `rustc-env` directives its build script emitted, spelled
/// as the floors read them (`cargo:rustc-cfg=...`, `cargo:rustc-env=K=V`).
pub(crate) fn cfg_env_directives(messages: &[Value]) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for m in messages
        .iter()
        .filter(|m| m["reason"] == "build-script-executed")
    {
        let Some(Ok((name, version))) = m["package_id"].as_str().map(package_of) else {
            continue;
        };
        let d = out
            .entry(format!("{name}@{}", series(&version)))
            .or_default();
        for c in m["cfgs"].as_array().into_iter().flatten() {
            d.push(format!(
                "cargo:rustc-cfg={}",
                c.as_str().unwrap_or_default()
            ));
        }
        for kv in m["env"].as_array().into_iter().flatten() {
            d.push(format!(
                "cargo:rustc-env={}={}",
                kv[0].as_str().unwrap_or_default(),
                kv[1].as_str().unwrap_or_default()
            ));
        }
        d.sort();
        d.dedup();
    }
    out
}

/// Per package series, `(name, link libraries, link-search paths)` its build script gave rustc,
/// as cargo recorded them (`linked_libs`, `linked_paths`).
pub(crate) fn link_directives(
    messages: &[Value],
) -> BTreeMap<String, (String, Vec<String>, Vec<String>)> {
    let mut out: BTreeMap<String, (String, Vec<String>, Vec<String>)> = BTreeMap::new();
    for m in messages
        .iter()
        .filter(|m| m["reason"] == "build-script-executed")
    {
        let Some(Ok((name, version))) = m["package_id"].as_str().map(package_of) else {
            continue;
        };
        let e = out
            .entry(format!("{name}@{}", series(&version)))
            .or_insert_with(|| (name.clone(), Vec::new(), Vec::new()));
        let strs = |k: &str| {
            m[k].as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        };
        e.1.extend(strs("linked_libs"));
        e.2.extend(strs("linked_paths"));
        e.1.sort();
        e.1.dedup();
        e.2.sort();
        e.2.dedup();
    }
    out
}

/// The link libraries in `head` that the prior record lacks for the same package series, as
/// `name@series: lib`. A new static library is new native code in the binary; a new dylib, a new
/// import. Either is reviewed.
pub(crate) fn new_link_libs(head: &[Value], prior: &[Value]) -> Vec<String> {
    let before = link_directives(prior);
    let mut out = Vec::new();
    for (key, (_, libs, _)) in link_directives(head) {
        for l in libs {
            if !before.get(&key).is_some_and(|b| b.1.contains(&l)) {
                out.push(format!("{key}: {l}"));
            }
        }
    }
    out
}

/// The `rustc-cfg` values in `head` that the prior record lacks for the same package series,
/// as `name@series: cfg`.
pub(crate) fn new_cfgs(head: &[Value], prior: &[Value]) -> Vec<String> {
    let before = cfg_env_directives(prior);
    let mut out = Vec::new();
    for (pkg, directives) in cfg_env_directives(head) {
        for d in directives
            .iter()
            .filter(|d| d.starts_with("cargo:rustc-cfg="))
        {
            if !before.get(&pkg).is_some_and(|b| b.contains(d)) {
                out.push(format!(
                    "{pkg}: {}",
                    d.trim_start_matches("cargo:rustc-cfg=")
                ));
            }
        }
    }
    out
}

/// The store asset name for a record: the binary's asset name, `.exe` dropped, plus the record's
/// own digest prefix.
pub(crate) fn asset_name(tool: &str, target: &str, digest: &str, raw_sha256: &str) -> String {
    let bin = crate::vdr::tool_asset_name(tool, target, digest);
    format!(
        "{}.build-{}.jsonl",
        bin.trim_end_matches(".exe"),
        &raw_sha256[..12]
    )
}

/// The producer logs `build record: <tool> <target> <binary sha256> <record sha256>` per tool.
/// Two different record digests for one binary in one log is refused: build output can print
/// text of that shape, and the record is taken from custody, never from a guess.
pub(crate) fn record_line(
    log: &str,
    tool: &str,
    target: &str,
    digest: &str,
) -> Result<Option<String>, String> {
    let mut found: Vec<String> = log
        .lines()
        .map(log_message)
        .filter_map(|m| {
            let f: Vec<&str> = m.split_whitespace().collect();
            (f.len() == 6
                && f[0] == "build"
                && f[1] == "record:"
                && f[2] == tool
                && f[3] == target
                && f[4] == digest
                && is_hex64(f[5]))
            .then(|| f[5].to_string())
        })
        .collect();
    found.sort();
    found.dedup();
    match found.len() {
        0 => Ok(None),
        1 => Ok(found.pop()),
        _ => Err(format!(
            "the run log names {} records for {tool} {target} {}: {}",
            found.len(),
            &digest[..12],
            found.join(", ")
        )),
    }
}

/// A verified raw record: its store asset, kept messages, and the commit the producer ran at.
pub(crate) struct Verified {
    pub asset: String,
    pub messages: Vec<Value>,
    pub source_commit: String,
}

/// Fetch a raw record from the store and parse it. Refused unless the bytes match `raw_sha256`,
/// one statement signed by the producer workflow names both the record and the binary and was
/// issued by producer run `run_id`, and the record shows the tool's own binary target compiled.
fn fetch_verified(
    tool: &str,
    target: &str,
    digest: &str,
    raw_sha256: &str,
    run_id: &str,
) -> Result<Verified, String> {
    let asset = asset_name(tool, target, digest, raw_sha256);
    let dir = std::env::temp_dir().join(format!("build-record-{}", &raw_sha256[..12]));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let d = dir.to_string_lossy().into_owned();
    gh(&[
        "release",
        "download",
        STORE_TAG,
        "--pattern",
        &asset,
        "--dir",
        &d,
        "--clobber",
    ])?;
    let path = dir.join(&asset);
    let bytes = std::fs::read(&path).map_err(|e| format!("{asset}: {e}"))?;
    let got = crate::sha256::sha256_hex(&bytes);
    if got != raw_sha256 {
        return Err(format!("{asset}: sha256 {got}, expected {raw_sha256}"));
    }
    let repo = gh(&[
        "repo",
        "view",
        "--json",
        "nameWithOwner",
        "--jq",
        ".nameWithOwner",
    ])?;
    let repo = repo.trim();
    let signer = format!("{repo}/{PRODUCER}");
    let p = path.to_string_lossy().into_owned();
    let v = gh_json(&[
        "attestation",
        "verify",
        &p,
        "--repo",
        repo,
        "--signer-workflow",
        &signer,
        "--format",
        "json",
    ])?;
    let names = |subj: &Value, want: &str| {
        subj.as_array()
            .into_iter()
            .flatten()
            .any(|s| s["digest"]["sha256"] == want)
    };
    let run = format!("/actions/runs/{run_id}/");
    let bound = v.as_array().into_iter().flatten().find(|r| {
        let subj = &r["verificationResult"]["statement"]["subject"];
        let cert = &r["verificationResult"]["signature"]["certificate"];
        names(subj, raw_sha256)
            && names(subj, digest)
            && cert["runInvocationURI"]
                .as_str()
                .is_some_and(|u| u.contains(&run))
    });
    let Some(bound) = bound else {
        return Err(format!(
            "{asset}: no statement from {PRODUCER} run {run_id} names both the record and {}",
            &digest[..12]
        ));
    };
    let source_commit =
        bound["verificationResult"]["signature"]["certificate"]["sourceRepositoryDigest"]
            .as_str()
            .filter(|c| c.len() == 40 && c.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or_else(|| format!("{asset}: the statement names no source commit"))?
            .to_string();
    let text = String::from_utf8(bytes).map_err(|_| format!("{asset}: not UTF-8"))?;
    let messages = parse(&text).map_err(|e| format!("{asset}: {e}"))?;
    root_bin(&messages, tool).map_err(|e| format!("{asset}: {e}"))?;
    Ok(Verified {
        asset,
        messages,
        source_commit,
    })
}

/// Files that decide how the producer built a tool and recorded the build. A record (and the
/// binary in its statement) is admitted only if its run's commit and HEAD agree on all of them:
/// otherwise the bytes came from a pipeline other than the one being merged.
pub(crate) fn producer_inputs(tool: &str) -> Vec<String> {
    let mut v: Vec<String> = [
        ".github/workflows/build-tools-pipeline.yml",
        ".github/workflows/build-tools.yml",
        ".github/actions/install-toolchain",
        ".cargo/config.toml",
        "app/rust-toolchain.toml",
        "tools/TOOLCHAIN.lock",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    for dir in ["tools/build-args", "tools/rustflags", "tools/patches"] {
        v.push(format!("{dir}/{tool}"));
    }
    v.push(format!("tools/locks/{tool}.lock"));
    v
}

/// The producer inputs at `commit` equal HEAD's. The commit is fetched if absent; one that
/// cannot be read fails closed.
pub(crate) fn same_producer(commit: &str, tool: &str) -> Result<(), String> {
    let have = |c: &str| {
        std::process::Command::new("git")
            .args(["cat-file", "-e", &format!("{c}^{{commit}}")])
            .status()
            .is_ok_and(|s| s.success())
    };
    if !have(commit) {
        let _ = crate::advance::git(&["fetch", "--quiet", "origin", commit]);
        if !have(commit) {
            return Err(format!(
                "producer commit {} is not available to compare",
                &commit[..12]
            ));
        }
    }
    let mut args = vec![
        "diff".to_string(),
        "--name-only".to_string(),
        commit.to_string(),
        "HEAD".to_string(),
        "--".to_string(),
    ];
    args.extend(producer_inputs(tool));
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let changed = crate::advance::git(&argv)?;
    let changed: Vec<&str> = changed.lines().filter(|l| !l.trim().is_empty()).collect();
    if changed.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "built at {} by a different pipeline than HEAD's ({}): rerun the producer",
            &commit[..12],
            changed.join(", ")
        ))
    }
}

/// Fetch a producer run's raw record (see `fetch_verified`) and build its evidence.
pub(crate) fn fetch_evidence(
    tool: &str,
    target: &str,
    digest: &str,
    raw_sha256: &str,
    run_id: &str,
) -> Result<String, String> {
    let Verified {
        asset,
        messages: msgs,
        ..
    } = fetch_verified(tool, target, digest, raw_sha256, run_id)?;
    let run_url = gh(&["run", "view", run_id, "--json", "url", "--jq", ".url"])?;
    Ok(evidence(
        &Anchor {
            tool,
            digest,
            run_url: run_url.trim(),
            raw_sha256,
            asset: &asset,
        },
        &msgs,
    ))
}

/// Re-verify a committed `build.jsonl`: it names this subject, its anchored raw record is in the
/// store under the expected name and sha256 with a producer statement naming both it and the
/// binary, and its messages are exactly what that raw record parses to. Returns the messages.
pub(crate) fn verify_custody(
    text: &str,
    tool: &str,
    target: &str,
    digest: &str,
) -> Result<Verified, String> {
    let (h, msgs) = read_evidence(text)?;
    if h["subject"]["name"] != tool || h["subject"]["sha256"] != digest {
        return Err(format!(
            "names another subject than {tool} {}",
            &digest[..12]
        ));
    }
    let raw = h["rawRecord"]["sha256"]
        .as_str()
        .filter(|x| is_hex64(x))
        .ok_or("header has no rawRecord sha256")?;
    let asset = asset_name(tool, target, digest, raw);
    if h["rawRecord"]["asset"] != asset.as_str() {
        return Err(format!("header names another asset than {asset}"));
    }
    let run_id = h["producerRun"]
        .as_str()
        .and_then(|u| u.rsplit_once("/actions/runs/"))
        .map(|(_, id)| id.trim_end_matches('/'))
        .filter(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()))
        .ok_or("header names no producer run")?;
    let fetched = fetch_verified(tool, target, digest, raw, run_id)?;
    if fetched.messages != msgs {
        return Err(format!(
            "{asset}: committed messages differ from the raw record"
        ));
    }
    Ok(Verified {
        asset,
        messages: msgs,
        source_commit: fetched.source_commit,
    })
}

/// The record must show the tool's own `bin` target compiled.
fn root_bin(messages: &[Value], tool: &str) -> Result<(), String> {
    let found = messages.iter().any(|m| {
        m["reason"] == "compiler-artifact"
            && kinds(m).any(|k| k == "bin")
            && m["package_id"]
                .as_str()
                .and_then(|id| package_of(id).ok())
                .is_some_and(|(n, _)| n == tool)
    });
    if found {
        Ok(())
    } else {
        Err(format!("no compiled `bin` target of package {tool}"))
    }
}

fn summary(messages: &[Value]) -> String {
    let units = messages
        .iter()
        .filter(|m| m["reason"] == "compiler-artifact")
        .count();
    let scripts = messages
        .iter()
        .filter(|m| m["reason"] == "build-script-executed")
        .count();
    let cfgs = cfg_env_directives(messages)
        .values()
        .flatten()
        .filter(|d| d.starts_with("cargo:rustc-cfg="))
        .count();
    format!(
        "{units} units compiled from {} packages, {} linked into binaries; {scripts} build scripts run, {cfgs} cfgs set",
        compiled(messages).len(),
        linked(messages).len(),
    )
}

/// `build-record check <raw.jsonl> --package <name>`: the producer's gate on its own record.
/// `build-record baseline --run <id>`: write `build.jsonl` for every TOOLS.lock pin the producer
/// run reproduced, and name each pin it did not.
pub fn run(args: &[String]) -> i32 {
    let res = match args.get(1).map(String::as_str) {
        Some("check") => check(&args[2..]),
        Some("baseline") => baseline(&args[2..]),
        _ => Err(
            "usage: build-record check <raw.jsonl> --package <name> | baseline --run <id>".into(),
        ),
    };
    match res {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("build-record: {e}");
            1
        }
    }
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

/// Parse a raw record file and require the package's own `bin` target. Returns a summary line.
pub(crate) fn check_file(path: &str, package: &str) -> Result<String, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let msgs = parse(&text).map_err(|e| format!("{path}: {e}"))?;
    root_bin(&msgs, package).map_err(|e| format!("{path}: {e}"))?;
    Ok(summary(&msgs))
}

fn check(args: &[String]) -> Result<(), String> {
    let path = args
        .first()
        .filter(|a| !a.starts_with("--"))
        .ok_or("check: no record path")?;
    let package = flag(args, "--package").ok_or("check: --package is required")?;
    println!("build record ({package}): {}", check_file(path, &package)?);
    Ok(())
}

fn baseline(args: &[String]) -> Result<(), String> {
    let run_id = flag(args, "--run").ok_or("baseline: --run is required")?;
    let log = crate::advance::run_log(&run_id)?;
    let lock = std::fs::read_to_string("tools/TOOLS.lock").map_err(|e| e.to_string())?;
    let mut missing = Vec::new();
    for t in crate::gate::parse_tools_lock(&lock) {
        let dir = Path::new("supply-chain/evidence")
            .join(&t.name)
            .join(&t.sha);
        match record_line(&log, &t.name, &t.target, &t.sha)? {
            Some(raw) => {
                let text = fetch_evidence(&t.name, &t.target, &t.sha, &raw, &run_id)?;
                std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
                std::fs::write(dir.join(FILE), &text).map_err(|e| e.to_string())?;
                let (_, msgs) = read_evidence(&text)?;
                println!(
                    "  {} {} {}: {}",
                    t.name,
                    t.target,
                    &t.sha[..12],
                    summary(&msgs)
                );
            }
            None => missing.push(format!(
                "{} {} {} (run {run_id} did not reproduce it)",
                t.name,
                t.target,
                &t.sha[..12]
            )),
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!("no record for: {}", missing.join("; ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RAW: &str = concat!(
        r#"{"reason":"compiler-artifact","package_id":"registry+https://github.com/rust-lang/crates.io-index#serde_json@1.0.154","manifest_path":"C:\\r\\serde_json-1.0.154\\Cargo.toml","target":{"kind":["lib"],"crate_types":["lib"],"name":"serde_json","src_path":"C:\\r\\lib.rs","edition":"2021","doc":true,"doctest":true,"test":true},"profile":{"opt_level":"3","debuginfo":0,"debug_assertions":false,"overflow_checks":false,"test":false},"features":["std"],"filenames":["C:\\t\\libserde_json.rlib"],"executable":null,"fresh":false}"#,
        "\n",
        r#"{"reason":"build-script-executed","package_id":"registry+https://github.com/rust-lang/crates.io-index#serde_json@1.0.154","linked_libs":[],"linked_paths":[],"cfgs":["fast_arithmetic=\"64\""],"env":[["K","v"]],"out_dir":"C:\\t\\out"}"#,
        "\n",
        r#"{"reason":"compiler-artifact","package_id":"registry+https://github.com/rust-lang/crates.io-index#serde_derive@1.0.228","manifest_path":"m","target":{"kind":["proc-macro"],"crate_types":["proc-macro"],"name":"serde_derive","src_path":"s","edition":"2021","doc":true,"doctest":true,"test":true},"profile":{"opt_level":"0","debuginfo":0,"debug_assertions":false,"overflow_checks":false,"test":false},"features":[],"filenames":["f"],"executable":null,"fresh":false}"#,
        "\n",
        r#"{"reason":"compiler-artifact","package_id":"path+file:///D:/a/x/src-cargo-audit/cargo-audit#0.22.2","manifest_path":"m","target":{"kind":["bin"],"crate_types":["bin"],"name":"cargo-audit","src_path":"s","edition":"2021","doc":true,"doctest":false,"test":true},"profile":{"opt_level":"3","debuginfo":0,"debug_assertions":false,"overflow_checks":false,"test":false},"features":[],"filenames":["f"],"executable":"e","fresh":false}"#,
        "\n",
        r#"{"reason":"some-future-reason","x":1}"#,
        "\n",
        r#"{"reason":"build-finished","success":true}"#,
        "\n",
    );

    #[test]
    fn package_ids_of_each_source_kind() {
        let reg = "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228";
        assert_eq!(package_of(reg).unwrap(), ("serde".into(), "1.0.228".into()));
        let path = "path+file:///D:/a/x/src-cargo-audit/cargo-audit#0.22.2";
        assert_eq!(
            package_of(path).unwrap(),
            ("cargo-audit".into(), "0.22.2".into())
        );
        let git = "git+https://github.com/o/r?rev=abc#name@0.1.0";
        assert_eq!(package_of(git).unwrap(), ("name".into(), "0.1.0".into()));
        let git_short = "git+https://github.com/o/tool?rev=abc#0.1.0";
        assert_eq!(
            package_of(git_short).unwrap(),
            ("tool".into(), "0.1.0".into())
        );
        assert!(package_of("serde 1.0.0 (registry+https://x)").is_err());
        assert!(package_of("registry+https://x#serde@").is_err());
    }

    #[test]
    fn parse_keeps_facts_drops_runner_paths() {
        let msgs = parse(RAW).unwrap();
        assert_eq!(
            msgs.len(),
            4,
            "unknown reasons skipped, build-finished not kept"
        );
        let text: String = msgs.iter().map(Value::to_string).collect();
        for gone in [
            "manifest_path",
            "src_path",
            "filenames",
            "out_dir",
            "fresh",
            "executable",
        ] {
            assert!(!text.contains(gone), "{gone} kept");
        }
        assert!(text.contains(r#"fast_arithmetic=\"64\""#));
    }

    #[test]
    fn an_incomplete_failed_or_polluted_record_is_refused() {
        let cut = RAW.rsplit_once(r#"{"reason":"build-finished""#).unwrap().0;
        assert!(parse(cut).unwrap_err().contains("incomplete"));
        let failed = RAW.replace(r#""success":true"#, r#""success":false"#);
        assert!(parse(&failed).unwrap_err().contains("failure"));
        let noisy = format!("Compiling foo\n{RAW}");
        assert!(parse(&noisy).unwrap_err().contains("line 1"));
        let after = format!("{RAW}{}\n", r#"{"reason":"compiler-artifact"}"#);
        assert!(parse(&after).unwrap_err().contains("after build-finished"));
        let no_env_pairs = RAW.replace(r#"[["K","v"]]"#, r#"["K=v"]"#);
        assert!(parse(&no_env_pairs).unwrap_err().contains("env"));
    }

    #[test]
    fn semver_series_keys() {
        assert_eq!(series("1.0.154"), "1");
        assert_eq!(series("0.52.6"), "0.52");
        assert_eq!(series("0.0.7"), "0.0.7");
        assert_eq!(series("2.0.0-rc.1"), "2");
        assert!(std_deps(&parse(RAW).unwrap()).is_empty());
    }

    #[test]
    fn linked_excludes_proc_macros_and_build_scripts() {
        let msgs = parse(RAW).unwrap();
        let l = linked(&msgs);
        assert!(l.contains(&("serde_json".into(), "1.0.154".into())));
        assert!(l.contains(&("cargo-audit".into(), "0.22.2".into())));
        assert!(!l.contains(&("serde_derive".into(), "1.0.228".into())));
        assert!(compiled(&msgs).contains(&("serde_derive".into(), "1.0.228".into())));
    }

    #[test]
    fn directives_spelled_as_the_floors_read_them() {
        let d = cfg_env_directives(&parse(RAW).unwrap());
        assert_eq!(
            d["serde_json@1"],
            vec![
                r#"cargo:rustc-cfg=fast_arithmetic="64""#.to_string(),
                "cargo:rustc-env=K=v".to_string()
            ]
        );
    }

    #[test]
    fn evidence_round_trips_and_refuses_edits() {
        let msgs = parse(RAW).unwrap();
        let digest = "a".repeat(64);
        let raw = "b".repeat(64);
        let a = Anchor {
            tool: "cargo-audit",
            digest: &digest,
            run_url: "https://github.com/o/r/actions/runs/1",
            raw_sha256: &raw,
            asset: "cargo-audit-aaaaaaaaaaaa.build-bbbbbbbbbbbb.jsonl",
        };
        let text = evidence(&a, &msgs);
        let (h, back) = read_evidence(&text).unwrap();
        assert_eq!(back, msgs);
        assert_eq!(h["rawRecord"]["sha256"], raw);
        let edited = text.replace(r#""features":["std"]"#, r#""features":["std"],"note":"x""#);
        assert!(
            read_evidence(&edited)
                .unwrap_err()
                .contains("outside the kept subset")
        );
        let other = text.replacen(SCHEMA, "hp-thermal/evidence-build/v0", 1);
        assert!(read_evidence(&other).is_err());
        assert!(root_bin(&msgs, "cargo-audit").is_ok());
        assert!(root_bin(&msgs, "serde_json").is_err());
    }

    #[test]
    fn record_line_and_asset_name() {
        let d = "c".repeat(64);
        let r = "d".repeat(64);
        let log = format!(
            "build-tools-windows\tBuild\t2026-11-13T00:00:00.0000000Z build record: cargo-audit windows-x86_64 {d} {r}\n\
             build-tools-windows\tBuild\t2026-11-13T00:00:00.0000000Z   echo \"build record: $name $target $d $r\"\n"
        );
        assert_eq!(
            record_line(&log, "cargo-audit", "windows-x86_64", &d).unwrap(),
            Some(r.clone())
        );
        assert_eq!(
            record_line(&log, "cargo-deny", "windows-x86_64", &d).unwrap(),
            None
        );
        let other = "9".repeat(64);
        let forged = format!(
            "{log}x\tstep\t2026-11-13T00:00:01.0000000Z build record: cargo-audit windows-x86_64 {d} {other}\n"
        );
        assert!(
            record_line(&forged, "cargo-audit", "windows-x86_64", &d)
                .unwrap_err()
                .contains("2 records")
        );
        assert_eq!(
            asset_name("cargo-audit", "windows-x86_64", &d, &r),
            "cargo-audit-cccccccccccc.build-dddddddddddd.jsonl"
        );
        assert_eq!(
            asset_name("cargo-acl", "linux-x86_64", &d, &r),
            "cargo-acl-cccccccccccc-linux-x86_64.build-dddddddddddd.jsonl"
        );
    }
}
