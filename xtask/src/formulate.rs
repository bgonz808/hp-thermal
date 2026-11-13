//! `sbom-formulate`: declare the build environment in the SBOM as CycloneDX 1.6 `formulation`
//! (the spec's carrier for "how this component was manufactured"), so a rebuilder learns the
//! rustc commit, the MSVC toolset, the Windows SDK and the runner image from the SBOM itself.
//!
//! Two kinds of fact meet here and the record keeps them apart:
//! * DECLARED by the build step (`build-env.json`, schema `hp-thermal/build-env/v2`): what was
//!   installed and what rustc's MSVC detection resolves (toolset from
//!   `Microsoft.VCToolsVersion.default.txt`, SDK = newest `lib/<ver>` holding kernel32.lib;
//!   rust-lang/cc-rs find-msvc-tools `vs15plus_vc_read_version`, `get_sdk10_dir`).
//! * MEASURED from the produced exe: the Rich header's linker entry carries the build number of
//!   the link.exe that wrote the file. The declared toolset is admitted only when its link.exe
//!   FileVersion build equals that number; otherwise the declaration is wrong and the step fails.
//!   (Folder version and tool build differ: 14.44.35207 ships link.exe 14.44.35229.)
//!
//! Fail-closed throughout: a SBOM that already carries `formulation` is refused rather than
//! merged; a missing fact is an error, never an empty component.

use serde_json::{Map, Value, json};
use std::path::Path;

pub(crate) const ENV_SCHEMA: &str = "hp-thermal/build-env/v2";
/// Rich header product id of the MSVC 14.x linker. Confirmed against link.exe's FileVersion on
/// toolset 14.44.35207 (link.exe 14.44.35229 -> Rich build 35229).
const RICH_LINKER: u16 = 0x0102;

/// Build number of the linker recorded in the PE's Rich header.
pub(crate) fn rich_linker_build(pe: &[u8]) -> Result<u16, String> {
    if pe.len() < 0x40 || &pe[..2] != b"MZ" {
        return Err("not a PE file (no MZ)".into());
    }
    let e_lfanew = u32::from_le_bytes([pe[0x3c], pe[0x3d], pe[0x3e], pe[0x3f]]) as usize;
    if e_lfanew > pe.len() || e_lfanew < 0x80 {
        return Err("e_lfanew out of range".into());
    }
    let stub = &pe[..e_lfanew];
    let rich = stub
        .windows(4)
        .rposition(|w| w == b"Rich")
        .ok_or("no Rich header (not linked by MSVC link.exe, or stripped)")?;
    if rich + 8 > stub.len() {
        return Err("Rich marker without key".into());
    }
    let dw = |at: usize| u32::from_le_bytes([pe[at], pe[at + 1], pe[at + 2], pe[at + 3]]);
    let key = dw(rich + 4);
    let mut at = rich;
    let mut linker: Option<u16> = None;
    loop {
        if at < 0x80 + 8 {
            return Err("Rich header has no DanS start".into());
        }
        at -= 8;
        let d1 = dw(at) ^ key;
        if d1 == 0x536e_6144 {
            break; // "DanS"
        }
        if (d1 >> 16) as u16 == RICH_LINKER {
            let build = (d1 & 0xffff) as u16;
            match linker {
                Some(b) if b != build => {
                    return Err(format!(
                        "Rich header names two linker builds ({b}, {build})"
                    ));
                }
                _ => linker = Some(build),
            }
        }
    }
    linker.ok_or_else(|| "Rich header has no linker entry (prodid 0x0102)".to_string())
}

/// The declared facts, validated to the shape the formula needs.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct BuildEnv {
    /// Release as rustc reports it: `1.101.0-nightly`.
    pub rustc_version: String,
    /// The full `rustc -vV` first line.
    pub rustc_line: String,
    pub rustc_commit: String,
    pub rustc_host: String,
    pub channel: String,
    pub vs_product: String,
    pub vs_version: String,
    pub toolset: String,
    pub link_file_version: String,
    /// SHA-256 of the link.exe that the pinned toolset resolves to.
    pub link_sha256: String,
    pub sdk_version: String,
    pub image_os: String,
    pub image_version: String,
    pub os_version: String,
}

fn req<'a>(v: &'a Value, path: &str) -> Result<&'a str, String> {
    v.pointer(path)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| format!("build-env{path}: missing or empty"))
}

pub(crate) fn parse_env(text: &str) -> Result<BuildEnv, String> {
    let v: Value = serde_json::from_str(text).map_err(|e| format!("build-env.json: {e}"))?;
    if v.get("schema").and_then(Value::as_str) != Some(ENV_SCHEMA) {
        return Err(format!("build-env.json: schema must be {ENV_SCHEMA}"));
    }
    let commit = req(&v, "/rustc/commit")?;
    if commit.len() != 40 || !commit.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("build-env/rustc/commit: not a 40-hex commit".into());
    }
    // `rustc -vV` first line: "rustc 1.101.0-nightly (a30aa9064 2026-10-08)". The channel the
    // lock pins must be the one that answered: a stable rustc reporting for a nightly pin means
    // the step ran outside the rust-toolchain.toml directory.
    let line = req(&v, "/rustc/version")?;
    let release = line
        .strip_prefix("rustc ")
        .and_then(|s| s.split_whitespace().next())
        .ok_or("build-env/rustc/version: not a `rustc -vV` first line")?;
    let channel = req(&v, "/rustc/channel")?;
    let channel_kind = channel.split('-').next().unwrap_or("");
    let release_kind = release.split('-').nth(1).unwrap_or("stable");
    if channel_kind != release_kind {
        return Err(format!(
            "build-env/rustc: channel {channel} but rustc reports {release}; the toolchain that answered is not the pinned one"
        ));
    }
    Ok(BuildEnv {
        rustc_version: release.to_string(),
        rustc_line: line.to_string(),
        rustc_commit: commit.to_string(),
        rustc_host: req(&v, "/rustc/host")?.to_string(),
        channel: channel.to_string(),
        vs_product: req(&v, "/msvc/product")?.to_string(),
        vs_version: req(&v, "/msvc/product_version")?.to_string(),
        toolset: req(&v, "/msvc/toolset")?.to_string(),
        link_file_version: req(&v, "/msvc/link_file_version")?.to_string(),
        link_sha256: {
            let h = req(&v, "/msvc/link_sha256")?;
            if h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("build-env/msvc/link_sha256: not a 64-hex sha256".into());
            }
            h.to_ascii_lowercase()
        },
        sdk_version: req(&v, "/windows_sdk/version")?.to_string(),
        image_os: req(&v, "/runner/image_os")?.to_string(),
        image_version: req(&v, "/runner/image_version")?.to_string(),
        os_version: req(&v, "/runner/os_version")?.to_string(),
    })
}

/// Build component of a `Major.Minor.Build[.Rev]` file version.
pub(crate) fn file_version_build(fv: &str) -> Result<u16, String> {
    fv.split('.')
        .nth(2)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("file version '{fv}' has no numeric build component"))
}

/// actions/runner-images release tag for a hosted runner, from its `ImageOS` / `ImageVersion`
/// environment. Observed 2026-11-13 against the releases list: the tag prefix is the `ImageOS`
/// value itself (`win25`, `win25-vs2026`, `ubuntu24`) and the tag carries `ImageVersion` without
/// its last component (`20261103.298.1` -> `win25-vs2026/20261103.298`). `None` when the
/// version does not have that shape; a link is a convenience, never a guess.
fn image_release_tag(image_os: &str, image_version: &str) -> Option<String> {
    let parts: Vec<&str> = image_version.split('.').collect();
    let shaped = parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    let os_ok = !image_os.is_empty()
        && image_os
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-');
    (shaped && os_ok).then(|| format!("{image_os}/{}.{}", parts[0], parts[1]))
}

/// Identity of the run, for the workflow resource references.
pub(crate) struct Run<'a> {
    pub repository: &'a str,
    pub workflow_ref: &'a str,
    pub run_id: &'a str,
    pub run_attempt: &'a str,
    pub sha: &'a str,
}

/// The formula. Deterministic for a given (env, linker build, run): no clocks, no attempt id.
pub(crate) fn formula(
    env: &BuildEnv,
    linker_build: u16,
    run: &Run,
    product_ref: Option<&str>,
) -> Result<Value, String> {
    let declared = file_version_build(&env.link_file_version)?;
    if declared != linker_build {
        return Err(format!(
            "declared toolset {} (link.exe {}) did not link this exe: Rich header linker build is {linker_build}",
            env.toolset, env.link_file_version
        ));
    }
    // Structured fields only. What used to be sentences here has a home in the schema: the
    // product -> toolset -> link.exe containment is component nesting; how each version was
    // established is `evidence.identity` (field, concluded value, technique); link.exe is pinned
    // by content hash so anyone can re-check the Rich-header binding.
    let pinned_by = |var: &str| {
        json!({"technique": "manifest-analysis", "confidence": 1.0,
               "value": format!(".cargo/config.toml [env] {var}")})
    };
    let link = json!({
        "type": "application",
        "bom-ref": "build-env:link-exe",
        "supplier": {"name": "Microsoft"},
        "name": "link.exe",
        "version": env.link_file_version,
        "hashes": [{"alg": "SHA-256", "content": env.link_sha256}],
        "evidence": {"identity": [{
            "field": "version",
            "confidence": 1.0,
            "concludedValue": env.link_file_version,
            "methods": [{
                "technique": "binary-analysis",
                "confidence": 1.0,
                "value": format!("Rich header of the build output: prodid 0x0102 build {linker_build}")
            }]
        }]}
    });
    let toolset = json!({
        "type": "application",
        "bom-ref": "build-env:msvc-toolset",
        "supplier": {"name": "Microsoft"},
        "name": "MSVC Build Tools",
        "version": env.toolset,
        "evidence": {"identity": [{
            "field": "version", "confidence": 1.0, "concludedValue": env.toolset,
            "methods": [pinned_by("VCToolsVersion")]
        }]},
        "components": [link]
    });
    let mut components = vec![
        json!({
            "type": "application",
            "bom-ref": "build-env:rustc",
            "name": "rustc",
            "version": env.rustc_version,
            "purl": format!("pkg:github/rust-lang/rust@{}", env.rustc_commit),
            "externalReferences": [{
                "type": "vcs",
                "url": format!("https://github.com/rust-lang/rust/commit/{}", env.rustc_commit)
            }]
        }),
        json!({
            "type": "application",
            "bom-ref": "build-env:visual-studio",
            "supplier": {"name": "Microsoft"},
            "name": env.vs_product,
            "version": env.vs_version,
            "components": [toolset]
        }),
        json!({
            "type": "library",
            "bom-ref": "build-env:windows-sdk",
            "supplier": {"name": "Microsoft"},
            "name": "Windows SDK",
            "version": env.sdk_version,
            "evidence": {"identity": [{
                "field": "version", "confidence": 1.0, "concludedValue": env.sdk_version,
                "methods": [pinned_by("WindowsSDKVersion")]
            }]}
        }),
        json!({
            "type": "operating-system",
            "bom-ref": "build-env:os",
            "supplier": {"name": "Microsoft"},
            "name": "Microsoft Windows",
            "version": env.os_version
        }),
    ];
    let mut image = json!({
        "type": "platform",
        "bom-ref": "build-env:runner-image",
        "name": format!("GitHub Actions runner image {}", env.image_os),
        "version": env.image_version
    });
    if let Some(tag) = image_release_tag(&env.image_os, &env.image_version) {
        image["externalReferences"] = json!([{
            "type": "release-notes",
            "url": format!("https://github.com/actions/runner-images/releases/tag/{}", tag.replace('/', "%2F"))
        }]);
    }
    components.push(image);

    let mut workflow = json!({
        "bom-ref": "build-env:workflow",
        "uid": format!("{}/actions/runs/{}/attempts/{}", run.repository, run.run_id, run.run_attempt),
        "name": run.workflow_ref,
        "taskTypes": ["build"],
        "resourceReferences": [
            {"externalReference": {"type": "build-system",
                "url": format!("https://github.com/{}/actions/runs/{}/attempts/{}", run.repository, run.run_id, run.run_attempt)}},
            {"externalReference": {"type": "vcs",
                "url": format!("https://github.com/{}/tree/{}", run.repository, run.sha)}}
        ]
    });
    if let Some(r) = product_ref {
        workflow["outputs"] = json!([{"type": "artifact", "resource": {"ref": r}}]);
    }
    Ok(json!({
        "bom-ref": "build-env:formula",
        "components": components,
        "workflows": [workflow]
    }))
}

/// Insert the formula into a SBOM that has none.
pub(crate) fn insert(sbom: &mut Value, formula: Value) -> Result<(), String> {
    let obj: &mut Map<String, Value> = sbom.as_object_mut().ok_or("SBOM is not a JSON object")?;
    if obj.get("bomFormat").and_then(Value::as_str) != Some("CycloneDX")
        || obj.get("specVersion").and_then(Value::as_str) != Some("1.6")
    {
        return Err("SBOM is not CycloneDX 1.6".into());
    }
    if obj.contains_key("formulation") {
        return Err("SBOM already carries formulation; refusing to merge or overwrite".into());
    }
    obj.insert("formulation".into(), Value::Array(vec![formula]));
    Ok(())
}

fn arg<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

fn env_or_arg<'a>(
    args: &'a [String],
    name: &str,
    var: &str,
    store: &'a mut String,
) -> Result<&'a str, String> {
    if let Some(v) = arg(args, name) {
        return Ok(v);
    }
    *store = std::env::var(var).map_err(|_| format!("{name} not given and {var} unset"))?;
    Ok(store.as_str())
}

pub fn run(args: &[String]) -> i32 {
    match run_inner(args) {
        Ok(msg) => {
            println!("{msg}");
            0
        }
        Err(e) => {
            eprintln!("sbom-formulate: {e}");
            1
        }
    }
}

fn run_inner(args: &[String]) -> Result<String, String> {
    let sbom_path = arg(args, "--sbom").ok_or("--sbom <file.cdx.json> required")?;
    let exe_path = arg(args, "--exe").ok_or("--exe <hp-thermal.exe> required")?;
    let env_path = arg(args, "--env").ok_or("--env <build-env.json> required")?;
    let out_path = arg(args, "--out").unwrap_or(sbom_path);
    let (mut s1, mut s2, mut s3, mut s4, mut s5) = Default::default();
    let run = Run {
        repository: env_or_arg(args, "--repository", "GITHUB_REPOSITORY", &mut s1)?,
        workflow_ref: env_or_arg(args, "--workflow-ref", "GITHUB_WORKFLOW_REF", &mut s2)?,
        run_id: env_or_arg(args, "--run-id", "GITHUB_RUN_ID", &mut s3)?,
        run_attempt: env_or_arg(args, "--run-attempt", "GITHUB_RUN_ATTEMPT", &mut s4)?,
        sha: env_or_arg(args, "--sha", "GITHUB_SHA", &mut s5)?,
    };
    let env = parse_env(&read(env_path)?)?;
    let pe = std::fs::read(exe_path).map_err(|e| format!("{exe_path}: {e}"))?;
    let linker = rich_linker_build(&pe).map_err(|e| format!("{exe_path}: {e}"))?;
    let mut sbom: Value =
        serde_json::from_str(&read(sbom_path)?).map_err(|e| format!("{sbom_path}: {e}"))?;
    let product_ref = sbom
        .pointer("/metadata/component/bom-ref")
        .and_then(Value::as_str)
        .map(str::to_string);
    let f = formula(&env, linker, &run, product_ref.as_deref())?;
    insert(&mut sbom, f)?;
    let text = serde_json::to_string_pretty(&sbom).map_err(|e| e.to_string())? + "\n";
    std::fs::write(out_path, text).map_err(|e| format!("{out_path}: {e}"))?;
    Ok(format!(
        "sbom-formulate: {out_path}: formulation declared (rustc {} @ {}; MSVC toolset {}, link.exe {} = Rich linker build {linker}; SDK {}; {} {})",
        env.rustc_version,
        &env.rustc_commit[..9],
        env.toolset,
        env.link_file_version,
        env.sdk_version,
        env.image_os,
        env.image_version
    ))
}

fn read(p: &str) -> Result<String, String> {
    std::fs::read_to_string(Path::new(p)).map_err(|e| format!("{p}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A DOS stub carrying a Rich header: DanS, padding, entries, "Rich", key.
    fn pe_with_rich(entries: &[(u16, u16, u32)], key: u32) -> Vec<u8> {
        let mut b = vec![0u8; 0x80];
        b[0] = b'M';
        b[1] = b'Z';
        let mut body = Vec::new();
        body.extend_from_slice(&(0x536e_6144u32 ^ key).to_le_bytes());
        body.extend_from_slice(&key.to_le_bytes());
        body.extend_from_slice(&key.to_le_bytes());
        body.extend_from_slice(&key.to_le_bytes());
        for (prod, build, count) in entries {
            let d1 = ((*prod as u32) << 16) | *build as u32;
            body.extend_from_slice(&(d1 ^ key).to_le_bytes());
            body.extend_from_slice(&(count ^ key).to_le_bytes());
        }
        body.extend_from_slice(b"Rich");
        body.extend_from_slice(&key.to_le_bytes());
        b.extend_from_slice(&body);
        let e_lfanew = b.len() as u32;
        b[0x3c..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
        b.extend_from_slice(b"PE\0\0");
        b
    }

    #[test]
    fn rich_linker_build_is_read_through_the_key() {
        let pe = pe_with_rich(
            &[(0x0104, 35721, 16), (0x0102, 36260, 1), (0x00ff, 36260, 1)],
            0xba4d_27ff,
        );
        assert_eq!(rich_linker_build(&pe).unwrap(), 36260);
    }

    #[test]
    fn rich_refuses_absent_header_two_linkers_and_no_linker() {
        let mut plain = vec![0u8; 0x100];
        plain[0] = b'M';
        plain[1] = b'Z';
        plain[0x3c] = 0x80;
        assert!(rich_linker_build(&plain).unwrap_err().contains("no Rich"));
        let two = pe_with_rich(&[(0x0102, 1, 1), (0x0102, 2, 1)], 7);
        assert!(rich_linker_build(&two).unwrap_err().contains("two linker"));
        let none = pe_with_rich(&[(0x0104, 1, 1)], 7);
        assert!(rich_linker_build(&none).unwrap_err().contains("no linker"));
    }

    const ENV: &str = r#"{"schema":"hp-thermal/build-env/v2",
      "rustc":{"version":"rustc 1.101.0-nightly (a30aa9064 2026-10-08)","commit":"a30aa9064df6a504b6a323c6884a2f4cfbfff666","host":"x86_64-pc-windows-msvc","channel":"nightly-2026-10-09"},
      "msvc":{"product":"Visual Studio Enterprise 2022","product_version":"17.14.1","toolset":"14.51.36231","link_file_version":"14.51.36260.0","link_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
      "windows_sdk":{"version":"10.0.26100.0"},
      "runner":{"image_os":"win25","image_version":"20261105.1.0","os_version":"10.0.26100"}}"#;

    fn run() -> Run<'static> {
        Run {
            repository: "o/r",
            workflow_ref: "o/r/.github/workflows/release-pipeline.yml@refs/tags/v0.3.3",
            run_id: "1",
            run_attempt: "1",
            sha: "0123456789abcdef0123456789abcdef01234567",
        }
    }

    #[test]
    fn env_parses_and_rejects_missing_or_bad_fields() {
        let e = parse_env(ENV).unwrap();
        assert_eq!(e.toolset, "14.51.36231");
        assert_eq!(e.rustc_version, "1.101.0-nightly");
        let stable = ENV.replace(
            "rustc 1.101.0-nightly (a30aa9064 2026-10-08)",
            "rustc 1.99.1 (58cf8f9c3 2026-10-13)",
        );
        assert!(
            parse_env(&stable)
                .unwrap_err()
                .contains("not the pinned one")
        );
        assert!(
            parse_env(&ENV.replace(r#""toolset":"14.51.36231","#, ""))
                .unwrap_err()
                .contains("toolset")
        );
        assert!(
            parse_env(&ENV.replace("a30aa9064df6a504b6a323c6884a2f4cfbfff666", "abc"))
                .unwrap_err()
                .contains("40-hex")
        );
        assert!(parse_env(&ENV.replace("build-env/v2", "build-env/v1")).is_err());
        assert!(
            parse_env(&ENV.replace(&"a".repeat(64), "abc"))
                .unwrap_err()
                .contains("link_sha256")
        );
    }

    #[test]
    fn toolset_is_admitted_only_when_its_linker_wrote_the_exe() {
        let e = parse_env(ENV).unwrap();
        let f = formula(&e, 36260, &run(), Some("app")).unwrap();
        let names: Vec<&str> = f["components"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "rustc",
                "Visual Studio Enterprise 2022",
                "Windows SDK",
                "Microsoft Windows",
                "GitHub Actions runner image win25"
            ]
        );
        // product -> toolset -> link.exe is nesting; versions are established by evidence.
        let toolset = &f["components"][1]["components"][0];
        assert_eq!(toolset["version"], "14.51.36231");
        assert_eq!(
            toolset["evidence"]["identity"][0]["methods"][0]["technique"],
            "manifest-analysis"
        );
        let link = &toolset["components"][0];
        assert_eq!(link["version"], "14.51.36260.0");
        assert_eq!(link["hashes"][0]["alg"], "SHA-256");
        assert_eq!(
            link["evidence"]["identity"][0]["methods"][0]["technique"],
            "binary-analysis"
        );
        assert!(
            f["components"]
                .as_array()
                .unwrap()
                .iter()
                .all(|c| c.get("description").is_none()),
            "no prose descriptions in the formula"
        );
        assert_eq!(f["workflows"][0]["outputs"][0]["resource"]["ref"], "app");
        assert!(
            f["components"][4]["externalReferences"][0]["url"]
                .as_str()
                .unwrap()
                .ends_with("win25%2F20261105.1")
        );
        let err = formula(&e, 36231, &run(), None).unwrap_err();
        assert!(err.contains("did not link this exe"), "{err}");
    }

    #[test]
    fn runner_image_tag_follows_the_observed_shape_or_is_absent() {
        assert_eq!(
            image_release_tag("win25-vs2026", "20261103.298.1").unwrap(),
            "win25-vs2026/20261103.298"
        );
        assert_eq!(
            image_release_tag("ubuntu24", "20261111.1.0").unwrap(),
            "ubuntu24/20261111.1"
        );
        assert!(image_release_tag("win25", "20261103").is_none());
        assert!(image_release_tag("", "20261103.298.1").is_none());
        assert!(image_release_tag("win 25", "20261103.298.1").is_none());
        let e = parse_env(&ENV.replace(
            r#""image_version":"20261105.1.0""#,
            r#""image_version":"custom""#,
        ))
        .unwrap();
        let f = formula(&e, 36260, &run(), None).unwrap();
        assert!(f["components"][4].get("externalReferences").is_none());
        assert!(f["workflows"][0].get("outputs").is_none());
    }

    #[test]
    fn insert_requires_a_1_6_bom_without_formulation() {
        let mut ok = json!({"bomFormat":"CycloneDX","specVersion":"1.6","components":[]});
        insert(&mut ok, json!({"bom-ref":"f"})).unwrap();
        assert_eq!(ok["formulation"].as_array().unwrap().len(), 1);
        assert!(insert(&mut ok, json!({})).unwrap_err().contains("already"));
        let mut old = json!({"bomFormat":"CycloneDX","specVersion":"1.5"});
        assert!(insert(&mut old, json!({})).is_err());
    }

    #[test]
    fn file_version_build_component() {
        assert_eq!(file_version_build("14.44.35229.0").unwrap(), 35229);
        assert!(file_version_build("14.44").is_err());
    }
}
