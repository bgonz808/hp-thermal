//! `verify-build-env`: the developer-side check of the build-environment pin in
//! `.cargo/config.toml` (`[env]` VCToolsVersion / WindowsSdkDir / WindowsSDKVersion).
//!
//! The pin is enforced by cargo and rustc themselves: find-msvc-tools reads those variables and
//! links with that toolset or fails. This command exists so the failure mode is a sentence
//! instead of a missing link.exe: it resolves the Visual Studio instance the way rustc does
//! (newest installed), checks the pinned toolset and SDK are present, and prints what to install
//! when they are not. No build-environment facts are decided here; the pipeline measures them.

use std::path::{Path, PathBuf};

pub(crate) const CONFIG: &str = ".cargo/config.toml";

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Pin {
    pub toolset: String,
    pub sdk_dir: String,
    pub sdk_version: String,
}

/// `NAME = { value = "..." | '...', ... }` on one line, anywhere in the file.
fn env_value(config: &str, name: &str) -> Result<String, String> {
    let line = config
        .lines()
        .map(str::trim)
        .find(|l| {
            l.strip_prefix(name)
                .is_some_and(|rest| rest.trim_start().starts_with('='))
        })
        .ok_or_else(|| format!("{CONFIG}: no [env] pin for {name}"))?;
    let at = line
        .find("value")
        .ok_or_else(|| format!("{CONFIG}: {name} has no `value`"))?;
    let rest = line[at + "value".len()..].trim_start();
    let rest = rest
        .strip_prefix('=')
        .ok_or_else(|| format!("{CONFIG}: {name} value is not `value = ...`"))?
        .trim_start();
    let quote = rest
        .chars()
        .next()
        .filter(|c| *c == '"' || *c == '\'')
        .ok_or_else(|| format!("{CONFIG}: {name} value is not quoted"))?;
    let body = &rest[1..];
    let end = body
        .find(quote)
        .ok_or_else(|| format!("{CONFIG}: {name} value has no closing quote"))?;
    let v = &body[..end];
    if v.is_empty() {
        return Err(format!("{CONFIG}: {name} value is empty"));
    }
    Ok(v.to_string())
}

pub(crate) fn pin(config: &str) -> Result<Pin, String> {
    let toolset = env_value(config, "VCToolsVersion")?;
    if toolset.split('.').count() != 3
        || !toolset
            .split('.')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(format!(
            "{CONFIG}: VCToolsVersion '{toolset}' is not a Major.Minor.Build toolset directory"
        ));
    }
    Ok(Pin {
        toolset,
        sdk_dir: env_value(config, "WindowsSdkDir")?,
        sdk_version: env_value(config, "WindowsSDKVersion")?
            .trim_end_matches('\\')
            .to_string(),
    })
}

/// Paths the build will look for, given the pin and a Visual Studio installation directory:
/// the linker, the Spectre-mitigated CRT build.rs links against (#385), and the SDK's kernel32.
pub(crate) fn expected_paths(pin: &Pin, vs_install: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let toolset = vs_install
        .join("VC")
        .join("Tools")
        .join("MSVC")
        .join(&pin.toolset);
    let link = toolset
        .join("bin")
        .join("Hostx64")
        .join("x64")
        .join("link.exe");
    let spectre = toolset
        .join("lib")
        .join("spectre")
        .join("x64")
        .join("libcmt.lib");
    let kernel32 = Path::new(&pin.sdk_dir)
        .join("Lib")
        .join(&pin.sdk_version)
        .join("um")
        .join("x64")
        .join("kernel32.lib");
    (link, spectre, kernel32)
}

/// Visual Studio instances, newest first (find-msvc-tools picks the highest version).
#[cfg(windows)]
fn instances() -> Result<Vec<(String, String, PathBuf)>, String> {
    let pf86 = std::env::var("ProgramFiles(x86)").map_err(|_| "ProgramFiles(x86) unset")?;
    let vswhere = Path::new(&pf86)
        .join("Microsoft Visual Studio")
        .join("Installer")
        .join("vswhere.exe");
    if !vswhere.is_file() {
        return Err(format!(
            "{} not found: no Visual Studio installer on this machine",
            vswhere.display()
        ));
    }
    let out = std::process::Command::new(&vswhere)
        .args(["-all", "-products", "*", "-format", "json", "-utf8"])
        .output()
        .map_err(|e| format!("vswhere: {e}"))?;
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).map_err(|e| format!("vswhere json: {e}"))?;
    let mut list: Vec<(String, String, PathBuf)> = v
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|i| {
                    Some((
                        i.get("displayName")?.as_str()?.to_string(),
                        i.get("installationVersion")?.as_str()?.to_string(),
                        PathBuf::from(i.get("installationPath")?.as_str()?),
                    ))
                })
                .collect()
        })
        .unwrap_or_default();
    list.sort_by_key(|a| std::cmp::Reverse(version_key(&a.1)));
    Ok(list)
}

fn version_key(v: &str) -> Vec<u64> {
    v.split('.').map(|p| p.parse().unwrap_or(0)).collect()
}

pub fn run(args: &[String]) -> i32 {
    let flag = |name: &str| {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .map(String::as_str)
    };
    let exe = flag("--exe");
    let against = flag("--against");
    let text = match std::fs::read_to_string(CONFIG) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("verify-build-env: cannot read {CONFIG}: {e} (run from the repo root)");
            return 1;
        }
    };
    let pin = match pin(&text) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("verify-build-env: {e}");
            return 1;
        }
    };
    println!("pinned ({CONFIG} [env]):");
    println!("  MSVC toolset   {}", pin.toolset);
    println!("  Windows SDK    {} under {}", pin.sdk_version, pin.sdk_dir);
    check(&pin, exe, against)
}

/// The toolchain trust policy, shared with `.github/actions/verify-msvc`.
const TRUST: &str = "supply-chain/policy/toolchain-trust.json";

/// Microsoft roots a toolchain signature must chain to, and explicit distrust.
#[derive(Debug)]
pub(crate) struct Trust {
    pub roots: Vec<String>,
    pub revoked_files: Vec<String>,
    pub revoked_certs: Vec<String>,
}

/// Parse `toolchain-trust.json`. No roots, a malformed entry, or another schema fails.
pub(crate) fn parse_trust(text: &str) -> Result<Trust, String> {
    let v: serde_json::Value = serde_json::from_str(text).map_err(|e| format!("{TRUST}: {e}"))?;
    if v["schema"] != "hp-thermal/toolchain-trust/v1" {
        return Err(format!("{TRUST}: unknown schema"));
    }
    let list = |ptr: &str, key: &str, len: usize, upper: bool| -> Result<Vec<String>, String> {
        let mut out = Vec::new();
        for e in v
            .pointer(ptr)
            .and_then(|a| a.as_array())
            .into_iter()
            .flatten()
        {
            let h = e[key].as_str().unwrap_or_default();
            if h.len() != len || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(format!("{TRUST}: {ptr} entry without a {len}-hex `{key}`"));
            }
            out.push(if upper {
                h.to_ascii_uppercase()
            } else {
                h.to_ascii_lowercase()
            });
        }
        Ok(out)
    };
    let roots = list("/microsoft_roots", "sha1", 40, true)?;
    if roots.is_empty() {
        return Err(format!("{TRUST}: names no Microsoft root"));
    }
    Ok(Trust {
        roots,
        revoked_files: list("/revoked/file_sha256", "sha256", 64, false)?,
        revoked_certs: list("/revoked/certificate_sha1", "sha1", 40, true)?,
    })
}

/// Authenticode of `path` as Windows verifies it (WinVerifyTrust, through Windows PowerShell by
/// absolute path): Valid, signed by Microsoft Corporation, chaining to a root in `TRUST`, and
/// matching none of its revoked files or certificates.
#[cfg(windows)]
fn microsoft_signed(path: &Path) -> Result<String, String> {
    let trust = parse_trust(
        &std::fs::read_to_string(TRUST)
            .map_err(|e| format!("{TRUST}: {e} (run from the repo root)"))?,
    )?;
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    if trust
        .revoked_files
        .contains(&crate::sha256::sha256_hex(&bytes))
    {
        return Err(format!("revoked file ({TRUST})"));
    }
    let ps = std::path::PathBuf::from(
        std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()),
    )
    .join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    let lit = path.display().to_string().replace('\'', "''");
    let script = format!(
        "$s = Get-AuthenticodeSignature -LiteralPath '{lit}'; \
         if ($s.Status -ne 'Valid') {{ \"$($s.Status)||\"; exit }}; \
         $c = [System.Security.Cryptography.X509Certificates.X509Chain]::new(); \
         $c.ChainPolicy.RevocationMode = 'NoCheck'; [void]$c.Build($s.SignerCertificate); \
         \"Valid|$($s.SignerCertificate.Subject)|$(($c.ChainElements | ForEach-Object {{ $_.Certificate.Thumbprint }}) -join ',')\""
    );
    // PSModulePath from PowerShell 7 makes Windows PowerShell load the wrong
    // Microsoft.PowerShell.Security; without it, its own default applies.
    let out = std::process::Command::new(&ps)
        .env_remove("PSModulePath")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .map_err(|e| format!("cannot run {}: {e}", ps.display()))?;
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let mut f = text.splitn(3, '|');
    let (status, subject, chain) = (
        f.next().unwrap_or(""),
        f.next().unwrap_or(""),
        f.next().unwrap_or(""),
    );
    let prints: Vec<&str> = chain.split(',').filter(|p| !p.is_empty()).collect();
    let root = prints.last().copied().unwrap_or("");
    if status != "Valid" {
        return Err(format!("Authenticode status {status:?}"));
    }
    if !subject.split(", ").any(|p| p == "O=Microsoft Corporation") {
        return Err(format!("signed by {subject}, not Microsoft Corporation"));
    }
    if let Some(p) = prints
        .iter()
        .find(|p| trust.revoked_certs.iter().any(|r| r == *p))
    {
        return Err(format!("chain holds revoked certificate {p}"));
    }
    if !trust.roots.iter().any(|r| r == root) {
        return Err(format!("chains to unpinned root {root}"));
    }
    Ok(format!("Microsoft-signed, root {}", &root[..8]))
}

/// The formulation facts a release SBOM records for the build environment.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Debug)]
struct Recorded {
    link_version: String,
    link_sha256: String,
    toolset: String,
    sdk: String,
}

#[cfg_attr(not(windows), allow(dead_code))]
fn find_ref<'a>(v: &'a serde_json::Value, r: &str) -> Option<&'a serde_json::Value> {
    if v["bom-ref"] == r {
        return Some(v);
    }
    match v {
        serde_json::Value::Array(a) => a.iter().find_map(|x| find_ref(x, r)),
        serde_json::Value::Object(o) => o.values().find_map(|x| find_ref(x, r)),
        _ => None,
    }
}

#[cfg_attr(not(windows), allow(dead_code))]
fn recorded(sbom: &serde_json::Value) -> Result<Recorded, String> {
    let f = sbom
        .get("formulation")
        .ok_or("the SBOM has no formulation (releases before 0.3.3 carry none)")?;
    let get = |r: &str| find_ref(f, r).ok_or_else(|| format!("formulation has no {r}"));
    let s = |v: &serde_json::Value, k: &str| v[k].as_str().unwrap_or_default().to_string();
    let link = get("build-env:link-exe")?;
    Ok(Recorded {
        link_version: s(link, "version"),
        link_sha256: link["hashes"][0]["content"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        toolset: s(get("build-env:msvc-toolset")?, "version"),
        sdk: s(get("build-env:windows-sdk")?, "version"),
    })
}

/// `--against`: a release tag (its SBOM is downloaded and its provenance verified first) or a
/// path to an SBOM file (taken as given, e.g. a dry run's).
#[cfg_attr(not(windows), allow(dead_code))]
fn load_against(target: &str) -> Result<(serde_json::Value, String), String> {
    let p = Path::new(target);
    if p.is_file() {
        let text = std::fs::read_to_string(p).map_err(|e| format!("{target}: {e}"))?;
        let v = serde_json::from_str(&text).map_err(|e| format!("{target}: {e}"))?;
        return Ok((v, format!("{target} (file, not verified)")));
    }
    let dir = std::env::temp_dir().join(format!("verify-build-env-{target}"));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let d = dir.to_string_lossy().into_owned();
    crate::advance::gh(&[
        "release",
        "download",
        target,
        "--pattern",
        "hp-thermal.cdx.json",
        "--dir",
        &d,
        "--clobber",
    ])?;
    let file = dir.join("hp-thermal.cdx.json");
    let f = file.to_string_lossy().into_owned();
    let repo = crate::advance::gh(&[
        "repo",
        "view",
        "--json",
        "nameWithOwner",
        "--jq",
        ".nameWithOwner",
    ])?;
    let repo = repo.trim();
    // release-pipeline.yml signs from 0.3.3; release.yml signed the releases before it.
    let verified = ["release-pipeline.yml", "release.yml"].iter().any(|w| {
        let signer = format!("{repo}/.github/workflows/{w}");
        crate::advance::gh(&[
            "attestation",
            "verify",
            &f,
            "--repo",
            repo,
            "--signer-workflow",
            &signer,
        ])
        .is_ok()
    });
    if !verified {
        return Err(format!(
            "{target}: SBOM provenance did not verify against this repository's release workflows"
        ));
    }
    let text = std::fs::read_to_string(&file).map_err(|e| e.to_string())?;
    let v = serde_json::from_str(&text).map_err(|e| format!("{f}: {e}"))?;
    Ok((v, format!("release {target} (provenance verified)")))
}

/// Compare this machine's pinned toolchain with what a release's SBOM recorded on the runner.
/// Two independent installs agreeing on the linker's bytes is evidence both are the genuine
/// Microsoft files; any difference is printed and fails.
#[cfg_attr(not(windows), allow(dead_code))]
fn cross_check(pin: &Pin, link: &Path, target: &str) -> bool {
    let (sbom, what) = match load_against(target) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("MISMATCH  --against {target}: {e}");
            return false;
        }
    };
    let rec = match recorded(&sbom) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("MISMATCH  {what}: {e}");
            return false;
        }
    };
    let mut ok = true;
    let mut line = |good: bool, msg: String| {
        if good {
            println!("OK  {msg}");
        } else {
            ok = false;
            eprintln!("MISMATCH  {msg}");
        }
    };
    line(
        rec.toolset == pin.toolset,
        format!("toolset: here {}, {what} {}", pin.toolset, rec.toolset),
    );
    line(
        rec.sdk == pin.sdk_version,
        format!("Windows SDK: here {}, {what} {}", pin.sdk_version, rec.sdk),
    );
    match std::fs::read(link) {
        Ok(bytes) => {
            let here = crate::sha256::sha256_hex(&bytes);
            line(
                here == rec.link_sha256,
                format!(
                    "link.exe {} sha256: here {}, {what} {} ({})",
                    rec.link_version,
                    &here[..16],
                    &rec.link_sha256[..rec.link_sha256.len().min(16)],
                    if here == rec.link_sha256 {
                        "same bytes on both machines"
                    } else {
                        "different bytes"
                    }
                ),
            );
        }
        Err(e) => line(false, format!("{}: {e}", link.display())),
    }
    ok
}

#[cfg(not(windows))]
fn check(_pin: &Pin, _exe: Option<&str>, _against: Option<&str>) -> i32 {
    println!(
        "not Windows: the pin applies to x86_64-pc-windows-msvc builds only; nothing to check here"
    );
    0
}

#[cfg(windows)]
fn check(pin: &Pin, exe: Option<&str>, against: Option<&str>) -> i32 {
    let list = match instances() {
        Ok(l) => l,
        Err(e) => {
            eprintln!("verify-build-env: {e}");
            print_install(pin, None);
            return 1;
        }
    };
    if list.is_empty() {
        eprintln!("verify-build-env: no Visual Studio instance found");
        print_install(pin, None);
        return 1;
    }
    println!("installed Visual Studio instances (rustc uses the newest):");
    for (name, ver, path) in &list {
        println!("  {name} {ver}  {}", path.display());
    }
    let (name, ver, path) = &list[0];
    let (link, spectre, kernel32) = expected_paths(pin, path);
    let mut ok = true;
    let mut missing_spectre = false;
    if link.is_file() {
        println!("OK  toolset {} present in {name} {ver}", pin.toolset);
        match microsoft_signed(&link) {
            Ok(m) => println!("OK  link.exe {m}"),
            Err(e) => {
                ok = false;
                eprintln!("UNVERIFIED  link.exe {}: {e}", link.display());
            }
        }
    } else {
        ok = false;
        let default = std::fs::read_to_string(
            path.join("VC")
                .join("Auxiliary")
                .join("Build")
                .join("Microsoft.VCToolsVersion.default.txt"),
        )
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "?".into());
        eprintln!(
            "MISSING  toolset {} is not in {name} {ver} (its default toolset is {default}); cargo builds will fail to link",
            pin.toolset
        );
    }
    if link.is_file() {
        if spectre.is_file() {
            println!(
                "OK  Spectre-mitigated CRT present for toolset {} (build.rs #385)",
                pin.toolset
            );
        } else {
            ok = false;
            missing_spectre = true;
            eprintln!(
                "MISSING  Spectre-mitigated CRT for toolset {} ({}); build.rs refuses to link without it",
                pin.toolset,
                spectre.display()
            );
        }
    }
    if kernel32.is_file() {
        println!("OK  Windows SDK {} present", pin.sdk_version);
    } else {
        ok = false;
        eprintln!(
            "MISSING  Windows SDK {} under {}",
            pin.sdk_version, pin.sdk_dir
        );
    }
    if let Some(t) = against {
        ok &= link.is_file() && cross_check(pin, &link, t);
    }
    // --exe: the same binding the pipeline makes. The Rich header of a produced exe names the
    // build of the link.exe that wrote it; the pinned toolset's link.exe carries that build in
    // its version resource. Equal means this build used the pinned linker.
    if let Some(exe_path) = exe {
        match linked_by_pinned(Path::new(exe_path), &link) {
            Ok((rich, lv)) => println!(
                "OK  {exe_path}: Rich header linker build {rich} = link.exe {}.{}.{}.{} of toolset {}",
                lv.0, lv.1, lv.2, lv.3, pin.toolset
            ),
            Err(e) => {
                ok = false;
                eprintln!("MISMATCH  {exe_path}: {e}");
            }
        }
    }
    if ok {
        0
    } else {
        print_install(
            pin,
            if missing_spectre && link.is_file() {
                Some(path.as_path())
            } else {
                None
            },
        );
        1
    }
}

const COMPONENTS: &str = "--add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 --add Microsoft.VisualStudio.Component.VC.Runtimes.x86.x64.Spectre";

/// `only_component_missing` names the instance that has the toolset but lacks a component, so
/// the fix is the installer's `modify` rather than a fresh install.
#[cfg(windows)]
fn print_install(pin: &Pin, only_component_missing: Option<&Path>) {
    let sdk = sdk_component(&pin.sdk_version);
    eprintln!();
    if let Some(inst) = only_component_missing {
        eprintln!(
            "The toolset is installed; add the missing component to that instance. `--passive` must start ELEVATED (exit 5007 otherwise), so from pwsh:"
        );
        eprintln!(
            "  Start-Process -Verb RunAs -Wait -FilePath \"${{env:ProgramFiles(x86)}}\\Microsoft Visual Studio\\Installer\\setup.exe\" -ArgumentList 'modify','--installPath','\"{}\"',{},'--add','Microsoft.VisualStudio.Component.Windows11SDK.{sdk}','--passive','--norestart'",
            inst.display(),
            COMPONENTS
                .split(' ')
                .map(|t| format!("'{t}'"))
                .collect::<Vec<_>>()
                .join(",")
        );
    } else {
        eprintln!(
            "To match the pin, install the Visual Studio 2026 Build Tools release whose default toolset is {}",
            pin.toolset
        );
        eprintln!(
            "(the toolset point build follows the Visual Studio servicing release; there is no per-point-build component):"
        );
        eprintln!("  winget show --id Microsoft.VisualStudio.BuildTools --versions");
        eprintln!(
            "  winget install -e --id Microsoft.VisualStudio.BuildTools -v <release> --override \"--passive --wait --norestart {COMPONENTS} --add Microsoft.VisualStudio.Component.Windows11SDK.{sdk}\""
        );
    }
    eprintln!(
        "then run `cargo xtask verify-build-env` again. See CONTRIBUTING.md, Build environment pin."
    );
}

/// `Major.Minor.Build.Revision` from a PE's VS_FIXEDFILEINFO (dwFileVersionMS/LS). The
/// structure is located by its signature and strucVersion rather than by walking the resource
/// directory; every occurrence must agree, so a stray match cannot pick a different number.
/// `Major.Minor.Build.Revision`.
pub(crate) type FileVersion = (u16, u16, u16, u16);

pub(crate) fn file_version(pe: &[u8]) -> Result<FileVersion, String> {
    const SIGNATURE: [u8; 8] = [0xBD, 0x04, 0xEF, 0xFE, 0x00, 0x00, 0x01, 0x00];
    let mut found: Option<FileVersion> = None;
    let mut at = 0;
    while at + 16 <= pe.len() {
        if pe[at..at + 8] == SIGNATURE {
            let ms = u32::from_le_bytes([pe[at + 8], pe[at + 9], pe[at + 10], pe[at + 11]]);
            let ls = u32::from_le_bytes([pe[at + 12], pe[at + 13], pe[at + 14], pe[at + 15]]);
            let v = (
                (ms >> 16) as u16,
                (ms & 0xffff) as u16,
                (ls >> 16) as u16,
                (ls & 0xffff) as u16,
            );
            match found {
                Some(prev) if prev != v => {
                    return Err(format!(
                        "two VS_FIXEDFILEINFO blocks disagree ({prev:?} vs {v:?})"
                    ));
                }
                _ => found = Some(v),
            }
        }
        at += 4;
    }
    found.ok_or_else(|| "no VS_FIXEDFILEINFO (version resource) found".to_string())
}

/// Rich header linker build of `exe` against the file version of `link`; Ok carries both.
pub(crate) fn linked_by_pinned(exe: &Path, link: &Path) -> Result<(u16, FileVersion), String> {
    let pe = std::fs::read(exe).map_err(|e| format!("{}: {e}", exe.display()))?;
    let rich =
        crate::formulate::rich_linker_build(&pe).map_err(|e| format!("{}: {e}", exe.display()))?;
    let lb = std::fs::read(link).map_err(|e| format!("{}: {e}", link.display()))?;
    let lv = file_version(&lb).map_err(|e| format!("{}: {e}", link.display()))?;
    if lv.2 != rich {
        return Err(format!(
            "Rich header linker build {rich} but the pinned toolset's link.exe is {}.{}.{}.{}: this exe was not linked by the pinned toolset",
            lv.0, lv.1, lv.2, lv.3
        ));
    }
    Ok((rich, lv))
}

/// `10.0.26100.0` -> `26100`, the component id suffix.
pub(crate) fn sdk_component(sdk_version: &str) -> &str {
    sdk_version.split('.').nth(2).unwrap_or(sdk_version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_committed_trust_policy_parses_and_bad_ones_fail() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let t = parse_trust(&std::fs::read_to_string(root.join(TRUST)).unwrap()).unwrap();
        assert_eq!(t.roots.len(), 3);
        assert!(
            parse_trust(r#"{"schema":"hp-thermal/toolchain-trust/v1","microsoft_roots":[]}"#)
                .is_err()
        );
        assert!(parse_trust(r#"{"schema":"x","microsoft_roots":[{"sha1":"3B1EFD3A66EA28B16697394703A72CA340A05BD5"}]}"#).is_err());
        let revoked = r#"{"schema":"hp-thermal/toolchain-trust/v1","microsoft_roots":[{"sha1":"3b1efd3a66ea28b16697394703a72ca340a05bd5"}],"revoked":{"file_sha256":[{"sha256":"AB"}]}}"#;
        assert!(parse_trust(revoked).unwrap_err().contains("64-hex"));
        let ok = r#"{"schema":"hp-thermal/toolchain-trust/v1","microsoft_roots":[{"sha1":"3b1efd3a66ea28b16697394703a72ca340a05bd5"}],"revoked":{"certificate_sha1":[{"sha1":"cdd4eeae6000ac7f40c3802c171e30148030c072","why":"drill","date":"2026-11-13"}]}}"#;
        let t = parse_trust(ok).unwrap();
        assert_eq!(t.roots[0], "3B1EFD3A66EA28B16697394703A72CA340A05BD5");
        assert_eq!(
            t.revoked_certs[0],
            "CDD4EEAE6000AC7F40C3802C171E30148030C072"
        );
    }

    #[test]
    fn recorded_reads_nested_formulation_refs() {
        let sbom = serde_json::json!({"formulation": [{"components": [
            {"bom-ref": "build-env:visual-studio", "components": [
                {"bom-ref": "build-env:msvc-toolset", "version": "14.51.36231", "components": [
                    {"bom-ref": "build-env:link-exe", "version": "14.51.36260.0",
                     "hashes": [{"alg": "SHA-256", "content": "ab"}]}]}]},
            {"bom-ref": "build-env:windows-sdk", "version": "10.0.26100.0"}]}]});
        let r = recorded(&sbom).unwrap();
        assert_eq!(
            (
                r.toolset.as_str(),
                r.sdk.as_str(),
                r.link_version.as_str(),
                r.link_sha256.as_str()
            ),
            ("14.51.36231", "10.0.26100.0", "14.51.36260.0", "ab")
        );
        assert!(
            recorded(&serde_json::json!({}))
                .unwrap_err()
                .contains("no formulation")
        );
    }

    const CFG: &str = r#"
[alias]
xtask = "run --manifest-path xtask/Cargo.toml --"

[env]
VCToolsVersion = { value = "14.51.36231", force = true }
WindowsSdkDir = { value = 'C:\Program Files (x86)\Windows Kits\10\', force = true }
WindowsSDKVersion = { value = '10.0.26100.0\', force = true }
"#;

    #[test]
    fn pin_reads_both_quote_styles_and_strips_the_sdk_backslash() {
        let p = pin(CFG).unwrap();
        assert_eq!(p.toolset, "14.51.36231");
        assert_eq!(p.sdk_dir, r"C:\Program Files (x86)\Windows Kits\10\");
        assert_eq!(p.sdk_version, "10.0.26100.0");
        assert_eq!(sdk_component(&p.sdk_version), "26100");
    }

    #[test]
    fn pin_refuses_missing_or_malformed_entries() {
        assert!(
            pin(&CFG.replace("VCToolsVersion", "VCToolsVersionX"))
                .unwrap_err()
                .contains("no [env] pin")
        );
        assert!(
            pin(&CFG.replace("14.51.36231", "14.51"))
                .unwrap_err()
                .contains("Major.Minor.Build")
        );
        assert!(pin(&CFG.replace(r#"value = "14.51.36231""#, r#"value = "#)).is_err());
    }

    #[test]
    fn expected_paths_follow_the_toolset_layout() {
        let p = pin(CFG).unwrap();
        let (link, spectre, k32) = expected_paths(&p, Path::new(r"C:\VS"));
        assert!(link.to_string_lossy().ends_with("link.exe"));
        assert!(link.to_string_lossy().contains("14.51.36231"));
        assert!(spectre.to_string_lossy().contains("spectre"));
        assert!(spectre.to_string_lossy().ends_with("libcmt.lib"));
        assert!(k32.to_string_lossy().contains("10.0.26100.0"));
    }

    fn fixed_file_info(ms: u32, ls: u32) -> Vec<u8> {
        let mut b = vec![0u8; 64];
        b.extend_from_slice(&[0xBD, 0x04, 0xEF, 0xFE, 0x00, 0x00, 0x01, 0x00]);
        b.extend_from_slice(&ms.to_le_bytes());
        b.extend_from_slice(&ls.to_le_bytes());
        b.extend_from_slice(&[0u8; 40]);
        b
    }

    #[test]
    fn file_version_is_read_from_the_fixed_file_info() {
        // 14.51.36260.0
        let b = fixed_file_info((14 << 16) | 51, 36260 << 16);
        assert_eq!(file_version(&b).unwrap(), (14, 51, 36260, 0));
        assert!(
            file_version(&[0u8; 32])
                .unwrap_err()
                .contains("no VS_FIXEDFILEINFO")
        );
        let mut two = fixed_file_info((14 << 16) | 51, 36260 << 16);
        two.extend(fixed_file_info((14 << 16) | 44, 35229 << 16));
        assert!(file_version(&two).unwrap_err().contains("disagree"));
        let mut same = fixed_file_info((14 << 16) | 51, 36260 << 16);
        same.extend(fixed_file_info((14 << 16) | 51, 36260 << 16));
        assert_eq!(file_version(&same).unwrap().2, 36260);
    }

    #[test]
    fn the_committed_config_carries_a_valid_pin() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let text = std::fs::read_to_string(root.join(CONFIG)).expect("root cargo config");
        let p = pin(&text).expect("committed pin parses");
        assert_eq!(sdk_component(&p.sdk_version).len(), 5);
    }
}
