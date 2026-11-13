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

pub fn run(_args: &[String]) -> i32 {
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
    check(&pin)
}

#[cfg(not(windows))]
fn check(_pin: &Pin) -> i32 {
    println!(
        "not Windows: the pin applies to x86_64-pc-windows-msvc builds only; nothing to check here"
    );
    0
}

#[cfg(windows)]
fn check(pin: &Pin) -> i32 {
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
            "The toolset is installed; add the missing component to that instance (the installer elevates):"
        );
        eprintln!(
            "  \"%ProgramFiles(x86)%\\Microsoft Visual Studio\\Installer\\setup.exe\" modify --installPath \"{}\" {COMPONENTS} --add Microsoft.VisualStudio.Component.Windows11SDK.{sdk} --passive --norestart",
            inst.display()
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

/// `10.0.26100.0` -> `26100`, the component id suffix.
pub(crate) fn sdk_component(sdk_version: &str) -> &str {
    sdk_version.split('.').nth(2).unwrap_or(sdk_version)
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn the_committed_config_carries_a_valid_pin() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let text = std::fs::read_to_string(root.join(CONFIG)).expect("root cargo config");
        let p = pin(&text).expect("committed pin parses");
        assert_eq!(sdk_component(&p.sdk_version).len(), 5);
    }
}
