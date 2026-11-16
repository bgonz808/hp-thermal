//! Cargo's unit graph (`cargo build --unit-graph`, nightly): the units cargo would compile,
//! computed from the reviewed inputs (lock, manifest, target, features, pinned toolchain) before
//! any dependency code runs. Nothing is built. A plan, not a measurement, so it can be trusted
//! where the build's own outputs cannot (#386).
//!
//! `std-deps`: the app builds std from source (`build-std`, app/.cargo/config.toml), so std's own
//! crates.io dependencies are compiled into hp-thermal.exe. They are pinned by the toolchain's
//! `library/Cargo.lock` (rust-src, digest-verified via tools/TOOLCHAIN.lock) and appear in neither
//! app/Cargo.lock nor the exe's `.dep-v0`, so no lock or binary scan covers them. This writes
//! them, copied from std's lock, as a lockfile for the pinned cargo-audit.
//!
//! Add-only: every crates.io unit must come from app/Cargo.lock or std's lock, every path unit
//! must be the app or the toolchain's library, and std must be among the units. Anything else
//! fails; nothing here can drop a package from a scan.

use crate::freeze::{LockEntry, lock_entries};
use std::collections::BTreeMap;
use std::process::{Command, Stdio};

const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";
const APP_DIR: &str = "app";
pub const STD_DEPS_LOCK: &str = "app/target/std-deps.lock";

/// A Package ID Spec as cargo prints it: `<kind>+<url>#<name>@<version>`, or `<kind>+<url>#<version>`
/// when the name is the url's last segment.
fn parse_pkg_id(id: &str) -> Result<(String, String, String), String> {
    let (url, frag) = id
        .split_once('#')
        .ok_or_else(|| format!("unrecognized package id `{id}`"))?;
    let (name, version) = match frag.rsplit_once('@') {
        Some((n, v)) => (n.to_string(), v.to_string()),
        None => (
            url.rsplit('/').next().unwrap_or_default().to_string(),
            frag.to_string(),
        ),
    };
    if name.is_empty() || version.is_empty() || !url.contains('+') {
        return Err(format!("unrecognized package id `{id}`"));
    }
    Ok((url.to_string(), name, version))
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct StdDeps {
    pub units: usize,
    pub std_units: usize,
    /// std's crates.io dependencies compiled into the product, with their std-lock entries.
    pub carried: BTreeMap<(String, String), LockEntry>,
}

/// Classify every unit of `graph` (cargo's `--unit-graph` JSON). `library_url` is the
/// `path+file://` url of the toolchain's library directory; `root_name` the product package.
pub fn analyze(
    graph: &str,
    app_lock: &str,
    std_lock: &str,
    library_url: &str,
    root_name: &str,
) -> Result<StdDeps, String> {
    let g: serde_json::Value =
        serde_json::from_str(graph).map_err(|e| format!("unit graph is not JSON ({e})"))?;
    if g.get("version").and_then(serde_json::Value::as_u64) != Some(1) {
        return Err("unit graph: unsupported format version (expected 1)".into());
    }
    let units = g
        .get("units")
        .and_then(serde_json::Value::as_array)
        .ok_or("unit graph: no `units` array")?;
    let roots = g
        .get("roots")
        .and_then(serde_json::Value::as_array)
        .ok_or("unit graph: no `roots` array")?;
    let [root] = roots.as_slice() else {
        return Err(format!(
            "unit graph: expected exactly one root, found {}",
            roots.len()
        ));
    };
    let root_id = root
        .as_u64()
        .and_then(|i| units.get(usize::try_from(i).ok()?))
        .and_then(|u| u.get("pkg_id"))
        .and_then(serde_json::Value::as_str)
        .ok_or("unit graph: root index out of range")?;
    let (root_url, name, _) = parse_pkg_id(root_id)?;
    if name != root_name || !root_url.starts_with("path+") {
        return Err(format!(
            "unit graph: root is `{root_id}`, expected the local package `{root_name}`"
        ));
    }

    let app = lock_entries(app_lock);
    let std = lock_entries(std_lock);
    let lib_prefix = format!("{}/", library_url.trim_end_matches('/'));
    let mut out = StdDeps {
        units: units.len(),
        ..StdDeps::default()
    };
    for u in units {
        let id = u
            .get("pkg_id")
            .and_then(serde_json::Value::as_str)
            .ok_or("unit graph: a unit has no pkg_id")?;
        let (url, name, version) = parse_pkg_id(id)?;
        let key = (name, version);
        if url == CRATES_IO {
            let from = |l: &BTreeMap<(String, String), LockEntry>| {
                l.get(&key)
                    .filter(|e| e.source.as_deref() == Some(CRATES_IO))
                    .cloned()
            };
            if from(&app).is_some() {
                continue;
            }
            let Some(entry) = from(&std) else {
                return Err(format!(
                    "{}@{} is compiled but is in neither app/Cargo.lock nor std's library/Cargo.lock",
                    key.0, key.1
                ));
            };
            if entry.checksum.is_none() {
                return Err(format!(
                    "{}@{}: std's lock carries no checksum",
                    key.0, key.1
                ));
            }
            out.carried.insert(key, entry);
        } else if url == root_url {
            continue;
        } else if url.starts_with(&lib_prefix) {
            out.std_units += 1;
        } else {
            return Err(format!(
                "`{id}` is neither crates.io, the app, nor the toolchain's library ({library_url})"
            ));
        }
    }
    if out.std_units == 0 {
        return Err(format!(
            "no unit comes from the toolchain's library ({library_url}): std is not built from \
             source, so its crates.io dependencies cannot be enumerated"
        ));
    }
    Ok(out)
}

/// A Cargo.lock holding exactly `carried`, for `cargo audit --file`.
pub fn render_lock(carried: &BTreeMap<(String, String), LockEntry>) -> String {
    let mut s = String::from(
        "# std's crates.io dependencies compiled into the app (xtask std-deps, #386),\n\
         # copied from the pinned toolchain's library/Cargo.lock.\nversion = 4\n",
    );
    for ((n, v), e) in carried {
        s.push_str(&format!(
            "\n[[package]]\nname = \"{n}\"\nversion = \"{v}\"\nsource = \"{}\"\nchecksum = \"{}\"\n",
            e.source.as_deref().unwrap_or_default(),
            e.checksum.as_deref().unwrap_or_default()
        ));
    }
    s
}

/// Run a toolchain command in `dir`, resolved by the shim at that cwd (same scrub as `step`).
fn capture(dir: &str, program: &str, args: &[&str]) -> Result<String, String> {
    let o = Command::new(program)
        .current_dir(dir)
        .env_remove("RUSTUP_TOOLCHAIN")
        .env_remove("CARGO")
        .env_remove("RUSTC")
        .args(args)
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| format!("cannot run `{program}` ({e})"))?;
    if !o.status.success() {
        return Err(format!(
            "`{program} {}` failed ({})",
            args.join(" "),
            o.status
        ));
    }
    String::from_utf8(o.stdout).map_err(|_| format!("`{program}` printed non-UTF-8"))
}

fn std_deps(out_path: &str) -> Result<String, String> {
    // The same command line as the release build, plus --unit-graph: nothing is compiled.
    let graph = capture(
        APP_DIR,
        "cargo",
        &[
            "build",
            "--unit-graph",
            "-Z",
            "unstable-options",
            "--release",
            "--locked",
        ],
    )?;
    let sysroot = capture(APP_DIR, "rustc", &["--print", "sysroot"])?;
    let library = format!(
        "{}/lib/rustlib/src/rust/library",
        sysroot.trim().replace('\\', "/")
    );
    // cargo prints file urls unencoded for these paths; a path that needed percent-encoding
    // would not match and fails closed.
    let library_url = if library.starts_with('/') {
        format!("path+file://{library}")
    } else {
        format!("path+file:///{library}")
    };
    let std_lock_path = format!("{library}/Cargo.lock");
    let std_lock = std::fs::read_to_string(&std_lock_path)
        .map_err(|e| format!("cannot read {std_lock_path} ({e}); is rust-src installed?"))?;
    let app_lock = std::fs::read_to_string(format!("{APP_DIR}/Cargo.lock"))
        .map_err(|e| format!("cannot read {APP_DIR}/Cargo.lock ({e})"))?;
    let r = analyze(&graph, &app_lock, &std_lock, &library_url, "hp-thermal")?;
    std::fs::write(out_path, render_lock(&r.carried))
        .map_err(|e| format!("cannot write {out_path} ({e})"))?;
    let list: Vec<String> = r.carried.keys().map(|(n, v)| format!("{n}@{v}")).collect();
    Ok(format!(
        "{} units ({} from std's source); std's crates.io dependencies compiled in: {} -> {out_path}",
        r.units,
        r.std_units,
        if list.is_empty() {
            "none".into()
        } else {
            list.join(" ")
        }
    ))
}

/// Write the lock for the release gate and the daily monitor. A stale file is removed first, so
/// a failure here can never leave an old list behind for the audit that follows.
pub fn std_deps_step(out_path: &str) -> bool {
    eprintln!("\n=== std's crates.io dependencies (unit graph) ===");
    let _ = std::fs::remove_file(out_path);
    match std_deps(out_path) {
        Ok(s) => {
            eprintln!("{s}");
            true
        }
        Err(e) => {
            eprintln!("FAIL: std-deps — {e}");
            false
        }
    }
}

pub fn run(args: &[String]) -> i32 {
    let out = match args.get(1).map(String::as_str) {
        None => STD_DEPS_LOCK,
        Some("--out") => match args.get(2) {
            Some(p) => p.as_str(),
            None => {
                eprintln!("usage: xtask std-deps [--out PATH]");
                return 2;
            }
        },
        Some(_) => {
            eprintln!("usage: xtask std-deps [--out PATH]");
            return 2;
        }
    };
    i32::from(!std_deps_step(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIB: &str = "path+file:///C:/rust/sysroot/lib/rustlib/src/rust/library";
    const APP: &str = "path+file:///C:/src/hp-thermal/app#hp-thermal@0.3.3";
    const APP_LOCK: &str = "version = 4\n\n[[package]]\nname = \"hp-thermal\"\nversion = \"0.3.3\"\n\n\
        [[package]]\nname = \"windows\"\nversion = \"0.62.2\"\n\
        source = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"aa\"\n";
    const STD_LOCK: &str = "version = 4\n\n[[package]]\nname = \"std\"\nversion = \"0.0.0\"\n\n\
        [[package]]\nname = \"hashbrown\"\nversion = \"0.17.1\"\n\
        source = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"bb\"\n\n\
        [[package]]\nname = \"rand\"\nversion = \"0.9.5\"\n\
        source = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"cc\"\n";

    fn graph(ids: &[&str], roots: &str) -> String {
        let units: Vec<String> = ids
            .iter()
            .map(|i| format!("{{\"pkg_id\":\"{i}\",\"mode\":\"build\",\"platform\":null}}"))
            .collect();
        format!(
            "{{\"version\":1,\"units\":[{}],\"roots\":{roots}}}",
            units.join(",")
        )
    }
    fn std_unit() -> String {
        format!("{LIB}/std#0.0.0")
    }
    fn ok_ids() -> Vec<String> {
        vec![
            APP.into(),
            std_unit(),
            format!("{CRATES_IO}#windows@0.62.2"),
            format!("{CRATES_IO}#hashbrown@0.17.1"),
        ]
    }
    fn run_on(ids: &[String], roots: &str) -> Result<StdDeps, String> {
        let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
        analyze(&graph(&ids, roots), APP_LOCK, STD_LOCK, LIB, "hp-thermal")
    }

    #[test]
    fn carries_only_the_std_packages_cargo_compiles() {
        let r = run_on(&ok_ids(), "[0]").unwrap();
        let keys: Vec<_> = r.carried.keys().cloned().collect();
        // windows is scanned through app/Cargo.lock; rand is in std's lock but not compiled.
        assert_eq!(keys, vec![("hashbrown".to_string(), "0.17.1".to_string())]);
        assert_eq!((r.units, r.std_units), (4, 1));
    }

    #[test]
    fn a_package_from_neither_lock_fails() {
        let mut ids = ok_ids();
        ids.push(format!("{CRATES_IO}#evil@1.0.0"));
        assert!(run_on(&ids, "[0]").unwrap_err().contains("evil@1.0.0"));
        // right name, version the locks do not pin
        let mut ids = ok_ids();
        ids.push(format!("{CRATES_IO}#hashbrown@0.17.2"));
        assert!(run_on(&ids, "[0]").is_err());
    }

    #[test]
    fn other_sources_and_foreign_paths_fail() {
        for id in [
            "git+https://example.com/x#x@1.0.0".to_string(),
            "registry+https://example.com/index#hashbrown@0.17.1".to_string(),
            "path+file:///C:/elsewhere/x#x@1.0.0".to_string(),
            // a sibling directory whose name merely starts like the library's
            format!("{LIB}-evil/std#0.0.0"),
        ] {
            let mut ids = ok_ids();
            ids.push(id.clone());
            assert!(run_on(&ids, "[0]").is_err(), "{id} was accepted");
        }
    }

    #[test]
    fn std_not_built_from_source_fails() {
        let ids = vec![APP.to_string(), format!("{CRATES_IO}#windows@0.62.2")];
        assert!(
            run_on(&ids, "[0]")
                .unwrap_err()
                .contains("not built from source")
        );
    }

    #[test]
    fn root_must_be_the_one_local_product() {
        assert!(run_on(&ok_ids(), "[]").is_err());
        assert!(run_on(&ok_ids(), "[0,1]").is_err());
        assert!(run_on(&ok_ids(), "[9]").is_err());
        // root is a crates.io package
        assert!(run_on(&ok_ids(), "[2]").is_err());
        let mut ids = ok_ids();
        ids[0] = "path+file:///C:/src/other#other@1.0.0".into();
        assert!(run_on(&ids, "[0]").is_err());
    }

    #[test]
    fn source_must_match_not_just_name_and_version() {
        // std's lock lists hashbrown from a git source: not the crates.io package that is compiled
        let std_lock = STD_LOCK.replace(
            "name = \"hashbrown\"\nversion = \"0.17.1\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"",
            "name = \"hashbrown\"\nversion = \"0.17.1\"\nsource = \"git+https://example.com/hb\"",
        );
        let ids: Vec<String> = ok_ids();
        let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
        assert!(analyze(&graph(&ids, "[0]"), APP_LOCK, &std_lock, LIB, "hp-thermal").is_err());
    }

    #[test]
    fn missing_checksum_and_bad_input_fail() {
        let std_lock = STD_LOCK.replace("checksum = \"bb\"\n", "");
        let ids: Vec<String> = ok_ids();
        let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
        assert!(analyze(&graph(&ids, "[0]"), APP_LOCK, &std_lock, LIB, "hp-thermal").is_err());
        assert!(analyze("not json", APP_LOCK, STD_LOCK, LIB, "hp-thermal").is_err());
        let v2 = graph(&ids, "[0]").replace("\"version\":1", "\"version\":2");
        assert!(analyze(&v2, APP_LOCK, STD_LOCK, LIB, "hp-thermal").is_err());
        // the pre-1.77 `name version (source)` id form is not guessed at
        let mut old = ok_ids();
        old.push("hashbrown 0.17.1 (registry+https://github.com/rust-lang/crates.io-index)".into());
        assert!(run_on(&old, "[0]").is_err());
    }

    #[test]
    fn rendered_lock_round_trips_through_the_lock_parser() {
        let r = run_on(&ok_ids(), "[0]").unwrap();
        assert_eq!(lock_entries(&render_lock(&r.carried)), r.carried);
    }

    #[test]
    fn package_ids_parse_both_spec_forms() {
        assert_eq!(
            parse_pkg_id(&format!("{CRATES_IO}#cfg-if@1.0.4")).unwrap(),
            (CRATES_IO.to_string(), "cfg-if".into(), "1.0.4".into())
        );
        assert_eq!(
            parse_pkg_id(&format!("{LIB}/alloc#0.0.0")).unwrap(),
            (format!("{LIB}/alloc"), "alloc".into(), "0.0.0".into())
        );
    }
}
