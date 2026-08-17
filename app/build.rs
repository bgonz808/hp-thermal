fn main() {
    // --- Git build ID ---
    let count = run("git", &["rev-list", "--count", "HEAD"]);
    let hash = run("git", &["rev-parse", "--short", "HEAD"]);
    let dirty = !run("git", &["status", "--porcelain"]).is_empty();

    let build_id = match (count.as_str(), hash.as_str()) {
        ("", _) | (_, "") => "dev".to_string(),
        (n, h) => {
            if dirty {
                format!("{n}.{h}-dirty")
            } else {
                format!("{n}.{h}")
            }
        }
    };
    println!("cargo:rustc-env=BUILD_ID={build_id}");

    // --- Build timestamp (UTC), reproducible ---
    // Source the timestamp deterministically so the SAME commit builds the SAME bytes:
    //   1. SOURCE_DATE_EPOCH (reproducible-builds.org convention; CI/packagers set it),
    //   2. else the HEAD commit's committer time (ties the date to the commit),
    //   3. else wall-clock (only for a git-less build; not reproducible, a last resort).
    // Uniqueness-per-source-change comes from BUILD_ID (commit hash + -dirty) and the
    // compiled code itself, NOT this label — so pinning the date to the commit is exactly
    // what lets a third party rebuild a tag and get a byte-identical exe to verify.
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    let epoch = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .or_else(|| {
            run("git", &["log", "-1", "--format=%ct"])
                .parse::<u64>()
                .ok()
        })
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        });
    let (y, mo, d, hh, mm, ss) = epoch_to_utc(epoch);
    let build_date = format!("{y:04}{mo:02}{d:02}.{hh:02}{mm:02}{ss:02}");
    println!("cargo:rustc-env=BUILD_DATE={build_date}");

    // --- PDB sidecar basename ---
    // The MSVC linker names the PDB after the crate (hp_thermal.pdb); embed the
    // package basename instead (hp-thermal.pdb) so the shipped exe and pdb basenames
    // agree. Derived from CARGO_PKG_NAME — no duplicated literal. /PDBALTPATH also
    // strips the absolute build path from the exe's debug directory (path hygiene +
    // reproducibility). https://learn.microsoft.com/cpp/build/reference/pdbaltpath
    println!(
        "cargo:rustc-link-arg-bins=/PDBALTPATH:{}.pdb",
        env("CARGO_PKG_NAME")
    );

    // --- #106: DELAY-LOAD rstrtmgr + powrprof (close the pre-main DLL-hijack window, honestly) ---
    // Both are used only on cold paths (rstrtmgr: install/uninstall; powrprof: SetSuspendState on
    // Fn+F12). As regular static imports the loader resolves them — and their non-KnownDLL
    // transitive deps (ncrypt / umpdc / wmiclnt) — at process init, BEFORE main()'s
    // SetDefaultDllDirectories(SYSTEM32) pin, via the search order (app dir before System32): a
    // plantable pre-main window (proven exploitable for rstrtmgr->ncrypt). Delay-loading keeps them
    // as DECLARED imports (in the delay-import directory — visible to static analysis, unlike a
    // manual LoadLibrary+GetProcAddress, which reads as dynamic-API-resolution obfuscation) while
    // deferring the load to first use, by when the pin is live -> the deps resolve from System32.
    // Needs delayimp.lib (the MSVC delay-load helper). Pattern per rust-lang/rustup's build.rs.
    // COST: measured +4,608 bytes (~4.5 KB, ~1.5%: 303,616 -> 308,224) for delayimp.lib + the two
    // DLLs' delay thunks — the price of search-order enforcement on these deps. Worth it.
    println!("cargo:rustc-link-arg-bins=/DELAYLOAD:rstrtmgr.dll");
    println!("cargo:rustc-link-arg-bins=/DELAYLOAD:powrprof.dll");
    println!("cargo:rustc-link-arg-bins=delayimp.lib");

    // --- Parse version from Cargo.toml ---
    let version = env("CARGO_PKG_VERSION");
    let parts: Vec<&str> = version.split('.').collect();
    // FILEVERSION/PRODUCTVERSION fields are NUMERIC (u16). A SemVer pre-release like
    // "0.3.0-rc.2" splits to ["0","3","0-rc","2"], so take only each part's leading digits
    // ("0-rc" -> "0"). The full "0.3.0-rc.2" string is preserved in full_version and the
    // StringFileInfo values (which are strings). Without this, rc.exe errors RC2237.
    let numeric = |s: &&str| -> String {
        let d: String = s.chars().take_while(char::is_ascii_digit).collect();
        if d.is_empty() { "0".into() } else { d }
    };
    let major = numeric(parts.first().unwrap_or(&"0"));
    let minor = numeric(parts.get(1).unwrap_or(&"0"));
    let patch = numeric(parts.get(2).unwrap_or(&"0"));

    let build_num = count.parse::<u16>().unwrap_or(0);
    let full_version = format!("{version}+{build_id}");
    let description = ascii_safe(&env("CARGO_PKG_DESCRIPTION"));
    let authors = ascii_safe(&env("CARGO_PKG_AUTHORS"));
    let repository = ascii_safe(&env("CARGO_PKG_REPOSITORY"));
    let license = ascii_safe(&env("CARGO_PKG_LICENSE"));

    // Version-resource identity strings. These carry the author's name IN THE BINARY
    // (File > Properties > Details) and -- via FileDescription -- in the UAC consent
    // dialog's app-name line. This is a human-readable CLAIM only: unsigned, Windows
    // still shows "Publisher: Unknown"; cryptographic proof is Authenticode/SLSA
    // provenance. Use "(C)" not the Unicode (c) glyph -- the .rc stays ASCII.
    let author = authors
        .split('<')
        .next()
        .unwrap_or(&authors)
        .trim()
        .to_string();
    let product = "HP Thermal Control";
    let file_description = format!("{product} by {author}");
    let legal_copyright = format!("(C) {y} {author}. {license} License.");

    // --- Generate .rc with VERSIONINFO + manifest ---
    let rc = format!(
        r#"// Auto-generated by build.rs — do not edit
#include <winver.h>
#include <winresrc.h>

// Executable metadata — shows in Properties, Task Manager, UAC dialog
1 VERSIONINFO
FILEVERSION {major},{minor},{patch},{build_num}
PRODUCTVERSION {major},{minor},{patch},{build_num}
FILEFLAGSMASK VS_FFI_FILEFLAGSMASK
FILEFLAGS 0
FILEOS VOS__WINDOWS32
FILETYPE VFT_APP
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904B0"
        BEGIN
            VALUE "Comments", "{description} - {repository}\0"
            VALUE "CompanyName", "{author}\0"
            VALUE "FileDescription", "{file_description}\0"
            VALUE "FileVersion", "{full_version}\0"
            VALUE "InternalName", "hp-thermal\0"
            VALUE "LegalCopyright", "{legal_copyright}\0"
            VALUE "OriginalFilename", "hp-thermal.exe\0"
            VALUE "ProductName", "{product}\0"
            VALUE "ProductVersion", "{full_version} ({build_date})\0"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x0409, 1200
    END
END

// Onboarding dialog (prototype) — laid out in dialog units. The dialog manager
// scales these to the font/DPI, so no pixel or fitting math is needed in code.
100 DIALOGEX 0, 0, 176, 139
STYLE DS_SETFONT | DS_MODALFRAME | DS_CENTER | WS_POPUP | WS_CAPTION | WS_SYSMENU
CAPTION "Install {product}"
FONT 9, "Segoe UI", 400, 0, 0x1
BEGIN
    LTEXT           "Required:",-1,7,7,120,9
    CONTROL         "SYSTEM service, started at boot",1011,"Button",BS_CHECKBOX | WS_CHILD | WS_VISIBLE,12,18,157,10
    CONTROL         "Installed to Program Files (admin-only)",1012,"Button",BS_CHECKBOX | WS_CHILD | WS_VISIBLE,12,30,157,10
    CONTROL         "Uninstall entry (Settings > Apps)",1013,"Button",BS_CHECKBOX | WS_CHILD | WS_VISIBLE,12,42,157,10
    LTEXT           "Optional:",-1,7,56,120,9
    AUTOCHECKBOX    "Run the tray at logon",1001,12,67,157,10
    AUTOCHECKBOX    "Start Menu shortcut",1002,12,79,157,10
    AUTOCHECKBOX    "Desktop shortcut",1003,12,91,157,10
    RTEXT           "",1020,7,106,162,9
    DEFPUSHBUTTON   "Install",1,65,118,50,14
    PUSHBUTTON      "Cancel",2,119,118,50,14
END
"#
    );

    let out_dir = env("OUT_DIR");
    let rc_path = std::path::Path::new(&out_dir).join("app.rc");
    std::fs::write(&rc_path, &rc).unwrap();

    // --- Manifest via the LINKER (ComCtl32 v6 -> TaskDialogIndirect), NOT the resource
    //     compiler. link.exe is the linker rustc already invokes (an absolute, admin-write-only
    //     VS path resolved by vswhere) -- so, unlike rc.exe's PATH/SDK heuristic that a planted
    //     rc.exe could win OR that silently "not found" on a new SDK layout (shipped the
    //     launch-crashing rc.2), this cannot be squatted or silently dropped. Embeds the exact
    //     app.manifest unchanged, keeping the app-launch-critical resource independent of the
    //     resource compiler entirely.
    let target = env("TARGET");
    if target.ends_with("windows-msvc") {
        let abs_manifest = std::path::Path::new(&env("CARGO_MANIFEST_DIR"))
            .join("app.manifest")
            .canonicalize()
            .expect("app.manifest must exist");
        println!("cargo:rustc-link-arg-bins=/MANIFEST:EMBED");
        println!(
            "cargo:rustc-link-arg-bins=/MANIFESTINPUT:{}",
            abs_manifest.display()
        );
    }

    // --- VERSIONINFO + the onboarding DIALOG still need a resource compiler. Pin it to the
    //     CANONICAL Microsoft rc.exe, located by ABSOLUTE PATH from the admin-write-only HKLM
    //     SDK registry root -- never a bare name / PATH search a planted rc.exe could win
    //     (CWE-426 at build time, upstream of signing). Same principle as install.rs::system32_exe.
    //     FAIL-LOUD: no canonical compiler => no build, never a silent resource drop.
    let rc_exe = canonical_rc_exe();
    // rc.exe needs the SDK headers (winver.h/winresrc.h + the window-style macros the DIALOG
    // uses). Pinning RC bypasses embed_resource's own include setup, so point INCLUDE at the
    // canonical SDK include dirs derived from the SAME trusted root as rc.exe
    // (<root>\bin\<ver>\x64\rc.exe -> <root>\Include\<ver>\{um,shared}). Admin-write-only, so
    // not squattable; prepended to any existing INCLUDE.
    let ver_dir = rc_exe.parent().and_then(|p| p.parent()); // <root>\bin\<ver>
    let (ver, sdk_root) = ver_dir
        .and_then(|v| Some((v.file_name()?, v.parent()?.parent()?)))
        .expect("unexpected rc.exe path layout");
    let inc = sdk_root.join("Include").join(ver);
    let (um, shared) = (inc.join("um"), inc.join("shared"));
    assert!(
        um.is_dir() && shared.is_dir(),
        "SDK include dirs missing under {} -- SDK incomplete",
        inc.display()
    );
    let prior = std::env::var("INCLUDE").unwrap_or_default();
    let include = format!("{};{};{prior}", um.display(), shared.display());

    // Invoke the pinned rc.exe DIRECTLY (not via embed_resource): full control of the compiler
    // path, its header search, and its args -- no third-party heuristic that could pick a
    // planted rc.exe or a wrong INCLUDE. Compile app.rc -> app.res, then hand the .res to the
    // MSVC linker (which accepts .res inputs) via rustc-link-arg. FAIL-LOUD on any failure.
    let res_path = std::path::Path::new(&out_dir).join("app.res");
    let out = std::process::Command::new(&rc_exe)
        .env("INCLUDE", &include)
        .args(["/nologo", "/fo"])
        .arg(&res_path)
        .arg(&rc_path)
        .output()
        .unwrap_or_else(|e| panic!("failed to run pinned rc.exe {}: {e}", rc_exe.display()));
    if !out.status.success() {
        panic!(
            "pinned rc.exe {} failed to compile {} -- refusing to ship a binary missing its \
             VERSIONINFO/onboarding-dialog resources.\nINCLUDE={}\nstdout: {}\nstderr: {}",
            rc_exe.display(),
            rc_path.display(),
            include,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }
    println!("cargo:rustc-link-arg-bins={}", res_path.display());

    // --- Rerun triggers ---
    println!("cargo:rerun-if-changed=src/");
    println!("cargo:rerun-if-changed=app.manifest");
    for dir in &[".", ".."] {
        let git = format!("{dir}/.git");
        if std::path::Path::new(&git).exists() {
            println!("cargo:rerun-if-changed={git}/HEAD");
            println!("cargo:rerun-if-changed={git}/index");
            break;
        }
    }
}

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_default()
}

/// Replace non-ASCII chars with '?' so the .rc file stays clean for the resource compiler.
fn ascii_safe(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii() { c } else { '?' })
        .collect()
}

fn epoch_to_utc(secs: u64) -> (u64, u64, u64, u64, u64, u64) {
    let s = secs % 86400;
    let hh = s / 3600;
    let mm = (s % 3600) / 60;
    let ss = s % 60;
    let mut days = (secs / 86400) as i64;
    let mut y = 1970i64;
    loop {
        let ydays = if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) {
            366
        } else {
            365
        };
        if days < ydays {
            break;
        }
        days -= ydays;
        y += 1;
    }
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let mdays = [
        31,
        if leap { 29 } else { 28 },
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
    while m < 12 && days >= mdays[m] {
        days -= mdays[m];
        m += 1;
    }
    (y as u64, (m + 1) as u64, (days + 1) as u64, hh, mm, ss)
}

/// Absolute path to the CANONICAL Microsoft rc.exe, so the resource compiler cannot be
/// squatted (a planted rc.exe on PATH/CWD executing inside build.rs, upstream of signing --
/// CWE-426). Trust chain: the SDK root comes from `HKLM\...\Windows Kits\Installed Roots`
/// `KitsRoot10` -- an admin-write-only registry value pointing into an admin-write-only
/// Program Files directory, neither plantable by a standard user. We read it via the
/// hardcoded System32 reg.exe (not a PATH-searchable `reg`, same squat-avoidance), pick the
/// highest installed SDK version, and require rc.exe to actually exist there. Panics (build
/// fails) if no canonical rc.exe is found -- never falls back to a search.
fn canonical_rc_exe() -> std::path::PathBuf {
    // Hardcoded System32 reg.exe: %SystemRoot% could be repointed to stage a planted reg.exe,
    // so we do not trust it for locating the tool that then locates our compiler.
    let reg = std::path::Path::new("C:\\Windows\\System32\\reg.exe");
    let out = std::process::Command::new(reg)
        .args([
            "query",
            r"HKLM\SOFTWARE\Microsoft\Windows Kits\Installed Roots",
            "/v",
            "KitsRoot10",
            "/reg:64",
        ])
        .output()
        .expect("failed to run System32 reg.exe to locate the Windows SDK root");
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Line looks like: `    KitsRoot10    REG_SZ    C:\Program Files (x86)\Windows Kits\10\`
    let root = stdout
        .lines()
        .find(|l| l.contains("KitsRoot10") && l.contains("REG_SZ"))
        .and_then(|l| l.split("REG_SZ").nth(1))
        .map(|s| s.trim().to_string())
        .expect("KitsRoot10 not found in HKLM (Windows SDK not installed?)");

    let bin = std::path::Path::new(&root).join("bin");
    let mut versions: Vec<std::path::PathBuf> = std::fs::read_dir(&bin)
        .unwrap_or_else(|e| panic!("cannot read SDK bin dir {}: {e}", bin.display()))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.is_dir()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("10."))
        })
        .collect();
    versions.sort(); // lexicographic sort of 10.0.NNNNN.0 dirs; highest is last
    for v in versions.iter().rev() {
        let rc = v.join("x64").join("rc.exe");
        if rc.is_file() {
            return rc;
        }
    }
    panic!(
        "no canonical rc.exe under {}\\bin\\10.*\\x64 -- Windows SDK incomplete. Refusing to \
         search PATH for a resource compiler.",
        root
    );
}

fn run(cmd: &str, args: &[&str]) -> String {
    let mut c = std::process::Command::new(cmd);
    // Harden the git calls against config-driven code execution at build time: a hostile
    // checkout's .git/config (or a poisoned global/system config) can set core.fsmonitor
    // or core.pager to run a program when git executes. Ignore system+global config and
    // blank those keys. (rev-list/rev-parse/status don't run hooks.) A PATH-planted `git`
    // stays a build-env trust assumption — build.rs + build-deps already run arbitrary
    // code at build, so that's the actual boundary.
    if cmd == "git" {
        c.env("GIT_CONFIG_NOSYSTEM", "1")
            .env(
                "GIT_CONFIG_GLOBAL",
                if cfg!(windows) { "NUL" } else { "/dev/null" },
            )
            .env("GIT_TERMINAL_PROMPT", "0")
            .args(["-c", "core.fsmonitor=", "-c", "core.pager=cat"]);
    }
    c.args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}
