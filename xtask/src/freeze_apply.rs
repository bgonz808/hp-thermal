//! `cargo xtask freeze-apply --run <id> [--no-commit]`: the maintainer's half of the
//! strictly-better fix automation (#405).
//!
//! `freeze-propose.yml` computes proposals with read-only permissions and reports them in one
//! issue; it holds no write access to the repository. This command takes one run's proposal,
//! checks where it came from and that its bytes are the ones GitHub recorded, writes the proposed
//! locks, and commits them with the maintainer's signing key. The PR then runs every required
//! check like any other change; nothing is blessed until the producer build, the gate, and a merge.
//!
//! Refused unless: the run is `freeze-propose.yml` on `main` of this repository, started by its
//! schedule or a dispatch, and succeeded; the `freeze-proposal` artifact is unexpired and its
//! SHA-256 equals GitHub's recorded digest; the archive holds only `proposals.json`, `report.md`
//! and `locks/<tool>.lock` for tools TOOLS.lock pins; the locks are exactly the proposals' tools.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde_json::Value;

use crate::advance::{gh, gh_json, git, s};

const WORKFLOW: &str = ".github/workflows/freeze-propose.yml";
const ARTIFACT: &str = "freeze-proposal";
/// Largest file the archive may expand to; a proposal is a few locks and a report.
const MAX_ENTRY: usize = 16 << 20;

/// Why `run` (the Actions API run object) is not a run this command takes a proposal from.
pub(crate) fn run_refusal(run: &Value, repo: &str) -> Option<String> {
    let path = s(run, &["path"]);
    if path != WORKFLOW {
        return Some(format!("workflow is `{path}`, not `{WORKFLOW}`"));
    }
    for (what, got) in [
        ("repository", s(run, &["repository", "full_name"])),
        ("head repository", s(run, &["head_repository", "full_name"])),
    ] {
        if got != repo {
            return Some(format!("{what} is `{got}`, not `{repo}`"));
        }
    }
    let branch = s(run, &["head_branch"]);
    if branch != "main" {
        return Some(format!("ran on `{branch}`, not `main`"));
    }
    let event = s(run, &["event"]);
    if event != "schedule" && event != "workflow_dispatch" {
        return Some(format!(
            "started by `{event}`, not its schedule or a dispatch"
        ));
    }
    let (status, conclusion) = (s(run, &["status"]), s(run, &["conclusion"]));
    if status != "completed" || conclusion != "success" {
        return Some(format!(
            "run is {status}/{conclusion}, not completed/success"
        ));
    }
    None
}

/// Entries of a zip archive (stored or deflated), by name. Minimal by design: the central
/// directory is found from the end-of-central-directory record; ZIP64, multi-disk and encrypted
/// archives are refused, and so is any name that appears twice.
pub(crate) fn unzip(bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let le16 = |o: usize| -> Result<usize, String> {
        bytes
            .get(o..o + 2)
            .map(|x| u16::from_le_bytes([x[0], x[1]]) as usize)
            .ok_or_else(|| "zip: truncated".to_string())
    };
    let le32 = |o: usize| -> Result<usize, String> {
        bytes
            .get(o..o + 4)
            .map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]]) as usize)
            .ok_or_else(|| "zip: truncated".to_string())
    };
    if bytes.len() < 22 {
        return Err("zip: too short".into());
    }
    let low = bytes.len().saturating_sub(22 + 0xffff);
    let eocd = (low..=bytes.len() - 22)
        .rev()
        .find(|&i| bytes[i..i + 4] == [0x50, 0x4b, 0x05, 0x06])
        .ok_or("zip: no end-of-central-directory record")?;
    let (disk, cd_disk, entries, cd_off) = (
        le16(eocd + 4)?,
        le16(eocd + 6)?,
        le16(eocd + 10)?,
        le32(eocd + 16)?,
    );
    if disk != 0 || cd_disk != 0 || entries == 0xffff || cd_off == 0xffff_ffff {
        return Err("zip: multi-disk or ZIP64 archives are refused".into());
    }
    let mut out = BTreeMap::new();
    let mut p = cd_off;
    for _ in 0..entries {
        if le32(p)? != 0x0201_4b50 {
            return Err("zip: bad central directory entry".into());
        }
        let (flags, method) = (le16(p + 8)?, le16(p + 10)?);
        let (csize, size) = (le32(p + 20)?, le32(p + 24)?);
        let (nlen, elen, clen) = (le16(p + 28)?, le16(p + 30)?, le16(p + 32)?);
        let local = le32(p + 42)?;
        let raw = bytes
            .get(p + 46..p + 46 + nlen)
            .ok_or("zip: truncated name")?;
        let name = std::str::from_utf8(raw)
            .map_err(|_| "zip: a name is not UTF-8".to_string())?
            .to_string();
        p += 46 + nlen + elen + clen;
        if flags & 1 != 0 {
            return Err(format!("zip: {name} is encrypted"));
        }
        if name.ends_with('/') {
            continue;
        }
        if size > MAX_ENTRY {
            return Err(format!(
                "zip: {name} expands to {size} bytes, over the {MAX_ENTRY}-byte limit"
            ));
        }
        if le32(local)? != 0x0403_4b50 {
            return Err(format!("zip: {name}: bad local header"));
        }
        let start = local + 30 + le16(local + 26)? + le16(local + 28)?;
        let data = bytes
            .get(start..start + csize)
            .ok_or_else(|| format!("zip: {name}: truncated data"))?;
        let content = match method {
            0 => data.to_vec(),
            8 => miniz_oxide::inflate::decompress_to_vec_with_limit(data, MAX_ENTRY)
                .map_err(|e| format!("zip: {name}: inflate failed: {e:?}"))?,
            m => return Err(format!("zip: {name}: compression method {m} is refused")),
        };
        if content.len() != size {
            return Err(format!(
                "zip: {name}: {} bytes, the directory records {size}",
                content.len()
            ));
        }
        if out.insert(name.clone(), content).is_some() {
            return Err(format!("zip: {name} appears twice"));
        }
    }
    Ok(out)
}

/// Tools TOOLS.lock pins (first field of every non-comment line).
pub(crate) fn pinned_tools(tools_lock: &str) -> BTreeSet<String> {
    tools_lock
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_whitespace().next())
        .map(str::to_string)
        .collect()
}

/// The proposal's locks by tool, after checking every file in the archive.
pub(crate) fn proposal_locks(
    files: &BTreeMap<String, Vec<u8>>,
    pinned: &BTreeSet<String>,
) -> Result<(Value, BTreeMap<String, String>), String> {
    let mut locks = BTreeMap::new();
    let mut proposals = None;
    for (name, bytes) in files {
        let text = || String::from_utf8(bytes.clone()).map_err(|_| format!("{name} is not UTF-8"));
        match name.as_str() {
            "proposals.json" => {
                proposals = Some(
                    serde_json::from_str::<Value>(&text()?).map_err(|e| format!("{name}: {e}"))?,
                )
            }
            "report.md" => {}
            other => {
                let tool = other
                    .strip_prefix("locks/")
                    .and_then(|t| t.strip_suffix(".lock"))
                    .filter(|t| !t.contains(['/', '.']) && !t.is_empty())
                    .ok_or_else(|| format!("unexpected file `{other}` in the proposal"))?;
                if !pinned.contains(tool) {
                    return Err(format!(
                        "`{other}` is for `{tool}`, which TOOLS.lock does not pin"
                    ));
                }
                locks.insert(tool.to_string(), text()?);
            }
        }
    }
    let proposals = proposals.ok_or("the proposal has no proposals.json")?;
    let named: BTreeSet<String> = proposals["proposals"]
        .as_array()
        .ok_or("proposals.json has no `proposals` array")?
        .iter()
        .map(|p| s(p, &["tool"]))
        .collect();
    let have: BTreeSet<String> = locks.keys().cloned().collect();
    if named.is_empty() || named != have {
        return Err(format!(
            "the locks ({}) are not exactly the proposals' tools ({})",
            have.into_iter().collect::<Vec<_>>().join(", "),
            named.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    Ok((proposals, locks))
}

/// `name old -> new` for every package whose version set changed between two locks.
pub(crate) fn lock_changes(old: &str, new: &str) -> Vec<String> {
    let (a, b) = (
        crate::freeze::lock_package_versions(old),
        crate::freeze::lock_package_versions(new),
    );
    let names: BTreeSet<&String> = a.keys().chain(b.keys()).collect();
    names
        .into_iter()
        .filter(|n| a.get(*n) != b.get(*n))
        .map(|n| {
            let show =
                |v: Option<&Vec<String>>| v.map(|v| v.join("+")).unwrap_or_else(|| "(none)".into());
            format!("{n} {} -> {}", show(a.get(n)), show(b.get(n)))
        })
        .collect()
}

fn apply(run_id: &str, no_commit: bool) -> Result<(), String> {
    let branch = git(&["rev-parse", "--abbrev-ref", "HEAD"])?
        .trim()
        .to_string();
    if branch == "main" || branch == "HEAD" {
        return Err("check out a new branch first; freeze-apply never commits on main".into());
    }
    if !git(&["status", "--porcelain", "--", "tools/locks"])?
        .trim()
        .is_empty()
    {
        return Err("tools/locks has uncommitted changes".into());
    }
    let repo = gh(&[
        "repo",
        "view",
        "--json",
        "nameWithOwner",
        "--jq",
        ".nameWithOwner",
    ])?
    .trim()
    .to_string();
    let run = gh_json(&["api", &format!("repos/{repo}/actions/runs/{run_id}")])?;
    if let Some(why) = run_refusal(&run, &repo) {
        return Err(format!("run {run_id} refused: {why}"));
    }
    let list = gh_json(&[
        "api",
        &format!("repos/{repo}/actions/runs/{run_id}/artifacts?per_page=100"),
    ])?;
    let art = list["artifacts"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|a| s(a, &["name"]) == ARTIFACT)
        .ok_or_else(|| format!("run {run_id} has no `{ARTIFACT}` artifact"))?;
    if art["expired"].as_bool() != Some(false) {
        return Err(format!(
            "the `{ARTIFACT}` artifact of run {run_id} has expired"
        ));
    }
    let want = s(art, &["digest"]);
    let want = want
        .strip_prefix("sha256:")
        .filter(|d| d.len() == 64)
        .ok_or("GitHub records no SHA-256 digest for the artifact")?;
    let dir = std::env::temp_dir().join(format!("freeze-apply-{run_id}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let zip = dir.join("artifact.zip");
    let id = s(art, &["id"]);
    let out = std::process::Command::new("gh")
        .args(["api", &format!("repos/{repo}/actions/artifacts/{id}/zip")])
        .output()
        .map_err(|e| format!("gh: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "artifact download failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    std::fs::write(&zip, &out.stdout).map_err(|e| e.to_string())?;
    let got = crate::sha256::sha256_hex(&out.stdout);
    if got != want {
        return Err(format!(
            "artifact SHA-256 {got} differs from GitHub's recorded {want}"
        ));
    }
    println!(
        "run {run_id}: {WORKFLOW} on main ({}), artifact {} sha256 {}",
        s(&run, &["event"]),
        id,
        &got[..12]
    );

    let pinned = pinned_tools(
        &std::fs::read_to_string("tools/TOOLS.lock")
            .map_err(|e| format!("tools/TOOLS.lock: {e}"))?,
    );
    let (proposals, locks) = proposal_locks(&unzip(&out.stdout)?, &pinned)?;
    let mut paths = Vec::new();
    for (tool, text) in &locks {
        let p = PathBuf::from("tools/locks").join(format!("{tool}.lock"));
        let old = std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        let changes = lock_changes(&old, text);
        if changes.is_empty() {
            return Err(format!(
                "{tool}: the proposed lock changes no package version"
            ));
        }
        println!("  {tool}:");
        for c in &changes {
            println!("    {c}");
        }
        std::fs::write(&p, text).map_err(|e| format!("{}: {e}", p.display()))?;
        paths.push(p);
    }
    let tools: Vec<&String> = locks.keys().collect();
    let mut fixes: Vec<String> = proposals["proposals"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|p| {
            p["fixes"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|f| f.as_str().unwrap_or_default().to_string())
        })
        .collect();
    fixes.sort();
    fixes.dedup();
    let msg = format!(
        "freeze-apply: {} - {} (#405, run {run_id})",
        tools
            .iter()
            .map(|t| t.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        fixes.join(", ")
    );
    for p in &paths {
        git(&["add", "--", &p.to_string_lossy()])?;
    }
    if no_commit {
        println!("(--no-commit) staged: {msg}");
        return Ok(());
    }
    git(&["commit", "-q", "-S", "-m", &msg])?;
    println!(
        "committed {}: {msg}",
        git(&["log", "-1", "--format=%h %G?"])?.trim()
    );
    println!("next: git push -u origin {branch} && gh pr create --fill");
    Ok(())
}

pub fn run(args: &[String]) -> i32 {
    let usage = "usage: cargo xtask freeze-apply --run <freeze-propose run id> [--no-commit]";
    let (mut run_id, mut no_commit) = (String::new(), false);
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--run" => run_id = it.next().cloned().unwrap_or_default(),
            "--no-commit" => no_commit = true,
            other => {
                eprintln!("freeze-apply: unknown argument {other}\n{usage}");
                return 2;
            }
        }
    }
    if run_id.is_empty() || !run_id.bytes().all(|b| b.is_ascii_digit()) {
        eprintln!("{usage}");
        return 2;
    }
    match apply(&run_id, no_commit) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("freeze-apply: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn zip_of(files: &[(&str, &[u8], bool)]) -> Vec<u8> {
        let (mut out, mut cd) = (Vec::new(), Vec::new());
        for (name, data, deflate) in files {
            let body = if *deflate {
                miniz_oxide::deflate::compress_to_vec(data, 6)
            } else {
                data.to_vec()
            };
            let method: u16 = if *deflate { 8 } else { 0 };
            let off = out.len() as u32;
            out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
            out.extend_from_slice(&[20, 0, 0, 0]);
            out.extend_from_slice(&method.to_le_bytes());
            out.extend_from_slice(&[0; 8]);
            out.extend_from_slice(&(body.len() as u32).to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&[0, 0]);
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&body);
            cd.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
            cd.extend_from_slice(&[20, 0, 20, 0, 0, 0]);
            cd.extend_from_slice(&method.to_le_bytes());
            cd.extend_from_slice(&[0; 8]);
            cd.extend_from_slice(&(body.len() as u32).to_le_bytes());
            cd.extend_from_slice(&(data.len() as u32).to_le_bytes());
            cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
            cd.extend_from_slice(&[0; 12]);
            cd.extend_from_slice(&off.to_le_bytes());
            cd.extend_from_slice(name.as_bytes());
        }
        let (cd_off, cd_len) = (out.len() as u32, cd.len() as u32);
        out.extend_from_slice(&cd);
        out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.extend_from_slice(&(files.len() as u16).to_le_bytes());
        out.extend_from_slice(&(files.len() as u16).to_le_bytes());
        out.extend_from_slice(&cd_len.to_le_bytes());
        out.extend_from_slice(&cd_off.to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out
    }

    #[test]
    fn unzip_reads_stored_and_deflated_entries_and_refuses_damage() {
        let z = zip_of(&[
            ("report.md", b"hello", false),
            ("locks/cargo-acl.lock", b"version = 4\n", true),
        ]);
        let m = unzip(&z).unwrap();
        assert_eq!(m["report.md"], b"hello");
        assert_eq!(m["locks/cargo-acl.lock"], b"version = 4\n");
        assert!(unzip(&z[..z.len() - 3]).is_err(), "truncated end record");
        let twice = zip_of(&[("a", b"1", false), ("a", b"2", false)]);
        assert!(unzip(&twice).unwrap_err().contains("twice"));
        assert!(unzip(b"not a zip at all, really not").is_err());
    }

    #[test]
    fn only_freeze_propose_on_main_by_schedule_or_dispatch_and_successful() {
        let ok = json!({"path": WORKFLOW, "repository": {"full_name": "o/r"}, "head_repository": {"full_name": "o/r"},
                        "head_branch": "main", "event": "schedule", "status": "completed", "conclusion": "success"});
        assert_eq!(run_refusal(&ok, "o/r"), None);
        let with = |k: &str, v: Value| {
            let mut r = ok.clone();
            r[k] = v;
            r
        };
        assert!(run_refusal(&with("path", json!(".github/workflows/other.yml")), "o/r").is_some());
        assert!(run_refusal(&with("head_branch", json!("evil")), "o/r").is_some());
        assert!(run_refusal(&with("event", json!("pull_request")), "o/r").is_some());
        assert!(run_refusal(&with("conclusion", json!("failure")), "o/r").is_some());
        assert!(
            run_refusal(
                &with("head_repository", json!({"full_name": "fork/r"})),
                "o/r"
            )
            .is_some()
        );
        assert_eq!(
            run_refusal(&with("event", json!("workflow_dispatch")), "o/r"),
            None
        );
    }

    #[test]
    fn proposal_files_are_exactly_reports_and_pinned_tool_locks() {
        let pinned: BTreeSet<String> = ["cargo-acl".to_string(), "cargo-vet".to_string()].into();
        let props = br#"{"proposals":[{"tool":"cargo-acl","fixes":["RUSTSEC-2026-0253"]}]}"#;
        let mk = |extra: &[(&str, &[u8])]| {
            let mut m: BTreeMap<String, Vec<u8>> = BTreeMap::new();
            m.insert("proposals.json".into(), props.to_vec());
            m.insert("report.md".into(), b"r".to_vec());
            for (k, v) in extra {
                m.insert((*k).into(), v.to_vec());
            }
            m
        };
        let (_, locks) = proposal_locks(&mk(&[("locks/cargo-acl.lock", b"x")]), &pinned).unwrap();
        assert_eq!(locks.keys().collect::<Vec<_>>(), ["cargo-acl"]);
        assert!(
            proposal_locks(
                &mk(&[("locks/cargo-acl.lock", b"x"), ("evil.sh", b"x")]),
                &pinned
            )
            .is_err()
        );
        assert!(
            proposal_locks(
                &mk(&[
                    ("locks/cargo-acl.lock", b"x"),
                    ("locks/cargo-vet.lock", b"x")
                ]),
                &pinned
            )
            .is_err(),
            "a lock no proposal names"
        );
        assert!(proposal_locks(&mk(&[("locks/not-pinned.lock", b"x")]), &pinned).is_err());
        assert!(proposal_locks(&mk(&[("locks/../x.lock", b"x")]), &pinned).is_err());
        assert!(
            proposal_locks(&mk(&[]), &pinned).is_err(),
            "a proposal without its lock"
        );
    }

    #[test]
    fn lock_changes_lists_moved_versions_only() {
        let lock = |pkgs: &[(&str, &str)]| {
            pkgs.iter()
                .map(|(n, v)| format!("[[package]]\nname = \"{n}\"\nversion = \"{v}\"\n"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        let old = lock(&[("lru", "0.16.4"), ("libc", "0.2.1")]);
        let new = lock(&[("lru", "0.18.2"), ("libc", "0.2.1")]);
        assert_eq!(lock_changes(&old, &new), vec!["lru 0.16.4 -> 0.18.2"]);
        assert!(lock_changes(&old, &old).is_empty());
    }

    #[test]
    fn pinned_tools_reads_the_first_field_of_live_lines() {
        let t = pinned_tools("# c\ncargo-deny  a b c d  # note\n\n  cargo-acl x y z w\n");
        assert_eq!(
            t.into_iter().collect::<Vec<_>>(),
            ["cargo-acl", "cargo-deny"]
        );
    }
}
