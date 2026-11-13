//! `cargo xtask release-advance <stage> --tag <vX.Y.Z> [...]` — the app's post-release evidence,
//! as stages, mirroring `candidate-advance` for the tool fleet.
//!
//! A published release is a product like a tool: its shipped `hp-thermal.exe` digest (from the
//! Release's own SHA256SUMS) gets a measured vuln baseline (app lock at the tag, recorded by
//! `record-vuln`) and a VirusTotal panel record (lookup first; submit only if absent) under
//! `supply-chain/evidence/hp-thermal/<digest>/`. CI computes nothing into the repository; the
//! maintainer runs this on an `evidence/*` branch and opens the PR. Same privilege model as
//! candidate-advance: the maintainer's `gh` session and signing key, no merge path.
//!
//! Stages: `status`, `vuln --auditor <digest-pinned cargo-audit>`, `mal [--no-submit]`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;

use crate::advance::{
    dispatch, gh, gh_json, git, mal_absent, mal_record_line, read_jsonl, run_log, s, short,
    wait_run,
};

const PRODUCT: &str = "hp-thermal";
const STORE_TAG: &str = "tools";

fn evidence_dir(digest: &str) -> PathBuf {
    PathBuf::from("supply-chain/evidence")
        .join(PRODUCT)
        .join(digest)
}

/// The shipped exe digest for a tag: the Release's SHA256SUMS line for hp-thermal.exe. The
/// manifest is itself an attestation subject, so this is the signed-bytes identity, not a guess.
pub(crate) fn exe_digest_from_sums(sums: &str) -> Result<String, String> {
    for l in sums.lines() {
        let mut it = l.split_whitespace();
        if let (Some(h), Some(n)) = (it.next(), it.next())
            && n.trim_start_matches('*') == "hp-thermal.exe"
        {
            if h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Ok(h.to_ascii_lowercase());
            }
            return Err(format!(
                "SHA256SUMS: hp-thermal.exe digest is not 64 hex: {h}"
            ));
        }
    }
    Err("SHA256SUMS has no hp-thermal.exe line".into())
}

fn release_digest(tag: &str) -> Result<String, String> {
    let tmp = std::env::temp_dir().join(format!("release-advance-{tag}-SHA256SUMS"));
    let _ = std::fs::remove_file(&tmp);
    gh(&[
        "release",
        "download",
        tag,
        "--pattern",
        "SHA256SUMS",
        "-O",
        &tmp.to_string_lossy(),
        "--clobber",
    ])?;
    let sums = std::fs::read_to_string(&tmp).map_err(|e| e.to_string())?;
    exe_digest_from_sums(&sums)
}

fn current_branch_ok() -> Result<String, String> {
    let b = git(&["rev-parse", "--abbrev-ref", "HEAD"])?
        .trim()
        .to_string();
    if b == "main" {
        return Err("release-advance never writes on main — check out an evidence/* branch".into());
    }
    Ok(b)
}

fn commit(paths: &[&Path], msg: &str, no_commit: bool) -> Result<(), String> {
    for p in paths {
        git(&["add", "-A", &p.to_string_lossy()])?;
    }
    if no_commit {
        println!("  (--no-commit) left staged: {msg}");
        return Ok(());
    }
    if git(&["diff", "--cached", "--name-only"])?.trim().is_empty() {
        println!("  nothing to commit (already recorded)");
        return Ok(());
    }
    git(&["commit", "-q", "-S", "-m", msg])?;
    println!(
        "  committed {} — {msg}",
        git(&["log", "-1", "--format=%h %G?"])?.trim()
    );
    Ok(())
}

fn stage_status(tag: &str) -> Result<(), String> {
    let d = release_digest(tag)?;
    println!("{PRODUCT} {tag}: shipped exe {d}");
    let dir = evidence_dir(&d);
    for f in ["vuln.jsonl", "mal.jsonl"] {
        let p = dir.join(f);
        if !p.exists() {
            println!("  {f:<10} MISSING");
            continue;
        }
        let rows = read_jsonl(&p);
        match f {
            "vuln.jsonl" => println!(
                "  {f:<10} {} instance(s); {}",
                rows.len().saturating_sub(1),
                rows.first()
                    .map(|h| s(h, &["lockProvenance"]))
                    .unwrap_or_default()
            ),
            _ => {
                if let Some(last) = rows.last() {
                    println!(
                        "  {f:<10} {} record(s); last: {}/{} on {}, sandbox {}",
                        rows.len(),
                        s(last, &["detections", "malicious"]),
                        s(last, &["detections", "total"]),
                        s(last, &["panelDate"]),
                        s(last, &["sandbox", "state"])
                    );
                }
            }
        }
    }
    Ok(())
}

fn stage_vuln(tag: &str, auditor: &Path, no_commit: bool) -> Result<(), String> {
    let d = release_digest(tag)?;
    let commit_sha = git(&["rev-list", "-n", "1", tag])?.trim().to_string();
    let lock_text = git(&["show", &format!("{tag}:app/Cargo.lock")])?;
    let lock = std::env::temp_dir().join(format!("release-advance-{tag}-Cargo.lock"));
    std::fs::write(&lock, lock_text).map_err(|e| e.to_string())?;
    let raw_dir = std::env::temp_dir().join(format!("release-advance-raw-{tag}"));
    let _ = std::fs::remove_dir_all(&raw_dir);
    let prov = format!(
        "app/Cargo.lock at {tag} ({}); shipped exe digest from the Release's SHA256SUMS",
        short(&commit_sha)
    );
    let args: Vec<String> = [
        "record-vuln",
        "--tool",
        PRODUCT,
        "--digest",
        &d,
        "--auditor",
        &auditor.to_string_lossy(),
        "--lock",
        &lock.to_string_lossy(),
        "--out-raw",
        &raw_dir.to_string_lossy(),
        "--lock-provenance",
        &prov,
    ]
    .iter()
    .map(|x| x.to_string())
    .collect();
    if crate::record_vuln::run(&args) != 0 {
        return Err("record-vuln failed".into());
    }
    let header = read_jsonl(&evidence_dir(&d).join("vuln.jsonl"))
        .into_iter()
        .next()
        .ok_or("vuln.jsonl has no header")?;
    let asset = s(&header, &["rawPayload", "asset"]);
    let want = s(&header, &["rawPayload", "sha256"]);
    gh(&[
        "release",
        "upload",
        STORE_TAG,
        &raw_dir.join(&asset).to_string_lossy(),
        "--clobber",
    ])?;
    match crate::monitor::store_digests(STORE_TAG)?.get(&asset) {
        Some(got) if *got == want => println!(
            "  raw payload {asset} stored and verified ({})",
            short(&want)
        ),
        Some(got) => return Err(format!("stored {asset} has sha {got}, header says {want}")),
        None => {
            return Err(format!(
                "{asset} not visible in the {STORE_TAG} release after upload"
            ));
        }
    }
    commit(
        &[&evidence_dir(&d)],
        &format!(
            "evidence: {PRODUCT} {tag} ({}) vuln baseline (record-vuln, measured)",
            short(&d)
        ),
        no_commit,
    )
}

fn stage_mal(
    tag: &str,
    no_submit: bool,
    panel_wait: Duration,
    wait: Duration,
    no_commit: bool,
) -> Result<(), String> {
    let d = release_digest(tag)?;
    let latest = s(
        &gh_json(&["release", "view", "--json", "tagName"])?,
        &["tagName"],
    );
    if latest != tag {
        return Err(format!(
            "the monitor reads the LATEST release only ({latest}); {tag} cannot be read through it"
        ));
    }
    let m1 = dispatch("supply-chain-monitor.yml", "main", &[])?;
    println!("  monitor (lookup) run {m1}");
    let _ = wait_run(&m1, wait)?;
    let mut log = run_log(&m1)?;
    let mut record = mal_record_line(&log, PRODUCT, &d);
    let mut source = m1;
    if record.is_none() {
        if !mal_absent(&log, &d) {
            return Err(format!(
                "monitor run {source} neither recorded {} nor reported it absent",
                short(&d)
            ));
        }
        if no_submit {
            return Err("exe is not in the VT corpus and --no-submit was given".into());
        }
        let sub = dispatch(
            "vt-submit.yml",
            "main",
            &[("only", &format!("release:{tag}"))],
        )?;
        println!("  vt-submit run {sub}");
        if wait_run(&sub, wait)? != "success" {
            return Err(format!("vt-submit run {sub} did not succeed"));
        }
        println!("  waiting {:?} for the panel", panel_wait);
        std::thread::sleep(panel_wait);
        let m2 = dispatch("supply-chain-monitor.yml", "main", &[])?;
        println!("  monitor (record) run {m2}");
        let _ = wait_run(&m2, wait)?;
        log = run_log(&m2)?;
        record = mal_record_line(&log, PRODUCT, &d);
        source = m2;
    }
    let rec: Value = record.ok_or_else(|| {
        format!(
            "monitor run {source} printed no record line for {}",
            short(&d)
        )
    })?;
    let path = evidence_dir(&d).join("mal.jsonl");
    let line = serde_json::to_string(&rec).map_err(|e| e.to_string())?;
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    if existing.lines().any(|l| l == line) {
        println!("  identical record already present");
    } else {
        std::fs::create_dir_all(path.parent().unwrap()).map_err(|e| e.to_string())?;
        let mut out = existing;
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&line);
        out.push('\n');
        std::fs::write(&path, out).map_err(|e| e.to_string())?;
    }
    let (m, t, st) = (
        s(&rec, &["detections", "malicious"]),
        s(&rec, &["detections", "total"]),
        s(&rec, &["sandbox", "state"]),
    );
    println!("  VT {m}/{t}, sandbox {st}");
    commit(
        &[&evidence_dir(&d)],
        &format!(
            "evidence: {PRODUCT} {tag} ({}) mal record (VT {m}/{t}, sandbox {st}; monitor run {source})",
            short(&d)
        ),
        no_commit,
    )
}

pub fn run(args: &[String]) -> i32 {
    let usage = "usage: cargo xtask release-advance <status|vuln|mal> --tag <vX.Y.Z> [--no-commit]\n\
                 \x20 vuln --auditor <digest-pinned cargo-audit exe>\n\
                 \x20 mal  [--no-submit] [--panel-wait-seconds N] [--wait-minutes N]";
    let Some(stage) = args.get(1).map(String::as_str) else {
        eprintln!("{usage}");
        return 2;
    };
    let (mut tag, mut auditor, mut no_submit, mut no_commit, mut panel_wait, mut wait_minutes) =
        (String::new(), None::<PathBuf>, false, false, 540u64, 60u64);
    let mut it = args.iter().skip(2);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--tag" => tag = it.next().cloned().unwrap_or_default(),
            "--auditor" => auditor = it.next().map(PathBuf::from),
            "--no-submit" => no_submit = true,
            "--no-commit" => no_commit = true,
            "--panel-wait-seconds" => {
                panel_wait = it.next().and_then(|v| v.parse().ok()).unwrap_or(panel_wait)
            }
            "--wait-minutes" => {
                wait_minutes = it
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(wait_minutes)
            }
            other => {
                eprintln!("release-advance: unknown argument {other}\n{usage}");
                return 2;
            }
        }
    }
    if !tag.starts_with('v') {
        eprintln!("release-advance: --tag vX.Y.Z is required\n{usage}");
        return 2;
    }
    if let Err(e) = current_branch_ok() {
        eprintln!("release-advance: {e}");
        return 2;
    }
    let wait = Duration::from_secs(wait_minutes * 60);
    let res = match stage {
        "status" => stage_status(&tag),
        "vuln" => match auditor {
            Some(a) => stage_vuln(&tag, &a, no_commit),
            None => Err("vuln needs --auditor <exe>".into()),
        },
        "mal" => stage_mal(
            &tag,
            no_submit,
            Duration::from_secs(panel_wait),
            wait,
            no_commit,
        ),
        other => Err(format!("unknown stage `{other}`\n{usage}")),
    };
    match res {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("release-advance {stage}: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256sums_parsing_is_strict() {
        let good = "abf1669303679e8879fb2fc0aebf76325f441cc3794de930b7cb72d33145bc4f  hp-thermal.exe\nd307b47185f3d307b47185f3d307b47185f3d307b47185f3d307b47185f3d307  hp-thermal.pdb\n";
        assert_eq!(
            exe_digest_from_sums(good).unwrap(),
            "abf1669303679e8879fb2fc0aebf76325f441cc3794de930b7cb72d33145bc4f"
        );
        assert_eq!(
            exe_digest_from_sums(
                "ABF1669303679E8879FB2FC0AEBF76325F441CC3794DE930B7CB72D33145BC4F *hp-thermal.exe\n"
            )
            .unwrap()
            .len(),
            64,
            "binary-mode marker and upper-case accepted, lowered"
        );
        assert!(
            exe_digest_from_sums("deadbeef  hp-thermal.exe\n").is_err(),
            "short digest refused"
        );
        assert!(
            exe_digest_from_sums("abc  hp-thermal.pdb\n").is_err(),
            "no exe line"
        );
    }
}
