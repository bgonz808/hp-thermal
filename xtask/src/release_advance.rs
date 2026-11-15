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
//! Stages: `status`, `vuln --auditor <digest-pinned cargo-audit>`, `mal [--no-submit]`, `anchor`.
//!
//! `anchor` copies the release's original attestations into the evidence tree, so the record of
//! what was released does not rest on GitHub's attestation store (deletable by the repository
//! owner) or on release assets. An original is signed by a release workflow at the tag's ref and
//! commit, by the tag push, and logged before the release was published. Anything else signed at
//! the tag (a re-run or dispatch after publish) stops the stage for a person to look.

use std::collections::BTreeMap;
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

// ---------- anchor ----------

/// Release workflows whose signature at `refs/tags/<tag>` can make an attestation an original:
/// `release-pipeline.yml` from v0.3.3, `release.yml` before it.
const RELEASE_SIGNERS: [&str; 2] = ["release-pipeline.yml", "release.yml"];
const PROVENANCE: &str = "https://slsa.dev/provenance/v1";

/// The evidence file an original attestation of `predicate_type` is anchored in; the names match
/// the release's own `hp-thermal.<kind>.sigstore.jsonl` assets.
pub(crate) fn anchor_file(predicate_type: &str) -> Option<&'static str> {
    match predicate_type {
        PROVENANCE => Some("provenance.sigstore.jsonl"),
        "https://cyclonedx.org/bom" => Some("sbom.sigstore.jsonl"),
        "https://docs.oasis-open.org/sarif/sarif/v2.1.0" => Some("sarif.sigstore.jsonl"),
        "https://slsa.dev/verification_summary/v1" => Some("vsa.sigstore.jsonl"),
        _ => None,
    }
}

/// RFC 3339 date-time (`Z` or `+HH:MM`/`-HH:MM`, optional fraction) as Unix seconds.
pub(crate) fn rfc3339_unix(t: &str) -> Option<i64> {
    let b = t.as_bytes();
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || !matches!(b[10], b'T' | b't')
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let x = t.get(r)?;
        if x.bytes().all(|c| c.is_ascii_digit()) {
            x.parse().ok()
        } else {
            None
        }
    };
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    let mut i = 19;
    if b.get(i) == Some(&b'.') {
        i += 1;
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            return None;
        }
    }
    let off = match *b.get(i)? {
        b'Z' | b'z' if i + 1 == b.len() => 0,
        sign @ (b'+' | b'-') if i + 6 == b.len() && b[i + 3] == b':' => {
            let (oh, om) = (num(i + 1..i + 3)?, num(i + 4..i + 6)?);
            if oh > 23 || om > 59 {
                return None;
            }
            let o = oh * 3600 + om * 60;
            if sign == b'+' { o } else { -o }
        }
        _ => return None,
    };
    let days = crate::eox::days_from_civil(y, mo as u32, d as u32);
    Some(days * 86_400 + h * 3600 + mi * 60 + sec - off)
}

/// Standard-alphabet base64 (RFC 4648 section 4, padding optional). Used only to read a DSSE
/// payload's claimed predicate type, which `gh attestation verify` then enforces.
pub(crate) fn b64decode(text: &str) -> Option<Vec<u8>> {
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    };
    let t = text.trim_end_matches('=');
    if text.len() - t.len() > 2 {
        return None;
    }
    let mut out = Vec::with_capacity(t.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &c in t.as_bytes() {
        acc = (acc << 6) | val(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    if bits >= 6 {
        return None;
    }
    Some(out)
}

/// One stored attestation signed by a release workflow at the tag and commit, judged by how and
/// when it was made.
#[derive(Debug, PartialEq)]
pub(crate) enum Origin {
    /// Made by the tag push and logged before the release was published.
    Original,
    /// Signed at the tag but not by the tag push, or logged after publish: never anchored.
    Suspect(String),
}

/// `tlog` are the transparency-log times (Unix seconds); `published` is the release's.
pub(crate) fn judge(trigger: &str, runner: &str, tlog: &[i64], published: i64) -> Origin {
    if trigger != "push" {
        return Origin::Suspect(format!("build trigger `{trigger}`, not the tag push"));
    }
    if runner != "github-hosted" {
        return Origin::Suspect(format!("runner `{runner}`"));
    }
    match tlog.iter().max() {
        None => Origin::Suspect("no transparency-log time".into()),
        Some(&t) if t > published => Origin::Suspect(format!(
            "logged {}s after the release was published",
            t - published
        )),
        Some(_) => Origin::Original,
    }
}

/// The commit a tag names on origin (the peeled `^{}` line for an annotated tag).
fn remote_tag_commit(tag: &str) -> Result<String, String> {
    let out = git(&[
        "ls-remote",
        "origin",
        &format!("refs/tags/{tag}"),
        &format!("refs/tags/{tag}^{{}}"),
    ])?;
    let mut direct = None;
    for l in out.lines() {
        let mut it = l.split_whitespace();
        if let (Some(sha), Some(r)) = (it.next(), it.next()) {
            if r.ends_with("^{}") {
                return Ok(sha.to_string());
            }
            direct = Some(sha.to_string());
        }
    }
    direct.ok_or_else(|| format!("origin has no tag {tag}"))
}

fn plain_file_name(name: &str) -> bool {
    !name.starts_with('.') && Path::new(name).file_name().and_then(|f| f.to_str()) == Some(name)
}

fn stage_anchor(tag: &str, no_commit: bool) -> Result<(), String> {
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
    let rel = gh_json(&["release", "view", tag, "--json", "publishedAt,isDraft"])?;
    if rel["isDraft"].as_bool() != Some(false) {
        return Err(format!("{tag}: a draft, or its state is unreadable"));
    }
    let published_at = s(&rel, &["publishedAt"]);
    let published = rfc3339_unix(&published_at)
        .ok_or(format!("publishedAt `{published_at}` is not RFC 3339"))?;
    let tag_commit = git(&["rev-list", "-n", "1", tag])?.trim().to_string();
    let remote = remote_tag_commit(tag)?;
    if remote != tag_commit {
        return Err(format!("local {tag} is {tag_commit}; origin has {remote}"));
    }

    let work = std::env::temp_dir().join(format!("release-anchor-{tag}"));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).map_err(|e| e.to_string())?;
    let w = work.to_string_lossy().into_owned();
    gh(&[
        "release",
        "download",
        tag,
        "--pattern",
        "hp-thermal.exe",
        "--dir",
        &w,
        "--clobber",
    ])?;
    let exe = work.join("hp-thermal.exe");
    let x = exe.to_string_lossy().into_owned();
    let digest = crate::sha256::sha256_hex(&std::fs::read(&exe).map_err(|e| format!("{x}: {e}"))?);
    println!(
        "{PRODUCT} {tag}: exe {digest}, commit {}, published {published_at}",
        short(&tag_commit)
    );

    let list = gh_json(&[
        "api",
        &format!("repos/{repo}/attestations/sha256:{digest}?per_page=100"),
    ])?;
    let atts = list["attestations"]
        .as_array()
        .ok_or("attestations API: no `attestations` array")?;
    if atts.len() >= 100 {
        return Err("100 or more attestations for one digest: the list may be truncated".into());
    }
    let source_ref = format!("refs/tags/{tag}");
    let mut kept: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
    let mut subjects: Vec<(String, String)> = Vec::new();
    let mut suspects = 0usize;
    for (i, a) in atts.iter().enumerate() {
        let bundle = &a["bundle"];
        if !bundle.is_object() {
            return Err(format!(
                "attestation {i}: bundle not inline; refusing to skip it unseen"
            ));
        }
        let payload = s(bundle, &["dsseEnvelope", "payload"]);
        let statement: serde_json::Value = b64decode(&payload)
            .and_then(|b| serde_json::from_slice(&b).ok())
            .ok_or(format!("attestation {i}: DSSE payload is not base64 JSON"))?;
        let pt = s(&statement, &["predicateType"]);
        let Some(fname) = anchor_file(&pt) else {
            println!("  other     {pt}: not a release attestation kind");
            continue;
        };
        let line = serde_json::to_string(bundle).map_err(|e| e.to_string())?;
        let bf = work.join(format!("bundle-{i}.jsonl"));
        std::fs::write(&bf, format!("{line}\n")).map_err(|e| e.to_string())?;
        let b = bf.to_string_lossy().into_owned();
        let mut verified = None;
        for wf in RELEASE_SIGNERS {
            let ident = format!("https://github.com/{repo}/.github/workflows/{wf}@{source_ref}");
            if let Ok(v) = gh_json(&[
                "attestation",
                "verify",
                &x,
                "--bundle",
                &b,
                "--repo",
                &repo,
                "--predicate-type",
                &pt,
                "--cert-identity",
                &ident,
                "--source-ref",
                &source_ref,
                "--source-digest",
                &tag_commit,
                "--deny-self-hosted-runners",
                "--format",
                "json",
            ]) {
                verified = Some((wf, v));
                break;
            }
        }
        let Some((wf, v)) = verified else {
            println!("  other     {fname:<26} not signed by a release workflow at {tag}");
            continue;
        };
        let r = &v[0]["verificationResult"];
        let cert = &r["signature"]["certificate"];
        let run = s(cert, &["runInvocationURI"]);
        let tlog: Vec<i64> = r["verifiedTimestamps"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|t| s(t, &["type"]) == "Tlog")
            .filter_map(|t| rfc3339_unix(&s(t, &["timestamp"])))
            .collect();
        match judge(
            &s(cert, &["buildTrigger"]),
            &s(cert, &["runnerEnvironment"]),
            &tlog,
            published,
        ) {
            Origin::Original => {
                println!("  original  {fname:<26} {wf}, {run}");
                if pt == PROVENANCE {
                    for sub in r["statement"]["subject"].as_array().into_iter().flatten() {
                        subjects.push((s(sub, &["name"]), s(sub, &["digest", "sha256"])));
                    }
                }
                kept.entry(fname).or_default().push(line);
            }
            Origin::Suspect(why) => {
                println!("  SUSPECT   {fname:<26} {wf}, {run}: {why}");
                suspects += 1;
            }
        }
    }
    if suspects > 0 {
        return Err(format!(
            "{suspects} attestation(s) signed at {tag} are not originals; investigate before anchoring"
        ));
    }
    for (f, lines) in &kept {
        if lines.len() != 1 {
            return Err(format!("{} originals for {f}: ambiguous", lines.len()));
        }
    }
    if !kept.contains_key("provenance.sigstore.jsonl") {
        return Err(format!("{tag}: no original provenance"));
    }
    for (name, want) in &subjects {
        if !plain_file_name(name) {
            return Err(format!(
                "provenance subject `{name}` is not a plain file name"
            ));
        }
        if name != "hp-thermal.exe" {
            gh(&[
                "release",
                "download",
                tag,
                "--pattern",
                name,
                "--dir",
                &w,
                "--clobber",
            ])?;
        }
        let got = crate::sha256::sha256_hex(
            &std::fs::read(work.join(name)).map_err(|e| format!("{name}: {e}"))?,
        );
        if &got != want {
            return Err(format!("{name}: published {got}, provenance says {want}"));
        }
        println!("  subject   {name:<26} matches the provenance");
    }

    let dir = evidence_dir(&digest);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    for (f, lines) in &kept {
        let p = dir.join(f);
        let body = format!("{}\n", lines[0]);
        match std::fs::read(&p) {
            Ok(old) if old == body.as_bytes() => println!("  recorded  {f} (unchanged)"),
            Ok(_) => {
                return Err(format!(
                    "{}: differs from the original found now; anchors are never replaced",
                    p.display()
                ));
            }
            Err(_) => {
                std::fs::write(&p, &body).map_err(|e| e.to_string())?;
                println!("  wrote     {}", p.display());
            }
        }
    }
    commit(
        &[&dir],
        &format!(
            "evidence: {PRODUCT} {tag} ({}): original attestations anchored",
            short(&digest)
        ),
        no_commit,
    )
}

pub fn run(args: &[String]) -> i32 {
    let usage = "usage: cargo xtask release-advance <status|vuln|mal|anchor> --tag <vX.Y.Z> [--no-commit]\n\
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
        "anchor" => stage_anchor(&tag, no_commit),
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
    fn rfc3339_handles_offsets_fractions_and_rejects_junk() {
        assert_eq!(rfc3339_unix("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            rfc3339_unix("2026-08-02T09:20:03-07:00"),
            rfc3339_unix("2026-08-02T16:20:03Z")
        );
        assert_eq!(
            rfc3339_unix("2026-11-14T06:34:00.123Z"),
            rfc3339_unix("2026-11-14T06:34:00Z")
        );
        for bad in [
            "2026-08-02",
            "2026-08-02T16:20:03",
            "2026-13-02T16:20:03Z",
            "2026-08-02T16:20:03+0700",
            "2026-08-02T16:20:03.Z",
        ] {
            assert_eq!(rfc3339_unix(bad), None, "{bad}");
        }
    }

    #[test]
    fn base64_decodes_dsse_payloads_strictly() {
        assert_eq!(b64decode("eyJhIjoxfQ==").unwrap(), br#"{"a":1}"#);
        assert_eq!(b64decode("eyJhIjoxfQ").unwrap(), br#"{"a":1}"#);
        assert_eq!(b64decode("").unwrap(), b"");
        assert!(b64decode("eyJh!").is_none(), "outside the alphabet");
        assert!(b64decode("e").is_none(), "a lone trailing sextet");
        assert!(b64decode("eyJhIjoxfQ===").is_none(), "three pads");
    }

    #[test]
    fn only_tag_push_attestations_logged_before_publish_are_originals() {
        // v0.2.2: provenance logged 16:20:03Z, release published 16:20:19Z.
        let published = rfc3339_unix("2026-08-02T16:20:19Z").unwrap();
        let logged = rfc3339_unix("2026-08-02T09:20:03-07:00").unwrap();
        assert_eq!(
            judge("push", "github-hosted", &[logged], published),
            Origin::Original
        );
        assert!(matches!(
            judge("workflow_dispatch", "github-hosted", &[logged], published),
            Origin::Suspect(_)
        ));
        assert!(matches!(
            judge("push", "self-hosted", &[logged], published),
            Origin::Suspect(_)
        ));
        assert!(matches!(
            judge("push", "github-hosted", &[], published),
            Origin::Suspect(_)
        ));
        assert!(matches!(
            judge("push", "github-hosted", &[published + 1], published),
            Origin::Suspect(_)
        ));
    }

    #[test]
    fn anchor_files_mirror_release_asset_names() {
        assert_eq!(anchor_file(PROVENANCE), Some("provenance.sigstore.jsonl"));
        assert_eq!(
            anchor_file("https://cyclonedx.org/bom"),
            Some("sbom.sigstore.jsonl")
        );
        assert_eq!(
            anchor_file("https://slsa.dev/verification_summary/v1"),
            Some("vsa.sigstore.jsonl")
        );
        assert_eq!(anchor_file("https://example.com/other"), None);
        assert!(plain_file_name("hp-thermal.pdb") && plain_file_name("SHA256SUMS"));
        assert!(!plain_file_name("../x") && !plain_file_name("a/b") && !plain_file_name(".hidden"));
    }

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
