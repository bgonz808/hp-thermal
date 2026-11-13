//! `cargo xtask slsa-vsa` — the SLSA Verification Summary Attestation predicate (#419 phase 4).
//!
//! A VSA (predicateType `https://slsa.dev/verification_summary/v1`) is a verifier's signed
//! statement: "I evaluated this artifact and these attestations against this policy at this
//! time; result PASSED/FAILED at these levels." Ours is self-issued: the verifier is this
//! repository's release workflow, which has just re-verified the provenance and SBOM
//! attestations identity-pinned to the reusable pipeline, checked SHA256SUMS, and is about to
//! publish. The predicate is written here and signed by `actions/attest` in the publish job, so
//! the Sigstore certificate binds it to the workflow run that performed the verification.
//!
//! Every field is from the SLSA v1.2 VSA schema; nothing custom. `dependencyLevels` is omitted:
//! we do not evaluate transitive dependencies' SLSA levels (they are vetted and audited by other
//! means, which the VSA does not express).

use std::path::Path;

use serde_json::{Value, json};

pub(crate) const PREDICATE_TYPE: &str = "https://slsa.dev/verification_summary/v1";

pub(crate) struct Inputs<'a> {
    pub(crate) verifier_id: &'a str,
    pub(crate) time_verified: &'a str,
    pub(crate) resource_uri: &'a str,
    pub(crate) policy_uri: &'a str,
    pub(crate) policy_commit: &'a str,
    /// (uri, sha256)
    pub(crate) input_attestations: &'a [(String, String)],
    pub(crate) result: &'a str,
    pub(crate) levels: &'a [String],
    pub(crate) slsa_version: &'a str,
}

/// Build the predicate. Refuses anything the schema would make meaningless: an empty verifier,
/// a result other than PASSED/FAILED, a PASSED result with no levels, a malformed level name.
pub(crate) fn predicate(i: &Inputs<'_>) -> Result<Value, String> {
    if i.verifier_id.is_empty() || i.resource_uri.is_empty() || i.policy_uri.is_empty() {
        return Err("verifier id, resource URI and policy URI are required".into());
    }
    if !matches!(i.result, "PASSED" | "FAILED") {
        return Err(format!(
            "verificationResult must be PASSED or FAILED, got {}",
            i.result
        ));
    }
    if i.result == "PASSED" && i.levels.is_empty() {
        return Err("a PASSED verification must name at least one verified level".into());
    }
    for l in i.levels {
        if !(l.starts_with("SLSA_BUILD_LEVEL_") || l.starts_with("SLSA_SOURCE_LEVEL_")) {
            return Err(format!(
                "level `{l}` is not an SLSA level name (SLSA_BUILD_LEVEL_n / SLSA_SOURCE_LEVEL_n)"
            ));
        }
    }
    if i.policy_commit.len() != 40 || !i.policy_commit.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("policy commit must be a 40-hex git sha".into());
    }
    let inputs: Vec<Value> = i
        .input_attestations
        .iter()
        .map(|(u, d)| json!({"uri": u, "digest": {"sha256": d}}))
        .collect();
    Ok(json!({
        "verifier": {"id": i.verifier_id, "version": {"xtask": env!("CARGO_PKG_VERSION")}},
        "timeVerified": i.time_verified,
        "resourceUri": i.resource_uri,
        "policy": {"uri": i.policy_uri, "digest": {"gitCommit": i.policy_commit}},
        "inputAttestations": inputs,
        "verificationResult": i.result,
        "verifiedLevels": i.levels,
        "slsaVersion": i.slsa_version,
    }))
}

fn now_utc() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

pub fn run(args: &[String]) -> i32 {
    let usage = "usage: cargo xtask slsa-vsa --verifier <uri> --resource <uri> --policy-uri <uri> --policy-commit <sha> \\\n\
                 \x20      --input <uri>=<path> [--input ...] --result PASSED|FAILED --level <SLSA_..._LEVEL_n> [--level ...] \\\n\
                 \x20      [--slsa-version 1.2] --out <predicate.json>";
    let (
        mut verifier,
        mut resource,
        mut policy_uri,
        mut policy_commit,
        mut result,
        mut slsa,
        mut out,
    ) = (
        String::new(),
        String::new(),
        String::new(),
        String::new(),
        String::new(),
        "1.2".to_string(),
        None::<String>,
    );
    let mut inputs: Vec<(String, String)> = Vec::new();
    let mut levels: Vec<String> = Vec::new();
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--verifier" => verifier = it.next().cloned().unwrap_or_default(),
            "--resource" => resource = it.next().cloned().unwrap_or_default(),
            "--policy-uri" => policy_uri = it.next().cloned().unwrap_or_default(),
            "--policy-commit" => policy_commit = it.next().cloned().unwrap_or_default(),
            "--result" => result = it.next().cloned().unwrap_or_default(),
            "--slsa-version" => slsa = it.next().cloned().unwrap_or(slsa),
            "--out" => out = it.next().cloned(),
            "--level" => levels.push(it.next().cloned().unwrap_or_default()),
            "--input" => {
                let spec = it.next().cloned().unwrap_or_default();
                let Some((uri, path)) = spec.split_once('=') else {
                    eprintln!("slsa-vsa: --input needs <uri>=<path>, got {spec}");
                    return 2;
                };
                match std::fs::read(Path::new(path)) {
                    Ok(b) => inputs.push((uri.to_string(), crate::sha256::sha256_hex(&b))),
                    Err(e) => {
                        eprintln!(
                            "vsa: cannot read input attestation {path}: {e} (an input the verifier did not read is not an input)"
                        );
                        return 1;
                    }
                }
            }
            other => {
                eprintln!("slsa-vsa: unknown argument {other}\n{usage}");
                return 2;
            }
        }
    }
    let Some(out) = out else {
        eprintln!("{usage}");
        return 2;
    };
    let time = now_utc();
    let pred = match predicate(&Inputs {
        verifier_id: &verifier,
        time_verified: &time,
        resource_uri: &resource,
        policy_uri: &policy_uri,
        policy_commit: &policy_commit,
        input_attestations: &inputs,
        result: &result,
        levels: &levels,
        slsa_version: &slsa,
    }) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("slsa-vsa: {e}");
            return 1;
        }
    };
    if let Err(e) = std::fs::write(&out, serde_json::to_string_pretty(&pred).unwrap() + "\n") {
        eprintln!("slsa-vsa: {out}: {e}");
        return 1;
    }
    println!(
        "slsa-vsa: wrote {out} ({PREDICATE_TYPE}) — {} {} by {} over {} input attestation(s), policy @ {}",
        result,
        levels.join(","),
        verifier,
        inputs.len(),
        &policy_commit[..12]
    );
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMMIT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn base<'a>(inputs: &'a [(String, String)], levels: &'a [String]) -> Inputs<'a> {
        Inputs {
            verifier_id: "https://github.com/o/r/.github/workflows/release.yml",
            time_verified: "2026-11-13T00:00:00Z",
            resource_uri: "https://github.com/o/r/releases/download/v1/x.exe",
            policy_uri: "git+https://github.com/o/r@abc#supply-chain/policy",
            policy_commit: COMMIT,
            input_attestations: inputs,
            result: "PASSED",
            levels,
            slsa_version: "1.2",
        }
    }

    #[test]
    fn predicate_has_the_schema_fields_and_nothing_custom() {
        let inputs = vec![("https://x/prov.jsonl".to_string(), "b".repeat(64))];
        let levels = vec!["SLSA_BUILD_LEVEL_3".to_string()];
        let p = predicate(&base(&inputs, &levels)).unwrap();
        let mut keys: Vec<&str> = p.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        let mut want = vec![
            "verifier",
            "timeVerified",
            "resourceUri",
            "policy",
            "inputAttestations",
            "verificationResult",
            "verifiedLevels",
            "slsaVersion",
        ];
        want.sort_unstable();
        assert_eq!(keys, want, "exactly the schema's fields, nothing custom");
        assert_eq!(
            p["inputAttestations"][0]["digest"]["sha256"],
            "b".repeat(64)
        );
        assert_eq!(p["policy"]["digest"]["gitCommit"], COMMIT);
        assert_eq!(p["verifiedLevels"][0], "SLSA_BUILD_LEVEL_3");
    }

    #[test]
    fn predicate_refuses_meaningless_statements() {
        let inputs: Vec<(String, String)> = vec![];
        let none: Vec<String> = vec![];
        assert!(
            predicate(&base(&inputs, &none)).is_err(),
            "PASSED with no level"
        );
        let bad = vec!["LEVEL_3".to_string()];
        assert!(
            predicate(&base(&inputs, &bad)).is_err(),
            "not an SLSA level name"
        );
        let ok = vec!["SLSA_BUILD_LEVEL_2".to_string()];
        let mut i = base(&inputs, &ok);
        i.result = "MAYBE";
        assert!(predicate(&i).is_err(), "result enum");
        let mut j = base(&inputs, &ok);
        j.policy_commit = "abc";
        assert!(predicate(&j).is_err(), "policy commit shape");
        let mut k = base(&inputs, &none);
        k.result = "FAILED";
        assert!(predicate(&k).is_ok(), "FAILED needs no level");
    }
}
