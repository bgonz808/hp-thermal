//! `cadence-check`: parse and validate `supply-chain/policy/cadence.json`, the single source
//! of the time bounds the scheduled checks apply to the pinned posture.
//!
//! The workflows read the numbers with `jq -e` (a missing field fails the job there too); this
//! module is the second, offline reading: PR CI refuses a policy whose shape the consumers would
//! misread. Invariants checked here are the ones a per-field `jq` cannot see across fields:
//! `fail`, when set, is not below `warn`; the tool release-lag `warn` clears the toolchain soak
//! floor; the crate-candidate numbers equal the constants compiled into `explore`.

use serde_json::Value;

pub(crate) const POLICY: &str = "supply-chain/policy/cadence.json";
pub(crate) const SCHEMA: &str = "hp-thermal/cadence/v1";

/// A warn/fail pair; `fail == None` annotates only.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Bound {
    pub warn: i64,
    pub fail: Option<i64>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Cadence {
    pub tool_release_lag_days: Bound,
    pub toolchain_age_days: Bound,
    pub sandbox_not_ready_days: Bound,
    pub crate_soak_days: i64,
    pub crate_cadence_days: i64,
}

fn bound(v: &Value, key: &str) -> Result<Bound, String> {
    let o = v
        .get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{key}: missing object"))?;
    let warn = o
        .get("warn")
        .and_then(Value::as_i64)
        .filter(|n| *n > 0)
        .ok_or_else(|| format!("{key}.warn: must be a positive integer"))?;
    let fail = match o.get("fail") {
        Some(Value::Null) => None,
        Some(Value::Number(n)) => Some(
            n.as_i64()
                .ok_or_else(|| format!("{key}.fail: not an integer"))?,
        ),
        Some(_) => return Err(format!("{key}.fail: must be an integer or null")),
        None => {
            return Err(format!(
                "{key}.fail: missing (write null to mean annotate-only)"
            ));
        }
    };
    if let Some(f) = fail
        && f < warn
    {
        return Err(format!("{key}: fail ({f}) below warn ({warn})"));
    }
    Ok(Bound { warn, fail })
}

fn days(v: &Value, key: &str, field: &str) -> Result<i64, String> {
    v.get(key)
        .and_then(|o| o.get(field))
        .and_then(Value::as_i64)
        .filter(|n| *n > 0)
        .ok_or_else(|| format!("{key}.{field}: must be a positive integer"))
}

/// Parse the policy text. `soak_floor_days` is `tools/TOOLCHAIN.lock` min-age-days; the
/// tool release-lag warning must sit above it.
pub(crate) fn parse(text: &str, soak_floor_days: i64) -> Result<Cadence, String> {
    let v: Value = serde_json::from_str(text).map_err(|e| format!("{POLICY}: {e}"))?;
    if v.get("schema").and_then(Value::as_str) != Some(SCHEMA) {
        return Err(format!("{POLICY}: schema must be {SCHEMA}"));
    }
    let c = Cadence {
        tool_release_lag_days: bound(&v, "tool_release_lag_days")?,
        toolchain_age_days: bound(&v, "toolchain_age_days")?,
        sandbox_not_ready_days: bound(&v, "sandbox_not_ready_days")?,
        crate_soak_days: days(&v, "crate_candidate", "soak_days")?,
        crate_cadence_days: days(&v, "crate_candidate", "cadence_days")?,
    };
    if c.tool_release_lag_days.warn <= soak_floor_days {
        return Err(format!(
            "tool_release_lag_days.warn ({}) must exceed the toolchain soak floor ({soak_floor_days} d): \
             a release cannot be both too new to adopt and overdue",
            c.tool_release_lag_days.warn
        ));
    }
    if c.crate_soak_days != crate::explore::SOAK_DAYS
        || c.crate_cadence_days != crate::explore::CADENCE_DAYS
    {
        return Err(format!(
            "crate_candidate ({}/{}) disagrees with explore.rs SOAK_DAYS/CADENCE_DAYS ({}/{}); change both",
            c.crate_soak_days,
            c.crate_cadence_days,
            crate::explore::SOAK_DAYS,
            crate::explore::CADENCE_DAYS
        ));
    }
    Ok(c)
}

/// `min-age-days` from `tools/TOOLCHAIN.lock` (whitespace-separated `key value` lines).
pub(crate) fn soak_floor(lock_text: &str) -> Result<i64, String> {
    lock_text
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .find_map(|l| {
            let mut it = l.split_whitespace();
            (it.next() == Some("min-age-days"))
                .then(|| it.next())
                .flatten()
        })
        .and_then(|s| s.parse::<i64>().ok())
        .ok_or_else(|| "tools/TOOLCHAIN.lock: no min-age-days field".to_string())
}

pub fn run(_args: &[String]) -> i32 {
    let lock = match std::fs::read_to_string("tools/TOOLCHAIN.lock") {
        Ok(t) => t,
        Err(e) => {
            eprintln!("cadence-check: cannot read tools/TOOLCHAIN.lock: {e}");
            return 1;
        }
    };
    let floor = match soak_floor(&lock) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("cadence-check: {e}");
            return 1;
        }
    };
    let text = match std::fs::read_to_string(POLICY) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("cadence-check: cannot read {POLICY}: {e} (no policy = fail)");
            return 1;
        }
    };
    match parse(&text, floor) {
        Ok(c) => {
            let show = |b: &Bound| match b.fail {
                Some(f) => format!("warn {} d / fail {f} d", b.warn),
                None => format!("warn {} d / fail -", b.warn),
            };
            println!("cadence-check: {POLICY} OK");
            println!("  tool release lag     {}", show(&c.tool_release_lag_days));
            println!("  toolchain age        {}", show(&c.toolchain_age_days));
            println!("  sandbox NOT READY    {}", show(&c.sandbox_not_ready_days));
            println!(
                "  crate candidate      soak {} d, cadence {} d (= explore.rs)",
                c.crate_soak_days, c.crate_cadence_days
            );
            0
        }
        Err(e) => {
            eprintln!("cadence-check: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OK: &str = r#"{"schema":"hp-thermal/cadence/v1",
        "tool_release_lag_days":{"warn":45,"fail":90},
        "toolchain_age_days":{"warn":75,"fail":null},
        "sandbox_not_ready_days":{"warn":14,"fail":null},
        "crate_candidate":{"soak_days":7,"cadence_days":7}}"#;

    #[test]
    fn parses_bounds_and_null_fail() {
        let c = parse(OK, 30).unwrap();
        assert_eq!(
            c.tool_release_lag_days,
            Bound {
                warn: 45,
                fail: Some(90)
            }
        );
        assert_eq!(
            c.toolchain_age_days,
            Bound {
                warn: 75,
                fail: None
            }
        );
        assert_eq!(c.sandbox_not_ready_days.warn, 14);
    }

    #[test]
    fn refuses_fail_below_warn_missing_fail_and_bad_schema() {
        let r = parse(&OK.replace(r#""fail":90"#, r#""fail":10"#), 30);
        assert!(r.unwrap_err().contains("below warn"));
        let r = parse(&OK.replace(r#""warn":14,"fail":null"#, r#""warn":14"#), 30);
        assert!(r.unwrap_err().contains("fail: missing"));
        assert!(parse(&OK.replace("cadence/v1", "cadence/v2"), 30).is_err());
    }

    #[test]
    fn warn_must_clear_the_soak_floor() {
        assert!(parse(OK, 45).unwrap_err().contains("soak floor"));
        assert!(parse(OK, 44).is_ok());
    }

    #[test]
    fn crate_candidate_must_match_explore() {
        let r = parse(&OK.replace(r#""soak_days":7"#, r#""soak_days":8"#), 30);
        assert!(r.unwrap_err().contains("explore.rs"));
    }

    #[test]
    fn soak_floor_reads_the_lock_field_only() {
        assert_eq!(
            soak_floor("# min-age-days 99\nchannel x\nmin-age-days  30\n").unwrap(),
            30
        );
        assert!(soak_floor("channel x\n").is_err());
    }

    #[test]
    fn the_committed_policy_parses_against_the_committed_lock() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let lock = std::fs::read_to_string(root.join("tools/TOOLCHAIN.lock")).expect("lock");
        let text = std::fs::read_to_string(root.join(POLICY)).expect("policy");
        parse(&text, soak_floor(&lock).unwrap()).expect("committed cadence policy is valid");
    }
}
