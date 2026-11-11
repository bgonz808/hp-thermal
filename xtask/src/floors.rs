//! Absolute floors (#241 §4 HARD-STOP): a state the gate refuses regardless of acks.
//!
//! The axes have delta semantics (vuln: fixed/carried/added; caps: #367's subset rule) and
//! ack semantics (any RAISE is signable). They lacked an absolute: a proposed state that no
//! signature admits. Policy is committed data in `supply-chain/policy/floors.json`, read
//! here; a missing or malformed file is an error the caller turns into UNEVALUATED, never
//! into "no floors".

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::gate::Instance;

pub const DEFAULT_PATH: &str = "supply-chain/policy/floors.json";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VectorShape {
    pub attack_vector: String,
    pub privileges_required: String,
    pub user_interaction: String,
    /// Impact axes (C / I / A), any of which at High trips the floor.
    pub high_impact_any_of: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Floors {
    pub vuln_shape: Option<VectorShape>,
    pub mal_malicious_engines: Option<u64>,
    pub mal_sandbox_malicious: bool,
    /// Completeness precondition (#347 step 1): a panel with fewer verdict-bearing engines
    /// than this is still running (or a partial rescan), not a verdict about the bytes.
    pub mal_min_engines: Option<u64>,
    pub caps_new_grants: Vec<String>,
}

pub fn load(path: &Path) -> Result<Floors, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("floors policy {}: {e}", path.display()))?;
    parse(&text).map_err(|e| format!("floors policy {}: {e}", path.display()))
}

pub fn parse(text: &str) -> Result<Floors, String> {
    let v: Value = serde_json::from_str(text).map_err(|e| format!("invalid JSON: {e}"))?;
    if v.get("schema").and_then(Value::as_str) != Some("hp-thermal/floors/v1") {
        return Err("schema is not hp-thermal/floors/v1".into());
    }
    let strs = |x: Option<&Value>| -> Result<Vec<String>, String> {
        x.and_then(Value::as_array)
            .ok_or_else(|| "expected an array of strings".to_string())?
            .iter()
            .map(|s| {
                s.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| "non-string in array".to_string())
            })
            .collect()
    };
    let vuln_shape = match v.pointer("/vuln/hard_stop_vector_shape") {
        None | Some(Value::Null) => None,
        Some(s) => Some(VectorShape {
            attack_vector: req_str(s, "attack_vector")?,
            privileges_required: req_str(s, "privileges_required")?,
            user_interaction: req_str(s, "user_interaction")?,
            high_impact_any_of: strs(s.get("high_impact_any_of"))?,
        }),
    };
    let mal_malicious_engines = match v.pointer("/mal/hard_stop_malicious_engines") {
        None | Some(Value::Null) => None,
        Some(n) => Some(
            n.as_u64()
                .ok_or("mal.hard_stop_malicious_engines must be a non-negative integer")?,
        ),
    };
    let mal_sandbox_malicious = v
        .pointer("/mal/hard_stop_on_sandbox_malicious")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mal_min_engines = match v.pointer("/mal/min_verdict_engines") {
        None | Some(Value::Null) => None,
        Some(n) => Some(
            n.as_u64()
                .ok_or("mal.min_verdict_engines must be a non-negative integer")?,
        ),
    };
    let caps_new_grants = match v.pointer("/caps/hard_stop_new_grants") {
        None | Some(Value::Null) => Vec::new(),
        Some(a) => strs(Some(a))?,
    };
    Ok(Floors {
        vuln_shape,
        mal_malicious_engines,
        mal_sandbox_malicious,
        mal_min_engines,
        caps_new_grants,
    })
}

/// The sandbox verdicts a mal record carries, whichever shape it uses: the stated object
/// `{"state", "verdicts": [...]}` (#347 step 1) or the bare array of earlier records.
pub fn sandbox_verdicts(panel: &Value) -> Vec<&Value> {
    match panel.get("sandbox") {
        Some(Value::Array(a)) => a.iter().collect(),
        Some(Value::Object(o)) => o
            .get("verdicts")
            .and_then(Value::as_array)
            .map(|a| a.iter().collect())
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// The sandbox readiness a mal record STATES. Object form: its `state` (`ANALYZED`, or
/// `NOT READY` while no sandbox has reported — which is not "no behaviours", #347). Bare array
/// (records before #347 step 1): `UNSTATED`. Missing or malformed: `MALFORMED`. Only ANALYZED
/// says the behavioural axis was read; none of the others reads as clean.
pub fn sandbox_state(panel: &Value) -> String {
    match panel.get("sandbox") {
        Some(Value::Array(_)) => "UNSTATED (record predates #347)".to_string(),
        Some(Value::Object(o)) => match o.get("state").and_then(Value::as_str) {
            Some(st) if !st.trim().is_empty() => st.to_string(),
            _ => "MALFORMED (sandbox.state missing)".to_string(),
        },
        _ => "MALFORMED (no sandbox field)".to_string(),
    }
}

fn req_str(v: &Value, key: &str) -> Result<String, String> {
    v.get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("vuln.hard_stop_vector_shape.{key} must be a string"))
}

// ---------- vuln ----------

/// advisory id -> CVSS vector, from `cargo audit --json` (vulnerabilities list only;
/// warnings carry no vector and never floor).
pub fn extract_cvss(audit: &Value) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for e in audit
        .pointer("/vulnerabilities/list")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let (Some(id), Some(c)) = (
            e.pointer("/advisory/id").and_then(Value::as_str),
            e.pointer("/advisory/cvss").and_then(Value::as_str),
        ) {
            out.insert(id.to_string(), c.to_string());
        }
    }
    out
}

/// Does the vector have the critical SHAPE? Version-agnostic over CVSS 3.x and 4.0: AV / PR
/// / UI are spelled the same; impact is C/I/A (3.x) or VC/VI/VA plus SC/SI/SA (4.0). An
/// unknown or missing metric never satisfies a condition: a floor must be provable from the
/// vector, so doubt falls toward RAISE, not toward HARD-STOP.
pub fn vector_has_shape(vector: &str, shape: &VectorShape) -> bool {
    let m: BTreeMap<&str, &str> = vector
        .split('/')
        .filter_map(|t| t.split_once(':'))
        .collect();
    let eq = |k: &str, want: &str| m.get(k).is_some_and(|v| *v == want);
    if !(eq("AV", &shape.attack_vector)
        && eq("PR", &shape.privileges_required)
        && eq("UI", &shape.user_interaction))
    {
        return false;
    }
    shape.high_impact_any_of.iter().any(|axis| {
        [axis.clone(), format!("V{axis}"), format!("S{axis}")]
            .iter()
            .any(|k| eq(k, "H"))
    })
}

impl Floors {
    /// One reason per instance crossing the vuln floor. Informational kinds never do.
    pub fn vuln_stops(
        &self,
        instances: &BTreeSet<Instance>,
        cvss: &BTreeMap<String, String>,
    ) -> Vec<String> {
        let Some(shape) = &self.vuln_shape else {
            return Vec::new();
        };
        instances
            .iter()
            .filter(|i| i.kind == "vulnerability")
            .filter_map(|i| {
                let vec = cvss.get(&i.id)?;
                vector_has_shape(vec, shape).then(|| {
                    format!(
                        "{} {} {}: {vec} — network-reachable, no privileges, no interaction, \
                         High impact: absolute floor, not ackable",
                        i.id, i.package, i.version
                    )
                })
            })
            .collect()
    }

    /// Mal floor on a parsed `mal.jsonl` record.
    pub fn mal_stop(&self, panel: &Value) -> Option<String> {
        let malicious = panel
            .pointer("/detections/malicious")
            .and_then(Value::as_u64);
        if let (Some(n), Some(floor)) = (malicious, self.mal_malicious_engines)
            && n >= floor
        {
            return Some(format!(
                "{n} engines report malicious (floor {floor}): not a false-positive profile; \
                 absolute floor, not ackable"
            ));
        }
        if self.mal_sandbox_malicious {
            for sb in sandbox_verdicts(panel) {
                let cat = sb.get("category").and_then(Value::as_str).unwrap_or("");
                if cat.eq_ignore_ascii_case("malicious") {
                    let name = sb.get("name").and_then(Value::as_str).unwrap_or("?");
                    return Some(format!(
                        "sandbox {name} verdict malicious: absolute floor, not ackable"
                    ));
                }
            }
        }
        None
    }

    /// Completeness precondition on a mal record (#347 step 1). `Some(why)` when the record is
    /// not a verdict at all: fewer verdict-bearing engines than `mal.min_verdict_engines`, or no
    /// `detections.total` to judge by. Not a floor (nothing is being condemned) and not ALLOW —
    /// the gate's UNEVALUATED, so it blocks and cannot be acked.
    pub fn mal_incomplete(&self, panel: &Value) -> Option<String> {
        let floor = self.mal_min_engines?;
        match panel.pointer("/detections/total").and_then(Value::as_u64) {
            None => {
                Some("no detections.total: panel completeness unknown — not a verdict".to_string())
            }
            Some(n) if n < floor => Some(format!(
                "panel INCOMPLETE: {n} engines returned a verdict (floor {floor}) — not a \
                 verdict about these bytes, never read as clean"
            )),
            Some(_) => None,
        }
    }

    /// Caps floor: a MEASURED head inventory granting a floor class to a package the prior
    /// blessed inventory did not. `None` when not applicable (copied-forward head, no prior):
    /// applicability is the ack's business, not the floor's.
    pub fn caps_stop(&self, head_caps: &str, base_caps: Option<&str>) -> Option<String> {
        if self.caps_new_grants.is_empty() || is_copied_forward(head_caps) {
            return None;
        }
        let base = grants(base_caps?);
        let head = grants(head_caps);
        let floor: BTreeSet<&str> = self.caps_new_grants.iter().map(String::as_str).collect();
        let mut hits = Vec::new();
        for (pkg, classes) in &head {
            let before = base.get(pkg).cloned().unwrap_or_default();
            for c in classes {
                if floor.contains(c.as_str()) && !before.contains(c) {
                    hits.push(format!("{pkg} newly granted `{c}`"));
                }
            }
        }
        (!hits.is_empty()).then(|| {
            format!(
                "measured inventory crosses the caps floor: {}: absolute floor, not ackable",
                hits.join(", ")
            )
        })
    }
}

fn is_copied_forward(caps: &str) -> bool {
    caps.lines()
        .take_while(|l| l.trim_start().starts_with('#'))
        .any(|l| l.contains("COPIED FORWARD"))
}

/// `[pkg.NAME]` -> API classes granted in SHIPPING scopes: `allow_apis`, `build.allow_apis`,
/// `from.build.allow_apis`. `test.*` / `from.test.*` are ignored.
pub fn grants(caps: &str) -> BTreeMap<String, BTreeSet<String>> {
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut pkg: Option<String> = None;
    let mut collecting = false;
    for raw in caps.lines() {
        let line = raw.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            collecting = false;
            pkg = line
                .strip_prefix("[pkg.")
                .and_then(|r| r.strip_suffix(']'))
                .map(|n| n.trim_matches('"').to_string());
            continue;
        }
        let Some(p) = &pkg else {
            continue;
        };
        if collecting {
            collect_quoted(line, out.entry(p.clone()).or_default());
            if line.contains(']') {
                collecting = false;
            }
            continue;
        }
        if let Some((key, rhs)) = line.split_once('=') {
            let key = key.trim();
            if matches!(
                key,
                "allow_apis" | "build.allow_apis" | "from.build.allow_apis"
            ) {
                let set = out.entry(p.clone()).or_default();
                collect_quoted(rhs, set);
                collecting = rhs.contains('[') && !rhs.contains(']');
            }
        }
    }
    out
}

fn collect_quoted(s: &str, into: &mut BTreeSet<String>) {
    let mut rest = s;
    while let Some(i) = rest.find('"') {
        let after = &rest[i + 1..];
        let Some(j) = after.find('"') else {
            break;
        };
        into.insert(after[..j].to_string());
        rest = &after[j + 1..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Floors {
        parse(include_str!("../../supply-chain/policy/floors.json")).unwrap()
    }
    fn inst(id: &str, kind: &str) -> Instance {
        Instance {
            id: id.into(),
            package: "p".into(),
            version: "1".into(),
            kind: kind.into(),
        }
    }

    #[test]
    fn committed_policy_parses_and_is_armed_on_every_axis() {
        let f = policy();
        assert!(f.vuln_shape.is_some());
        assert_eq!(f.mal_malicious_engines, Some(3));
        assert!(f.mal_sandbox_malicious);
        assert_eq!(f.mal_min_engines, Some(50));
        assert_eq!(f.caps_new_grants, ["process", "net"]);
    }

    #[test]
    fn missing_schema_or_bad_json_is_an_error_not_no_floors() {
        assert!(parse("{}").is_err());
        assert!(parse("not json").is_err());
    }

    #[test]
    fn critical_shape_trips_on_3x_and_4_0_but_not_on_dos_or_local() {
        let f = policy();
        let shape = f.vuln_shape.as_ref().unwrap();
        assert!(vector_has_shape(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            shape
        ));
        assert!(vector_has_shape(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N",
            shape
        ));
        // the ruzstd DoS (RUSTSEC-2026-0344): availability only -> RAISE, not floor
        assert!(!vector_has_shape(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            shape
        ));
        assert!(!vector_has_shape(
            "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            shape
        ));
        assert!(!vector_has_shape(
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            shape
        ));
        assert!(!vector_has_shape(
            "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:A/VC:N/VI:N/VA:H/SC:N/SI:N/SA:H",
            shape
        ));
        assert!(!vector_has_shape("", shape));
        assert!(!vector_has_shape("CVSS:3.1/AV:N", shape));
    }

    #[test]
    fn informational_kinds_and_missing_vectors_never_floor() {
        let f = policy();
        let mut cvss = BTreeMap::new();
        cvss.insert(
            "A".to_string(),
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string(),
        );
        let set: BTreeSet<Instance> = [inst("A", "unsound"), inst("B", "vulnerability")].into();
        assert!(f.vuln_stops(&set, &cvss).is_empty());
        let set: BTreeSet<Instance> = [inst("A", "vulnerability")].into();
        assert_eq!(f.vuln_stops(&set, &cvss).len(), 1);
    }

    #[test]
    fn mal_floor_on_engine_count_and_sandbox_verdict() {
        let f = policy();
        let p = |s: &str| serde_json::from_str::<Value>(s).unwrap();
        assert!(
            f.mal_stop(&p(r#"{"detections":{"malicious":2},"sandbox":[]}"#))
                .is_none()
        );
        assert!(
            f.mal_stop(&p(r#"{"detections":{"malicious":3},"sandbox":[]}"#))
                .is_some()
        );
        assert!(f
            .mal_stop(&p(
                r#"{"detections":{"malicious":0},"sandbox":[{"name":"Zenbox","category":"harmless"}]}"#
            ))
            .is_none());
        assert!(f
            .mal_stop(&p(
                r#"{"detections":{"malicious":0},"sandbox":[{"name":"Zenbox","category":"Malicious"}]}"#
            ))
            .is_some());
        // missing field is the gate's UNEVALUATED, not a floor
        assert!(f.mal_stop(&p(r#"{"sandbox":[]}"#)).is_none());
        // the stated object form (#347 step 1) is read the same way
        assert!(f
            .mal_stop(&p(
                r#"{"detections":{"malicious":0},"sandbox":{"state":"ANALYZED","verdicts":[{"name":"Zenbox","category":"malicious"}]}}"#
            ))
            .is_some());
        assert!(
            f.mal_stop(&p(
                r#"{"detections":{"malicious":0},"sandbox":{"state":"NOT READY","verdicts":[]}}"#
            ))
            .is_none()
        );
    }

    #[test]
    fn incomplete_panel_is_not_a_verdict() {
        let f = policy();
        let p = |s: &str| serde_json::from_str::<Value>(s).unwrap();
        assert!(
            f.mal_incomplete(&p(r#"{"detections":{"malicious":0,"total":70}}"#))
                .is_none()
        );
        assert!(
            f.mal_incomplete(&p(r#"{"detections":{"malicious":0,"total":50}}"#))
                .is_none()
        );
        assert!(
            f.mal_incomplete(&p(r#"{"detections":{"malicious":0,"total":12}}"#))
                .is_some()
        );
        // no total at all: completeness unknown, same answer (fail-closed)
        assert!(
            f.mal_incomplete(&p(r#"{"detections":{"malicious":0}}"#))
                .is_some()
        );
    }

    #[test]
    fn sandbox_state_is_read_from_the_record_never_inferred() {
        let p = |s: &str| serde_json::from_str::<Value>(s).unwrap();
        assert_eq!(
            sandbox_state(&p(r#"{"sandbox":{"state":"ANALYZED","verdicts":[]}}"#)),
            "ANALYZED"
        );
        assert_eq!(
            sandbox_state(&p(r#"{"sandbox":{"state":"NOT READY","verdicts":[]}}"#)),
            "NOT READY"
        );
        assert!(sandbox_state(&p(r#"{"sandbox":[]}"#)).starts_with("UNSTATED"));
        assert!(sandbox_state(&p(r#"{"sandbox":{"verdicts":[]}}"#)).starts_with("MALFORMED"));
        assert!(sandbox_state(&p(r#"{}"#)).starts_with("MALFORMED"));
        assert_eq!(
            sandbox_verdicts(&p(
                r#"{"sandbox":{"state":"ANALYZED","verdicts":[{"name":"Zenbox"}]}}"#
            ))
            .len(),
            1
        );
        assert_eq!(
            sandbox_verdicts(&p(r#"{"sandbox":[{"name":"Zenbox"}]}"#)).len(),
            1
        );
    }

    const BASE: &str = "# caps evidence\n[pkg.a]\nallow_apis = [\n    \"fs\",\n]\n\n[pkg.b]\nbuild.allow_apis = [\"env\"]\n";

    #[test]
    fn caps_floor_trips_only_on_a_new_shipping_grant_of_a_floor_class() {
        let f = policy();
        assert!(f.caps_stop(BASE, Some(BASE)).is_none());
        let head = "# caps evidence\n[pkg.a]\nallow_unsafe = true\n\n[pkg.b]\nbuild.allow_apis = [\"env\", \"process\"]\n";
        assert!(
            f.caps_stop(head, Some(BASE))
                .unwrap()
                .contains("b newly granted `process`")
        );
        let head = format!("{BASE}\n[pkg.c]\nallow_apis = [\"net\"]\n");
        assert!(f.caps_stop(&head, Some(BASE)).is_some());
        let head = format!("{BASE}\n[pkg.c]\nfrom.test.allow_apis = [\"process\", \"net\"]\n");
        assert!(
            f.caps_stop(&head, Some(BASE)).is_none(),
            "test scope does not ship"
        );
        let head = format!("{BASE}\n[pkg.c]\nallow_apis = [\"fs\"]\n");
        assert!(
            f.caps_stop(&head, Some(BASE)).is_none(),
            "fs is RAISE territory"
        );
    }

    #[test]
    fn caps_floor_is_not_applicable_without_a_measurement_or_a_prior() {
        let f = policy();
        let copied =
            "# caps evidence — COPIED FORWARD from abc\n[pkg.c]\nallow_apis = [\"process\"]\n";
        assert!(f.caps_stop(copied, Some(BASE)).is_none());
        let head = format!("{BASE}\n[pkg.c]\nallow_apis = [\"process\"]\n");
        assert!(f.caps_stop(&head, None).is_none());
    }

    #[test]
    fn grants_parser_handles_multiline_arrays_and_scopes() {
        let g = grants(
            "[pkg.x]\nallow_apis = [\n  \"fs\",\n  \"net\",\n]\nfrom.build.allow_apis = [\"process\"]\ntest.allow_apis = [\"env\"]\n[api.net]\ninclude = [\"std::net\"]\n",
        );
        let x = &g["x"];
        assert_eq!(
            x.iter().cloned().collect::<Vec<_>>(),
            ["fs", "net", "process"]
        );
        assert!(!g.contains_key("net"));
    }
}
