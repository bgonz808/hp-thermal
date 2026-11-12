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
    /// #382: build-script directive floors, evaluated on MEASURED inventories (Bubblewrap-mode
    /// cackle records every `cargo:` line a build script emits). Each rule is armed separately
    /// so the policy file shows what is enforced.
    pub build_link_arg: bool,
    pub build_foreign_link_search: bool,
    pub build_new_env_cfg: bool,
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
    let flag = |ptr: &str| v.pointer(ptr).and_then(Value::as_bool).unwrap_or(false);
    Ok(Floors {
        vuln_shape,
        mal_malicious_engines,
        mal_sandbox_malicious,
        mal_min_engines,
        caps_new_grants,
        build_link_arg: flag("/build_instructions/hard_stop_link_arg"),
        build_foreign_link_search: flag("/build_instructions/hard_stop_foreign_link_search"),
        build_new_env_cfg: flag("/build_instructions/hard_stop_new_rustc_env_cfg"),
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
        if is_copied_forward(head_caps) {
            return None;
        }
        let mut hits = Vec::new();
        if !self.caps_new_grants.is_empty()
            && let Some(base_caps) = base_caps
        {
            let (base, head) = match (grants(base_caps), grants(head_caps)) {
                (Ok(b), Ok(h)) => (b, h),
                (b, h) => {
                    for e in [b, h].into_iter().filter_map(Result::err) {
                        hits.push(format!(
                            "inventory not parseable ({e}): unknown is never clean"
                        ));
                    }
                    (BTreeMap::new(), BTreeMap::new())
                }
            };
            let floor: BTreeSet<&str> = self.caps_new_grants.iter().map(String::as_str).collect();
            for (pkg, classes) in &head {
                let before = base.get(pkg).cloned().unwrap_or_default();
                for c in classes {
                    if floor.contains(c.as_str()) && !before.contains(c) {
                        hits.push(format!("{pkg} newly granted `{c}`"));
                    }
                }
            }
        }
        // #382: build-script directives. The absolute rules (linker flags, foreign link-search,
        // unclassifiable directives) need no prior; the relative one (rustc-env / rustc-cfg)
        // compares against the prior blessed inventory for the same package when there is one.
        let prior = match base_caps.map(build_instructions) {
            None => None,
            Some(Ok(m)) => Some(m),
            Some(Err(e)) => {
                hits.push(format!(
                    "prior inventory not parseable ({e}): unknown is never clean"
                ));
                None
            }
        };
        let head_dirs = match build_instructions(head_caps) {
            Ok(m) => m,
            Err(e) => {
                hits.push(format!(
                    "inventory not parseable ({e}): unknown is never clean"
                ));
                BTreeMap::new()
            }
        };
        for (pkg, directives) in head_dirs {
            // A prior inventory that has nothing for this package is a prior with NO directives
            // for it (the package or its build script is new): the relative rule applies.
            let prior_pkg = prior
                .as_ref()
                .map(|p| p.get(&pkg).map_or(&[][..], Vec::as_slice));
            for d in &directives {
                if let Some(why) = self.directive_stop(&pkg, d, prior_pkg) {
                    hits.push(why);
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

    fn build_armed(&self) -> bool {
        self.build_link_arg || self.build_foreign_link_search || self.build_new_env_cfg
    }

    /// Classify one `cargo:` directive a build script emitted (#382). `Some(why)` is a floor.
    /// Everything that is not a floor rides the ordinary inventory-change path (a new dynamic
    /// `rustc-link-lib`, `system_libs=`, even a new self-named static lib is an ADDITION the
    /// subset rule refuses and an ack must cover): no auto-ALLOW here.
    fn directive_stop(
        &self,
        pkg: &str,
        directive: &str,
        prior: Option<&[String]>,
    ) -> Option<String> {
        if !self.build_armed() {
            return None;
        }
        let d = normalize_directive(directive);
        let (key, value) = d.split_once('=').unwrap_or((d.as_str(), ""));
        let emits = format!("{pkg} build script emits `{directive}`");
        match key {
            k if k.starts_with("rustc-link-arg") || k.starts_with("rustc-cdylib-link-arg") => self
                .build_link_arg
                .then(|| format!("{emits}: arbitrary linker flags")),
            "rustc-link-search" => {
                let path = value.split_once('=').map_or(value, |(_, p)| p);
                (self.build_foreign_link_search && !own_dir(pkg, path)).then(|| {
                    format!("{emits}: link-search outside its own OUT_DIR / registry source")
                })
            }
            "rustc-flags" => {
                // `-L` is a link-search, `-l` a link-lib; anything else is an arbitrary flag.
                let mut bad = Vec::new();
                let mut toks = value.split_whitespace();
                while let Some(t) = toks.next() {
                    let (flag, inline) =
                        if t.len() > 2 && (t.starts_with("-L") || t.starts_with("-l")) {
                            (&t[..2], Some(&t[2..]))
                        } else {
                            (t, None)
                        };
                    match flag {
                        "-L" => {
                            let p = inline.or_else(|| toks.next()).unwrap_or("");
                            let p = p.split_once('=').map_or(p, |(_, x)| x);
                            if self.build_foreign_link_search && !own_dir(pkg, p) {
                                bad.push(format!("-L {p} is outside its own dirs"));
                            }
                        }
                        "-l" => {
                            if inline.is_none() {
                                toks.next();
                            }
                        }
                        other => {
                            if self.build_link_arg {
                                bad.push(format!("`{other}` is neither -l nor -L"));
                            }
                        }
                    }
                }
                (!bad.is_empty()).then(|| format!("{emits}: {}", bad.join("; ")))
            }
            "rustc-env" | "rustc-cfg" => match prior {
                Some(p)
                    if self.build_new_env_cfg && !p.iter().any(|x| normalize_directive(x) == d) =>
                {
                    Some(format!(
                        "{emits}: not in the prior blessed inventory for this package"
                    ))
                }
                _ => None,
            },
            "rustc-link-lib"
            | "rustc-check-cfg"
            | "rerun-if-changed"
            | "rerun-if-env-changed"
            | "warning"
            | "error"
            | "metadata" => None,
            k if k.starts_with("rustc-") || k.starts_with("rerun-") => Some(format!(
                "{emits}: unknown rustc directive, not classifiable (unknown is never clean)"
            )),
            // `cargo:KEY=VALUE` links metadata (include=, root=, conf=, system_libs=, ...): data
            // handed to dependents' build scripts, not an instruction to rustc.
            _ => None,
        }
    }
}

/// `cargo::` (Cargo >= 1.77) and `cargo:` spellings are one directive.
fn normalize_directive(d: &str) -> String {
    let d = d.trim();
    d.strip_prefix("cargo::")
        .or_else(|| d.strip_prefix("cargo:"))
        .unwrap_or(d)
        .to_string()
}

/// Is `path` inside the emitting package's own build OUT_DIR (`<target>/build/<pkg>-<hash>/out`
/// or the newer `<target>/build/<pkg>/<hash>/out`) or its own registry source directory
/// (`<registry>/src/<index>/<pkg>-<version>/`)? Byte-stable across runners because only the
/// shape after `/build/` or `/registry/src/` is read, never the prefix.
pub fn own_dir(pkg: &str, path: &str) -> bool {
    let p = path.replace('\\', "/");
    let pkg = pkg.split(':').next().unwrap_or(pkg);
    if pkg.is_empty() {
        return false;
    }
    // A relative or empty segment anywhere (`..`, `.`, `//`, trailing `/`) is a traversal
    // shape: `<own OUT_DIR>/../../usr/lib` must never read as "own". Foreign, whatever follows.
    if p.split('/')
        .skip(1)
        .any(|seg| seg.is_empty() || seg == "." || seg == "..")
    {
        return false;
    }
    for (i, _) in p.match_indices("/build/") {
        let rest = &p[i + "/build/".len()..];
        for sep in ['-', '/'] {
            if let Some(r) = rest.strip_prefix(pkg).and_then(|r| r.strip_prefix(sep)) {
                let hash_len = r.chars().take_while(|c| c.is_ascii_hexdigit()).count();
                if hash_len == 16
                    && let Some(after) = r[hash_len..].strip_prefix("/out")
                    && (after.is_empty() || after.starts_with('/'))
                {
                    return true;
                }
            }
        }
    }
    if let Some(i) = p.find("/registry/src/") {
        let rest = &p[i + "/registry/src/".len()..];
        // The segment after the index dir must be EXACTLY `<pkg>-<version>`: a version starts
        // with a digit and uses semver characters only, and the segment ends there.
        if let Some((_, after_index)) = rest.split_once('/')
            && let Some(r) = after_index
                .strip_prefix(pkg)
                .and_then(|r| r.strip_prefix('-'))
        {
            let version = r.split('/').next().unwrap_or("");
            if version.chars().next().is_some_and(|c| c.is_ascii_digit())
                && version
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-'))
            {
                return true;
            }
        }
    }
    false
}

/// One line of a TOML array of strings: the strings on it (basic `"…"` with escapes, literal
/// `'…'` without) and whether a `]` OUTSIDE any string closed the array. `Err` on an
/// unterminated string or an unsupported escape — the caller treats that as "not parseable",
/// never as "no more entries". A `#` outside strings starts a comment.
fn scan_array_line(line: &str) -> Result<(Vec<String>, bool), String> {
    enum St {
        Outside,
        Basic(String),
        Literal(String),
    }
    let mut items = Vec::new();
    let mut st = St::Outside;
    let mut closed = false;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        st = match st {
            St::Outside => match c {
                '"' => St::Basic(String::new()),
                '\'' => St::Literal(String::new()),
                ']' => {
                    closed = true;
                    St::Outside
                }
                '#' => break,
                _ => St::Outside,
            },
            St::Basic(mut s) => match c {
                '"' => {
                    items.push(s);
                    St::Outside
                }
                '\\' => {
                    match chars.next() {
                        Some('"') => s.push('"'),
                        Some('\\') => s.push('\\'),
                        Some('n') => s.push('\n'),
                        Some('t') => s.push('\t'),
                        Some('r') => s.push('\r'),
                        Some(other) => {
                            return Err(format!("unsupported escape `\\{other}` in {line:?}"));
                        }
                        None => return Err(format!("dangling escape in {line:?}")),
                    }
                    St::Basic(s)
                }
                _ => {
                    s.push(c);
                    St::Basic(s)
                }
            },
            St::Literal(mut s) => match c {
                '\'' => {
                    items.push(s);
                    St::Outside
                }
                _ => {
                    s.push(c);
                    St::Literal(s)
                }
            },
        };
    }
    if !matches!(st, St::Outside) {
        return Err(format!("unterminated string in {line:?}"));
    }
    Ok((items, closed))
}

/// `[pkg.NAME]` -> the `cargo:` directives its build script emitted, from
/// `build.allow_build_instructions` (or `allow_build_instructions` inside `[pkg.NAME.build]`).
/// Order preserved; cackle writes these only when its sandbox captured the build script's
/// stdout, so an inventory without them says nothing about directives.
pub fn build_instructions(caps: &str) -> Result<BTreeMap<String, Vec<String>>, String> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut pkg: Option<String> = None;
    let mut in_build_table = false;
    let mut collecting = false;
    for raw in caps.lines() {
        let line = raw.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            if collecting {
                return Err(
                    "allow_build_instructions array not closed before the next table".into(),
                );
            }
            let inner = line.trim_start_matches('[').trim_end_matches(']').trim();
            match inner.strip_prefix("pkg.") {
                Some(n) => {
                    let (n, b) = match n.strip_suffix(".build") {
                        Some(n) => (n, true),
                        None => (n, false),
                    };
                    pkg = Some(n.trim_matches('"').to_string());
                    in_build_table = b;
                }
                None => {
                    pkg = None;
                    in_build_table = false;
                }
            }
            continue;
        }
        let Some(p) = &pkg else {
            continue;
        };
        if collecting {
            let (items, closed) = scan_array_line(line)?;
            out.entry(p.clone()).or_default().extend(items);
            collecting = !closed;
            continue;
        }
        if let Some((key, rhs)) = line.split_once('=') {
            let key = key.trim();
            if key == "build.allow_build_instructions"
                || (in_build_table && key == "allow_build_instructions")
            {
                let (items, closed) = scan_array_line(rhs)?;
                out.entry(p.clone()).or_default().extend(items);
                collecting = rhs.trim_start().starts_with('[') && !closed;
            }
        }
    }
    if collecting {
        return Err("allow_build_instructions array not closed at end of file".into());
    }
    Ok(out)
}

fn is_copied_forward(caps: &str) -> bool {
    caps.lines()
        .take_while(|l| l.trim_start().starts_with('#'))
        .any(|l| l.contains("COPIED FORWARD"))
}

/// `[pkg.NAME]` -> API classes granted in SHIPPING scopes: `allow_apis`, `build.allow_apis`,
/// `from.build.allow_apis`. `test.*` / `from.test.*` are ignored.
pub fn grants(caps: &str) -> Result<BTreeMap<String, BTreeSet<String>>, String> {
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut pkg: Option<String> = None;
    let mut collecting = false;
    for raw in caps.lines() {
        let line = raw.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            if collecting {
                return Err("allow_apis array not closed before the next table".into());
            }
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
            let (items, closed) = scan_array_line(line)?;
            out.entry(p.clone()).or_default().extend(items);
            collecting = !closed;
            continue;
        }
        if let Some((key, rhs)) = line.split_once('=') {
            let key = key.trim();
            if matches!(
                key,
                "allow_apis" | "build.allow_apis" | "from.build.allow_apis"
            ) {
                let (items, closed) = scan_array_line(rhs)?;
                out.entry(p.clone()).or_default().extend(items);
                collecting = rhs.trim_start().starts_with('[') && !closed;
            }
        }
    }
    if collecting {
        return Err("allow_apis array not closed at end of file".into());
    }
    Ok(out)
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
        assert!(f.build_link_arg && f.build_foreign_link_search && f.build_new_env_cfg);
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

    // ---------- #382: build-script directives ----------

    const OWN_OUT_OLD: &str =
        "/home/runner/work/_temp/caps-build/cackle/build/zstd-sys-b5f0e2aa84868937/out";
    const OWN_OUT_NEW: &str =
        "/home/runner/work/_temp/caps-build/cackle-release/build/zstd-sys/920a401143eae1b7/out";
    const OWN_SRC: &str = "/home/runner/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/zstd-sys-2.1.2+zstd.1.5.7/zstd/lib";

    fn with_directives(pkg: &str, dirs: &[&str]) -> String {
        let list = dirs
            .iter()
            .map(|d| format!("    \"{d}\",\n"))
            .collect::<String>();
        format!(
            "# caps evidence — cackle-generated inventory\n[pkg.{pkg}]\nbuild.allow_build_instructions = [\n{list}]\n"
        )
    }

    #[test]
    fn own_dir_recognises_both_out_dir_layouts_and_the_registry_source_only_for_the_emitter() {
        assert!(own_dir("zstd-sys", OWN_OUT_OLD));
        assert!(own_dir("zstd-sys", OWN_OUT_NEW));
        assert!(own_dir("zstd-sys", &format!("{OWN_OUT_NEW}/lib")));
        assert!(own_dir("zstd-sys", OWN_SRC));
        assert!(
            own_dir("zstd-sys:2.1.2", OWN_SRC),
            "version-qualified package names"
        );
        assert!(
            !own_dir("ring", OWN_OUT_NEW),
            "another package's OUT_DIR is foreign"
        );
        assert!(
            !own_dir("zstd", OWN_OUT_NEW),
            "prefix of the name is not the name"
        );
        assert!(!own_dir("zstd-sys", "/usr/lib"));
        assert!(!own_dir(
            "zstd-sys",
            "/home/runner/work/_temp/caps-build/cackle/build/zstd-sys-notahash/out"
        ));
        assert!(
            !own_dir(
                "zstd-sys",
                "/home/runner/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/zstd-sys-fake/x"
            ),
            "registry dir must carry a version"
        );
        assert!(
            own_dir("zstd-sys", &OWN_OUT_NEW.replace('/', "\\")),
            "Windows separators"
        );
    }

    #[test]
    fn link_arg_and_foreign_link_search_are_floors_without_a_prior() {
        let f = policy();
        let head = with_directives("zstd-sys", &["cargo:rustc-link-arg=-Wl,-rpath,/tmp/x"]);
        assert!(
            f.caps_stop(&head, None)
                .unwrap()
                .contains("arbitrary linker flags")
        );
        let head = with_directives("zstd-sys", &["cargo::rustc-link-arg-bins=/evil"]);
        assert!(
            f.caps_stop(&head, None)
                .unwrap()
                .contains("arbitrary linker flags"),
            "cargo:: spelling"
        );
        let head = with_directives("zstd-sys", &["cargo:rustc-cdylib-link-arg=-undefined"]);
        assert!(f.caps_stop(&head, None).is_some());
        let head = with_directives(
            "zstd-sys",
            &["cargo:rustc-link-search=native=/usr/local/lib"],
        );
        assert!(
            f.caps_stop(&head, None)
                .unwrap()
                .contains("outside its own OUT_DIR")
        );
        let head = with_directives(
            "zstd-sys",
            &[&format!(
                "cargo:rustc-link-search=native={}",
                OWN_OUT_NEW.replace("zstd-sys", "ring")
            )],
        );
        assert!(
            f.caps_stop(&head, None)
                .unwrap()
                .contains("outside its own OUT_DIR"),
            "another crate's OUT_DIR"
        );
        let head = with_directives("zstd-sys", &["cargo:rustc-flags=-L /opt/lib -l z"]);
        assert!(f.caps_stop(&head, None).unwrap().contains("-L /opt/lib"));
        let head = with_directives("zstd-sys", &["cargo:rustc-flags=-C link-arg=/evil"]);
        assert!(
            f.caps_stop(&head, None)
                .unwrap()
                .contains("neither -l nor -L")
        );
        let head = with_directives("zstd-sys", &["cargo:rustc-frobnicate=1"]);
        assert!(
            f.caps_stop(&head, None)
                .unwrap()
                .contains("unknown is never clean")
        );
    }

    #[test]
    fn self_referential_directives_and_links_metadata_are_not_floors() {
        let f = policy();
        let head = with_directives(
            "zstd-sys",
            &[
                &format!("cargo:include={OWN_SRC}"),
                &format!("cargo:root={OWN_OUT_NEW}"),
                "cargo:rustc-link-lib=static=zstd",
                "cargo:rustc-link-lib=z",
                &format!("cargo:rustc-link-search=native={OWN_OUT_OLD}"),
                &format!("cargo:rustc-link-search=native={OWN_OUT_NEW}"),
                &format!("cargo:rustc-flags=-L {OWN_OUT_NEW} -l zstd"),
                "cargo:system_libs=z",
                "cargo:conf=ZSTD_STATIC",
                "cargo:rerun-if-changed=build.rs",
                "cargo:rustc-check-cfg=cfg(zstd_pkg)",
                "cargo:warning=hello",
            ],
        );
        assert_eq!(f.caps_stop(&head, None), None);
        assert_eq!(
            f.caps_stop(&head, Some(BASE)),
            None,
            "a dynamic -l z is RAISE territory (an addition), not a floor"
        );
    }

    #[test]
    fn rustc_env_and_cfg_are_floors_only_when_new_against_a_prior() {
        let f = policy();
        let prior = with_directives(
            "ring",
            &[
                "cargo:rustc-cfg=ring_core",
                "cargo:rustc-env=RING_CORE_PREFIX=ring_core_0_17_14_",
            ],
        );
        let same = with_directives(
            "ring",
            &[
                "cargo::rustc-cfg=ring_core",
                "cargo:rustc-env=RING_CORE_PREFIX=ring_core_0_17_14_",
            ],
        );
        assert_eq!(
            f.caps_stop(&same, Some(&prior)),
            None,
            "spelling differences are not changes"
        );
        let new_cfg = with_directives(
            "ring",
            &[
                "cargo:rustc-cfg=ring_core",
                "cargo:rustc-cfg=unsafe_fast_path",
            ],
        );
        assert!(
            f.caps_stop(&new_cfg, Some(&prior))
                .unwrap()
                .contains("not in the prior blessed inventory")
        );
        let new_env = with_directives("ring", &["cargo:rustc-env=RUSTFLAGS_OVERRIDE=1"]);
        assert!(f.caps_stop(&new_env, Some(&prior)).is_some());
        let other_pkg_prior = with_directives("other", &["cargo:rustc-cfg=unsafe_fast_path"]);
        assert!(
            f.caps_stop(&new_cfg, Some(&other_pkg_prior)).is_some(),
            "the prior is per package"
        );
        assert_eq!(
            f.caps_stop(&new_cfg, None),
            None,
            "no prior: the ack path, not the floor"
        );
        let copied = format!(
            "# caps evidence — COPIED FORWARD from abc\n{}",
            with_directives("ring", &["cargo:rustc-link-arg=/evil"])
        );
        assert_eq!(
            f.caps_stop(&copied, Some(&prior)),
            None,
            "not a measurement"
        );
    }

    #[test]
    fn array_parser_is_quote_aware_and_unparseable_inventories_are_floors() {
        let f = policy();
        // A `]` inside a string must not end the array early and hide what follows.
        let head = "# caps evidence\n[pkg.p]\nbuild.allow_build_instructions = [\n    \"cargo:warning=]\",\n    \"cargo:rustc-link-arg=/evil\",\n]\n";
        assert_eq!(build_instructions(head).unwrap()["p"].len(), 2);
        assert!(
            f.caps_stop(head, None)
                .unwrap()
                .contains("arbitrary linker flags")
        );
        let head = "# caps evidence\n[pkg.p]\nbuild.allow_build_instructions = [\"cargo:x=]\", \"cargo:rustc-link-arg=/evil\"]\n";
        assert!(
            f.caps_stop(head, None)
                .unwrap()
                .contains("arbitrary linker flags")
        );
        // TOML literal strings and escaped quotes are read, not skipped.
        let head = "# caps evidence\n[pkg.p]\nbuild.allow_build_instructions = ['cargo:rustc-link-arg=/evil', \"cargo:warning=say \\\"hi\\\"\"] # note\n";
        let b = build_instructions(head).unwrap();
        assert_eq!(
            b["p"],
            ["cargo:rustc-link-arg=/evil", "cargo:warning=say \"hi\""]
        );
        assert!(f.caps_stop(head, None).is_some());
        // Unterminated string / unclosed array: not parseable, and that is a floor, not silence.
        for bad in [
            "# caps evidence\n[pkg.p]\nbuild.allow_build_instructions = [\"cargo:x=1]\n",
            "# caps evidence\n[pkg.p]\nbuild.allow_build_instructions = [\n    \"cargo:x=1\",\n[pkg.q]\nallow_unsafe = true\n",
            "# caps evidence\n[pkg.p]\nbuild.allow_build_instructions = [\"cargo:x=\\u0041\"]\n",
            "# caps evidence\n[pkg.p]\nallow_apis = [\"fs\"\n",
        ] {
            assert!(
                f.caps_stop(bad, Some(BASE))
                    .unwrap()
                    .contains("not parseable"),
                "{bad:?}"
            );
        }
        // the same applies to a prior that cannot be read
        let good = with_directives("p", &["cargo:rustc-cfg=a"]);
        assert!(
            f.caps_stop(&good, Some("[pkg.p]\nallow_apis = [\"fs\"\n"))
                .unwrap()
                .contains("prior inventory not parseable")
        );
    }

    #[test]
    fn own_dir_rejects_traversal_and_junk_segments() {
        assert!(!own_dir(
            "zstd-sys",
            &format!("{OWN_OUT_NEW}/../../../../usr/lib")
        ));
        assert!(!own_dir("zstd-sys", &format!("{OWN_OUT_NEW}/./lib")));
        assert!(!own_dir(
            "zstd-sys",
            &OWN_OUT_NEW.replace("/build/", "//build/")
        ));
        assert!(!own_dir("zstd-sys", &format!("{OWN_OUT_NEW}/")));
        assert!(!own_dir(
            "zstd-sys",
            &OWN_SRC.replace("zstd-sys-2.1.2+zstd.1.5.7", "zstd-sys-2.1.2;rm")
        ));
        assert!(!own_dir(
            "zstd-sys",
            &OWN_SRC.replace("zstd-sys-2.1.2+zstd.1.5.7", "zstd-sys-2.1.2 x")
        ));
        assert!(own_dir("zstd-sys", OWN_SRC));
        assert!(own_dir("zstd-sys", &OWN_SRC.replace("/zstd/lib", "")));
    }

    #[test]
    fn build_instructions_parser_reads_both_table_shapes() {
        let caps = "[pkg.a]\nbuild.allow_build_instructions = [\"cargo:x=1\",\n  \"cargo:y=2\",\n]\nallow_unsafe = true\n[pkg.b.build]\nallow_build_instructions = [\"cargo:z=3\"]\n[pkg.c]\nallow_apis = [\"fs\"]\n";
        let b = build_instructions(caps).unwrap();
        assert_eq!(b["a"], ["cargo:x=1", "cargo:y=2"]);
        assert_eq!(b["b"], ["cargo:z=3"]);
        assert!(!b.contains_key("c"));
    }

    #[test]
    fn frontier_inventories_pass_the_build_directive_floor_and_the_parser_sees_their_directives() {
        let f = policy();
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let lock = std::fs::read_to_string(root.join("tools/TOOLS.lock")).unwrap();
        let mut seen_dirs = 0;
        let mut seen_inv = 0;
        for t in crate::gate::parse_tools_lock(&lock) {
            let p = root
                .join("supply-chain/evidence")
                .join(&t.name)
                .join(&t.sha)
                .join("caps.toml");
            let Ok(caps) = std::fs::read_to_string(&p) else {
                continue;
            };
            seen_inv += 1;
            seen_dirs += build_instructions(&caps)
                .unwrap()
                .values()
                .map(Vec::len)
                .sum::<usize>();
            assert_eq!(f.caps_stop(&caps, None), None, "{}", p.display());
            assert_eq!(f.caps_stop(&caps, Some(&caps)), None, "{}", p.display());
        }
        assert!(seen_inv >= 5, "frontier inventories read: {seen_inv}");
        assert!(
            seen_dirs >= 20,
            "the hand-audited directives (#381: 31) are visible to the parser: {seen_dirs}"
        );
    }

    #[test]
    fn grants_parser_handles_multiline_arrays_and_scopes() {
        let g = grants(
            "[pkg.x]\nallow_apis = [\n  \"fs\",\n  \"net\",\n]\nfrom.build.allow_apis = [\"process\"]\ntest.allow_apis = [\"env\"]\n[api.net]\ninclude = [\"std::net\"]\n",
        )
        .unwrap();
        let x = &g["x"];
        assert_eq!(
            x.iter().cloned().collect::<Vec<_>>(),
            ["fs", "net", "process"]
        );
        assert!(!g.contains_key("net"));
    }
}
