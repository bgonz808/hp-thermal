//! #376: EoX (end-of-x) tracking for the environments this repo builds and measures on —
//! hosted runner images, the operating systems under them, the pinned Rust channel.
//!
//! WHY. Runner-image lifetimes bit us mid-task on 2026-11-09: a plan moved to ubuntu-22.04
//! before anyone checked that its image had entered deprecation on 2026-09-17. Lifetimes are
//! data and the data has a standard: the OASIS OpenEoX Core Schema v1.0 (CSD01, 2026-07-13).
//! `supply-chain/policy/eox/records.json` embeds one OpenEoX Core document per product; this
//! module validates them against the schema copy pinned by digest in `SCHEMA.lock`, scans the
//! workflows for every `runs-on` label actually in use, and FAILS when a label's image is
//! inside the configured window before its deprecation START (brownouts precede removal).
//!
//! WHAT THE VALIDATOR IS. An OpenEoX Core "Validator Basic" (conformance clause 9.1,
//! `Validator Basic`: schema + section 7.1 mandatory tests) for the keyword subset the CSD01
//! schema uses: `required`, closed `properties`, `$ref` into `$defs`, `const`, `type: string`,
//! `format: date-time` (asserted, per the TC's meta-schema `format-assertion` vocabulary), and
//! `oneOf [format date-time | const tba]`. It is NOT a general JSON Schema engine, and it says
//! so by refusing: any keyword outside that subset in the pinned schema makes the whole check
//! UNEVALUATED (exit 1) rather than silently ignored — so swapping in a later schema stage that
//! adds a keyword cannot pass by accident. Recommended tests (7.2) are warnings and informative
//! tests (7.3) are notices, as the specification requires. The TC's own test vectors are
//! vendored under `xtask/testdata/openeox/` and run in this crate's unit tests.
//!
//! FAIL DIRECTIONS. Schema digest mismatch: nothing evaluated, exit 1. Schema keyword outside the
//! subset: exit 1. A `runs-on` label without a record, a floating label (`*-latest`), or an
//! expression that cannot be resolved from the file: exit 1 — an untracked image is the exact
//! failure mode this exists to prevent. Projected dates are enforced like announced ones (a
//! projection in the fail window fails until a reviewed record replaces it) and are always
//! labelled PROJECTED. The endoflife.date cross-check (monitor only; the files are passed in)
//! fails on any disagreement and WARNS loudly on an unreachable source — never a pass.

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

// ───────────────────────────── RFC 3339 per OpenEoX Core §4.1.6 ─────────────────────────────

/// A point in time: nanoseconds since the Unix epoch with the offset applied, so the derived
/// ordering IS chronological ordering across time zones (§7.1.1 "sorting MUST take timezones
/// into account").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant(i128);

impl Instant {
    /// The UTC calendar day (days since 1970-01-01) this instant falls on.
    pub fn utc_days(self) -> i64 {
        (self.0 / 1_000_000_000).div_euclid(86_400) as i64
    }
}

/// Howard Hinnant's days-from-civil (proleptic Gregorian).
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub fn fmt_days(days: i64) -> String {
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}")
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

fn digits(s: &str, from: usize, n: usize) -> Result<i64, String> {
    let sl = s
        .as_bytes()
        .get(from..from + n)
        .ok_or_else(|| format!("`{s}`: truncated at offset {from}"))?;
    if !sl.iter().all(u8::is_ascii_digit) {
        return Err(format!("`{s}`: expected {n} digits at offset {from}"));
    }
    Ok(std::str::from_utf8(sl).unwrap().parse().unwrap())
}

/// `YYYY-MM-DD` only (shell fields, endoflife.date dates). Days since the epoch.
pub fn parse_date(s: &str) -> Result<i64, String> {
    if s.len() != 10 {
        return Err(format!("`{s}`: expected YYYY-MM-DD"));
    }
    let b = s.as_bytes();
    if b[4] != b'-' || b[7] != b'-' {
        return Err(format!("`{s}`: expected YYYY-MM-DD"));
    }
    let (y, m, d) = (
        digits(s, 0, 4)?,
        digits(s, 5, 2)? as u32,
        digits(s, 8, 2)? as u32,
    );
    if !(1..=12).contains(&m) || d == 0 || d > days_in_month(y, m) {
        return Err(format!("`{s}`: not a calendar date"));
    }
    Ok(days_from_civil(y, m, d))
}

/// RFC 3339 `date-time` under the OpenEoX Core §4.1.6 tightenings: upper-case `T` and `Z`,
/// mandatory offset, fraction with `.` only, and NO leap seconds.
pub fn parse_date_time(s: &str) -> Result<Instant, String> {
    let b = s.as_bytes();
    if b.len() < 19 {
        return Err(format!("`{s}`: too short for an RFC 3339 date-time"));
    }
    if b[4] != b'-' || b[7] != b'-' {
        return Err(format!("`{s}`: expected YYYY-MM-DD"));
    }
    let (y, mo, d) = (
        digits(s, 0, 4)?,
        digits(s, 5, 2)? as u32,
        digits(s, 8, 2)? as u32,
    );
    if !(1..=12).contains(&mo) || d == 0 || d > days_in_month(y, mo) {
        return Err(format!("`{s}`: not a calendar date"));
    }
    match b[10] {
        b'T' => {}
        b't' => {
            return Err(format!(
                "`{s}`: the date/time separator `t` must be upper case (§4.1.6)"
            ));
        }
        b' ' => {
            return Err(format!(
                "`{s}`: the date/time separator must be `T`, not a space (§4.1.6)"
            ));
        }
        _ => return Err(format!("`{s}`: expected `T` at offset 10")),
    }
    if b[13] != b':' || b[16] != b':' {
        return Err(format!("`{s}`: expected HH:MM:SS"));
    }
    let (h, mi, sec) = (digits(s, 11, 2)?, digits(s, 14, 2)?, digits(s, 17, 2)?);
    if h > 23 || mi > 59 {
        return Err(format!("`{s}`: hour/minute out of range"));
    }
    if sec == 60 {
        return Err(format!("`{s}`: leap seconds are prohibited (§4.1.6)"));
    }
    if sec > 60 {
        return Err(format!("`{s}`: second out of range"));
    }
    let mut pos = 19;
    let mut nanos: i128 = 0;
    if b.get(pos) == Some(&b'.') {
        let start = pos + 1;
        let mut end = start;
        while b.get(end).is_some_and(u8::is_ascii_digit) {
            end += 1;
        }
        if end == start {
            return Err(format!("`{s}`: empty fraction"));
        }
        let mut frac = s[start..end].to_string();
        frac.truncate(9);
        while frac.len() < 9 {
            frac.push('0');
        }
        nanos = frac.parse::<i128>().unwrap();
        pos = end;
    }
    let offset_secs: i64 = match b.get(pos) {
        None => return Err(format!("`{s}`: a time zone is required (§4.1.6)")),
        Some(b'Z') => {
            pos += 1;
            0
        }
        Some(b'z') => {
            return Err(format!(
                "`{s}`: the UTC designator `z` must be upper case (§4.1.6)"
            ));
        }
        Some(sign @ (b'+' | b'-')) => {
            if b.len() < pos + 6 || b[pos + 3] != b':' {
                return Err(format!("`{s}`: expected ±HH:MM offset"));
            }
            let (oh, om) = (digits(s, pos + 1, 2)?, digits(s, pos + 4, 2)?);
            if oh > 23 || om > 59 {
                return Err(format!("`{s}`: offset out of range"));
            }
            pos += 6;
            let secs = oh * 3600 + om * 60;
            if *sign == b'-' { -secs } else { secs }
        }
        Some(_) => return Err(format!("`{s}`: unexpected character after seconds")),
    };
    if pos != b.len() {
        return Err(format!("`{s}`: trailing characters"));
    }
    let secs = days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + sec - offset_secs;
    Ok(Instant(secs as i128 * 1_000_000_000 + nanos))
}

/// Today's UTC calendar day from the system clock.
pub fn today_days() -> i64 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    secs.div_euclid(86_400)
}

// ─────────────────────── OpenEoX Core schema: subset interpreter ───────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
enum Rule {
    /// `type: string, const: X`
    Const(String),
    /// `type: string, format: date-time`
    DateTime,
    /// `$ref` to an `eox_timestamp_t`-shaped def: date-time or the `tba` constant.
    Timestamp { tba: String },
}

/// The compiled CSD01-subset schema. Built from the pinned document, never hardcoded, so the
/// pinned bytes are what decide.
#[derive(Debug)]
pub struct CoreSchema {
    pub id: String,
    required: Vec<String>,
    props: BTreeMap<String, Rule>,
}

fn only_keys(
    obj: &serde_json::Map<String, Value>,
    allowed: &[&str],
    at: &str,
) -> Result<(), String> {
    for k in obj.keys() {
        if !allowed.contains(&k.as_str()) {
            return Err(format!(
                "schema keyword `{k}` at {at} is not implemented by this validator — refusing to evaluate (UNEVALUATED, not ignored)"
            ));
        }
    }
    Ok(())
}

/// Compile the pinned schema. `meta` is the TC's meta-schema (schema/meta.json): when given,
/// the core schema's `$schema` must name it and it must assert formats, otherwise `date-time`
/// would be annotation-only under JSON Schema 2020-12 and this validator's strictness would be
/// stricter than the document it claims to implement.
pub fn compile_schema(schema: &Value, meta: Option<&Value>) -> Result<CoreSchema, String> {
    let obj = schema.as_object().ok_or("schema is not a JSON object")?;
    only_keys(
        obj,
        &[
            "$schema",
            "$id",
            "title",
            "description",
            "type",
            "$defs",
            "required",
            "properties",
            "unevaluatedProperties",
        ],
        "/",
    )?;
    if obj.get("type").and_then(Value::as_str) != Some("object") {
        return Err("schema /type is not \"object\"".into());
    }
    if obj.get("unevaluatedProperties") != Some(&Value::Bool(false)) {
        return Err(
            "schema does not close the object (unevaluatedProperties: false); this validator implements closed objects only"
                .into(),
        );
    }
    let id = obj
        .get("$id")
        .and_then(Value::as_str)
        .ok_or("schema has no $id")?
        .to_string();
    if let Some(meta) = meta {
        let meta_id = meta.get("$id").and_then(Value::as_str).unwrap_or("");
        if obj.get("$schema").and_then(Value::as_str) != Some(meta_id) {
            return Err(format!(
                "schema /$schema does not name the pinned meta-schema ({meta_id})"
            ));
        }
        if meta.pointer(
            "/$vocabulary/https:~1~1json-schema.org~1draft~12020-12~1vocab~1format-assertion",
        ) != Some(&Value::Bool(true))
        {
            return Err("meta-schema does not require the format-assertion vocabulary; `date-time` would be annotation-only".into());
        }
    }

    // $defs: each must be exactly the eox_timestamp_t shape.
    let mut defs: BTreeMap<String, String> = BTreeMap::new();
    if let Some(d) = obj.get("$defs") {
        let d = d.as_object().ok_or("schema /$defs is not an object")?;
        for (name, def) in d {
            let at = format!("/$defs/{name}");
            let def = def
                .as_object()
                .ok_or_else(|| format!("{at} is not an object"))?;
            only_keys(def, &["title", "description", "type", "oneOf"], &at)?;
            if def.get("type").and_then(Value::as_str) != Some("string") {
                return Err(format!("{at}/type is not \"string\""));
            }
            let one = def
                .get("oneOf")
                .and_then(Value::as_array)
                .ok_or_else(|| format!("{at} has no oneOf"))?;
            let mut fmt = false;
            let mut tba: Option<String> = None;
            for alt in one {
                let a = alt
                    .as_object()
                    .ok_or_else(|| format!("{at}/oneOf alternative is not an object"))?;
                only_keys(a, &["format", "const"], &format!("{at}/oneOf"))?;
                match (
                    a.get("format").and_then(Value::as_str),
                    a.get("const").and_then(Value::as_str),
                ) {
                    (Some("date-time"), None) => fmt = true,
                    (None, Some(c)) => tba = Some(c.to_string()),
                    _ => {
                        return Err(format!(
                            "{at}/oneOf alternative is neither format:date-time nor a string const"
                        ));
                    }
                }
            }
            match (fmt, tba) {
                (true, Some(t)) if one.len() == 2 => {
                    defs.insert(name.clone(), t);
                }
                _ => return Err(format!("{at}/oneOf is not [format date-time | const]")),
            }
        }
    }

    let props_v = obj
        .get("properties")
        .and_then(Value::as_object)
        .ok_or("schema has no /properties object")?;
    let mut props = BTreeMap::new();
    for (name, p) in props_v {
        let at = format!("/properties/{name}");
        let p = p
            .as_object()
            .ok_or_else(|| format!("{at} is not an object"))?;
        only_keys(
            p,
            &["title", "description", "type", "const", "$ref", "format"],
            &at,
        )?;
        let rule = if let Some(r) = p.get("$ref") {
            let r = r
                .as_str()
                .ok_or_else(|| format!("{at}/$ref is not a string"))?;
            let def = r
                .strip_prefix("#/$defs/")
                .and_then(|n| defs.get(n))
                .ok_or_else(|| {
                    format!("{at}/$ref `{r}` does not resolve to a local $defs entry")
                })?;
            if p.contains_key("type") || p.contains_key("const") || p.contains_key("format") {
                return Err(format!("{at} mixes $ref with inline constraints"));
            }
            Rule::Timestamp { tba: def.clone() }
        } else {
            if p.get("type").and_then(Value::as_str) != Some("string") {
                return Err(format!("{at}/type is not \"string\""));
            }
            match (p.get("const"), p.get("format").and_then(Value::as_str)) {
                (Some(Value::String(c)), None) => Rule::Const(c.clone()),
                (None, Some("date-time")) => Rule::DateTime,
                _ => {
                    return Err(format!(
                        "{at} is neither a string const nor format:date-time"
                    ));
                }
            }
        };
        props.insert(name.clone(), rule);
    }

    let required = obj
        .get("required")
        .and_then(Value::as_array)
        .ok_or("schema has no /required array")?
        .iter()
        .map(|r| {
            r.as_str()
                .map(str::to_string)
                .ok_or_else(|| "non-string in /required".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    for r in &required {
        if !props.contains_key(r) {
            return Err(format!("/required names `{r}` which is not in /properties"));
        }
    }
    Ok(CoreSchema {
        id,
        required,
        props,
    })
}

/// §7 outcomes, kept apart because the specification assigns them different severities:
/// mandatory = error, recommended = warning, informative = notice.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Conformance {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub notices: Vec<String>,
}

impl CoreSchema {
    /// Schema validation (structure, closed object, const, formats). The `format` check is the
    /// §4.1.6 parser, which is also what §7.1.2 demands, so that mandatory test lives here.
    fn validate(&self, doc: &Value) -> Vec<String> {
        let mut errs = Vec::new();
        let Some(obj) = doc.as_object() else {
            return vec!["EoX Core document is not a JSON object".into()];
        };
        for r in &self.required {
            if !obj.contains_key(r) {
                errs.push(format!("required property `{r}` is missing"));
            }
        }
        for (k, v) in obj {
            let Some(rule) = self.props.get(k) else {
                errs.push(format!(
                    "property `{k}` is not in the schema (closed object)"
                ));
                continue;
            };
            let Some(s) = v.as_str() else {
                errs.push(format!("`{k}` is not a string"));
                continue;
            };
            match rule {
                Rule::Const(c) => {
                    if s != c {
                        errs.push(format!("`{k}` must be the constant `{c}`"));
                    }
                }
                Rule::DateTime => {
                    if let Err(e) = parse_date_time(s) {
                        errs.push(format!("§7.1.2 `{k}`: {e}"));
                    }
                }
                Rule::Timestamp { tba } => {
                    if s != tba
                        && let Err(e) = parse_date_time(s)
                    {
                        errs.push(format!("§7.1.2 `{k}`: {e}"));
                    }
                }
            }
        }
        errs
    }

    /// The eox_timestamp_t-typed properties present in `doc`: `None` = tba.
    fn timestamps(&self, doc: &Value) -> BTreeMap<String, Option<Instant>> {
        let mut out = BTreeMap::new();
        if let Some(obj) = doc.as_object() {
            for (k, v) in obj {
                if let (Some(Rule::Timestamp { tba }), Some(s)) = (self.props.get(k), v.as_str()) {
                    out.insert(
                        k.clone(),
                        if s == tba {
                            None
                        } else {
                            parse_date_time(s).ok()
                        },
                    );
                }
            }
        }
        out
    }

    /// Conformance clause "EoX Core Information" (§9.1.1) plus the §7.2/§7.3 advisories. On a
    /// schema-invalid document only the schema errors are reported: the semantic tests are
    /// defined over valid documents.
    pub fn check(&self, doc: &Value) -> Conformance {
        let mut c = Conformance {
            errors: self.validate(doc),
            ..Default::default()
        };
        if !c.errors.is_empty() {
            return c;
        }
        let ts = self.timestamps(doc);
        let dated = |k: &str| ts.get(k).copied().flatten();
        // §7.1.1 end_of_life is >= every other date (tba in EoL = greater than max: vacuous).
        if let Some(eol) = dated("end_of_life") {
            for (k, v) in &ts {
                if k != "end_of_life" && v.is_some_and(|d| d > eol) {
                    c.errors
                        .push(format!("§7.1.1 `{k}` is later than `end_of_life`"));
                }
            }
        }
        // §7.1.3 general_availability is <= every other date (skipped when tba).
        if let Some(ga) = dated("general_availability") {
            for (k, v) in &ts {
                if k != "general_availability" && v.is_some_and(|d| ga > d) {
                    c.errors
                        .push(format!("§7.1.3 `general_availability` is later than `{k}`"));
                }
            }
        }
        // §7.2.1 no tba elsewhere once end_of_life is a date.
        if dated("end_of_life").is_some() {
            for (k, v) in &ts {
                if k != "end_of_life" && v.is_none() {
                    c.warnings
                        .push(format!("§7.2.1 `{k}` is tba although `end_of_life` is set"));
                }
            }
        }
        // §7.2.2 general_availability tba while any other eox date is set.
        if matches!(ts.get("general_availability"), Some(None))
            && ts
                .iter()
                .any(|(k, v)| k != "general_availability" && v.is_some())
        {
            c.warnings
                .push("§7.2.2 `general_availability` is tba although another date is set".into());
        }
        // §7.3.1 end_of_sales <= end_of_security_support (skipped when either is tba).
        if let (Some(eos), Some(eoss)) = (dated("end_of_sales"), dated("end_of_security_support"))
            && eos > eoss
        {
            c.notices
                .push("§7.3.1 `end_of_sales` is later than `end_of_security_support`".into());
        }
        c
    }
}

// ─────────────────────────── SCHEMA.lock: the pinned schema copy ───────────────────────────

/// Verify every `file url sha256` line of SCHEMA.lock against the committed copies and return
/// the parsed core schema (compiled with the meta-schema when the lock carries one). Any
/// mismatch is fatal: nothing downstream is evaluated against an unreviewed schema.
pub fn load_pinned_schema(lock: &Path) -> Result<CoreSchema, String> {
    let text = std::fs::read_to_string(lock).map_err(|e| format!("{}: {e}", lock.display()))?;
    let dir = lock.parent().unwrap_or(Path::new(".")).join("schema");
    let mut core: Option<Value> = None;
    let mut meta: Option<Value> = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() != 3 {
            return Err(format!(
                "{}: malformed line `{line}` (want: file url sha256)",
                lock.display()
            ));
        }
        let path = dir.join(f[0]);
        let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let got = crate::sha256::sha256_hex(&bytes);
        if got != f[2] {
            return Err(format!(
                "{}: sha256 {got} does not match SCHEMA.lock ({}) — the pinned schema copy was changed without a lock review; refusing to evaluate",
                path.display(),
                f[2]
            ));
        }
        let v: Value =
            serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display()))?;
        match f[0] {
            "core.json" => core = Some(v),
            "meta.json" => meta = Some(v),
            other => {
                return Err(format!(
                    "{}: unexpected schema file `{other}`",
                    lock.display()
                ));
            }
        }
    }
    let core = core.ok_or_else(|| format!("{}: no core.json line", lock.display()))?;
    compile_schema(&core, meta.as_ref())
}

// ───────────────────────────── records.json: the hp-thermal shell ─────────────────────────────

#[derive(Debug, Clone)]
pub struct Projection {
    pub end_of_active_support: Option<i64>,
    pub end_of_life: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct Product {
    pub id: String,
    pub kind: String,
    pub runs_on: Vec<String>,
    pub eox: Value,
    /// `None` = not applicable to this kind; `Some(None)` = tba; `Some(Some(days))` = announced.
    pub end_of_active_support: Option<Option<i64>>,
    pub projection: Option<Projection>,
    pub crosscheck: Option<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct OneImageRule {
    pub mentions: Vec<String>,
    pub label_prefix: String,
}

#[derive(Debug)]
pub struct Records {
    pub fail_days: i64,
    pub warn_days: i64,
    pub one_image: Vec<OneImageRule>,
    pub products: Vec<Product>,
}

const KINDS: &[&str] = &["runner-image", "os", "toolchain-channel"];

fn date_or_tba(v: &Value, at: &str) -> Result<Option<i64>, String> {
    match v.as_str() {
        Some("tba") => Ok(None),
        Some(s) => parse_date(s).map(Some).map_err(|e| format!("{at}: {e}")),
        None => Err(format!("{at}: expected a YYYY-MM-DD string or \"tba\"")),
    }
}

pub fn parse_records(v: &Value) -> Result<Records, String> {
    if v.get("schema").and_then(Value::as_str) != Some("hp-thermal/eox-records/v1") {
        return Err("schema is not hp-thermal/eox-records/v1".into());
    }
    let obj = v.as_object().ok_or("records is not an object")?;
    only_keys(
        obj,
        &[
            "schema",
            "_doc",
            "thresholds_days",
            "one_image_rules",
            "products",
        ],
        "/",
    )?;
    let th = |k: &str| -> Result<i64, String> {
        v.pointer(&format!("/thresholds_days/{k}"))
            .and_then(Value::as_i64)
            .filter(|d| *d > 0)
            .ok_or_else(|| format!("/thresholds_days/{k} missing or not a positive integer"))
    };
    let (fail_days, warn_days) = (th("fail")?, th("warn")?);
    if warn_days < fail_days {
        return Err("/thresholds_days: warn must be >= fail".into());
    }
    let mut one_image = Vec::new();
    for (i, r) in v
        .get("one_image_rules")
        .and_then(Value::as_array)
        .unwrap_or(&Vec::new())
        .iter()
        .enumerate()
    {
        let at = format!("/one_image_rules/{i}");
        let o = r
            .as_object()
            .ok_or_else(|| format!("{at} is not an object"))?;
        only_keys(o, &["_doc", "consumer_mentions", "label_prefix"], &at)?;
        let mentions = o
            .get("consumer_mentions")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("{at}/consumer_mentions missing"))?
            .iter()
            .map(|m| {
                m.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| format!("{at}: non-string mention"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let label_prefix = o
            .get("label_prefix")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{at}/label_prefix missing"))?
            .to_string();
        if mentions.is_empty() || label_prefix.is_empty() {
            return Err(format!("{at}: empty rule"));
        }
        one_image.push(OneImageRule {
            mentions,
            label_prefix,
        });
    }
    let list = v
        .get("products")
        .and_then(Value::as_array)
        .ok_or("/products is not an array")?;
    if list.is_empty() {
        return Err("/products is empty".into());
    }
    let mut products = Vec::new();
    let mut ids = BTreeSet::new();
    let mut labels = BTreeSet::new();
    for (i, p) in list.iter().enumerate() {
        let at = format!("/products/{i}");
        let o = p
            .as_object()
            .ok_or_else(|| format!("{at} is not an object"))?;
        only_keys(
            o,
            &[
                "id",
                "kind",
                "vendor",
                "runs_on",
                "base_os",
                "eox",
                "end_of_active_support",
                "projection",
                "sources",
                "crosscheck",
                "note",
            ],
            &at,
        )?;
        let id = o
            .get("id")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| format!("{at}/id missing"))?
            .to_string();
        if !ids.insert(id.clone()) {
            return Err(format!("{at}: duplicate id `{id}`"));
        }
        let kind = o
            .get("kind")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{at}/kind missing"))?
            .to_string();
        if !KINDS.contains(&kind.as_str()) {
            return Err(format!("{at}/kind `{kind}` is not one of {KINDS:?}"));
        }
        let runs_on = o
            .get("runs_on")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("{at}/runs_on missing (use [] for a product no job runs on)"))?
            .iter()
            .map(|l| {
                l.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| format!("{at}/runs_on: non-string label"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        for l in &runs_on {
            if kind != "runner-image" {
                return Err(format!(
                    "{at}: only runner-image products carry runs_on labels"
                ));
            }
            if !labels.insert(l.clone()) {
                return Err(format!("{at}: label `{l}` is claimed by two products"));
            }
        }
        let eox = o
            .get("eox")
            .cloned()
            .ok_or_else(|| format!("{at}/eox missing"))?;
        let end_of_active_support = match (kind.as_str(), o.get("end_of_active_support")) {
            ("runner-image", Some(e)) => {
                Some(date_or_tba(e, &format!("{at}/end_of_active_support"))?)
            }
            ("runner-image", None) => {
                return Err(format!(
                    "{at}/end_of_active_support missing: a runner image record must state its deprecation start or \"tba\""
                ));
            }
            (_, Some(_)) => {
                return Err(format!(
                    "{at}/end_of_active_support applies to runner images only"
                ));
            }
            (_, None) => None,
        };
        let projection = match o.get("projection") {
            None => None,
            Some(pj) => {
                let pat = format!("{at}/projection");
                let po = pj
                    .as_object()
                    .ok_or_else(|| format!("{pat} is not an object"))?;
                only_keys(po, &["end_of_active_support", "end_of_life", "basis"], &pat)?;
                if po
                    .get("basis")
                    .and_then(Value::as_str)
                    .is_none_or(str::is_empty)
                {
                    return Err(format!(
                        "{pat}/basis missing: a projection must state the pattern it rests on"
                    ));
                }
                let d = |k: &str| -> Result<Option<i64>, String> {
                    match po.get(k) {
                        None => Ok(None),
                        Some(x) => parse_date(x.as_str().unwrap_or(""))
                            .map(Some)
                            .map_err(|e| format!("{pat}/{k}: {e}")),
                    }
                };
                let pr = Projection {
                    end_of_active_support: d("end_of_active_support")?,
                    end_of_life: d("end_of_life")?,
                };
                if pr.end_of_active_support.is_none() && pr.end_of_life.is_none() {
                    return Err(format!("{pat} projects nothing"));
                }
                if let (Some(Some(_)), Some(_)) = (end_of_active_support, pr.end_of_active_support)
                {
                    return Err(format!(
                        "{pat}/end_of_active_support: the vendor announced this date; drop the projection"
                    ));
                }
                Some(pr)
            }
        };
        let crosscheck = match o.get("crosscheck") {
            None => None,
            Some(c) => {
                let cat = format!("{at}/crosscheck");
                let co = c
                    .as_object()
                    .ok_or_else(|| format!("{cat} is not an object"))?;
                only_keys(co, &["endoflife"], &cat)?;
                let e = co
                    .get("endoflife")
                    .and_then(Value::as_object)
                    .ok_or_else(|| format!("{cat}/endoflife missing"))?;
                only_keys(e, &["product", "release"], &format!("{cat}/endoflife"))?;
                let g = |k: &str| {
                    e.get(k)
                        .and_then(Value::as_str)
                        .map(str::to_string)
                        .ok_or_else(|| format!("{cat}/endoflife/{k} missing"))
                };
                Some((g("product")?, g("release")?))
            }
        };
        products.push(Product {
            id,
            kind,
            runs_on,
            eox,
            end_of_active_support,
            projection,
            crosscheck,
        });
    }
    Ok(Records {
        fail_days,
        warn_days,
        one_image,
        products,
    })
}

// ───────────────────────────────── workflow scan: runs-on ─────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobRef {
    pub file: String,
    pub job: String,
    /// Resolved runner labels (one for a literal, several for a resolved expression).
    pub labels: Vec<String>,
    /// The job's non-comment text (for consumer-mention rules).
    pub text: String,
}

/// Drop YAML comments: whole-line comments and ` #...` tails. Good enough for `runs-on` lines
/// and for deciding whether a job *mentions* a tool in code rather than in prose.
fn strip_comment(line: &str) -> &str {
    if line.trim_start().starts_with('#') {
        return "";
    }
    match line.find(" #") {
        Some(i) => &line[..i],
        None => line,
    }
}

fn unquote(s: &str) -> &str {
    let s = s.trim();
    s.strip_prefix('"')
        .and_then(|x| x.strip_suffix('"'))
        .or_else(|| s.strip_prefix('\'').and_then(|x| x.strip_suffix('\'')))
        .unwrap_or(s)
}

/// `runner=<label>` assignments anywhere in the file: how a job that picks its runner in an
/// earlier job's shell (candidate-build.yml's `resolve`) declares its candidates. A workflow
/// whose expression cannot be resolved this way is an error, not a skip.
fn runner_tokens(text: &str) -> Vec<String> {
    let mut out = BTreeSet::new();
    for line in text.lines().map(strip_comment) {
        let mut rest = line;
        while let Some(i) = rest.find("runner=") {
            let after = &rest[i + "runner=".len()..];
            let tok: String = after
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '.' || *c == '_')
                .collect();
            if !tok.is_empty() && !tok.starts_with('$') {
                out.insert(tok);
            }
            rest = after;
        }
    }
    out.into_iter().collect()
}

/// Split a workflow into jobs and resolve each job's `runs-on`. Errors are per-job and
/// collected rather than short-circuited so one run reports every untracked label.
pub fn scan_workflow(file: &str, text: &str) -> (Vec<JobRef>, Vec<String>) {
    let mut jobs: Vec<JobRef> = Vec::new();
    let mut errors = Vec::new();
    let mut in_jobs = false;
    let mut raw_runs_on: Vec<(String, String)> = Vec::new(); // (job, value)
    for raw in text.lines() {
        let line = strip_comment(raw);
        if line.trim().is_empty() {
            continue;
        }
        if !line.starts_with(' ') {
            in_jobs = line.trim_end() == "jobs:";
            continue;
        }
        if !in_jobs {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if indent == 2 {
            let head = line.trim();
            if let Some(name) = head.strip_suffix(':')
                && !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                jobs.push(JobRef {
                    file: file.to_string(),
                    job: name.to_string(),
                    labels: vec![],
                    text: String::new(),
                });
                continue;
            }
        }
        if let Some(j) = jobs.last_mut() {
            j.text.push_str(line);
            j.text.push('\n');
            let t = line.trim_start();
            if let Some(v) = t.strip_prefix("runs-on:") {
                raw_runs_on.push((j.job.clone(), v.trim().to_string()));
            }
        }
    }
    let tokens = runner_tokens(text);
    for (job, value) in raw_runs_on {
        let Some(j) = jobs.iter_mut().find(|j| j.job == job) else {
            continue;
        };
        let v = unquote(&value);
        if v.is_empty() || v.starts_with('[') || v.starts_with('{') || v.starts_with('-') {
            errors.push(format!(
                "{file}: job `{job}`: runs-on shape `{value}` is not a single label; this check cannot track it"
            ));
            continue;
        }
        if v.starts_with("${{") {
            if tokens.is_empty() {
                errors.push(format!(
                    "{file}: job `{job}`: runs-on is the expression `{v}` and no `runner=<label>` assignment in the file declares its candidates — untrackable"
                ));
            } else {
                j.labels = tokens.clone();
            }
            continue;
        }
        j.labels = vec![v.to_string()];
    }
    for j in &jobs {
        for l in &j.labels {
            if l.ends_with("-latest") {
                errors.push(format!(
                    "{}: job `{}`: runs-on `{l}` is a floating label (its image changes under us: ubuntu-latest moved to 26.04 in 2026-11); pin the image",
                    j.file, j.job
                ));
            }
        }
    }
    (jobs, errors)
}

pub fn scan_workflows_dir(dir: &Path) -> Result<(Vec<JobRef>, Vec<String>), String> {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "yml" || x == "yaml"))
        .collect();
    entries.sort();
    if entries.is_empty() {
        return Err(format!(
            "{}: no workflow files found (fail-closed: nothing to track is not a pass)",
            dir.display()
        ));
    }
    let mut jobs = Vec::new();
    let mut errors = Vec::new();
    for p in entries {
        let text = std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        let name = p
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("?")
            .to_string();
        let (j, e) = scan_workflow(&name, &text);
        jobs.extend(j);
        errors.extend(e);
    }
    Ok((jobs, errors))
}

// ───────────────────────────────────── evaluation ─────────────────────────────────────

#[derive(Debug, Default)]
pub struct Report {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub notices: Vec<String>,
}

/// endoflife.date v1 product responses by product slug; a product named in a record's
/// crosscheck but absent here is UNKNOWN (warning), never a pass.
pub type EndOfLife = BTreeMap<String, Value>;

fn eox_date(p: &Product, field: &str) -> Result<Option<i64>, String> {
    match p.eox.get(field).and_then(Value::as_str) {
        None => Err(format!("{}: eox/{field} missing", p.id)),
        Some("tba") => Ok(None),
        Some(s) => parse_date_time(s).map(|i| Some(i.utc_days())),
    }
}

fn api_date(rel: &Value, key: &str) -> Result<Option<i64>, String> {
    match rel.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => parse_date(s).map(Some),
        Some(other) => Err(format!("{key}: unexpected {other}")),
    }
}

fn crosscheck_product(p: &Product, rel: &Value) -> Result<Vec<String>, String> {
    let mut mism = Vec::new();
    let mut cmp = |what: &str, ours: Option<i64>, theirs: Option<i64>| {
        if ours != theirs {
            let f = |d: Option<i64>| d.map(fmt_days).unwrap_or_else(|| "tba".into());
            mism.push(format!(
                "{what}: record {} vs endoflife.date {}",
                f(ours),
                f(theirs)
            ));
        }
    };
    cmp(
        "general_availability~releaseDate",
        eox_date(p, "general_availability")?,
        api_date(rel, "releaseDate")?,
    );
    match p.kind.as_str() {
        "runner-image" => {
            cmp(
                "end_of_active_support~eoasFrom",
                p.end_of_active_support.flatten(),
                api_date(rel, "eoasFrom")?,
            );
            cmp(
                "end_of_life~eolFrom",
                eox_date(p, "end_of_life")?,
                api_date(rel, "eolFrom")?,
            );
        }
        "os" => {
            cmp(
                "end_of_security_support~eolFrom",
                eox_date(p, "end_of_security_support")?,
                api_date(rel, "eolFrom")?,
            );
            cmp(
                "end_of_life~eoesFrom",
                eox_date(p, "end_of_life")?,
                api_date(rel, "eoesFrom")?,
            );
        }
        _ => {}
    }
    Ok(mism)
}

pub fn evaluate(
    schema: &CoreSchema,
    recs: &Records,
    jobs: &[JobRef],
    toolchain_channel: Option<&str>,
    today: i64,
    endoflife: Option<&EndOfLife>,
) -> Report {
    let mut r = Report::default();

    // 1. Every embedded OpenEoX document conforms; §7.2/§7.3 findings are surfaced too.
    for p in &recs.products {
        let c = schema.check(&p.eox);
        r.errors
            .extend(c.errors.iter().map(|e| format!("{}: eox: {e}", p.id)));
        r.warnings
            .extend(c.warnings.iter().map(|e| format!("{}: eox: {e}", p.id)));
        r.notices
            .extend(c.notices.iter().map(|e| format!("{}: eox: {e}", p.id)));
        if p.eox.get("$schema").and_then(Value::as_str) != Some(schema.id.as_str()) {
            r.errors.push(format!(
                "{}: eox/$schema is not the pinned schema id {}",
                p.id, schema.id
            ));
        }
    }

    // 2. Every label in use has a record; the records' windows are enforced on those.
    let mut used: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for j in jobs {
        for l in &j.labels {
            used.entry(l.clone())
                .or_default()
                .push(format!("{}:{}", j.file, j.job));
        }
    }
    for (label, where_) in &used {
        let Some(p) = recs
            .products
            .iter()
            .find(|p| p.runs_on.iter().any(|l| l == label))
        else {
            r.errors.push(format!(
                "runs-on `{label}` (used by {}) has no EoX record in records.json — an untracked image is the failure this check exists for",
                where_.join(", ")
            ));
            continue;
        };
        match eox_date(p, "end_of_life") {
            Ok(Some(eol)) if today >= eol => r.errors.push(format!(
                "{label}: image end_of_life {} has passed (used by {})",
                fmt_days(eol),
                where_.join(", ")
            )),
            Err(e) => r.errors.push(e),
            _ => {}
        }
        let (date, projected) = match (p.end_of_active_support, &p.projection) {
            (Some(Some(d)), _) => (Some(d), false),
            (
                _,
                Some(Projection {
                    end_of_active_support: Some(d),
                    ..
                }),
            ) => (Some(*d), true),
            _ => (None, false),
        };
        let tag = if projected {
            " (PROJECTED — confirm or correct the record)"
        } else {
            ""
        };
        match date {
            None => r.notices.push(format!(
                "{label}: no announced or projected deprecation start; the endoflife.date cross-check watches for the announcement (used by {})",
                where_.join(", ")
            )),
            Some(d) => {
                let left = d - today;
                let when = fmt_days(d);
                if left <= 0 {
                    r.errors.push(format!(
                        "{label}: deprecation started {} ({} days ago){tag}; migrate every job off it (used by {})",
                        when, -left, where_.join(", ")
                    ));
                } else if left < recs.fail_days {
                    r.errors.push(format!(
                        "{label}: deprecation starts {when} in {left} days, inside the {}-day window{tag}; migrate (used by {})",
                        recs.fail_days, where_.join(", ")
                    ));
                } else if left < recs.warn_days {
                    r.warnings.push(format!(
                        "{label}: deprecation starts {when} in {left} days, inside the {}-day warning window{tag} (used by {})",
                        recs.warn_days, where_.join(", ")
                    ));
                } else {
                    r.notices.push(format!("{label}: deprecation starts {when} in {left} days{tag}"));
                }
            }
        }
    }

    // 3. One-image rules: consumers of a tool measure where they build.
    for rule in &recs.one_image {
        let mut seen: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for j in jobs {
            if rule.mentions.iter().any(|m| j.text.contains(m.as_str())) {
                for l in j
                    .labels
                    .iter()
                    .filter(|l| l.starts_with(&rule.label_prefix))
                {
                    seen.entry(l.clone())
                        .or_default()
                        .push(format!("{}:{}", j.file, j.job));
                }
            }
        }
        if seen.len() > 1 {
            let desc: Vec<String> = seen
                .iter()
                .map(|(l, w)| format!("{l} <- {}", w.join(", ")))
                .collect();
            r.errors.push(format!(
                "one-image rule for {:?}: jobs consuming it run on {} different `{}*` images: {}",
                rule.mentions,
                seen.len(),
                rule.label_prefix,
                desc.join("; ")
            ));
        }
    }

    // 4. The pinned toolchain channel is tracked as data.
    if let Some(ch) = toolchain_channel {
        let want = format!("rust-toolchain/{ch}");
        if !recs
            .products
            .iter()
            .any(|p| p.kind == "toolchain-channel" && p.id == want)
        {
            r.errors.push(format!(
                "TOOLCHAIN.lock channel `{ch}` has no EoX record (want a toolchain-channel product with id `{want}`)"
            ));
        }
    }

    // 5. Cross-check against endoflife.date (when the monitor passed responses in).
    if let Some(eol) = endoflife {
        for p in &recs.products {
            let Some((product, release)) = &p.crosscheck else {
                continue;
            };
            let Some(resp) = eol.get(product) else {
                r.warnings.push(format!(
                    "{}: cross-check UNKNOWN — endoflife.date product `{product}` was not fetched or did not parse; this is not a pass",
                    p.id
                ));
                continue;
            };
            let rel = resp
                .pointer("/result/releases")
                .and_then(Value::as_array)
                .and_then(|a| {
                    a.iter()
                        .find(|x| x.get("name").and_then(Value::as_str) == Some(release))
                });
            match rel {
                None => r.errors.push(format!(
                    "{}: cross-check: endoflife.date `{product}` has no release named `{release}` — the record's binding is stale",
                    p.id
                )),
                Some(rel) => match crosscheck_product(p, rel) {
                    Ok(m) if m.is_empty() => {}
                    Ok(m) => {
                        for x in m {
                            r.errors.push(format!("{}: cross-check mismatch — {x}; confirm or correct the record", p.id));
                        }
                    }
                    Err(e) => r.errors.push(format!("{}: cross-check: {e}", p.id)),
                },
            }
        }
    }
    r
}

// ──────────────────────────────────────── CLI ────────────────────────────────────────

fn toolchain_channel(lock: &Path) -> Result<String, String> {
    let text = std::fs::read_to_string(lock).map_err(|e| format!("{}: {e}", lock.display()))?;
    text.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .find_map(|l| l.strip_prefix("channel").map(|r| r.trim().to_string()))
        .filter(|c| !c.is_empty())
        .ok_or_else(|| format!("{}: no `channel` line", lock.display()))
}

fn emit(kind: &str, msg: &str) {
    let gha = std::env::var("GITHUB_ACTIONS").is_ok_and(|v| v == "true");
    match (kind, gha) {
        ("error", true) => println!("::error::eox-check: {msg}"),
        ("warning", true) => println!("::warning::eox-check: {msg}"),
        ("notice", true) => println!("::notice::eox-check: {msg}"),
        ("error", false) => println!("FAIL: {msg}"),
        ("warning", false) => println!("WARN: {msg}"),
        _ => println!("note: {msg}"),
    }
}

pub fn run(args: &[String]) -> i32 {
    let mut records = PathBuf::from("supply-chain/policy/eox/records.json");
    let mut lock = PathBuf::from("supply-chain/policy/eox/SCHEMA.lock");
    let mut workflows = PathBuf::from(".github/workflows");
    let mut toolchain_lock = PathBuf::from("tools/TOOLCHAIN.lock");
    let mut today: Option<i64> = None;
    let mut eol_files: Vec<(String, PathBuf)> = Vec::new();
    let mut crosscheck = false;
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        let next = |it: &mut dyn Iterator<Item = &String>| it.next().cloned().unwrap_or_default();
        match a.as_str() {
            "--records" => records = PathBuf::from(next(&mut it)),
            "--schema-lock" => lock = PathBuf::from(next(&mut it)),
            "--workflows" => workflows = PathBuf::from(next(&mut it)),
            "--toolchain-lock" => toolchain_lock = PathBuf::from(next(&mut it)),
            "--today" => match parse_date(&next(&mut it)) {
                Ok(d) => today = Some(d),
                Err(e) => {
                    eprintln!("eox-check: --today: {e}");
                    return 2;
                }
            },
            "--endoflife" => {
                crosscheck = true;
                let spec = next(&mut it);
                match spec.split_once('=') {
                    Some((p, f)) if !p.is_empty() && !f.is_empty() => {
                        eol_files.push((p.to_string(), PathBuf::from(f)))
                    }
                    _ => {
                        eprintln!("eox-check: --endoflife wants <product>=<file>");
                        return 2;
                    }
                }
            }
            "--crosscheck" => crosscheck = true,
            other => {
                eprintln!("eox-check: unknown argument {other}");
                eprintln!(
                    "usage: xtask eox-check [--records P] [--schema-lock P] [--workflows DIR] [--toolchain-lock P] [--today YYYY-MM-DD] [--crosscheck] [--endoflife <product>=<file>]..."
                );
                return 2;
            }
        }
    }
    let today = today.unwrap_or_else(today_days);

    let schema = match load_pinned_schema(&lock) {
        Ok(s) => s,
        Err(e) => {
            emit("error", &e);
            return 1;
        }
    };
    println!(
        "eox-check: schema {} verified against {}",
        schema.id,
        lock.display()
    );
    let recs = match std::fs::read_to_string(&records)
        .map_err(|e| format!("{}: {e}", records.display()))
        .and_then(|t| {
            serde_json::from_str::<Value>(&t).map_err(|e| format!("{}: {e}", records.display()))
        })
        .and_then(|v| parse_records(&v))
    {
        Ok(r) => r,
        Err(e) => {
            emit("error", &format!("records: {e}"));
            return 1;
        }
    };
    let (jobs, scan_errors) = match scan_workflows_dir(&workflows) {
        Ok(x) => x,
        Err(e) => {
            emit("error", &e);
            return 1;
        }
    };
    let channel = match toolchain_channel(&toolchain_lock) {
        Ok(c) => c,
        Err(e) => {
            emit("error", &e);
            return 1;
        }
    };
    let endoflife: Option<EndOfLife> = if crosscheck {
        let mut m = EndOfLife::new();
        for (product, file) in &eol_files {
            match std::fs::read(file)
                .map_err(|e| e.to_string())
                .and_then(|b| serde_json::from_slice::<Value>(&b).map_err(|e| e.to_string()))
            {
                Ok(v)
                    if v.pointer("/result/releases")
                        .and_then(Value::as_array)
                        .is_some() =>
                {
                    m.insert(product.clone(), v);
                }
                Ok(_) => emit(
                    "warning",
                    &format!(
                        "endoflife.date `{product}`: response has no result.releases — treated as UNKNOWN"
                    ),
                ),
                Err(e) => emit(
                    "warning",
                    &format!("endoflife.date `{product}`: {e} — treated as UNKNOWN"),
                ),
            }
        }
        Some(m)
    } else {
        None
    };

    let mut report = evaluate(
        &schema,
        &recs,
        &jobs,
        Some(&channel),
        today,
        endoflife.as_ref(),
    );
    report.errors.splice(0..0, scan_errors);

    let mut labels: BTreeSet<&str> = BTreeSet::new();
    for j in &jobs {
        labels.extend(j.labels.iter().map(String::as_str));
    }
    println!(
        "eox-check: today {} · {} products · {} jobs in {} · labels in use: {}",
        fmt_days(today),
        recs.products.len(),
        jobs.len(),
        workflows.display(),
        labels.into_iter().collect::<Vec<_>>().join(", ")
    );
    for n in &report.notices {
        emit("notice", n);
    }
    for w in &report.warnings {
        emit("warning", w);
    }
    for e in &report.errors {
        emit("error", e);
    }
    if !crosscheck {
        println!("eox-check: cross-check against endoflife.date not requested (offline run)");
    }
    if report.errors.is_empty() {
        println!(
            "eox-check: OK ({} warning(s), {} notice(s))",
            report.warnings.len(),
            report.notices.len()
        );
        0
    } else {
        println!("eox-check: FAIL ({} error(s))", report.errors.len());
        1
    }
}

// ──────────────────────────────────────── tests ────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn repo(rel: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(rel)
    }
    fn pinned() -> CoreSchema {
        load_pinned_schema(&repo("supply-chain/policy/eox/SCHEMA.lock")).expect("pinned schema")
    }
    fn json(s: &str) -> Value {
        serde_json::from_str(s).unwrap()
    }

    // ── §4.1.6 parser ──

    #[test]
    fn date_time_accepts_rfc3339_and_orders_across_offsets() {
        let a = parse_date_time("2025-11-25T10:00:00.000-20:30").unwrap(); // 2025-11-26T06:30Z
        let b = parse_date_time("2025-11-27T03:00:00.000+20:59").unwrap(); // 2025-11-26T06:01Z
        let c = parse_date_time("2025-11-26T10:00:00.000+03:37").unwrap(); // 2025-11-26T06:23Z
        assert!(b < c && c < a, "offset-aware ordering");
        assert_eq!(fmt_days(a.utc_days()), "2025-11-26");
        assert_eq!(
            parse_date_time("2025-12-31T12:00:00Z").unwrap().utc_days(),
            parse_date("2025-12-31").unwrap()
        );
        // fraction ordering
        assert!(
            parse_date_time("2025-10-03T00:00:19.90Z").unwrap()
                > parse_date_time("2025-10-03T00:00:19.5Z").unwrap()
        );
    }

    #[test]
    fn date_time_rejects_every_4_1_6_violation() {
        for (bad, why) in [
            ("2025-12-31 12:00:00Z", "space"),
            ("2025-12-17t14:00:00Z", "upper case"),
            ("2025-11-19T16:00:00z", "upper case"),
            ("2016-12-31T23:59:60.0123+00:00", "leap"),
            ("2025-12-31T12:00:00", "time zone"),
            ("2025-12-31T12:00:00.Z", "fraction"),
            ("2025-12-31T12:00:00,5Z", "unexpected"),
            ("2025-02-30T12:00:00Z", "calendar"),
            ("2025-12-31T24:00:00Z", "range"),
            ("2025-12-31T12:00:00+24:00", "range"),
            ("2025-12-31T12:00:00Zx", "trailing"),
        ] {
            let e = parse_date_time(bad).expect_err(bad);
            assert!(e.contains(why), "{bad}: {e}");
        }
        assert!(parse_date("2025-13-01").is_err());
        assert!(parse_date("2025-1-01").is_err());
        assert_eq!(fmt_days(parse_date("2000-02-29").unwrap()), "2000-02-29");
        assert_eq!(fmt_days(0), "1970-01-01");
    }

    // ── schema interpreter ──

    #[test]
    fn pinned_schema_compiles_and_matches_the_lock() {
        let s = pinned();
        assert_eq!(
            s.id,
            "https://docs.oasis-open.org/openeox/eox-core/v1.0/schema/core.json"
        );
        assert_eq!(
            s.required,
            [
                "$schema",
                "end_of_life",
                "end_of_security_support",
                "last_updated"
            ]
        );
        assert_eq!(
            s.props.get("end_of_sales"),
            Some(&Rule::Timestamp { tba: "tba".into() })
        );
        assert_eq!(s.props.get("last_updated"), Some(&Rule::DateTime));
    }

    #[test]
    fn schema_outside_the_subset_is_refused_not_ignored() {
        let core =
            std::fs::read_to_string(repo("supply-chain/policy/eox/schema/core.json")).unwrap();
        let mut v: Value = serde_json::from_str(&core).unwrap();
        compile_schema(&v, None).expect("baseline compiles");
        // a keyword this validator does not implement
        v["properties"]["end_of_life"]["pattern"] = Value::String("x".into());
        let e = compile_schema(&v, None).unwrap_err();
        assert!(e.contains("`pattern`") && e.contains("UNEVALUATED"), "{e}");
        // an open object
        let mut v2: Value = serde_json::from_str(&core).unwrap();
        v2.as_object_mut().unwrap().remove("unevaluatedProperties");
        assert!(compile_schema(&v2, None).unwrap_err().contains("close"));
        // a meta-schema that makes format annotation-only
        let v3: Value = serde_json::from_str(&core).unwrap();
        let meta = json(
            r#"{"$id":"https://docs.oasis-open.org/openeox/eox-core/v1.0/schema/meta.json","$vocabulary":{}}"#,
        );
        assert!(
            compile_schema(&v3, Some(&meta))
                .unwrap_err()
                .contains("format-assertion")
        );
    }

    #[test]
    fn tampered_schema_copy_fails_the_lock_and_nothing_is_evaluated() {
        let dir = std::env::temp_dir().join(format!("eox-lock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("schema")).unwrap();
        let core = std::fs::read(repo("supply-chain/policy/eox/schema/core.json")).unwrap();
        let mut tampered = core.clone();
        tampered.extend_from_slice(b"\n");
        std::fs::write(dir.join("schema/core.json"), &tampered).unwrap();
        std::fs::write(
            dir.join("SCHEMA.lock"),
            format!(
                "core.json https://x/core.json {}\n",
                crate::sha256::sha256_hex(&core)
            ),
        )
        .unwrap();
        let e = load_pinned_schema(&dir.join("SCHEMA.lock")).unwrap_err();
        assert!(e.contains("does not match SCHEMA.lock"), "{e}");
        std::fs::write(dir.join("schema/core.json"), &core).unwrap();
        load_pinned_schema(&dir.join("SCHEMA.lock")).expect("matching digest compiles");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── the TC's own vectors ──

    #[test]
    fn oasis_examples_all_conform() {
        let s = pinned();
        let dir = repo("xtask/testdata/openeox/examples");
        let mut n = 0;
        for e in std::fs::read_dir(&dir).unwrap() {
            let p = e.unwrap().path();
            if p.extension().is_some_and(|x| x == "json") {
                let d: Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
                let c = s.check(&d);
                assert!(c.errors.is_empty(), "{}: {:?}", p.display(), c.errors);
                n += 1;
            }
        }
        assert_eq!(n, 7, "all seven published examples present");
    }

    #[test]
    fn oasis_testcases_manifest_verdicts_are_reproduced() {
        let s = pinned();
        let base = repo("xtask/testdata/openeox/validator-data");
        let manifest: Value =
            serde_json::from_str(&std::fs::read_to_string(base.join("testcases.json")).unwrap())
                .unwrap();
        let mut checked = 0;
        for t in manifest["tests"].as_array().unwrap() {
            let id = t["id"].as_str().unwrap(); // e.g. "7.1.1"
            let group = t["group"].as_str().unwrap();
            let tag = format!("§{id}");
            for (bucket, expect_failure) in [("failures", true), ("valid", false)] {
                for case in t[bucket].as_array().unwrap() {
                    let name = case["name"].as_str().unwrap();
                    let doc: Value =
                        serde_json::from_str(&std::fs::read_to_string(base.join(name)).unwrap())
                            .unwrap();
                    let c = s.check(&doc);
                    let schema_valid = case["valid"].as_bool().unwrap();
                    match group {
                        "mandatory" => {
                            assert_eq!(
                                c.errors.is_empty(),
                                !expect_failure,
                                "{name}: errors {:?}",
                                c.errors
                            );
                            assert_eq!(
                                schema_valid, !expect_failure,
                                "{name}: manifest consistency"
                            );
                            if expect_failure && id != "7.1.2" {
                                assert!(
                                    c.errors.iter().any(|e| e.starts_with(&tag)),
                                    "{name}: {:?}",
                                    c.errors
                                );
                            }
                            if expect_failure && id == "7.1.2" {
                                assert!(
                                    c.errors.iter().any(|e| e.contains("§7.1.2")),
                                    "{name}: {:?}",
                                    c.errors
                                );
                            }
                        }
                        "recommended" => {
                            assert!(
                                c.errors.is_empty() && schema_valid,
                                "{name}: {:?}",
                                c.errors
                            );
                            assert_eq!(
                                c.warnings.iter().any(|w| w.starts_with(&tag)),
                                expect_failure,
                                "{name}: {:?}",
                                c.warnings
                            );
                        }
                        "informative" => {
                            assert!(
                                c.errors.is_empty() && schema_valid,
                                "{name}: {:?}",
                                c.errors
                            );
                            assert_eq!(
                                c.notices.iter().any(|w| w.starts_with(&tag)),
                                expect_failure,
                                "{name}: {:?}",
                                c.notices
                            );
                        }
                        other => panic!("unknown group {other}"),
                    }
                    checked += 1;
                }
            }
        }
        let on_disk = ["mandatory", "recommended", "informative"]
            .iter()
            .map(|d| std::fs::read_dir(base.join(d)).unwrap().count())
            .sum::<usize>();
        assert_eq!(checked, 41, "every vector in the TC manifest was exercised");
        assert_eq!(
            on_disk, checked,
            "every vendored vector is named by the manifest (TC check_testcases.sh)"
        );
    }

    // ── records + workflows: the committed posture ──

    const TODAY: &str = "2026-11-11";

    fn committed_records() -> Records {
        let v: Value = serde_json::from_str(
            &std::fs::read_to_string(repo("supply-chain/policy/eox/records.json")).unwrap(),
        )
        .unwrap();
        parse_records(&v).expect("committed records parse")
    }

    #[test]
    fn committed_records_and_workflows_evaluate_clean_at_the_pin_date() {
        let s = pinned();
        let recs = committed_records();
        let (jobs, scan_errors) = scan_workflows_dir(&repo(".github/workflows")).unwrap();
        assert!(scan_errors.is_empty(), "{scan_errors:?}");
        let channel = toolchain_channel(&repo("tools/TOOLCHAIN.lock")).unwrap();
        let r = evaluate(
            &s,
            &recs,
            &jobs,
            Some(&channel),
            parse_date(TODAY).unwrap(),
            None,
        );
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        assert!(
            r.warnings.is_empty(),
            "records must not carry §7.2 findings: {:?}",
            r.warnings
        );
        let mut labels: BTreeSet<&str> = BTreeSet::new();
        for j in &jobs {
            labels.extend(j.labels.iter().map(String::as_str));
        }
        assert!(
            labels.contains("windows-2025") && labels.contains("ubuntu-26.04"),
            "{labels:?}"
        );
        // the candidate-build expression resolved through its runner= tokens
        assert!(
            jobs.iter().any(|j| j.file == "candidate-build.yml"
                && j.job == "build"
                && j.labels.len() == 2),
            "{jobs:#?}"
        );
    }

    #[test]
    fn committed_records_cross_check_against_a_live_shaped_response() {
        // Shape of endoflife.date v1 as observed 2026-11-11; a drift in OUR record against it
        // must fail, null must pair with tba.
        let s = pinned();
        let recs = committed_records();
        let gha = json(
            r#"{"result":{"releases":[
              {"name":"ubuntu-22.04","releaseDate":"2022-08-09","eoasFrom":"2026-09-17","eolFrom":"2027-04-17"},
              {"name":"ubuntu-24.04","releaseDate":"2024-05-14","eoasFrom":null,"eolFrom":null},
              {"name":"ubuntu-26.04","releaseDate":"2026-09-17","eoasFrom":null,"eolFrom":null},
              {"name":"windows-2025","releaseDate":"2025-04-10","eoasFrom":null,"eolFrom":null}]}}"#,
        );
        let ubuntu = json(
            r#"{"result":{"releases":[
              {"name":"22.04","releaseDate":"2022-04-21","eolFrom":"2027-06-01","eoesFrom":"2032-04-21"},
              {"name":"24.04","releaseDate":"2024-04-25","eolFrom":"2029-05-31","eoesFrom":"2034-04-25"},
              {"name":"26.04","releaseDate":"2026-04-23","eolFrom":"2031-05-29","eoesFrom":"2036-04-23"}]}}"#,
        );
        let mut eol = EndOfLife::new();
        eol.insert("github-actions-runner-images".into(), gha.clone());
        eol.insert("ubuntu".into(), ubuntu);
        let r = evaluate(&s, &recs, &[], None, parse_date(TODAY).unwrap(), Some(&eol));
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        // the announcement lands upstream, our record still says tba -> FAIL (the 22.04 miss)
        let mut moved = gha.clone();
        moved["result"]["releases"][1]["eoasFrom"] = Value::String("2028-06-01".into());
        eol.insert("github-actions-runner-images".into(), moved);
        let r = evaluate(&s, &recs, &[], None, parse_date(TODAY).unwrap(), Some(&eol));
        assert!(
            r.errors.iter().any(|e| e.contains("ubuntu-24.04")
                && e.contains("eoasFrom")
                && e.contains("tba vs endoflife.date 2028-06-01")),
            "{:?}",
            r.errors
        );
        // an unfetched product is UNKNOWN: a warning that names it, never silence
        eol.remove("ubuntu");
        let r = evaluate(&s, &recs, &[], None, parse_date(TODAY).unwrap(), Some(&eol));
        assert!(
            r.warnings
                .iter()
                .any(|w| w.contains("UNKNOWN") && w.contains("`ubuntu`")),
            "{:?}",
            r.warnings
        );
    }

    // ── windows and scan rules on synthetic inputs ──

    fn recs_with(eoas: &str, projection: Option<&str>) -> Records {
        let proj = projection
            .map(|d| format!(r#","projection":{{"end_of_active_support":"{d}","basis":"test"}}"#))
            .unwrap_or_default();
        let v = json(&format!(
            r#"{{"schema":"hp-thermal/eox-records/v1","thresholds_days":{{"fail":120,"warn":180}},
               "products":[{{"id":"github-actions-runner-images/img","kind":"runner-image","runs_on":["img"],
                 "eox":{{"$schema":"https://docs.oasis-open.org/openeox/eox-core/v1.0/schema/core.json",
                         "general_availability":"2024-01-01T00:00:00Z","end_of_security_support":"tba","end_of_life":"tba","last_updated":"2026-01-01T00:00:00Z"}},
                 "end_of_active_support":"{eoas}"{proj}}}]}}"#
        ));
        parse_records(&v).unwrap()
    }
    fn job(label: &str) -> JobRef {
        JobRef {
            file: "w.yml".into(),
            job: "j".into(),
            labels: vec![label.into()],
            text: String::new(),
        }
    }

    #[test]
    fn deprecation_windows_fail_warn_and_pass_and_projections_are_labelled() {
        let s = pinned();
        let today = parse_date("2027-01-01").unwrap();
        let at = |days: i64| fmt_days(today + days);
        let r = evaluate(
            &s,
            &recs_with(&at(119), None),
            &[job("img")],
            None,
            today,
            None,
        );
        assert!(
            r.errors
                .iter()
                .any(|e| e.contains("in 119 days") && !e.contains("PROJECTED")),
            "{r:?}"
        );
        let r = evaluate(
            &s,
            &recs_with(&at(120), None),
            &[job("img")],
            None,
            today,
            None,
        );
        assert!(
            r.errors.is_empty() && r.warnings.iter().any(|w| w.contains("in 120 days")),
            "{r:?}"
        );
        let r = evaluate(
            &s,
            &recs_with(&at(180), None),
            &[job("img")],
            None,
            today,
            None,
        );
        assert!(r.errors.is_empty() && r.warnings.is_empty(), "{r:?}");
        let r = evaluate(
            &s,
            &recs_with(&at(-3), None),
            &[job("img")],
            None,
            today,
            None,
        );
        assert!(r.errors.iter().any(|e| e.contains("3 days ago")), "{r:?}");
        // projected inside the warn window: a finding that says so; inside fail: fails
        let r = evaluate(
            &s,
            &recs_with("tba", Some(&at(150))),
            &[job("img")],
            None,
            today,
            None,
        );
        assert!(
            r.errors.is_empty() && r.warnings.iter().any(|w| w.contains("PROJECTED")),
            "{r:?}"
        );
        let r = evaluate(
            &s,
            &recs_with("tba", Some(&at(100))),
            &[job("img")],
            None,
            today,
            None,
        );
        assert!(r.errors.iter().any(|e| e.contains("PROJECTED")), "{r:?}");
        // nothing announced or projected: a notice, and the label is still tracked
        let r = evaluate(
            &s,
            &recs_with("tba", None),
            &[job("img")],
            None,
            today,
            None,
        );
        assert!(
            r.errors.is_empty()
                && r.notices
                    .iter()
                    .any(|n| n.contains("no announced or projected")),
            "{r:?}"
        );
        // an unused product enforces nothing
        let r = evaluate(&s, &recs_with(&at(-3), None), &[], None, today, None);
        assert!(r.errors.is_empty(), "{r:?}");
        // a used label with no record is the failure this exists for
        let r = evaluate(
            &s,
            &recs_with("tba", None),
            &[job("other-2030")],
            None,
            today,
            None,
        );
        assert!(
            r.errors
                .iter()
                .any(|e| e.contains("`other-2030`") && e.contains("no EoX record")),
            "{r:?}"
        );
        // toolchain pin must be tracked
        let r = evaluate(
            &s,
            &recs_with("tba", None),
            &[],
            Some("nightly-2099-01-01"),
            today,
            None,
        );
        assert!(
            r.errors
                .iter()
                .any(|e| e.contains("rust-toolchain/nightly-2099-01-01")),
            "{r:?}"
        );
    }

    #[test]
    fn records_shell_is_closed_and_projection_needs_a_basis() {
        let base = r#"{"schema":"hp-thermal/eox-records/v1","thresholds_days":{"fail":120,"warn":180},"products":[%P%]}"#;
        let ok = r#"{"id":"a/b","kind":"runner-image","runs_on":["b"],"eox":{},"end_of_active_support":"tba"}"#;
        parse_records(&json(&base.replace("%P%", ok))).unwrap();
        let bad_key = ok.replace(r#""kind""#, r#""deprecated_at":"x","kind""#);
        assert!(
            parse_records(&json(&base.replace("%P%", &bad_key)))
                .unwrap_err()
                .contains("deprecated_at")
        );
        let no_eoas = r#"{"id":"a/b","kind":"runner-image","runs_on":["b"],"eox":{}}"#;
        assert!(
            parse_records(&json(&base.replace("%P%", no_eoas)))
                .unwrap_err()
                .contains("end_of_active_support")
        );
        let no_basis = r#"{"id":"a/b","kind":"runner-image","runs_on":["b"],"eox":{},"end_of_active_support":"tba","projection":{"end_of_active_support":"2030-01-01"}}"#;
        assert!(
            parse_records(&json(&base.replace("%P%", no_basis)))
                .unwrap_err()
                .contains("basis")
        );
        let announced_and_projected = r#"{"id":"a/b","kind":"runner-image","runs_on":["b"],"eox":{},"end_of_active_support":"2029-01-01","projection":{"end_of_active_support":"2030-01-01","basis":"x"}}"#;
        assert!(
            parse_records(&json(&base.replace("%P%", announced_and_projected)))
                .unwrap_err()
                .contains("drop the projection")
        );
        let os_with_label = r#"{"id":"u/1","kind":"os","runs_on":["x"],"eox":{}}"#;
        assert!(
            parse_records(&json(&base.replace("%P%", os_with_label)))
                .unwrap_err()
                .contains("runner-image products")
        );
        assert!(
            parse_records(&json(&base.replace("%P%", "")))
                .unwrap_err()
                .contains("empty")
        );
    }

    #[test]
    fn workflow_scan_resolves_literals_and_expressions_and_refuses_floating_or_opaque() {
        let wf = "name: x\non: push\njobs:\n  a:\n    runs-on: ubuntu-24.04   # comment\n    steps: []\n  b:\n    runs-on: \"windows-2025\"\n  c:\n    runs-on: ${{ needs.r.outputs.runner }}\n    steps:\n      - run: |\n          case x in\n            w) runner=windows-2025 ;;\n            l) runner=ubuntu-26.04 ;;\n          esac\n          echo \"runner=$runner\" >> \"$GITHUB_OUTPUT\"\n";
        let (jobs, errs) = scan_workflow("w.yml", wf);
        assert!(errs.is_empty(), "{errs:?}");
        assert_eq!(
            jobs.iter()
                .map(|j| (j.job.as_str(), j.labels.clone()))
                .collect::<Vec<_>>(),
            [
                ("a", vec!["ubuntu-24.04".to_string()]),
                ("b", vec!["windows-2025".to_string()]),
                (
                    "c",
                    vec!["ubuntu-26.04".to_string(), "windows-2025".to_string()]
                ),
            ]
        );
        let (_, errs) = scan_workflow("f.yml", "jobs:\n  a:\n    runs-on: ubuntu-latest\n");
        assert!(errs.iter().any(|e| e.contains("floating")), "{errs:?}");
        let (_, errs) = scan_workflow("m.yml", "jobs:\n  a:\n    runs-on: ${{ matrix.os }}\n");
        assert!(errs.iter().any(|e| e.contains("untrackable")), "{errs:?}");
        let (_, errs) = scan_workflow("l.yml", "jobs:\n  a:\n    runs-on: [self-hosted, linux]\n");
        assert!(
            errs.iter().any(|e| e.contains("not a single label")),
            "{errs:?}"
        );
        // a job with no runs-on (reusable workflow call) is fine and has no labels
        let (jobs, errs) = scan_workflow(
            "r.yml",
            "jobs:\n  a:\n    uses: o/r/.github/workflows/x.yml@sha\n",
        );
        assert!(errs.is_empty() && jobs[0].labels.is_empty());
    }

    #[test]
    fn one_image_rule_fails_on_split_consumers_and_ignores_prose() {
        let s = pinned();
        let mut recs = recs_with("tba", None);
        recs.one_image.push(OneImageRule {
            mentions: vec!["cargo-acl".into()],
            label_prefix: "ubuntu-".into(),
        });
        let mk = |file: &str, label: &str, text: &str| JobRef {
            file: file.into(),
            job: "j".into(),
            labels: vec![label.into()],
            text: text.into(),
        };
        let jobs = [
            mk("a.yml", "ubuntu-26.04", "run: cargo-acl x\n"),
            mk("b.yml", "ubuntu-24.04", "run: cargo-acl y\n"),
            mk("c.yml", "windows-2025", "run: cargo-acl z\n"),
        ];
        let r = evaluate(
            &s,
            &recs,
            &jobs,
            None,
            parse_date("2027-01-01").unwrap(),
            None,
        );
        assert!(
            r.errors
                .iter()
                .any(|e| e.contains("one-image rule") && e.contains("2 different")),
            "{r:?}"
        );
        // comments are stripped by the scanner, so a job that only talks about the tool is not a consumer
        let (jobs, _) = scan_workflow(
            "p.yml",
            "jobs:\n  a:\n    # cargo-acl is Linux-only\n    runs-on: ubuntu-24.04\n  b:\n    runs-on: ubuntu-26.04\n    steps:\n      - run: cargo-acl\n",
        );
        let r = evaluate(
            &s,
            &recs,
            &jobs,
            None,
            parse_date("2027-01-01").unwrap(),
            None,
        );
        assert!(!r.errors.iter().any(|e| e.contains("one-image")), "{r:?}");
    }
}
