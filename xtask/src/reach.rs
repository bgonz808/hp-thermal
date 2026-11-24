//! `cargo xtask reach emit|check` — the reachability record a `not_affected` vuln statement is
//! bound to (#520).
//!
//! A statement that the vulnerable code of advisory A in package P@V is not reached by tool T at
//! digest D rests on a search: every file of the source the producer compiled that could call
//! into P is searched for the names the advisory lists as affected. The record is that search,
//! as SARIF 2.1.0, written beside the digest's evidence and named so it is never edited:
//! `<record dir>/reach/<A>-<h12>.sarif`, `h12` the first 12 hex of the sha256 over the emitter
//! format, A, P, V and the advisory's affected functions. A changed function list or emitter is
//! a new file; the old one stays as history.
//!
//! Inputs are the checkout's, never the record's: the frozen lock `tools/locks/<T>.lock`, the
//! TOOLS.lock repo and rev of D, `tools/patches/<T>/*.patch` applied in name order as the producer
//! applies them, and the advisory's affected functions from the scan that asks. The source is
//! read from git objects (a tree built with `git read-tree` + `git apply --cached`, no working
//! tree, so no ignore rules or line-ending filters apply) and from `.crate` archives whose sha256
//! equals the lock checksum, parsed in memory and never extracted. Nothing fetched is built or run.
//!
//! Universe: the patched tool tree (the lock's path packages live there; the whole tree is a
//! superset) and every registry package in the reverse-dependency closure of P@V in the lock, P
//! included, across every dependency kind (lock edges carry no kind). A lock package from any
//! other source fails the record. Of each package, the Rust files are searched except its
//! `tests/`, `benches/` and `examples/` directories (cargo compiles those only as their own
//! targets), plus its `Cargo.toml`.
//!
//! Two rules per record: `<A>`, every occurrence of an affected function's name; and
//! `<A>/crate`, every reference to P from another package (a `p::` path, `extern crate p`, or
//! P's name in a manifest). The second is the short list the claim usually rests on: which
//! files can name P at all.
//!
//! Disclosed limits: a text search is not a call graph. It misses calls through trait dispatch,
//! generic or trait-object code in crates that do not depend on P, macro- and build.rs-generated
//! code, symbol renames and std. An advisory that lists no functions yields a record of the
//! dependent set only.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{Value, json};

/// Emitter format. Any change to what a record contains or how it is laid out takes the next
/// number: a record is reproduced byte for byte, and committed records are never edited.
pub(crate) const FORMAT: &str = "reach-v1";

/// Largest total a `.crate` may expand to, and largest single file.
const MAX_CRATE: usize = 256 << 20;
/// Bytes of a hit line kept as its snippet.
const SNIPPET: usize = 200;

// ---------- .crate archives (gzip + tar), in memory ----------

fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (i, e) in table.iter_mut().enumerate() {
        let mut c = i as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
        *e = c;
    }
    let mut c = !0u32;
    for &b in data {
        c = table[((c ^ b as u32) & 0xff) as usize] ^ (c >> 8);
    }
    !c
}

/// One gzip member's payload. Header flags are honored, the CRC32 and length are checked, and
/// anything after the member is refused.
pub(crate) fn gunzip(gz: &[u8]) -> Result<Vec<u8>, String> {
    if gz.len() < 18 || gz[0] != 0x1f || gz[1] != 0x8b || gz[2] != 8 {
        return Err("gzip: not a deflate gzip member".into());
    }
    let flg = gz[3];
    if flg & 0xe0 != 0 {
        return Err("gzip: reserved header flags set".into());
    }
    let mut i = 10;
    let need = |i: usize, n: usize| -> Result<(), String> {
        if i + n > gz.len() {
            Err("gzip: truncated header".into())
        } else {
            Ok(())
        }
    };
    if flg & 4 != 0 {
        need(i, 2)?;
        let xlen = u16::from_le_bytes([gz[i], gz[i + 1]]) as usize;
        need(i + 2, xlen)?;
        i += 2 + xlen;
    }
    for bit in [8u8, 16] {
        if flg & bit != 0 {
            let end = gz[i..]
                .iter()
                .position(|&b| b == 0)
                .ok_or("gzip: unterminated name or comment")?;
            i += end + 1;
        }
    }
    if flg & 2 != 0 {
        need(i, 2)?;
        i += 2;
    }
    if i + 8 > gz.len() {
        return Err("gzip: truncated".into());
    }
    let body = &gz[i..gz.len() - 8];
    let out = miniz_oxide::inflate::decompress_to_vec_with_limit(body, MAX_CRATE)
        .map_err(|e| format!("gzip: inflate: {e:?}"))?;
    let t = &gz[gz.len() - 8..];
    let crc = u32::from_le_bytes([t[0], t[1], t[2], t[3]]);
    let isize = u32::from_le_bytes([t[4], t[5], t[6], t[7]]);
    if crc32(&out) != crc || out.len() as u32 != isize {
        return Err("gzip: CRC32 or length mismatch (a second member or a corrupt stream)".into());
    }
    Ok(out)
}

fn octal(field: &[u8]) -> Result<usize, String> {
    let s: String = field
        .iter()
        .take_while(|&&b| b != 0)
        .map(|&b| b as char)
        .collect();
    let s = s.trim();
    if s.is_empty() {
        return Ok(0);
    }
    usize::from_str_radix(s, 8).map_err(|_| format!("tar: bad octal field `{s}`"))
}

fn cstr(field: &[u8]) -> Result<String, String> {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    String::from_utf8(field[..end].to_vec()).map_err(|_| "tar: non-UTF-8 name".to_string())
}

fn clean_path(p: &str) -> Result<String, String> {
    let p = p.trim_end_matches('/');
    if p.is_empty()
        || p.starts_with('/')
        || p.contains('\\')
        || p.split('/').any(|c| c.is_empty() || c == "." || c == "..")
    {
        return Err(format!("archive path `{p}` is not a plain relative path"));
    }
    Ok(p.to_string())
}

/// Regular files of a tar stream by path. Directories are skipped; pax (`x`, `g`) and GNU long
/// name (`L`) headers are honored; any other entry type, a duplicate path, a bad header checksum
/// or a size past the limit fails.
pub(crate) fn untar(tar: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let mut out = BTreeMap::new();
    let mut total = 0usize;
    let mut next_name: Option<String> = None;
    let mut i = 0;
    while i + 512 <= tar.len() {
        let h = &tar[i..i + 512];
        if h.iter().all(|&b| b == 0) {
            return Ok(out);
        }
        let sum: u32 = h
            .iter()
            .enumerate()
            .map(|(k, &b)| {
                if (148..156).contains(&k) {
                    32
                } else {
                    b as u32
                }
            })
            .sum();
        if octal(&h[148..156])? as u32 != sum {
            return Err(format!("tar: header checksum mismatch at offset {i}"));
        }
        if h[124] & 0x80 != 0 {
            return Err("tar: base-256 size field".into());
        }
        let size = octal(&h[124..136])?;
        let data_start = i + 512;
        let data_end = data_start
            .checked_add(size)
            .filter(|&e| e <= tar.len())
            .ok_or("tar: entry runs past the archive")?;
        let data = &tar[data_start..data_end];
        let name = {
            let n = cstr(&h[0..100])?;
            let prefix = if &h[257..262] == b"ustar" {
                cstr(&h[345..500])?
            } else {
                String::new()
            };
            if prefix.is_empty() {
                n
            } else {
                format!("{prefix}/{n}")
            }
        };
        match h[156] {
            b'0' | 0 => {
                let path = clean_path(&next_name.take().unwrap_or(name))?;
                total += size;
                if total > MAX_CRATE {
                    return Err(format!("tar: expands past {MAX_CRATE} bytes"));
                }
                if out.insert(path.clone(), data.to_vec()).is_some() {
                    return Err(format!("tar: `{path}` appears twice"));
                }
            }
            b'5' => {
                next_name = None;
            }
            b'L' => {
                next_name = Some(cstr(data)?);
            }
            b'x' => {
                for rec in pax_records(data)? {
                    match rec.0.as_str() {
                        "path" => next_name = Some(rec.1),
                        "size" | "linkpath" => {
                            return Err(format!("tar: pax `{}` override", rec.0));
                        }
                        _ => {}
                    }
                }
            }
            b'g' => {}
            t => return Err(format!("tar: entry type `{}` refused", t as char)),
        }
        i = data_start + size.div_ceil(512) * 512;
    }
    Err("tar: no end-of-archive marker".into())
}

fn pax_records(data: &[u8]) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    let mut rest = data;
    while !rest.is_empty() && rest[0] != 0 {
        let sp = rest
            .iter()
            .position(|&b| b == b' ')
            .ok_or("tar: bad pax record")?;
        let len: usize = std::str::from_utf8(&rest[..sp])
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or("tar: bad pax record length")?;
        if len <= sp + 1 || len > rest.len() || rest[len - 1] != b'\n' {
            return Err("tar: bad pax record".into());
        }
        let kv = std::str::from_utf8(&rest[sp + 1..len - 1]).map_err(|_| "tar: non-UTF-8 pax")?;
        let (k, v) = kv.split_once('=').ok_or("tar: pax record without `=`")?;
        out.push((k.to_string(), v.to_string()));
        rest = &rest[len..];
    }
    Ok(out)
}

/// The regular files of a `.crate`, by path.
pub(crate) fn crate_files(gz: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, String> {
    untar(&gunzip(gz)?)
}

// ---------- the lock graph ----------

/// The registry source of crates.io as a lock writes it.
pub(crate) const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";

/// Resolve a lock dependency string (`name`, `name version`, `name version (source)`) to the one
/// package it names.
fn resolve_dep(
    pkgs: &crate::evidence_rev::Pkgs,
    dep: &str,
) -> Result<crate::evidence_rev::Key, String> {
    let mut it = dep.splitn(3, ' ');
    let name = it.next().unwrap_or_default();
    let version = it.next();
    let source = it
        .next()
        .map(|s| s.trim_start_matches('(').trim_end_matches(')'));
    let hits: Vec<_> = pkgs
        .iter()
        .filter(|((n, v), p)| {
            n == name
                && version.is_none_or(|w| w == v)
                && source.is_none_or(|s| p.source.as_deref() == Some(s))
        })
        .map(|(k, _)| k.clone())
        .collect();
    match hits.as_slice() {
        [one] => Ok(one.clone()),
        [] => Err(format!("lock dependency `{dep}` names no package")),
        _ => Err(format!("lock dependency `{dep}` is ambiguous")),
    }
}

/// P@V and every package that depends on it, directly or transitively, in the lock.
pub(crate) fn reverse_closure(
    pkgs: &crate::evidence_rev::Pkgs,
    name: &str,
    version: &str,
) -> Result<BTreeSet<crate::evidence_rev::Key>, String> {
    let root = (name.to_string(), version.to_string());
    if !pkgs.contains_key(&root) {
        return Err(format!("{name}@{version} is not in the lock"));
    }
    let mut dependents: BTreeMap<crate::evidence_rev::Key, BTreeSet<crate::evidence_rev::Key>> =
        BTreeMap::new();
    for (k, p) in pkgs {
        for d in &p.deps {
            dependents
                .entry(resolve_dep(pkgs, d)?)
                .or_default()
                .insert(k.clone());
        }
    }
    let mut seen = BTreeSet::from([root.clone()]);
    let mut todo = vec![root];
    while let Some(k) = todo.pop() {
        for d in dependents.get(&k).into_iter().flatten() {
            if seen.insert(d.clone()) {
                todo.push(d.clone());
            }
        }
    }
    Ok(seen)
}

// ---------- the query ----------

/// The advisory's affected functions for this instance, from a `cargo audit --json` report:
/// path -> version requirements, as the advisory lists them. Absent means none listed.
pub(crate) fn affected_functions(
    audit: &serde_json::Value,
    id: &str,
    package: &str,
    version: &str,
) -> Result<BTreeMap<String, Vec<String>>, String> {
    let mut entries = Vec::new();
    if let Some(l) = audit
        .pointer("/vulnerabilities/list")
        .and_then(|v| v.as_array())
    {
        entries.extend(l.iter());
    }
    if let Some(w) = audit.get("warnings").and_then(|v| v.as_object()) {
        for arr in w.values().filter_map(|v| v.as_array()) {
            entries.extend(arr.iter());
        }
    }
    let e = entries
        .into_iter()
        .find(|e| {
            e.pointer("/advisory/id").and_then(|v| v.as_str()) == Some(id)
                && e.pointer("/package/name").and_then(|v| v.as_str()) == Some(package)
                && e.pointer("/package/version").and_then(|v| v.as_str()) == Some(version)
        })
        .ok_or_else(|| format!("{id} {package} {version} is not in the scan"))?;
    let mut out = BTreeMap::new();
    let f = &e["affected"]["functions"];
    if let Some(m) = f.as_object() {
        for (path, reqs) in m {
            let reqs = reqs
                .as_array()
                .ok_or_else(|| format!("{id}: affected function `{path}` without a list"))?
                .iter()
                .map(|r| r.as_str().map(str::to_string))
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| format!("{id}: affected function `{path}`: non-string range"))?;
            out.insert(path.clone(), reqs);
        }
    } else if !f.is_null() {
        return Err(format!("{id}: affected.functions is not an object"));
    }
    Ok(out)
}

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Search tokens: the last segment of each affected path, sorted and deduplicated. A token must
/// be a non-empty ASCII identifier.
pub(crate) fn query_tokens(
    functions: &BTreeMap<String, Vec<String>>,
) -> Result<Vec<String>, String> {
    let mut out = BTreeSet::new();
    for path in functions.keys() {
        let last = path.rsplit("::").next().unwrap_or_default();
        if last.is_empty() || !last.bytes().all(is_ident) {
            return Err(format!(
                "affected function `{path}`: last segment is not an identifier"
            ));
        }
        out.insert(last.to_string());
    }
    Ok(out.into_iter().collect())
}

/// `RUSTSEC-YYYY-NNNN`.
pub(crate) fn is_rustsec_id(id: &str) -> bool {
    let b = id.as_bytes();
    b.len() == 17
        && id.starts_with("RUSTSEC-")
        && b[8..12].iter().all(u8::is_ascii_digit)
        && b[12] == b'-'
        && b[13..].iter().all(u8::is_ascii_digit)
}

/// The record's file name for this instance and query.
pub(crate) fn record_name(
    id: &str,
    package: &str,
    version: &str,
    functions: &BTreeMap<String, Vec<String>>,
) -> Result<String, String> {
    if !is_rustsec_id(id) {
        return Err(format!(
            "`{id}` is not a RustSec advisory id: no reachability record"
        ));
    }
    let key = serde_json::json!([FORMAT, id, package, version, functions]).to_string();
    let h = crate::sha256::sha256_hex(key.as_bytes());
    Ok(format!("{id}-{}.sarif", &h[..12]))
}

/// One occurrence of a token.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Hit {
    /// 1-based line.
    pub(crate) line: usize,
    /// 1-based byte column within the line.
    pub(crate) col: usize,
    pub(crate) token: String,
    /// The line's first SNIPPET bytes, lossy UTF-8, without its line ending.
    pub(crate) snippet: String,
}

/// Every occurrence of any token, bounded by non-identifier ASCII bytes (or the ends of the
/// line) on both sides.
pub(crate) fn token_hits(text: &[u8], tokens: &[String]) -> Vec<Hit> {
    hits_where(text, tokens, is_ident, |_, _, _| true)
}

/// Rust references to crate `ident` by path: `ident::...` or `extern crate ident`.
pub(crate) fn crate_path_hits(text: &[u8], ident: &str) -> Vec<Hit> {
    hits_where(text, &[ident.to_string()], is_ident, |line, at, len| {
        let before = &line[..at];
        // `a::ident::` is a module of `a` (`crate::`, `self::`, `remote::`), not the crate; a
        // leading `::ident::` is the crate.
        let segment = before
            .strip_suffix(b"::")
            .is_some_and(|b| b.last().is_some_and(|&c| is_ident(c) || c == b'>'));
        (line[at + len..].starts_with(b"::") && !segment)
            || before.trim_ascii_end().ends_with(b"extern crate")
    })
}

/// Occurrences of package `name` in a manifest, where `-` also bounds a name.
pub(crate) fn manifest_hits(text: &[u8], name: &str) -> Vec<Hit> {
    hits_where(
        text,
        &[name.to_string()],
        |b| is_ident(b) || b == b'-',
        |_, _, _| true,
    )
}

fn hits_where(
    text: &[u8],
    tokens: &[String],
    inner: fn(u8) -> bool,
    accept: impl Fn(&[u8], usize, usize) -> bool,
) -> Vec<Hit> {
    let mut out = Vec::new();
    if tokens.is_empty() {
        return out;
    }
    for (n, line) in text.split(|&b| b == b'\n').enumerate() {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        for t in tokens {
            let t = t.as_bytes();
            if t.is_empty() || t.len() > line.len() {
                continue;
            }
            for at in 0..=line.len() - t.len() {
                if &line[at..at + t.len()] == t
                    && (at == 0 || !inner(line[at - 1]))
                    && line.get(at + t.len()).is_none_or(|&b| !inner(b))
                    && accept(line, at, t.len())
                {
                    out.push(Hit {
                        line: n + 1,
                        col: at + 1,
                        token: String::from_utf8_lossy(t).into_owned(),
                        snippet: String::from_utf8_lossy(&line[..line.len().min(SNIPPET)])
                            .into_owned(),
                    });
                }
            }
        }
    }
    out.sort();
    out
}

// ---------- sources ----------

/// The tool's source as the producer compiles it: the pinned commit with the downstream patches
/// applied, read from git objects.
pub(crate) struct ToolTree {
    pub(crate) commit: String,
    /// The patched tree's id.
    pub(crate) tree: String,
    /// (patch file name, sha256), in application order.
    pub(crate) patches: Vec<(String, String)>,
    /// Blob content by path, for every blob entry of the patched tree.
    pub(crate) files: BTreeMap<String, Vec<u8>>,
    /// Submodule entries: the producer never initializes them, so nothing of theirs is compiled.
    pub(crate) gitlinks: Vec<String>,
}

fn is_hex(s: &str, n: usize) -> bool {
    s.len() == n && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

struct Git {
    dir: PathBuf,
    config: PathBuf,
}

impl Git {
    fn cmd(&self) -> Command {
        let mut c = Command::new("git");
        // No system or user configuration: an ignore file, a filter or an alias of the machine
        // that emits must not change what is read.
        c.arg("-C")
            .arg(&self.dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", &self.config)
            .env("GIT_TERMINAL_PROMPT", "0");
        c
    }
    fn run(&self, args: &[&str]) -> Result<Vec<u8>, String> {
        let out = self
            .cmd()
            .args(args)
            .output()
            .map_err(|e| format!("git {}: {e}", args.join(" ")))?;
        if !out.status.success() {
            return Err(format!(
                "git {}: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(out.stdout)
    }
    /// Blob contents for `oids`, in order, through one `git cat-file --batch`.
    fn blobs(&self, oids: &[String]) -> Result<Vec<Vec<u8>>, String> {
        let mut child = self
            .cmd()
            .args(["cat-file", "--batch"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("git cat-file: {e}"))?;
        let mut stdin = child.stdin.take().ok_or("git cat-file: no stdin")?;
        let input: Vec<u8> = oids
            .iter()
            .flat_map(|o| format!("{o}\n").into_bytes())
            .collect();
        let writer = std::thread::spawn(move || stdin.write_all(&input));
        let mut out = Vec::new();
        child
            .stdout
            .take()
            .ok_or("git cat-file: no stdout")?
            .read_to_end(&mut out)
            .map_err(|e| format!("git cat-file: {e}"))?;
        writer
            .join()
            .map_err(|_| "git cat-file: writer panicked".to_string())?
            .map_err(|e| format!("git cat-file: {e}"))?;
        if !child.wait().map_err(|e| e.to_string())?.success() {
            return Err("git cat-file failed".into());
        }
        let mut res = Vec::with_capacity(oids.len());
        let mut i = 0;
        for oid in oids {
            let nl = out[i..]
                .iter()
                .position(|&b| b == b'\n')
                .ok_or("git cat-file: truncated header")?;
            let header = std::str::from_utf8(&out[i..i + nl]).map_err(|e| e.to_string())?;
            let mut f = header.split(' ');
            let (Some(o), Some("blob"), Some(size)) = (f.next(), f.next(), f.next()) else {
                return Err(format!("git cat-file: `{header}` for {oid}"));
            };
            let size: usize = size
                .parse()
                .map_err(|_| format!("git cat-file: `{header}`"))?;
            if o != oid {
                return Err(format!("git cat-file: asked {oid}, got {o}"));
            }
            let start = i + nl + 1;
            if start + size + 1 > out.len() {
                return Err("git cat-file: truncated blob".into());
            }
            res.push(out[start..start + size].to_vec());
            i = start + size + 1;
        }
        Ok(res)
    }
}

/// Fetch `repo` at `rev`, apply `patches` in order to the index as the producer applies them to
/// its checkout (`git apply --check`, then `git apply`), and read every blob of the result.
pub(crate) fn tool_tree(repo: &str, rev: &str, patches: &[PathBuf]) -> Result<ToolTree, String> {
    if !is_hex(rev, 40) {
        return Err(format!("rev `{rev}` is not a full commit id"));
    }
    if repo.split('/').count() != 2
        || !repo
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/'))
    {
        return Err(format!("repo `{repo}` is not owner/name"));
    }
    let work =
        std::env::temp_dir().join(format!("reach-src-{}-{}", std::process::id(), &rev[..12]));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).map_err(|e| format!("{}: {e}", work.display()))?;
    let config = work.join("empty.gitconfig");
    std::fs::write(&config, "").map_err(|e| e.to_string())?;
    let git = Git {
        dir: work.join("src"),
        config,
    };
    let res = (|| -> Result<ToolTree, String> {
        std::fs::create_dir_all(&git.dir).map_err(|e| e.to_string())?;
        git.run(&["init", "-q"])?;
        git.run(&[
            "fetch",
            "-q",
            "--depth",
            "1",
            &format!("https://github.com/{repo}"),
            rev,
        ])?;
        let head = String::from_utf8_lossy(&git.run(&["rev-parse", "FETCH_HEAD"])?)
            .trim()
            .to_string();
        if head != rev {
            return Err(format!("fetched {head}, pinned {rev}"));
        }
        git.run(&["read-tree", "FETCH_HEAD"])?;
        let mut applied = Vec::new();
        for p in patches {
            let bytes = std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?;
            let abs = std::fs::canonicalize(p).map_err(|e| format!("{}: {e}", p.display()))?;
            let abs = abs.to_string_lossy();
            git.run(&["apply", "--cached", "--check", &abs])
                .map_err(|e| format!("{} no longer applies to {repo}@{rev}: {e}", p.display()))?;
            git.run(&["apply", "--cached", &abs])?;
            let name = p
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            applied.push((name, crate::sha256::sha256_hex(&bytes)));
        }
        let tree = String::from_utf8_lossy(&git.run(&["write-tree"])?)
            .trim()
            .to_string();
        let ls = git.run(&["ls-tree", "-r", "-z", "--full-tree", &tree])?;
        let mut blobs = Vec::new();
        let mut gitlinks = Vec::new();
        for entry in ls.split(|&b| b == 0).filter(|e| !e.is_empty()) {
            let s = std::str::from_utf8(entry).map_err(|_| "git ls-tree: non-UTF-8 path")?;
            let (meta, path) = s.split_once('\t').ok_or("git ls-tree: malformed entry")?;
            let mut m = meta.split(' ');
            match (m.next(), m.next(), m.next()) {
                (Some(_mode), Some("blob"), Some(oid)) => {
                    blobs.push((path.to_string(), oid.to_string()))
                }
                (Some("160000"), Some("commit"), Some(_)) => gitlinks.push(path.to_string()),
                _ => return Err(format!("git ls-tree: unexpected entry `{s}`")),
            }
        }
        let oids: Vec<String> = blobs.iter().map(|(_, o)| o.clone()).collect();
        let contents = git.blobs(&oids)?;
        let files = blobs.into_iter().map(|(p, _)| p).zip(contents).collect();
        Ok(ToolTree {
            commit: head,
            tree,
            patches: applied,
            files,
            gitlinks,
        })
    })();
    let _ = std::fs::remove_dir_all(&work);
    res
}

fn crate_url(name: &str, version: &str) -> String {
    // `+` (build metadata) is reserved in a URL path.
    format!(
        "https://static.crates.io/crates/{name}/{name}-{}.crate",
        version.replace('+', "%2B")
    )
}

/// The `.crate` of name@version from crates.io, refused unless its sha256 is the lock checksum.
/// Verified archives are cached by checksum for the rest of the run.
pub(crate) fn fetch_crate(name: &str, version: &str, checksum: &str) -> Result<Vec<u8>, String> {
    if !is_hex(checksum, 64)
        || name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        || version.is_empty()
        || !version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'))
    {
        return Err(format!(
            "{name}@{version} ({checksum}): not a crates.io package identity"
        ));
    }
    let dir = std::env::temp_dir().join("reach-crates");
    let cached = dir.join(format!("{checksum}.crate"));
    if let Ok(b) = std::fs::read(&cached)
        && crate::sha256::sha256_hex(&b) == checksum
    {
        return Ok(b);
    }
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let tmp = dir.join(format!("{checksum}.{}.part", std::process::id()));
    let st = Command::new("curl")
        .args(["-sSfL", "--proto", "=https", "--tlsv1.2", "-o"])
        .arg(&tmp)
        .arg(crate_url(name, version))
        .status()
        .map_err(|e| format!("curl: {e}"))?;
    if !st.success() {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("curl {}: {st}", crate_url(name, version)));
    }
    let b = std::fs::read(&tmp).map_err(|e| e.to_string())?;
    let got = crate::sha256::sha256_hex(&b);
    if got != checksum {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!(
            "{name}@{version}: sha256 {got} != lock checksum {checksum}"
        ));
    }
    std::fs::rename(&tmp, &cached).map_err(|e| e.to_string())?;
    Ok(b)
}

// ---------- the record ----------

/// What a record is about, and the checkout inputs it is built from.
pub(crate) struct Inputs {
    pub(crate) tool: String,
    pub(crate) digest: String,
    pub(crate) repo: String,
    pub(crate) rev: String,
    pub(crate) lock: String,
    pub(crate) patches: Vec<PathBuf>,
    pub(crate) id: String,
    pub(crate) package: String,
    pub(crate) version: String,
    pub(crate) functions: BTreeMap<String, Vec<String>>,
}

/// A registry package of the universe: name, version, checksum, files.
pub(crate) type CrateSource = (String, String, String, BTreeMap<String, Vec<u8>>);

/// What a file of a package is to the search.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FileKind {
    /// Rust source of the package's library, binaries or build script.
    Rust,
    /// The package's `Cargo.toml`.
    Manifest,
}

/// Package roots of a tree: the directories holding a `Cargo.toml` (`""` for the top).
pub(crate) fn package_roots<'a>(paths: impl Iterator<Item = &'a String>) -> BTreeSet<String> {
    paths
        .filter_map(|p| {
            if p == "Cargo.toml" {
                Some(String::new())
            } else {
                p.strip_suffix("/Cargo.toml").map(str::to_string)
            }
        })
        .collect()
}

/// Whether `path` is searched, given the package roots it may belong to. Rust files count unless
/// they sit in the package's `tests/`, `benches/` or `examples/` directory: cargo builds those
/// only as their own test, bench and example targets, never into a dependent or an installed
/// binary. Data, docs and licenses cannot call code.
pub(crate) fn file_kind(path: &str, roots: &BTreeSet<String>) -> Option<FileKind> {
    let root = roots
        .iter()
        .filter(|r| r.is_empty() || path.starts_with(&format!("{r}/")))
        .max_by_key(|r| r.len())?;
    let rel = if root.is_empty() {
        path
    } else {
        &path[root.len() + 1..]
    };
    if rel == "Cargo.toml" {
        return Some(FileKind::Manifest);
    }
    if !rel.ends_with(".rs") {
        return None;
    }
    match rel.split('/').next() {
        Some("tests" | "benches" | "examples") => None,
        _ => Some(FileKind::Rust),
    }
}

/// The record as SARIF 2.1.0. Pure: every input is passed in.
///
/// Two rules. `<A>`: every occurrence of an affected function's name in searched Rust files,
/// the affected package's own included. `<A>/crate`: every reference to the affected package
/// from another package — a `<ident>::` path or `extern crate <ident>` in Rust, or its name in a
/// `Cargo.toml` (a dependency declaration, a rename's `package = ...`).
pub(crate) fn render(i: &Inputs, tree: &ToolTree, crates: &[CrateSource]) -> Result<Value, String> {
    let tokens = query_tokens(&i.functions)?;
    let ident = i.package.replace('-', "_");
    let crate_rule = format!("{}/crate", i.id);
    let mut artifacts = vec![json!({
        "location": {"uri": format!("https://github.com/{}/tree/{}", i.repo, i.rev)},
        "roles": ["analysisTarget"],
        "properties": {"gitCommit": tree.commit, "gitTree": tree.tree, "files": tree.files.len()},
    })];
    for (n, v, ck, files) in crates {
        artifacts.push(json!({
            "location": {"uri": crate_url(n, v)},
            "hashes": {"sha-256": ck},
            "roles": ["analysisTarget"],
            "properties": {"files": files.len()},
        }));
    }
    let mut results = Vec::new();
    let (mut rust, mut manifests) = (0usize, 0usize);
    let tree_roots = package_roots(tree.files.keys());
    let sources = std::iter::once((&tree.files, tree_roots, false)).chain(crates.iter().map(
        |(n, v, _, files)| {
            let own = n == &i.package && v == &i.version;
            (files, BTreeSet::from([format!("{n}-{v}")]), own)
        },
    ));
    for (parent, (files, roots, own)) in sources.enumerate() {
        for (path, bytes) in files {
            let mut hits: Vec<(&str, Hit)> = Vec::new();
            match file_kind(path, &roots) {
                Some(FileKind::Rust) => {
                    rust += 1;
                    hits.extend(
                        token_hits(bytes, &tokens)
                            .into_iter()
                            .map(|h| (i.id.as_str(), h)),
                    );
                    if !own {
                        hits.extend(
                            crate_path_hits(bytes, &ident)
                                .into_iter()
                                .map(|h| (crate_rule.as_str(), h)),
                        );
                    }
                }
                Some(FileKind::Manifest) => {
                    manifests += 1;
                    if !own {
                        hits.extend(
                            manifest_hits(bytes, &i.package)
                                .into_iter()
                                .map(|h| (crate_rule.as_str(), h)),
                        );
                    }
                }
                None => {}
            }
            if hits.is_empty() {
                continue;
            }
            hits.sort_by(|a, b| (a.1.line, a.1.col, a.0).cmp(&(b.1.line, b.1.col, b.0)));
            let idx = artifacts.len();
            artifacts.push(json!({
                "location": {"uri": path},
                "parentIndex": parent,
                "hashes": {"sha-256": crate::sha256::sha256_hex(bytes)},
            }));
            for (rule, h) in hits {
                results.push(json!({
                    "ruleId": rule,
                    "level": "note",
                    "message": {"text": format!("`{}`", h.token)},
                    "locations": [{"physicalLocation": {
                        "artifactLocation": {"index": idx},
                        "region": {"startLine": h.line, "snippet": {"text": h.snippet}},
                    }}],
                    "properties": {"byteColumn": h.col},
                }));
            }
        }
    }
    let universe: Vec<String> = crates
        .iter()
        .map(|(n, v, _, _)| format!("{n}@{v}"))
        .collect();
    Ok(json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "hp-thermal xtask reach",
                "informationUri": "https://github.com/bgonz808/hp-thermal",
                "rules": [
                    {"id": i.id, "properties": {"functions": i.functions, "tokens": tokens}},
                    {"id": crate_rule, "properties": {"crateIdent": ident, "package": i.package}},
                ],
            }},
            "versionControlProvenance": [{
                "repositoryUri": format!("https://github.com/{}", i.repo),
                "revisionId": i.rev,
            }],
            "artifacts": artifacts,
            "results": results,
            "properties": {
                "format": FORMAT,
                "tool": i.tool,
                "digest": i.digest,
                "advisory": i.id,
                "package": i.package,
                "version": i.version,
                "lockSha256": crate::sha256::sha256_hex(i.lock.as_bytes()),
                "patches": tree.patches.iter().map(|(n, s)| json!({"file": n, "sha256": s})).collect::<Vec<_>>(),
                "gitlinks": tree.gitlinks,
                "registryPackages": universe,
                "searched": {"rustFiles": rust, "manifests": manifests},
            },
        }],
    }))
}

/// The record's bytes: pretty JSON with sorted keys and one trailing newline.
pub(crate) fn serialize(v: &Value) -> String {
    serde_json::to_string_pretty(v).expect("a JSON value serializes") + "\n"
}

/// Build the record from checkout inputs: (file name, bytes).
pub(crate) fn generate(i: &Inputs) -> Result<(String, String), String> {
    let name = record_name(&i.id, &i.package, &i.version, &i.functions)?;
    let (pkgs, _) = crate::evidence_rev::parse_lock(&i.lock)?;
    for ((n, v), p) in &pkgs {
        match p.source.as_deref() {
            None | Some(CRATES_IO) => {}
            Some(s) => {
                return Err(format!(
                    "{n}@{v}: source `{s}` is neither crates.io nor a path"
                ));
            }
        }
    }
    let mut crates = Vec::new();
    for (n, v) in reverse_closure(&pkgs, &i.package, &i.version)? {
        let p = &pkgs[&(n.clone(), v.clone())];
        if p.source.is_none() {
            continue; // a path package: part of the tool tree
        }
        let ck = p
            .checksum
            .clone()
            .ok_or_else(|| format!("{n}@{v}: registry package without a checksum"))?;
        let files = crate_files(&fetch_crate(&n, &v, &ck)?).map_err(|e| format!("{n}@{v}: {e}"))?;
        crates.push((n, v, ck, files));
    }
    let tree = tool_tree(&i.repo, &i.rev, &i.patches)?;
    Ok((name, serialize(&render(i, &tree, &crates)?)))
}

/// The downstream patches the producer applies for `tool`, in its order (file name).
pub(crate) fn patches_for(tool: &str) -> Result<Vec<PathBuf>, String> {
    let dir = Path::new("tools/patches").join(tool);
    let mut out = Vec::new();
    match std::fs::read_dir(&dir) {
        Ok(rd) => {
            for e in rd {
                let p = e.map_err(|e| e.to_string())?.path();
                if p.extension().is_some_and(|x| x == "patch") {
                    out.push(p);
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("{}: {e}", dir.display())),
    }
    out.sort_by_key(|p| p.file_name().map(|n| n.to_os_string()));
    Ok(out)
}

/// The checkout inputs for (tool, digest, instance): TOOLS.lock repo and rev of that digest, the
/// frozen lock, the patches, and the query from `audit`.
pub(crate) fn inputs(
    tool: &str,
    digest: &str,
    id: &str,
    package: &str,
    version: &str,
    audit: &Value,
) -> Result<Inputs, String> {
    let tools = std::fs::read_to_string("tools/TOOLS.lock")
        .map_err(|e| format!("tools/TOOLS.lock: {e}"))?;
    let row = crate::gate::parse_tools_lock(&tools)
        .into_iter()
        .find(|l| l.name == tool && l.sha == digest)
        .ok_or_else(|| format!("tools/TOOLS.lock pins no {tool} at {digest}"))?;
    let lock_path = Path::new("tools/locks").join(format!("{tool}.lock"));
    let lock =
        std::fs::read_to_string(&lock_path).map_err(|e| format!("{}: {e}", lock_path.display()))?;
    Ok(Inputs {
        tool: tool.into(),
        digest: digest.into(),
        repo: row.repo,
        rev: row.rev,
        lock,
        patches: patches_for(tool)?,
        id: id.into(),
        package: package.into(),
        version: version.into(),
        functions: affected_functions(audit, id, package, version)?,
    })
}

/// `cargo xtask reach emit|check --tool T --digest D --advisory A --package P --version V
/// [--audit <cargo audit --json report>]`. Without `--audit`, the frozen lock is scanned with the
/// pinned auditor (`PINNED_TOOLS_DIR`), as the gate scans it.
pub fn run(args: &[String]) -> i32 {
    let usage = "usage: cargo xtask reach <emit|check> --tool T --digest D --advisory A --package P --version V [--audit <report.json>]";
    let cmd = args.get(1).map(String::as_str).unwrap_or("");
    let mut opt: BTreeMap<&str, String> = BTreeMap::new();
    let mut it = args.iter().skip(2);
    while let Some(a) = it.next() {
        match a.as_str() {
            k @ ("--tool" | "--digest" | "--advisory" | "--package" | "--version" | "--audit") => {
                opt.insert(k, it.next().cloned().unwrap_or_default());
            }
            other => {
                eprintln!("reach: unknown argument {other}\n{usage}");
                return 2;
            }
        }
    }
    let get = |k: &str| opt.get(k).cloned().unwrap_or_default();
    let (tool, digest, id, package, version) = (
        get("--tool"),
        get("--digest"),
        get("--advisory"),
        get("--package"),
        get("--version"),
    );
    if !matches!(cmd, "emit" | "check")
        || tool.is_empty()
        || !is_hex(&digest, 64)
        || id.is_empty()
        || package.is_empty()
        || version.is_empty()
    {
        eprintln!("{usage}");
        return 2;
    }
    let res = (|| -> Result<String, String> {
        let audit: Value = match opt.get("--audit") {
            Some(p) => {
                serde_json::from_str(&std::fs::read_to_string(p).map_err(|e| format!("{p}: {e}"))?)
                    .map_err(|e| format!("{p}: {e}"))?
            }
            None => crate::gate::run_audit(
                &Path::new("tools/locks").join(format!("{tool}.lock")),
                false,
            )?,
        };
        let i = inputs(&tool, &digest, &id, &package, &version, &audit)?;
        let dir = crate::evidence_rev::current(
            Path::new("supply-chain/evidence"),
            Path::new("tools/locks"),
            &tool,
            &digest,
        )?
        .dir
        .join("reach");
        let (name, text) = generate(&i)?;
        let path = dir.join(&name);
        let sha = crate::sha256::sha256_hex(text.as_bytes());
        match (cmd, std::fs::read_to_string(&path)) {
            (_, Ok(old)) if old == text => {
                Ok(format!("{} is up to date (sha256 {sha})", path.display()))
            }
            ("emit", Ok(_)) => Err(format!(
                "{} exists with other content: records are never edited; it does not reproduce from the checkout",
                path.display()
            )),
            ("emit", Err(_)) => {
                std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
                std::fs::write(&path, &text).map_err(|e| format!("{}: {e}", path.display()))?;
                Ok(format!("wrote {} (sha256 {sha})", path.display()))
            }
            (_, Ok(_)) => Err(format!(
                "{} does not reproduce from the checkout",
                path.display()
            )),
            (_, Err(_)) => Err(format!(
                "{} is not committed (it would hash to {sha})",
                path.display()
            )),
        }
    })();
    match res {
        Ok(msg) => {
            println!("reach: {msg}");
            0
        }
        Err(e) => {
            eprintln!("reach: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tar_entry(name: &str, kind: u8, data: &[u8]) -> Vec<u8> {
        let mut h = [0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        h[100..107].copy_from_slice(b"0000644");
        let size = format!("{:011o}", data.len());
        h[124..135].copy_from_slice(size.as_bytes());
        h[156] = kind;
        h[257..263].copy_from_slice(b"ustar\0");
        h[148..156].copy_from_slice(b"        ");
        let sum: u32 = h.iter().map(|&b| b as u32).sum();
        h[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
        let mut out = h.to_vec();
        out.extend_from_slice(data);
        out.resize(out.len().div_ceil(512) * 512, 0);
        out
    }
    fn tar_of(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut t: Vec<u8> = entries.concat();
        t.extend_from_slice(&[0u8; 1024]);
        t
    }
    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut g = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];
        g.extend(miniz_oxide::deflate::compress_to_vec(data, 6));
        g.extend(crc32(data).to_le_bytes());
        g.extend((data.len() as u32).to_le_bytes());
        g
    }

    #[test]
    fn crc32_matches_the_reference_vector() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn a_crate_archive_reads_in_memory_and_refuses_what_it_cannot_vouch_for() {
        let t = tar_of(&[
            tar_entry("p-1.0.0/", b'5', b""),
            tar_entry("p-1.0.0/src/lib.rs", b'0', b"pub fn origin() {}\n"),
            tar_entry("././@LongLink", b'L', b"p-1.0.0/src/a_very_long_name.rs\0"),
            tar_entry("p-1.0.0/src/trunc", b'0', b"x"),
        ]);
        let files = crate_files(&gzip(&t)).unwrap();
        assert_eq!(
            files.keys().collect::<Vec<_>>(),
            ["p-1.0.0/src/a_very_long_name.rs", "p-1.0.0/src/lib.rs"]
        );
        // a link, a duplicate path, a traversal, a corrupt stream
        assert!(untar(&tar_of(&[tar_entry("p/l", b'2', b"")])).is_err());
        assert!(
            untar(&tar_of(&[
                tar_entry("p/a", b'0', b"1"),
                tar_entry("p/a", b'0', b"2")
            ]))
            .is_err()
        );
        assert!(untar(&tar_of(&[tar_entry("p/../x", b'0', b"1")])).is_err());
        let mut bad = gzip(&t);
        let n = bad.len();
        bad[n - 5] ^= 1;
        assert!(gunzip(&bad).is_err());
        let mut two = gzip(&t);
        two.extend(gzip(b"more"));
        assert!(gunzip(&two).is_err(), "a second member is refused");
        // a bad header checksum
        let mut e = tar_entry("p/a", b'0', b"1");
        e[0] = b'q';
        assert!(untar(&tar_of(&[e])).is_err());
    }

    #[test]
    fn the_universe_is_the_package_and_everything_that_depends_on_it() {
        let lock = "version = 4\n\n\
            [[package]]\nname = \"app\"\nversion = \"1.0.0\"\ndependencies = [\n \"mid\",\n \"other\",\n]\n\n\
            [[package]]\nname = \"mid\"\nversion = \"2.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"aa\"\ndependencies = [\n \"p 1.0.0\",\n]\n\n\
            [[package]]\nname = \"other\"\nversion = \"3.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"bb\"\ndependencies = [\n \"p 2.0.0\",\n]\n\n\
            [[package]]\nname = \"p\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"cc\"\n\n\
            [[package]]\nname = \"p\"\nversion = \"2.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"dd\"\n";
        let (pkgs, _) = crate::evidence_rev::parse_lock(lock).unwrap();
        let k = |n: &str, v: &str| (n.to_string(), v.to_string());
        assert_eq!(
            reverse_closure(&pkgs, "p", "1.0.0").unwrap(),
            BTreeSet::from([k("p", "1.0.0"), k("mid", "2.0.0"), k("app", "1.0.0")])
        );
        assert_eq!(
            reverse_closure(&pkgs, "p", "2.0.0").unwrap(),
            BTreeSet::from([k("p", "2.0.0"), k("other", "3.0.0"), k("app", "1.0.0")])
        );
        assert!(reverse_closure(&pkgs, "p", "9.0.0").is_err());
    }

    #[test]
    fn the_query_and_the_name_come_from_the_advisory() {
        let audit = serde_json::json!({"vulnerabilities": {"list": [{
            "advisory": {"id": "RUSTSEC-2026-0592"},
            "package": {"name": "url", "version": "2.5.8"},
            "affected": {"functions": {"url::Url::origin": ["< 2.5.9"], "url::quirks::origin": ["< 2.5.9"]}}
        }]}});
        let f = affected_functions(&audit, "RUSTSEC-2026-0592", "url", "2.5.8").unwrap();
        assert_eq!(query_tokens(&f).unwrap(), ["origin"]);
        let name = record_name("RUSTSEC-2026-0592", "url", "2.5.8", &f).unwrap();
        assert!(name.starts_with("RUSTSEC-2026-0592-") && name.ends_with(".sarif"));
        assert_eq!(name.len(), "RUSTSEC-2026-0592-".len() + 12 + ".sarif".len());
        // a changed function list, or a different version, is a different file
        let mut g = f.clone();
        g.insert("url::Url::other".into(), vec![]);
        assert_ne!(
            record_name("RUSTSEC-2026-0592", "url", "2.5.8", &g).unwrap(),
            name
        );
        assert_ne!(
            record_name("RUSTSEC-2026-0592", "url", "2.5.7", &f).unwrap(),
            name
        );
        // a warning without an advisory id never gets a record
        assert!(record_name("yanked", "url", "2.5.8", &f).is_err());
        assert!(affected_functions(&audit, "RUSTSEC-2026-0592", "url", "2.5.7").is_err());
        // none listed: an empty query
        let none = serde_json::json!({"warnings": {"unmaintained": [{
            "advisory": {"id": "RUSTSEC-2026-0543"},
            "package": {"name": "chrono", "version": "0.4.44"}
        }]}});
        assert!(
            affected_functions(&none, "RUSTSEC-2026-0543", "chrono", "0.4.44")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn only_compiled_rust_and_manifests_are_searched() {
        let paths = [
            "Cargo.toml",
            "src/main.rs",
            "tests/it.rs",
            "member/Cargo.toml",
            "member/src/lib.rs",
            "member/src/tests/mod.rs",
            "member/benches/b.rs",
            "member/examples/e.rs",
            "member/build.rs",
            "member/README.md",
            "LICENSE",
        ]
        .map(String::from);
        let roots = package_roots(paths.iter());
        assert_eq!(
            roots,
            BTreeSet::from(["".to_string(), "member".to_string()])
        );
        let k = |p: &str| file_kind(p, &roots);
        assert_eq!(k("Cargo.toml"), Some(FileKind::Manifest));
        assert_eq!(k("member/Cargo.toml"), Some(FileKind::Manifest));
        assert_eq!(k("src/main.rs"), Some(FileKind::Rust));
        assert_eq!(k("member/src/lib.rs"), Some(FileKind::Rust));
        assert_eq!(k("member/build.rs"), Some(FileKind::Rust));
        // a `tests` module under src is compiled code, not a test target
        assert_eq!(k("member/src/tests/mod.rs"), Some(FileKind::Rust));
        for skipped in [
            "tests/it.rs",
            "member/benches/b.rs",
            "member/examples/e.rs",
            "member/README.md",
            "LICENSE",
        ] {
            assert_eq!(k(skipped), None, "{skipped}");
        }
        // a file outside every package root is not searched
        assert_eq!(
            file_kind("x.rs", &BTreeSet::from(["member".to_string()])),
            None
        );
    }

    #[test]
    fn crate_references_are_paths_extern_crates_and_manifest_names() {
        let rs =
            b"use heapless::Vec;\nlet heapless = 1;\nextern crate heapless;\n// heapless docs\n";
        let at: Vec<usize> = crate_path_hits(rs, "heapless")
            .iter()
            .map(|h| h.line)
            .collect();
        assert_eq!(at, [1, 3]);
        // a module of the same name under another path is not the crate; a leading `::` is
        let rs = b"use crate::url::Rewrite;\nremote::url::X;\n<T as A>::url::f();\nuse ::url::Url;\nurl::Url::parse(s);\n";
        let at: Vec<usize> = crate_path_hits(rs, "url").iter().map(|h| h.line).collect();
        assert_eq!(at, [4, 5]);
        let toml = b"[dependencies]\nheapless = \"0.8\"\nheapless-extra = \"1\"\nx = { package = \"heapless\" }\n";
        let at: Vec<usize> = manifest_hits(toml, "heapless")
            .iter()
            .map(|h| h.line)
            .collect();
        assert_eq!(at, [2, 4]);
        let at: Vec<usize> =
            manifest_hits(b"faster-hex = \"0.10\"\nfaster-hex-x = 1\n", "faster-hex")
                .iter()
                .map(|h| h.line)
                .collect();
        assert_eq!(at, [1]);
    }

    #[test]
    fn a_record_is_deterministic_and_says_what_it_searched() {
        let mut functions = BTreeMap::new();
        functions.insert("p::Thing::pop".to_string(), vec!["< 1.1".to_string()]);
        let i = Inputs {
            tool: "t".into(),
            digest: "d".repeat(64),
            repo: "o/r".into(),
            rev: "a".repeat(40),
            lock: "version = 4\n".into(),
            patches: Vec::new(),
            id: "RUSTSEC-2026-0001".into(),
            package: "p".into(),
            version: "1.0.0".into(),
            functions,
        };
        let tree = ToolTree {
            commit: "a".repeat(40),
            tree: "b".repeat(40),
            patches: vec![("0001.patch".into(), "c".repeat(64))],
            files: BTreeMap::from([
                (
                    "Cargo.toml".to_string(),
                    b"[dependencies]\nmid = \"1\"\n".to_vec(),
                ),
                (
                    "src/main.rs".to_string(),
                    b"fn main() { v.pop(); }\n".to_vec(),
                ),
                ("tests/t.rs".to_string(), b"x.pop();\n".to_vec()),
            ]),
            gitlinks: vec![],
        };
        let crates = vec![
            (
                "mid".to_string(),
                "1.0.0".to_string(),
                "e".repeat(64),
                BTreeMap::from([
                    (
                        "mid-1.0.0/Cargo.toml".to_string(),
                        b"[dependencies]\np = \"1\"\n".to_vec(),
                    ),
                    (
                        "mid-1.0.0/src/lib.rs".to_string(),
                        b"use p::Thing;\n".to_vec(),
                    ),
                    ("mid-1.0.0/README.md".to_string(), b"pop\n".to_vec()),
                ]),
            ),
            (
                "p".to_string(),
                "1.0.0".to_string(),
                "f".repeat(64),
                BTreeMap::from([(
                    "p-1.0.0/src/lib.rs".to_string(),
                    b"pub fn pop() {}\nuse p::x;\n".to_vec(),
                )]),
            ),
        ];
        let a = serialize(&render(&i, &tree, &crates).unwrap());
        assert_eq!(a, serialize(&render(&i, &tree, &crates).unwrap()));
        assert!(a.ends_with("}\n") && !a.contains("\r"));
        let v: Value = serde_json::from_str(&a).unwrap();
        let run = &v["runs"][0];
        let hits: Vec<(String, String, u64)> = run["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                let idx = r["locations"][0]["physicalLocation"]["artifactLocation"]["index"]
                    .as_u64()
                    .unwrap();
                (
                    r["ruleId"].as_str().unwrap().to_string(),
                    run["artifacts"][idx as usize]["location"]["uri"]
                        .as_str()
                        .unwrap()
                        .to_string(),
                    r["locations"][0]["physicalLocation"]["region"]["startLine"]
                        .as_u64()
                        .unwrap(),
                )
            })
            .collect();
        let rule = "RUSTSEC-2026-0001".to_string();
        let crate_rule = "RUSTSEC-2026-0001/crate".to_string();
        assert_eq!(
            hits,
            [
                (rule.clone(), "src/main.rs".to_string(), 1),
                (crate_rule.clone(), "mid-1.0.0/Cargo.toml".to_string(), 2),
                (crate_rule, "mid-1.0.0/src/lib.rs".to_string(), 1),
                (rule, "p-1.0.0/src/lib.rs".to_string(), 1),
            ],
            "tests/, README and P's own self-references are not hits"
        );
        assert_eq!(run["properties"]["searched"]["rustFiles"], 3);
        assert_eq!(run["properties"]["searched"]["manifests"], 2);
        assert_eq!(run["properties"]["format"], FORMAT);
    }

    #[test]
    fn tokens_match_on_identifier_boundaries_only() {
        let text = b"x.origin();\r\nlet originate = 1;\n// Url::origin\nr#origin\n";
        let hits = token_hits(text, &["origin".to_string()]);
        let at: Vec<(usize, usize)> = hits.iter().map(|h| (h.line, h.col)).collect();
        assert_eq!(at, [(1, 3), (3, 9), (4, 3)]);
        assert_eq!(hits[0].snippet, "x.origin();");
        assert!(token_hits(text, &[]).is_empty());
    }
}
