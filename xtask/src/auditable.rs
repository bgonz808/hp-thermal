//! cargo-auditable's `.dep-v0` section: presence and shape, parsed in-tree (#386).
//!
//! `cargo audit bin` on a binary WITHOUT the section does not fail: it recovers a PARTIAL
//! dependency list from panic strings and exits 0, so a scan that could not see the
//! dependencies reads as cleaner. Presence is therefore checked here, before any binary-vantage
//! scan is allowed to count — for the shipped exe (release-attest) and for every produced tool
//! (build-tools.yml). The section holds zlib-compressed JSON (cargo-auditable's published
//! format); the zlib header is checked so an empty or garbage section is not "present".
//!
//! PE: ordinary image section. ELF: cargo-auditable emits it NON-ALLOC (sh_flags = 0), the same
//! class as `.comment`, which `strip` leaves in place — so a missing section means the binary was
//! not built through cargo-auditable, not that it was stripped.

use std::path::Path;

const SECTION: &[u8] = b".dep-v0";

fn u16le(b: &[u8], o: usize) -> Option<usize> {
    b.get(o..o + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]) as usize)
}
fn u32le(b: &[u8], o: usize) -> Option<usize> {
    b.get(o..o + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as usize)
}
fn u64le(b: &[u8], o: usize) -> Option<usize> {
    b.get(o..o + 8).and_then(|s| {
        usize::try_from(u64::from_le_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ]))
        .ok()
    })
}
fn cstr(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

/// The raw bytes of the `.dep-v0` section, or why there are none.
pub(crate) fn dep_v0_section(b: &[u8]) -> Result<&[u8], String> {
    if b.starts_with(b"MZ") {
        pe_section(b)
    } else if b.starts_with(b"\x7fELF") {
        elf_section(b)
    } else {
        Err("not a PE or ELF image".into())
    }
}

fn pe_section(b: &[u8]) -> Result<&[u8], String> {
    let pe = u32le(b, 0x3c).ok_or("truncated DOS header")?;
    if b.get(pe..pe + 4) != Some(b"PE\0\0") {
        return Err("no PE signature".into());
    }
    let nsec = u16le(b, pe + 6).ok_or("truncated COFF header")?;
    let opt = u16le(b, pe + 20).ok_or("truncated COFF header")?;
    let table = pe + 24 + opt;
    for i in 0..nsec {
        let h = table + i * 40;
        let row = b.get(h..h + 40).ok_or("truncated section table")?;
        if cstr(&row[..8]) != SECTION {
            continue;
        }
        let vsize = u32le(row, 8).unwrap_or(0);
        let raw = u32le(row, 16).unwrap_or(0);
        let ptr = u32le(row, 20).unwrap_or(0);
        // VirtualSize is the data length; SizeOfRawData is padded to file alignment. A zero
        // VirtualSize (object-style) falls back to the raw size.
        let len = if vsize == 0 { raw } else { vsize.min(raw) };
        return b
            .get(ptr..ptr + len)
            .ok_or_else(|| ".dep-v0 section points outside the file".to_string());
    }
    Err("no .dep-v0 section (not built through cargo-auditable)".into())
}

fn elf_section(b: &[u8]) -> Result<&[u8], String> {
    if b.get(5) != Some(&1) {
        return Err("big-endian ELF unsupported".into());
    }
    let is64 = match b.get(4) {
        Some(2) => true,
        Some(1) => false,
        _ => return Err("bad ELF class".into()),
    };
    let (shoff, shentsize, shnum, shstrndx) = if is64 {
        (
            u64le(b, 0x28).ok_or("truncated ELF header")?,
            u16le(b, 0x3a).ok_or("truncated ELF header")?,
            u16le(b, 0x3c).ok_or("truncated ELF header")?,
            u16le(b, 0x3e).ok_or("truncated ELF header")?,
        )
    } else {
        (
            u32le(b, 0x20).ok_or("truncated ELF header")?,
            u16le(b, 0x2e).ok_or("truncated ELF header")?,
            u16le(b, 0x30).ok_or("truncated ELF header")?,
            u16le(b, 0x32).ok_or("truncated ELF header")?,
        )
    };
    // (sh_name, sh_offset, sh_size) of section header i.
    let sh = |i: usize| -> Option<(usize, usize, usize)> {
        let h = shoff + i * shentsize;
        let name = u32le(b, h)?;
        if is64 {
            Some((name, u64le(b, h + 0x18)?, u64le(b, h + 0x20)?))
        } else {
            Some((name, u32le(b, h + 0x10)?, u32le(b, h + 0x14)?))
        }
    };
    let (_, stroff, strsz) = sh(shstrndx).ok_or("truncated section headers")?;
    let strtab = b
        .get(stroff..stroff + strsz)
        .ok_or(".shstrtab points outside the file")?;
    for i in 0..shnum {
        let (name, off, size) = sh(i).ok_or("truncated section headers")?;
        let n = strtab.get(name..).ok_or("sh_name outside .shstrtab")?;
        if cstr(n) != SECTION {
            continue;
        }
        return b
            .get(off..off + size)
            .ok_or_else(|| ".dep-v0 section points outside the file".to_string());
    }
    Err("no .dep-v0 section (not built through cargo-auditable)".into())
}

/// Present AND shaped like cargo-auditable's payload (zlib stream header). Returns its length.
pub(crate) fn verify(b: &[u8]) -> Result<usize, String> {
    let s = dep_v0_section(b)?;
    if s.len() < 2 {
        return Err(format!(
            ".dep-v0 section present but empty ({} bytes)",
            s.len()
        ));
    }
    // RFC 1950: CM = 8 (deflate) in the low nibble of CMF; (CMF*256 + FLG) is a multiple of 31.
    if s[0] & 0x0f != 8 || (usize::from(s[0]) * 256 + usize::from(s[1])) % 31 != 0 {
        return Err(format!(
            ".dep-v0 section present ({} bytes) but does not start with a zlib header ({:02x}{:02x})",
            s.len(),
            s[0],
            s[1]
        ));
    }
    Ok(s.len())
}

/// Read + verify one file; prints the verdict. true = present and well-formed.
pub(crate) fn check(path: &str) -> bool {
    let bytes = match std::fs::read(Path::new(path)) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("verify-auditable: cannot read {path} ({e})");
            return false;
        }
    };
    match verify(&bytes) {
        Ok(n) => {
            println!("verify-auditable: {path}: .dep-v0 present ({n} bytes, zlib)");
            true
        }
        Err(e) => {
            eprintln!(
                "verify-auditable: {path}: {e} — a binary-vantage scan of this file would be \
                 fail-open (partial list from panic strings, exit 0); refusing (#386)"
            );
            false
        }
    }
}

pub(crate) fn cmd(path: Option<&str>) -> i32 {
    let Some(p) = path else {
        eprintln!("usage: cargo xtask verify-auditable <BINARY>");
        return 2;
    };
    i32::from(!check(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZLIB: [u8; 4] = [0x78, 0x9c, 0x01, 0x00]; // 0x789c % 31 == 0, CM = 8

    fn pe_with(name: &[u8], data: &[u8], vsize: u32) -> Vec<u8> {
        let mut b = vec![0u8; 64];
        b[..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&64u32.to_le_bytes());
        b.extend_from_slice(b"PE\0\0");
        let mut coff = [0u8; 20];
        coff[..2].copy_from_slice(&0x8664u16.to_le_bytes());
        coff[2..4].copy_from_slice(&1u16.to_le_bytes()); // one section
        coff[16..18].copy_from_slice(&0u16.to_le_bytes()); // no optional header
        b.extend_from_slice(&coff);
        let data_off = (b.len() + 40) as u32;
        let mut row = [0u8; 40];
        row[..name.len().min(8)].copy_from_slice(&name[..name.len().min(8)]);
        row[8..12].copy_from_slice(&vsize.to_le_bytes());
        row[16..20].copy_from_slice(&(data.len() as u32).to_le_bytes());
        row[20..24].copy_from_slice(&data_off.to_le_bytes());
        b.extend_from_slice(&row);
        b.extend_from_slice(data);
        b
    }

    fn elf64_with(name: &[u8], data: &[u8]) -> Vec<u8> {
        // header(64) | 3 shdrs @64 (null, data, shstrtab) | shstrtab | data
        let shoff = 64usize;
        let strtab_off = shoff + 3 * 64;
        let mut strtab = vec![0u8];
        let name_idx = strtab.len();
        strtab.extend_from_slice(name);
        strtab.push(0);
        let shstr_idx = strtab.len();
        strtab.extend_from_slice(b".shstrtab\0");
        let data_off = strtab_off + strtab.len();
        let mut b = vec![0u8; 64];
        b[..4].copy_from_slice(b"\x7fELF");
        b[4] = 2; // 64-bit
        b[5] = 1; // little-endian
        b[0x28..0x30].copy_from_slice(&(shoff as u64).to_le_bytes());
        b[0x3a..0x3c].copy_from_slice(&64u16.to_le_bytes());
        b[0x3c..0x3e].copy_from_slice(&3u16.to_le_bytes());
        b[0x3e..0x40].copy_from_slice(&2u16.to_le_bytes());
        let shdr = |name: u32, off: usize, size: usize| {
            let mut h = [0u8; 64];
            h[..4].copy_from_slice(&name.to_le_bytes());
            h[0x18..0x20].copy_from_slice(&(off as u64).to_le_bytes());
            h[0x20..0x28].copy_from_slice(&(size as u64).to_le_bytes());
            h
        };
        b.extend_from_slice(&[0u8; 64]);
        b.extend_from_slice(&shdr(name_idx as u32, data_off, data.len()));
        b.extend_from_slice(&shdr(shstr_idx as u32, strtab_off, strtab.len()));
        b.extend_from_slice(&strtab);
        b.extend_from_slice(data);
        b
    }

    #[test]
    fn pe_section_found_and_verified() {
        let img = pe_with(b".dep-v0", &ZLIB, 4);
        assert_eq!(dep_v0_section(&img).unwrap(), &ZLIB);
        assert_eq!(verify(&img).unwrap(), 4);
        // VirtualSize bounds the padded raw data
        let padded = pe_with(b".dep-v0", &[0x78, 0x9c, 0x01, 0, 0, 0, 0, 0], 3);
        assert_eq!(dep_v0_section(&padded).unwrap().len(), 3);
    }

    #[test]
    fn pe_without_section_or_with_garbage_is_refused() {
        assert!(dep_v0_section(&pe_with(b".text", &ZLIB, 4)).is_err());
        assert!(
            verify(&pe_with(b".dep-v0", &[], 0)).is_err(),
            "empty section"
        );
        assert!(
            verify(&pe_with(b".dep-v0", &[0x00, 0x01, 0x02, 0x03], 4)).is_err(),
            "not zlib"
        );
        assert!(dep_v0_section(b"MZ\0\0").is_err(), "truncated");
        assert!(dep_v0_section(b"hello").is_err(), "not an image");
    }

    #[test]
    fn elf_section_found_and_verified() {
        let img = elf64_with(b".dep-v0", &ZLIB);
        assert_eq!(dep_v0_section(&img).unwrap(), &ZLIB);
        assert_eq!(verify(&img).unwrap(), 4);
        assert!(dep_v0_section(&elf64_with(b".comment", &ZLIB)).is_err());
        let mut be = elf64_with(b".dep-v0", &ZLIB);
        be[5] = 2;
        assert!(
            dep_v0_section(&be).is_err(),
            "big-endian refused, not misparsed"
        );
    }
}
