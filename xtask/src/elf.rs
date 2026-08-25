//! ELF64 walker -- the Linux half of the per-binary capability gate (#245).
//!
//! `verify-caps` parsed PE only, so `cargo-acl` (our one linux-x86_64 tool) had no
//! capability manifest and no hardening record at all: it was outside the gate entirely,
//! while the producer's output still read as if every produced binary were covered.
//!
//! WHAT MAPS ACROSS FORMATS, AND WHAT DOES NOT. PE and ELF express the same defensive
//! CLASSES through different mechanisms, so the manifest records format-appropriate names
//! rather than pretending one vocabulary fits both:
//!
//!   class                    PE                      ELF
//!   ---------------------    --------------------    --------------------------------
//!   address randomisation    ASLR_DYNAMICBASE        PIE       (ET_DYN + DF_1_PIE)
//!   (64-bit entropy)         HIGH_ENTROPY_VA         -- implied by PIE on x86-64
//!   non-executable data      DEP_NX                  NX_STACK  (PT_GNU_STACK w/o PF_X)
//!   relocation hardening     -- n/a                  RELRO     (PT_GNU_RELRO)
//!                                                    BIND_NOW  (DF_BIND_NOW / DF_1_NOW)
//!   forward-edge CFI         CONTROL_FLOW_GUARD      CET_IBT   (GNU property note)
//!   backward-edge CFI        -- (CETCOMPAT, separate)  CET_SHSTK (GNU property note)
//!   stack canaries           -- inline, not in header  STACK_PROTECTOR (__stack_chk_fail)
//!
//! Collapsing these into shared labels would assert an equivalence that does not hold:
//! HIGH_ENTROPY_VA has no ELF counterpart, RELRO/BIND_NOW have no PE counterpart, and CFG
//! and LLVM CFI are different mechanisms with different guarantees. Distinct names keep the
//! manifest a description of the artifact rather than a translation of it.
//!
//! WHY THE FLOOR DIFFERS BY FORMAT. Per the rustc Exploit Mitigations chapter, on Linux
//! rustc enables PIE (since 0.12.0), non-executable memory (1.8.0), and RELRO + immediate
//! binding (1.21.0) BY DEFAULT -- so an ordinary `cargo install` already produces all four.
//! On Windows, Control Flow Guard is opt-in (`-C control-flow-guard`), which is exactly why
//! our PE tools lack it (#300). The floors therefore differ because the achievable-by-default
//! baselines genuinely differ, not because one platform is held to a lower standard.
//!
//! SCOPE: ELF64 little-endian. ELF32 is explicitly REJECTED rather than parsed with 64-bit
//! offsets, because a walker that mis-parses is worse than one that declines: it would report
//! a confident, wrong capability set.

use std::collections::BTreeSet;

// --- ELF constants (see the System V gABI and the GNU extensions) ---
const ET_DYN: u16 = 3;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_GNU_STACK: u32 = 0x6474_e551;
const PT_GNU_RELRO: u32 = 0x6474_e552;
const PT_GNU_PROPERTY: u32 = 0x6474_e553;
const PT_INTERP: u32 = 3;
const PF_X: u32 = 1;

/// Intel CET, the modern x86-64 forward/backward-edge control-flow protection, is advertised
/// through a GNU property note rather than a header bit.
const NT_GNU_PROPERTY_TYPE_0: u32 = 5;
const GNU_PROPERTY_X86_FEATURE_1_AND: u32 = 0xc000_0002;
const GNU_PROPERTY_X86_FEATURE_1_IBT: u32 = 0x1;
const GNU_PROPERTY_X86_FEATURE_1_SHSTK: u32 = 0x2;

const DT_NULL: i64 = 0;
const DT_NEEDED: i64 = 1;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_SYMENT: i64 = 11;
const DT_BIND_NOW: i64 = 24;
const DT_FLAGS: i64 = 30;
const DT_FLAGS_1: i64 = 0x6fff_fffb;

const DF_BIND_NOW: u64 = 0x8;
const DF_1_NOW: u64 = 0x1;
const DF_1_PIE: u64 = 0x0800_0000;

fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(off..off + 2)?.try_into().ok()?))
}
fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
}
fn u64_at(b: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(off..off + 8)?.try_into().ok()?))
}

/// True when the bytes begin a little-endian 64-bit ELF image.
pub fn is_elf64_le(b: &[u8]) -> bool {
    b.len() > 0x40 && b[..4] == [0x7f, b'E', b'L', b'F'] && b[4] == 2 && b[5] == 1
}

/// Any ELF at all, including classes we decline to parse.
pub fn is_elf(b: &[u8]) -> bool {
    b.len() > 16 && b[..4] == [0x7f, b'E', b'L', b'F']
}

struct Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_filesz: u64,
    p_memsz: u64,
}

fn program_headers(b: &[u8]) -> Option<Vec<Phdr>> {
    let phoff = u64_at(b, 0x20)? as usize;
    let phentsize = u16_at(b, 0x36)? as usize;
    let phnum = u16_at(b, 0x38)? as usize;
    // A 64-bit program header is 56 bytes; anything smaller cannot hold the fields we read.
    if phentsize < 56 || phnum == 0 || phnum > 0x1000 {
        return None;
    }
    let mut out = Vec::with_capacity(phnum);
    for i in 0..phnum {
        let o = phoff.checked_add(i.checked_mul(phentsize)?)?;
        out.push(Phdr {
            p_type: u32_at(b, o)?,
            p_flags: u32_at(b, o + 4)?,
            p_offset: u64_at(b, o + 8)?,
            p_vaddr: u64_at(b, o + 16)?,
            p_filesz: u64_at(b, o + 32)?,
            p_memsz: u64_at(b, o + 40)?,
        });
    }
    Some(out)
}

/// Translate a virtual address to a file offset using the PT_LOAD map. Dynamic-section
/// pointers are virtual addresses, so nothing in the dynamic table is readable without this.
fn vaddr_to_off(phdrs: &[Phdr], vaddr: u64) -> Option<u64> {
    for p in phdrs.iter().filter(|p| p.p_type == PT_LOAD) {
        if vaddr >= p.p_vaddr && vaddr < p.p_vaddr.checked_add(p.p_memsz)? {
            let delta = vaddr - p.p_vaddr;
            if delta < p.p_filesz {
                return p.p_offset.checked_add(delta);
            }
        }
    }
    None
}

/// Every (tag, value) pair in PT_DYNAMIC, stopping at DT_NULL.
fn dynamic_entries(b: &[u8], phdrs: &[Phdr]) -> Option<Vec<(i64, u64)>> {
    let dyn_ph = phdrs.iter().find(|p| p.p_type == PT_DYNAMIC)?;
    let base = dyn_ph.p_offset as usize;
    let len = dyn_ph.p_filesz as usize;
    let mut out = Vec::new();
    let mut o = base;
    while o + 16 <= base + len {
        let tag = i64::from_le_bytes(b.get(o..o + 8)?.try_into().ok()?);
        let val = u64_at(b, o + 8)?;
        if tag == DT_NULL {
            break;
        }
        out.push((tag, val));
        o += 16;
        // Defensive bound: a malformed table must terminate rather than spin.
        if out.len() > 4096 {
            return None;
        }
    }
    Some(out)
}

fn cstr_at(b: &[u8], off: usize) -> Option<String> {
    let end = b.get(off..)?.iter().position(|&c| c == 0)? + off;
    Some(String::from_utf8_lossy(b.get(off..end)?).to_string())
}

/// Shared objects this binary needs at load time (`DT_NEEDED`) -- the ELF analogue of a PE's
/// imported DLL list, and the same thing the caps allowlist ratchets.
pub fn elf_needed(b: &[u8]) -> Option<Vec<String>> {
    if !is_elf64_le(b) {
        return None;
    }
    let phdrs = program_headers(b)?;
    let dynamic = dynamic_entries(b, &phdrs)?;
    let strtab_va = dynamic.iter().find(|(t, _)| *t == DT_STRTAB)?.1;
    let strtab = vaddr_to_off(&phdrs, strtab_va)? as usize;
    let mut out = Vec::new();
    for (tag, val) in &dynamic {
        if *tag == DT_NEEDED {
            if let Some(s) = cstr_at(b, strtab.checked_add(*val as usize)?) {
                out.push(s.to_ascii_lowercase());
            }
        }
    }
    Some(out)
}

/// Undefined dynamic symbols -- the functions this binary imports from those objects.
///
/// Walks `.dynsym` from the dynamic table. Symbol count is not recorded in the dynamic
/// section, so the table is read until it leaves the containing PT_LOAD segment; entries
/// that do not parse simply end the walk rather than being guessed at.
pub fn elf_imported_functions(b: &[u8]) -> Option<Vec<String>> {
    if !is_elf64_le(b) {
        return None;
    }
    let phdrs = program_headers(b)?;
    let dynamic = dynamic_entries(b, &phdrs)?;
    let strtab = vaddr_to_off(&phdrs, dynamic.iter().find(|(t, _)| *t == DT_STRTAB)?.1)? as usize;
    let symtab_va = dynamic.iter().find(|(t, _)| *t == DT_SYMTAB)?.1;
    let symtab = vaddr_to_off(&phdrs, symtab_va)? as usize;
    let syment = dynamic
        .iter()
        .find(|(t, _)| *t == DT_SYMENT)
        .map(|(_, v)| *v as usize)
        .unwrap_or(24);
    if syment < 24 {
        return None;
    }
    // Bound the walk by the segment that actually contains the symbol table.
    let seg_end = phdrs
        .iter()
        .filter(|p| p.p_type == PT_LOAD)
        .find(|p| symtab_va >= p.p_vaddr && symtab_va < p.p_vaddr + p.p_memsz)
        .map(|p| (p.p_offset + p.p_filesz) as usize)?;

    let mut out = Vec::new();
    let mut o = symtab;
    while o + syment <= seg_end && out.len() < 100_000 {
        let st_name = u32_at(b, o)? as usize;
        let st_shndx = u16_at(b, o + 6)?;
        // SHN_UNDEF (0) means the symbol is imported rather than defined here.
        if st_shndx == 0 && st_name != 0 {
            if let Some(s) = cstr_at(b, strtab.checked_add(st_name)?) {
                if !s.is_empty() {
                    out.push(s.to_ascii_lowercase());
                }
            }
        }
        o += syment;
    }
    Some(out)
}

/// Intel CET features advertised in `.note.gnu.property` (IBT, shadow stack).
///
/// Parsed structurally rather than inferred: the note is a sequence of (type, size, data)
/// records, and only `GNU_PROPERTY_X86_FEATURE_1_AND` carries the CET bitmask. A malformed
/// note ends the walk instead of being guessed at.
fn cet_features(b: &[u8], phdrs: &[Phdr]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Some(ph) = phdrs.iter().find(|p| p.p_type == PT_GNU_PROPERTY) else {
        return out;
    };
    let base = ph.p_offset as usize;
    let end = base.saturating_add(ph.p_filesz as usize);
    let Some(namesz) = u32_at(b, base) else {
        return out;
    };
    let Some(descsz) = u32_at(b, base + 4) else {
        return out;
    };
    let Some(ntype) = u32_at(b, base + 8) else {
        return out;
    };
    if ntype != NT_GNU_PROPERTY_TYPE_0 {
        return out;
    }
    // name is padded to 4 bytes; the descriptor follows.
    let mut o = base + 12 + ((namesz as usize + 3) & !3);
    let desc_end = o.saturating_add(descsz as usize).min(end);
    while o + 8 <= desc_end {
        let (Some(pr_type), Some(pr_datasz)) = (u32_at(b, o), u32_at(b, o + 4)) else {
            break;
        };
        if pr_type == GNU_PROPERTY_X86_FEATURE_1_AND && pr_datasz >= 4 {
            if let Some(bits) = u32_at(b, o + 8) {
                if bits & GNU_PROPERTY_X86_FEATURE_1_IBT != 0 {
                    out.insert("CET_IBT".to_string());
                }
                if bits & GNU_PROPERTY_X86_FEATURE_1_SHSTK != 0 {
                    out.insert("CET_SHSTK".to_string());
                }
            }
        }
        // records are 8-byte aligned on 64-bit
        o += 8 + ((pr_datasz as usize + 7) & !7);
    }
    out
}

/// The set of hardening mitigations this ELF image actually carries.
///
/// Every name is derived from a structural fact in the image, never from a build flag we
/// hope was passed -- the same discipline as reading PE `DllCharacteristics` rather than
/// trusting the linker invocation.
pub fn elf_hardening(b: &[u8]) -> Option<BTreeSet<String>> {
    if !is_elf64_le(b) {
        return None;
    }
    let phdrs = program_headers(b)?;
    let mut out = BTreeSet::new();

    // PIE. ET_DYN alone is NOT sufficient: a shared library is also ET_DYN, so keying on it
    // would label any .so a position-independent EXECUTABLE. Require the explicit DF_1_PIE
    // marker, or failing that the presence of a program interpreter, which distinguishes an
    // executable from a library. rustc default on Linux since 0.12.0.
    let dynamic = dynamic_entries(b, &phdrs).unwrap_or_default();
    let df1 = dynamic
        .iter()
        .find(|(t, _)| *t == DT_FLAGS_1)
        .map(|(_, v)| *v)
        .unwrap_or(0);
    let is_exec_image = df1 & DF_1_PIE != 0 || phdrs.iter().any(|p| p.p_type == PT_INTERP);
    if u16_at(b, 0x10)? == ET_DYN && is_exec_image {
        out.insert("PIE".to_string());
    }

    // Non-executable stack: PT_GNU_STACK present and NOT marked executable.
    //
    // Absence of the header is deliberately NOT treated as protection: the kernel then
    // falls back to an architecture default that has historically been executable, so a
    // missing header is the unsafe reading, not a neutral one.
    if let Some(gs) = phdrs.iter().find(|p| p.p_type == PT_GNU_STACK) {
        if gs.p_flags & PF_X == 0 {
            out.insert("NX_STACK".to_string());
        }
    }

    // RELRO: the relocation region is made read-only after startup.
    if phdrs.iter().any(|p| p.p_type == PT_GNU_RELRO) {
        out.insert("RELRO".to_string());
    }

    // Immediate binding: any of the three encodings the toolchain may emit. Full RELRO is
    // RELRO + BIND_NOW together; recording them separately keeps the distinction visible.
    let bind_now = dynamic.iter().any(|(t, v)| {
        *t == DT_BIND_NOW
            || (*t == DT_FLAGS && v & DF_BIND_NOW != 0)
            || (*t == DT_FLAGS_1 && v & DF_1_NOW != 0)
    });
    if bind_now {
        out.insert("BIND_NOW".to_string());
    }

    // Intel CET (IBT / shadow stack) -- the current x86-64 control-flow protection, and the
    // closest ELF analogue to PE Control Flow Guard. rustc does NOT emit it by default, so
    // its absence here is the expected baseline rather than a regression; recording it means
    // a future toolchain that starts emitting it shows up as a reviewable change instead of
    // passing unnoticed.
    out.extend(cet_features(b, &phdrs));

    // Stack smashing protection is NOT a header bit in either format: it is inline code.
    // Its presence is inferred from the guard-failure symbol the instrumentation calls.
    // Recorded because on Linux it is opt-in (`-Z stack-protector`), so unlike PIE/NX/RELRO
    // its absence is the expected default rather than a regression.
    if let Some(funcs) = elf_imported_functions(b) {
        if funcs.iter().any(|f| f.contains("__stack_chk_fail")) {
            out.insert("STACK_PROTECTOR".to_string());
        }
    }

    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_elf_and_elf32() {
        assert!(!is_elf64_le(b"MZ\x90\x00 not an elf at all, this is a PE stub....."));
        // ELF32 (EI_CLASS = 1) must be declined, not parsed with 64-bit offsets: a walker
        // that mis-parses reports a confident, wrong capability set.
        let mut elf32 = vec![0u8; 0x80];
        elf32[..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        elf32[4] = 1;
        elf32[5] = 1;
        assert!(is_elf(&elf32));
        assert!(!is_elf64_le(&elf32));
        assert!(elf_hardening(&elf32).is_none());
        assert!(elf_needed(&elf32).is_none());
    }

    #[test]
    fn truncated_image_is_declined_not_guessed() {
        let mut short = vec![0u8; 0x30];
        short[..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        short[4] = 2;
        short[5] = 1;
        // Too short to hold program headers: every accessor must fail closed.
        assert!(!is_elf64_le(&short));
        assert!(elf_needed(&short).is_none());
    }

    #[test]
    fn garbage_phnum_is_rejected() {
        let mut b = vec![0u8; 0x200];
        b[..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        b[4] = 2;
        b[5] = 1;
        b[0x36..0x38].copy_from_slice(&56u16.to_le_bytes()); // phentsize
        b[0x38..0x3A].copy_from_slice(&0xFFFFu16.to_le_bytes()); // absurd phnum
        assert!(program_headers(&b).is_none(), "an absurd phnum must be refused");
    }
}
