//! The decision half of [RFC-0029](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0029-a-confined-launcher.md)'s launcher: what it may
//! run, where, and how an ELF becomes pages, with no syscalls in it, so it can be tested on a host. `src/main.rs` is the
//! program around it.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use lantern_abi::elf;
use lantern_abi::grant::{APP_SLOTS, INTERFACE_FILESYSTEM, INTERFACE_KEYSTORE};
use lantern_abi::launcher::outcome;
use lantern_launch_binder::{read_package, TRUSTED_PUBLISHERS};

/// One verified package in the set, as `apps` lists it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Entry {
    /// Its index in the set, which `REGISTER` names.
    pub index: usize,
    pub name: String,
    /// The first justification it gives, if any.
    pub description: String,
    /// The one host interface it asks for, which decides the channel it gets. An app the runtime can't host (both, or
    /// neither) isn't listed.
    pub interface: usize,
    pub len: usize,
}

/// The packages the launcher verified. One it didn't verify is never listed and never run.
#[derive(Default)]
pub struct Catalog {
    pub entries: Vec<Entry>,
}

impl Catalog {
    /// Verifies each package of the set under the binder's own trusted publishers.
    pub fn new<'a>(packages: impl IntoIterator<Item = Option<&'a [u8]>>) -> Self {
        let entries = packages
            .into_iter()
            .enumerate()
            .filter_map(|(index, lpkg)| {
                let lpkg = lpkg?;
                let (_, plan) = read_package(lpkg, TRUSTED_PUBLISHERS)?;
                let interface = match (plan.keystore.is_empty(), plan.filesystem.is_empty()) {
                    (false, true) => INTERFACE_KEYSTORE,
                    (true, false) => INTERFACE_FILESYSTEM,
                    _ => return None,
                };
                let description =
                    plan.keystore.iter().chain(&plan.filesystem).next().map(|r| r.justification.clone()).unwrap_or_default();
                Some(Entry { index, name: plan.app.name, description, interface, len: lpkg.len() })
            })
            .collect();
        Self { entries }
    }

    /// The first verified package called `name`.
    pub fn find(&self, name: &[u8]) -> Option<&Entry> {
        self.entries.iter().find(|e| e.name.as_bytes() == name)
    }
}

/// What each app slot holds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Slot {
    Free,
    /// Built, registered and started: running the set's package `package`.
    Running { package: usize },
    /// Ended, and kept resident (the `launcher-hold-test` feature only).
    Held { package: usize },
}

/// The app slots.
pub struct Slots {
    pub slots: [Slot; APP_SLOTS],
}

impl Default for Slots {
    fn default() -> Self {
        Self { slots: [Slot::Free; APP_SLOTS] }
    }
}

impl Slots {
    /// A free slot, or `NO_ROOM`.
    pub fn free(&self) -> Result<usize, u8> {
        self.slots.iter().position(|s| *s == Slot::Free).ok_or(outcome::NO_ROOM)
    }
}

/// One megapage of an ELF: its address, and the union of the permissions of every segment in it, as
/// `lantern_abi::wire::MapPerms` bits less `USER`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Megapage {
    pub vaddr: usize,
    pub perms: usize,
}

pub const MEGA: usize = 2 << 20;
/// The most megapages an ELF the launcher builds may touch.
pub const MAX_ELF_MEGAPAGES: usize = 4;

/// Every megapage `bytes`' loadable segments touch, each once, with their permissions unioned: two segments often share
/// one. `None` if it doesn't parse, or needs more than [`MAX_ELF_MEGAPAGES`].
pub fn plan_megapages(bytes: &[u8]) -> Option<(usize, Vec<Megapage>)> {
    let header = elf::parse_header(bytes).ok()?;
    let mut pages: Vec<Megapage> = Vec::new();
    for i in 0..header.phnum {
        let Some(ph) = elf::program_header(bytes, &header, i).ok()? else { continue };
        let mut perms = 0;
        for (flag, bit) in [(elf::PF_R, 1), (elf::PF_W, 2), (elf::PF_X, 4)] {
            if ph.flags & flag != 0 {
                perms |= bit;
            }
        }
        let start = ph.vaddr as usize & !(MEGA - 1);
        let end = (ph.vaddr as usize).checked_add(ph.memsz as usize)?;
        let mut v = start;
        while v < end {
            match pages.iter().position(|p| p.vaddr == v) {
                Some(i) => pages[i].perms |= perms,
                None if pages.len() < MAX_ELF_MEGAPAGES => pages.push(Megapage { vaddr: v, perms }),
                None => return None,
            }
            v += MEGA;
        }
    }
    Some((header.entry as usize, pages))
}

/// What part of each loadable segment's file bytes lands in the megapage at `vaddr`: `(offset in the megapage, offset in
/// the file, length)`, for each segment that has some there.
pub fn copies_into(bytes: &[u8], vaddr: usize) -> Vec<(usize, usize, usize)> {
    let Ok(header) = elf::parse_header(bytes) else { return Vec::new() };
    (0..header.phnum)
        .filter_map(|i| {
            let ph = elf::program_header(bytes, &header, i).ok()??;
            let (file_start, file_end) = (ph.vaddr as usize, ph.vaddr as usize + ph.filesz as usize);
            let (from, to) = (vaddr.max(file_start), (vaddr + MEGA).min(file_end));
            (from < to).then(|| (from - vaddr, ph.offset as usize + (from - file_start), to - from))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use lantern_crypto::signing::SigningKey;
    use lantern_sdk::package::{encode_package, sign_package};
    use std::format;
    use std::vec;

    const CWASM: &[u8] = b"not really a cwasm";

    fn lpkg(seed: u8, app: &str, table: &str) -> Vec<u8> {
        let manifest = format!(
            "[app]\nname = \"{app}\"\nversion = \"0.1.0\"\n\n[[{table}]]\nrole = \"r\"\nops = [\"read\"]\njustification = \"says why\"\n"
        );
        let key = SigningKey::from_random_bytes([seed; 32]);
        encode_package(manifest.as_bytes(), CWASM, &sign_package(manifest.as_bytes(), CWASM, &key))
    }

    #[test]
    fn only_verified_packages_are_listed_and_found() {
        let good = lpkg(0x4c, "confined-fs-probe", "filesystem.file");
        let untrusted = lpkg(0x11, "evil", "filesystem.file");
        let mut tampered = lpkg(0x4c, "tampered", "filesystem.file");
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        let catalog = Catalog::new([Some(&untrusted[..]), Some(&good[..]), None, Some(&tampered[..])]);
        assert_eq!(catalog.entries.len(), 1);
        let entry = catalog.find(b"confined-fs-probe").unwrap();
        assert_eq!((entry.index, entry.interface, entry.description.as_str()), (1, INTERFACE_FILESYSTEM, "says why"));
        assert_eq!(catalog.find(b"evil"), None);
        assert_eq!(catalog.find(b"tampered"), None);
    }

    #[test]
    fn slots_fill_and_then_there_is_no_room() {
        let mut slots = Slots::default();
        for app in 0..APP_SLOTS {
            assert_eq!(slots.free(), Ok(app));
            slots.slots[app] = Slot::Running { package: 0 };
        }
        assert_eq!(slots.free(), Err(outcome::NO_ROOM));
        slots.slots[2] = Slot::Held { package: 0 };
        assert_eq!(slots.free(), Err(outcome::NO_ROOM), "a held app keeps its slot");
        slots.slots[1] = Slot::Free;
        assert_eq!(slots.free(), Ok(1));
    }

    /// A minimal ELF64 with the given `(vaddr, filesz, memsz, flags)` loadable segments, each at file offset 0x1000.
    fn elf(segments: &[(u64, u64, u64, u32)]) -> Vec<u8> {
        let mut b = vec![0u8; 0x2000];
        b[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        b[4] = 2;
        b[5] = 1;
        b[0x10..0x12].copy_from_slice(&2u16.to_le_bytes());
        b[0x12..0x14].copy_from_slice(&243u16.to_le_bytes());
        b[0x18..0x20].copy_from_slice(&0x8400_0000u64.to_le_bytes());
        b[0x20..0x28].copy_from_slice(&64u64.to_le_bytes());
        b[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
        b[0x38..0x3a].copy_from_slice(&(segments.len() as u16).to_le_bytes());
        for (i, &(vaddr, filesz, memsz, flags)) in segments.iter().enumerate() {
            let at = 64 + i * 56;
            b[at..at + 4].copy_from_slice(&1u32.to_le_bytes());
            b[at + 4..at + 8].copy_from_slice(&flags.to_le_bytes());
            b[at + 8..at + 16].copy_from_slice(&0x1000u64.to_le_bytes());
            b[at + 16..at + 24].copy_from_slice(&vaddr.to_le_bytes());
            b[at + 32..at + 40].copy_from_slice(&filesz.to_le_bytes());
            b[at + 40..at + 48].copy_from_slice(&memsz.to_le_bytes());
        }
        b
    }

    #[test]
    fn segments_sharing_a_megapage_share_it_with_both_permissions() {
        let (r, w, x) = (elf::PF_R, elf::PF_W, elf::PF_X);
        // The runtime's shape: text and rodata in one megapage, data in the next.
        let bytes = elf(&[(0x8400_0000, 0x100, 0x100, r | x), (0x840d_8000, 0x10, 0x10, r), (0x8420_0000, 0x8, 0x1000, r | w)]);
        let (entry, pages) = plan_megapages(&bytes).unwrap();
        assert_eq!(entry, 0x8400_0000);
        assert_eq!(pages, [Megapage { vaddr: 0x8400_0000, perms: 0b101 }, Megapage { vaddr: 0x8420_0000, perms: 0b011 }]);
        assert_eq!(copies_into(&bytes, 0x8400_0000), [(0, 0x1000, 0x100), (0xd_8000, 0x1000, 0x10)]);
        assert_eq!(copies_into(&bytes, 0x8420_0000), [(0, 0x1000, 0x8)], "only the file bytes; the rest stays zero");
    }

    #[test]
    fn an_elf_too_big_or_malformed_is_refused() {
        let huge = elf(&[(0x8400_0000, 0, (MAX_ELF_MEGAPAGES as u64 + 1) * MEGA as u64, elf::PF_R)]);
        assert_eq!(plan_megapages(&huge), None);
        assert_eq!(plan_megapages(b"not an elf"), None);
        let overflow = elf(&[(u64::MAX - 10, 0, 100, elf::PF_R)]);
        assert_eq!(plan_megapages(&overflow), None);
    }
}
