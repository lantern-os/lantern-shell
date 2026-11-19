//! The archiver's logic ([RFC-0038](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0038-signed-models-and-kept-audit-history.md)), with no
//! syscalls in it, so it can be tested on a host. `src/main.rs` is the program around it.
//!
//! **Writing an export.** The policy store offers its oldest full audit sector not yet kept. The archiver checks it
//! ([`lantern_policy_store::audit::verify_sector`]), picks the slot after the newest ([`Index::next_slot`]), clears that
//! slot's header, writes the sector sealed in pieces, and writes the new header last. A power cut leaves an empty slot,
//! never one that looks complete; and since the policy store is told `EXPORTED` only after that, it offers the sector
//! again. A slot written over drops the export it held, and how far that drops history is reported with the new one.
//!
//! **Reading one back.** Every piece is unsealed and the whole sector checked against its header before a record is
//! served: a changed piece, a moved one, or a header that doesn't match fails the whole sector.
//!
//! **Each piece's nonce** comes from the sector's first sequence number, the chain head after its last record, and the
//! piece's index: unique for distinct contents under the archiver's key, without a random source. The same sector
//! exported twice seals to the same bytes, which reveals nothing new.

#![cfg_attr(not(test), no_std)]

use lantern_abi::archive::{aad, Header, CHUNK, SEALED_CHUNK, SLOTS, SLOT_SECTORS};
use lantern_abi::block::SECTOR;
use lantern_abi::policy::AuditEntry;
use lantern_crypto::hash;
use lantern_policy_store::audit::{sector_records, verify_sector, EXPORT_SECTOR_WORDS};

/// Pieces per exported sector.
pub const CHUNKS: usize = EXPORT_SECTOR_WORDS * 4 / CHUNK;
/// How many disk sectors a slot's sealed pieces take, after its header.
const DATA_SECTORS: usize = (CHUNKS * SEALED_CHUNK).div_ceil(SECTOR);
const _: () = assert!(DATA_SECTORS < SLOT_SECTORS as usize, "a header and a sealed sector fit a slot");

/// The archive partition, by sector from its start.
pub trait Disk {
    fn read(&mut self, sector: u64, buf: &mut [u8]) -> bool;
    fn write(&mut self, sector: u64, buf: &[u8]) -> bool;
}

/// The archiver's keystore key: authenticated encryption, one piece at a time.
pub trait Sealer {
    fn seal(&mut self, nonce: &[u8; 24], aad: &[u8], plain: &[u8; CHUNK]) -> Option<([u8; 16], [u8; CHUNK])>;
    fn open(&mut self, nonce: &[u8; 24], aad: &[u8], tag: &[u8; 16], sealed: &[u8; CHUNK]) -> Option<[u8; CHUNK]>;
}

/// Why an export couldn't be written or read.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fail {
    /// The disk refused a read or write.
    Disk,
    /// The keystore refused to seal or open a piece.
    Sealing,
    /// What was offered, or what was read back, isn't a whole, checked audit sector matching its header.
    Corrupt,
}

/// Piece `chunk`'s nonce, for a sector starting at `first` whose chain ends at `end_head`.
pub fn nonce(first: u64, end_head: &[u8; 16], chunk: u32) -> [u8; 24] {
    let mut input = [0u8; 8 + 8 + 16 + 4];
    input[..8].copy_from_slice(b"LNTNANON");
    input[8..16].copy_from_slice(&first.to_le_bytes());
    input[16..32].copy_from_slice(end_head);
    input[32..].copy_from_slice(&chunk.to_le_bytes());
    hash::hash(&input).as_bytes()[..24].try_into().unwrap()
}

fn slot_base(slot: usize) -> u64 {
    slot as u64 * SLOT_SECTORS
}

/// The archive's slots, as their headers say.
pub struct Index {
    headers: [Option<Header>; SLOTS],
}

impl Index {
    /// Reads every slot's header. A slot that can't be read, or holds no header, is empty.
    pub fn load(disk: &mut impl Disk) -> Self {
        let mut sector = [0u8; SECTOR];
        Self {
            headers: core::array::from_fn(|slot| {
                disk.read(slot_base(slot), &mut sector).then(|| Header::decode(&sector)).flatten()
            }),
        }
    }

    fn newest(&self) -> Option<(usize, Header)> {
        self.headers.iter().enumerate().filter_map(|(s, h)| h.map(|h| (s, h))).max_by_key(|(_, h)| h.generation)
    }

    /// The slot the next export goes in, its generation, and how far history the archive will then have dropped: the
    /// slot after the newest, round the ring, which drops whatever it held.
    pub fn next_slot(&self) -> (usize, u64, u64) {
        let dropped_before = self.headers.iter().flatten().map(|h| h.dropped).max().unwrap_or(0);
        let Some((newest, header)) = self.newest() else { return (0, 1, dropped_before) };
        let slot = (newest + 1) % SLOTS;
        let dropped = self.headers[slot].map_or(dropped_before, |old| dropped_before.max(old.end));
        (slot, header.generation + 1, dropped)
    }

    /// The `i`th export, oldest first.
    pub fn nth_oldest(&self, i: usize) -> Option<(usize, Header)> {
        let mut all = [(0usize, 0u64); SLOTS];
        let mut n = 0;
        for (slot, header) in self.headers.iter().enumerate() {
            if let Some(h) = header {
                all[n] = (slot, h.generation);
                n += 1;
            }
        }
        all[..n].sort_unstable_by_key(|&(_, generation)| generation);
        let (slot, _) = *all[..n].get(i)?;
        Some((slot, self.headers[slot]?))
    }

    /// The export holding sequence number `sequence`, if any.
    pub fn holding(&self, sequence: u64) -> Option<(usize, Header)> {
        self.headers.iter().enumerate().find_map(|(s, h)| h.filter(|h| h.first <= sequence && sequence < h.end).map(|h| (s, h)))
    }
}

fn word_bytes(words: &[u32], chunk: usize) -> [u8; CHUNK] {
    let mut out = [0u8; CHUNK];
    for (i, word) in words[chunk * CHUNK / 4..(chunk + 1) * CHUNK / 4].iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// Writes `words`, an audit sector the policy store offered, to the next slot, sealed, and records it in `index`. Gives
/// its header: the caller reports its `end` and `dropped` to the policy store.
pub fn write_export(disk: &mut impl Disk, sealer: &mut impl Sealer, index: &mut Index, words: &[u32]) -> Result<Header, Fail> {
    let (first, _, records, end_head) = verify_sector(words).map_err(|_| Fail::Corrupt)?;
    let (slot, generation, dropped) = index.next_slot();
    let header = Header { first, end: first + records, records, end_head, generation, dropped, words: words.len() as u64 };
    // The old header goes first, so the slot reads as empty until the new one is whole.
    index.headers[slot] = None;
    if !disk.write(slot_base(slot), &[0u8; SECTOR]) {
        return Err(Fail::Disk);
    }
    // The sealed pieces, packed, a disk sector at a time.
    let mut buffer = [0u8; SECTOR];
    let (mut filled, mut next_sector) = (0usize, slot_base(slot) + 1);
    for chunk in 0..CHUNKS {
        let (tag, sealed) = sealer
            .seal(&nonce(first, &end_head, chunk as u32), &aad(first, chunk as u32), &word_bytes(words, chunk))
            .ok_or(Fail::Sealing)?;
        for byte in sealed.iter().chain(tag.iter()) {
            buffer[filled] = *byte;
            filled += 1;
            if filled == SECTOR {
                if !disk.write(next_sector, &buffer) {
                    return Err(Fail::Disk);
                }
                (filled, next_sector) = (0, next_sector + 1);
            }
        }
    }
    if filled > 0 && !disk.write(next_sector, &buffer) {
        return Err(Fail::Disk);
    }
    let mut sector = [0u8; SECTOR];
    header.encode(&mut sector);
    if !disk.write(slot_base(slot), &sector) {
        return Err(Fail::Disk);
    }
    index.headers[slot] = Some(header);
    Ok(header)
}

/// Reads slot `slot`'s export into `words`, unsealing every piece and checking the whole sector against `header`.
pub fn read_export(
    disk: &mut impl Disk,
    sealer: &mut impl Sealer,
    slot: usize,
    header: &Header,
    words: &mut [u32],
) -> Result<(), Fail> {
    if header.words != words.len() as u64 || words.len() != EXPORT_SECTOR_WORDS {
        return Err(Fail::Corrupt);
    }
    let mut buffer = [0u8; SECTOR];
    let mut loaded = u64::MAX;
    let mut piece = [0u8; SEALED_CHUNK];
    for chunk in 0..CHUNKS {
        for (i, byte) in piece.iter_mut().enumerate() {
            let at = chunk * SEALED_CHUNK + i;
            let sector = slot_base(slot) + 1 + (at / SECTOR) as u64;
            if sector != loaded {
                if !disk.read(sector, &mut buffer) {
                    return Err(Fail::Disk);
                }
                loaded = sector;
            }
            *byte = buffer[at % SECTOR];
        }
        let (sealed, tag) = piece.split_at(CHUNK);
        let plain = sealer
            .open(
                &nonce(header.first, &header.end_head, chunk as u32),
                &aad(header.first, chunk as u32),
                tag.try_into().unwrap(),
                sealed.try_into().unwrap(),
            )
            .ok_or(Fail::Corrupt)?;
        for (i, word) in words[chunk * CHUNK / 4..(chunk + 1) * CHUNK / 4].iter_mut().enumerate() {
            *word = u32::from_le_bytes(plain[i * 4..i * 4 + 4].try_into().unwrap());
        }
    }
    let (first, _, records, end_head) = verify_sector(words).map_err(|_| Fail::Corrupt)?;
    if (first, records, end_head) != (header.first, header.records, header.end_head) {
        return Err(Fail::Corrupt);
    }
    Ok(())
}

/// Record `sequence` from an export already read and checked.
pub fn record(words: &[u32], sequence: u64) -> Option<AuditEntry> {
    sector_records(words).find(|&(s, _)| s == sequence).map(|(_, entry)| entry)
}

#[cfg(test)]
mod tests;
