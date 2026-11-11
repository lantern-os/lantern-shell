//! The audit log: a hash-chained, append-only record of the launch binder's decisions
//! ([RFC-0024](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0024-audit-log.md)) and of every use of a grant
//! ([RFC-0025](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0025-audit-log-service-operations.md)), in sectors 2 to 7 of the same
//! flash as the revocation log, beside the remembered decisions in sector 1.
//!
//! **Each sector is its own run of slots**, starting with a header: the sequence number of its first record and
//! the chain head before it. Slots follow the revocation log's rules (`lib.rs`): erased, a record, a tombstone,
//! or torn, and anything else is corrupt. A record is valid only if its sequence number and chain both follow
//! from the record before it, so an edit anywhere but the end breaks every later record, and reads as corrupt.
//!
//! **Retention.** When the active sector is full and the next one in the ring holds the oldest history, that
//! sector is erased, given a new header, and its first record is `RETIRED`, naming the last sequence number that
//! history held. Every interruption recovers on [`AuditLog::open`]: a sector half-erased or with a torn header,
//! next to a full active sector, is finished; an empty newest sector in a wrapped ring gets its `RETIRED`. A
//! reader verifies from the oldest surviving header, and nobody can verify what was retired.
//!
//! **What this detects and what it doesn't.** It detects accidental corruption, and any edit that doesn't
//! recompute the rest of the chain. The chain has no key, so someone who can write the flash can rewrite the
//! whole log consistently, or erase it, and only a head kept elsewhere ([`verify_prefix`]) reveals that, and
//! only while that head's history hasn't been retired. Resisting it needs a key held in hardware and a
//! monotonic counter: Phase 4, on RFC-0023's checklist.

use lantern_abi::policy::{event, AuditEntry};
use lantern_crypto::hash;

use crate::Flash;

const ERASED: u32 = u32::MAX;
const SLOT_WORDS: usize = 16;
const SECTOR_WORDS: usize = 0x4_0000 / 4;
/// Sectors 2 to 7 of the mapped megapage. Sector 0 is the revocation log's and sector 1 the remembered decisions'
/// ([RFC-0026](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0026-trusted-path-and-consent.md)), and retention never touches either.
pub const FIRST_SECTOR: usize = 2;
pub const LAST_SECTOR: usize = 7;
/// Records per sector: the header takes the first slot.
pub const SECTOR_SLOTS: usize = SECTOR_WORDS / SLOT_WORDS - 1;
/// `b"LNTNAUD3"`, then the format version. Format 3 starts at sector 2; earlier formats, which started at sector 1,
/// read as corrupt, rather than half-parsing.
const MAGIC: [u32; 3] = [0x4e54_4e4c, 0x3344_5541, 3];

type Slot = [u32; SLOT_WORDS];

/// The chain before the first record.
pub const GENESIS: [u8; 16] = [0; 16];

/// The next chain value: the first 128 bits of `BLAKE3(previous ‖ the record's hashed fields)`.
pub fn chain(previous: [u8; 16], entry: &AuditEntry, sequence: u64) -> [u8; 16] {
    let mut bytes = [0u8; 16 + 32];
    bytes[..16].copy_from_slice(&previous);
    for (i, word) in hashed_words(entry, sequence).iter().enumerate() {
        bytes[16 + i * 4..16 + i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    hash::hash(&bytes).as_bytes()[..16].try_into().unwrap()
}

fn hashed_words(entry: &AuditEntry, sequence: u64) -> [u32; 8] {
    let subject = entry.subject;
    [
        entry.event as u32 | (entry.reason as u32) << 8 | (entry.interface as u32) << 16 | (entry.slot as u32) << 24,
        entry.object as u32 | (entry.ops as u32) << 16,
        subject[0] as u32,
        (subject[0] >> 32) as u32,
        subject[1] as u32,
        (subject[1] >> 32) as u32,
        sequence as u32,
        (sequence >> 32) as u32,
    ]
}

fn entry_of(words: &Slot) -> (AuditEntry, u64) {
    let entry = AuditEntry {
        event: words[0] as u8,
        reason: (words[0] >> 8) as u8,
        interface: (words[0] >> 16) as u8,
        slot: (words[0] >> 24) as u8,
        object: words[1] as u16,
        ops: (words[1] >> 16) as u8,
        subject: [words[2] as u64 | (words[3] as u64) << 32, words[4] as u64 | (words[5] as u64) << 32],
    };
    (entry, words[6] as u64 | (words[7] as u64) << 32)
}

fn hash_words(hash: [u8; 16]) -> [u32; 4] {
    core::array::from_fn(|i| u32::from_le_bytes(hash[i * 4..i * 4 + 4].try_into().unwrap()))
}

fn words_hash(words: &[u32]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for i in 0..4 {
        out[i * 4..i * 4 + 4].copy_from_slice(&words[i].to_le_bytes());
    }
    out
}

fn record_for(entry: &AuditEntry, sequence: u64, chained: [u8; 16]) -> Slot {
    let mut words = [0u32; SLOT_WORDS];
    words[..8].copy_from_slice(&hashed_words(entry, sequence));
    words[8..12].copy_from_slice(&hash_words(chained));
    // Words 12 to 15 stay zero. The last is written last, which is how a torn record is told apart.
    words
}

fn header_for(first: u64, previous: [u8; 16]) -> Slot {
    let mut words = [0u32; SLOT_WORDS];
    words[..3].copy_from_slice(&MAGIC);
    words[3] = first as u32;
    words[4] = (first >> 32) as u32;
    words[5..9].copy_from_slice(&hash_words(previous));
    // Words 9 to 15 stay zero, and the last is written last, as for a record.
    words
}

/// A record whose sequence and chain follow from `(count, head)`, giving the new head.
fn follows(words: &Slot, count: u64, head: [u8; 16]) -> Option<(AuditEntry, [u8; 16])> {
    let (entry, sequence) = entry_of(words);
    let expected = chain(head, &entry, count);
    (sequence == count && words[12..] == [0; 4] && words_hash(&words[8..12]) == expected).then_some((entry, expected))
}

/// Where the log stands.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Head {
    /// The sector being appended to, and its first erased slot.
    pub sector: usize,
    pub next_slot: usize,
    /// How many records have ever been appended, retired ones included, and the chain's head.
    pub count: u64,
    pub head: [u8; 16],
    /// The first record still held, the chain head before it, and its sector. Everything before it is retired.
    pub oldest: u64,
    pub oldest_previous: [u8; 16],
    pub oldest_sector: usize,
}

/// Why the log can't be read or written. The binder declines every grant on it, and a service every operation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Corrupt;

/// What [`AuditLog::open`] has to finish, found by [`scan`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Pending {
    Nothing,
    /// Every sector is erased: open the first.
    Start,
    /// Opening this sector, the full newest one's neighbour, was interrupted: mid-erase, mid-header, or with the
    /// sector erased and no header yet. [`AuditLog::open`] erases it again and opens it, as a retirement if it was one.
    Reopen(usize),
    /// The newest sector was opened by retiring the one before it, but has no `RETIRED` yet.
    RecordRetired,
}

/// What [`scan`] found besides the head.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Scanned {
    pub head: Head,
    /// A torn last record, by sector and slot, for [`AuditLog::open`] to tombstone.
    pub torn: Option<(usize, usize)>,
    pub pending: Pending,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Erased,
    Header { first: u64, previous: [u8; 16] },
    Garbage,
}

/// Whether opening `sector` retires history: the sector after it already holds a later part of the chain. Before
/// the ring first wraps, the sector after the one being opened is erased, or is the first sector, from 0.
fn retires(kinds: &[Kind; LAST_SECTOR + 1], sector: usize) -> bool {
    matches!(kinds[ring_next(sector)], Kind::Header { first, .. } if first > 0)
}

fn ring_next(sector: usize) -> usize {
    if sector == LAST_SECTOR { FIRST_SECTOR } else { sector + 1 }
}

fn classify<F: Flash>(flash: &F, sector: usize) -> Kind {
    let header = read_slot(flash, sector_word(sector));
    if header == [ERASED; SLOT_WORDS] {
        return if words_erased(flash, sector_word(sector) + SLOT_WORDS, sector_word(sector + 1)) {
            Kind::Erased
        } else {
            Kind::Garbage
        };
    }
    if header[..3] == MAGIC && header[9..] == [0; 7] {
        Kind::Header { first: header[3] as u64 | (header[4] as u64) << 32, previous: words_hash(&header[5..9]) }
    } else {
        Kind::Garbage
    }
}

/// Reads and checks the whole log without writing anything. `on_record` sees each surviving record in order,
/// with its sequence number.
pub fn scan<F: Flash>(flash: &F, mut on_record: impl FnMut(u64, &AuditEntry)) -> Result<Scanned, Corrupt> {
    let kinds: [Kind; LAST_SECTOR + 1] =
        core::array::from_fn(|sector| if sector < FIRST_SECTOR { Kind::Erased } else { classify(flash, sector) });
    let headers = || {
        (FIRST_SECTOR..=LAST_SECTOR).filter_map(|s| match kinds[s] {
            Kind::Header { first, .. } => Some((s, first)),
            _ => None,
        })
    };
    let Some((oldest_sector, _)) = headers().min_by_key(|&(_, first)| first) else {
        // Nothing has ever been written, or something that isn't this log has.
        return if kinds.iter().all(|&kind| kind == Kind::Erased) {
            let head = Head {
                sector: FIRST_SECTOR,
                next_slot: 0,
                count: 0,
                head: GENESIS,
                oldest: 0,
                oldest_previous: GENESIS,
                oldest_sector: FIRST_SECTOR,
            };
            Ok(Scanned { head, torn: None, pending: Pending::Start })
        } else {
            Err(Corrupt)
        };
    };
    let Kind::Header { first: oldest, previous: oldest_previous } = kinds[oldest_sector] else { unreachable!() };
    if oldest == 0 && oldest_previous != GENESIS {
        return Err(Corrupt);
    }

    // The headers have to be one run around the ring from the oldest, each continuing the chain where the last
    // left off, and every sector but the newest full.
    let valid = headers().count();
    let (mut count, mut head) = (oldest, oldest_previous);
    let mut sector = oldest_sector;
    let mut torn = None;
    let mut next_slot = 0;
    let mut newest_records = 0;
    for run in 0..valid {
        let Kind::Header { first, previous } = kinds[sector] else { return Err(Corrupt) };
        if (first, previous) != (count, head) {
            return Err(Corrupt);
        }
        let newest = run == valid - 1;
        next_slot = SECTOR_SLOTS;
        newest_records = 0;
        for slot in 0..SECTOR_SLOTS {
            let words = read_slot(flash, slot_word(sector, slot));
            if words == [ERASED; SLOT_WORDS] {
                if !newest || !slots_erased(flash, sector, slot) {
                    return Err(Corrupt);
                }
                next_slot = slot;
                break;
            }
            if words == [0; SLOT_WORDS] {
                continue;
            }
            if let Some((entry, chained)) = follows(&words, count, head) {
                on_record(count, &entry);
                (count, head) = (count + 1, chained);
                newest_records += 1;
            } else if newest && words[SLOT_WORDS - 1] == ERASED && slots_erased(flash, sector, slot + 1) {
                torn = Some((sector, slot));
            } else {
                return Err(Corrupt);
            }
        }
        if !newest {
            sector = ring_next(sector);
        }
    }

    // Everything after the newest, up to the oldest, is free: erased, except that a full newest sector's
    // neighbour may be mid-opening. An erased neighbour whose own neighbour holds retired-from history was
    // being retired: it has to be reopened now, or its `RETIRED` would never be written.
    let mut pending = Pending::Nothing;
    let mut free = ring_next(sector);
    while free != oldest_sector {
        let beside_full = free == ring_next(sector) && next_slot == SECTOR_SLOTS;
        match kinds[free] {
            Kind::Garbage if beside_full => pending = Pending::Reopen(free),
            Kind::Erased if beside_full && retires(&kinds, free) => pending = Pending::Reopen(free),
            Kind::Erased => {}
            _ => return Err(Corrupt),
        }
        free = ring_next(free);
    }
    // A newest sector opened by retiring has `RETIRED` as its first record. The first time the ring fills, it
    // fills without retiring anything.
    if valid > 1 && retires(&kinds, sector) && newest_records == 0 && pending == Pending::Nothing {
        pending = Pending::RecordRetired;
    }
    let head = Head { sector, next_slot, count, head, oldest, oldest_previous, oldest_sector };
    Ok(Scanned { head, torn, pending })
}

/// Whether a head kept from earlier still matches, now that some history may be retired.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kept {
    Matches,
    Differs,
    /// The kept position is before the oldest surviving record: retired, so nobody can check it.
    Retired,
}

/// Checks a head kept from earlier, as `(count, head)`, against the log, recomputing from the oldest surviving
/// header rather than from genesis.
pub fn verify_prefix<F: Flash>(flash: &F, count: u64, kept: [u8; 16]) -> Result<Kept, Corrupt> {
    let state = scan(flash, |_, _| {})?.head;
    if count < state.oldest {
        return Ok(Kept::Retired);
    }
    if count > state.count {
        return Ok(Kept::Differs);
    }
    let mut head = state.oldest_previous;
    scan(flash, |sequence, entry| {
        if sequence < count {
            head = chain(head, entry, sequence);
        }
    })?;
    Ok(if head == kept { Kept::Matches } else { Kept::Differs })
}

pub struct AuditLog<F> {
    flash: F,
    state: Option<Head>,
}

impl<F: Flash> AuditLog<F> {
    /// Opens the log, finishes whatever a power cut interrupted, and appends `BOOT`.
    pub fn open(flash: F) -> Self {
        let mut log = Self { flash, state: None };
        if let Ok(scanned) = scan(&log.flash, |_, _| {}) {
            let torn_ok = scanned.torn.is_none_or(|(sector, slot)| log.write(slot_word(sector, slot), &[0; SLOT_WORDS]));
            if torn_ok {
                log.state = Some(scanned.head);
                let finished = match scanned.pending {
                    Pending::Nothing => Ok(()),
                    Pending::Start => log.open_sector(FIRST_SECTOR),
                    Pending::Reopen(sector) => log.reopen(sector),
                    Pending::RecordRetired => log.append_retired(),
                };
                if finished.is_err() {
                    log.state = None;
                }
            }
        }
        let _ = log.append(&AuditEntry { event: event::BOOT, ..AuditEntry::default() });
        log
    }

    pub fn head(&self) -> Result<Head, Corrupt> {
        self.state.ok_or(Corrupt)
    }

    /// Appends a record, retiring the oldest sector first if there's no room. Only `Ok` means it's on flash.
    pub fn append(&mut self, entry: &AuditEntry) -> Result<(), Corrupt> {
        let state = self.state.ok_or(Corrupt)?;
        if state.next_slot == SECTOR_SLOTS {
            let next = ring_next(state.sector);
            let advanced = if next == state.oldest_sector { self.reopen(next) } else { self.open_sector(next) };
            if advanced.is_err() {
                self.state = None;
                return Err(Corrupt);
            }
        }
        self.write_record(entry)
    }

    /// The record with sequence number `index`, if it's still held.
    pub fn read(&self, index: u64) -> Result<Option<AuditEntry>, Corrupt> {
        let state = self.state.ok_or(Corrupt)?;
        if index < state.oldest || index >= state.count {
            return Ok(None);
        }
        // The sector holding it is the last, going round from the oldest, whose first record is at or before it.
        let mut sector = state.oldest_sector;
        let mut first = state.oldest;
        loop {
            let next = ring_next(sector);
            if sector == state.sector {
                break;
            }
            match classify_header(&self.flash, next) {
                Some(next_first) if next_first <= index => (sector, first) = (next, next_first),
                Some(_) => break,
                None => return Err(Corrupt),
            }
        }
        let mut sequence = first;
        for slot in 0..SECTOR_SLOTS {
            // A record's first word is never zero, since its event isn't, and a tombstone's is.
            if self.flash.read(slot_word(sector, slot)) == 0 {
                continue;
            }
            if sequence == index {
                return Ok(Some(entry_of(&read_slot(&self.flash, slot_word(sector, slot))).0));
            }
            sequence += 1;
        }
        Err(Corrupt)
    }

    fn write_record(&mut self, entry: &AuditEntry) -> Result<(), Corrupt> {
        let state = self.state.ok_or(Corrupt)?;
        let chained = chain(state.head, entry, state.count);
        let word = slot_word(state.sector, state.next_slot);
        if self.write(word, &record_for(entry, state.count, chained)) {
            self.state = Some(Head { next_slot: state.next_slot + 1, count: state.count + 1, head: chained, ..state });
            Ok(())
        } else {
            let tombstoned = self.write(word, &[0; SLOT_WORDS]);
            self.state = tombstoned.then_some(Head { next_slot: state.next_slot + 1, ..state });
            Err(Corrupt)
        }
    }

    /// Opens an erased sector to continue the chain.
    fn open_sector(&mut self, sector: usize) -> Result<(), Corrupt> {
        let state = self.state.ok_or(Corrupt)?;
        if !self.write(sector_word(sector), &header_for(state.count, state.head)) {
            return Err(Corrupt);
        }
        self.state = Some(Head { sector, next_slot: 0, ..state });
        Ok(())
    }

    /// Erases `sector` and continues the chain in it. If that retires history, which it does whenever `sector`
    /// was the oldest, the oldest becomes the sector after it, and the first record is `RETIRED`.
    fn reopen(&mut self, sector: usize) -> Result<(), Corrupt> {
        let mut kinds = [Kind::Erased; LAST_SECTOR + 1];
        kinds[ring_next(sector)] = classify(&self.flash, ring_next(sector));
        self.flash.erase_sector(sector_word(sector), SECTOR_WORDS);
        if !words_erased(&self.flash, sector_word(sector), sector_word(sector + 1)) {
            return Err(Corrupt);
        }
        self.open_sector(sector)?;
        if !retires(&kinds, sector) {
            return Ok(());
        }
        let state = self.state.ok_or(Corrupt)?;
        let Kind::Header { first, previous } = kinds[ring_next(sector)] else { return Err(Corrupt) };
        self.state = Some(Head { oldest: first, oldest_previous: previous, oldest_sector: ring_next(sector), ..state });
        self.append_retired()
    }

    fn append_retired(&mut self) -> Result<(), Corrupt> {
        let state = self.state.ok_or(Corrupt)?;
        let retired =
            AuditEntry { event: event::RETIRED, slot: state.sector as u8, subject: [state.oldest - 1, 0], ..AuditEntry::default() };
        // A failure here leaves the newest sector without `RETIRED`. Failing closed means the next open, which
        // sees that, writes it.
        self.write_record(&retired).inspect_err(|_| self.state = None)
    }

    fn write(&mut self, first: usize, words: &Slot) -> bool {
        for (i, &word) in words.iter().enumerate() {
            self.flash.program(first + i, word);
        }
        read_slot(&self.flash, first) == *words
    }
}

fn classify_header<F: Flash>(flash: &F, sector: usize) -> Option<u64> {
    let header = read_slot(flash, sector_word(sector));
    (header[..3] == MAGIC && header[9..] == [0; 7]).then(|| header[3] as u64 | (header[4] as u64) << 32)
}

fn sector_word(sector: usize) -> usize {
    sector * SECTOR_WORDS
}

fn slot_word(sector: usize, slot: usize) -> usize {
    sector_word(sector) + (slot + 1) * SLOT_WORDS
}

fn read_slot<F: Flash>(flash: &F, first: usize) -> Slot {
    core::array::from_fn(|i| flash.read(first + i))
}

fn slots_erased<F: Flash>(flash: &F, sector: usize, from_slot: usize) -> bool {
    words_erased(flash, slot_word(sector, from_slot), sector_word(sector + 1))
}

fn words_erased<F: Flash>(flash: &F, from: usize, to: usize) -> bool {
    (from..to).all(|word| flash.read(word) == ERASED)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::FakeFlash;
    use lantern_abi::policy::reason;

    const MEGAPAGE_WORDS: usize = 0x20_0000 / 4;
    const CAPACITY: usize = SECTOR_SLOTS * (LAST_SECTOR - FIRST_SECTOR + 1);

    fn flash() -> FakeFlash {
        FakeFlash::erased_words(MEGAPAGE_WORDS)
    }

    fn granting(slot: u8) -> AuditEntry {
        AuditEntry { event: event::GRANTING, interface: 1, slot, object: 7, ops: 4, subject: [9, 10], ..AuditEntry::default() }
    }

    fn events<F: Flash>(flash: &F) -> Vec<(u8, u8)> {
        let mut out = Vec::new();
        scan(flash, |_, entry| out.push((entry.event, entry.slot))).unwrap();
        out
    }

    /// Appends until the active sector is `sector` with `free` slots left.
    fn fill_to(log: &mut AuditLog<FakeFlash>, sector: usize, free: usize) {
        while {
            let head = log.head().unwrap();
            head.sector != sector || SECTOR_SLOTS - head.next_slot != free
        } {
            log.append(&granting(0)).unwrap();
        }
    }

    fn verify_all<F: Flash>(flash: &F) -> Head {
        let scanned = scan(flash, |_, _| {}).unwrap();
        assert_eq!(scanned.pending, Pending::Nothing);
        scanned.head
    }

    #[test]
    fn a_blank_log_gets_a_header_and_a_boot_record() {
        let flash = flash();
        let log = AuditLog::open(flash.clone());
        assert_eq!(log.head().unwrap().count, 1);
        assert_eq!(log.read(0), Ok(Some(AuditEntry { event: event::BOOT, ..AuditEntry::default() })));
        assert_eq!(events(&flash), vec![(event::BOOT, 0)]);
    }

    #[test]
    fn records_survive_a_reboot_in_order_and_each_boot_is_marked() {
        let flash = flash();
        let mut log = AuditLog::open(flash.clone());
        log.append(&granting(0)).unwrap();
        log.append(&AuditEntry { event: event::DECLINED, reason: reason::NOT_IN_POLICY, ..granting(1) }).unwrap();
        let head = log.head().unwrap();

        let log = AuditLog::open(flash.clone());
        assert_eq!(log.head().unwrap().count, head.count + 1);
        assert_eq!(events(&flash), vec![(event::BOOT, 0), (event::GRANTING, 0), (event::DECLINED, 1), (event::BOOT, 0)]);
        assert_eq!(log.read(2).unwrap().unwrap().reason, reason::NOT_IN_POLICY);
        assert_eq!(log.read(4), Ok(None));
    }

    #[test]
    fn the_head_is_the_chain_over_every_record() {
        let flash = flash();
        let mut log = AuditLog::open(flash.clone());
        log.append(&granting(0)).unwrap();
        let mut head = GENESIS;
        for index in 0..2 {
            head = chain(head, &log.read(index).unwrap().unwrap(), index);
        }
        assert_eq!(log.head().unwrap().head, head);
    }

    #[test]
    fn the_subject_is_hashed_and_read_back_whole() {
        let flash = flash();
        let mut log = AuditLog::open(flash.clone());
        let using = AuditEntry { event: event::USING, subject: [u64::MAX - 1, 1 << 40], ..granting(3) };
        log.append(&using).unwrap();
        assert_eq!(log.read(1), Ok(Some(using)));
        assert_ne!(chain(GENESIS, &using, 1), chain(GENESIS, &AuditEntry { subject: [u64::MAX - 1, 0], ..using }, 1));
    }

    #[test]
    fn editing_any_byte_of_any_record_but_the_last_is_corrupt() {
        let flash = flash();
        let mut log = AuditLog::open(flash.clone());
        log.append(&granting(0)).unwrap();
        log.append(&granting(1)).unwrap();
        for slot in 0..2 {
            for word in 0..SLOT_WORDS {
                let copy = flash.deep_copy();
                let at = slot_word(FIRST_SECTOR, slot) + word;
                copy.poke(at, copy.read(at) ^ 0x100);
                assert_eq!(scan(&copy, |_, _| {}).map(|_| ()), Err(Corrupt), "slot {slot} word {word}");
                assert_eq!(AuditLog::open(copy).head(), Err(Corrupt));
            }
        }
    }

    #[test]
    fn editing_any_word_of_a_header_is_corrupt() {
        let flash = flash();
        let mut log = AuditLog::open(flash.clone());
        log.append(&granting(0)).unwrap();
        for word in 0..SLOT_WORDS {
            let copy = flash.deep_copy();
            let at = sector_word(FIRST_SECTOR) + word;
            copy.poke(at, copy.read(at) ^ 0x100);
            assert_eq!(AuditLog::open(copy).head(), Err(Corrupt), "word {word}");
        }
    }

    #[test]
    fn a_flipped_bit_in_the_last_record_is_corrupt_not_torn() {
        for word in 0..SLOT_WORDS {
            let flash = flash();
            let mut log = AuditLog::open(flash.clone());
            log.append(&granting(0)).unwrap();
            let at = slot_word(FIRST_SECTOR, 1) + word;
            flash.poke(at, flash.read(at) ^ 1);
            assert_eq!(AuditLog::open(flash).head(), Err(Corrupt), "word {word}");
        }
    }

    #[test]
    fn a_power_cut_mid_append_is_never_acknowledged_and_the_chain_continues() {
        for words in 0..SLOT_WORDS {
            let flash = flash();
            let mut log = AuditLog::open(flash.clone());
            flash.lose_power_after(words);
            assert_eq!(log.append(&granting(0)), Err(Corrupt), "{words} words");
            flash.power_back();

            let mut log = AuditLog::open(flash.clone());
            log.append(&granting(1)).unwrap();
            assert_eq!(events(&flash), vec![(event::BOOT, 0), (event::BOOT, 0), (event::GRANTING, 1)], "{words} words");
        }
    }

    #[test]
    fn a_consistent_rewrite_is_accepted_but_a_kept_head_reveals_it() {
        let flash = flash();
        let mut log = AuditLog::open(flash.clone());
        log.append(&granting(0)).unwrap();
        let kept = log.head().unwrap();

        // Rewrite from outside: erase everything, then replay the log without the grant.
        let forged = self::flash();
        let mut rewriter = AuditLog::open(forged.clone());
        rewriter.append(&AuditEntry { event: event::DECLINED, ..granting(0) }).unwrap();

        assert!(AuditLog::open(forged.clone()).head().is_ok(), "the known limit: nothing in the log shows it");
        assert_eq!(verify_prefix(&forged, kept.count, kept.head), Ok(Kept::Differs));
        assert_eq!(verify_prefix(&flash, kept.count, kept.head), Ok(Kept::Matches));
    }

    #[test]
    fn all_zeros_is_corrupt_which_is_what_no_flash_looks_like() {
        let flash = flash();
        for word in 0..MEGAPAGE_WORDS {
            flash.poke(word, 0);
        }
        let mut log = AuditLog::open(flash);
        assert_eq!(log.head(), Err(Corrupt));
        assert_eq!(log.append(&granting(0)), Err(Corrupt));
    }

    #[test]
    fn an_earlier_format_is_corrupt_not_half_read() {
        // Format 1's single header, and format 2's sector header, which started the ring at sector 1.
        for old in [[0x4e54_4e4c, 0x3144_5541, 1], [0x4e54_4e4c, 0x3244_5541, 2]] {
            let flash = flash();
            for (i, word) in old.into_iter().chain([0; 13]).enumerate() {
                flash.poke(sector_word(FIRST_SECTOR) + i, word);
            }
            assert_eq!(AuditLog::open(flash).head(), Err(Corrupt), "{old:x?}");
        }
    }

    #[test]
    fn a_full_sector_opens_the_next_and_the_chain_runs_across() {
        let flash = flash();
        let mut log = AuditLog::open(flash.clone());
        fill_to(&mut log, FIRST_SECTOR, 0);
        log.append(&granting(1)).unwrap();
        let head = log.head().unwrap();
        assert_eq!((head.sector, head.next_slot, head.count), (FIRST_SECTOR + 1, 1, SECTOR_SLOTS as u64 + 1));
        assert_eq!(log.read(SECTOR_SLOTS as u64).unwrap().unwrap().slot, 1);
        assert_eq!(verify_all(&flash).head, head.head);
        assert_eq!(AuditLog::open(flash.clone()).head().unwrap().count, head.count + 1);
    }

    #[test]
    fn a_full_ring_retires_the_oldest_sector_and_records_it_first() {
        let flash = flash();
        let mut log = AuditLog::open(flash.clone());
        fill_to(&mut log, LAST_SECTOR, 0);
        assert_eq!(log.head().unwrap().count, CAPACITY as u64);
        log.append(&granting(1)).unwrap();

        let head = log.head().unwrap();
        assert_eq!((head.sector, head.oldest_sector, head.oldest), (FIRST_SECTOR, FIRST_SECTOR + 1, SECTOR_SLOTS as u64));
        assert_eq!(head.count, CAPACITY as u64 + 2, "RETIRED, then the record");
        let retired = log.read(CAPACITY as u64).unwrap().unwrap();
        assert_eq!((retired.event, retired.slot, retired.subject), (event::RETIRED, FIRST_SECTOR as u8, [SECTOR_SLOTS as u64 - 1, 0]));
        assert_eq!(log.read(0), Ok(None), "retired");
        assert_eq!(log.read(SECTOR_SLOTS as u64 - 1), Ok(None), "retired");
        assert!(log.read(SECTOR_SLOTS as u64).unwrap().is_some());
        assert_eq!(verify_all(&flash), head);

        // And again, round the ring: sector 1 fills, and sector 2 is the next oldest.
        fill_to(&mut log, FIRST_SECTOR, 0);
        log.append(&granting(2)).unwrap();
        let head = log.head().unwrap();
        assert_eq!((head.sector, head.oldest_sector), (FIRST_SECTOR + 1, FIRST_SECTOR + 2));
        assert_eq!(verify_all(&flash), head);
        assert_eq!(AuditLog::open(flash.clone()).head().unwrap().count, head.count + 1);
    }

    #[test]
    fn a_power_cut_anywhere_in_a_retirement_recovers_on_the_next_open() {
        let template = flash();
        let mut log = AuditLog::open(template.clone());
        fill_to(&mut log, LAST_SECTOR, 0);
        let before = log.head().unwrap();
        // Erase, then 16 header words, then 16 RETIRED words, then 16 of the record. Cut at a spread of points.
        let mut cuts: Vec<usize> = (0..SLOT_WORDS * 3 + 2).collect();
        cuts.extend([SECTOR_WORDS / 2, SECTOR_WORDS - 1].iter().copied());
        cuts.extend((0..SLOT_WORDS * 3).map(|w| SECTOR_WORDS + w));
        for cut in cuts {
            let flash = template.deep_copy();
            let mut log = AuditLog { flash: flash.clone(), state: Some(before) };
            flash.lose_power_after(cut);
            let _ = log.append(&granting(1));
            flash.power_back();

            let reopened = AuditLog::open(flash.clone());
            let head = reopened.head().unwrap_or_else(|_| panic!("cut at {cut}"));
            assert_eq!((head.sector, head.oldest_sector), (FIRST_SECTOR, FIRST_SECTOR + 1), "cut at {cut}");
            let after = verify_all(&flash);
            let mut seen = Vec::new();
            scan(&flash, |sequence, entry| {
                if sequence >= CAPACITY as u64 {
                    seen.push(entry.event)
                }
            })
            .unwrap();
            assert_eq!(seen.first(), Some(&event::RETIRED), "cut at {cut}: {seen:?}");
            assert_eq!(seen.last(), Some(&event::BOOT), "cut at {cut}: {seen:?}");
            assert_eq!(seen.iter().filter(|&&e| e == event::RETIRED).count(), 1, "cut at {cut}");
            assert_eq!(after.count, head.count, "cut at {cut}");
        }
    }

    #[test]
    fn a_power_cut_opening_a_fresh_sector_reopens_it_without_retiring_anything() {
        let template = flash();
        let mut log = AuditLog::open(template.clone());
        fill_to(&mut log, LAST_SECTOR - 1, 0);
        let before = log.head().unwrap();
        for cut in 0..SLOT_WORDS * 2 {
            let flash = template.deep_copy();
            let mut log = AuditLog { flash: flash.clone(), state: Some(before) };
            flash.lose_power_after(cut);
            let _ = log.append(&granting(1));
            flash.power_back();

            let head = AuditLog::open(flash.clone()).head().unwrap_or_else(|_| panic!("cut at {cut}"));
            assert_eq!((head.sector, head.oldest, head.oldest_sector), (LAST_SECTOR, 0, FIRST_SECTOR), "cut at {cut}");
            assert!(!events(&flash).iter().any(|&(e, _)| e == event::RETIRED), "cut at {cut}");
            assert_eq!(verify_all(&flash), head, "cut at {cut}");
        }
    }

    #[test]
    fn garbage_anywhere_but_beside_a_full_sector_is_corrupt() {
        let flash = flash();
        let mut log = AuditLog::open(flash.clone());
        log.append(&granting(0)).unwrap();
        // The neighbour of a sector that isn't full.
        let copy = flash.deep_copy();
        copy.poke(sector_word(FIRST_SECTOR + 1) + 100, 0);
        assert_eq!(AuditLog::open(copy).head(), Err(Corrupt));
        // A free sector further on.
        let copy = flash.deep_copy();
        copy.poke(sector_word(FIRST_SECTOR + 3), 0);
        assert_eq!(AuditLog::open(copy).head(), Err(Corrupt));
    }

    #[test]
    fn sectors_out_of_ring_order_are_corrupt() {
        let flash = flash();
        let mut log = AuditLog::open(flash.clone());
        fill_to(&mut log, FIRST_SECTOR + 1, SECTOR_SLOTS - 1);
        // Move sector 2 to sector 4.
        let copy = flash.deep_copy();
        for word in 0..SECTOR_WORDS {
            copy.poke(sector_word(FIRST_SECTOR + 3) + word, flash.read(sector_word(FIRST_SECTOR + 1) + word));
            copy.poke(sector_word(FIRST_SECTOR + 1) + word, ERASED);
        }
        assert_eq!(AuditLog::open(copy).head(), Err(Corrupt));
    }

    #[test]
    fn a_kept_head_from_before_a_retirement_is_reported_retired() {
        let flash = flash();
        let mut log = AuditLog::open(flash.clone());
        log.append(&granting(0)).unwrap();
        let early = log.head().unwrap();
        fill_to(&mut log, FIRST_SECTOR + 2, 0);
        let later = log.head().unwrap();
        fill_to(&mut log, LAST_SECTOR, 0);
        log.append(&granting(1)).unwrap();
        assert_eq!(verify_prefix(&flash, early.count, early.head), Ok(Kept::Retired));
        assert_eq!(verify_prefix(&flash, later.count, later.head), Ok(Kept::Matches));
        assert_eq!(verify_prefix(&flash, later.count, early.head), Ok(Kept::Differs));
    }

    #[test]
    fn the_audit_log_and_the_revocation_log_dont_overlap_even_after_retiring() {
        let flash = flash();
        crate::Log::open(flash.clone()).record([1, 2]).unwrap();
        let mut log = AuditLog::open(flash.clone());
        fill_to(&mut log, LAST_SECTOR, 0);
        log.append(&granting(0)).unwrap();
        assert_eq!(crate::Log::open(flash.clone()).is_revoked([1, 2]), Ok(true));
        assert_eq!(log.head().unwrap().sector, FIRST_SECTOR);
    }
}
