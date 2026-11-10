//! [RFC-0024](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0024-audit-log.md)'s audit log: a hash-chained, append-only
//! record of the launch binder's decisions, in sectors 1 to 7 of the same flash as the revocation log.
//!
//! Slots follow the revocation log's rules (`lib.rs`): erased, a record, a tombstone, or torn, and anything
//! else is corrupt. A record is valid only if its sequence number and chain both follow from the record
//! before it, so an edit anywhere but the end breaks every later record, and reads as corrupt.
//!
//! **What this detects and what it doesn't.** It detects accidental corruption, and any edit that doesn't
//! recompute the rest of the chain. The chain has no key, so someone who can write the flash can rewrite the
//! whole log consistently, or erase it, and only a head kept elsewhere ([`verify_prefix`]) reveals that.
//! Resisting it needs a key held in hardware and a monotonic counter: Phase 4, on RFC-0023's checklist.

use lantern_abi::policy::{event, AuditEntry, RevocationKey};
use lantern_crypto::hash;

use crate::Flash;

const ERASED: u32 = u32::MAX;
const SLOT_WORDS: usize = 16;
/// Sectors 1 to 7 of the mapped megapage.
const FIRST_WORD: usize = 0x4_0000 / 4;
const END_WORD: usize = 0x20_0000 / 4;
/// The header takes the first slot.
pub const SLOTS: usize = (END_WORD - FIRST_WORD) / SLOT_WORDS - 1;
/// `b"LNTNAUD1"`, then a format version. The rest of the header is zero.
const HEADER: [u32; SLOT_WORDS] = [0x4e54_4e4c, 0x3144_5541, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

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
    let key = entry.key;
    [
        entry.event as u32 | (entry.reason as u32) << 8 | (entry.interface as u32) << 16 | (entry.slot as u32) << 24,
        entry.object as u32 | (entry.ops as u32) << 16,
        key[0] as u32,
        (key[0] >> 32) as u32,
        key[1] as u32,
        (key[1] >> 32) as u32,
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
        key: [words[2] as u64 | (words[3] as u64) << 32, words[4] as u64 | (words[5] as u64) << 32] as RevocationKey,
    };
    (entry, words[6] as u64 | (words[7] as u64) << 32)
}

fn chain_of(words: &Slot) -> [u8; 16] {
    let mut out = [0u8; 16];
    for i in 0..4 {
        out[i * 4..i * 4 + 4].copy_from_slice(&words[8 + i].to_le_bytes());
    }
    out
}

fn record_for(entry: &AuditEntry, sequence: u64, chained: [u8; 16]) -> Slot {
    let mut words = [0u32; SLOT_WORDS];
    words[..8].copy_from_slice(&hashed_words(entry, sequence));
    for i in 0..4 {
        words[8 + i] = u32::from_le_bytes(chained[i * 4..i * 4 + 4].try_into().unwrap());
    }
    // Words 12 to 15 stay zero. The last is written last, which is how a torn record is told apart.
    words
}

/// A record whose sequence and chain follow from `(count, head)`, giving the new pair.
fn follows(words: &Slot, count: u64, head: [u8; 16]) -> Option<(AuditEntry, [u8; 16])> {
    let (entry, sequence) = entry_of(words);
    let expected = chain(head, &entry, count);
    (sequence == count && words[12..] == [0; 4] && chain_of(words) == expected).then_some((entry, expected))
}

/// Where the log stands: the first erased slot, how many records, and the chain's head.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Head {
    pub next_slot: usize,
    pub count: u64,
    pub head: [u8; 16],
}

/// Why the log can't be read or written. The binder declines every grant on it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Corrupt;

/// Reads and checks the whole log without writing anything. `on_record` sees each record in order.
/// A torn last record is reported as `torn`, for [`AuditLog::open`] to tombstone.
pub fn scan<F: Flash>(flash: &F, mut on_record: impl FnMut(u64, &AuditEntry)) -> Result<(Head, Option<usize>), Corrupt> {
    let header = read_slot(flash, FIRST_WORD);
    let mut state = Head { next_slot: 0, count: 0, head: GENESIS };
    if header == [ERASED; SLOT_WORDS] {
        return if erased_from(flash, 0) { Ok((state, None)) } else { Err(Corrupt) };
    }
    if header != HEADER {
        return Err(Corrupt);
    }
    let mut torn = None;
    while state.next_slot < SLOTS {
        let words = read_slot(flash, slot_word(state.next_slot));
        if words == [ERASED; SLOT_WORDS] {
            break;
        }
        if words == [0; SLOT_WORDS] {
            state.next_slot += 1;
        } else if let Some((entry, head)) = follows(&words, state.count, state.head) {
            on_record(state.count, &entry);
            state = Head { next_slot: state.next_slot + 1, count: state.count + 1, head };
        } else if words[SLOT_WORDS - 1] == ERASED && erased_from(flash, state.next_slot + 1) {
            torn = Some(state.next_slot);
            state.next_slot += 1;
        } else {
            return Err(Corrupt);
        }
    }
    if erased_from(flash, state.next_slot) {
        Ok((state, torn))
    } else {
        Err(Corrupt)
    }
}

/// Whether the first `count` records of the log on `flash` still chain to `kept`, a head recorded
/// earlier. This is what reveals a log rewritten consistently from outside.
pub fn verify_prefix<F: Flash>(flash: &F, count: u64, kept: [u8; 16]) -> Result<bool, Corrupt> {
    let mut head = GENESIS;
    let (state, _) = scan(flash, |sequence, entry| {
        if sequence < count {
            head = chain(head, entry, sequence);
        }
    })?;
    Ok(state.count >= count && head == kept)
}

pub struct AuditLog<F> {
    flash: F,
    state: Option<Head>,
}

impl<F: Flash> AuditLog<F> {
    /// Checks the whole log, writes a header to a blank one, tombstones a torn record, then records `BOOT`.
    pub fn open(flash: F) -> Self {
        let mut log = Self { flash, state: None };
        if let Ok((state, torn)) = scan(&log.flash, |_, _| {}) {
            let header_ok = state.count != 0 || state.next_slot != 0 || read_slot(&log.flash, FIRST_WORD) == HEADER || log.write(FIRST_WORD, &HEADER);
            let torn_ok = torn.is_none_or(|slot| log.write(slot_word(slot), &[0; SLOT_WORDS]));
            if header_ok && torn_ok {
                log.state = Some(state);
            }
        }
        let _ = log.append(&AuditEntry { event: event::BOOT, ..AuditEntry::default() });
        log
    }

    /// Where the log stands, if it can be trusted.
    pub fn head(&self) -> Result<Head, Corrupt> {
        self.state.ok_or(Corrupt)
    }

    /// Appends `entry` and reads it back. A failed write is tombstoned so the log stays readable.
    pub fn append(&mut self, entry: &AuditEntry) -> Result<(), Corrupt> {
        let state = self.state.ok_or(Corrupt)?;
        if state.next_slot >= SLOTS {
            return Err(Corrupt);
        }
        let chained = chain(state.head, entry, state.count);
        let word = slot_word(state.next_slot);
        if self.write(word, &record_for(entry, state.count, chained)) {
            self.state = Some(Head { next_slot: state.next_slot + 1, count: state.count + 1, head: chained });
            Ok(())
        } else {
            let tombstoned = self.write(word, &[0; SLOT_WORDS]);
            self.state = tombstoned.then_some(Head { next_slot: state.next_slot + 1, ..state });
            Err(Corrupt)
        }
    }

    /// The record at `index`, counting records only.
    pub fn read(&self, index: u64) -> Result<Option<AuditEntry>, Corrupt> {
        let state = self.state.ok_or(Corrupt)?;
        if index >= state.count {
            return Ok(None);
        }
        let mut count = 0;
        for slot in 0..state.next_slot {
            let words = read_slot(&self.flash, slot_word(slot));
            if words == [0; SLOT_WORDS] {
                continue;
            }
            if count == index {
                return Ok(Some(entry_of(&words).0));
            }
            count += 1;
        }
        Err(Corrupt)
    }

    fn write(&mut self, first: usize, words: &Slot) -> bool {
        for (i, &word) in words.iter().enumerate() {
            self.flash.program(first + i, word);
        }
        read_slot(&self.flash, first) == *words
    }
}

fn slot_word(slot: usize) -> usize {
    FIRST_WORD + (slot + 1) * SLOT_WORDS
}

fn read_slot<F: Flash>(flash: &F, first: usize) -> Slot {
    core::array::from_fn(|i| flash.read(first + i))
}

fn erased_from<F: Flash>(flash: &F, slot: usize) -> bool {
    (slot..SLOTS).all(|slot| read_slot(flash, slot_word(slot)) == [ERASED; SLOT_WORDS])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::FakeFlash;
    use lantern_abi::policy::reason;

    const MEGAPAGE_WORDS: usize = 0x20_0000 / 4;

    fn flash() -> FakeFlash {
        FakeFlash::erased_words(MEGAPAGE_WORDS)
    }

    fn granting(slot: u8) -> AuditEntry {
        AuditEntry { event: event::GRANTING, interface: 1, slot, object: 7, ops: 4, key: [9, 10], ..AuditEntry::default() }
    }

    fn events<F: Flash>(flash: &F) -> Vec<(u8, u8)> {
        let mut out = Vec::new();
        scan(flash, |_, entry| out.push((entry.event, entry.slot))).unwrap();
        out
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
    fn editing_any_byte_of_any_record_but_the_last_is_corrupt() {
        let flash = flash();
        let mut log = AuditLog::open(flash.clone());
        log.append(&granting(0)).unwrap();
        log.append(&granting(1)).unwrap();
        for slot in 0..2 {
            for word in 0..SLOT_WORDS {
                let copy = flash.deep_copy();
                let at = slot_word(slot) + word;
                copy.poke(at, copy.read(at) ^ 0x100);
                assert_eq!(scan(&copy, |_, _| {}).map(|_| ()), Err(Corrupt), "slot {slot} word {word}");
                assert_eq!(AuditLog::open(copy).head(), Err(Corrupt));
            }
        }
    }

    #[test]
    fn a_flipped_bit_in_the_last_record_is_corrupt_not_torn() {
        for word in 0..SLOT_WORDS {
            let flash = flash();
            let mut log = AuditLog::open(flash.clone());
            log.append(&granting(0)).unwrap();
            let at = slot_word(1) + word;
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
        assert_eq!(verify_prefix(&forged, kept.count, kept.head), Ok(false));
        assert_eq!(verify_prefix(&flash, kept.count, kept.head), Ok(true));
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
    fn a_full_log_refuses_appends_but_stays_readable() {
        let flash = flash();
        let mut log = AuditLog::open(flash.clone());
        for _ in 1..SLOTS {
            log.append(&granting(0)).unwrap();
        }
        assert_eq!(log.append(&granting(0)), Err(Corrupt));
        assert_eq!(log.head().unwrap().count, SLOTS as u64);
        assert!(log.read(SLOTS as u64 - 1).unwrap().is_some());
    }

    #[test]
    fn the_audit_log_and_the_revocation_log_dont_overlap() {
        let flash = flash();
        crate::Log::open(flash.clone()).record([1, 2]).unwrap();
        AuditLog::open(flash.clone()).append(&granting(0)).unwrap();
        assert_eq!(crate::Log::open(flash.clone()).is_revoked([1, 2]), Ok(true));
        assert_eq!(events(&flash), vec![(event::BOOT, 0), (event::GRANTING, 0)]);
    }
}
