//! [RFC-0026](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0026-trusted-path-and-consent.md)'s remembered decisions: a person's "always"
//! and "never", by role, in sector 1 of the policy store's flash. Once-only answers aren't remembered.
//!
//! The format is the revocation log's (`lib.rs`): a header, then 8-word slots that are erased, a record, a tombstone, or
//! torn, and anything else is corrupt. A record is a revocation key, a decision and its ops, and the first 96 bits of
//! `BLAKE3` over them. **The latest record for a key wins**, so forgetting appends a record of
//! `decision::NONE`, and nothing is ever rewritten.
//!
//! Like the revocation log, this detects accidents, not attackers. Someone who can write the flash can plant an "always",
//! which is on RFC-0023's Phase 4 checklist. A full log can't remember anything new, and the person is simply asked.

use lantern_abi::policy::{decision, RevocationKey};
use lantern_crypto::hash;

use crate::Flash;

const ERASED: u32 = u32::MAX;
const SLOT_WORDS: usize = 8;
/// Sector 1 of the mapped megapage.
const FIRST_WORD: usize = 0x4_0000 / 4;
const LOG_WORDS: usize = 0x4_0000 / 4;
pub const SLOTS: usize = LOG_WORDS / SLOT_WORDS - 1;
/// `b"LNTNDEC1"`, then a format version.
const HEADER: [u32; SLOT_WORDS] = [0x4e54_4e4c, 0x3143_4544, 1, 0, 0, 0, 0, 0];

type Slot = [u32; SLOT_WORDS];

/// The log can't be read or written. The binder then asks the person, and remembers nothing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Unavailable;

/// One remembered decision.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Remembered {
    pub key: RevocationKey,
    pub decision: u8,
    pub ops: u8,
}

pub struct Decisions<F> {
    flash: F,
    next: Option<usize>,
}

impl<F: Flash> Decisions<F> {
    /// Checks the log, writes a header on blank flash, and tombstones a torn last record.
    pub fn open(flash: F) -> Self {
        let mut log = Self { flash, next: None };
        log.next = log.validate();
        log
    }

    fn validate(&mut self) -> Option<usize> {
        let header = self.read_slot(FIRST_WORD);
        if header == [ERASED; SLOT_WORDS] {
            if !self.erased_from(0) {
                return None;
            }
            return self.write(FIRST_WORD, &HEADER).then_some(0);
        }
        if header != HEADER {
            return None;
        }
        let mut slot = 0;
        while slot < SLOTS {
            let words = self.read_slot(slot_word(slot));
            if words == [ERASED; SLOT_WORDS] {
                break;
            }
            if words == [0; SLOT_WORDS] || record_of(&words).is_some() {
                slot += 1;
            } else if words[SLOT_WORDS - 1] == ERASED && self.erased_from(slot + 1) {
                if !self.write(slot_word(slot), &[0; SLOT_WORDS]) {
                    return None;
                }
                slot += 1;
            } else {
                return None;
            }
        }
        self.erased_from(slot).then_some(slot)
    }

    /// The decision remembered for `key`, `decision::NONE` if there's none.
    pub fn get(&self, key: RevocationKey) -> Result<(u8, u8), Unavailable> {
        let next = self.next.ok_or(Unavailable)?;
        Ok((0..next)
            .rev()
            .filter_map(|slot| record_of(&self.read_slot(slot_word(slot))))
            .find(|r| r.key == key)
            .map_or((decision::NONE, 0), |r| (r.decision, r.ops)))
    }

    /// Remembers `decision` for `key`, or forgets with `decision::NONE`. `Ok` only once it's on flash, and at once if it's
    /// already what's remembered.
    pub fn set(&mut self, key: RevocationKey, decision: u8, ops: u8) -> Result<(), Unavailable> {
        let (current, current_ops) = self.get(key)?;
        if (current, current_ops) == (decision, ops) || (current == decision::NONE && decision == decision::NONE) {
            return Ok(());
        }
        let slot = self.next.ok_or(Unavailable)?;
        if slot >= SLOTS || !matches!(decision, decision::NONE | decision::ALLOW | decision::DENY) {
            return Err(Unavailable);
        }
        let record = Remembered { key, decision, ops };
        if self.write(slot_word(slot), &slot_for(&record)) {
            self.next = Some(slot + 1);
            Ok(())
        } else {
            self.next = self.write(slot_word(slot), &[0; SLOT_WORDS]).then_some(slot + 1);
            Err(Unavailable)
        }
    }

    /// The `index`th key with a decision in force, in the order each was first remembered.
    pub fn read(&self, index: usize) -> Result<Option<Remembered>, Unavailable> {
        let next = self.next.ok_or(Unavailable)?;
        let mut seen = 0;
        for slot in 0..next {
            let Some(first) = record_of(&self.read_slot(slot_word(slot))) else { continue };
            let earlier = (0..slot).any(|s| record_of(&self.read_slot(slot_word(s))).is_some_and(|r| r.key == first.key));
            if earlier {
                continue;
            }
            let (decision, ops) = self.get(first.key)?;
            if decision == decision::NONE {
                continue;
            }
            if seen == index {
                return Ok(Some(Remembered { key: first.key, decision, ops }));
            }
            seen += 1;
        }
        Ok(None)
    }

    fn read_slot(&self, first: usize) -> Slot {
        core::array::from_fn(|i| self.flash.read(first + i))
    }

    fn erased_from(&self, slot: usize) -> bool {
        (slot..SLOTS).all(|slot| self.read_slot(slot_word(slot)) == [ERASED; SLOT_WORDS])
    }

    fn write(&mut self, first: usize, words: &Slot) -> bool {
        for (i, &word) in words.iter().enumerate() {
            self.flash.program(first + i, word);
        }
        self.read_slot(first) == *words
    }
}

fn slot_word(slot: usize) -> usize {
    FIRST_WORD + (slot + 1) * SLOT_WORDS
}

fn check(key: RevocationKey, value: u32) -> [u32; 3] {
    let mut bytes = [0u8; 20];
    bytes[..8].copy_from_slice(&key[0].to_le_bytes());
    bytes[8..16].copy_from_slice(&key[1].to_le_bytes());
    bytes[16..].copy_from_slice(&value.to_le_bytes());
    let digest = hash::hash(&bytes);
    core::array::from_fn(|i| u32::from_le_bytes(digest.as_bytes()[i * 4..i * 4 + 4].try_into().unwrap()))
}

fn slot_for(record: &Remembered) -> Slot {
    let value = record.decision as u32 | (record.ops as u32) << 8;
    let c = check(record.key, value);
    let k = record.key;
    // The last word is written last: a torn record is one whose last word is still erased.
    [k[0] as u32, (k[0] >> 32) as u32, k[1] as u32, (k[1] >> 32) as u32, value, c[0], c[1], c[2]]
}

fn record_of(words: &Slot) -> Option<Remembered> {
    let key = [words[0] as u64 | (words[1] as u64) << 32, words[2] as u64 | (words[3] as u64) << 32];
    let value = words[4];
    (value >> 16 == 0 && words[5..] == check(key, value)).then_some(Remembered {
        key,
        decision: value as u8,
        ops: (value >> 8) as u8,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::FakeFlash;

    const A: RevocationKey = [1, 2];
    const B: RevocationKey = [3, 4];

    fn flash() -> FakeFlash {
        FakeFlash::erased_words(0x20_0000 / 4)
    }

    #[test]
    fn remembered_decisions_survive_a_reboot_and_the_latest_wins() {
        let flash = flash();
        let mut log = Decisions::open(flash.clone());
        assert_eq!(log.get(A), Ok((decision::NONE, 0)));
        log.set(A, decision::ALLOW, 4).unwrap();
        log.set(B, decision::DENY, 1).unwrap();
        log.set(A, decision::DENY, 4).unwrap();
        let log = Decisions::open(flash.clone());
        assert_eq!((log.get(A), log.get(B)), (Ok((decision::DENY, 4)), Ok((decision::DENY, 1))));
    }

    #[test]
    fn forgetting_appends_and_listing_shows_only_decisions_in_force() {
        let flash = flash();
        let mut log = Decisions::open(flash.clone());
        log.set(A, decision::ALLOW, 4).unwrap();
        log.set(B, decision::DENY, 1).unwrap();
        log.set(A, decision::NONE, 0).unwrap();
        assert_eq!(log.get(A), Ok((decision::NONE, 0)));
        assert_eq!(log.read(0), Ok(Some(Remembered { key: B, decision: decision::DENY, ops: 1 })));
        assert_eq!(log.read(1), Ok(None));
        log.set(A, decision::ALLOW, 2).unwrap();
        assert_eq!(log.read(0).unwrap().unwrap().key, A, "listed in the order first remembered");
        assert_eq!(log.read(1).unwrap().unwrap().key, B);
    }

    #[test]
    fn a_repeat_writes_nothing() {
        let flash = flash();
        let mut log = Decisions::open(flash.clone());
        log.set(A, decision::ALLOW, 4).unwrap();
        let next = log.next;
        log.set(A, decision::ALLOW, 4).unwrap();
        log.set(B, decision::NONE, 0).unwrap();
        assert_eq!(log.next, next);
    }

    #[test]
    fn a_power_cut_mid_record_is_never_acknowledged_and_the_log_recovers() {
        for words in 0..SLOT_WORDS {
            let flash = flash();
            let mut log = Decisions::open(flash.clone());
            log.set(B, decision::DENY, 1).unwrap();
            flash.lose_power_after(words);
            assert_eq!(log.set(A, decision::ALLOW, 4), Err(Unavailable), "{words} words");
            flash.power_back();
            let mut log = Decisions::open(flash.clone());
            assert_eq!(log.get(A), Ok((decision::NONE, 0)), "{words} words");
            assert_eq!(log.get(B), Ok((decision::DENY, 1)));
            log.set(A, decision::ALLOW, 4).unwrap();
        }
    }

    #[test]
    fn an_edit_or_garbage_is_unavailable() {
        let flash = flash();
        let mut log = Decisions::open(flash.clone());
        log.set(A, decision::ALLOW, 4).unwrap();
        log.set(B, decision::DENY, 1).unwrap();
        for word in 0..SLOT_WORDS {
            let copy = flash.deep_copy();
            copy.poke(slot_word(0) + word, copy.read(slot_word(0) + word) ^ 0x10);
            assert_eq!(Decisions::open(copy).get(A), Err(Unavailable), "word {word}");
        }
        let copy = flash.deep_copy();
        copy.poke(FIRST_WORD, 0);
        assert_eq!(Decisions::open(copy).get(A), Err(Unavailable), "a bad header");
    }

    #[test]
    fn it_stays_in_sector_1() {
        let flash = flash();
        crate::Log::open(flash.clone()).record(A).unwrap();
        let mut log = Decisions::open(flash.clone());
        log.set(A, decision::DENY, 1).unwrap();
        assert_eq!(crate::Log::open(flash.clone()).is_revoked(A), Ok(true));
        assert!((0x8_0000 / 4..0x20_0000 / 4).all(|w| flash.read(w) == ERASED), "the audit ring's sectors are untouched");
    }
}
