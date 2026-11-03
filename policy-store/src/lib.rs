//! The log half of [RFC-0022](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0022-persistent-revocation-store.md)'s
//! policy store: everything that reads flash contents, which are untrusted bytes, with no
//! syscalls in it, so it can be tested on a host. `src/main.rs` is the program around it.
//!
//! **This detects accidents, not attackers.** The check on each record has no key, because any key
//! would be a public demo constant in the same image. Anyone who can write the flash from outside
//! can erase it, which restores every revoked role.
//!
//! A log is a header, then fixed-size slots, each of which is one of:
//!
//! - **erased:** all ones. Every later slot must be erased too.
//! - **a record:** a key, then the first half of its `BLAKE3`.
//! - **a tombstone:** all zeros, a slot given up on. Programming can only clear bits, so this can
//!   always be written.
//! - **torn:** its last word is still erased, because that word is written last. Only the slot just
//!   before erased space can be torn. It can't have been acknowledged, since `OK` follows a read-back,
//!   so it is tombstoned on start.
//!
//! Anything else is corrupt, and the log then answers nothing: the binder declines every grant.
//! That includes a flipped bit in the last record, which a looser rule would read as torn, silently
//! restoring a revoked role.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use lantern_abi::policy::RevocationKey;
use lantern_crypto::hash;

/// One 32-bit word of flash, by index. Programming clears bits and never sets them.
pub trait Flash {
    fn read(&self, word: usize) -> u32;
    fn program(&mut self, word: usize, value: u32);
}

const ERASED: u32 = u32::MAX;
const SLOT_WORDS: usize = 8;
/// One flash sector, 256 KiB, holds the header and every slot.
const LOG_WORDS: usize = 0x4_0000 / 4;
/// The header takes the first slot's worth of words.
pub const SLOTS: usize = LOG_WORDS / SLOT_WORDS - 1;

/// `b"LNTNPOL1"`, then a format version. The rest of the header is zero.
const HEADER: [u32; SLOT_WORDS] = [0x4e54_4e4c, 0x314c_4f50, 1, 0, 0, 0, 0, 0];

type Slot = [u32; SLOT_WORDS];

/// Why an answer can't be given. There's deliberately no finer detail: the binder treats them alike.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Unavailable;

pub struct Log<F> {
    flash: F,
    /// The first erased slot. `None` means corrupt.
    next: Option<usize>,
}

impl<F: Flash> Log<F> {
    /// Validates the whole log, writes the header to a blank one, and tombstones a torn record.
    pub fn open(flash: F) -> Self {
        let mut log = Self { flash, next: None };
        log.next = log.validate();
        log
    }

    fn validate(&mut self) -> Option<usize> {
        let header = self.read_words::<SLOT_WORDS>(0);
        if header == [ERASED; SLOT_WORDS] {
            if !(0..SLOTS).all(|slot| self.slot(slot) == [ERASED; SLOT_WORDS]) {
                return None;
            }
            return self.write_words(0, &HEADER).then_some(0);
        }
        if header != HEADER {
            return None;
        }

        let mut slot = 0;
        while slot < SLOTS {
            let words = self.slot(slot);
            if words == [ERASED; SLOT_WORDS] {
                break;
            }
            if words == [0; SLOT_WORDS] || is_record(&words) {
                slot += 1;
            } else if words[SLOT_WORDS - 1] == ERASED && self.erased_from(slot + 1) {
                if !self.tombstone(slot) {
                    return None;
                }
                slot += 1;
            } else {
                return None;
            }
        }
        self.erased_from(slot).then_some(slot)
    }

    /// `Ok(true)` if `key` has been recorded.
    pub fn is_revoked(&self, key: RevocationKey) -> Result<bool, Unavailable> {
        let next = self.next.ok_or(Unavailable)?;
        Ok((0..next).any(|slot| {
            let words = self.slot(slot);
            is_record(&words) && key_of(&words) == key
        }))
    }

    /// Makes `key` durable, including when it already is. Fails on a corrupt or full log, or if what
    /// was written doesn't read back.
    pub fn record(&mut self, key: RevocationKey) -> Result<(), Unavailable> {
        if self.is_revoked(key)? {
            return Ok(());
        }
        let slot = self.next.ok_or(Unavailable)?;
        if slot >= SLOTS {
            return Err(Unavailable);
        }
        let written = self.write_words(slot_word(slot), &record_for(key));
        if !written {
            // Give the slot up, so this log stays readable. If even that fails, stop answering.
            self.next = self.tombstone(slot).then_some(slot + 1);
            return Err(Unavailable);
        }
        self.next = Some(slot + 1);
        Ok(())
    }

    fn slot(&self, slot: usize) -> Slot {
        self.read_words(slot_word(slot))
    }

    fn erased_from(&self, slot: usize) -> bool {
        (slot..SLOTS).all(|slot| self.slot(slot) == [ERASED; SLOT_WORDS])
    }

    fn tombstone(&mut self, slot: usize) -> bool {
        self.write_words(slot_word(slot), &[0; SLOT_WORDS])
    }

    fn read_words<const N: usize>(&self, first: usize) -> [u32; N] {
        core::array::from_fn(|i| self.flash.read(first + i))
    }

    /// In order, so the last word marks a finished write. `true` if it all reads back.
    fn write_words(&mut self, first: usize, words: &Slot) -> bool {
        for (i, &word) in words.iter().enumerate() {
            self.flash.program(first + i, word);
        }
        self.read_words::<SLOT_WORDS>(first) == *words
    }
}

fn slot_word(slot: usize) -> usize {
    (slot + 1) * SLOT_WORDS
}

fn key_bytes(key: RevocationKey) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[..8].copy_from_slice(&key[0].to_le_bytes());
    bytes[8..].copy_from_slice(&key[1].to_le_bytes());
    bytes
}

fn check_words(key: RevocationKey) -> [u32; 4] {
    let digest = hash::hash(&key_bytes(key));
    core::array::from_fn(|i| {
        let start = i * 4;
        u32::from_le_bytes(digest.as_bytes()[start..start + 4].try_into().unwrap())
    })
}

fn record_for(key: RevocationKey) -> Slot {
    let check = check_words(key);
    [key[0] as u32, (key[0] >> 32) as u32, key[1] as u32, (key[1] >> 32) as u32, check[0], check[1], check[2], check[3]]
}

fn key_of(words: &Slot) -> RevocationKey {
    [words[0] as u64 | (words[1] as u64) << 32, words[2] as u64 | (words[3] as u64) << 32]
}

fn is_record(words: &Slot) -> bool {
    words[4..] == check_words(key_of(words))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// Real flash's one rule: programming can only clear bits. Shared, so a test can reopen it as a reboot.
    #[derive(Clone)]
    struct FakeFlash {
        words: Rc<RefCell<Vec<u32>>>,
        /// Programs after this many words are lost, as in a power cut.
        budget: Rc<RefCell<usize>>,
    }

    impl FakeFlash {
        fn erased() -> Self {
            Self { words: Rc::new(RefCell::new(vec![ERASED; LOG_WORDS])), budget: Rc::new(RefCell::new(usize::MAX)) }
        }

        fn lose_power_after(&self, words: usize) {
            *self.budget.borrow_mut() = words;
        }

        fn power_back(&self) {
            *self.budget.borrow_mut() = usize::MAX;
        }

        fn poke(&self, word: usize, value: u32) {
            self.words.borrow_mut()[word] = value;
        }
    }

    impl Flash for FakeFlash {
        fn read(&self, word: usize) -> u32 {
            self.words.borrow()[word]
        }
        fn program(&mut self, word: usize, value: u32) {
            let mut budget = self.budget.borrow_mut();
            if *budget > 0 {
                *budget -= 1;
                self.words.borrow_mut()[word] &= value;
            }
        }
    }

    const KEY: RevocationKey = [0x1111_2222_3333_4444, 0x5555_6666_7777_8888];
    const OTHER: RevocationKey = [1, 2];

    #[test]
    fn a_blank_log_has_nothing_revoked_and_gets_a_header() {
        let flash = FakeFlash::erased();
        let log = Log::open(flash.clone());
        assert_eq!(log.is_revoked(KEY), Ok(false));
        assert_eq!(flash.read(0), HEADER[0]);
    }

    #[test]
    fn a_record_survives_a_reboot_and_only_that_key_is_revoked() {
        let flash = FakeFlash::erased();
        Log::open(flash.clone()).record(KEY).unwrap();

        let log = Log::open(flash);
        assert_eq!(log.is_revoked(KEY), Ok(true));
        assert_eq!(log.is_revoked(OTHER), Ok(false));
    }

    #[test]
    fn recording_twice_writes_once() {
        let flash = FakeFlash::erased();
        let mut log = Log::open(flash.clone());
        log.record(KEY).unwrap();
        log.record(KEY).unwrap();
        assert_eq!(log.next, Some(1));
        assert_eq!(Log::open(flash).next, Some(1));
    }

    #[test]
    fn all_zeros_reads_as_corrupt_which_is_what_no_flash_looks_like() {
        let flash = FakeFlash::erased();
        for word in 0..LOG_WORDS {
            flash.poke(word, 0);
        }
        let mut log = Log::open(flash);
        assert_eq!(log.is_revoked(KEY), Err(Unavailable));
        assert_eq!(log.record(KEY), Err(Unavailable));
    }

    #[test]
    fn a_bad_header_is_corrupt() {
        let flash = FakeFlash::erased();
        Log::open(flash.clone());
        flash.poke(2, 2);
        assert_eq!(Log::open(flash).is_revoked(KEY), Err(Unavailable));
    }

    #[test]
    fn a_blank_header_over_a_nonblank_log_is_corrupt() {
        let flash = FakeFlash::erased();
        flash.poke(slot_word(5), 0);
        assert_eq!(Log::open(flash).is_revoked(KEY), Err(Unavailable));
    }

    #[test]
    fn a_flipped_bit_in_the_last_record_is_corrupt_not_torn() {
        for word in 0..SLOT_WORDS {
            let flash = FakeFlash::erased();
            Log::open(flash.clone()).record(KEY).unwrap();
            flash.poke(slot_word(0) + word, flash.read(slot_word(0) + word) ^ 1);
            assert_eq!(Log::open(flash).is_revoked(KEY), Err(Unavailable), "word {word}");
        }
    }

    #[test]
    fn a_record_after_a_gap_is_corrupt() {
        let flash = FakeFlash::erased();
        Log::open(flash.clone());
        flash.poke(slot_word(3), 7);
        assert_eq!(Log::open(flash).is_revoked(KEY), Err(Unavailable));
    }

    #[test]
    fn a_power_cut_at_every_word_of_a_record_is_safe_and_the_log_recovers() {
        for words in 0..SLOT_WORDS {
            let flash = FakeFlash::erased();
            let mut log = Log::open(flash.clone());
            log.record(OTHER).unwrap();

            flash.lose_power_after(words);
            assert_eq!(log.record(KEY), Err(Unavailable), "{words} words: no acknowledgement");
            flash.power_back();

            let mut log = Log::open(flash.clone());
            assert_eq!(log.is_revoked(OTHER), Ok(true), "{words} words: earlier records survive");
            assert_eq!(log.is_revoked(KEY), Ok(false), "{words} words: never acknowledged");
            log.record(KEY).unwrap();

            let log = Log::open(flash);
            assert_eq!(log.is_revoked(KEY), Ok(true), "{words} words: recorded after recovery");
            assert_eq!(log.is_revoked(OTHER), Ok(true));
        }
    }

    #[test]
    fn a_torn_record_after_reboot_is_tombstoned_and_later_records_stay_readable() {
        let flash = FakeFlash::erased();
        let mut log = Log::open(flash.clone());
        flash.lose_power_after(4);
        let _ = log.record(KEY);
        // Power is lost for good here, so the tombstone wasn't written either.
        flash.power_back();
        for word in 4..SLOT_WORDS {
            assert_eq!(flash.read(slot_word(0) + word), ERASED);
        }

        let mut log = Log::open(flash.clone());
        assert_eq!(log.next, Some(1));
        assert_eq!(flash.read(slot_word(0)), 0);
        log.record(OTHER).unwrap();

        let log = Log::open(flash);
        assert_eq!(log.next, Some(2));
        assert_eq!(log.is_revoked(OTHER), Ok(true));
    }

    #[test]
    fn a_full_log_refuses_new_keys_but_still_answers() {
        let flash = FakeFlash::erased();
        let mut log = Log::open(flash.clone());
        for slot in 0..SLOTS {
            log.record([slot as u64, 9]).unwrap();
        }
        assert_eq!(log.record(KEY), Err(Unavailable));
        assert_eq!(log.record([0, 9]), Ok(()), "a repeat is still durable");
        assert_eq!(log.is_revoked([SLOTS as u64 - 1, 9]), Ok(true));
        assert_eq!(Log::open(flash).is_revoked([0, 9]), Ok(true));
    }

    #[test]
    fn a_write_that_doesnt_read_back_fails_and_the_log_stays_usable() {
        let flash = FakeFlash::erased();
        let mut log = Log::open(flash.clone());
        // Dirty only the slot's last word, so programming can't produce the record.
        flash.poke(slot_word(0) + SLOT_WORDS - 1, 0);
        assert_eq!(log.record(KEY), Err(Unavailable));
        assert_eq!(log.next, Some(1));
        log.record(OTHER).unwrap();
        assert_eq!(Log::open(flash).is_revoked(OTHER), Ok(true));
    }

    #[test]
    fn the_key_and_check_layout_is_stable() {
        // The on-flash format: changing this strands every existing log.
        let record = record_for(KEY);
        assert_eq!(key_of(&record), KEY);
        assert_eq!(&record[..4], &[0x3333_4444, 0x1111_2222, 0x7777_8888, 0x5555_6666]);
        assert!(is_record(&record));
    }
}
