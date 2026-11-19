use super::*;
use lantern_abi::archive::SEALED_CHUNK;
use lantern_abi::policy::event;
use lantern_crypto::aead::AeadKey;
use lantern_policy_store::audit::AuditLog;
use lantern_policy_store::Flash;
use std::cell::RefCell;
use std::rc::Rc;

/// The policy store's flash, in memory: a megapage, erased.
#[derive(Clone)]
struct MemFlash(Rc<RefCell<Vec<u32>>>);

impl MemFlash {
    fn new() -> Self {
        Self(Rc::new(RefCell::new(vec![u32::MAX; 0x20_0000 / 4])))
    }
}

impl Flash for MemFlash {
    fn read(&self, word: usize) -> u32 {
        self.0.borrow()[word]
    }
    fn program(&mut self, word: usize, value: u32) {
        self.0.borrow_mut()[word] &= value;
    }
    fn erase_sector(&mut self, first: usize, words: usize) {
        self.0.borrow_mut()[first..first + words].fill(u32::MAX);
    }
}

/// The archive partition, in memory.
struct MemDisk(Vec<u8>);

impl MemDisk {
    fn new() -> Self {
        Self(vec![0; lantern_abi::archive::PARTITION_SECTORS as usize * SECTOR])
    }
}

impl Disk for MemDisk {
    fn read(&mut self, sector: u64, buf: &mut [u8]) -> bool {
        let at = sector as usize * SECTOR;
        buf.copy_from_slice(&self.0[at..at + buf.len()]);
        true
    }
    fn write(&mut self, sector: u64, buf: &[u8]) -> bool {
        let at = sector as usize * SECTOR;
        self.0[at..at + buf.len()].copy_from_slice(buf);
        true
    }
}

/// The keystore, standing in: the same AEAD, under a fixed key.
struct Key(AeadKey);

impl Sealer for Key {
    fn seal(&mut self, nonce: &[u8; 24], aad: &[u8], plain: &[u8; CHUNK]) -> Option<([u8; 16], [u8; CHUNK])> {
        let mut buffer = *plain;
        let tag = self.0.encrypt_in_place_detached(nonce, aad, &mut buffer).ok()?;
        Some((tag, buffer))
    }
    fn open(&mut self, nonce: &[u8; 24], aad: &[u8], tag: &[u8; 16], sealed: &[u8; CHUNK]) -> Option<[u8; CHUNK]> {
        let mut buffer = *sealed;
        self.0.decrypt_in_place_detached(nonce, aad, &mut buffer, tag).ok()?;
        Some(buffer)
    }
}

fn key() -> Key {
    Key(AeadKey::from_random_bytes([0x41; 32]))
}

fn granting(n: u64) -> AuditEntry {
    AuditEntry { event: event::GRANTING, slot: 3, subject: [n, 0], ..AuditEntry::default() }
}

/// The words of the sector `log` offers now.
fn take(log: &AuditLog<MemFlash>) -> Option<(lantern_policy_store::audit::Exportable, Vec<u32>)> {
    let offered = log.exportable().unwrap()?;
    let mut words = vec![0u32; EXPORT_SECTOR_WORDS];
    let mut at = 0;
    while at < words.len() {
        let end = (at + 1024).min(words.len());
        at += log.export_read(offered.sector, at, &mut words[at..end]).unwrap();
    }
    Some((offered, words))
}

fn fill_one_sector(log: &mut AuditLog<MemFlash>, n: &mut u64) {
    let before = log.exportable().unwrap();
    while log.exportable().unwrap() == before {
        log.append(&granting(*n)).unwrap();
        *n += 1;
    }
}

#[test]
fn an_export_is_written_sealed_read_back_and_checked() {
    let mut log = AuditLog::open(MemFlash::new());
    let mut n = 0;
    fill_one_sector(&mut log, &mut n);
    let (offered, words) = take(&log).unwrap();
    let (mut disk, mut key) = (MemDisk::new(), key());
    let mut index = Index::load(&mut disk);
    let header = write_export(&mut disk, &mut key, &mut index, &words).unwrap();
    assert_eq!((header.first, header.end, header.generation, header.dropped), (offered.first, offered.end, 1, 0));

    // The disk holds no record in the clear: the first record's subject word appears nowhere after the header.
    let plain = words[16..32].iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>();
    assert!(!disk.0[SECTOR..].windows(plain.len()).any(|w| w == plain.as_slice()), "a record in the clear");

    // A fresh index, as after a reboot, finds it, and it reads back exactly, record by record.
    let index = Index::load(&mut disk);
    let (slot, found) = index.holding(offered.first + 5).unwrap();
    assert_eq!(found, header);
    let mut back = vec![0u32; EXPORT_SECTOR_WORDS];
    read_export(&mut disk, &mut key, slot, &found, &mut back).unwrap();
    assert_eq!(back, words);
    assert_eq!(record(&back, offered.first + 5).map(|e| e.subject[0]), Some(offered.first + 5 - 1), "after BOOT");
    assert_eq!(index.holding(offered.end), None, "past it");
}

#[test]
fn a_changed_byte_anywhere_in_a_slot_fails_the_whole_sector() {
    let mut log = AuditLog::open(MemFlash::new());
    let mut n = 0;
    fill_one_sector(&mut log, &mut n);
    let (_, words) = take(&log).unwrap();
    let (mut disk, mut key) = (MemDisk::new(), key());
    let mut index = Index::load(&mut disk);
    let header = write_export(&mut disk, &mut key, &mut index, &words).unwrap();
    let mut back = vec![0u32; EXPORT_SECTOR_WORDS];
    // Bytes in the first piece, at the edge between ciphertext and tag, in the middle, and in the last piece.
    let data_end = SECTOR + CHUNKS * SEALED_CHUNK;
    for at in [SECTOR, SECTOR + 255, SECTOR + 256, SECTOR + 271, SECTOR + data_end / 2, data_end - 1] {
        disk.0[at] ^= 1;
        assert_eq!(read_export(&mut disk, &mut key, 0, &header, &mut back), Err(Fail::Corrupt), "byte {at}");
        disk.0[at] ^= 1;
    }
    // A header that lies about its sector.
    let lying = Header { end_head: [9; 16], ..header };
    assert_eq!(read_export(&mut disk, &mut key, 0, &lying, &mut back), Err(Fail::Corrupt));
    // One that decrypts, its first record and chain head being right, but lies about how much it holds.
    let short = Header { records: header.records - 1, end: header.end - 1, ..header };
    assert_eq!(read_export(&mut disk, &mut key, 0, &short, &mut back), Err(Fail::Corrupt), "a header claiming less");
    let moved = Header { first: header.first + 1, ..header };
    assert_eq!(read_export(&mut disk, &mut key, 0, &moved, &mut back), Err(Fail::Corrupt), "its pieces belong elsewhere");
    // Another key.
    let mut other = Key(AeadKey::from_random_bytes([0x42; 32]));
    assert_eq!(read_export(&mut disk, &mut other, 0, &header, &mut back), Err(Fail::Corrupt));
    read_export(&mut disk, &mut key, 0, &header, &mut back).unwrap();
}

#[test]
fn what_isnt_a_whole_audit_sector_is_refused() {
    let (mut disk, mut key) = (MemDisk::new(), key());
    let mut index = Index::load(&mut disk);
    assert_eq!(write_export(&mut disk, &mut key, &mut index, &vec![0u32; EXPORT_SECTOR_WORDS]), Err(Fail::Corrupt));
    assert_eq!(write_export(&mut disk, &mut key, &mut index, &[u32::MAX; 16]), Err(Fail::Corrupt));
    assert_eq!(index.nth_oldest(0), None, "nothing written");
}

#[test]
fn a_full_archive_drops_its_oldest_export_and_says_how_far() {
    let mut log = AuditLog::open(MemFlash::new());
    let mut n = 0;
    let (mut disk, mut key) = (MemDisk::new(), key());
    let mut index = Index::load(&mut disk);
    let mut ends = Vec::new();
    // One more export than there are slots.
    for _ in 0..=SLOTS {
        fill_one_sector(&mut log, &mut n);
        let (offered, words) = take(&log).unwrap();
        let header = write_export(&mut disk, &mut key, &mut index, &words).unwrap();
        log.mark_exported(header.end, header.dropped).unwrap();
        ends.push((offered.first, header.end, header.dropped));
    }
    // Every export but the last dropped nothing; the last wrote over the first, so history before its end is dropped.
    assert!(ends[..SLOTS].iter().all(|&(_, _, dropped)| dropped == 0));
    assert_eq!(ends[SLOTS].2, ends[0].1);
    // Oldest first, after a reboot: the second export, then the rest in order.
    let index = Index::load(&mut disk);
    assert_eq!(index.nth_oldest(0).unwrap().1.first, ends[1].0);
    assert_eq!(index.nth_oldest(SLOTS - 1).unwrap().1.first, ends[SLOTS].0);
    assert!(index.nth_oldest(SLOTS).is_none());
    assert_eq!(index.holding(ends[0].0), None, "dropped");
    // And it keeps saying so: the next export after a reboot carries the same, or more.
    assert!(index.next_slot().2 >= ends[0].1);
}

#[test]
fn a_power_cut_mid_write_leaves_an_empty_slot_not_a_false_one() {
    let mut log = AuditLog::open(MemFlash::new());
    let mut n = 0;
    fill_one_sector(&mut log, &mut n);
    let (_, first) = take(&log).unwrap();
    log.mark_exported(log.exportable().unwrap().unwrap().end, 0).unwrap();
    fill_one_sector(&mut log, &mut n);
    let (_, second) = take(&log).unwrap();

    let (mut disk, mut key) = (MemDisk::new(), key());
    let mut index = Index::load(&mut disk);
    write_export(&mut disk, &mut key, &mut index, &first).unwrap();

    /// The disk, losing power after `left` writes.
    struct Cut<'a>(&'a mut MemDisk, usize);
    impl Disk for Cut<'_> {
        fn read(&mut self, sector: u64, buf: &mut [u8]) -> bool {
            self.0.read(sector, buf)
        }
        fn write(&mut self, sector: u64, buf: &[u8]) -> bool {
            if self.1 == 0 {
                return false;
            }
            self.1 -= 1;
            self.0.write(sector, buf)
        }
    }
    // A write clears the header, writes DATA_SECTORS sectors, then the header: cut before the header lands.
    for left in [1, 2, DATA_SECTORS / 2 + 1, DATA_SECTORS + 1] {
        let mut copy = MemDisk(disk.0.clone());
        let mut index = Index::load(&mut copy);
        assert!(write_export(&mut Cut(&mut copy, left), &mut key, &mut index, &second).is_err());
        let after = Index::load(&mut copy);
        assert_eq!(after.nth_oldest(1), None, "after {left} writes: no second export");
        assert!(after.nth_oldest(0).is_some(), "the first is untouched");
    }
}

#[test]
fn nonces_differ_by_piece_by_sector_and_by_content() {
    let head = [1u8; 16];
    assert_ne!(nonce(0, &head, 0), nonce(0, &head, 1));
    assert_ne!(nonce(0, &head, 0), nonce(1, &head, 0));
    assert_ne!(nonce(0, &head, 0), nonce(0, &[2; 16], 0), "a log started again, with different records");
}
