//! `lantern-archiver` — [RFC-0038](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0038-signed-models-and-kept-audit-history.md)'s archiver:
//! keeps audit history before the policy store retires it, sealed, in the disk's archive partition, and reads it back.
//!
//! - **Woken by the policy store**, which sends to this program's endpoint under `ARCHIVER_WAKE_BADGE`, without blocking,
//!   while a full sector waits. After anything it does, it asks the policy store for work again, so no wake-up is lost.
//! - **Exporting a sector**: `EXPORT_NEXT`, then its words a page at a time through the page shared with the policy
//!   store (`EXPORT_READ`), then [`lantern_archiver::write_export`], sealing each piece through its own keystore key, and
//!   finally `EXPORTED`, saying how far history the archive has dropped to make room.
//! - **Reading for the shell**, under `archive::READER_BADGE`: `LIST` an export's range, `READ` a record, from an export
//!   unsealed and checked whole.
//!
//! It holds the policy store under the archiver's badge, the keystore under its own, the archive partition through the
//! volume, and nothing else: no console, network or store. Its keystore calls aren't recorded in the audit log: they only
//! seal that log. The grant of its key is.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::cell::UnsafeCell;

use lantern_abi::archive::{self, CHUNK};
use lantern_abi::block::Client;
use lantern_abi::frame::{status, Channel};
use lantern_abi::{policy, sys};
use lantern_archiver::{read_export, record, write_export, Disk, Index, Sealer};
use lantern_crypto::wire as kswire;
use lantern_policy_store::audit::EXPORT_SECTOR_WORDS;

lantern_abi::entry!(run);

// Granted by the loader (`lantern-boot/src/system/loader.rs`).
const ENDPOINT: usize = 1;
/// The policy store, under `policy::ARCHIVER_BADGE`.
const POLICY: usize = 2;
/// The keystore, under `archive::KEYSTORE_BADGE`; and where its grant of the archiver's key lands.
const KEYSTORE: usize = 3;
const KEYSTORE_DEST: usize = 4;
/// The volume, under its `ARCHIVE` badge.
const VOLUME: usize = 5;
const FAILURE: usize = 6;

/// Shared with the policy store: `EXPORT_READ` copies a sector's words here.
const POLICY_PAGE_VADDR: usize = 0x9001_0000;
const VOLUME_VADDR: usize = 0x9002_0000;
const KEYSTORE_VADDR: usize = 0x9003_0000;

/// One exported sector: the one being written, or the one last read for the shell.
struct Words(UnsafeCell<[u32; EXPORT_SECTOR_WORDS]>);
// SAFETY: one thread, and only `run` touches it.
unsafe impl Sync for Words {}
static WORDS: Words = Words(UnsafeCell::new([0; EXPORT_SECTOR_WORDS]));

/// The archive partition, through the volume.
struct Volume(Client);

impl Disk for Volume {
    fn read(&mut self, sector: u64, buf: &mut [u8]) -> bool {
        self.0.read(sector, buf).is_ok()
    }
    fn write(&mut self, sector: u64, buf: &[u8]) -> bool {
        self.0.write(sector, buf).is_ok()
    }
}

/// The archiver's keystore key, over its channel.
struct Keystore(Channel);

impl Sealer for Keystore {
    fn seal(&mut self, nonce: &[u8; 24], aad: &[u8], plain: &[u8; CHUNK]) -> Option<([u8; 16], [u8; CHUNK])> {
        let mut request = [0u8; 2 * CHUNK];
        let len = kswire::encode_encrypt_request(nonce, aad, plain, &mut request)?;
        let mut reply = [0u8; 2 * CHUNK];
        match self.0.call(kswire::OP_ENCRYPT, &request[..len], &mut reply) {
            Ok((kswire::status::OK, n)) => {
                let (tag, sealed) = kswire::decode_encrypt_reply(&reply[..n])?;
                Some((tag, sealed.try_into().ok()?))
            }
            _ => None,
        }
    }

    fn open(&mut self, nonce: &[u8; 24], aad: &[u8], tag: &[u8; 16], sealed: &[u8; CHUNK]) -> Option<[u8; CHUNK]> {
        let mut request = [0u8; 2 * CHUNK];
        let len = kswire::encode_decrypt_request(nonce, aad, tag, sealed, &mut request)?;
        let mut reply = [0u8; 2 * CHUNK];
        match self.0.call(kswire::OP_DECRYPT, &request[..len], &mut reply) {
            Ok((kswire::status::OK, n)) => kswire::decode_decrypt_reply(&reply[..n]).try_into().ok(),
            _ => None,
        }
    }
}

fn run(_arg0: usize) -> ! {
    lantern_abi::rt::report_panics_via(FAILURE);
    // SAFETY: the loader mapped each channel and the shared page read/write at its address, for this program's life.
    let (volume, keystore) =
        unsafe { (Channel::new(VOLUME, VOLUME_VADDR as *mut u8), Channel::new(KEYSTORE_DEST, KEYSTORE_VADDR as *mut u8)) };
    let mut disk = Volume(Client { channel: volume });
    let mut sealer = Keystore(keystore);
    // The keystore grants this badge the archiver's own sealing key, once. Without it nothing is exported: the policy
    // store then retires history as it always has, recording each loss.
    let sealing = sys::call_with_reply_slot(KEYSTORE, KEYSTORE_DEST, [0, 0]).is_ok();
    let mut index = Index::load(&mut disk);
    // SAFETY: only `run` uses WORDS, one borrow at a time.
    let words = unsafe { &mut *WORDS.0.get() };
    // The export last read into `words` for the shell, by slot and generation, so reading on is cheap.
    let mut cached: Option<(usize, u64)> = None;
    loop {
        if sealing {
            export_all(&mut disk, &mut sealer, &mut index, words, &mut cached);
        }
        let Ok(received) = sys::recv(ENDPOINT) else { continue };
        match received.badge {
            archive::READER_BADGE => {
                serve_reader(&mut disk, &mut sealer, &index, words, &mut cached, received.tag.label, received.msg[1] as u64)
            }
            // A wake-up, sent without blocking: no reply. Anything else: refused.
            policy::ARCHIVER_WAKE_BADGE => {}
            _ => {
                let _ = sys::reply_with_label(status::ACCESS as u32, [0, 0, 0]);
            }
        }
    }
}

/// Exports every full sector the policy store offers, one after another.
fn export_all(
    disk: &mut Volume,
    sealer: &mut Keystore,
    index: &mut Index,
    words: &mut [u32; EXPORT_SECTOR_WORDS],
    cached: &mut Option<(usize, u64)>,
) {
    loop {
        let Ok((status::OK, _, end, sector)) = policy::export_next(POLICY) else { return };
        let mut at = 0;
        while at < words.len() {
            match policy::export_read(POLICY, sector, at) {
                Ok((status::OK, n)) if n > 0 => {
                    // SAFETY: the loader mapped the page shared with the policy store at POLICY_PAGE_VADDR; it wrote
                    // `n` words there before replying, and won't again until this program asks.
                    let page = unsafe { core::slice::from_raw_parts(POLICY_PAGE_VADDR as *const u32, n) };
                    let n = n.min(words.len() - at);
                    words[at..at + n].copy_from_slice(&page[..n]);
                    at += n;
                }
                _ => return,
            }
        }
        // `words` is about to hold an export, not the one read for the shell.
        *cached = None;
        let Ok(header) = write_export(disk, sealer, index, words) else { return };
        if header.end != end || !matches!(policy::exported(POLICY, header.end, header.dropped), Ok(status::OK)) {
            return;
        }
    }
}

/// `LIST` and `READ` for the shell.
fn serve_reader(
    disk: &mut Volume,
    sealer: &mut Keystore,
    index: &Index,
    words: &mut [u32; EXPORT_SECTOR_WORDS],
    cached: &mut Option<(usize, u64)>,
    op: u32,
    argument: u64,
) {
    let _ = match op {
        archive::OP_LIST => match index.nth_oldest(argument as usize) {
            Some((_, h)) => sys::reply_with_label(status::OK as u32, [h.first as usize, h.end as usize, h.dropped as usize]),
            None => sys::reply_with_label(status::INVALID as u32, [0, 0, 0]),
        },
        archive::OP_READ => match index.holding(argument) {
            None => policy::reply_read(status::INVALID, &Default::default()),
            Some((slot, header)) => {
                let fresh = *cached == Some((slot, header.generation));
                if !fresh && read_export(disk, sealer, slot, &header, words).is_err() {
                    *cached = None;
                    policy::reply_read(status::FAILED, &Default::default())
                } else {
                    *cached = Some((slot, header.generation));
                    match record(words, argument) {
                        Some(entry) => policy::reply_read(status::OK, &entry),
                        None => policy::reply_read(status::INVALID, &Default::default()),
                    }
                }
            }
        },
        _ => sys::reply_with_label(status::INVALID as u32, [0, 0, 0]),
    };
}
