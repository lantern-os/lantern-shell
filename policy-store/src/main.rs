//! `lantern-policy-store` — [RFC-0022](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0022-persistent-revocation-store.md)'s
//! persistent policy store: a confined service, and the only program with the flash mapped. See
//! `lib.rs` for the log, and for why it detects accidents rather than attackers.
//!
//! It holds revocations, and since [RFC-0026](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0026-trusted-path-and-consent.md) a person's
//! remembered "always" and "never", in sector 1. An "always" only skips a prompt: it can't widen past the launch binder's
//! compiled-in policy, which is now a ceiling. The binder holds its endpoint under badge 0. It also keeps the audit log
//! ([RFC-0024](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0024-audit-log.md)), in the same flash, which one read-only copy
//! under `READER_BADGE` reads, and which each service appends to under its own writer badge
//! ([RFC-0025](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0025-audit-log-service-operations.md)). **The badge, which the kernel
//! sets, decides what a request may do** (`policy::Source`), and a service's records are stamped with its own
//! interface whatever it sends. It holds no other service's endpoint and can mint nothing.
//!
//! `arg0` is the per-grant quota of operation records, if the launcher wants it below `USE_QUOTA`. 0 means
//! the default.
//!
//! The driver below is the Intel command set of QEMU's `virt.flash1`, width 4, so each command goes
//! to both interleaved 16-bit devices. A real board needs its own driver behind the same protocol.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

use lantern_abi::frame::status;
use lantern_abi::policy::{event, AuditEntry, Source};
use lantern_abi::{policy, sys};
use lantern_policy_store::audit::AuditLog;
use lantern_policy_store::decisions::Decisions;
use lantern_policy_store::quota::{Charge, Quota};
use lantern_policy_store::{Flash, Log};

const ENDPOINT_CPTR: usize = 1;
/// Shared with the runtime, whose number for it the demos' trap handlers compare against. Only a
/// panic signals it, so a binder waiting here doesn't hang silently.
const FAILURE_CPTR: usize = 4;

/// Must equal `lantern_boot::launch::POLICY_FLASH_VADDR`.
const FLASH_VADDR: usize = 0x9400_0000;

const CMD_READ_ARRAY: u32 = 0x00ff_00ff;
const CMD_PROGRAM: u32 = 0x0040_0040;
const CMD_BLOCK_ERASE: u32 = 0x0020_0020;
const CMD_CONFIRM: u32 = 0x00d0_00d0;
const CMD_CLEAR_STATUS: u32 = 0x0050_0050;
const STATUS_READY: u32 = 0x0080_0080;
/// A QEMU program finishes at once. On timeout, the log's read-back finds out what happened.
const READY_POLLS: usize = 100_000;
/// A real sector erase takes on the order of a second. On timeout, the log's read-back finds out.
const ERASE_POLLS: usize = 100_000_000;

/// Grants tracked for the quota: every grant two services can hold (`lantern-capabilities`' `MAX_GRANTS`).
const QUOTA_GRANTS: usize = 64;

struct MappedFlash;

impl MappedFlash {
    fn word(word: usize) -> *mut u32 {
        (FLASH_VADDR + word * 4) as *mut u32
    }
}

impl Flash for MappedFlash {
    fn read(&self, word: usize) -> u32 {
        // SAFETY: the loader mapped one megapage of flash read/write at FLASH_VADDR for this program's
        // whole life (`launch::map_device_frame`), and `Log` stays within its first sector. It is left in
        // read-array mode after every program, so this is an ordinary read.
        unsafe { core::ptr::read_volatile(Self::word(word)) }
    }

    fn program(&mut self, word: usize, value: u32) {
        let address = Self::word(word);
        // SAFETY: as `read`. Nothing else maps this device, and this program is single-threaded.
        unsafe {
            core::ptr::write_volatile(address, CMD_PROGRAM);
            core::ptr::write_volatile(address, value);
            for _ in 0..READY_POLLS {
                if core::ptr::read_volatile(address) & STATUS_READY == STATUS_READY {
                    break;
                }
            }
            core::ptr::write_volatile(address, CMD_READ_ARRAY);
        }
    }

    fn erase_sector(&mut self, first: usize, _words: usize) {
        let address = Self::word(first);
        // SAFETY: as `program`. The audit log only erases whole sectors of its own, inside the megapage.
        unsafe {
            core::ptr::write_volatile(address, CMD_CLEAR_STATUS);
            core::ptr::write_volatile(address, CMD_BLOCK_ERASE);
            core::ptr::write_volatile(address, CMD_CONFIRM);
            for _ in 0..ERASE_POLLS {
                if core::ptr::read_volatile(address) & STATUS_READY == STATUS_READY {
                    break;
                }
            }
            core::ptr::write_volatile(address, CMD_READ_ARRAY);
        }
    }
}

lantern_abi::entry!(run);

fn run(quota: usize) -> ! {
    lantern_abi::rt::report_panics_via(FAILURE_CPTR);
    let mut log = Log::open(MappedFlash);
    let mut audit = AuditLog::open(MappedFlash);
    let mut decisions = Decisions::open(MappedFlash);
    let limit = if quota == 0 { policy::USE_QUOTA } else { (quota as u32).min(policy::USE_QUOTA) };
    let mut quota = Quota::<QUOTA_GRANTS>::new(limit);
    loop {
        let Ok(received) = sys::recv(ENDPOINT_CPTR) else { continue };
        let request = policy::request(&received);
        let _ = match request.source {
            Source::Reader => serve_reader(&audit, request.op, request.index),
            Source::Binder => match request.op {
                policy::OP_APPEND => policy::reply_append(append(&mut audit, Source::Binder, request.entry)),
                policy::OP_IS_REVOKED => policy::reply(match log.is_revoked(request.key) {
                    Ok(false) => status::OK,
                    Ok(true) => status::ACCESS,
                    Err(_) => status::FAILED,
                }),
                policy::OP_RECORD => policy::reply(match log.record(request.key) {
                    Ok(()) => status::OK,
                    Err(_) => status::FAILED,
                }),
                // RFC-0026's remembered decisions: the binder's alone, like the revocation log.
                policy::OP_DECISION_GET => match decisions.get(request.key) {
                    Ok((decision, ops)) => policy::reply_decision(status::OK, decision, ops, request.key),
                    Err(_) => policy::reply_decision(status::FAILED, 0, 0, [0, 0]),
                },
                policy::OP_DECISION_SET => {
                    let (decision, ops) = (request.word as u8, (request.word >> 8) as u8);
                    policy::reply_append(match decisions.set(request.key, decision, ops) {
                        Ok(()) => status::OK,
                        Err(_) => status::FAILED,
                    })
                }
                policy::OP_DECISION_READ => match decisions.read(request.word) {
                    Ok(Some(r)) => policy::reply_decision(status::OK, r.decision, r.ops, r.key),
                    Ok(None) => policy::reply_decision(status::INVALID, 0, 0, [0, 0]),
                    Err(_) => policy::reply_decision(status::FAILED, 0, 0, [0, 0]),
                },
                _ => policy::reply(status::INVALID),
            },
            Source::Service(interface) if request.op == policy::OP_APPEND => {
                let entry = AuditEntry { interface, ..request.entry };
                let answer = if !Source::Service(interface).may_append(entry.event) {
                    status::ACCESS
                } else if matches!(entry.event, event::USING | event::USE_FAILED) {
                    match quota.charge(interface, entry.subject[0]) {
                        Charge::Allowed => append(&mut audit, request.source, entry),
                        Charge::Reached => {
                            let _ = audit.append(&AuditEntry { event: event::QUOTA_REACHED, slot: entry.event, ..entry });
                            status::ACCESS
                        }
                        Charge::Refused => status::ACCESS,
                    }
                } else {
                    append(&mut audit, request.source, entry)
                };
                policy::reply_append(answer)
            }
            Source::Service(_) | Source::Unknown => policy::reply_refused(),
        };
    }
}

/// An `APPEND` from `source`: `OK` only once it's on flash. The events a source may not append are refused,
/// which includes the store's own `BOOT`, `QUOTA_REACHED` and `RETIRED`.
fn append(audit: &mut AuditLog<MappedFlash>, source: Source, entry: AuditEntry) -> u16 {
    if !source.may_append(entry.event) {
        status::ACCESS
    } else if audit.append(&entry).is_ok() {
        status::OK
    } else {
        status::FAILED
    }
}

/// `HEAD`, `OLDEST` and `READ`, and nothing else, for the read-only badge.
fn serve_reader(audit: &AuditLog<MappedFlash>, op: u32, index: u64) -> Result<(), lantern_abi::wire::SyscallError> {
    match op {
        policy::OP_HEAD => match audit.head() {
            Ok(head) => policy::reply_head(status::OK, head.count, head.head),
            Err(_) => policy::reply_head(status::FAILED, 0, [0; 16]),
        },
        policy::OP_OLDEST => match audit.head() {
            Ok(head) => policy::reply_oldest(status::OK, head.oldest, head.oldest_previous),
            Err(_) => policy::reply_oldest(status::FAILED, 0, [0; 16]),
        },
        policy::OP_READ => match audit.read(index) {
            Ok(Some(entry)) => policy::reply_read(status::OK, &entry),
            Ok(None) => policy::reply_read(status::INVALID, &Default::default()),
            Err(_) => policy::reply_read(status::FAILED, &Default::default()),
        },
        _ => policy::reply_refused(),
    }
}
