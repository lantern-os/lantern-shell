//! `lantern-policy-store` — [RFC-0022](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0022-persistent-revocation-store.md)'s
//! persistent policy store: a confined service, and the only program with the flash mapped. See
//! `lib.rs` for the log, and for why it detects accidents rather than attackers.
//!
//! It holds revocations, not grants, so **it can only narrow** what the launch binder's compiled-in
//! policy allows. Only the binder holds its endpoint. It holds no other service's endpoint and can
//! mint nothing.
//!
//! The driver below is the Intel command set of QEMU's `virt.flash1`, width 4, so each command goes
//! to both interleaved 16-bit devices. A real board needs its own driver behind the same protocol.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

use lantern_abi::frame::status;
use lantern_abi::{policy, sys};
use lantern_policy_store::{Flash, Log};

const ENDPOINT_CPTR: usize = 1;
/// Shared with the runtime, whose number for it the demos' trap handlers compare against. Only a
/// panic signals it, so a binder waiting here doesn't hang silently.
const FAILURE_CPTR: usize = 4;

/// Must equal `lantern_boot::launch::POLICY_FLASH_VADDR`.
const FLASH_VADDR: usize = 0x9400_0000;

const CMD_READ_ARRAY: u32 = 0x00ff_00ff;
const CMD_PROGRAM: u32 = 0x0040_0040;
const STATUS_READY: u32 = 0x0080_0080;
/// A QEMU program finishes at once. On timeout, the log's read-back finds out what happened.
const READY_POLLS: usize = 100_000;

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
}

lantern_abi::entry!(run);

fn run(_arg0: usize) -> ! {
    lantern_abi::rt::report_panics_via(FAILURE_CPTR);
    let mut log = Log::open(MappedFlash);
    loop {
        let Ok(received) = sys::recv(ENDPOINT_CPTR) else { continue };
        let request = policy::request(&received);
        let answer = match request.op {
            policy::OP_IS_REVOKED => match log.is_revoked(request.key) {
                Ok(false) => status::OK,
                Ok(true) => status::ACCESS,
                Err(_) => status::FAILED,
            },
            policy::OP_RECORD => match log.record(request.key) {
                Ok(()) => status::OK,
                Err(_) => status::FAILED,
            },
            _ => status::INVALID,
        };
        let _ = policy::reply(answer);
    }
}
