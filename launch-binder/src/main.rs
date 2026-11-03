//! `lantern-launch-binder` — [RFC-0020](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0020-launch-binder.md)'s launch
//! binder: an ordinary confined program, and the only holder of authority to request grants
//! from a service. See `lib.rs` for the decision, and for why its policy isn't consent.
//!
//! It verifies the package once, then serves `BIND` requests. For a request `lib.rs` grants,
//! it asks the owning service to `GRANT`, records the result in its ledger, and passes the
//! badged endpoint on. Everything else gets the same `DECLINED`, whatever the reason.
//!
//! The holder of the control capability ([RFC-0021](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0021-grant-ledger-and-revocation.md))
//! can list the ledger and revoke an entry. It names entries by index and never sees a badge.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use lantern_abi::frame::status;
use lantern_abi::grant::{self, CONTROL_BADGE, CONTROL_LIST, CONTROL_REVOKE};
use lantern_abi::sys;
use lantern_launch_binder::{decide, read_package, BoundSlots, Interface, Ledger, MAX_BINDS, POLICY, TRUSTED_PUBLISHERS};

/// What the launcher grants: this program's endpoint for `BIND`, and each service's endpoint
/// under `GRANTER_BADGE`. A slot with nothing in it declines that interface.
const BINDER_ENDPOINT_CPTR: usize = 1;
const KEYSTORE_GRANTER_CPTR: usize = 2;
const STORE_GRANTER_CPTR: usize = 3;
/// The first of [`MAX_BINDS`] slots where obtained badges land, and stay.
const GRANT_CPTR_BASE: usize = 4;

/// Must equal `lantern_boot::launch::HEAP_VADDR`, sized by the loader's `heap_megapages`.
const HEAP_BASE: usize = 0x8620_0000;
const HEAP_LEN: usize = 0x20_0000;
/// Must equal `lantern_boot::launch::PACKAGE_VADDR`; the exact length arrives in `arg0`.
const PACKAGE_VADDR: usize = 0x8c00_0000;
const PACKAGE_MAX_LEN: usize = 0x20_0000;

lantern_abi::entry!(run);

fn run(package_len: usize) -> ! {
    // SAFETY: the loader mapped `HEAP_BASE..+HEAP_LEN` read/write into this program's own
    // VSpace before its first instruction ran (`ProgramSpec::heap_megapages`).
    unsafe { lantern_abi::rt::init_heap(HEAP_BASE, HEAP_LEN) };

    let package = (package_len <= PACKAGE_MAX_LEN)
        .then(|| {
            // SAFETY: the loader mapped `PACKAGE_MAX_LEN` bytes read-only at `PACKAGE_VADDR`
            // for this program's whole life (`launch::map_package`), and nothing maps over it.
            let lpkg = unsafe { core::slice::from_raw_parts(PACKAGE_VADDR as *const u8, package_len) };
            read_package(lpkg, TRUSTED_PUBLISHERS)
        })
        .flatten();

    let mut bound = BoundSlots::default();
    let mut ledger = Ledger::default();
    loop {
        let Ok(received) = sys::recv(BINDER_ENDPOINT_CPTR) else { continue };
        if received.badge == CONTROL_BADGE {
            serve_control(&mut ledger, grant::control_request(&received));
            continue;
        }
        let (interface, slot) = grant::bind_request(&received);
        let granted = bound.claim(interface, slot).zip(Interface::from_wire(interface)).and_then(|(index, interface)| {
            let (publisher, plan) = package.as_ref()?;
            let binding = decide(publisher, plan, POLICY, interface, slot)?;
            let dest = GRANT_CPTR_BASE + index;
            let (status, badge) =
                grant::request_grant(granter(interface), dest, binding.object as usize, binding.ops as usize).ok()?;
            (status == status::OK).then(|| {
                // `decide` refuses a slot that doesn't fit.
                ledger.record(index, interface, slot as u8, binding, badge);
                dest
            })
        });
        let _ = match granted {
            Some(dest) => grant::reply_granted(dest),
            None => grant::reply_declined(),
        };
    }
}

fn granter(interface: Interface) -> usize {
    match interface {
        Interface::Keystore => KEYSTORE_GRANTER_CPTR,
        Interface::Filesystem => STORE_GRANTER_CPTR,
    }
}

fn serve_control(ledger: &mut Ledger, (op, index): (usize, usize)) {
    let entry = ledger.get(index).copied();
    let words = match (op, entry) {
        (CONTROL_LIST, Some(entry)) => entry.listed().to_words(),
        (CONTROL_REVOKE, Some(entry)) => {
            // The ledger changes only on the service's `OK`; anything else is reported as it is.
            let status = grant::request_revoke(granter(entry.interface), entry.badge).unwrap_or(status::FAILED);
            if status == status::OK {
                ledger.mark_revoked(index);
            }
            [status as usize, 0]
        }
        _ => [status::INVALID as usize, 0],
    };
    let _ = sys::reply([0, words[0], words[1]]);
}

const _: () = assert!(GRANT_CPTR_BASE + MAX_BINDS <= 32);
