//! `lantern-launch-binder` — [RFC-0020](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0020-launch-binder.md)'s launch
//! binder: an ordinary confined program, and the only holder of authority to request grants
//! from a service. See `lib.rs` for the decision, and for why its policy isn't consent.
//!
//! It verifies the package once, then serves `BIND` requests. For a request `lib.rs` grants,
//! it asks the owning service to `GRANT`, and passes the badged endpoint on. Everything else
//! gets the same `DECLINED`, whatever the reason. It holds the badges it obtained, which is
//! where revocation will attach.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use lantern_abi::frame::status;
use lantern_abi::grant;
use lantern_abi::sys;
use lantern_launch_binder::{decide, read_package, BoundSlots, Interface, MAX_BINDS, POLICY, TRUSTED_PUBLISHERS};

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
    loop {
        let Ok(received) = sys::recv(BINDER_ENDPOINT_CPTR) else { continue };
        let (interface, slot) = grant::bind_request(&received);
        let granted = bound.claim(interface, slot).zip(Interface::from_wire(interface)).and_then(|(index, interface)| {
            let (publisher, plan) = package.as_ref()?;
            let binding = decide(publisher, plan, POLICY, interface, slot)?;
            let granter = match interface {
                Interface::Keystore => KEYSTORE_GRANTER_CPTR,
                Interface::Filesystem => STORE_GRANTER_CPTR,
            };
            let dest = GRANT_CPTR_BASE + index;
            let status = grant::request_grant(granter, dest, binding.object as usize, binding.ops as usize).ok()?;
            (status == status::OK).then_some(dest)
        });
        let _ = match granted {
            Some(dest) => grant::reply_granted(dest),
            None => grant::reply_declined(),
        };
    }
}

const _: () = assert!(GRANT_CPTR_BASE + MAX_BINDS <= 32);
