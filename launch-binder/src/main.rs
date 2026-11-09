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
//!
//! The policy store ([RFC-0022](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0022-persistent-revocation-store.md)) makes a
//! revocation outlive a reboot. Before each grant, only its `OK` lets the grant proceed, so a corrupt or
//! missing store declines everything. It can only narrow what [`POLICY`] allows.
//!
//! The audit log ([RFC-0024](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0024-audit-log.md)) records every grant, decline and
//! revocation, with the reason the runtime isn't told. **A grant is recorded before it's attempted**, so an
//! unrecorded grant can't happen, and a log that can't take the record declines it. A revocation is never
//! blocked by the log.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use lantern_abi::frame::status;
use lantern_abi::grant::{self, CONTROL_BADGE, CONTROL_LIST, CONTROL_REVOKE};
use lantern_abi::policy::{event, reason, AuditEntry};
use lantern_abi::{policy, sys};
use lantern_launch_binder::{
    decide, read_package, revocation_key, BoundSlots, Interface, Ledger, PublisherKey, MAX_BINDS, POLICY, TRUSTED_PUBLISHERS,
};
use lantern_sdk::GrantPlan;

/// What the launcher grants: this program's endpoint for `BIND`, and each service's endpoint
/// under `GRANTER_BADGE`. A slot with nothing in it declines that interface.
const BINDER_ENDPOINT_CPTR: usize = 1;
const KEYSTORE_GRANTER_CPTR: usize = 2;
const STORE_GRANTER_CPTR: usize = 3;
/// The first of [`MAX_BINDS`] slots where obtained badges land, and stay.
const GRANT_CPTR_BASE: usize = 4;
/// The policy store's endpoint. Only this program holds one.
const POLICY_STORE_CPTR: usize = GRANT_CPTR_BASE + MAX_BINDS;

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
        // Only a slot's first attempt is decided, or recorded: a caller can't fill the log by repeating one.
        let granted = bound.claim(interface, slot).and_then(|index| bind(&package, &mut ledger, index, interface, slot));
        let _ = match granted {
            Some(dest) => grant::reply_granted(dest),
            None => grant::reply_declined(),
        };
    }
}

/// One first attempt at `(interface, slot)`: `Some` with the capability's slot if granted. Every outcome is
/// recorded except one the log itself refused.
fn bind(
    package: &Option<(PublisherKey, GrantPlan)>,
    ledger: &mut Ledger,
    index: usize,
    interface_word: usize,
    slot: usize,
) -> Option<usize> {
    let mut entry =
        AuditEntry { event: event::DECLINED, interface: interface_word as u8, slot: slot as u8, ..AuditEntry::default() };
    // `Err(Some(reason))` is recorded as a decline; `Err(None)` has been recorded already, or can't be.
    let mut attempt = || -> Result<usize, Option<u8>> {
        let interface = Interface::from_wire(interface_word).ok_or(reason::NOT_DECLARED)?;
        let (publisher, plan) = package.as_ref().ok_or(reason::UNVERIFIED_PACKAGE)?;
        if let Some(key) = revocation_key(publisher, plan, interface, slot) {
            entry.key = key;
        }
        let binding = decide(publisher, plan, POLICY, interface, slot)?;
        entry.object = binding.object;
        entry.ops = binding.ops;
        match policy::is_revoked(POLICY_STORE_CPTR, entry.key) {
            Ok(status::OK) => {}
            Ok(status::ACCESS) => return Err(Some(reason::REVOKED)),
            _ => return Err(Some(reason::STORE_UNAVAILABLE)),
        }
        if policy::append(POLICY_STORE_CPTR, &AuditEntry { event: event::GRANTING, ..entry }) != Ok(status::OK) {
            return Err(None);
        }
        let dest = GRANT_CPTR_BASE + index;
        match grant::request_grant(granter(interface), dest, binding.object as usize, binding.ops as usize) {
            Ok((status::OK, badge)) => {
                // `decide` refuses a slot that doesn't fit.
                ledger.record(index, interface, slot as u8, binding, badge, entry.key);
                Ok(dest)
            }
            _ => {
                let _ = policy::append(POLICY_STORE_CPTR, &AuditEntry { event: event::GRANT_FAILED, ..entry });
                Err(None)
            }
        }
    };
    match attempt() {
        Ok(dest) => Some(dest),
        Err(declined) => {
            if let Some(reason) = declined {
                let _ = policy::append(POLICY_STORE_CPTR, &AuditEntry { reason, ..entry });
            }
            None
        }
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
            // Recorded first, so a crash from here on means declined next boot, the safe direction.
            // A failure to record doesn't stop the revocation: the holder asked for it to end now.
            let recorded = policy::record(POLICY_STORE_CPTR, entry.key) == Ok(status::OK);
            if recorded {
                ledger.mark_durable(index);
            }
            let revoking = AuditEntry {
                event: event::REVOKING,
                interface: entry.interface.to_wire() as u8,
                slot: entry.slot,
                object: entry.binding.object,
                ops: entry.binding.ops,
                key: entry.key,
                ..AuditEntry::default()
            };
            let logged = policy::append(POLICY_STORE_CPTR, &revoking) == Ok(status::OK);
            // The ledger changes only on the service's `OK`; anything else is reported as it is.
            let revoked = grant::request_revoke(granter(entry.interface), entry.badge).unwrap_or(status::FAILED);
            if revoked == status::OK {
                ledger.mark_revoked(index);
            }
            let status = if revoked == status::OK && !(recorded && logged) { status::FAILED } else { revoked };
            [status as usize, 0]
        }
        _ => [status::INVALID as usize, 0],
    };
    let _ = sys::reply([0, words[0], words[1]]);
}

const _: () = assert!(POLICY_STORE_CPTR < 32);
