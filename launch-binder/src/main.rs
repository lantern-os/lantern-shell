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
//! blocked by the log. After the service's `OK`, `GRANTED` records the badge it minted, which is how a reader
//! links each service's records of use ([RFC-0025](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0025-audit-log-service-operations.md))
//! back to the role.
//!
//! **With consent** ([RFC-0026](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0026-trusted-path-and-consent.md), the `WITH_CONSENT` flag),
//! [`POLICY`] is a ceiling, and a person decides each request within it, at a console only the shell reaches. A
//! remembered "always" or "never" settles a request without a prompt; otherwise the binder writes the request into the
//! consent `Frame`, signals the shell, and waits for the answer, serving nothing else meanwhile. `CONSENTED`, or a decline
//! with the person's reason, is recorded before anything else happens. A revoke from the console ends the grant and
//! forgets any "always", so the person is asked again next time; "never" is how a person says no for good.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use lantern_abi::consent::{self, Answer, Ask};
use lantern_abi::frame::status;
use lantern_abi::grant::{self, ListedDecision, CONTROL_BADGE, CONTROL_DECISIONS, CONTROL_FORGET, CONTROL_LIST, CONTROL_REVOKE};
use lantern_abi::policy::{decision, event, reason, AuditEntry};
use lantern_abi::{policy, sys};
use lantern_launch_binder::{
    decide, outcome, read_package, remembered, request, revocation_key, role_for_key, BoundSlots, Interface, Ledger,
    PublisherKey, Remembered, MAX_BINDS, POLICY, TRUSTED_PUBLISHERS,
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
/// RFC-0026, with consent only: the shell's notification, badged `consent::bit::ASK`, and this program's own answer
/// notification, which only the shell can signal.
const SHELL_ASK_CPTR: usize = POLICY_STORE_CPTR + 1;
const ANSWER_CPTR: usize = POLICY_STORE_CPTR + 2;
/// Where the loader maps the consent `Frame`, shared with the shell. Must equal `launch::BINDER_CONSENT_VADDR`.
const CONSENT_VADDR: usize = 0x9000_0000;

/// Must equal `lantern_boot::launch::HEAP_VADDR`, sized by the loader's `heap_megapages`.
const HEAP_BASE: usize = 0x8620_0000;
const HEAP_LEN: usize = 0x20_0000;
/// Must equal `lantern_boot::launch::PACKAGE_VADDR`; the exact length arrives in `arg0`.
const PACKAGE_VADDR: usize = 0x8c00_0000;
const PACKAGE_MAX_LEN: usize = 0x20_0000;

lantern_abi::entry!(run);

/// Text for the shell, written into the consent `Frame`.
struct ConsentFrame;

impl ConsentFrame {
    fn half(offset: usize, len: usize) -> &'static mut [u8] {
        // SAFETY: with consent, the loader mapped the 4 KiB consent `Frame` read/write at CONSENT_VADDR for this program's
        // whole life. The two halves don't overlap, and only one is borrowed at a time, briefly, in this single thread.
        unsafe { core::slice::from_raw_parts_mut((CONSENT_VADDR + offset) as *mut u8, len) }
    }

    fn ask(ask: &Ask<'_>) {
        consent::encode_ask(ask, Self::half(consent::ASK_OFFSET, consent::ASK_LEN));
    }

    fn names(app: &[u8], role: &[u8]) {
        consent::encode_names(app, role, Self::half(consent::NAMES_OFFSET, consent::NAMES_LEN));
    }
}

fn run(arg0: usize) -> ! {
    let with_consent = arg0 & grant::WITH_CONSENT != 0;
    let package_len = arg0 & (grant::WITH_CONSENT - 1);
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
            serve_control(&package, with_consent, &mut ledger, grant::control_request(&received));
            continue;
        }
        let (interface, slot) = grant::bind_request(&received);
        // Only a slot's first attempt is decided, or recorded: a caller can't fill the log by repeating one.
        let granted =
            bound.claim(interface, slot).and_then(|index| bind(&package, with_consent, &mut ledger, index, interface, slot));
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
    with_consent: bool,
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
            entry.subject = key;
        }
        let binding = decide(publisher, plan, POLICY, interface, slot)?;
        entry.object = binding.object;
        entry.ops = binding.ops;
        match policy::is_revoked(POLICY_STORE_CPTR, entry.subject) {
            Ok(status::OK) => {}
            Ok(status::ACCESS) => return Err(Some(reason::REVOKED)),
            _ => return Err(Some(reason::STORE_UNAVAILABLE)),
        }
        if with_consent {
            let consented = consent_for(publisher, plan, interface, slot, entry.subject, binding.ops)?;
            let record = AuditEntry { event: event::CONSENTED, reason: consented, ..entry };
            if policy::append(POLICY_STORE_CPTR, &record) != Ok(status::OK) {
                return Err(None);
            }
        }
        if policy::append(POLICY_STORE_CPTR, &AuditEntry { event: event::GRANTING, ..entry }) != Ok(status::OK) {
            return Err(None);
        }
        let dest = GRANT_CPTR_BASE + index;
        match grant::request_grant(granter(interface), dest, binding.object as usize, binding.ops as usize) {
            Ok((status::OK, badge)) => {
                // `decide` refuses a slot that doesn't fit.
                ledger.record(index, interface, slot as u8, binding, badge, entry.subject);
                // `GRANTING` already covers the grant, so failing to record this loses only the link from the badge
                // to the role, which then shows as a `GRANTING` with nothing after it.
                let granted = AuditEntry { event: event::GRANTED, subject: [badge, 0], ..entry };
                let _ = policy::append(POLICY_STORE_CPTR, &granted);
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

/// RFC-0026: a person's decision on a request already inside the ceiling. `Ok` with `CONSENTED`'s reason, or `Err` with
/// the decline's. A remembered decision settles it without a prompt; an unreadable one declines, since a remembered
/// "never" may be what's unreadable.
fn consent_for(
    publisher: &PublisherKey,
    plan: &GrantPlan,
    interface: Interface,
    slot: usize,
    key: policy::RevocationKey,
    ops: u8,
) -> Result<u8, Option<u8>> {
    let (stored, remembered_decision, remembered_ops) =
        policy::decision_get(POLICY_STORE_CPTR, key).map_err(|_| Some(reason::STORE_UNAVAILABLE))?;
    if stored != status::OK {
        return Err(Some(reason::STORE_UNAVAILABLE));
    }
    match remembered(remembered_decision, remembered_ops, ops) {
        Remembered::Allow => return Ok(policy::consent_reason::REMEMBERED),
        Remembered::Deny => return Err(Some(reason::REMEMBERED_DENIAL)),
        Remembered::Ask => {}
    }
    let request = request(plan, interface, slot).ok_or(Some(reason::NOT_DECLARED))?;
    ConsentFrame::ask(&Ask {
        interface: interface.to_wire() as u8,
        ops,
        publisher: *publisher,
        app: plan.app.name.as_bytes(),
        role: request.role.as_bytes(),
        justification: request.justification.as_bytes(),
        truncated: false,
    });
    // The shell can't be reached: nobody was asked, so nobody consented.
    let answer = sys::signal(SHELL_ASK_CPTR).ok().and_then(|()| sys::wait(ANSWER_CPTR).ok()).and_then(Answer::from_badge);
    let (decided, remember) = outcome(answer);
    if let Some(remember) = remember {
        // A failure to remember doesn't change this answer; it only means the person is asked again next time. An
        // "always" not remembered is recorded as once.
        let stored = policy::decision_set(POLICY_STORE_CPTR, key, remember, ops) == Ok(status::OK);
        if !stored && remember == decision::ALLOW {
            return Ok(policy::consent_reason::ONCE);
        }
    }
    decided.map_err(Some)
}

fn granter(interface: Interface) -> usize {
    match interface {
        Interface::Keystore => KEYSTORE_GRANTER_CPTR,
        Interface::Filesystem => STORE_GRANTER_CPTR,
    }
}

fn serve_control(
    package: &Option<(PublisherKey, GrantPlan)>,
    with_consent: bool,
    ledger: &mut Ledger,
    (op, index): (usize, usize),
) {
    let entry = ledger.get(index).copied();
    let words = match (op, entry) {
        (CONTROL_LIST, Some(entry)) => {
            if let (true, Some((_, plan))) = (with_consent, package) {
                let role = request(plan, entry.interface, entry.slot as usize).map_or(&b""[..], |r| r.role.as_bytes());
                ConsentFrame::names(plan.app.name.as_bytes(), role);
            }
            entry.listed().to_words()
        }
        (CONTROL_DECISIONS, _) if with_consent => list_decision(package, index),
        (CONTROL_FORGET, _) if with_consent => {
            let forgot = match policy::decision_read(POLICY_STORE_CPTR, index) {
                Ok((status::OK, _, _, key)) => {
                    policy::decision_set(POLICY_STORE_CPTR, key, decision::NONE, 0).unwrap_or(status::FAILED)
                }
                Ok((status::INVALID, ..)) => status::INVALID,
                _ => status::FAILED,
            };
            [forgot as usize, 0]
        }
        (CONTROL_REVOKE, Some(entry)) => {
            // Recorded first, so a crash from here on means declined next boot, the safe direction.
            // A failure to record doesn't stop the revocation: the holder asked for it to end now.
            // With consent, what's recorded is that any "always" is forgotten: the person is asked again next time.
            let recorded = if with_consent {
                policy::decision_set(POLICY_STORE_CPTR, entry.key, decision::NONE, 0) == Ok(status::OK)
            } else {
                policy::record(POLICY_STORE_CPTR, entry.key) == Ok(status::OK)
            };
            if recorded {
                ledger.mark_durable(index);
            }
            let revoking = AuditEntry {
                event: event::REVOKING,
                interface: entry.interface.to_wire() as u8,
                slot: entry.slot,
                object: entry.binding.object,
                ops: entry.binding.ops,
                subject: entry.key,
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

/// `DECISIONS`: the `index`th remembered decision, with its names written to the consent `Frame` if it's one of this
/// package's roles.
fn list_decision(package: &Option<(PublisherKey, GrantPlan)>, index: usize) -> [usize; 2] {
    match policy::decision_read(POLICY_STORE_CPTR, index) {
        Ok((status::OK, decision, ops, key)) => {
            let role = package.as_ref().and_then(|(publisher, plan)| Some((plan, role_for_key(publisher, plan, key)?)));
            match role {
                Some((plan, role)) => ConsentFrame::names(plan.app.name.as_bytes(), role.role.as_bytes()),
                None => ConsentFrame::names(b"", b""),
            }
            let words = ListedDecision { decision, ops, named: role.is_some() }.to_words();
            [words[0] | status::OK as usize, words[1]]
        }
        Ok((status::INVALID, ..)) => [status::INVALID as usize, 0],
        _ => [status::FAILED as usize, 0],
    }
}

const _: () = assert!(ANSWER_CPTR < 32);
