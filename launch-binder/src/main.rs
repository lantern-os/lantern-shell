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
//!
//! **With a launcher** ([RFC-0029](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0029-a-confined-launcher.md), the `WITH_LAUNCHER` flag),
//! it serves many apps. It reads and verifies every package in the set itself, from its own read-only mapping, and trusts
//! nothing the launcher says about them. The launcher `REGISTER`s which package each app slot runs, under a badge only it
//! holds, and each app's `BIND`s come under that slot's own badge. A badge with nothing registered is declined. Each slot
//! has its own bound requests, ledger range and grant capability slots, and each grant names the slot's channel to the
//! service. When an app ends, `UNREGISTER` revokes its grants at their services, records `REVOKING` with `APP_ENDED`, and
//! drops this program's copies.
//!
//! **A request has a time limit** ([RFC-0028](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0028-deadlines-and-a-capability-clock.md)): 60
//! seconds, or less if the launcher says so. Nobody answering by then is `NO_CONSENT`, and the shell is told, so a person
//! who walked away, or a shell that hung, can't hold grants forever. The binder arms its own `Deadline`, so the limit
//! doesn't depend on the shell.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use alloc::vec::Vec;

use lantern_abi::consent::{self, Answer, Ask};
use lantern_abi::frame::status;
use lantern_abi::grant::{
    self, ListedDecision, CONTROL_BADGE, CONTROL_DECISIONS, CONTROL_FORGET, CONTROL_LIST, CONTROL_REVOKE, REGISTER, REGISTER_BADGE,
    UNREGISTER,
};
use lantern_abi::launcher;
use lantern_abi::policy::{decision, event, reason, AuditEntry};
use lantern_abi::sys::deadline;
use lantern_abi::{policy, sys};
use lantern_launch_binder::{
    decide, outcome, read_package, remembered, request, revocation_key, role_for_key, BoundSlots, Interface, Ledger,
    PublisherKey, Registry, Remembered, MAX_BINDS, POLICY, TRUSTED_PUBLISHERS,
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
/// RFC-0028, with consent only: this program's `Deadline`, its own answer notification badged `consent::TIMED_OUT` (to bind
/// the deadline to), and the shell's notification badged `ASK_DONE` and `ASK_CANCELLED`.
const DEADLINE_CPTR: usize = POLICY_STORE_CPTR + 3;
const ANSWER_TIMED_OUT_CPTR: usize = POLICY_STORE_CPTR + 4;
const SHELL_DONE_CPTR: usize = POLICY_STORE_CPTR + 5;
const SHELL_CANCELLED_CPTR: usize = POLICY_STORE_CPTR + 6;
/// RFC-0029, with a launcher only: this program's own CNode, to drop its copies of an ended app's grants, and where
/// each app slot's grants land, `MAX_BINDS` each.
const SELF_CNODE_CPTR: usize = POLICY_STORE_CPTR + 7;
const APP_GRANT_CPTR_BASE: usize = 40;
/// `arg0`'s bits 48 to 55: the consent limit in seconds, if the launcher wants it below `consent::LIMIT_NS`. 0 means the
/// default. It can only lower it.
const LIMIT_SHIFT: usize = 48;
/// Where the loader maps the consent `Frame`, shared with the shell. Must equal `launch::BINDER_CONSENT_VADDR`.
const CONSENT_VADDR: usize = 0x9000_0000;

/// Must equal `lantern_boot::launch::HEAP_VADDR`, sized by the loader's `heap_megapages`.
const HEAP_BASE: usize = 0x8620_0000;
const HEAP_LEN: usize = 0x20_0000;
/// Must equal `lantern_boot::launch::PACKAGE_VADDR`; the exact length arrives in `arg0`. With a launcher, the package
/// set is there instead (`launcher::SET_VADDR`), and `arg0` carries how many packages it holds.
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
    let limit_s = ((arg0 >> LIMIT_SHIFT) & 0xff) as u64;
    let limit = if limit_s == 0 { consent::LIMIT_NS } else { (limit_s * 1_000_000_000).min(consent::LIMIT_NS) };
    // A deadline that can't be bound means no request can have a limit: `consent_for` then declines rather than wait forever.
    let timed = with_consent && deadline::set_notification(DEADLINE_CPTR, ANSWER_TIMED_OUT_CPTR).is_ok();
    // SAFETY: the loader mapped `HEAP_BASE..+HEAP_LEN` read/write into this program's own
    // VSpace before its first instruction ran (`ProgramSpec::heap_megapages`).
    unsafe { lantern_abi::rt::init_heap(HEAP_BASE, HEAP_LEN) };

    let with_launcher = arg0 & grant::WITH_LAUNCHER != 0;
    let packages: Vec<Package> = if with_launcher {
        (0..package_len.min(launcher::SET_MAX))
            .map(|i| {
                // SAFETY: with a launcher, the loader mapped `package_len` set Frames read-only, consecutively, at
                // `SET_VADDR` for this program's whole life, and nothing maps over them.
                let frame = unsafe {
                    core::slice::from_raw_parts((launcher::SET_VADDR + i * launcher::SET_STRIDE) as *const u8, launcher::SET_STRIDE)
                };
                launcher::set_entry(frame).and_then(|lpkg| read_package(lpkg, TRUSTED_PUBLISHERS))
            })
            .collect()
    } else {
        let package = (package_len <= PACKAGE_MAX_LEN)
            .then(|| {
                // SAFETY: the loader mapped `PACKAGE_MAX_LEN` bytes read-only at `PACKAGE_VADDR`
                // for this program's whole life (`launch::map_package`), and nothing maps over it.
                let lpkg = unsafe { core::slice::from_raw_parts(PACKAGE_VADDR as *const u8, package_len) };
                read_package(lpkg, TRUSTED_PUBLISHERS)
            })
            .flatten();
        alloc::vec![package]
    };

    let mut bound = BoundSlots::default();
    let mut registry = Registry::default();
    let mut ledger = Ledger::default();
    loop {
        let Ok(received) = sys::recv(BINDER_ENDPOINT_CPTR) else { continue };
        if received.badge == CONTROL_BADGE {
            serve_control(&packages, with_consent, &mut ledger, grant::control_request(&received));
            continue;
        }
        if with_launcher && received.badge == REGISTER_BADGE {
            serve_registration(&packages, &mut registry, &mut ledger, grant::registration_request(&received));
            continue;
        }
        let (interface, slot) = grant::bind_request(&received);
        // Only a slot's first attempt is decided, or recorded: a caller can't fill the log by repeating one. With a
        // launcher, that's per run of an app slot, and a badge with nothing registered is declined without a record.
        let consent = with_consent.then_some(Consent { timed, limit });
        let claimed = if with_launcher {
            grant::app_for_badge(received.badge).and_then(|app| {
                let package = registry.package(app)?;
                Some((registry.claim(app, interface, slot)?, Some(app), package))
            })
        } else {
            bound.claim(interface, slot).map(|index| (index, None, 0))
        };
        let granted = claimed.and_then(|(index, app, package)| {
            let request = Request { index, interface, slot, app, package };
            bind(&packages[package as usize], consent, &mut ledger, request)
        });
        let _ = match granted {
            Some(dest) => grant::reply_granted(dest),
            None => grant::reply_declined(),
        };
    }
}

/// A package as this program verified it, or `None` if it didn't.
type Package = Option<(PublisherKey, GrantPlan)>;

/// Where an app slot's ledger entry `index` keeps its capability: with a launcher, `APP_GRANT_CPTR_BASE` on.
fn grant_cptr(app: Option<usize>, index: usize) -> usize {
    match app {
        Some(_) => APP_GRANT_CPTR_BASE + index,
        None => GRANT_CPTR_BASE + index,
    }
}

/// One `BIND` to decide: its ledger index, `(interface, slot)`, and, with a launcher, the app slot and its package.
struct Request {
    index: usize,
    interface: usize,
    slot: usize,
    app: Option<usize>,
    package: u8,
}

/// With consent: whether this program's deadline is bound, and the limit on each request.
#[derive(Clone, Copy)]
struct Consent {
    timed: bool,
    limit: u64,
}

/// One first attempt at `(interface, slot)`: `Some` with the capability's slot if granted. Every outcome is
/// recorded except one the log itself refused.
fn bind(package: &Package, consent: Option<Consent>, ledger: &mut Ledger, request: Request) -> Option<usize> {
    let Request { index, interface: interface_word, slot, app, package: package_index } = request;
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
        if let Some(consent) = consent {
            let consented = consent_for(consent, publisher, plan, interface, slot, entry.subject, binding.ops)?;
            let record = AuditEntry { event: event::CONSENTED, reason: consented, ..entry };
            if policy::append(POLICY_STORE_CPTR, &record) != Ok(status::OK) {
                return Err(None);
            }
        }
        if policy::append(POLICY_STORE_CPTR, &AuditEntry { event: event::GRANTING, ..entry }) != Ok(status::OK) {
            return Err(None);
        }
        let dest = grant_cptr(app, index);
        // With a launcher, the service ties the badge to this app slot's channel, and serves it there only.
        let ops = grant::grant_ops(binding.ops, app);
        match grant::request_grant(granter(interface), dest, binding.object as usize, ops) {
            Ok((status::OK, badge)) => {
                // `decide` refuses a slot that doesn't fit.
                ledger.record(index, interface, slot as u8, binding, badge, entry.subject, package_index);
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
    consent: Consent,
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
    // RFC-0028: no request without a limit. Drain first, so a late answer or a stale timeout from an earlier request can't
    // count for this one.
    let _ = sys::poll(ANSWER_CPTR);
    let armed = consent.timed
        && deadline::now(DEADLINE_CPTR).is_ok_and(|now| deadline::arm(DEADLINE_CPTR, now.saturating_add(consent.limit)).is_ok());
    if !armed {
        return Err(Some(reason::NO_CONSENT));
    }
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
    let bits = sys::signal(SHELL_ASK_CPTR).ok().and_then(|()| sys::wait(ANSWER_CPTR).ok()).unwrap_or(0);
    let _ = deadline::cancel(DEADLINE_CPTR);
    // An answer wins over a timeout that arrived with it: the person answered by the time this looked.
    let answer = Answer::from_badge(bits & !consent::TIMED_OUT);
    // Tell the shell which happened, so it never claims an answer counted when it didn't.
    let _ = sys::signal(if answer.is_some() { SHELL_DONE_CPTR } else { SHELL_CANCELLED_CPTR });
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

/// `REGISTER` and `UNREGISTER`, from the launcher alone.
fn serve_registration(packages: &[Package], registry: &mut Registry, ledger: &mut Ledger, (op, app, package): (usize, usize, usize)) {
    let status = match op {
        REGISTER => registry.register(app, package, |p| packages.get(p).is_some_and(Option::is_some)),
        UNREGISTER if registry.package(app).is_some() => {
            let mut status = status::OK;
            for index in Registry::ledger_range(app) {
                let Some(entry) = ledger.get(index).copied() else { continue };
                if !entry.revoked {
                    let ending = AuditEntry {
                        event: event::REVOKING,
                        reason: reason::APP_ENDED,
                        interface: entry.interface.to_wire() as u8,
                        slot: entry.slot,
                        object: entry.binding.object,
                        ops: entry.binding.ops,
                        subject: entry.key,
                    };
                    let _ = policy::append(POLICY_STORE_CPTR, &ending);
                    if grant::request_revoke(granter(entry.interface), entry.badge) != Ok(status::OK) {
                        status = status::FAILED;
                    }
                }
                let _ = sys::cnode::delete(SELF_CNODE_CPTR, grant_cptr(Some(app), index));
                ledger.clear(index);
            }
            registry.unregister(app);
            status
        }
        _ => status::INVALID,
    };
    let _ = sys::reply([0, status as usize, 0]);
}

fn serve_control(
    packages: &[Package],
    with_consent: bool,
    ledger: &mut Ledger,
    (op, index): (usize, usize),
) {
    let entry = ledger.get(index).copied();
    let words = match (op, entry) {
        (CONTROL_LIST, Some(entry)) => {
            if let (true, Some(Some((_, plan)))) = (with_consent, packages.get(entry.package as usize)) {
                let role = request(plan, entry.interface, entry.slot as usize).map_or(&b""[..], |r| r.role.as_bytes());
                ConsentFrame::names(plan.app.name.as_bytes(), role);
            }
            entry.listed().to_words()
        }
        (CONTROL_DECISIONS, _) if with_consent => list_decision(packages, index),
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
fn list_decision(packages: &[Package], index: usize) -> [usize; 2] {
    match policy::decision_read(POLICY_STORE_CPTR, index) {
        Ok((status::OK, decision, ops, key)) => {
            // Any verified package's role: a decision outlives the run that made it.
            let role = packages
                .iter()
                .flatten()
                .find_map(|(publisher, plan)| Some((plan, role_for_key(publisher, plan, key)?)));
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

const _: () = assert!(SHELL_CANCELLED_CPTR < 32);
const _: () = assert!(SELF_CNODE_CPTR < APP_GRANT_CPTR_BASE && APP_GRANT_CPTR_BASE + lantern_launch_binder::LEDGER_LEN <= 72);
