//! The decision half of [RFC-0020](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0020-launch-binder.md)'s launch
//! binder: everything that decides whether a request is granted, with no syscalls in it, so
//! it can be tested on a host. `src/main.rs` is the program around it.
//!
//! **The policy here is not user consent.** It is a compiled-in table with the shape of a
//! recorded consent decision, in the place one will sit. No person is asked, and nothing on
//! this path may be described as consent until a real prompt writes what [`POLICY`] holds.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use lantern_abi::grant::{ListedGrant, INTERFACE_FILESYSTEM, INTERFACE_KEYSTORE};
use lantern_abi::policy::RevocationKey;
use lantern_crypto::KeyOps;
use lantern_filesystem::FileOps;
use lantern_sdk::plan::ResourceRequest;
use lantern_sdk::GrantPlan;

/// An Ed25519 verifying key.
pub type PublisherKey = [u8; 32];

/// The verifying half of the **public** demo seed `lantern-sdk build --seed 4c4c…4c`. It
/// proves the verification path, not anyone's identity.
pub const DEMO_PUBLISHER: PublisherKey = [
    0x92, 0x73, 0x08, 0xf5, 0x3d, 0x67, 0x65, 0x50, 0x3d, 0x2b, 0x64, 0xc1, 0x03, 0xab, 0x5a, 0xa4,
    0x72, 0x06, 0xab, 0x39, 0x50, 0x2c, 0xfe, 0x8f, 0x98, 0x44, 0x2f, 0xdb, 0x54, 0x31, 0x00, 0xb7,
];

/// The same for seed `4d4d…4d`: trusted to publish, but with nothing approved in [`POLICY`].
/// It exists so a test can show that claiming an approved app's name under another trusted
/// publisher gets nothing.
pub const OTHER_DEMO_PUBLISHER: PublisherKey = [
    0x62, 0xa6, 0x11, 0xb4, 0x72, 0xd8, 0x9b, 0x0e, 0x5f, 0xc9, 0x3c, 0x06, 0x9b, 0x9f, 0x70, 0x0b,
    0x4c, 0x55, 0x2d, 0x55, 0xbc, 0x0e, 0x87, 0xb5, 0x60, 0x08, 0xef, 0x17, 0xb6, 0xb2, 0xbe, 0xbe,
];

/// Whose packages this binder will read at all.
pub const TRUSTED_PUBLISHERS: &[PublisherKey] = &[DEMO_PUBLISHER, OTHER_DEMO_PUBLISHER];

/// A host interface a role belongs to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Interface {
    Keystore,
    Filesystem,
}

impl Interface {
    /// `BIND`'s interface word.
    pub fn from_wire(word: usize) -> Option<Self> {
        match word {
            INTERFACE_KEYSTORE => Some(Self::Keystore),
            INTERFACE_FILESYSTEM => Some(Self::Filesystem),
            _ => None,
        }
    }

    pub fn to_wire(self) -> usize {
        match self {
            Self::Keystore => INTERFACE_KEYSTORE,
            Self::Filesystem => INTERFACE_FILESYSTEM,
        }
    }
}

/// One recorded decision: this publisher's app may bind this role, to this object, for at
/// most these ops. See the crate doc: a stand-in for consent, not consent.
pub struct PolicyEntry {
    pub publisher: PublisherKey,
    pub app: &'static str,
    pub interface: Interface,
    pub role: &'static str,
    /// The `KeyId` or `FileId`, raw. The service holding it is implied by `interface`.
    pub object: u16,
    /// `KeyOps` or `FileOps` bits.
    pub approved_ops: u8,
}

/// Anything not here is declined.
pub const POLICY: &[PolicyEntry] = &[
    PolicyEntry {
        publisher: DEMO_PUBLISHER,
        app: "confined-probe",
        interface: Interface::Keystore,
        role: "probe-signing",
        object: 0,
        approved_ops: KeyOps::SIGN.bits(),
    },
    PolicyEntry {
        publisher: DEMO_PUBLISHER,
        app: "confined-fs-probe",
        interface: Interface::Filesystem,
        role: "scratch",
        object: 0,
        approved_ops: FileOps::READ.union(FileOps::WRITE).bits(),
    },
];

/// What a granted request becomes: mint exactly these ops on this object.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Binding {
    pub object: u16,
    /// The **manifest's** ops, not the policy entry's.
    pub ops: u8,
}

/// Verifies `lpkg` under `trusted` and reads its manifest. `None` declines every request for
/// the whole launch. Parsing happens only after a signature verifies.
pub fn read_package(lpkg: &[u8], trusted: &[PublisherKey]) -> Option<(PublisherKey, GrantPlan)> {
    let package = lantern_sdk::package::decode_package_ref(lpkg).ok()?;
    let publisher = *trusted.iter().find(|key| package.verify(key).is_ok())?;
    let manifest = lantern_sdk::parse_bytes(package.manifest_bytes).ok()?;
    Some((publisher, manifest.plan()))
}

/// RFC-0020's decision, less "already bound" ([`BoundSlots`]) and the service's own answer.
/// Grants only for an exact policy match whose approved ops cover everything the role asks
/// for. A request beyond what's approved is declined, never narrowed: an app that gets less
/// than it declared should see `none`, not a handle that fails later.
pub fn decide(
    publisher: &PublisherKey,
    plan: &GrantPlan,
    policy: &[PolicyEntry],
    interface: Interface,
    slot: usize,
) -> Option<Binding> {
    // `LIST` reports a slot in 8 bits.
    if slot > u8::MAX as usize {
        return None;
    }
    let requests = match interface {
        Interface::Keystore => &plan.keystore,
        Interface::Filesystem => &plan.filesystem,
    };
    let request = requests.get(slot)?;
    let entry = policy.iter().find(|entry| {
        entry.publisher == *publisher
            && entry.interface == interface
            && entry.app == plan.app.name
            && entry.role == request.role
    })?;
    let ops = ops_bits(interface, request)?;
    (ops & !entry.approved_ops == 0).then_some(Binding { object: entry.object, ops })
}

/// What a revocation of this role means, for the policy store ([RFC-0022](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0022-persistent-revocation-store.md)):
/// the same across boots, unlike a ledger index or a badge. `None` if the plan has no such slot.
pub fn revocation_key(publisher: &PublisherKey, plan: &GrantPlan, interface: Interface, slot: usize) -> Option<RevocationKey> {
    let requests = match interface {
        Interface::Keystore => &plan.keystore,
        Interface::Filesystem => &plan.filesystem,
    };
    Some(key_for(publisher, &plan.app.name, interface, &requests.get(slot)?.role))
}

/// Lengths keep `("ab", "c")` and `("a", "bc")` apart.
fn key_for(publisher: &PublisherKey, app: &str, interface: Interface, role: &str) -> RevocationKey {
    let mut hasher = lantern_crypto::hash::Hasher::new();
    hasher
        .update(publisher)
        .update(&(app.len() as u64).to_le_bytes())
        .update(app.as_bytes())
        .update(&(interface.to_wire() as u64).to_le_bytes())
        .update(&(role.len() as u64).to_le_bytes())
        .update(role.as_bytes());
    let digest = hasher.finalize();
    let bytes = digest.as_bytes();
    [u64::from_le_bytes(bytes[..8].try_into().unwrap()), u64::from_le_bytes(bytes[8..16].try_into().unwrap())]
}

/// A role's validated `ops` names as bits. `None` for a name this binder has no bit for, or
/// for no ops at all, either of which it won't mint.
fn ops_bits(interface: Interface, request: &ResourceRequest) -> Option<u8> {
    let mut bits = 0u8;
    for op in &request.ops {
        bits |= op_bit(interface, op)?;
    }
    (bits != 0).then_some(bits)
}

fn op_bit(interface: Interface, op: &str) -> Option<u8> {
    match (interface, op) {
        (Interface::Keystore, "encrypt") => Some(KeyOps::ENCRYPT.bits()),
        (Interface::Keystore, "decrypt") => Some(KeyOps::DECRYPT.bits()),
        (Interface::Keystore, "sign") => Some(KeyOps::SIGN.bits()),
        (Interface::Filesystem, "read") => Some(FileOps::READ.bits()),
        (Interface::Filesystem, "write") => Some(FileOps::WRITE.bits()),
        _ => None,
    }
}

/// How many grants one launch can hold: each takes one of the binder's capability slots.
pub const MAX_BINDS: usize = 4;

/// Each `(interface, slot)` is bound at most once per launch, granted or not, so a caller
/// can't accumulate badges or fill a service's grant table.
#[derive(Default)]
pub struct BoundSlots {
    taken: [Option<(usize, usize)>; MAX_BINDS],
}

impl BoundSlots {
    /// Records the attempt. `Some(i)` is this attempt's own index below [`MAX_BINDS`]; `None`
    /// means already attempted, or no room.
    pub fn claim(&mut self, interface: usize, slot: usize) -> Option<usize> {
        if self.taken.iter().flatten().any(|&taken| taken == (interface, slot)) {
            return None;
        }
        let free = self.taken.iter().position(Option::is_none)?;
        self.taken[free] = Some((interface, slot));
        Some(free)
    }
}

/// A granted request, as the binder remembers it (RFC-0021).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LedgerEntry {
    pub interface: Interface,
    pub slot: u8,
    pub binding: Binding,
    /// Never leaves this program: it is what `REVOKE` names to the service.
    pub badge: u64,
    /// What `RECORD` names to the policy store.
    pub key: RevocationKey,
    pub revoked: bool,
    pub durable: bool,
}

impl LedgerEntry {
    pub fn listed(&self) -> ListedGrant {
        ListedGrant {
            interface: self.interface.to_wire() as u8,
            slot: self.slot,
            object: self.binding.object,
            ops: self.binding.ops,
            revoked: self.revoked,
            durable: self.durable,
        }
    }
}

/// What this launch granted, indexed as [`BoundSlots::claim`] numbered it. A declined request
/// leaves its index empty. It lives in memory: what outlives a reboot is the policy store's record
/// of a revocation, which [`LedgerEntry::durable`] reports.
#[derive(Default)]
pub struct Ledger {
    entries: [Option<LedgerEntry>; MAX_BINDS],
}

impl Ledger {
    /// Call only after the service answered `OK`.
    pub fn record(&mut self, index: usize, interface: Interface, slot: u8, binding: Binding, badge: u64, key: RevocationKey) {
        if let Some(entry) = self.entries.get_mut(index) {
            *entry = Some(LedgerEntry { interface, slot, binding, badge, key, revoked: false, durable: false });
        }
    }

    pub fn get(&self, index: usize) -> Option<&LedgerEntry> {
        self.entries.get(index)?.as_ref()
    }

    /// Call only after the service answered `OK`, so the ledger never claims a revocation that
    /// didn't happen.
    pub fn mark_revoked(&mut self, index: usize) {
        if let Some(Some(entry)) = self.entries.get_mut(index) {
            entry.revoked = true;
        }
    }

    /// Call only after the policy store answered `OK`.
    pub fn mark_durable(&mut self, index: usize) {
        if let Some(Some(entry)) = self.entries.get_mut(index) {
            entry.durable = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lantern_crypto::signing::SigningKey;
    use lantern_sdk::package::{encode_package, sign_package};
    use std::string::String;

    const CWASM: &[u8] = b"not really a cwasm";

    fn manifest(app: &str, table: &str, role: &str, ops: &str) -> String {
        format!(
            "[app]\nname = \"{app}\"\nversion = \"0.1.0\"\n\n[[{table}]]\nrole = \"{role}\"\nops = [{ops}]\njustification = \"x\"\n"
        )
    }

    fn lpkg(seed: u8, manifest: &str) -> Vec<u8> {
        let key = SigningKey::from_random_bytes([seed; 32]);
        encode_package(manifest.as_bytes(), CWASM, &sign_package(manifest.as_bytes(), CWASM, &key))
    }

    fn decide_keystore(seed: u8, manifest: &str) -> Option<Binding> {
        let (publisher, plan) = read_package(&lpkg(seed, manifest), TRUSTED_PUBLISHERS)?;
        decide(&publisher, &plan, POLICY, Interface::Keystore, 0)
    }

    #[test]
    fn the_demo_publisher_constants_are_the_seeds_they_claim() {
        assert_eq!(SigningKey::from_random_bytes([0x4c; 32]).verifying_key(), DEMO_PUBLISHER);
        assert_eq!(SigningKey::from_random_bytes([0x4d; 32]).verifying_key(), OTHER_DEMO_PUBLISHER);
    }

    #[test]
    fn an_approved_request_mints_the_manifests_ops() {
        let m = manifest("confined-probe", "keystore.key", "probe-signing", "\"sign\"");
        assert_eq!(decide_keystore(0x4c, &m), Some(Binding { object: 0, ops: KeyOps::SIGN.bits() }));
    }

    #[test]
    fn a_subset_of_approved_ops_mints_only_the_subset() {
        let m = manifest("confined-fs-probe", "filesystem.file", "scratch", "\"read\"");
        let (publisher, plan) = read_package(&lpkg(0x4c, &m), TRUSTED_PUBLISHERS).unwrap();
        let binding = decide(&publisher, &plan, POLICY, Interface::Filesystem, 0).unwrap();
        assert_eq!(binding.ops, FileOps::READ.bits());
    }

    #[test]
    fn ops_outside_the_approved_set_are_declined_not_narrowed() {
        for ops in ["\"decrypt\"", "\"sign\", \"encrypt\"", "\"sign\", \"encrypt\", \"decrypt\""] {
            let m = manifest("confined-probe", "keystore.key", "probe-signing", ops);
            assert_eq!(decide_keystore(0x4c, &m), None, "{ops}");
        }
    }

    #[test]
    fn an_unlisted_app_or_role_is_declined() {
        assert_eq!(decide_keystore(0x4c, &manifest("other-app", "keystore.key", "probe-signing", "\"sign\"")), None);
        assert_eq!(decide_keystore(0x4c, &manifest("confined-probe", "keystore.key", "other-role", "\"sign\"")), None);
    }

    #[test]
    fn another_trusted_publisher_cant_claim_an_approved_apps_name() {
        let m = manifest("confined-probe", "keystore.key", "probe-signing", "\"sign\"");
        assert!(read_package(&lpkg(0x4d, &m), TRUSTED_PUBLISHERS).is_some(), "the publisher itself is trusted");
        assert_eq!(decide_keystore(0x4d, &m), None);
    }

    #[test]
    fn an_untrusted_publisher_or_a_tampered_package_reads_as_nothing() {
        let m = manifest("confined-probe", "keystore.key", "probe-signing", "\"sign\"");
        assert!(read_package(&lpkg(0x11, &m), TRUSTED_PUBLISHERS).is_none());

        let mut tampered = lpkg(0x4c, &m);
        let byte = 8 + m.find("sign").unwrap();
        tampered[byte] ^= 1;
        assert!(read_package(&tampered, TRUSTED_PUBLISHERS).is_none());
    }

    #[test]
    fn a_signed_invalid_manifest_reads_as_nothing() {
        assert!(read_package(&lpkg(0x4c, "this is not = = toml"), TRUSTED_PUBLISHERS).is_none());
    }

    #[test]
    fn an_undeclared_slot_or_the_wrong_interface_is_declined() {
        let m = manifest("confined-probe", "keystore.key", "probe-signing", "\"sign\"");
        let (publisher, plan) = read_package(&lpkg(0x4c, &m), TRUSTED_PUBLISHERS).unwrap();
        assert_eq!(decide(&publisher, &plan, POLICY, Interface::Keystore, 1), None);
        assert_eq!(decide(&publisher, &plan, POLICY, Interface::Filesystem, 0), None);
    }

    #[test]
    fn an_empty_policy_declines_everything() {
        let m = manifest("confined-probe", "keystore.key", "probe-signing", "\"sign\"");
        let (publisher, plan) = read_package(&lpkg(0x4c, &m), TRUSTED_PUBLISHERS).unwrap();
        assert_eq!(decide(&publisher, &plan, &[], Interface::Keystore, 0), None);
    }

    #[test]
    fn each_slot_is_claimed_once_and_the_table_is_bounded() {
        let mut bound = BoundSlots::default();
        assert_eq!(bound.claim(INTERFACE_KEYSTORE, 0), Some(0));
        assert_eq!(bound.claim(INTERFACE_KEYSTORE, 0), None);
        assert_eq!(bound.claim(INTERFACE_FILESYSTEM, 0), Some(1));
        assert_eq!(bound.claim(INTERFACE_KEYSTORE, 1), Some(2));
        assert_eq!(bound.claim(INTERFACE_KEYSTORE, 2), Some(3));
        assert_eq!(bound.claim(INTERFACE_KEYSTORE, 3), None);
    }

    #[test]
    fn a_slot_list_cant_report_is_declined() {
        let m = manifest("confined-probe", "keystore.key", "probe-signing", "\"sign\"");
        let (publisher, plan) = read_package(&lpkg(0x4c, &m), TRUSTED_PUBLISHERS).unwrap();
        assert_eq!(decide(&publisher, &plan, POLICY, Interface::Keystore, 256), None);
    }

    #[test]
    fn the_ledger_lists_what_was_recorded_without_the_badge() {
        let mut ledger = Ledger::default();
        assert_eq!(ledger.get(0), None);

        let binding = Binding { object: 7, ops: KeyOps::SIGN.bits() };
        ledger.record(2, Interface::Keystore, 1, binding, 0xabcd, [1, 2]);
        assert_eq!(ledger.get(0), None, "other indexes stay empty");

        let entry = ledger.get(2).unwrap();
        assert_eq!(entry.badge, 0xabcd);
        let listed = entry.listed();
        assert_eq!(
            listed,
            ListedGrant { interface: INTERFACE_KEYSTORE as u8, slot: 1, object: 7, ops: KeyOps::SIGN.bits(), revoked: false, durable: false }
        );
        assert!(!listed.to_words().contains(&0xabcd));
    }

    #[test]
    fn marking_revoked_touches_one_entry_and_tolerates_a_bad_index() {
        let mut ledger = Ledger::default();
        let binding = Binding { object: 0, ops: 1 };
        ledger.record(0, Interface::Keystore, 0, binding, 1, [1, 1]);
        ledger.record(1, Interface::Filesystem, 0, binding, 2, [2, 2]);

        ledger.mark_revoked(0);
        ledger.mark_revoked(3);
        ledger.mark_revoked(99);
        assert!(ledger.get(0).unwrap().revoked);
        assert!(!ledger.get(1).unwrap().revoked);
        assert_eq!(ledger.get(3), None);
        assert_eq!(ledger.get(99), None);
    }

    #[test]
    fn durable_is_separate_from_revoked() {
        let mut ledger = Ledger::default();
        ledger.record(0, Interface::Keystore, 0, Binding { object: 0, ops: 1 }, 1, [1, 1]);
        ledger.mark_revoked(0);
        assert!(!ledger.get(0).unwrap().durable);
        ledger.mark_durable(0);
        assert!(ledger.get(0).unwrap().listed().durable);
    }

    #[test]
    fn a_revocation_key_distinguishes_every_part_of_what_it_means() {
        let key = key_for(&DEMO_PUBLISHER, "app", Interface::Keystore, "role");
        assert_eq!(key, key_for(&DEMO_PUBLISHER, "app", Interface::Keystore, "role"));
        assert_ne!(key, key_for(&OTHER_DEMO_PUBLISHER, "app", Interface::Keystore, "role"));
        assert_ne!(key, key_for(&DEMO_PUBLISHER, "other", Interface::Keystore, "role"));
        assert_ne!(key, key_for(&DEMO_PUBLISHER, "app", Interface::Filesystem, "role"));
        assert_ne!(key, key_for(&DEMO_PUBLISHER, "app", Interface::Keystore, "other"));
        assert_ne!(
            key_for(&DEMO_PUBLISHER, "ab", Interface::Keystore, "c"),
            key_for(&DEMO_PUBLISHER, "a", Interface::Keystore, "bc"),
        );
    }

    #[test]
    fn a_revocation_key_needs_a_declared_slot() {
        let m = manifest("confined-probe", "keystore.key", "probe-signing", "\"sign\"");
        let (publisher, plan) = read_package(&lpkg(0x4c, &m), TRUSTED_PUBLISHERS).unwrap();
        assert_eq!(
            revocation_key(&publisher, &plan, Interface::Keystore, 0),
            Some(key_for(&publisher, "confined-probe", Interface::Keystore, "probe-signing")),
        );
        assert_eq!(revocation_key(&publisher, &plan, Interface::Keystore, 1), None);
    }

    #[test]
    fn an_out_of_range_record_is_dropped() {
        let mut ledger = Ledger::default();
        ledger.record(MAX_BINDS, Interface::Keystore, 0, Binding { object: 0, ops: 1 }, 1, [1, 1]);
        assert!((0..MAX_BINDS).all(|index| ledger.get(index).is_none()));
    }

    #[test]
    fn unknown_interface_words_are_not_interfaces() {
        assert_eq!(Interface::from_wire(INTERFACE_KEYSTORE), Some(Interface::Keystore));
        assert_eq!(Interface::from_wire(0), None);
        assert_eq!(Interface::from_wire(3), None);
    }
}
