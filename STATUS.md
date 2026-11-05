# lantern-shell — Status

**Phase:** 3 (Privacy, identity, networking, and AI) — opened per [RFC-0017](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0017-phase-2-to-phase-3-transition.md)/[ADR-0021](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0021-phase-2-complete-phase-3-opened.md). Three confined programs exist; the consent surface is still design only — see "Blocked on".

## Done
- **The launch binder v0 (2026-11-02), this repo's first code:** `launch-binder/`, per
  [RFC-0020](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0020-launch-binder.md)/[ADR-0025](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0025-launch-binder.md).
  A confined program, and the only holder of authority to request grants from a service. It verifies
  a package, reads its manifest, decides each request against a deny-by-default policy, and passes on
  a badge minted for exactly the manifest's `ops`. **The policy is a compiled-in table, not consent:
  no person is asked.** The decision logic is host-tested (`cargo test --lib --target
  x86_64-unknown-linux-gnu`, 12 tests). Both runtime demos run with it under QEMU, and
  `lantern-boot/scripts/binder-matrix.sh` checks 14 cases, including that a read-only request stops a
  guest writing. The first-caller grant is gone from the app path.
- **The grant ledger and revocation v0 (2026-11-02):** [RFC-0021](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0021-grant-ledger-and-revocation.md)/[ADR-0026](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0026-grant-ledger-and-revocation.md). The binder records what it granted, and the
  holder of a control capability can list entries and revoke one, naming them by index and never seeing a
  badge. `grant-control/` holds that capability, and **is a test script, not a user interface**. The owning
  service enforces revocation, so the kernel doesn't change. **A revocation lasts only until the next boot**,
  when the compiled-in policy grants the same thing again (the store below changes that), so this mustn't be
  described as a durable user decision. A revoked role can't be re-granted. 16 binder tests at the time.
- **The persistent policy store v0 (2026-11-03):** [RFC-0022](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0022-persistent-revocation-store.md)/[ADR-0027](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0027-persistent-revocation-store.md). `policy-store/` is a confined service, the only program with
  flash mapped, keeping an append-only log of revoked roles that the binder consults before every grant. A revocation
  now survives a reboot, tested across real QEMU boots of one image. **It can only narrow** the compiled-in policy, and a
  corrupt store or missing flash declines everything. **It doesn't resist offline tampering:** erasing the flash restores
  every revoked role, and `binder-matrix.sh` tests that so it stays visible. 13 log tests, including a power cut at
  every word of a record, and 19 binder tests.
- Shell-as-consent-broker role and responsibilities drafted and reviewed ([ARCHITECTURE.md](./ARCHITECTURE.md)).
- Threat model drafted and reviewed (consent integrity, trusted path).

## Next
- **Replace the binder's compiled-in policy and `grant-control` with real consent**, which needs a trusted-path
  surface. That's what's left of the Phase 3 exit criterion's "visible, revocable capability set": no person sees
  or decides anything yet. The store then has to hold grants too, and can no longer only narrow (RFC-0022).
- A recovery path for a corrupt store.
- Design the consent UX and standard capability shapes (with [`lantern-ai-runtime`](https://github.com/lantern-os/lantern-ai-runtime) and [`lantern-sdk`](https://github.com/lantern-os/lantern-sdk)).

## Phase 4
- **A hardware root of trust**, so the log resists offline tampering and rollback, on
  [RFC-0023](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0023-hardware-key-custody-in-phase-4.md)'s checklist.

## Blocked on
- Audit log ([`lantern-ai-runtime`](https://github.com/lantern-os/lantern-ai-runtime)).
