# lantern-shell — Status

**Phase:** 3 (Privacy, identity, networking, and AI) — opened per [RFC-0017](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0017-phase-2-to-phase-3-transition.md)/[ADR-0021](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0021-phase-2-complete-phase-3-opened.md). Still design only — see "Blocked on".

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
- Shell-as-consent-broker role and responsibilities drafted and reviewed ([ARCHITECTURE.md](./ARCHITECTURE.md)).
- Threat model drafted and reviewed (consent integrity, trusted path).

## Next
- **Replace the binder's compiled-in policy with real consent**, which needs a trusted-path surface,
  and record each grant so a user can see and revoke it (`Keystore::revoke_access` exists). These are
  what the Phase 3 exit criterion's "visible, revocable capability set" still requires.
- Design the consent UX and standard capability shapes (with [`lantern-ai-runtime`](https://github.com/lantern-os/lantern-ai-runtime) and [`lantern-sdk`](https://github.com/lantern-os/lantern-sdk)).

## Blocked on
- Audit log ([`lantern-ai-runtime`](https://github.com/lantern-os/lantern-ai-runtime)).
