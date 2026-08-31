# lantern-shell — Status

**Phase:** 3 (Privacy, identity, networking, and AI) — opened per [RFC-0017](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0017-phase-2-to-phase-3-transition.md)/[ADR-0021](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0021-phase-2-complete-phase-3-opened.md). Still design only — see "Blocked on".

## Done
- Shell-as-consent-broker role and responsibilities drafted and reviewed ([ARCHITECTURE.md](./ARCHITECTURE.md)).
- Threat model drafted and reviewed (consent integrity, trusted path).

## Next
- **The launch binder** [RFC-0015](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0015-capability-manifest-format.md)/[ADR-0020](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0020-capability-manifest-format.md)
  names as this crate's job: resolve each manifest `role` (from `lantern-sdk`'s
  `GrantPlan`) to a concrete object with the user's consent, ask the owning service to
  mint the badge, and emit the `lantern_runtime::GrantManifest`. `lantern-sdk` already
  produces the `GrantPlan` and offers a `bind` helper.
- Design the consent UX and standard capability shapes (with [`lantern-ai-runtime`](https://github.com/lantern-os/lantern-ai-runtime) and [`lantern-sdk`](https://github.com/lantern-os/lantern-sdk)).

## Blocked on
- **The confined-execution port carried forward from Phase 2 (ADR-0021).** A consent broker
  that mints real badges needs the services reachable as confined IPC processes, not
  host-target stand-ins — Phase 3's first work.
- Audit log ([`lantern-ai-runtime`](https://github.com/lantern-os/lantern-ai-runtime)).
